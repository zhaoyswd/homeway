//go:build !windows

// term_surface_session.go — surface 的会话侧编排（任务 2.3–2.7；多腿化 = term-host-cli 2.2b）。
//
// 分工：线格式在 term_surface.go，腿的投递与背压在 term_surface_leg.go，
// 这里负责「什么时候发什么」与「收到上行帧怎么处理」。
//
// 节奏（2.5）：PTY 有输出 ⇒ pump 在锁内喂完 vt 后 `wakeSurface()`；投递循环被唤醒后
// 先睡一个**合并窗**（窗内再来唤醒就顺延到上限），再把这一窗的脏行并成一帧发出去。
// 这样高频小输出不会变成高频小帧，而子进程也永远不会等投递（投递在独立 goroutine）。
//
// 多腿（2.2b）：flushSurface 同一拍遍历**所有** surface 腿——脏行集每拍取一次（共享一个
// vt render reader），快照/差分按腿各自构建（基线在腿上，2.2a）；掉队腿（上一拍发送失败/
// 超时）由自己的 needSnapshot 走全量。生产者只**入队**（每腿有界队列 + 写者，design D5/B'），
// 绝不直接写 socket ⇒ 慢腿不影响其它腿与子进程。
package term

import (
	"sync"
	"time"

	"github.com/zhaoyswd/homeway/pkg/term/vt"
)

// wakeSurface 通知投递循环「有东西要发」（非阻塞；已挂起时唤醒会被合并）。
func (s *termSession) wakeSurface() {
	if s.surfaceWake == nil {
		return
	}
	select {
	case s.surfaceWake <- struct{}{}:
	default: // 已有待处理唤醒 ⇒ 本次被合并窗吸收
	}
}

// surfaceLoop 投递循环（每会话一条；会话结束或服务关闭时退出）。
func (s *termSession) surfaceLoop() {
	for {
		select {
		case <-s.svc.stopCh:
			return
		case <-s.surfaceStop:
			// 会话结束（finish）：收工。旧实现只 select 服务级 stopCh ⇒ 每建删一个会话就
			// 漏一个常驻 goroutine（7.4 的「20 会话建删无泄漏」会抓到）。
			return
		case text := <-s.clipChan:
			// 剪贴板写（OSC 52）：立即下发（不参与脏行合并窗）；**只发 surface 腿**
			// （任务 2.1b：raw 腿的字节流里本来就带这条序列，重复投递 = 双份 + 撞 CLI 的
			// 未知帧分支）。
			s.mu.Lock()
			legs := s.surfaceLegsLocked()
			s.mu.Unlock()
			for _, c := range legs {
				c.out.enqueue(writeItem{op: opClipboard, payload: encClipboard(clipKindWrite, text)}, s.queueBytes)
			}
			continue
		case <-s.surfaceWake:
		}
		// 合并窗：先把窗内的后续唤醒吸收掉，再发一帧。
		deadline := time.Now().Add(surfaceMergeWindowMax)
		for time.Now().Before(deadline) {
			select {
			case <-s.surfaceWake:
				continue
			case <-time.After(surfaceMergeWindowMin):
				goto flush
			case <-s.svc.stopCh:
				return
			case <-s.surfaceStop:
				return
			}
		}
	flush:
		s.flushSurface()
	}
}

// flushSurface 取一帧要发的东西（锁内）并入队（锁外压缩；任务 2.2a/2.2b 的多腿版）。
//
// 锁纪律（design D2）：锁内只取快照与建体（cell 编码 ~100µs 量级），gzip/分片/入队全在锁外。
// 基线（base/hasBase）在**腿**上（2.2a）：掉队腿全量重建、健康腿继续差分、revision 各自对账。
// 脏标记的消费时机：本拍构建了任何载荷即 SurfaceClean（乐观消费）——入队失败/写失败都由
// needSnapshot 兜底全量重建，「宁可全量，不能半新半旧」的语义不变。
func (s *termSession) flushSurface() {
	s.mu.Lock()
	if s.done {
		s.mu.Unlock()
		return
	}
	sv := s.vt
	if sv == nil || !sv.Available() {
		s.mu.Unlock()
		return
	}
	legs := s.surfaceLegsLocked()
	if len(legs) == 0 {
		s.mu.Unlock()
		return
	}
	cols, rows := s.cols, s.rows
	title := s.scan.title

	// 回滚回落检测（任务 3.3 + 2026-10-03 平移判据）：非平移回落（距底/len 变化，行号语义
	// 不再纯平移）⇒ 该腿强制全量重建；平移型（真裁剪/erase 前缀）客户端自己平移缓存，
	// 差分继续。放在 takeSnapshotFlag 之前，这样它置的 needSnapshot 会被本拍消费。
	curSb := sv.SurfaceScrollbar()
	for _, c := range legs {
		if c.leg.noteScrollbar(curSb) {
			if s.svc.logf != nil {
				s.svc.logf("term: 会话 %s 回滚条非平移回落 ⇒ 强制全量重建（行号语义已变）", s.name)
			}
		}
	}

	// 每拍取一次脏行（所有 surface 腿共享同一份；2.2b）。changed 与 count>0 等价，
	// 不再单列——差分要不要发由「count>0 或腿基线有差异」决定（exec-r1 高1）。
	enc, count, st, _ := sv.SurfaceTick()

	type pending struct {
		c    *termClient
		op   byte
		body []byte
		st   SurfaceState
	}
	var outs []pending
	for _, c := range legs {
		force := c.leg.takeSnapshotFlag() || c.leg.underPressure()
		if !force {
			if !c.leg.hasBase || st.Alt != c.leg.base.Alt {
				// 首次基线缺失 / 备用屏进出（离开备用屏要重建主屏镜像）⇒ 该腿全量（2.2a）。
				c.leg.mu.Lock()
				c.leg.stats.degrades++
				c.leg.mu.Unlock()
				force = true
			}
		}
		switch {
		case force:
			body, st2 := s.buildSnapshotForLegLocked(c, sv, cols, rows, title)
			outs = append(outs, pending{c: c, op: opSnapshot, body: body, st: st2})
		default:
			// 差分（**count 可为 0**）：有脏行必发；无脏行时按**腿基线**判——光标/
			// 模式位/回滚条变化不产生脏行，但同样是一帧合法更新（「空行 patch」，
			// surfaceVer 4 语义；exec-r1 高1：只看脏行会让这些变化一帧都不发——
			// 2026-09-24 评审 P0 的回归，方向键光标不动/TUI 模式位滞后都是这条）。
			//（anyChange 为假时 count 必为 0，两条子条件等价于评审给的判定式。）
			if count == 0 && c.leg.stateUnchanged(st) {
				continue // 无脏行且该腿基线无差异 ⇒ 本腿整拍跳过
			}
			payload := encDiffBody(diffBody{
				Geometry: surfaceGeometry{Cols: cols, Rows: rows, Revision: c.leg.currentRevision()},
				Cursor:   surfaceCursorOf(st.Cursor),
				Modes:    st.Modes,
				Scroll:   scrollbar{Total: st.Total, Offset: st.Offset, Len: st.Len},
				Rows:     enc,
				RowCount: count,
			})
			outs = append(outs, pending{c: c, op: opSurfaceDiff, body: payload, st: st})
		}
	}
	if len(outs) > 0 {
		sv.SurfaceClean() // 乐观消费：入队/写失败由 needSnapshot 全量兜底
	}
	s.mu.Unlock()

	for _, p := range outs {
		if len(p.body) > s.pendingCap {
			// 失败模式一（单帧超上限，任务 4.3）：标记需全量、下一拍重试（既有语义）。
			p.c.leg.markNeedSnapshot("backpressure")
			continue
		}
		gz, err := gzipBytes(p.body)
		if err != nil {
			p.c.leg.markNeedSnapshot("encode_failed") // 低8（exec-r1）：计入 encodeFailed
			continue
		}
		items := make([]writeItem, 0, 2)
		for _, frag := range fragmentPayload(gz) {
			items = append(items, writeItem{op: p.op, payload: frag})
		}
		if p.op == opSnapshot {
			// 完成标志与分片同组入队（快照语义上是一段连续字节）。
			items = append(items, writeItem{op: opSnapshotDone,
				payload: encReplayDone(uint32(len(p.body)), 0)})
		}
		if !p.c.out.enqueueGroup(items, s.queueBytes) {
			// 失败模式二（队列积压超 perLegQueueBytes）：丢弃待发 + 标记需全量（新语义）。
			p.c.leg.markNeedSnapshot("queue_overflow")
			continue
		}
		p.c.leg.noteSent(p.op, items)
		p.c.leg.commitBaseline(p.st)
		// 回滚条基线随**成功入队的帧**推进（快照与差分都算）——noteScrollbar 的回落判据
		// 与客户端「上一帧已知的回滚条」对齐（2026-10-03：旧版只记快照时刻的 total，
		// 输出增长期间的回落全部漏判，全量抬高基线后又连锁触发风暴）。
		p.c.leg.noteSentScrollbar(vt.Scrollbar{Total: p.st.Total, Offset: p.st.Offset, Len: uint64(p.st.Len)})
	}
}

// buildSnapshotForLegLocked 组一条腿的全量快照体（**必须持会话锁**；2.2a：按腿参数化）。
//
// 推进**该腿**的 revision：客户端据此判定「快照之后收到的差分是新一代」。
// 同时返回本拍屏态（入队成功后由调用方 commitBaseline 到腿上）。
func (s *termSession) buildSnapshotForLegLocked(c *termClient, sv *sessionVT, cols, rows uint16, title string) ([]byte, SurfaceState) {
	rev := c.leg.nextRevision()
	st := sv.SurfaceStateNow()
	modes, kitty, misc := sv.SurfaceModes()
	body := snapshotBody{
		Geometry: surfaceGeometry{Cols: cols, Rows: rows, Revision: rev},
		Cursor:   surfaceCursorOf(st.Cursor),
		Modes:    modes,
		Kitty:    kitty,
		Misc:     misc,
		Title:    title,
		Scroll:   scrollbar{Total: st.Total, Offset: st.Offset, Len: st.Len},
		Grid:     sv.SurfaceGrid(cols, rows),
		// 镜像窗口：主屏才有意义（备用屏返回空，design D3 要求抑制）。
		Mirror: sv.SurfaceMirror(cols, rows, mirrorViewports),
	}
	// 回滚条基线不在这里记（2026-10-03 起）：noteSentScrollbar 在入队成功后统一推进
	// （本函数只建体；入队失败时基线不能前移，否则回落检测会漏判）。
	return encSnapshotBody(body), st
}

// handleFetchRows 处理 FETCH-ROWS 请求（任务 2.6）：锁内取行、锁外建帧入队
// （**应答走同一队列**——每腿唯一写者保证帧组原子性，任务 4.3）。
func (s *termSession) handleFetchRows(c *termClient, payload []byte) {
	req, err := decFetchRowsReq(payload)
	if err != nil {
		c.out.enqueue(writeItem{op: opError, payload: encError("bad_fetch", err.Error())}, 0)
		return
	}
	if req.Count > surfaceFetchRowsMax {
		req.Count = surfaceFetchRowsMax
	}
	s.mu.Lock()
	vt := s.vt
	if vt == nil || !vt.Available() || s.done {
		s.mu.Unlock()
		c.out.enqueue(writeItem{op: opError,
			payload: encError("surface_unavailable", "本会话没有服务端 vt")}, 0)
		return
	}
	cols, rows := s.cols, s.rows
	rev := c.leg.currentRevision()
	enc := vt.SurfaceRowsAt(req.From, int(req.Count))
	s.mu.Unlock()

	reply := fetchRowsReply{
		Geometry: surfaceGeometry{Cols: cols, Rows: rows, Revision: rev},
		From:     req.From,
		Count:    req.Count,
		Rows:     enc,
	}
	gz, gerr := gzipBytes(encFetchRowsReply(reply))
	if gerr != nil {
		return
	}
	items := make([]writeItem, 0, 2)
	for _, frag := range fragmentPayload(gz) {
		items = append(items, writeItem{op: opFetchRows, payload: frag})
	}
	if !c.out.enqueueGroup(items, s.queueBytes) {
		c.leg.markNeedSnapshot("queue_overflow")
		return
	}
	c.leg.noteFetchRows(len(enc) > 0)
}

// handleFetchSnapshot 处理 FETCH-SNAPSHOT（revision 断档/病态补丁被拒后客户端要全量）。
func (s *termSession) handleFetchSnapshot(c *termClient) {
	c.leg.markNeedSnapshot("client")
	s.wakeSurface()
}

// handleInput 处理抽象输入（任务 2.7）：服务端按 vt 真实模式编码成转义序列写进 PTY。
//
// 这是 vt 后端化的核心收益：kitty 协议/modifyOtherKeys/鼠标格式/括号粘贴全都只存在于出口
// 这一份 vt 里，客户端只上行「我按了哪个键」。输入 = 活动（design D4）。
func (s *termSession) handleInput(c *termClient, payload []byte) {
	ev, err := decInputEvent(payload)
	if err != nil {
		c.out.enqueue(writeItem{op: opError, payload: encError("bad_input", err.Error())}, 0)
		return
	}
	s.mu.Lock()
	// 输入 = 活动；输入不改腿尺寸 ⇒ 哨兵位无效果（传 false 表达「输入不注入哨兵」）。
	s.noteActivityLocked(c, false)
	vt := s.vt
	ptmx := s.ptmx
	done := s.done
	var out []byte
	if !done && vt != nil && vt.Available() {
		out = vt.EncodeInput(ev)
	}
	s.mu.Unlock()
	if done || ptmx == nil || len(out) == 0 {
		return
	}
	if _, werr := ptmx.Write(out); werr != nil {
		s.mu.Lock()
		s.endLegLocked(c, termEndNone, "", "ptmx_write_failed")
		s.mu.Unlock()
	}
}

// handleTheme 处理客户端主题上报（任务 2.7 + 3.3）：**记到腿上**，active 腿的主题才落
// 到会话 vt（OSC 10/11 查询按它应答）——多腿以最近活动腿为准。
func (s *termSession) handleTheme(c *termClient, payload []byte) {
	fg, bg, _, err := decTheme(payload)
	if err != nil {
		return // 主题是尽力而为的通道：坏帧不报错、不影响会话
	}
	s.mu.Lock()
	c.themeKnown = true
	c.themeFg, c.themeBg = fg, bg
	if s.active == c {
		if s.vt != nil && s.vt.Available() {
			s.vt.SetTheme(fg, bg)
		}
	}
	s.mu.Unlock()
}

// handleClipboardAnswer 处理客户端对剪贴板读请求的应答（任务 2.7 的读方向 + 3.3 归属）。
//
// 上游的读请求回调是**同步**的（请求句柄只在回调期间有效），所以服务端无法在里面等一次
// 客户端往返；这里把**上报腿**的内容缓存下来，active 腿的缓存即读请求的应答源。
func (s *termSession) handleClipboardAnswer(c *termClient, payload []byte) {
	text, err := decClipboardAnswer(payload)
	if err != nil {
		return
	}
	s.mu.Lock()
	c.clipCache = text
	if s.active == c {
		copied := text
		s.clipCachePub.Store(&copied) // 原子发布：读回调（锁外）用它
	}
	s.mu.Unlock()
}

// notifyFromScan 把 termScan 抓到的裸 OSC 9 通知转发给**所有 surface 腿**（任务 2.1b/2.7）。
//
// 从扫描器取而不是从 vt 回调取：OSC 9 的双语义判别（9;4 = progress）已经在 termScan 里做完了，
// 而且这条腿不需要装 vt 回调（少一个 cgo 回调面）。raw 腿**不发**（字节流自带该序列）。
// lastNotified 是会话级去重（surface 腿集合派生的状态，2.1b）。
func (s *termSession) notifyFromScan() {
	s.mu.Lock()
	text := s.scan.Notify()
	legs := s.surfaceLegsLocked()
	if text == "" || text == s.lastNotified || len(legs) == 0 {
		s.mu.Unlock()
		return
	}
	s.lastNotified = text
	s.mu.Unlock()
	for _, c := range legs {
		c.out.enqueue(writeItem{op: opNotify, payload: encNotify(text)}, s.queueBytes)
	}
}

// vtSessionRegistry 是 vt 终端 id → 会话的映射（剪贴板回调的分派表）。
var vtSessionRegistry = struct {
	sync.Mutex
	m map[uintptr]*termSession
}{m: map[uintptr]*termSession{}}

func registerVTSession(id uintptr, s *termSession) {
	if id == 0 {
		return
	}
	vtSessionRegistry.Lock()
	vtSessionRegistry.m[id] = s
	vtSessionRegistry.Unlock()
}

func unregisterVTSession(id uintptr) {
	vtSessionRegistry.Lock()
	delete(vtSessionRegistry.m, id)
	vtSessionRegistry.Unlock()
}

func sessionByVTID(id uintptr) *termSession {
	vtSessionRegistry.Lock()
	defer vtSessionRegistry.Unlock()
	return vtSessionRegistry.m[id]
}

// clipboardRouter 把「程序写剪贴板」的回调按终端 id 分派到对应会话。
//
// 为什么需要路由：上游的剪贴板写回调是进程级的（回调只带 userdata = 我们注册的整数 id），
// 所以这里维护 id → 会话的映射，收到内容后转成 CLIPBOARD 帧发给该会话的 surface 腿。
// （两个构建变体共用这份定义：无 vt 的构建里 installClipboardForwarder 是空操作 ⇒
// 注册表为空，回调不会被触发。）
// clipboardReadRouter 是「程序读剪贴板」的同步应答（任务 2.7 的读方向）。
//
// ⚠️ 这个回调在 vt.Write 内部**同步**触发，而 pump 调 vt.Write 时正持着会话锁
// ⇒ **绝不能在这里取会话锁**（自死锁，与 clipboardRouter 同一条纪律）。所以只读一个
// 原子发布的快照（读方向要的是「最近一次已知内容」，字面量字符串的原子替换足够）。
// clipCacheSnapshot 读最近上报的剪贴板内容（无锁；只在读回调里用）。
func (s *termSession) clipCacheSnapshot() string {
	if p := s.clipCachePub.Load(); p != nil {
		return *p
	}
	return ""
}

func clipboardReadRouter(id uintptr, location int) (string, bool) {
	s := sessionByVTID(id)
	if s == nil {
		return "", false
	}
	if location != 0 { // 0 = clipboard；primary selection 我们没有数据源
		return "", false
	}
	return s.clipCacheSnapshot(), true
}

func clipboardRouter(id uintptr, text string) bool {
	s := sessionByVTID(id)
	if s == nil {
		return false
	}
	// ⚠️ **绝不能在这里持会话锁**：回调是在 vt.Write 内部同步触发的，而 pump 调 vt.Write 时
	// 正持着会话锁 ⇒ 再锁一次就是自死锁（实测：整条会话卡死、连收尾的 cmd.Wait 都不返回）。
	// 所以这里只做「非阻塞投递到通道」，实际发帧由投递循环（另一个 goroutine）完成。
	// surfaceActive 是原子标志（腿集合派生，2.1b），专为这种「锁外快速判断」准备。
	if !s.surfaceActive.Load() {
		return false // 没有 surface 腿：拒绝这次写（客户端拿不到内容，不能假装成功）
	}
	select {
	case s.clipChan <- text:
		return true
	default:
		return false // 通道满：宁可拒绝，也不阻塞 VT 流
	}
}
