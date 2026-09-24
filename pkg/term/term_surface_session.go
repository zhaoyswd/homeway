//go:build !windows

// term_surface_session.go — surface 的会话侧编排（任务 2.3–2.7）。
//
// 分工：线格式在 term_surface.go，腿的投递与背压在 term_surface_leg.go，
// 这里负责「什么时候发什么」与「收到上行帧怎么处理」。
//
// 节奏（2.5）：PTY 有输出 ⇒ pump 在锁内喂完 vt 后 `wakeSurface()`；投递循环被唤醒后
// 先睡一个**合并窗**（窗内再来唤醒就顺延到上限），再把这一窗的脏行并成一帧发出去。
// 这样高频小输出不会变成高频小帧，而子进程也永远不会等投递（投递在独立 goroutine）。
package term

import (
	"sync"
	"time"
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

// surfaceLoop 投递循环（每会话一条；会话结束时随 stopCh 退出）。
func (s *termSession) surfaceLoop() {
	for {
		select {
		case <-s.svc.stopCh:
			return
		case text := <-s.clipChan:
			// 剪贴板写（OSC 52）：立即下发，不参与脏行合并窗。
			s.mu.Lock()
			c := s.attached
			ok := c != nil && c.surface && c.leg != nil
			s.mu.Unlock()
			if ok && !c.leg.sendClipboard(c, encClipboard(clipKindWrite, text)) {
				s.mu.Lock()
				if s.attached == c {
					s.detachLocked(c)
				}
				s.mu.Unlock()
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
			}
		}
	flush:
		s.flushSurface()
	}
}

// flushSurface 取一帧要发的东西（锁内）并下发（锁外）。
func (s *termSession) flushSurface() {
	s.mu.Lock()
	c := s.attached
	if c == nil || !c.surface || c.leg == nil || s.done {
		s.mu.Unlock()
		return
	}
	vt := s.vt
	if vt == nil || !vt.Available() {
		s.mu.Unlock()
		return
	}
	cols, rows := s.cols, s.rows
	title := s.scan.title

	// 回滚裁剪检测（任务 3.3）：total 变小 ⇒ 绝对行号滑动 ⇒ 本拍强制全量重建镜像与基线。
	// 放在 takeSnapshotFlag 之前，这样它置的 needSnapshot 会被本拍消费。
	if c.leg.noteScrollbar(vt.SurfaceScrollbar().Total) {
		// 判据行：回滚裁剪（page 粒度）导致行号滑动 ⇒ 重建基线（客户端缓存随之作废）。
		if s.svc.logf != nil {
			s.svc.logf("term: 会话 %s 回滚裁剪 ⇒ 强制全量重建（绝对行号已滑动）", s.name)
		}
	}

	// 全量还是差分：首次/背压/降级/备用屏切换/回滚裁剪都走全量。
	forceSnap := c.leg.takeSnapshotFlag() || c.leg.underPressure()
	var (
		op      byte
		payload []byte
		skip    bool
	)
	if forceSnap {
		op, payload = opSnapshot, s.buildSnapshotLocked(vt, cols, rows, title)
	} else {
		enc, count, full := vt.SurfaceDiff(cols, rows)
		switch {
		case count == 0 && !full:
			skip = true // 没有脏行（可能是别人先消费了脏状态）
		case full:
			c.leg.mu.Lock()
			c.leg.stats.degrades++
			c.leg.mu.Unlock()
			op, payload = opSnapshot, s.buildSnapshotLocked(vt, cols, rows, title)
		default:
			op = opSurfaceDiff
			payload = encDiffBody(diffBody{
				Geometry: surfaceGeometry{Cols: cols, Rows: rows, Revision: c.leg.currentRevision()},
				// 光标取**同一拍**（SurfaceDiff 已经把 render state 更新过了，这里读的就是本帧的
				// 光标；顺序反了会拿到上一拍的位置）。
				Cursor:   vt.SurfaceCursor(),
				Rows:     enc,
				RowCount: count,
			})
		}
	}
	s.mu.Unlock()

	if skip {
		return
	}
	// 锁外：gzip + 分片 + 写（耗时大头，绝不能占着会话锁）。
	var ok bool
	if op == opSnapshot {
		ok = c.leg.sendSnapshot(c, payload)
	} else {
		ok = c.leg.sendDiff(c, payload)
	}
	if !ok {
		// 写失败/超时 ⇒ 断该腿（会话存续，客户端走断线重连路径）。
		s.mu.Lock()
		if s.attached == c {
			s.detachLocked(c)
		}
		s.mu.Unlock()
		return
	}
	// 成功下发后才消费脏标记：中途失败则下一拍重来（宁可重复，不能半新半旧）。
	s.mu.Lock()
	vt.SurfaceClean()
	s.mu.Unlock()
}

// buildSnapshotLocked 组一次全量快照的体（**必须持会话锁**）。
//
// 推进 revision：客户端据此判定「快照之后收到的差分是新一代」（SNAPSHOT 隐含重置 revision 基线）。
func (s *termSession) buildSnapshotLocked(vt *sessionVT, cols, rows uint16, title string) []byte {
	rev := s.attached.leg.nextRevision()
	modes, kitty, misc := vt.SurfaceModes()
	sb := vt.SurfaceScrollbar()
	body := snapshotBody{
		Geometry: surfaceGeometry{Cols: cols, Rows: rows, Revision: rev},
		Cursor:   vt.SurfaceCursor(),
		Modes:    modes,
		Kitty:    kitty,
		Misc:     misc,
		Title:    title,
		Scroll:   scrollbar{Total: sb.Total, Offset: sb.Offset, Len: uint16(sb.Len)},
		Grid:     vt.SurfaceGrid(cols, rows),
		// 镜像窗口：主屏才有意义（备用屏返回空，design D3 要求抑制）。
		Mirror: vt.SurfaceMirror(cols, rows, mirrorViewports),
	}
	// 记下这一代的 total：回滚裁剪（page 粒度，探针实测 4000 行时 total 从 2001 掉到 1719）
	// 会让**绝对行号滑动** ⇒ 客户端缓存的镜像/拉取行全部失锚。判据用「total 变小」——
	// total 只在裁剪时减少（写入时只增或持平），比盯页边界可靠。
	if s.attached != nil && s.attached.leg != nil {
		s.attached.leg.mu.Lock()
		s.attached.leg.lastSnapTotal = sb.Total
		s.attached.leg.hasSnapTotal = true
		s.attached.leg.mu.Unlock()
	}
	return encSnapshotBody(body)
}

// handleFetchRows 处理 FETCH-ROWS 请求（任务 2.6）：锁内取行、锁外下发。
func (s *termSession) handleFetchRows(c *termClient, payload []byte) {
	req, err := decFetchRowsReq(payload)
	if err != nil {
		_ = c.frame(opError, encError("bad_fetch", err.Error()))
		return
	}
	if req.Count > surfaceFetchRowsMax {
		req.Count = surfaceFetchRowsMax
	}
	s.mu.Lock()
	vt := s.vt
	if vt == nil || !vt.Available() || s.done {
		s.mu.Unlock()
		_ = c.frame(opError, encError("surface_unavailable", "本会话没有服务端 vt"))
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
	if !c.leg.sendFetchRows(c, reply, len(enc) > 0) {
		s.mu.Lock()
		if s.attached == c {
			s.detachLocked(c)
		}
		s.mu.Unlock()
	}
}

// handleFetchSnapshot 处理 FETCH-SNAPSHOT（revision 断档/病态补丁被拒后客户端要全量）。
func (s *termSession) handleFetchSnapshot(c *termClient) {
	c.leg.markNeedSnapshot("client")
	s.wakeSurface()
}

// handleInput 处理抽象输入（任务 2.7）：服务端按 vt 真实模式编码成转义序列写进 PTY。
//
// 这是 vt 后端化的核心收益：kitty 协议/modifyOtherKeys/鼠标格式/括号粘贴全都只存在于出口
// 这一份 vt 里，客户端只上行「我按了哪个键」。
func (s *termSession) handleInput(c *termClient, payload []byte) {
	ev, err := decInputEvent(payload)
	if err != nil {
		_ = c.frame(opError, encError("bad_input", err.Error()))
		return
	}
	s.mu.Lock()
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
		if s.attached == c {
			s.detachLocked(c)
		}
		s.mu.Unlock()
	}
}

// handleTheme 处理客户端主题上报（任务 2.7）：默认前景/背景交给 vt，OSC 10/11 查询按它应答。
func (s *termSession) handleTheme(payload []byte) {
	fg, bg, dark, err := decTheme(payload)
	if err != nil {
		return // 主题是尽力而为的通道：坏帧不报错、不影响会话
	}
	s.mu.Lock()
	vt := s.vt
	if vt != nil && vt.Available() {
		vt.SetTheme(fg, bg)
	}
	s.darkTheme = dark
	s.mu.Unlock()
}

// handleClipboardAnswer 处理客户端对剪贴板读请求的应答（任务 2.7 的读方向）。
//
// 上游的读请求回调是**同步**的（请求句柄只在回调期间有效），所以服务端无法在里面等一次
// 客户端往返；这里把客户端最近一次上报的内容缓存下来，读请求命中缓存即答。
func (s *termSession) handleClipboardAnswer(payload []byte) {
	text, err := decClipboardAnswer(payload)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.clipCache = text
	copied := text
	s.clipCachePub.Store(&copied) // 原子发布：读回调（锁外）用它
	s.mu.Unlock()
}

// handleSurfaceResize 处理 surface 腿的尺寸变化（任务 2.6）：
// vt 重排 → 尺寸哨兵（逼远端 TUI 按新尺寸重绘）→ 下一帧全量快照（隐含重建镜像 + 重置 revision）。
func (s *termSession) handleSurfaceResize(c *termClient, cols, rows uint16) {
	s.resize(cols, rows)
	s.sentinelRepaint()
	c.leg.markNeedSnapshot("resize")
	s.wakeSurface()
}

// notifyFromScan 把 termScan 抓到的裸 OSC 9 通知转发给 surface 腿（任务 2.7）。
//
// 从扫描器取而不是从 vt 回调取：OSC 9 的双语义判别（9;4 = progress）已经在 termScan 里做完了，
// 而且这条腿不需要装 vt 回调（少一个 cgo 回调面）。
func (s *termSession) notifyFromScan() {
	s.mu.Lock()
	c := s.attached
	text := s.scan.Notify()
	if c == nil || !c.surface || c.leg == nil || text == "" || text == s.lastNotified {
		s.mu.Unlock()
		return
	}
	s.lastNotified = text
	s.mu.Unlock()
	if !c.leg.sendNotify(c, encNotify(text)) {
		s.mu.Lock()
		if s.attached == c {
			s.detachLocked(c)
		}
		s.mu.Unlock()
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
// （无 vt 的构建里 clipboardRouter 是空实现，见 term_vt_off.go 的同名声明。）
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
	// surfaceActive 是原子标志，专为这种「锁外快速判断」准备。
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
