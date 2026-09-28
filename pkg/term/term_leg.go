//go:build !windows

// term_leg.go — 多腿会话模型的核心（term-host-cli 任务组 2–5）。
//
// 一条会话允许**多条腿**同时在场（raw 与 surface 混合，上限 HOMEWAY_TERM_MAX_CLIENTS）：
//   - 注册/摘除只发生在会话锁内（D10-4），所有 detach 路径汇到 endLegLocked（幂等「只摘一次」）；
//   - **每腿一个写者 goroutine + 有界队列**（design D5/B'）：会话级生产者（pump / surfaceLoop /
//     读循环的应答）只入队、永不阻塞——任一条腿的缓慢/停滞不影响子进程与其它腿；
//   - conn 的关闭权归写者（送达 ENDED 后 close，D10-3）；ENDED 原因词表见 frames.go（D8）；
//   - 会话级派生状态（尺寸/主题/剪贴板）以**最近活动的腿**为准（design D4：单调到达序号 +
//     固定 tie-break「更晚接入者优先」）。
//
// 锁序（D10-1）：session.mu → legOut.mu。写者绝不在持有 legOut.mu 时取会话锁。
package term

import (
	"sync"
	"time"

	"github.com/creack/pty"
)

// ---- 腿的出站队列 ----

// writeItem 是写者要发的一帧。
type writeItem struct {
	op      byte
	payload []byte
}

// legOut 是一条腿的出站状态（legOut.mu 保护；wake 也归它）。
//
// raw 腿的「队列」语义与 surface 不同：实时字节不排队——写者直接从会话字节环按本腿 off
// 读取（D10-2：off 只由写者推进），队列里只有控制帧（STATE / ERROR 回执）；attach 回放由
// 写者按握手计划执行（连同 ATTACHED / REPLAY-DONE，D10-6）。surface 腿的全部下行帧都入队，
// 队列体积由 perLegQueueBytes 封顶（任务 4.3 的第二种失败模式）。
type legOut struct {
	mu     sync.Mutex
	queue  []writeItem
	qbytes int
	// ended 是收尾帧（ENDED）：队列排空后由写者发出、然后关 conn。
	ended *writeItem
	// quit = 立即收尾（不发 ENDED：硬错误 / 客户端已关）。
	quit bool
	// closedForProd 在收尾后置位：生产者（flush / 读循环应答）据此丢弃入队，防泄漏。
	closedForProd bool
	// stalled / stalledSince 是 raw 腿的停滞记账（任务 4.2：写超时 ≠ 死亡）。
	stalled      bool
	stalledSince time.Time

	wake chan struct{}
}

func newLegOut() legOut { return legOut{wake: make(chan struct{}, 1)} }

func (o *legOut) wakeWriter() {
	select {
	case o.wake <- struct{}{}:
	default:
	}
}

// enqueue 入队一帧。surface 腿受 perLegQueueBytes 封顶（超限返回 false = 丢弃待发，
// 调用方 markNeedSnapshot）；raw 腿的控制帧不受体积封顶（STATE 走 enqueueState 的
// latest-wins 通道，不会堆积）。ended/quit 之后一律拒绝。
func (o *legOut) enqueue(it writeItem, capBytes int) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closedForProd {
		return false
	}
	if capBytes > 0 && o.qbytes+len(it.payload) > capBytes {
		return false // 队列积压超上限：丢弃待发 + 调用方标记需全量（任务 4.3）
	}
	o.queue = append(o.queue, it)
	o.qbytes += len(it.payload)
	o.wakeWriter()
	return true
}

// enqueueGroup 原子入队一组帧（快照 = 分片 + DONE）。整组要么全进、要么全弃。
func (o *legOut) enqueueGroup(items []writeItem, capBytes int) bool {
	if len(items) == 0 {
		return true
	}
	total := 0
	for _, it := range items {
		total += len(it.payload)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closedForProd {
		return false
	}
	if capBytes > 0 && o.qbytes+total > capBytes {
		return false
	}
	o.queue = append(o.queue, items...)
	o.qbytes += total
	o.wakeWriter()
	return true
}

// enqueueState 入队 STATE 帧（latest-wins：丢掉还在排队的旧 STATE——状态只有最新值有意义，
// 与旧 stateChan 的缓冲 1 同语义）。
func (o *legOut) enqueueState(it writeItem) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closedForProd {
		return
	}
	out := o.queue[:0]
	for _, old := range o.queue {
		if old.op == opState {
			o.qbytes -= len(old.payload)
			continue
		}
		out = append(out, old)
	}
	o.queue = append(out, it)
	o.qbytes += len(it.payload)
	o.wakeWriter()
}

// finishEnded 安排收尾帧（ENDED）：写者排空队列后发出、再关 conn（ENDED 先于 close，任务 4.1）。
func (o *legOut) finishEnded(code int32, reason string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closedForProd = true
	o.ended = &writeItem{op: opEnded, payload: encEnded(code, reason)}
	o.wakeWriter()
}

// finishQuit 立即收尾（不发 ENDED）：排空即关。
func (o *legOut) finishQuit() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closedForProd = true
	o.quit = true
	o.wakeWriter()
}

// take 取走待发队列；ended 只在队列排空时交出（保证 ENDED 之前不再插帧）。
func (o *legOut) take() (items []writeItem, ended *writeItem, quit bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.quit {
		return nil, nil, true
	}
	items = o.queue
	o.queue = nil
	o.qbytes = 0
	if len(items) == 0 {
		return nil, o.ended, false
	}
	return items, nil, false
}

// noteStall 记录一次写停滞/恢复；返回停滞是否已连续超过 limit（= 该断腿了）。
func (o *legOut) noteStall(stalled bool, limit time.Duration) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if stalled {
		if !o.stalled {
			o.stalled = true
			o.stalledSince = time.Now()
		}
		return time.Since(o.stalledSince) > limit
	}
	o.stalled = false
	return false
}

// isStalled 读当前停滞位（上限淘汰策略用，任务 2.4）。
func (o *legOut) isStalled() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.stalled
}

// stalledFor 读已停滞多久（淘汰排序用）。
func (o *legOut) stalledFor() time.Duration {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.stalled {
		return 0
	}
	return time.Since(o.stalledSince)
}

// ---- raw 腿的握手计划（写者执行；锁内构建）----

// rawHandshake 是 attach 时（会话锁内）算好的回放计划：写者按它发
// ATTACHED → 换屏前序 → 回放 DATA（预算内）→ REPLAY-DONE → 实时流（D10-6）。
type rawHandshake struct {
	attached  []byte  // ATTACHED 载荷
	start     int64   // 回放起点（绝对偏移）
	end       int64   // 回放终点（attach 时刻的 written）
	truncated bool    // 构建期已截断（尾部窗口超上限）
	epochs    []int64 // 窗口内的尺寸变化点（REPLAY-DONE flags bit1 用）
	budget    time.Duration
	// nudgeFocus：本腿是首腿 ⇒ 回放完成后注入 focus-in（2.1a；surface 腿不吃这个——
	// 它的重绘靠尺寸哨兵 + 快照，旧路径本来就不给 surface 腿发 focus nudge）。
	nudgeFocus bool
}

// ---- 写者（D5：每腿一个；conn 关闭权在这里）----

// runLegWriter 每条腿一个写者 goroutine（stream 在注册成功后启动）。
func (s *termSession) runLegWriter(c *termClient) {
	if c.surface {
		s.runSurfaceWriter(c)
		return
	}
	s.runRawWriter(c)
}

// writeFrameOnce 写一帧（带写超时——raw 腿传会话级 writeTimeout，surface 腿沿用全局
// termWriteTimeout，既有语义不动）。只在写者 goroutine 里调用。
func (c *termClient) writeFrameOnce(op byte, payload []byte, timeout time.Duration) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err := c.conn.Write(encodeTermFrame(op, payload))
	return err
}

// runSurfaceWriter：出队 → 写 → 收尾。surface 腿的写失败（含超时）= 断腿（既有语义，
// 任务 4.3 只对 raw 腿引入停滞语义）。
func (s *termSession) runSurfaceWriter(c *termClient) {
	for {
		items, ended, quit := c.out.take()
		for _, it := range items {
			if err := c.writeFrameOnce(it.op, it.payload, termWriteTimeout); err != nil {
				s.legWriteFailed(c, err)
				return
			}
		}
		if ended != nil {
			_ = c.writeFrameOnce(ended.op, ended.payload, termWriteTimeout)
			_ = c.conn.Close()
			return
		}
		if quit {
			_ = c.conn.Close()
			return
		}
		if len(items) > 0 {
			continue // 队列可能又有货（或收尾标志刚置位），先再取一轮
		}
		<-c.out.wake
	}
}

// runRawWriter：握手（ATTACHED/回放/REPLAY-DONE）→ 实时（队列控制帧 + 字节环）。
// 停滞语义（任务 4.2 / D10-7）：写超时只标记落后并退避重试（恢复后从可用起点续投），
// **不得**在超时分支 close 或发 ENDED；只有硬错误或连续停滞超 termRawStallLimit 才断腿
// （断腿不发 ENDED——客户端看到裸 EOF）。
func (s *termSession) runRawWriter(c *termClient) {
	hs := c.handshake
	if !s.rawWriteFrame(c, opAttached, hs.attached) {
		return
	}
	if !s.rawWriteFrame(c, opData, []byte("\x1b[3J\x1b[2J\x1b[H")) {
		return // 换屏前序：客户端 vt 是新建的，回放起点要确定
	}
	// 回放：锁内读环、锁外写；时间预算用尽就跳到实时（丢头部保尾部）。
	sent, replayed := hs.start, 0
	deadline := time.Now().Add(hs.budget)
	for sent < hs.end {
		chunk, ok := s.nextRingChunk(c, &sent, termDataChunk)
		if !ok || len(chunk) == 0 {
			break
		}
		if !s.rawWriteFrame(c, opData, chunk) {
			return
		}
		replayed += len(chunk)
		if time.Now().After(deadline) && sent < hs.end {
			break // 预算用尽：剩余历史直接跳过，从「现在」接实时流
		}
	}
	truncated := hs.truncated || sent < hs.end
	flags := byte(0)
	if truncated {
		flags |= replayFlagTruncated
	}
	for _, e := range hs.epochs {
		if e > hs.start && e < sent {
			flags |= replayFlagSizeChange
			break
		}
	}
	if !s.rawWriteFrame(c, opReplayDone, encReplayDone(uint32(replayed), flags)) {
		return
	}
	// 实时起点：预算用尽 ⇒ 剩余回放窗口直接跳过（丢头部保尾部）；否则 sent == hs.end。
	// 回放期间新产生的字节 [hs.end, s.written) 由实时循环从环里接上。
	c.off = hs.end
	if hs.nudgeFocus {
		// 首腿：回放完成后注入 focus-in，逼 TUI 立即全屏重绘（见 focusNudgeLocked 注释）。
		s.mu.Lock()
		s.focusNudgeLocked(true)
		s.mu.Unlock()
	}

	// 实时循环：控制帧（STATE/ERROR/ENDED）优先、字节环随后。
	//
	// 停滞语义（exec-r1 高2 修正）：停滞期间**仍取环尝试写**——退避 sleep 放在写尝试
	// 之前、绝不 continue 跳过环读取；否则一旦写超时而之后没有 STATE 类帧，这条腿就
	// 永久哑掉（恢复读取也唤不醒），且停滞上限兜底永远不触发。恢复 = 写成功 ⇒ 清停滞位
	// ⇒ peekRingChunk 的有界追赶接管；连续停滞超 rawStallLimit 才断腿（不发 ENDED）。
	for {
		items, ended, quit := c.out.take()
		for _, it := range items {
			if !s.rawWriteFrame(c, it.op, it.payload) {
				return
			}
		}
		if ended != nil {
			_ = s.rawWriteFrame(c, ended.op, ended.payload)
			_ = c.conn.Close()
			return
		}
		if quit {
			_ = c.conn.Close()
			return
		}
		if len(items) > 0 {
			continue
		}
		if c.out.isStalled() {
			time.Sleep(s.stallRetryBackoff()) // 退避放写前：停一拍再试，而不是跳过写
		}
		chunk, ok := s.peekRingChunk(c, termDataChunk)
		if !ok {
			// 腿已被会话侧收尾（finish/接管/淘汰）：控制队列里可能还压着 ENDED——
			// **排空再退出**（ENDED 先于 close，任务 4.1；quit = 无 ENDED 的直接关）。
			items, ended, _ := c.out.take()
			for _, it := range items {
				if !s.rawWriteFrame(c, it.op, it.payload) {
					return
				}
			}
			if ended != nil {
				_ = s.rawWriteFrame(c, ended.op, ended.payload)
			}
			_ = c.conn.Close()
			return
		}
		if len(chunk) > 0 {
			if !s.rawWriteFrame(c, opData, chunk) {
				return
			}
			c.commitRingChunk(s, len(chunk)) // 写成功才推进 off（停滞重试重写同一片）
			continue
		}
		if c.out.isStalled() {
			continue // 停滞中且暂无数据：回环再退避（不睡死在 wake 上）
		}
		<-c.out.wake
	}
}

// stallRetryBackoff 停滞退避节拍：默认 1s；停滞上限较短时（测试注入）自适应缩短到
// 上限的 1/4，保证「连续停滞超限」在每个退避周期都被判定到（exec-r1 高2）。
func (s *termSession) stallRetryBackoff() time.Duration {
	if r := s.rawStallLimit / 4; r > 0 && r < termRawStallRetry {
		return r
	}
	return termRawStallRetry
}

// peekRingChunk 在会话锁内取本腿下一片环数据（**不推进 off**——写出成功才由
// commitRingChunk 提交；exec-r1 高2：停滞重试要重写同一片，不能在写失败时悄悄跳过）。
// ok=false = 腿已摘/会话已收工。落后超过一个回放窗口时**有界追赶**（跳到
// written-replay：停滞恢复不灌整环历史，D5「跳环续投」的落点）。
func (s *termSession) peekRingChunk(c *termClient, max int) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.removed || s.done {
		return nil, false
	}
	if budget := int64(s.svc.cfg.replay); budget > 0 && s.written-c.off > budget {
		c.off = s.written - budget
	}
	if c.off < s.start {
		c.off = s.start // 落后被环覆盖：跳到可用起点（宁可丢也不阻塞）
	}
	if c.off >= s.written {
		return nil, true
	}
	return s.readLocked(c.off, max), true
}

// commitRingChunk 写出成功后推进本腿 off（D10-2：只由本腿写者调用）。
func (c *termClient) commitRingChunk(s *termSession, n int) {
	if n <= 0 {
		return
	}
	s.mu.Lock()
	c.off += int64(n)
	if c.off > s.written {
		c.off = s.written
	}
	s.mu.Unlock()
}

// nextRingChunk 在会话锁内从字节环读 ≤max 字节并推进 *off（D10-2：off 只由本腿写者推进）。
// ok=false 表示腿已摘/会话已收工，写者应退出。
func (s *termSession) nextRingChunk(c *termClient, off *int64, max int) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.removed || s.done {
		return nil, false
	}
	if *off < s.start {
		*off = s.start // 落后被环覆盖：跳到可用起点（宁可丢也不阻塞）
	}
	if *off >= s.written {
		return nil, true
	}
	chunk := s.readLocked(*off, max)
	*off += int64(len(chunk))
	return chunk, true
}

// rawWriteFrame 写一帧到 raw 腿（停滞感知；超时/停滞上限用会话级参数，exec-r1 高2）。
// 返回 false = 写者收工。
func (s *termSession) rawWriteFrame(c *termClient, op byte, payload []byte) bool {
	err := c.writeFrameOnce(op, payload, s.writeTimeout)
	if err == nil {
		s.recoverFromStall(c)
		return true
	}
	if isWriteTimeout(err) {
		// 停滞：标记落后、退避重试（D10-7：绝不能在这里 close/发 ENDED）。
		if c.out.noteStall(true, s.rawStallLimit) {
			s.breakLeg(c, "stalled_over_limit")
			return false
		}
		if s.svc.logf != nil {
			s.svc.logf("term: 会话 %s raw 腿（%s）写停滞，退避重试（不断腿）", s.name, c.kind)
		}
		return true // 外层循环负责退避与续投
	}
	s.legWriteFailed(c, err)
	return false
}

// recoverFromStall 写成功后清停滞位（续投的有界追赶在 peekRingChunk 里统一做——
// 落后超过一个回放窗口就跳到 written-replay，exec-r1 高2）。
func (s *termSession) recoverFromStall(c *termClient) {
	if c.out.isStalled() {
		c.out.noteStall(false, s.rawStallLimit)
	}
}

// isWriteTimeout 区分写超时（停滞）与硬错误。
func isWriteTimeout(err error) bool {
	type timeouter interface{ Timeout() bool }
	if te, ok := err.(timeouter); ok {
		return te.Timeout()
	}
	return false
}

// legWriteFailed 写失败（硬错误）= 断腿：摘除（幂等）+ 关连接；**不发 ENDED**（任务 7.5：
// 客户端看到裸 EOF，CLI 给可行动文案）。surface/raw 共用。
func (s *termSession) legWriteFailed(c *termClient, err error) {
	if c.surface && c.leg != nil {
		c.leg.noteWriteFailure()
	}
	c.out.finishQuit()
	_ = c.conn.Close()
	s.mu.Lock()
	reason := "write_failed"
	if isWriteTimeout(err) {
		reason = "write_timeout"
	}
	s.endLegLocked(c, termEndNone, "", reason)
	s.mu.Unlock()
}

// breakLeg 服务端主动断腿（停滞超限等）：同 legWriteFailed 的收尾路径。
func (s *termSession) breakLeg(c *termClient, reason string) {
	c.out.finishQuit()
	_ = c.conn.Close()
	s.mu.Lock()
	s.endLegLocked(c, termEndNone, "", reason)
	s.mu.Unlock()
}

// ---- 腿的注册 / 摘除（会话锁内）----

// registerLegLocked 把腿接入会话（任务 2.1a/2.3/2.4）。调用方持 s.mu；成功后由 stream
// 启动写者。顺序：① 同实例替换（ENDED self_reconnect）→ ② 显式接管（ENDED replaced）
// → ③ 上限腾位（淘汰停滞/最久空闲腿）→ ④ 入表 + 活动选举（接入即活动）。
func (s *termSession) registerLegLocked(c *termClient, takeover bool) *termErr {
	if s.done {
		return termErrf("no_session", "会话 %s 已结束", s.name)
	}
	if c.clientID != "" {
		for _, old := range append([]*termClient{}, s.legs...) {
			if old.clientID == c.clientID {
				s.endLegLocked(old, termEndReplaced, termReasonSelfReconnect, "self_reconnect")
			}
		}
	}
	if takeover {
		for _, old := range append([]*termClient{}, s.legs...) {
			s.endLegLocked(old, termEndReplaced, termReasonReplaced, "takeover")
		}
	}
	if len(s.legs) >= s.svc.cfg.maxClients {
		s.evictForSlotLocked()
	}
	if len(s.legs) >= s.svc.cfg.maxClients {
		return termErrf("too_many_clients",
			"会话 %s 的客户端腿数已达上限 %d；可用 -d 显式接管，或先分离其它客户端", s.name, s.svc.cfg.maxClients)
	}
	first := len(s.legs) == 0
	s.legs = append(s.legs, c)
	s.attachSeq++
	c.attachSeq = s.attachSeq
	c.since = time.Now()
	if c.rawCapable {
		s.rawTermLegs++
	}
	if c.surface {
		// ATTACHED 先入队再继续（D10-6：首帧必须 ATTACHED——此刻腿已在表内，但所有
		// 生产者都要拿会话锁，而我们正持着，不可能有帧插到它前面）。
		c.out.enqueue(writeItem{op: opAttached, payload: encAttached(s.cols, s.rows, s.scan.modes,
			s.agent, stateForLeg(true, s.stateV2, s.state), s.name)}, 0)
		c.leg.markNeedSnapshot("attach")
	} else {
		c.handshake = s.buildRawHandshakeLocked(c, first)
	}
	// 接入即活动（design D4）：选举 → 尺寸应用 → 全 surface 腿标记全量。
	// 哨兵传 false：attach 的尺寸哨兵由 stream 统一注入一次（低7：一次 attach 一次哨兵）。
	s.noteActivityLocked(c, false)
	s.surfaceActive.Store(s.anySurfaceLocked())
	s.updateResponseSinkLocked()
	if s.svc.logf != nil {
		s.svc.logf("term: 会话 %s 腿接入（kind=%s %dx%d id=%s 首腿=%v）n=%d/%d",
			s.name, c.kind, c.cols, c.rows, idDesc(c.clientID), first, len(s.legs), s.svc.cfg.maxClients)
	}
	return nil
}

func idDesc(id string) string {
	if id == "" {
		return "-"
	}
	return id
}

// buildRawHandshakeLocked 构建 raw 腿的握手计划（回放窗口 + 预算 + ATTACHED 载荷）。
func (s *termSession) buildRawHandshakeLocked(c *termClient, first bool) *rawHandshake {
	start, truncated := s.replayStartLocked()
	return &rawHandshake{
		attached: encAttached(s.cols, s.rows, s.scan.modes, s.agent,
			stateForLeg(false, s.stateV2, s.state), s.name),
		start:      start,
		end:        s.written,
		truncated:  truncated,
		epochs:     s.epochOffsetsLocked(),
		budget:     termReplayBudget,
		nudgeFocus: first,
	}
}

// epochOffsetsLocked 取回放窗口附近的尺寸变化点（快照给写者判 flags 用）。
func (s *termSession) epochOffsetsLocked() []int64 {
	out := make([]int64, 0, len(s.epochs))
	for _, e := range s.epochs {
		out = append(out, e.off)
	}
	return out
}

// endLegLocked 摘腿（任务 2.1a：幂等「只摘一次」，覆盖所有 detach 路径——
// 正常关闭/写失败/停滞超限/kill/finish/接管/同实例替换）。
// code=termEndNone 时不发 ENDED（硬错误/客户端已关：裸 EOF）；否则经写者送达 ENDED
// 后再关 conn（ENDED 先于 close，任务 4.1）。why 只进日志（任务 2.7）。
func (s *termSession) endLegLocked(c *termClient, code int32, reason string, why string) {
	// 低10（exec-r1）：除了 removed 幂等位，还要校验腿确实在表内——未来若有调用点误传
	// 未注册的腿，这里早退，防 rawTermLegs 变负、静默废掉 D6 窄规则判据。
	if c.removed || !s.legAliveLocked(c) {
		c.removed = true
		return
	}
	c.removed = true
	for i, l := range s.legs {
		if l == c {
			s.legs = append(s.legs[:i], s.legs[i+1:]...)
			break
		}
	}
	if c.rawCapable && s.rawTermLegs > 0 {
		s.rawTermLegs--
	}
	if code != termEndNone {
		c.out.finishEnded(code, reason)
	} else {
		c.out.finishQuit()
	}
	if s.svc.logf != nil {
		if c.surface && c.leg != nil {
			st := c.leg.statsSnapshot()
			s.svc.logf("term: 会话 %s 腿断开（kind=%s 原因=%s）｜快照=%d 差分=%d 降级=%d 背压=%d "+
				"队列溢出=%d 分片=%d 下行=%dB FETCH 命中=%d 落空=%d",
				s.name, c.kind, why, st.snapshots, st.diffs, st.degrades, st.backpressure,
				st.queueOverflow, st.fragments, st.bytesOut, st.fetchHits, st.fetchMiss)
		} else {
			s.svc.logf("term: 会话 %s 腿断开（kind=%s 原因=%s）", s.name, c.kind, why)
		}
	}
	s.afterLegsChangedLocked()
}

// afterLegsChangedLocked 摘腿后的派生状态：surface 标志 / 应答让位 / 重选举 / 末腿 focus-out。
func (s *termSession) afterLegsChangedLocked() {
	s.surfaceActive.Store(s.anySurfaceLocked())
	s.updateResponseSinkLocked()
	if len(s.legs) == 0 {
		if s.active != nil {
			s.active = nil
		}
		if !s.done {
			// 末腿离开 → focus-out：TUI 停动画（2.1a；单腿时代正常断开不走 detach 的缺口在此修复）。
			s.focusNudgeLocked(false)
		}
		return
	}
	if s.active == nil || !s.legAliveLocked(s.active) {
		s.electActiveLocked()
	}
}

func (s *termSession) legAliveLocked(c *termClient) bool {
	for _, l := range s.legs {
		if l == c {
			return true
		}
	}
	return false
}

// anySurfaceLocked 是否还有 surface 腿（剪贴板路由的原子标志来源）。
func (s *termSession) anySurfaceLocked() bool {
	for _, l := range s.legs {
		if l.surface {
			return true
		}
	}
	return false
}

// surfaceLegsLocked 取 surface 腿快照（投递用）。
func (s *termSession) surfaceLegsLocked() []*termClient {
	out := make([]*termClient, 0, len(s.legs))
	for _, l := range s.legs {
		if l.surface && l.leg != nil {
			out = append(out, l)
		}
	}
	return out
}

// rawLegsLocked 取 raw 腿快照。
func (s *termSession) rawLegsLocked() []*termClient {
	out := make([]*termClient, 0, len(s.legs))
	for _, l := range s.legs {
		if !l.surface {
			out = append(out, l)
		}
	}
	return out
}

// ---- 活动 / 选举（design D4；任务 3.1/3.2）----

// noteActivityLocked 记一次活动（接入 / RESIZE / 输入）：单调序号 + 选举 + 尺寸/主题应用。
// 必须持 s.mu。
//
// sentinel：尺寸变化时是否注入尺寸哨兵——**注册路径传 false**（attach 的哨兵由 stream
// 统一注入一次，exec-r1 低7：一次 attach 一次哨兵）；RESIZE / 重选举路径传 true
// （逼远端 TUI 按新尺寸重绘；输入类活动不会改尺寸，传什么都无哨兵）。
func (s *termSession) noteActivityLocked(c *termClient, sentinel bool) {
	s.activitySeq++
	c.lastActivitySeq = s.activitySeq
	c.lastTouch = time.Now()
	if s.active != c {
		s.active = c
		s.applyActiveThemeLocked() // 主题/剪贴板读缓存跟随 active 腿（任务 3.3）
	}
	if c.cols != s.cols || c.rows != s.rows {
		s.applySizeLocked(c.cols, c.rows) // PTY setsize + epoch + vt 重排 + 全腿标记全量
		if sentinel {
			s.sentinelRepaintLocked() // 逼远端 TUI 按新尺寸重绘（surface 腿的快照在哨兵后）
		}
	}
}

// electActiveLocked 在剩余腿里重选举（任务 3.2）：序号最大者接管；平手（同序号）按
// 更晚接入者优先——tie-break 固定可测（design D4）。无腿保持现状。
func (s *termSession) electActiveLocked() {
	var best *termClient
	for _, l := range s.legs {
		if best == nil || l.lastActivitySeq > best.lastActivitySeq ||
			(l.lastActivitySeq == best.lastActivitySeq && l.attachSeq > best.attachSeq) {
			best = l
		}
	}
	s.active = best
	if best != nil {
		s.applyActiveThemeLocked()
		if best.cols != s.cols || best.rows != s.rows {
			s.applySizeLocked(best.cols, best.rows)
			s.sentinelRepaintLocked()
		}
	}
}

// applyActiveThemeLocked 把 active 腿的主题与剪贴板读缓存落到会话（任务 3.3）。
func (s *termSession) applyActiveThemeLocked() {
	if s.vt != nil && s.vt.Available() && s.active != nil && s.active.themeKnown {
		s.vt.SetTheme(s.active.themeFg, s.active.themeBg)
	}
	if s.active != nil {
		copied := s.active.clipCache
		s.clipCachePub.Store(&copied)
	}
}

// applySizeLocked 应用会话尺寸（PTY setsize + epoch + vt 回滚重排 + **所有** surface 腿
// 标记 needSnapshot——被动腿会拒收几何不符的差分，任务 3.1 的连带义务）。
func (s *termSession) applySizeLocked(cols, rows uint16) {
	if cols == 0 || rows == 0 || s.done || s.ptmx == nil || (s.cols == cols && s.rows == rows) {
		return
	}
	_ = pty.Setsize(s.ptmx, &pty.Winsize{Cols: cols, Rows: rows})
	s.noteSizeLocked(cols, rows)
	s.vt.Resize(cols, rows)
	for _, l := range s.legs {
		if l.surface && l.leg != nil {
			l.leg.markNeedSnapshot("resize")
		}
	}
	s.wakeSurface()
}

// ---- 上限淘汰（任务 2.4）----

// evictForSlotLocked 腾一个腿位：优先淘汰停滞（失活）腿（停滞最久者），否则淘汰最久
// 空闲腿。被淘汰的腿**不发 ENDED**（裸关闭；词表里没有「被挤出」，新增取值须先扩表）。
func (s *termSession) evictForSlotLocked() {
	var victim *termClient
	for _, l := range s.legs {
		if !l.out.isStalled() {
			continue
		}
		if victim == nil || l.out.stalledFor() > victim.out.stalledFor() {
			victim = l
		}
	}
	if victim == nil {
		for _, l := range s.legs {
			if victim == nil || l.lastTouch.Before(victim.lastTouch) {
				victim = l
			}
		}
	}
	if victim != nil {
		s.endLegLocked(victim, termEndNone, "", "evicted_cap")
	}
}

// wakeRawLegsLocked 唤醒所有 raw 腿的写者（pump 每批输出后调用，取代旧的锁内投递）。
func (s *termSession) wakeRawLegsLocked() {
	for _, l := range s.legs {
		if !l.surface {
			l.out.wakeWriter()
		}
	}
}

// pushStateToLegsLocked 给每条腿投递 STATE（任务 2.1b：每腿投递、按腿编码）。
func (s *termSession) pushStateToLegsLocked() {
	if len(s.legs) == 0 {
		return
	}
	var rawPayload, surfacePayload []byte
	for _, l := range s.legs {
		var payload []byte
		if l.surface {
			if surfacePayload == nil {
				surfacePayload = encState(s.agent, stateForLeg(true, s.stateV2, s.state), s.scan.title)
			}
			payload = surfacePayload
		} else {
			if rawPayload == nil {
				rawPayload = encState(s.agent, stateForLeg(false, s.stateV2, s.state), s.scan.title)
			}
			payload = rawPayload
		}
		l.out.enqueueState(writeItem{op: opState, payload: payload})
	}
}

// ---- 查询应答归属（任务 5.1：窄规则）----

// updateResponseSinkLocked 按腿况切换服务端 vt 的查询代答：有声明 capsRawTerminal 的腿
// 在场 ⇒ SetResponseSink(nil)（真实终端自己答 DA1/DSR/OSC 10-11，spike S1 实测：raw 终端
// 在场时双份应答）；仅 surface 腿 / 未声明的旧客户端腿 ⇒ 照旧代答（旧客户端零变化）。
// raw 腿在场期间被丢弃的查询不会在 sink 恢复时补答（已知窗口，design D6）。
func (s *termSession) updateResponseSinkLocked() {
	if s.vt == nil || !s.vt.Available() {
		return
	}
	if s.rawTermLegs > 0 {
		s.vt.SetResponseSink(nil)
		return
	}
	s.vt.SetResponseSink(s.responseFn)
}
