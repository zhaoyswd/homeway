// engine.go — 客户端测速引擎（openspec tunnel-speedtest / forward-socks-speedtest §1.1）。
//
// 自 clientcore/cmd/clientcore/app_speedtest.go 收拢（3e「口径一致的构造性保证」）：
// 手机核壳（app_speedtest.go，经本机 speedtest 桥）与守护侧 runner（facade，经
// Host.DialPort(7803) 直拨隧道）消费**同一引擎**——多流编排、窗口对齐 t0、接收端报数、
// 逐连接期限与总预算看门狗、归因词表都在这里。
//
// 拨号注入缝（dial）：引擎不关心连接怎么来——错误契约（r1 高-2）= 注入缝返回带 code 的
// 类型化错误（*DialError{Code}），引擎**原样透传 code、不做通用化收敛**；refused-like
// 判定与 code 生成归注入缝（手机壳产 bridge_down/bridge_auth，daemon runner 产
// not_supported〔refused-like〕/link_down，r2 新-4）——本包是协议真源包，不反向依赖
// 核内部件。
//
// 线协议（3e 去问候帧后）：客户端先写会话请求、再读。「无测速服务」归因三条判据
// （r1 高-1）：① 注入缝产 DialError{Code:not_supported}（拨号 refused-like——连接未
// 建立）⇒ 引擎透传该 code；② 请求发出后读侧零字节 EOF/复位 ⇒ not_supported（连接已
// 建立，含「写请求失败 + 零字节短读窗」形态——同一根因不随写竞态抖动，r2 新-3）；③ 读到
// 非 data/report 帧（旧出口预发问候帧）⇒ 按通道错误如实呈现。写请求失败不提前归因
// （r1 中-1①）：仍有界短读窗读一帧，读到 report{busy}/{link_down} 按报告归因。
//
// 并发模型（迁移前评审 F2 原样）：引擎实例只持「运行中」旗标与世代号 gen；每轮测速的
// 全部可变状态（连接表/取消旗标/计数器）都在轮级 run 里——Cancel 只关当轮连接、置当轮
// 旗标；旧轮的终态写回前比对世代，新轮绝不被旧轮收尾波及。单飞 = running 旗标。
package speedtest

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Phase 状态机相位（Status 面；取值与手机信封逐字一致）。
type Phase string

const (
	PhaseIdle       Phase = "idle"
	PhaseConnecting Phase = "connecting"
	PhaseDown       Phase = "down"
	PhaseUp         Phase = "up"
	PhaseDone       Phase = "done"
	PhaseFailed     Phase = "failed"
	PhaseCancelled  Phase = "cancelled"
)

// 归因词表（reason 码；手机 SpeedTestRules.ets 的短因分派依赖取值——迁移前后零变化）。
const (
	ReasonBusy         = "busy"          // 出口测速服务并发满员
	ReasonLinkDown     = "link_down"     // 链路正在恢复（桥宿主回 report / runner 会话不在）
	ReasonBridgeDown   = "bridge_down"   // 手机桥未就绪（unix 拨不上）
	ReasonBridgeAuth   = "bridge_auth"   // 手机桥鉴权失败
	ReasonNotSupported = "not_supported" // 出口没有测速服务（三条判据承载）
	ReasonInterrupted  = "interrupted"   // 通道错误（含读到非法帧）
	ReasonTimeout      = "timeout"       // 看门狗/期限到点
	ReasonCancelled    = "cancelled"     // 用户取消
	ReasonInvalidArg   = "invalid_arg"   // 参数非法（壳层前置校验用；引擎不产生）
)

// 引擎边界常量（与迁移前 app_speedtest.go 同值；服务端还有一道独立限额）。
const (
	MaxStreams  = 6                      // 并行流上限（= 手机 speedMaxStreams）
	MaxWindow   = 15 * time.Second       // 窗口上限
	MaxWarmup   = 5 * time.Second        // 预热上限
	blockBytes  = 64<<10 - 1             // u16 长度场硬顶（= maxPayload）
	phaseSlack  = 100 * time.Millisecond // 客户端窗口起点对服务端窗口的滞后余量
	connBudget  = 15 * time.Second       // 请求发出后每连接的读写硬期限（评审 F3）
	watchdogFix = time.Minute            // 总预算看门狗的固定部分；总量 = 本值 + warmup + down + up
	readWindow  = 2 * time.Second        // 写失败后的有界短读窗（r1 中-1①）
)

// DefaultParams 手机口径默认值（down/up 10s、预热 2s、4 流）。
func DefaultParams() Params {
	return Params{Down: 10 * time.Second, Up: 10 * time.Second, Warmup: 2 * time.Second, Streams: 4}
}

// Params 一轮测速的参数（零值字段取手机口径默认；越界 = 校验错误，不静默钳制）。
type Params struct {
	Down    time.Duration
	Up      time.Duration
	Warmup  time.Duration
	Streams int
}

// Normalize 填默认值并校验边界（越界返回 ReasonInvalidArg 类错误；调用方壳层负责
// 前置拦截与文案）。
func (p Params) Normalize() (Params, error) {
	def := DefaultParams()
	if p.Down <= 0 {
		p.Down = def.Down
	}
	if p.Up <= 0 {
		p.Up = def.Up
	}
	if p.Warmup <= 0 {
		p.Warmup = def.Warmup
	}
	if p.Streams <= 0 {
		p.Streams = def.Streams
	}
	if p.Down > MaxWindow || p.Up > MaxWindow || p.Warmup > MaxWarmup {
		return Params{}, fmt.Errorf("窗口/预热超上限（窗口 ≤ %s、预热 ≤ %s）", MaxWindow, MaxWarmup)
	}
	if p.Streams < 1 || p.Streams > MaxStreams {
		return Params{}, fmt.Errorf("并行流数 %d 超出 [1,%d]", p.Streams, MaxStreams)
	}
	return p, nil
}

// DialError 注入缝的类型化拨号错误：引擎原样透传 Code（错误契约，r1 高-2）。
type DialError struct {
	Code string
	Msg  string
}

func (e *DialError) Error() string { return e.Code + ": " + e.Msg }

// DialErrf 造一个 DialError（注入缝侧用）。
func DialErrf(code, format string, args ...any) *DialError {
	return &DialError{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// DialFunc 拨号注入缝：返回一条已建立的测速连接（手机壳 = 桥鉴权后的 unix 连接，
// daemon runner = Host.DialPort(7803) 的隧道连接）；失败返回 *DialError（code 透传）。
type DialFunc func(ctx context.Context) (net.Conn, error)

// Result 一轮测速的终态（成功 = OK；失败携带 reason/msg——reason 取值见 Reason* 词表）。
type Result struct {
	OK        bool
	Reason    string
	Msg       string
	DownBps   float64
	UpBps     float64
	UsageDown int64
	UsageUp   int64
	WallMs    int64
}

// UsageBrief 用量快照（Snapshot 内嵌；nil 语义 = 无轮次）。
type UsageBrief struct {
	Down int64
	Up   int64
}

// LiveBrief 窗口内实时读数（窗口未起/未进窗 = nil）。
type LiveBrief struct {
	Dir     string // down/up
	Bytes   int64
	InstBps float64
}

// Snapshot Status 面快照（消费方按需映射进各自的 JSON 信封——手机壳逐字段保持既有形态）。
type Snapshot struct {
	Phase     string
	Reason    string
	Usage     *UsageBrief
	Live      *LiveBrief
	ElapsedMs int64 // -1 = 从未开跑（映射层决定是否输出）
}

// run 一轮测速的全部可变状态（轮级所有权——Cancel/收尾只波及当轮；迁移前评审 F2）。
type run struct {
	gen       uint64
	cancelled atomic.Bool
	timedOut  atomic.Bool // 看门狗到点（区别于用户取消——归因不同）
	abort     func()      // 轮内 ctx 的取消（Cancel/看门狗同步打断在途拨号；Start 装配）

	connMu sync.Mutex
	conns  map[net.Conn]struct{}

	mu          sync.Mutex
	liveBytes   int64
	windowStart time.Time
	windowLen   time.Duration
	usageDown   int64
	usageUp     int64
}

func newRun(gen uint64) *run { return &run{gen: gen, conns: map[net.Conn]struct{}{}} }

func (r *run) track(c net.Conn) {
	r.connMu.Lock()
	r.conns[c] = struct{}{}
	r.connMu.Unlock()
}

func (r *run) untrack(c net.Conn) {
	r.connMu.Lock()
	delete(r.conns, c)
	r.connMu.Unlock()
}

// closeAll 关掉当轮全部连接（先摘表出锁再关——锁内不做 IO）。
func (r *run) closeAll() {
	r.connMu.Lock()
	cs := make([]net.Conn, 0, len(r.conns))
	for c := range r.conns {
		cs = append(cs, c)
	}
	r.conns = map[net.Conn]struct{}{}
	r.connMu.Unlock()
	for _, c := range cs {
		_ = c.Close()
	}
}

func (r *run) isCancelled() bool { return r.cancelled.Load() }
func (r *run) timedOutNow() bool { return r.timedOut.Load() }

// timeout 看门狗到点：置超时旗标并关连接（错误路径归因 timeout）。
func (r *run) timeout() {
	r.timedOut.Store(true)
	r.closeAll()
	if r.abort != nil {
		r.abort()
	}
}

// cancel 置旗标并关连接（旗标先置——错误路径据此把 interrupted 归回 cancelled），
// 同步取消轮内 ctx（在途拨号立即以 ctx 错误退出）。
func (r *run) cancel() {
	r.cancelled.Store(true)
	r.closeAll()
	if r.abort != nil {
		r.abort()
	}
}

func (r *run) addLive(n int64) {
	r.mu.Lock()
	r.liveBytes += n
	r.mu.Unlock()
}

func (r *run) setWindow(start time.Time, len time.Duration) {
	r.mu.Lock()
	r.windowStart = start
	r.windowLen = len
	r.liveBytes = 0
	r.mu.Unlock()
}

// countInWindow 单锁内完成「窗口内判定 + live 计数」（下行读热路径，2026-09-28 整改：
// 原先 inWindow+addLive 每 data 帧两次加锁）；返回该块是否计入读数。
func (r *run) countInWindow(n int64) bool {
	r.mu.Lock()
	now := time.Now()
	in := !r.windowStart.IsZero() && now.After(r.windowStart) && now.Before(r.windowStart.Add(r.windowLen))
	if in {
		r.liveBytes += n
	}
	r.mu.Unlock()
	return in
}

func (r *run) addUsage(up bool, n int64) {
	r.mu.Lock()
	if up {
		r.usageUp += n
	} else {
		r.usageDown += n
	}
	r.mu.Unlock()
}

// reasonOr：错误路径上优先认「取消」——Cancel 关连接会让在跑的读/写以任意错误退出，
// 只看 error 会误归因成 interrupted。
func (r *run) reasonOr(def string) string {
	if r.isCancelled() {
		return ReasonCancelled
	}
	if r.timedOutNow() {
		return ReasonTimeout
	}
	return def
}

// attrError 引擎内已归因的错误（reason 决定终态；nil = 无归因、按默认通道错误处理）。
type attrError struct {
	reason string
	msg    string
}

func (e *attrError) Error() string { return e.reason + ": " + e.msg }

// reportCode report 帧错误到 reason 码的映射（busy/link_down 照旧；其余空——调用方
// 按通道错误如实呈现）。
func reportCode(repErr string) string {
	switch repErr {
	case "busy":
		return ReasonBusy
	case "link_down":
		return ReasonLinkDown
	}
	return ""
}

// Engine 测速引擎（单飞；running 旗标判忙）。手机核 = 进程唯一实例；守护侧 runner =
// 每主机一个实例（per-host 单飞由 runner 面 guarantee）。
type Engine struct {
	logf func(format string, args ...any)

	mu        sync.Mutex
	running   bool
	gen       uint64
	phase     Phase
	reason    string
	startedAt time.Time
	run       *run // 当前/最近一轮（终态后保留：snapshot 的用量仍可读）
}

// NewEngine 建引擎（logf = 判据行输出口；nil = 丢弃）。
func NewEngine(logf func(format string, args ...any)) *Engine {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Engine{phase: PhaseIdle, logf: logf}
}

// Running 当前是否有轮次在跑（单飞判忙面）。
func (e *Engine) Running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}

// Start 同步跑完整轮（调用方自带并发面：手机在 NAPI async work 线程、runner 在
// goroutine）。忙时返回 busy Result（状态零变化）。业务失败走 Result.Reason，不用
// panic/错误双通道。
func (e *Engine) Start(ctx context.Context, dial DialFunc, p Params) Result {
	p, err := p.Normalize()
	if err != nil {
		return Result{OK: false, Reason: ReasonInvalidArg, Msg: err.Error()}
	}
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return Result{OK: false, Reason: ReasonBusy, Msg: "已有测速在跑（单飞）"}
	}
	e.gen++
	r := newRun(e.gen)
	ctx, abort := context.WithCancel(ctx)
	r.abort = abort
	defer abort()
	e.running = true
	e.phase = PhaseConnecting
	e.reason = ""
	e.startedAt = time.Now()
	e.run = r
	e.mu.Unlock()
	// 判据行在锁外打（迁移前评审 F10）。
	e.logf("speedtest: 开跑（down %d流 warmup=%s window=%s）", p.Streams, p.Warmup, p.Down)

	// 总预算看门狗（评审 F3）：无论如何到点强制当轮取消，引擎不可能永久停在窗口里。
	wd := time.AfterFunc(watchdogFix+p.Warmup+p.Down+p.Up, r.timeout)
	defer wd.Stop()

	res := e.runRound(ctx, dial, r, p)

	e.mu.Lock()
	e.running = false
	e.mu.Unlock()
	return res
}

func (e *Engine) setPhase(p Phase, reason string) {
	e.mu.Lock()
	e.phase = p
	if reason != "" {
		e.reason = reason
	}
	e.mu.Unlock()
}

// finish 终态归因（优先级：取消 > 超时 > 已归因码 > 默认通道错误——Cancel/看门狗关
// 连接会让任意在途读写以通道错误退出，必须先认旗标）+ 终态写回（世代比对——旧轮
// 收尾不得覆盖新轮的全局相位，评审 F2）。
func (e *Engine) finish(r *run, ae *attrError, defReason, defMsg string) Result {
	reason, msg := defReason, defMsg
	if ae != nil {
		reason, msg = ae.reason, ae.msg
	}
	if r.isCancelled() {
		reason, msg = ReasonCancelled, "测速已取消"
	} else if r.timedOutNow() {
		reason, msg = ReasonTimeout, "链路长时间不通，测速超时"
	}
	phase := PhaseFailed
	if reason == ReasonCancelled {
		phase = PhaseCancelled
	}
	e.mu.Lock()
	if e.gen == r.gen {
		e.phase = phase
		e.reason = reason
	}
	e.mu.Unlock()
	e.logf("speedtest: 终止（原因=%s）%s", reason, msg)
	return Result{OK: false, Reason: reason, Msg: msg}
}

// dialFailure 拨号错误的归因（注入缝错误契约：DialError.Code 原样透传；取消/超时
// 优先级由 finish 统一处理）。
func (e *Engine) dialFailure(r *run, err error) Result {
	var de *DialError
	if errors.As(err, &de) {
		return e.finish(r, &attrError{de.Code, de.Msg}, "", "")
	}
	return e.finish(r, nil, ReasonInterrupted, fmt.Sprintf("测速拨号错误：%v", err))
}

func (e *Engine) runRound(ctx context.Context, dial DialFunc, r *run, p Params) Result {
	// ---- 下行：N 条 role=recv ----
	e.setPhase(PhaseConnecting, "")
	// 先拨齐全部连接、再统一发请求：服务端的预热从「收到请求」起算，若拨一条发一条，
	// 早拨的流窗口会比晚拨的早开（拨号时差直接变成窗口错位）。拨齐后请求几乎同时到达，
	// 各流窗口彼此对齐、也与下面的 t0 对齐（design D3）。
	type dialResult struct {
		conn net.Conn
		br   *bufio.Reader
	}
	downRaw := make([]dialResult, 0, p.Streams)
	for i := 0; i < p.Streams; i++ {
		conn, err := dial(ctx)
		if err != nil {
			r.closeAll()
			return e.dialFailure(r, err)
		}
		r.track(conn)
		downRaw = append(downRaw, dialResult{conn, bufio.NewReader(conn)})
	}
	for _, d := range downRaw {
		if ae := e.sendRequest(r, d.conn, d.br, RoleRecv, p.Warmup, p.Down); ae != nil {
			r.closeAll()
			return e.finish(r, ae, ReasonInterrupted, "发下行请求失败")
		}
	}
	if r.isCancelled() {
		r.closeAll()
		return e.finish(r, nil, ReasonCancelled, "测速已取消")
	}

	// 计时窗从连接成功后起算（design D3）：预热尾端 + 滞后余量才是 t0。
	r.setWindow(time.Now().Add(p.Warmup+phaseSlack), p.Down)
	e.setPhase(PhaseDown, "")
	downGot := make([]int64, p.Streams)
	downErrs := make([]*attrError, p.Streams)
	var downUsage int64
	var downSrv int64 // 服务端 report 的窗内字节汇总（对账判据行用）
	var downSrvWarm int64
	var wg sync.WaitGroup
	for i, d := range downRaw {
		wg.Add(1)
		go func(i int, d dialResult) {
			defer wg.Done()
			defer r.untrack(d.conn)
			defer func() { _ = d.conn.Close() }()
			got, used, sb, sw, ae := e.readDownStream(r, d.br)
			downGot[i] = got
			atomic.AddInt64(&downUsage, used)
			atomic.AddInt64(&downSrv, sb)
			atomic.AddInt64(&downSrvWarm, sw)
			downErrs[i] = ae
		}(i, d)
	}
	wg.Wait()
	r.addUsage(false, downUsage)
	for i, ae := range downErrs {
		if ae != nil {
			r.closeAll()
			return e.finish(r, ae, ReasonInterrupted, fmt.Sprintf("下行流 %d 中断：%v", i, ae))
		}
	}
	downBps := windowBps(sum(downGot), p.Down)
	// 下行对账（design D3「END 帧对账」）：接收端窗内计数 vs 服务端窗内发出。稳态偏差
	// 应≈窗口错位余量（<2%）；显著偏大 = 链路侧重传堆积或窗口错位的自动判据。
	if downSrv > 0 {
		e.logf("speedtest: 下行对账（接收端窗内=%dB 服务端窗内=%dB 预热=%dB 偏差=%.2f%%）",
			sum(downGot), downSrv, downSrvWarm, float64(downSrv-sum(downGot))/float64(downSrv)*100)
	}

	// ---- 上行：N 条 role=send（新连接：每流一角色不复用）----
	e.setPhase(PhaseConnecting, "")
	upResults := make([]int64, p.Streams)
	upErrs := make([]*attrError, p.Streams)
	upWalls := make([]int64, p.Streams)
	upStreams := make([]dialResult, p.Streams)
	for i := 0; i < p.Streams; i++ {
		conn, err := dial(ctx)
		if err != nil {
			r.closeAll()
			return e.dialFailure(r, err)
		}
		r.track(conn)
		upStreams[i] = dialResult{conn, bufio.NewReader(conn)}
	}
	r.setWindow(time.Now().Add(p.Warmup+phaseSlack), p.Up)
	e.setPhase(PhaseUp, "")
	var upWg sync.WaitGroup
	for i := range upStreams {
		upWg.Add(1)
		go func(i int) {
			defer upWg.Done()
			defer r.untrack(upStreams[i].conn)
			defer func() { _ = upStreams[i].conn.Close() }()
			got, used, wallMs, ae := e.runUpStream(r, upStreams[i].conn, upStreams[i].br, p.Warmup, p.Up)
			upResults[i] = got
			upWalls[i] = wallMs
			r.addUsage(true, used)
			upErrs[i] = ae
		}(i)
	}
	upWg.Wait()
	for i, ae := range upErrs {
		if ae != nil {
			r.closeAll()
			return e.finish(r, ae, ReasonInterrupted, fmt.Sprintf("上行流 %d 中断：%v", i, ae))
		}
	}
	// 上行分母用服务端实测墙钟均值（迁移前口径：名义 10s 有 ~1% 虚高）。
	var wallSum int64
	for _, w := range upWalls {
		wallSum += w
	}
	denom := p.Up
	if wallSum > 0 {
		denom = time.Duration(wallSum/int64(p.Streams)) * time.Millisecond
	}
	upBps := windowBps(sum(upResults), denom)

	r.closeAll()
	return e.finishOK(r.gen, downBps, upBps)
}

// sendRequest 写会话请求（去问候帧后客户端先写）+ 失败时的有界短读窗：
//   - 写成功：设数据期硬期限（评审 F3：读写都盖；从请求发出起算，对齐迁移前
//     「greeting 后设期限」的语义），返回 nil；
//   - 写失败（EPIPE 等）：MUST NOT 提前归因——短读窗读一帧，读到 report{busy}/
//     {link_down} 按报告归因（r1 中-1①）；零字节 ⇒ 判据② not_supported（连接已建立，
//     同一根因不随写竞态抖动两种短因，r2 新-3）。
func (e *Engine) sendRequest(r *run, conn net.Conn, br *bufio.Reader, role Role, warmup, window time.Duration) *attrError {
	bw := bufio.NewWriter(conn)
	werr := WriteRequest(bw, role, warmup, window)
	if werr == nil {
		werr = bw.Flush()
	}
	if werr != nil {
		if reason, msg, ok := probeReport(conn, br); ok {
			return &attrError{reason, msg}
		}
		return &attrError{ReasonNotSupported, fmt.Sprintf("出口没有测速服务（请升级出口）：写请求失败且无应答：%v", werr)}
	}
	_ = conn.SetDeadline(time.Now().Add(warmup + window + connBudget))
	return nil
}

// probeReport 写失败后的有界短读窗：读一帧，report{error} → busy/link_down 归因
// （其余码同迁移前 greeting 期 default 分支 → not_supported）；零字节/超时/非 report
// → ok=false（调用方按其所在相位归因）。
func probeReport(conn net.Conn, br *bufio.Reader) (reason, msg string, ok bool) {
	_ = conn.SetReadDeadline(time.Now().Add(readWindow))
	t, _, payload, err := readFrame(br)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil || t != TypeReport {
		return "", "", false
	}
	var rep Report
	if json.Unmarshal(payload, &rep) != nil || rep.Error == "" {
		return "", "", false
	}
	if code := reportCode(rep.Error); code != "" {
		return code, reportMsg(code), true
	}
	return ReasonNotSupported, fmt.Sprintf("出口没有测速服务（请升级出口）：%s", rep.Error), true
}

// reportMsg report 归因的用户可见文案（与迁移前 speedDial 的 busy/link_down 文案一致）。
func reportMsg(code string) string {
	switch code {
	case ReasonBusy:
		return "出口测速服务并发满员，请稍后再试"
	case ReasonLinkDown:
		return "链路正在恢复"
	}
	return ""
}

// readDownStream 读一条下行流：预热期字节只进用量；窗口期字节进读数。收 report 正常收场。
// 用量只计**实收字节**（迁移前评审 F7：rep.WarmupBytes 与实收的预热是同一批字节）。
// data 帧走 header+discard 零分配路径（评审 F9），report 帧读进小缓冲。
// 归因：任何帧未收到前的读失败（EOF/复位/期限）= 判据② not_supported（连接已建立、
// 请求已发出）；已收帧后的失败 = 通道错误；report{error} = busy/link_down/通道错误。
func (e *Engine) readDownStream(r *run, br *bufio.Reader) (got, used, srvBytes, srvWarm int64, ae *attrError) {
	ctrl := make([]byte, 1024)
	frames := 0
	for {
		t, _, n, payload, rerr := ReadFrameLoose(br, ctrl)
		if rerr != nil {
			if frames == 0 {
				return got, used, srvBytes, srvWarm, &attrError{ReasonNotSupported,
					fmt.Sprintf("出口没有测速服务（请升级出口）：请求后无应答（%v）", rerr)}
			}
			return got, used, srvBytes, srvWarm, &attrError{ReasonInterrupted, rerr.Error()}
		}
		frames++
		switch t {
		case TypeData:
			if err := DiscardPayload(br, n); err != nil {
				return got, used, srvBytes, srvWarm, &attrError{ReasonInterrupted, err.Error()}
			}
			used += int64(n)
			if r.countInWindow(int64(n)) {
				got += int64(n)
			}
		case TypeReport:
			var rep Report
			if jerr := json.Unmarshal(payload, &rep); jerr != nil {
				return got, used, srvBytes, srvWarm, &attrError{ReasonInterrupted, jerr.Error()}
			}
			if rep.Error != "" {
				if code := reportCode(rep.Error); code != "" {
					return got, used, srvBytes, srvWarm, &attrError{code, reportMsg(code)}
				}
				return got, used, srvBytes, srvWarm, &attrError{ReasonInterrupted, rep.Error}
			}
			return got, used, rep.Bytes, rep.WarmupBytes, nil
		default:
			// 判据③（旧出口预发问候帧等）：按通道错误如实呈现。
			return got, used, srvBytes, srvWarm, &attrError{ReasonInterrupted,
				fmt.Sprintf("窗口期收到类型 %d", t)}
		}
	}
}

// runUpStream 一条上行流：请求 → 预热泵 → START → 窗口泵 → FINISH → report（接收端报数）。
// 窗口泵按 250ms 分片并回调实时字节（评审 F1：上行 instBps 的数据源；分片同时是取消
// 检查点）。归因：请求写失败 = 判据②（短读窗找 report）；泵送中写失败 = 通道错误
// （短读窗找 report，r1 中-1①——busy 服务端读掉请求后回帧即关，泵送会先撞上）；FINISH
// 后读侧零字节 = 判据②；非 report 帧（旧出口问候帧）= 判据③ 通道错误。
func (e *Engine) runUpStream(r *run, conn net.Conn, br *bufio.Reader, warmup, window time.Duration) (got, used, wallMs int64, ae *attrError) {
	bw := bufio.NewWriter(conn)
	if aerr := e.sendRequest(r, conn, br, RoleSend, warmup, window); aerr != nil {
		return 0, 0, 0, aerr
	}
	block := make([]byte, blockBytes)
	var seq uint32
	warm := PumpData(bw, block, &seq, warmup)
	if werr := bw.Flush(); werr != nil {
		return e.upWriteFailure(conn, br, warm, werr)
	}
	WriteStart(bw)
	if werr := bw.Flush(); werr != nil {
		return e.upWriteFailure(conn, br, warm, werr)
	}
	// 窗口泵：分片推进；**字节数必须用分片泵的返回值**（评审 r2-N1：一片内写多帧，
	// 「一片一帧」的记法曾造成 1~2 个数量级的少算）。
	var sent int64
	{
		deadline := time.Now().Add(window)
		scratch := make([]byte, MaxHeader+len(block))
		copy(scratch[MaxHeader:], block)
		for !time.Now().After(deadline) {
			n, err := PumpDataChunk(bw, scratch, &seq, 250*time.Millisecond)
			if n > 0 {
				sent += n
				r.addLive(n)
			}
			if ferr := bw.Flush(); ferr != nil {
				return e.upWriteFailure(conn, br, warm+sent, ferr)
			}
			if err != nil {
				return e.upWriteFailure(conn, br, warm+sent, err)
			}
		}
	}
	if werr := bw.Flush(); werr != nil {
		return e.upWriteFailure(conn, br, warm+sent, werr)
	}
	WriteFinish(bw)
	if werr := bw.Flush(); werr != nil {
		return e.upWriteFailure(conn, br, warm+sent, werr)
	}
	// 收口 report：读侧零字节 = 判据②（连接已建立、请求已发出——对端不答即无服务形态）；
	// 非 report 帧（旧出口预发问候帧）= 判据③。
	ctrl := make([]byte, 1024)
	t, _, _, payload, rerr := ReadFrameLoose(br, ctrl)
	if rerr != nil {
		return 0, warm + sent, warm + sent, &attrError{ReasonNotSupported,
			fmt.Sprintf("出口没有测速服务（请升级出口）：收口无应答（%v）", rerr)}
	}
	if t != TypeReport {
		return 0, warm + sent, warm + sent, &attrError{ReasonInterrupted,
			fmt.Sprintf("窗口期收到类型 %d", t)}
	}
	var rep Report
	if jerr := json.Unmarshal(payload, &rep); jerr != nil {
		return 0, warm + sent, warm + sent, &attrError{ReasonInterrupted, jerr.Error()}
	}
	if rep.Error != "" {
		if code := reportCode(rep.Error); code != "" {
			return 0, warm + sent, warm + sent, &attrError{code, reportMsg(code)}
		}
		return 0, warm + sent, warm + sent, &attrError{ReasonInterrupted, rep.Error}
	}
	return rep.Bytes, warm + sent, rep.WallMs, nil
}

// upWriteFailure 上行泵送/收口写失败的统一收口：先短读窗找 report（busy/link_down
// 按报告归因，r1 中-1①——busy 服务端读掉请求后回帧即关，泵送会先撞上）；零字节 = 通道
// 错误（数据期失败；请求期的零字节在 sendRequest 内按判据② 归因，r2 新-3）。
func (e *Engine) upWriteFailure(conn net.Conn, br *bufio.Reader, used int64, werr error) (int64, int64, int64, *attrError) {
	if reason, msg, ok := probeReport(conn, br); ok {
		return 0, used, used, &attrError{reason, msg}
	}
	return 0, used, used, &attrError{ReasonInterrupted, fmt.Sprintf("上行发送失败：%v", werr)}
}

func sum(vs []int64) int64 {
	var t int64
	for _, v := range vs {
		t += v
	}
	return t
}

func windowBps(bytes int64, window time.Duration) float64 {
	if window <= 0 {
		return 0
	}
	return float64(bytes) / window.Seconds()
}

// ---------- 状态与终态 ----------

func (e *Engine) finishOK(gen uint64, downBps, upBps float64) Result {
	e.mu.Lock()
	usageDown, usageUp, r := int64(0), int64(0), e.run
	if e.gen == gen {
		e.phase = PhaseDone
		e.reason = ""
	}
	e.mu.Unlock()
	if r != nil {
		r.mu.Lock()
		usageDown, usageUp = r.usageDown, r.usageUp
		r.mu.Unlock()
	}
	wall := time.Since(e.startedAt).Milliseconds()
	// 判据行（design D5）：精确值形态——取整只发生在展示层（D7）。
	e.logf("speedtest: 完成（down=%dB/s（%.2fMbps） up=%dB/s（%.2fMbps） 用量=%dMB 用时=%ds）",
		int64(downBps), downBps*8/1e6, int64(upBps), upBps*8/1e6,
		(usageDown+usageUp)/(1<<20), wall/1000)
	return Result{
		OK:        true,
		DownBps:   downBps,
		UpBps:     upBps,
		UsageDown: usageDown,
		UsageUp:   usageUp,
		WallMs:    wall,
	}
}

// CancelActive 取消当前在跑的一轮（幂等；空闲时无害空操作）。只波及当轮（评审 F2）：
// 关当轮连接 + 置当轮旗标，全局相位同步标记。
func (e *Engine) CancelActive() {
	e.mu.Lock()
	r, running := e.run, e.running
	e.mu.Unlock()
	if r == nil || !running {
		return
	}
	r.cancel()
	e.setPhase(PhaseCancelled, ReasonCancelled)
}

// Snapshot Status 的快照（页面 250ms 轮询 / runner 状态面）。
func (e *Engine) Snapshot() Snapshot {
	e.mu.Lock()
	phase, reason, startedAt, r := e.phase, e.reason, e.startedAt, e.run
	e.mu.Unlock()
	s := Snapshot{Phase: string(phase), Reason: reason, ElapsedMs: -1}
	if r != nil {
		r.mu.Lock()
		usage := &UsageBrief{Down: r.usageDown, Up: r.usageUp}
		ws, wl, live := r.windowStart, r.windowLen, r.liveBytes
		r.mu.Unlock()
		s.Usage = usage
		if !ws.IsZero() {
			now := time.Now()
			if now.After(ws) {
				elapsed := now.Sub(ws).Seconds()
				if elapsed > wl.Seconds() {
					elapsed = wl.Seconds()
				}
				if elapsed > 0 {
					// 方向按相位反推（phase 已在本函数锁内读过——别再嵌套取锁，互斥锁不可重入）。
					dir := ""
					switch phase {
					case PhaseDown:
						dir = "down"
					case PhaseUp:
						dir = "up"
					}
					s.Live = &LiveBrief{Dir: dir, Bytes: live, InstBps: float64(live) / elapsed}
				}
			}
		}
	}
	if !startedAt.IsZero() {
		e.mu.Lock()
		s.ElapsedMs = time.Since(startedAt).Milliseconds()
		e.mu.Unlock()
	}
	return s
}
