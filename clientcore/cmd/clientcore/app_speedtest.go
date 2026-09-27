//go:build cshared

// App 专用：测速引擎（openspec tunnel-speedtest）。CLI 不编。
//
// app_speedtest.go — 位置与 files/term 的原生消费方同构：App 进程的核实例没有 tunnel
// （currentTunRun() 为 nil），引擎经本机 **speedtest 桥**（<filesDir>/bridge/speedtest.sock
// → 隧道宿主/服务会话宿主 → 隧道 → 出口 7803）与出口的 pkg/speedtest 服务对话。
// 协议真源 = homeway `pkg/speedtest`（本地 replace）：帧/角色/报告语义都在那边；
// 这里只做编排——4 条并行流、下行先行、两向顺序、接收端报数、**计时窗从连接成功后起算**
// （拨号/鉴权/预热不计入窗口，tunnel-speedtest design D3）。
//
// 并发模型（评审 F2 整改）：全局单例只持「运行中」旗标与世代号 gen；每轮测速的全部
// 可变状态（连接表/取消旗标/计数器）都在**轮级 speedRun** 里——Cancel 只关当轮连接、
// 置当轮旗标；旧轮的终态写回前比对世代，新轮绝不被旧轮收尾波及。单飞 = running 旗标
// （不是相位——相位会被取消置成 cancelled，旗标不会）。
//
// 失败有界（评审 F3 整改）：greeting 有 20s 读期限；greeting 过后每连接设
// 「预热+窗口+15s」硬期限（读写都盖，堵住 files 在真机付过学费的「对端连着但不说话」
// 挂死）；另有总预算看门狗兜底，到点强制当轮取消。
//
// 归因（评审 F4/F5 整改）：桥宿主拨出口失败时对 speed 桥回 `report{link_down}` 再关——
// 引擎把它归 `link_down`（页面回等待循环自动续跑），只有「连上了但 greeting 缺失/协议
// 不符」才判 `not_supported`；恢复阶梯的就地恢复不拆世代 ⇒ 桥恒在 ⇒ 恢复期开跑会撞
// link_down 而不是「请升级出口」。
//
// via/rtt 不在这层取：App 进程没有 Transport，App 侧在开跑时从状态快照冻结。
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zhaoyswd/homeway/pkg/speedtest"
)

// speedtestServicePort 出口测速服务端口（= homeway internal/server.DefaultSpeedtestPort；
// 改任何一侧都要同步另一侧）。
const speedtestServicePort = 7803

// 引擎参数边界（服务端还有一道独立限额；这里提前拦，错误归因更友好）。
const (
	speedMaxStreams = 6
	speedMaxWindow  = 15 * time.Second
	speedMaxWarmup  = 5 * time.Second
	speedBlockBytes = 64<<10 - 1 // u16 长度场硬顶（pkg/speedtest maxPayload）
	speedDialBridge = 20 * time.Second
	speedPhaseSlack = 100 * time.Millisecond // 客户端窗口起点对服务端窗口的滞后余量
	// speedConnBudget greeting 之后每连接的读写硬期限（评审 F3）：盖住预热+窗口+收口，
	// 堵「对端连着但不说话」的无限挂死（同款坑 files 在真机 2026-09-22 付过学费）。
	speedConnBudget = 15 * time.Second
	// speedWatchdog 总预算看门狗的固定部分：拨号（含恢复期重试的最坏情况）+ 余量；
	// 到点强制当轮取消，引擎不可能永久停在窗口里。
	speedWatchdog = time.Minute
)

// speedPhase 状态机相位（Status 的 phase 字段）。
type speedPhase string

const (
	spIdle       speedPhase = "idle"
	spConnecting speedPhase = "connecting"
	spDown       speedPhase = "down"
	spUp         speedPhase = "up"
	spDone       speedPhase = "done"
	spFailed     speedPhase = "failed"
	spCancelled  speedPhase = "cancelled"
)

// speedRun 一轮测速的全部可变状态（评审 F2 整改：轮级所有权——Cancel/收尾只波及当轮）。
type speedRun struct {
	gen       uint64
	cancelled atomic.Bool
	timedOut  atomic.Bool // 看门狗到点（区别于用户取消——归因不同，评审 r2-N11）

	connMu sync.Mutex
	conns  map[net.Conn]struct{}

	mu          sync.Mutex
	liveBytes   int64
	windowStart time.Time
	windowLen   time.Duration
	usageDown   int64
	usageUp     int64
}

func newSpeedRun(gen uint64) *speedRun {
	return &speedRun{gen: gen, conns: map[net.Conn]struct{}{}}
}

func (r *speedRun) track(c net.Conn) {
	r.connMu.Lock()
	r.conns[c] = struct{}{}
	r.connMu.Unlock()
}

func (r *speedRun) untrack(c net.Conn) {
	r.connMu.Lock()
	delete(r.conns, c)
	r.connMu.Unlock()
}

// closeAll 关掉当轮全部连接（先摘表出锁再关——锁内不做 IO）。
func (r *speedRun) closeAll() {
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

func (r *speedRun) isCancelled() bool { return r.cancelled.Load() }

// timedOutNow：看门狗/超时路径的归因优先级同 cancelled（关连接引发的任意错误，
// 先认 timeout 再认 interrupted）。超时与取消互斥：看门狗不会与用户取消同时发生
// （看门狗到点前用户取消 ⇒ 已收场）。
func (r *speedRun) timedOutNow() bool { return r.timedOut.Load() }

// timeout 看门狗到点：置超时旗标并关连接（错误路径归因 timeout）。
func (r *speedRun) timeout() {
	r.timedOut.Store(true)
	r.closeAll()
}

// cancel 置旗标并关连接（旗标先置——错误路径据此把 interrupted 归回 cancelled）。
func (r *speedRun) cancel() {
	r.cancelled.Store(true)
	r.closeAll()
}

func (r *speedRun) addLive(n int64) {
	r.mu.Lock()
	r.liveBytes += n
	r.mu.Unlock()
}

func (r *speedRun) setWindow(start time.Time, len time.Duration) {
	r.mu.Lock()
	r.windowStart = start
	r.windowLen = len
	r.liveBytes = 0
	r.mu.Unlock()
}

// countInWindow 单锁内完成「窗口内判定 + live 计数」（下行读热路径整改 2026-09-28：
// 原先 inWindow+addLive 每 data 帧两次加锁）；返回该块是否计入读数。
func (r *speedRun) countInWindow(n int64) bool {
	r.mu.Lock()
	now := time.Now()
	in := !r.windowStart.IsZero() && now.After(r.windowStart) && now.Before(r.windowStart.Add(r.windowLen))
	if in {
		r.liveBytes += n
	}
	r.mu.Unlock()
	return in
}

func (r *speedRun) addUsage(up bool, n int64) {
	r.mu.Lock()
	if up {
		r.usageUp += n
	} else {
		r.usageDown += n
	}
	r.mu.Unlock()
}

// speedEngine 全核唯一的测速状态机（单飞；running 旗标判忙，见评审 F2）。
type speedEngine struct {
	mu        sync.Mutex
	running   bool
	gen       uint64
	phase     speedPhase
	reason    string
	startedAt time.Time
	run       *speedRun // 当前/最近一轮（终态后保留：snapshot 的用量仍可读）
}

var speed = &speedEngine{phase: spIdle}

// speedLinkDownReply 桥宿主拨出口失败时对 speed 桥回一帧 report{link_down} 再关
// （评审 F4：让客户端区分「出口不在/正在恢复」与「老出口没有服务」；该路径已在
// 桥鉴权之后，不会向未鉴权探测者回写任何字节）。帧格式照 pkg/speedtest 的 report。
func speedLinkDownReply(conn net.Conn) {
	bw := newSpeedBridgeWriter(conn)
	_ = speedtest.WriteControl(bw, speedtest.TypeReport, []byte(`{"error":"link_down"}`))
	_ = bw.Flush()
}

// speedLogf 测速判据行（进隧道日志/日志页）。前缀「speedtest: 」写在**调用方的字面量**
// 里——check-code-map.sh 按源码字面 grep，包装器里拼前缀会让判据串搜不到（评审 F8）。
func speedLogf(format string, args ...any) {
	log.Printf(format, args...)
}

func newSpeedBridgeWriter(c net.Conn) *bufio.Writer { return bufio.NewWriter(c) }

// speedError 带稳定错误码的内部错误（speedDial 的失败通道；最终都以
// {"ok":false,"reason","msg"} 形态出去，评审补③：不再用 {"error":...} 信封）。
type speedError struct {
	Code string
	Msg  string
}

func (e *speedError) Error() string { return e.Code + ": " + e.Msg }

func speedErrf(code, format string, args ...any) *speedError {
	return &speedError{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// speedParams Start 的入参（JSON）。
type speedParams struct {
	Auth     string `json:"auth"`     // 桥鉴权 blob（状态 JSON 的 bridgeAuth）
	Sock     string `json:"sock"`     // speedtest 桥 socket 路径（状态 JSON 的 bridgeSpeedSock）
	DownMs   int64  `json:"downMs"`   // 下行窗口（0 = 10000）
	UpMs     int64  `json:"upMs"`     // 上行窗口（0 = 10000）
	WarmupMs int64  `json:"warmupMs"` // 预热（0 = 2000）
	Streams  int    `json:"streams"`  // 并行流数（0 = 4）
}

//export TailcatSpeedTestStart
func TailcatSpeedTestStart(cParams *C.char) *C.char {
	raw := C.GoString(cParams)
	return speedMarshal(speedStart(raw))
}

//export TailcatSpeedTestStatus
func TailcatSpeedTestStatus() *C.char {
	return speedMarshal(speed.snapshot())
}

//export TailcatSpeedTestCancel
func TailcatSpeedTestCancel() *C.char {
	speed.cancelActive()
	return speedMarshal(map[string]any{"ok": true})
}

// speedFail 业务失败的统一返回（评审补③：与 run() 内失败同形态，不再用 error 信封）。
func speedFail(reason, msg string) map[string]any {
	return map[string]any{"ok": false, "reason": reason, "msg": msg}
}

// speedStart 同步跑完整轮（NAPI 在 async work 线程上）；业务失败一律走返回值
// {"ok":false,"reason","msg"}。
func speedStart(raw string) map[string]any {
	var p speedParams
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return speedFail("invalid_arg", fmt.Sprintf("参数不是合法 JSON：%v", err))
	}
	if p.Auth == "" || p.Sock == "" {
		return speedFail("bridge_down", "桥未就绪（缺 auth/sock：VPN 未连接且服务会话未就绪）")
	}
	down := time.Duration(p.DownMs) * time.Millisecond
	up := time.Duration(p.UpMs) * time.Millisecond
	warmup := time.Duration(p.WarmupMs) * time.Millisecond
	if down == 0 {
		down = 10 * time.Second
	}
	if up == 0 {
		up = 10 * time.Second
	}
	if warmup == 0 {
		warmup = 2 * time.Second
	}
	if down > speedMaxWindow || up > speedMaxWindow || warmup > speedMaxWarmup {
		return speedFail("invalid_arg", fmt.Sprintf("窗口/预热超上限（窗口 ≤ %s、预热 ≤ %s）", speedMaxWindow, speedMaxWarmup))
	}
	streams := p.Streams
	if streams == 0 {
		streams = 4
	}
	if streams < 1 || streams > speedMaxStreams {
		return speedFail("invalid_arg", fmt.Sprintf("并行流数 %d 超出 [1,%d]", streams, speedMaxStreams))
	}

	speed.mu.Lock()
	if speed.running {
		speed.mu.Unlock()
		return speedFail("busy", "已有测速在跑（单飞）")
	}
	speed.gen++
	run := newSpeedRun(speed.gen)
	speed.running = true
	speed.phase = spConnecting
	speed.reason = ""
	speed.startedAt = time.Now()
	speed.run = run
	speed.mu.Unlock()
	// 判据行在锁外打（评审 F10）。
	speedLogf("speedtest: 开跑（down %d流 warmup=%s window=%s）", streams, warmup, down)

	// 总预算看门狗（评审 F3）：无论如何到点强制当轮取消，引擎不可能永久停在窗口里。
	wd := time.AfterFunc(speedWatchdog+warmup+down+up, run.timeout)
	defer wd.Stop()

	res := speed.runRound(p, run, down, up, warmup, streams)

	speed.mu.Lock()
	speed.running = false
	speed.mu.Unlock()
	return res
}

func (e *speedEngine) setPhase(p speedPhase, reason string) {
	e.mu.Lock()
	e.phase = p
	if reason != "" {
		e.reason = reason
	}
	e.mu.Unlock()
}

// speedDial 拨本机测速桥（照 nativeFilesDial 的归因）并消费问候帧：
//   - unix 拨不上 = bridge_down（链路/服务会话都不在）；
//   - 鉴权失败 = bridge_auth；
//   - 问候期读到 report{link_down} = 桥宿主拨出口失败（出口不在/正在恢复）⇒ link_down；
//   - 问候期 report{busy} = 出口并发满员 ⇒ busy；
//   - 问候期 EOF/复位/协议不符 = 对端真是出口但没测速服务 ⇒ not_supported。
//
// 连接建立即登记进当轮（评审 F2：拨号/问候期也可被取消关闭，Cancel 关得到等待中的
// greeting）；greeting 过后设「预热+窗口+15s」硬期限（评审 F3，读写都盖）。
// 返回的 br 必须在后续读路径复用（缓冲延续，换 Reader 会错位）。
func speedDial(run *speedRun, ctx context.Context, authHex, sock string, warmup, window time.Duration) (net.Conn, *bufio.Reader, *speedError) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", sock)
	if err != nil {
		if run.isCancelled() {
			return nil, nil, speedErrf("cancelled", "测速已取消")
		}
		if run.timedOutNow() {
			return nil, nil, speedErrf("timeout", "链路长时间不通，测速超时")
		}
		return nil, nil, speedErrf("bridge_down", "测速通道暂时不可用（桥未就绪或正在恢复）：%v", err)
	}
	run.track(conn)
	if err := bridgeWriteAuth(conn, authHex); err != nil {
		_ = conn.Close()
		run.untrack(conn)
		return nil, nil, speedErrf("bridge_auth", "测速通道鉴权失败：%v", err)
	}
	br := bufio.NewReader(conn)
	// 问候预算 = 桥宿主拨出口的预算（15s）+ 隧道 RTT 余量。
	_ = conn.SetReadDeadline(time.Now().Add(speedDialBridge))
	gerr := speedtest.ReadGreeting(br)
	_ = conn.SetReadDeadline(time.Time{})
	if gerr != nil {
		_ = conn.Close()
		run.untrack(conn)
		if run.isCancelled() {
			return nil, nil, speedErrf("cancelled", "测速已取消")
		}
		switch gerr.Error() {
		case "busy":
			return nil, nil, speedErrf("busy", "出口测速服务并发满员，请稍后再试")
		case "link_down":
			return nil, nil, speedErrf("link_down", "链路正在恢复")
		default:
			return nil, nil, speedErrf("not_supported", "出口没有测速服务（请升级出口）：%v", gerr)
		}
	}
	// 数据期硬期限（评审 F3）：读写都盖；到点必然报错收场，绝不无限挂。
	_ = conn.SetDeadline(time.Now().Add(warmup + window + speedConnBudget))
	return conn, br, nil
}

func (e *speedEngine) runRound(p speedParams, run *speedRun, down, up, warmup time.Duration, streams int) map[string]any {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ---- 下行：4 条 role=recv ----
	e.setPhase(spConnecting, "")
	// 先拨齐全部连接、再统一发请求：服务端的预热从「收到请求」起算，若拨一条发一条，
	// 早拨的流窗口会比晚拨的早开（拨号时差直接变成窗口错位）。拨齐后请求几乎同时到达，
	// 各流窗口彼此对齐、也与下面的 t0 对齐（design D3）。
	type dialResult struct {
		conn net.Conn
		br   *bufio.Reader
	}
	downRaw := make([]dialResult, 0, streams)
	for i := 0; i < streams; i++ {
		conn, br, serr := speedDial(run, ctx, p.Auth, p.Sock, warmup, down)
		if serr != nil {
			run.closeAll()
			return e.finishRun(run.gen, spFailed, serr.Code, serr.Msg)
		}
		downRaw = append(downRaw, dialResult{conn, br})
	}
	for _, d := range downRaw {
		bw := bufio.NewWriter(d.conn)
		if err := speedtest.WriteRequest(bw, speedtest.RoleRecv, warmup, down); err != nil {
			run.closeAll()
			return e.finishRun(run.gen, spFailed, run.reasonOr("interrupted"), fmt.Sprintf("发下行请求失败：%v", err))
		}
		if err := bw.Flush(); err != nil {
			run.closeAll()
			return e.finishRun(run.gen, spFailed, run.reasonOr("interrupted"), fmt.Sprintf("发下行请求失败：%v", err))
		}
	}
	if run.isCancelled() {
		run.closeAll()
		return e.finishRun(run.gen, spCancelled, "cancelled", "测速已取消")
	}

	// 计时窗从连接成功后起算（design D3）：预热尾端 + 滞后余量才是 t0。
	// 预热并入方向相位（评审 r2-N9：spWarmup 实际不可观测，删掉——预热期 live≈0）。
	run.setWindow(time.Now().Add(warmup+speedPhaseSlack), down)
	e.setPhase(spDown, "")
	downGot := make([]int64, streams)
	downErrs := make([]error, streams)
	var downUsage int64
	var downSrv int64 // 服务端 report 的窗内字节汇总（对账判据行用）
	var downSrvWarm int64
	var wg sync.WaitGroup
	for i, d := range downRaw {
		wg.Add(1)
		go func(i int, d dialResult) {
			defer wg.Done()
			defer run.untrack(d.conn)
			defer func() { _ = d.conn.Close() }()
			got, used, sb, sw, rerr := e.readDownStream(run, d.br)
			downGot[i] = got
			atomic.AddInt64(&downUsage, used)
			atomic.AddInt64(&downSrv, sb)
			atomic.AddInt64(&downSrvWarm, sw)
			downErrs[i] = rerr
		}(i, d)
	}
	wg.Wait()
	run.addUsage(false, downUsage)
	for i, rerr := range downErrs {
		if rerr != nil {
			run.closeAll()
			if run.isCancelled() {
				return e.finishRun(run.gen, spCancelled, "cancelled", "测速已取消")
			}
			if run.timedOutNow() {
				return e.finishRun(run.gen, spFailed, "timeout", "链路长时间不通，测速超时")
			}
			return e.finishRun(run.gen, spFailed, "interrupted", fmt.Sprintf("下行流 %d 中断：%v", i, rerr))
		}
	}
	downBps := windowBps(sum(downGot), down)
	// 下行对账（design D3「END 帧对账」落实——原先 report 的服务端字节读到即弃）：
	// 接收端窗内计数 vs 服务端窗内发出。稳态偏差应≈窗口错位余量（<2%）；显著偏大
	// = 链路侧重传堆积或窗口错位的自动判据，不用再人工四方对账。
	if downSrv > 0 {
		speedLogf("speedtest: 下行对账（接收端窗内=%dB 服务端窗内=%dB 预热=%dB 偏差=%.2f%%）",
			sum(downGot), downSrv, downSrvWarm, float64(downSrv-sum(downGot))/float64(downSrv)*100)
	}

	// ---- 上行：4 条 role=send（新连接：每流一角色不复用）----
	e.setPhase(spConnecting, "")
	upResults := make([]int64, streams)
	upErrs := make([]error, streams)
	upWalls := make([]int64, streams)
	upStreams := make([]dialResult, streams)
	for i := 0; i < streams; i++ {
		conn, br, serr := speedDial(run, ctx, p.Auth, p.Sock, warmup, up)
		if serr != nil {
			run.closeAll()
			return e.finishRun(run.gen, spFailed, serr.Code, serr.Msg)
		}
		upStreams[i] = dialResult{conn, br}
	}
	run.setWindow(time.Now().Add(warmup+speedPhaseSlack), up)
	e.setPhase(spUp, "")
	var upWg sync.WaitGroup
	for i := range upStreams {
		upWg.Add(1)
		go func(i int) {
			defer upWg.Done()
			defer run.untrack(upStreams[i].conn)
			defer func() { _ = upStreams[i].conn.Close() }()
			got, used, wallMs, rerr := runUpStream(run, upStreams[i].conn, upStreams[i].br, warmup, up)
			upResults[i] = got
			upWalls[i] = wallMs
			run.addUsage(true, used)
			upErrs[i] = rerr
		}(i)
	}
	upWg.Wait()
	for i, rerr := range upErrs {
		if rerr != nil {
			run.closeAll()
			if run.isCancelled() {
				return e.finishRun(run.gen, spCancelled, "cancelled", "测速已取消")
			}
			if run.timedOutNow() {
				return e.finishRun(run.gen, spFailed, "timeout", "链路长时间不通，测速超时")
			}
			return e.finishRun(run.gen, spFailed, "interrupted", fmt.Sprintf("上行流 %d 中断：%v", i, rerr))
		}
	}
	// 上行分母用服务端实测墙钟均值（评审零散项：名义 10s 有 ~1% 虚高）。
	var wallSum int64
	for _, w := range upWalls {
		wallSum += w
	}
	denom := up
	if wallSum > 0 {
		denom = time.Duration(wallSum/int64(streams)) * time.Millisecond
	}
	upBps := windowBps(sum(upResults), denom)

	run.closeAll()
	return e.finishOK(run.gen, downBps, upBps)
}

// reasonOr：错误路径上优先认「取消」——Cancel 关连接会让在跑的读/写以任意错误退出，
// 只看 error 会误归因成 interrupted。
func (r *speedRun) reasonOr(def string) string {
	if r.isCancelled() {
		return "cancelled"
	}
	if r.timedOutNow() {
		return "timeout"
	}
	return def
}

// readDownStream 读一条下行流：预热期字节只进用量；窗口期字节进读数。收 report 正常收场。
// 用量只计**实收字节**（评审 F7：rep.WarmupBytes 与实收的预热是同一批字节，再加就是双计）。
// data 帧走 header+discard 零分配路径（评审 F9），report 帧读进小缓冲。
// 返回服务端 report 的窗内/预热字节（srvBytes/srvWarm）——runRound 汇总打对账判据行；
// 注意 recv 会话的 WallMs 含预热（t0 在预热泵前），与 send 会话（START→FINISH）语义不同，
// 这里不消费它。
func (e *speedEngine) readDownStream(run *speedRun, br *bufio.Reader) (got, used, srvBytes, srvWarm int64, err error) {
	ctrl := make([]byte, 1024)
	for {
		t, _, n, payload, rerr := speedtest.ReadFrameLoose(br, ctrl)
		if rerr != nil {
			return got, used, srvBytes, srvWarm, rerr
		}
		switch t {
		case speedtest.TypeData:
			if err := speedtest.DiscardPayload(br, n); err != nil {
				return got, used, srvBytes, srvWarm, err
			}
			used += int64(n)
			if run.countInWindow(int64(n)) {
				got += int64(n)
			}
		case speedtest.TypeReport:
			var rep speedtest.Report
			if jerr := json.Unmarshal(payload, &rep); jerr != nil {
				return got, used, srvBytes, srvWarm, jerr
			}
			if rep.Error != "" {
				return got, used, srvBytes, srvWarm, fmt.Errorf("%s", rep.Error)
			}
			return got, used, rep.Bytes, rep.WarmupBytes, nil
		default:
			return got, used, srvBytes, srvWarm, fmt.Errorf("下行期收到类型 %d", t)
		}
	}
}

// runUpStream 一条上行流：预热泵 → START → 窗口泵 → FINISH → report（接收端报数）。
// br 来自 speedDial（问候已消费、缓冲必须延续），写侧自建。
// 窗口泵按 250ms 分片并回调实时字节（评审 F1：上行 instBps 的数据源；分片同时是取消
// 检查点——连接被 Cancel 关掉时下一片写必然报错）。
func runUpStream(run *speedRun, conn net.Conn, br *bufio.Reader, warmup, window time.Duration) (got, used, wallMs int64, err error) {
	bw := bufio.NewWriter(conn)
	if werr := speedtest.WriteRequest(bw, speedtest.RoleSend, warmup, window); werr != nil {
		return 0, 0, 0, werr
	}
	if werr := bw.Flush(); werr != nil {
		return 0, 0, 0, werr
	}
	block := make([]byte, speedBlockBytes)
	var seq uint32
	warm := speedtest.PumpData(bw, block, &seq, warmup)
	if werr := bw.Flush(); werr != nil {
		return 0, warm, warm, werr
	}
	speedtest.WriteStart(bw)
	if werr := bw.Flush(); werr != nil {
		return 0, warm, warm, werr
	}
	// 窗口泵：分片推进；**字节数必须用分片泵的返回值**（评审 r2-N1：一片内写多帧，
	// 「一片一帧」的记法曾造成 1~2 个数量级的少算）。
	var sent int64
	{
		deadline := time.Now().Add(window)
		scratch := make([]byte, speedtest.MaxHeader+len(block))
		copy(scratch[speedtest.MaxHeader:], block)
		for !time.Now().After(deadline) {
			n, err := speedtest.PumpDataChunk(bw, scratch, &seq, 250*time.Millisecond)
			if n > 0 {
				sent += n
				run.addLive(n)
			}
			if ferr := bw.Flush(); ferr != nil {
				break
			}
			if err != nil {
				break
			}
		}
	}
	if werr := bw.Flush(); werr != nil {
		return 0, warm + sent, warm + sent, werr
	}
	speedtest.WriteFinish(bw)
	if werr := bw.Flush(); werr != nil {
		return 0, warm + sent, warm + sent, werr
	}
	rep, rerr := speedtest.ReadReport(br)
	if rerr != nil {
		return 0, warm + sent, warm + sent, rerr
	}
	return rep.Bytes, warm + sent, rep.WallMs, nil
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

// finishRun 终态写回（失败/取消）：世代比对（评审 F2——旧轮收尾不得覆盖新轮的全局相位）。
func (e *speedEngine) finishRun(gen uint64, phase speedPhase, reason, msg string) map[string]any {
	e.mu.Lock()
	if e.gen == gen {
		e.phase = phase
		e.reason = reason
	}
	e.mu.Unlock()
	speedLogf("speedtest: 终止（原因=%s）%s", reason, msg)
	return map[string]any{
		"ok":     false,
		"reason": reason,
		"msg":    msg,
	}
}

func (e *speedEngine) finishOK(gen uint64, downBps, upBps float64) map[string]any {
	e.mu.Lock()
	usageDown, usageUp, run := int64(0), int64(0), e.run
	if e.gen == gen {
		e.phase = spDone
		e.reason = ""
	}
	e.mu.Unlock()
	if run != nil {
		run.mu.Lock()
		usageDown, usageUp = run.usageDown, run.usageUp
		run.mu.Unlock()
	}
	wall := time.Since(e.startedAt).Milliseconds()
	// 判据行（design D5）：精确值形态——取整只发生在 App 展示层（D7）。
	speedLogf("speedtest: 完成（down=%dB/s（%.2fMbps） up=%dB/s（%.2fMbps） 用量=%dMB 用时=%ds）",
		int64(downBps), downBps*8/1e6, int64(upBps), upBps*8/1e6,
		(usageDown+usageUp)/(1<<20), wall/1000)
	return map[string]any{
		"ok":        true,
		"phase":     string(spDone),
		"downBps":   downBps,
		"upBps":     upBps,
		"usageDown": usageDown,
		"usageUp":   usageUp,
		"wallMs":    wall,
	}
}

// cancelActive 取消当前在跑的一轮（幂等；空闲时无害空操作）。
// 只波及当轮（评审 F2）：关当轮连接 + 置当轮旗标，全局相位同步标记。
func (e *speedEngine) cancelActive() {
	e.mu.Lock()
	r, running := e.run, e.running
	e.mu.Unlock()
	if r == nil || !running {
		return
	}
	r.cancel()
	e.setPhase(spCancelled, "cancelled")
}

// snapshot Status 的 JSON（页面 250ms 轮询）。
func (e *speedEngine) snapshot() map[string]any {
	e.mu.Lock()
	phase, reason, startedAt, run := e.phase, e.reason, e.startedAt, e.run
	e.mu.Unlock()
	m := map[string]any{
		"phase":  string(phase),
		"reason": reason,
	}
	if run != nil {
		run.mu.Lock()
		m["usageDown"] = run.usageDown
		m["usageUp"] = run.usageUp
		ws, wl, live := run.windowStart, run.windowLen, run.liveBytes
		run.mu.Unlock()
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
					case spDown:
						dir = "down"
					case spUp:
						dir = "up"
					}
					m["dir"] = dir
					m["bytes"] = live
					m["instBps"] = float64(live) / elapsed
				}
			}
		}
	}
	if !startedAt.IsZero() {
		e.mu.Lock()
		m["elapsedMs"] = time.Since(startedAt).Milliseconds()
		e.mu.Unlock()
	}
	return m
}

// ---------- JSON 信封 ----------

func speedMarshal(res map[string]any) *C.char {
	out, err := json.Marshal(res)
	if err != nil {
		out = []byte(`{"ok":false,"reason":"invalid_arg","msg":"结果序列化失败"}`)
	}
	return C.CString(string(out))
}
