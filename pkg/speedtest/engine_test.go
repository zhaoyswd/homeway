// engine_test.go — 客户端引擎（3e §1.1 自 app_speedtest.go 收拢）：dial 注入桩 +
// 真实 Server 全链路。not_supported 三条判据、写失败短读窗、轮级取消、单飞、参数边界。
package speedtest

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

// tcpDial 生产形态的注入桩：拨真实 TCP 服务（与守护 runner 的 Host.DialPort 同构——
// 连接返回、错误原样）。
func tcpDial(addr string) DialFunc {
	return func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
}

// startEngineServer 起真实 Server（限额外层覆盖）。
func startEngineServer(t *testing.T, lim Limits) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	srv := NewServer(nil)
	srv.SetLimits(lim)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

// startFakeUpstream 起一个可控假上游：mode 决定 accept 后的行为。
//   - "close"      立即关（零字节 EOF——判据② 形态：桥拨被拒不回帧直接关）；
//   - "greeting"   发一个 Type=6 的旧问候帧再关（判据③：非 data/report 帧）；
//   - "linkdown"   发 report{link_down} 后立刻关（不读请求——写 EPIPE 竞态靶子）；
//   - "delay"      静默 15s 再关（拨号后等待期取消的靶子）。
func startFakeUpstream(t *testing.T, mode string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		var conns atomic.Int32
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn, idx int32) {
				defer c.Close()
				switch mode {
				case "close":
					return
				case "greeting":
					bw := bufio.NewWriter(c)
					_ = WriteControl(bw, FrameType(6), []byte(`{"proto":1}`))
					_ = bw.Flush()
					return
				case "linkdown":
					bw := bufio.NewWriter(c)
					_ = WriteControl(bw, TypeReport, []byte(`{"error":"link_down"}`))
					_ = bw.Flush()
					return
				case "delay":
					time.Sleep(15 * time.Second)
				case "hold": // 吞一切、永不回帧（L4：下行首帧前的读期限到点形态）
					buf := make([]byte, 8192)
					for {
						if _, err := c.Read(buf); err != nil {
							return
						}
					}
				case "halfhold": // L4：首条（recv 角色，Streams=1）回空 report 让下行收场；
					// 之后（send 角色）只吞不发——上行收口 report 缺席到点。
					br := bufio.NewReader(c)
					if _, _, _, err := readFrame(br); err != nil {
						return
					}
					if idx == 0 {
						bw := bufio.NewWriter(c)
						_ = WriteControl(bw, TypeReport, []byte(`{}`))
						_ = bw.Flush()
					}
					buf := make([]byte, 8192)
					for {
						if _, err := c.Read(buf); err != nil {
							return
						}
					}
				}
			}(c, conns.Add(1)-1)
		}
	}()
	return ln.Addr().String()
}

// clampConn 把引擎设置的读写期限钳到短窗（测试用——引擎的硬期限是
// warmup+window+15s〔connBudget〕，钳后「读期限到点」无需真烧 15s 即可复现）。
type clampConn struct {
	net.Conn
	limit time.Duration
}

func (c clampConn) SetDeadline(t time.Time) error {
	if d := time.Until(t); d > c.limit {
		t = time.Now().Add(c.limit)
	}
	return c.Conn.SetDeadline(t)
}

func (c clampConn) SetReadDeadline(t time.Time) error {
	if d := time.Until(t); d > c.limit {
		t = time.Now().Add(c.limit)
	}
	return c.Conn.SetReadDeadline(t)
}

// TestEngineReadDeadlineInterrupted L4（exec-r1）：读期限到点 ≠ 判据②——下行首帧前
// 与上行收口两处的「到点」均按 interrupted 通道错误呈现（EOF/复位才归 not_supported；
// 此前「链路在 END 相位断掉」会误报「出口没有测速服务（请升级出口）」）。
func TestEngineReadDeadlineInterrupted(t *testing.T) {
	clampDial := func(addr string) DialFunc {
		return func(ctx context.Context) (net.Conn, error) {
			conn, err := tcpDial(addr)(ctx)
			if err != nil {
				return nil, err
			}
			return clampConn{Conn: conn, limit: 700 * time.Millisecond}, nil
		}
	}
	p := Params{Down: 200 * time.Millisecond, Up: 200 * time.Millisecond, Warmup: 100 * time.Millisecond, Streams: 1}

	// 形态一：请求后上游永不应答（下行首帧前期限到点）。
	e := NewEngine(nil)
	res := e.Start(context.Background(), clampDial(startFakeUpstream(t, "hold")), p)
	if res.OK || res.Reason != ReasonInterrupted {
		t.Fatalf("reason = %s（msg=%s），期望 interrupted（读期限到点不冒充 not_supported）", res.Reason, res.Msg)
	}

	// 形态二：下行相位正常收场、上行收口 report 缺席到点。
	res2 := NewEngine(nil).Start(context.Background(), clampDial(startFakeUpstream(t, "halfhold")), p)
	if res2.OK || res2.Reason != ReasonInterrupted {
		t.Fatalf("reason = %s（msg=%s），期望 interrupted（收口期限到点不冒充 not_supported）", res2.Reason, res2.Msg)
	}
}

// TestEngineFullRun 全流程（下行 + 上行，2 流）——成功终态、用量为正、相位真实流转。
func TestEngineFullRun(t *testing.T) {
	addr := startEngineServer(t, Limits{ConnTimeout: 20 * time.Second})
	e := NewEngine(func(format string, args ...any) { t.Logf(format, args...) })

	done := make(chan Result, 1)
	go func() {
		done <- e.Start(context.Background(), tcpDial(addr), Params{
			Down: 500 * time.Millisecond, Up: 400 * time.Millisecond, Warmup: 100 * time.Millisecond, Streams: 2,
		})
	}()

	// 轮中观察相位流转。
	sawDown, sawUp := false, false
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) && !sawUp {
		snap := e.Snapshot()
		if snap.Live != nil && snap.Live.Dir == "down" {
			sawDown = true
		}
		if snap.Live != nil && snap.Live.Dir == "up" {
			sawUp = true
		}
		time.Sleep(30 * time.Millisecond)
	}
	if !sawDown || !sawUp {
		t.Fatalf("轮中相位流转缺失：down=%v up=%v", sawDown, sawUp)
	}

	res := <-done
	if !res.OK {
		t.Fatalf("期望成功终态，got reason=%s msg=%s", res.Reason, res.Msg)
	}
	if res.DownBps <= 0 || res.UpBps <= 0 {
		t.Fatalf("两向速率应为正：down=%v up=%v", res.DownBps, res.UpBps)
	}
	if res.UsageDown <= 0 || res.UsageUp <= 0 {
		t.Fatalf("两向用量应为正：down=%v up=%v", res.UsageDown, res.UsageUp)
	}
	if e.Snapshot().Phase != string(PhaseDone) {
		t.Fatalf("终态相位 = %v，期望 done", e.Snapshot().Phase)
	}
}

// TestEngineSingleFlight 单飞：running 中再 Start 报 busy、状态零变化。
func TestEngineSingleFlight(t *testing.T) {
	addr := startFakeUpstream(t, "delay")
	e := NewEngine(nil)
	done := make(chan Result, 1)
	go func() {
		done <- e.Start(context.Background(), tcpDial(addr), Params{Down: time.Second, Up: time.Second, Warmup: 100 * time.Millisecond, Streams: 1})
	}()
	for !e.Running() {
		time.Sleep(10 * time.Millisecond)
	}
	res := e.Start(context.Background(), tcpDial(addr), Params{})
	if res.OK || res.Reason != ReasonBusy {
		t.Fatalf("单飞应报 busy，got %+v", res)
	}
	e.CancelActive()
	if res := <-done; res.OK {
		t.Fatal("delay 上游应失败收场")
	}
}

// TestEngineDialErrorPassthrough 判据①：注入缝返回 DialError{Code:not_supported}
// ⇒ reason 原样 not_supported 且不进等待相位（r2 新-4 口径——refused-like 分类归注入缝）。
func TestEngineDialErrorPassthrough(t *testing.T) {
	var dials atomic.Int64
	dial := func(ctx context.Context) (net.Conn, error) {
		dials.Add(1)
		return nil, DialErrf(ReasonNotSupported, "出口没有测速服务（出口需升级）：连接被拒")
	}
	e := NewEngine(nil)
	t0 := time.Now()
	res := e.Start(context.Background(), dial, Params{Down: time.Second, Up: time.Second, Streams: 4})
	if res.OK || res.Reason != ReasonNotSupported {
		t.Fatalf("reason = %s，期望 not_supported（DialError.Code 原样透传）", res.Reason)
	}
	if el := time.Since(t0); el > 2*time.Second {
		t.Fatalf("not_supported %v 才收场——必须立即失败、不进任何等待相位", el)
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("首条流失败即收场，dial 次数 = %d（应 1）", n)
	}
}

// TestEngineZeroByteEOF 判据②：连接已建立、请求发出后读侧零字节 EOF ⇒ not_supported。
func TestEngineZeroByteEOF(t *testing.T) {
	addr := startFakeUpstream(t, "close")
	e := NewEngine(nil)
	res := e.Start(context.Background(), tcpDial(addr), Params{Down: time.Second, Up: time.Second, Streams: 2})
	if res.OK || res.Reason != ReasonNotSupported {
		t.Fatalf("reason = %s，期望 not_supported（请求后零字节 EOF）：%s", res.Reason, res.Msg)
	}
}

// TestEngineNonDataFrame 判据③：读到非 data/report 帧（旧出口预发问候帧）⇒ 按通道错误
// 如实呈现（interrupted），MUST NOT 冒充 not_supported。
func TestEngineNonDataFrame(t *testing.T) {
	addr := startFakeUpstream(t, "greeting")
	e := NewEngine(nil)
	res := e.Start(context.Background(), tcpDial(addr), Params{Down: time.Second, Up: time.Second, Streams: 1})
	if res.OK || res.Reason != ReasonInterrupted {
		t.Fatalf("reason = %s，期望 interrupted（非 data/report 帧按通道错误）：%s", res.Reason, res.Msg)
	}
}

// TestEngineWriteEPIPEEatsReport 写请求失败不提前归因（r1 中-1①）：上游不读请求、
// 回 report{link_down} 即关——写与关竞态下无论谁先，都必须吃到 report 归因 link_down，
// 不得吞成 interrupted；report 缺席的零字节形态按判据② 归 not_supported（r2 新-3）。
func TestEngineWriteEPIPEEatsReport(t *testing.T) {
	addr := startFakeUpstream(t, "linkdown")
	for i := 0; i < 3; i++ { // 多跑几轮放大两种竞态交错
		e2 := NewEngine(nil)
		res := e2.Start(context.Background(), tcpDial(addr), Params{Down: time.Second, Up: time.Second, Streams: 2})
		if res.OK || res.Reason != ReasonLinkDown {
			t.Fatalf("第 %d 轮 reason = %s（msg=%s），期望 link_down（写失败仍吃到 report）", i, res.Reason, res.Msg)
		}
	}
}

// TestEngineWriteEPIPEZeroByteNotSupported r2 新-3 parity：写失败 + 零字节读（无 report）
// 且连接已建立 ⇒ 同判据② not_supported（不得随写竞态抖成 interrupted）。
func TestEngineWriteEPIPEZeroByteNotSupported(t *testing.T) {
	// "close" 上游：accept 即关。写请求可能成功（进缓冲）也可能 EPIPE；两种交错下
	// 读侧都是零字节 ⇒ 一律 not_supported。
	addr := startFakeUpstream(t, "close")
	e := NewEngine(nil)
	res := e.Start(context.Background(), tcpDial(addr), Params{Down: time.Second, Up: time.Second, Streams: 2})
	if res.OK || res.Reason != ReasonNotSupported {
		t.Fatalf("reason = %s，期望 not_supported（写失败+零字节读=判据②）：%s", res.Reason, res.Msg)
	}
}

// TestEngineBusy 服务端满员：第二流收到 report{busy} ⇒ reason busy（跨请求-应答形态）。
func TestEngineBusy(t *testing.T) {
	addr := startEngineServer(t, Limits{MaxConns: 1, ConnTimeout: 20 * time.Second})
	e := NewEngine(nil)
	res := e.Start(context.Background(), tcpDial(addr), Params{Down: 300 * time.Millisecond, Up: 300 * time.Millisecond, Warmup: 100 * time.Millisecond, Streams: 2})
	if res.OK || res.Reason != ReasonBusy {
		t.Fatalf("reason = %s，期望 busy（并发满员 report）：%s", res.Reason, res.Msg)
	}
}

// TestEngineCancelDuringDial 取消落在拨号后的等待期（上游 delay 15s）：秒级收场且归
// cancelled（迁移前评审 F2-1 行为）。
func TestEngineCancelDuringDial(t *testing.T) {
	addr := startFakeUpstream(t, "delay")
	e := NewEngine(nil)
	done := make(chan Result, 1)
	go func() {
		done <- e.Start(context.Background(), tcpDial(addr), Params{Down: 3 * time.Second, Up: 3 * time.Second, Warmup: 200 * time.Millisecond, Streams: 1})
	}()
	time.Sleep(300 * time.Millisecond) // 已进入请求后等待期
	t0 := time.Now()
	e.CancelActive()
	select {
	case res := <-done:
		if res.OK || res.Reason != ReasonCancelled {
			t.Fatalf("reason = %s，期望 cancelled", res.Reason)
		}
		if el := time.Since(t0); el > 3*time.Second {
			t.Fatalf("取消后 %v 才收场，应秒级", el)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("取消后引擎未收场")
	}
}

// TestEngineCancelDuringDialStub 取消打断在途拨号（run.abort → 轮内 ctx 取消）。
func TestEngineCancelDuringDialStub(t *testing.T) {
	dial := func(ctx context.Context) (net.Conn, error) {
		select {
		case <-ctx.Done():
			return nil, DialErrf(ReasonCancelled, "测速已取消")
		case <-time.After(15 * time.Second):
			return nil, fmt.Errorf("不该到这")
		}
	}
	e := NewEngine(nil)
	done := make(chan Result, 1)
	go func() {
		done <- e.Start(context.Background(), dial, Params{Down: time.Second, Up: time.Second, Streams: 1})
	}()
	time.Sleep(300 * time.Millisecond)
	t0 := time.Now()
	e.CancelActive()
	select {
	case res := <-done:
		if res.OK || res.Reason != ReasonCancelled {
			t.Fatalf("reason = %s，期望 cancelled（在途拨号被 run.abort 打断）", res.Reason)
		}
		if el := time.Since(t0); el > 2*time.Second {
			t.Fatalf("取消后 %v 才收场，应秒级", el)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("取消后引擎未收场（在途拨号未被 ctx 打断）")
	}
}

// TestEngineParams 参数边界（越界 = invalid_arg，不静默钳制）。
func TestEngineParams(t *testing.T) {
	e := NewEngine(nil)
	cases := []struct {
		name   string
		params Params
	}{
		{"流数越界", Params{Streams: 99}},
		{"窗口越界", Params{Down: 60 * time.Second}},
		{"预热越界", Params{Warmup: 30 * time.Second}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := e.Start(context.Background(), tcpDial("127.0.0.1:1"), tc.params)
			if res.OK || res.Reason != ReasonInvalidArg {
				t.Fatalf("reason = %s，期望 invalid_arg", res.Reason)
			}
		})
	}
}

// TestEngineSnapshotShape Snapshot 面形态：idle（无 elapsed）/运行中（usage+elapsed）/
// 窗口内（live 读数）。
func TestEngineSnapshotShape(t *testing.T) {
	e := NewEngine(nil)
	if s := e.Snapshot(); s.Phase != string(PhaseIdle) || s.ElapsedMs != -1 || s.Usage != nil || s.Live != nil {
		t.Fatalf("idle 快照形态： %+v", s)
	}

	addr := startEngineServer(t, Limits{ConnTimeout: 20 * time.Second})
	done := make(chan Result, 1)
	go func() {
		done <- e.Start(context.Background(), tcpDial(addr), Params{Down: 800 * time.Millisecond, Up: 400 * time.Millisecond, Warmup: 100 * time.Millisecond, Streams: 1})
	}()
	for !e.Running() { // 等 Start 真正起轮（goroutine 调度差）
		time.Sleep(5 * time.Millisecond)
	}
	deadline := time.Now().Add(4 * time.Second)
	sawLive := false
	for time.Now().Before(deadline) {
		s := e.Snapshot()
		if s.ElapsedMs < 0 || s.Usage == nil {
			t.Fatalf("运行中快照缺 elapsed/usage： %+v", s)
		}
		if s.Live != nil && s.Live.Dir == "down" && s.Live.Bytes > 0 && s.Live.InstBps > 0 {
			sawLive = true
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !sawLive {
		t.Fatal("快照从未观察到 down 窗口 live 读数")
	}
	if res := <-done; !res.OK {
		t.Fatalf("成功终态：%+v", res)
	}
}

// uncomparableConn 复刻 facade.countedConn 的失效形态：**值类型**结构体 + func 字段
// ⇒ 动态类型不可哈希不可 ==。v0.13.0 的 run.conns 以 net.Conn 做 map 键，daemon
// runner 经 Host.DialPort 拿到这种 conn、首次真拨通即 panic（发版窗口实测）；本用例
// 在修复前的形态下跑全轮会直接炸（hash of unhashable type）。
type uncomparableConn struct {
	net.Conn
	onClose func()
}

func TestEngineUncomparableConn(t *testing.T) {
	addr := startEngineServer(t, Limits{ConnTimeout: 20 * time.Second})
	e := NewEngine(func(format string, args ...any) { t.Logf(format, args...) })
	// 先证伪测试自身：值结构体确实不可比较（否则用例退化成普通全轮）。
	if reflect.TypeOf(uncomparableConn{}).Comparable() {
		t.Fatal("uncomparableConn 形态漂移（应保持含 func 字段的值结构体——不可比较）")
	}

	dial := func(ctx context.Context) (net.Conn, error) {
		c, err := tcpDial(addr)(ctx)
		if err != nil {
			return nil, err
		}
		return uncomparableConn{Conn: c, onClose: func() { _ = c.Close() }}, nil
	}
	res := e.Start(context.Background(), dial, Params{
		Down: 300 * time.Millisecond, Up: 300 * time.Millisecond, Warmup: 100 * time.Millisecond, Streams: 2,
	})
	if !res.OK {
		t.Fatalf("不可比较 conn 的全轮应成功（修复前 = panic hash of unhashable type）：reason=%s msg=%s", res.Reason, res.Msg)
	}
}

// TestCancelActiveDoesNotOverrideFinished（FIX-44）：落在「结果已定、Start 尚未收尾」
// 窗口里的迟到取消，绝不能把 done 覆盖成 cancelled——原实现在锁外 setPhase，UI 会显示
// 「已取消」而调用方拿到 OK 结果（同一轮两种真相）。
// 构造：直接复现那一拍的引擎状态（runRound 已 finishOK、running 仍 true）。
func TestCancelActiveDoesNotOverrideFinished(t *testing.T) {
	e := NewEngine(nil)
	e.mu.Lock()
	e.gen++
	r := newRun(e.gen)
	e.run, e.running, e.phase = r, true, PhaseConnecting
	e.mu.Unlock()

	e.finishOK(r.gen, 1000, 100) // 结果落定（phase=done），但 Start 还没把 running 置 false
	if got := e.Snapshot().Phase; got != string(PhaseDone) {
		t.Fatalf("前置：相位应为 done，实际 %q", got)
	}
	e.CancelActive() // 迟到取消：必须 no-op
	snap := e.Snapshot()
	if snap.Phase != string(PhaseDone) {
		t.Fatalf("迟到取消覆盖了已落定的相位：got %q want %q", snap.Phase, PhaseDone)
	}
	if r.cancelled.Load() {
		t.Fatal("迟到取消还给已落定的一轮打了 cancel 旗标（会污染该轮结果归因）")
	}

	// 在跑的轮照常可取消（正路径不受影响）。
	e.mu.Lock()
	e.gen++
	r2 := newRun(e.gen)
	e.run, e.running, e.phase = r2, true, PhaseDown
	e.mu.Unlock()
	e.CancelActive()
	if !r2.cancelled.Load() {
		t.Fatal("在跑的一轮应可取消")
	}
	if got := e.Snapshot().Phase; got != string(PhaseCancelled) {
		t.Fatalf("取消后相位应为 cancelled，实际 %q", got)
	}
}
