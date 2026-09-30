package control

// l2_upstream_test.go — 4a §5.1（L2 有界在途）与 §5.3（上行收流宽容化）的红绿
// 用例。L2 三路（tasks 5.1）：33 条并发慢请求触发 goodbye(overrun) 断连而守护
// 进程存活；32 条内全部应答边界；stream.open 在途时同连接另一请求照常应答
//（拨号独立执行体不占工位串行位，r2 新-6）。上行四路（tasks 5.3）：≤40 帧背靠背
// 大块上行流存活且数据完整；>40 帧仍收流（如实断言）；对端真死 → 停滞超时收流
// gone；停滞不扩散（一流停滞不拖同连接其它流/请求）。

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/facade"
)

// ---------- L2：有界在途（tasks 5.1） ----------

// closeOnce 幂等关闭（测试收尾与失败路径共用）。
func closeOnce(c chan struct{}) func() {
	var once sync.Once
	return func() { once.Do(func() { close(c) }) }
}

// l2RawReq 拼一条请求帧（raw 字节口径）。
func l2RawReq(corr uint64, op string, args string) []byte {
	body := fmt.Sprintf(`{"corr":%d,"op":%q,"args":%s}`, corr, op, args)
	return EncodeFrame(OpReq, []byte(body))
}

// l2ExpectGoodbyeOverrun 读到 goodbye(overrun) 后连接关闭（EOF）。
func l2ExpectGoodbyeOverrun(t *testing.T, nc net.Conn, r *bufio.Reader) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_ = nc.SetReadDeadline(time.Now().Add(2 * time.Second))
		head := make([]byte, 5)
		if _, err := io.ReadFull(r, head); err != nil {
			t.Fatalf("读帧头失败（未等到 goodbye(overrun)）：%v", err)
		}
		n := int(head[1])<<24 | int(head[2])<<16 | int(head[3])<<8 | int(head[4])
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			t.Fatalf("读 body 失败：%v", err)
		}
		if head[0] == OpGoodbye {
			var g GoodbyeBody
			if err := json.Unmarshal(body, &g); err != nil {
				t.Fatalf("goodbye JSON：%v", err)
			}
			if g.Reason != GoodbyeOverrun {
				t.Fatalf("goodbye 原因应为 overrun，得到 %q", g.Reason)
			}
			// 断连：随后 EOF。
			_ = nc.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := r.ReadByte(); err != io.EOF {
				t.Fatalf("overrun 后应断连（EOF），读到 err=%v", err)
			}
			return
		}
	}
	t.Fatal("5s 内未等到 goodbye(overrun)")
}

// TestServerL2OverrunDisconnectsAt33 红绿主路（r1 低-13 + 新-17 口径对齐）：
// 假 Backend 阻塞（entered 同步点），等第一条进入执行后再灌剩余——1 条执行中 +
// 31 条在队 = 在途 32，第 33 条触发 goodbye(overrun) 断连，而**守护进程存活**
// （新连接照常应答）。
func TestServerL2OverrunDisconnectsAt33(t *testing.T) {
	ts := startTestServer(t, facade.BusConfig{})
	entered, release := ts.backend.blockAdd()
	releaseFn := closeOnce(release)
	t.Cleanup(releaseFn) // 失败路径也放行（先于 srv.Close——防工位在途请求挂死收尾）

	nc, r := b3RawDial(t, ts)
	// 第 1 条：进入假 Backend（同步点）——工位执行中。
	if _, err := nc.Write(l2RawReq(1, facade.OpHostAdd, `{"name":"slow","token":"T1"}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("首条请求未进入假 Backend")
	}
	// 第 2..32 条：入队（31 条）——在途恰 32。
	for i := 2; i <= 32; i++ {
		if _, err := nc.Write(l2RawReq(uint64(i), facade.OpHostAdd, fmt.Sprintf(`{"name":"n%d","token":"T%d"}`, i, i))); err != nil {
			t.Fatal(err)
		}
	}
	// 灌完 31 条在队的微窗口（入队即计数——理论上同步完成，防御性等一小段）。
	time.Sleep(100 * time.Millisecond)
	// 第 33 条：超界 → goodbye(overrun) 断连。
	if _, err := nc.Write(l2RawReq(33, facade.OpHostAdd, `{"name":"over","token":"T33"}`)); err != nil {
		t.Fatal(err)
	}
	l2ExpectGoodbyeOverrun(t, nc, r)

	// 守护进程存活：新连接 daemon.status 照常应答。
	c2ctx, c2cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer c2cancel()
	c2, _, err := Dial(c2ctx, ts.sock, FrontendInfo{Kind: "cli", Name: "after", Version: "0"})
	if err != nil {
		t.Fatalf("overrun 断连后守护进程应存活：%v", err)
	}
	defer c2.Close()
	if _, err := c2.Request(c2ctx, facade.OpDaemonStatus, nil); err != nil {
		t.Fatalf("overrun 后新连接请求应照常应答：%v", err)
	}
	releaseFn() // 放行阻塞（被断连接的工位在途请求自然返回，rsp 写出无消费面、安全丢弃）
}

// TestServerL2WithinBoundAllAnswered 边界用例：32 条并发慢请求（恰在界内）全部
// 应答（corr 逐一齐全）——界不是「第 32 条也断连」。
func TestServerL2WithinBoundAllAnswered(t *testing.T) {
	ts := startTestServer(t, facade.BusConfig{})
	entered, release := ts.backend.blockAdd()
	releaseFn := closeOnce(release)
	t.Cleanup(releaseFn)
	nc, r := b3RawDial(t, ts)
	const total = 32
	for i := 1; i <= total; i++ {
		if _, err := nc.Write(l2RawReq(uint64(i), facade.OpHostAdd, fmt.Sprintf(`{"name":"n%d","token":"T%d"}`, i, i))); err != nil {
			t.Fatal(err)
		}
	}
	// 首条已进入假 Backend（entered 缓冲信号）——其余在队；放行后全部执行。
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("首条请求未进入假 Backend")
	}
	releaseFn()
	got := map[uint64]bool{}
	dl := time.After(10 * time.Second)
	for len(got) < total {
		_ = nc.SetReadDeadline(time.Now().Add(3 * time.Second))
		head := make([]byte, 5)
		if _, err := io.ReadFull(r, head); err != nil {
			t.Fatalf("读帧头失败（已收 %d/32）：%v", len(got), err)
		}
		n := int(head[1])<<24 | int(head[2])<<16 | int(head[3])<<8 | int(head[4])
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			t.Fatalf("读 body 失败：%v", err)
		}
		if head[0] != OpRsp {
			continue
		}
		var rsp ResponseBody
		if err := json.Unmarshal(body, &rsp); err != nil {
			t.Fatalf("rsp JSON：%v", err)
		}
		if !rsp.Ok {
			t.Fatalf("corr=%d 应答错误：%s", rsp.Corr, rsp.Error)
		}
		got[rsp.Corr] = true
		select {
		case <-dl:
			t.Fatalf("应答不全：%d/32", len(got))
		default:
		}
	}
}

// TestServerL2StreamOpenDialIndependent r2 新-6 判据：stream.open 的 30s 级拨号
// 走独立有界执行体——假 DialTerm 阻塞期间，同连接的 daemon.status 即时应答
// （拨号不占工位串行位）；放行后 stream.open 照常成功。
func TestServerL2StreamOpenDialIndependent(t *testing.T) {
	ts := startTestServer(t, facade.BusConfig{})
	entered, release := ts.backend.blockDial()
	c, _ := dialTest(t, ts)
	ctx := context.Background()

	openErr := make(chan error, 1)
	go func() {
		_, err := c.OpenStream(ctx, facade.StreamKindTerm, "aa")
		openErr <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("stream.open 未进入假拨号")
	}
	// 拨号在途：同连接另一请求照常应答（工位未被拨号占用）。
	rctx, rcancel := context.WithTimeout(ctx, 3*time.Second)
	defer rcancel()
	if _, err := c.Request(rctx, facade.OpDaemonStatus, nil); err != nil {
		t.Fatalf("拨号在途时同连接 daemon.status 应即时应答：%v", err)
	}
	close(release)
	select {
	case err := <-openErr:
		if err != nil {
			t.Fatalf("放行后 stream.open 应成功：%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stream.open 未在放行后完成")
	}
}

// TestStreamUpWorkerTotalLimit 全连接上行工位总量上限（4a §5.3：防「每流一
// 工位」的资源放大——超总量拒开新流，复用既有 stream_refused；工位随流终结
// 释放后可再开）。
func TestStreamUpWorkerTotalLimit(t *testing.T) {
	ts := startTestServerCfg(t, func(cfg *ServerConfig) { cfg.MaxUpWorkers = 1 })
	c, _ := dialTest(t, ts)
	ctx := context.Background()
	st1, err := c.OpenStream(ctx, facade.StreamKindTerm, "aa")
	if err != nil {
		t.Fatal(err)
	}
	// 第二条流（同连接）：工位总量已满 → stream_refused。
	if _, err := c.OpenStream(ctx, facade.StreamKindTerm, "aa"); !errors.Is(err, CodeError(facade.CodeStreamRefused)) {
		t.Fatalf("工位总量超限应 stream_refused，得到 %v", err)
	}
	// 关掉第一条（工位释放）→ 可再开。
	cctx, ccancel := context.WithTimeout(ctx, 3*time.Second)
	defer ccancel()
	if err := st1.Close(cctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, err := c.OpenStream(ctx, facade.StreamKindTerm, "aa")
		if err == nil {
			return // 工位已释放、再开成功
		}
		if !errors.Is(err, CodeError(facade.CodeStreamRefused)) {
			t.Fatalf("再开应只可能 stream_refused（释放竞态），得到 %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("工位释放后仍拒开（配额泄漏——红路）")
}

// ---------- §5.3：上行收流宽容化（tasks 5.3 四路） ----------

// startTestServerCfg startTestServer 的可配变体（UpStallTimeout 等注入）。
func startTestServerCfg(t *testing.T, tune func(*ServerConfig)) *testServer {
	t.Helper()
	dir := shortTempDir(t)
	bus := facade.NewBus(facade.NewGeneration(), facade.BusConfig{})
	backend := newFakeBackend()
	termLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	backend.dialAddr = termLn.Addr().String()
	cfg := ServerConfig{ServerVersion: "test-1.0", Bus: bus, Backend: backend, Logf: t.Logf}
	if tune != nil {
		tune(&cfg)
	}
	srv := NewServer(cfg)
	sock, ln, err := ListenControl(dir)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	ts := &testServer{dir: dir, sock: sock, bus: bus, backend: backend, srv: srv, termLn: termLn, t: t}
	t.Cleanup(func() {
		srv.Close()
		_ = termLn.Close()
	})
	return ts
}

// slowReadBackend 慢读后端：接受连接后按小块慢慢读（活着但慢），收满 want 字节
// 后发信号（「对端慢读但活着」形态）。
func slowReadBackend(t *testing.T, ln net.Listener, want int) chan struct{} {
	t.Helper()
	done := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		got := 0
		buf := make([]byte, 4<<10)
		for got < want {
			n, rerr := c.Read(buf)
			got += n
			if n > 0 {
				time.Sleep(2 * time.Millisecond) // 慢但在读
			}
			if rerr != nil {
				return
			}
		}
		close(done)
		_ = c.Close()
	}()
	return done
}

// TestStreamUpstreamBurstWithinToleranceSurvives ①（改前红：>8 帧背靠背立即
// gone）：20 帧 × 16KiB 背靠背大块上行（>8 帧旧队列、≤40 帧有效缓冲），对端慢读
// 但活着 → 流存活且数据完整到达后端。
func TestStreamUpstreamBurstWithinToleranceSurvives(t *testing.T) {
	ts := startTestServerCfg(t, nil)
	const frames = 20
	const frameSize = 16 << 10
	payload := make([]byte, frames*frameSize)
	for i := range payload {
		payload[i] = byte(i * 13 % 251)
	}
	// pipe 后端 + 慢排空（10ms/帧）：upstreamPump 每帧都真等对端读——upC 稳定
	// 满（确定性触发旧形态「>8 帧即秒杀」），对端又在读（活着）。
	ts.backend.mu.Lock()
	ts.backend.dialAddr = pipeDialAddr
	ts.backend.pipeDrainEvery = 10 * time.Millisecond
	ts.backend.mu.Unlock()
	c, _ := dialTest(t, ts)
	st, err := c.OpenStream(context.Background(), facade.StreamKindTerm, "aa")
	if err != nil {
		t.Fatal(err)
	}
	// 背靠背：不等回包逐帧 Send（ClientStream.Send 16KiB 分片 = 1 帧/次）。
	for off := 0; off < len(payload); off += frameSize {
		if err := st.Send(payload[off : off+frameSize]); err != nil {
			t.Fatalf("第 %d 帧 Send：%v", off/frameSize, err)
		}
	}
	// 数据完整到达后端：慢排空累计字节数收齐（20 帧 × 10ms ≈ 200ms；上限 10s
	// 容 CI 调度抖动）。
	deadline := time.Now().Add(10 * time.Second)
	for ts.backend.pipeDrained.Load() < int64(len(payload)) {
		if time.Now().After(deadline) {
			t.Fatalf("慢读后端未收齐全部上行数据：%d/%d（数据丢失或流被误收）",
				ts.backend.pipeDrained.Load(), len(payload))
		}
		time.Sleep(20 * time.Millisecond)
	}
	// 流未被收流（end 不应到达——数据完整、对端活着）。
	select {
	case r := <-st.End():
		t.Fatalf("≤40 帧背靠背不应收流（宽容化失效）：end=%q", r)
	default:
	}
}

// TestStreamUpstreamOverToleranceStillGone ②（如实断言，非无限缓速排空）：
// >40 帧仍收流（每流有效缓冲 = upC 8 + 工位 32 = 40 帧；41 帧起 = gone——发送端
// 仍义务分片节流、消费端仍义务及时读）。pipe 后端（对端从不读）= 确定性载体。
func TestStreamUpstreamOverToleranceStillGone(t *testing.T) {
	ts := startTestServerCfg(t, nil)
	ts.backend.mu.Lock()
	ts.backend.dialAddr = pipeDialAddr
	ts.backend.mu.Unlock()
	c, _ := dialTest(t, ts)
	st, err := c.OpenStream(context.Background(), facade.StreamKindTerm, "aa")
	if err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 16<<10) // 16KiB/帧（3b 分片形态）
	for i := range chunk {
		chunk[i] = byte(i)
	}
	// 45 帧背靠背（>40）：工位双界取先到 → gone（end 帧到达即判据——Send 侧的
	// EndedErr 复查与 end 帧到达存在天然竞态，不作断言）。
	for i := 0; i < 45; i++ {
		if err := st.Send(chunk); err != nil {
			break // 流已被收流（ErrStreamEnded 族）
		}
	}
	select {
	case r := <-st.End():
		if r != facade.StreamEndGone {
			t.Fatalf(">40 帧应收流 gone，得到 %q", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal(">40 帧背靠背应收流（非无限缓速排空）——gone 未到达")
	}
}

// TestStreamUpstreamStallTimeoutGone ③：对端真死（不读）→ 工位停滞等待超时
// （UpStallTimeout 注入 300ms）→ 收流 gone；停滞等待/超时收流计数进观测。
func TestStreamUpstreamStallTimeoutGone(t *testing.T) {
	ts := startTestServerCfg(t, func(cfg *ServerConfig) { cfg.UpStallTimeout = 300 * time.Millisecond })
	ts.backend.mu.Lock()
	ts.backend.dialAddr = pipeDialAddr
	ts.backend.mu.Unlock()
	c, _ := dialTest(t, ts)
	st, err := c.OpenStream(context.Background(), facade.StreamKindTerm, "aa")
	if err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 16<<10)
	for i := 0; i < 10; i++ { // ≤40 帧：全部被吸收，触发的是停滞等待路径
		if err := st.Send(chunk); err != nil {
			t.Fatalf("第 %d 帧 Send（应先被吸收）：%v", i, err)
		}
	}
	select {
	case r := <-st.End():
		if r != facade.StreamEndGone {
			t.Fatalf("停滞超时应收流 gone，得到 %q", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("停滞超时收流未发生（UpStallTimeout 未生效）")
	}
	// 观测计数：≥1 次停滞等待、≥1 次超时收流。
	if ts.srv.upStallWaits.Load() < 1 {
		t.Fatal("停滞等待计数应 ≥1（进观测）")
	}
	if ts.srv.upStallKills.Load() < 1 {
		t.Fatal("超时收流计数应 ≥1（进观测）")
	}
}

// TestStreamUpstreamStallDoesNotPropagate ④（「慢流 MUST NOT 阻塞」上行方向）：
// 一条流停滞吃满工位（对端不读），同连接另一条流照常收发、请求照常应答。
func TestStreamUpstreamStallDoesNotPropagate(t *testing.T) {
	ts := startTestServerCfg(t, func(cfg *ServerConfig) { cfg.UpStallTimeout = 400 * time.Millisecond })
	echo := startEchoBackend(t)
	// 同一 fakeBackend 只有一个 dialAddr——两条流拨不同后端需分流：先开停滞流
	//（pipe，对端从不读），再切 dialAddr 到 echo 开健康流。
	ts.backend.mu.Lock()
	ts.backend.dialAddr = pipeDialAddr
	ts.backend.mu.Unlock()
	c, _ := dialTest(t, ts)
	ctx := context.Background()
	stalled, err := c.OpenStream(ctx, facade.StreamKindTerm, "aa")
	if err != nil {
		t.Fatal(err)
	}
	ts.backend.mu.Lock()
	ts.backend.dialAddr = echo.ln.Addr().String()
	ts.backend.mu.Unlock()
	healthy, err := c.OpenStream(ctx, facade.StreamKindTerm, "bb")
	if err != nil {
		t.Fatal(err)
	}
	// 停滞流灌满缓冲（≤40 帧 → 全吸收 → 工位进入停滞等待）。
	chunk := make([]byte, 16<<10)
	for i := 0; i < 10; i++ {
		if err := stalled.Send(chunk); err != nil {
			t.Fatalf("停滞流第 %d 帧 Send：%v", i, err)
		}
	}
	// 停滞等待窗口内：健康流双向照常。
	msg := []byte("healthy-stream-ok")
	if err := healthy.Send(msg); err != nil {
		t.Fatalf("健康流 Send：%v", err)
	}
	got := make([]byte, 0, len(msg))
	dl := time.After(5 * time.Second)
	for len(got) < len(msg) {
		select {
		case b := <-healthy.Recv():
			got = append(got, b...)
		case r := <-healthy.End():
			t.Fatalf("健康流不应被停滞流拖垮：end=%q", r)
		case <-dl:
			t.Fatal("健康流 echo 未返回（停滞扩散——红路）")
		}
	}
	// 同连接请求照常应答。
	rctx, rcancel := context.WithTimeout(ctx, 3*time.Second)
	defer rcancel()
	if _, err := c.Request(rctx, facade.OpDaemonStatus, nil); err != nil {
		t.Fatalf("停滞流在途时同连接请求应照常应答：%v", err)
	}
	// 停滞流最终按超时收流（只收该流）。
	select {
	case r := <-stalled.End():
		if r != facade.StreamEndGone {
			t.Fatalf("停滞流应收 gone，得到 %q", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("停滞流超时收流未发生")
	}
}

// ---------- §6.2：daemon.status 的 demand 段（词表只增） ----------

// TestDaemonStatusDemandSection daemon.status 载荷携带 demand 段（各主机最近一拍
// 需求判定；旧前端按未知字段忽略——fixtures 不动）。
func TestDaemonStatusDemandSection(t *testing.T) {
	ts := startTestServer(t, facade.BusConfig{})
	ts.backend.mu.Lock()
	ts.backend.demand = []HostDemandBrief{
		{Host: strings.Repeat("11", 32), Active: true, Reason: "出站包", At: 1700000000000},
		{Host: strings.Repeat("22", 32), Active: false, Reason: "无", At: 1700000001000},
	}
	ts.backend.mu.Unlock()
	c, _ := dialTest(t, ts)
	raw, err := c.Request(context.Background(), facade.OpDaemonStatus, nil)
	if err != nil {
		t.Fatal(err)
	}
	var st DaemonStatusResult
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	if len(st.Demand) != 2 {
		t.Fatalf("demand 段应 2 条：%+v", st.Demand)
	}
	if !st.Demand[0].Active || st.Demand[0].Reason != "出站包" || st.Demand[0].At != 1700000000000 {
		t.Fatalf("demand 首条字段不符：%+v", st.Demand[0])
	}
	// 载荷原样（--json 消费面）：字符串里可见 demand 键。
	if !strings.Contains(string(raw), "\"demand\"") {
		t.Fatal("机器可读载荷应含 demand 键")
	}
}
