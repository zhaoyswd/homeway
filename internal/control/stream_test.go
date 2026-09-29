package control

// stream_test.go — §3.5 流式通道单测（客户端驱动 + 原始字节）：纯透传（含二进制
// 脏数据逐字节对拍）、慢流背压（控制帧时延断言）、stream.end 次序（数据先于
// end、end 后无数据）、在册流上限（stream_refused）、未知流 no_stream（close 与
// data 两形态）、后端不可达 gone。

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// echoTermBackend 假 term 后端：echo 模式 / 只写模式 / 受控关闭。
type echoTermBackend struct {
	ln    net.Listener
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func startEchoBackend(t *testing.T) *echoTermBackend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &echoTermBackend{ln: ln, conns: map[net.Conn]struct{}{}}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b.mu.Lock()
			b.conns[c] = struct{}{}
			b.mu.Unlock()
			go func() {
				defer func() {
					b.mu.Lock()
					delete(b.conns, c)
					b.mu.Unlock()
					_ = c.Close()
				}()
				_, _ = io.Copy(c, c) // 纯 echo（字节原样回）
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return b
}

func TestStreamPassthroughBinaryBytes(t *testing.T) {
	// 透传字节逐字节对拍：上行脏数据（0x00/0xff/UTF-8 截断段/全 256 值）经
	// stream.data → 后端 echo → stream.data 回来，字节原样（守护进程不解析不改写）。
	ts := startTestServer(t, BusConfig{})
	echo := startEchoBackend(t)
	ts.backend.mu.Lock()
	ts.backend.dialAddr = echo.ln.Addr().String()
	ts.backend.mu.Unlock()
	c, _ := dialTest(t, ts)

	st, err := c.OpenStream(context.Background(), "aa")
	if err != nil {
		t.Fatal(err)
	}
	// 全 256 字节值 + 随机脏块（含 JSON 危险字节）。
	payload := make([]byte, 0, 1024)
	for i := 0; i < 256; i++ {
		payload = append(payload, byte(i))
	}
	dirty := make([]byte, 768)
	if _, err := rand.Read(dirty); err != nil {
		t.Fatal(err)
	}
	payload = append(payload, dirty...)
	if err := st.Send(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 0, len(payload))
	deadline := time.After(5 * time.Second)
	for len(got) < len(payload) {
		select {
		case b := <-st.Recv():
			got = append(got, b...)
		case <-deadline:
			t.Fatalf("echo 未回齐：%d/%d", len(got), len(payload))
		}
	}
	for i := range payload {
		if got[i] != payload[i] {
			t.Fatalf("透传字节被改动 @%d：%02x ≠ %02x", i, got[i], payload[i])
		}
	}
	if err := st.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-st.End():
		if r != StreamEndClosed {
			t.Fatalf("前端主动关应 end(closed)：%q", r)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("end 帧未到达")
	}
}

// TestSendShardFrameBound 分片帧长上限断言（单元级，512KiB = 32 帧背靠背）：Send
// 大块产出的每个 stream.data 帧载荷 ≤ streamChunkSize（16KiB），帧数恰为 ceil、
// 总字节守恒——与服务端 256KiB 帧上限的距离即安全余量（单帧 512KiB 会被
// bad_frame 断连）。走 net.Pipe（不经服务器）⇒ 任意 CI 负载下确定性成立。
func TestSendShardFrameBound(t *testing.T) {
	pr, pw := net.Pipe()
	c := &Client{nc: pw}
	st := &ClientStream{c: c, ID: 5}
	big := make([]byte, 512<<10) // 512KiB → 恰 32 帧
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- st.Send(big)
		_ = pw.Close()
	}()
	total, frames := 0, 0
	for total < len(big) {
		head, err := ReadHeader(pr)
		if err != nil {
			t.Fatalf("读帧头：%v（已收 %d/%d）", err, total, len(big))
		}
		body, err := ReadBody(pr, head)
		if err != nil {
			t.Fatal(err)
		}
		if head.Op != OpStreamData {
			t.Fatalf("应为 stream.data 帧：0x%02x", head.Op)
		}
		id, payload, derr := DecodeStreamBody(body)
		if derr != nil || id != 5 {
			t.Fatalf("流 body：%v id=%d", derr, id)
		}
		if len(payload) > streamChunkSize {
			t.Fatalf("分片帧载荷 %d 超 %d", len(payload), streamChunkSize)
		}
		total += len(payload)
		frames++
	}
	if err := <-done; err != nil {
		t.Fatalf("Send：%v", err)
	}
	if want := (len(big) + streamChunkSize - 1) / streamChunkSize; frames != want {
		t.Fatalf("帧数 %d ≠ ceil(%d/%d)=%d", frames, len(big), streamChunkSize, want)
	}
	if total != len(big) {
		t.Fatalf("总字节 %d ≠ %d", total, len(big))
	}
}

// TestStreamSendShardingLargePayload host-cli 3b（exec-r2 ①）：Send 大块自动分片
// 经**真实服务器**逐字节重组（echo 对端持续读）。载荷 = 7 帧（112KiB）：帧数 ≤
// 服务端上行队列 8 槽 ⇒ 无论调度如何 upC 都装得下整个突发、不会 finish(gone)——
// 更大的突发（如 32 帧）在共享 runner 上是「泵一次调度空窗即红在背压（design D7
// 注记的收流语义）而非分片」；512KiB/32 帧的帧界与守恒断言由 TestSendShardFrameBound
// 在单元层确定性覆盖（2026-09-29 CI 实测：32 帧 e2e 在 ubuntu 共享 runner 红于
// 「流 1 不在册（已关？），上行 16384 字节被拒」——upC 溢出收流，分片本身无误）。
func TestStreamSendShardingLargePayload(t *testing.T) {
	ts := startTestServer(t, BusConfig{})
	echo := startEchoBackend(t)
	ts.backend.mu.Lock()
	ts.backend.dialAddr = echo.ln.Addr().String()
	ts.backend.mu.Unlock()
	c, _ := dialTest(t, ts)

	st, err := c.OpenStream(context.Background(), "aa")
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 7*streamChunkSize) // 7 帧（< 8 槽 ⇒ 无溢出可能）
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	// 持续读对端：echo 回投逐块收进重组缓冲。
	type chunk struct {
		b   []byte
		err error
	}
	chunks := make(chan chunk, 64)
	go func() {
		got := 0
		for got < len(payload) {
			b, ok := <-st.Recv()
			if !ok {
				chunks <- chunk{err: fmt.Errorf("Recv 通道提前关闭 @%d", got)}
				return
			}
			if len(b) > MaxStreamBody {
				chunks <- chunk{err: fmt.Errorf("下行块 %d 字节超帧上限（分片失效）", len(b))}
				return
			}
			got += len(b)
			chunks <- chunk{b: b}
		}
	}()

	if err := st.Send(payload); err != nil {
		t.Fatalf("Send：%v", err)
	}
	got := make([]byte, 0, len(payload))
	deadline := time.After(30 * time.Second)
	for len(got) < len(payload) {
		select {
		case ch := <-chunks:
			if ch.err != nil {
				t.Fatal(ch.err)
			}
			got = append(got, ch.b...)
		case <-deadline:
			t.Fatalf("echo 未回齐：%d/%d", len(got), len(payload))
		}
	}
	// 逐字节重组断言（字节流语义：分片不承诺边界，只承诺字节序）。
	for i := range payload {
		if got[i] != payload[i] {
			t.Fatalf("重组字节不符 @%d：%02x ≠ %02x", i, got[i], payload[i])
		}
	}
	// 流未被背压收流（end 不应到达——对端与前端都没关）。
	select {
	case r := <-st.End():
		t.Fatalf("不应收流（背压误判）：end=%q", r)
	default:
	}
}

func TestStreamEndOrderBackendClose(t *testing.T) {
	// 后端发 N 块后主动关闭：客户端收齐 N 块后收 end(closed)，之后无该流数据。
	ts := startTestServer(t, BusConfig{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ts.backend.mu.Lock()
	ts.backend.dialAddr = ln.Addr().String()
	ts.backend.mu.Unlock()
	written := make(chan []byte, 16)
	go func() {
		bc, err := ln.Accept()
		if err != nil {
			return
		}
		for i := 0; i < 8; i++ {
			block := []byte{byte('0' + i)}
			written <- block
			_, _ = bc.Write(block)
			time.Sleep(5 * time.Millisecond) // 确保分块边界
		}
		_ = bc.Close() // 后端主动关（EOF → end(closed)）
	}()
	c, _ := dialTest(t, ts)
	st, err := c.OpenStream(context.Background(), "aa")
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	got := []byte{}
	deadline := time.After(5 * time.Second)
	for total < 8 {
		select {
		case b := <-st.Recv():
			got = append(got, b...)
			total += len(b)
		case <-deadline:
			t.Fatalf("流数据未收齐：%d/8（收到 %q）", total, got)
		}
	}
	t.Logf("收到 %q", got)
	select {
	case r := <-st.End():
		if r != StreamEndClosed {
			t.Fatalf("后端 EOF 应 end(closed)：%q", r)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("end 帧未到达")
	}
	// end 之后绝无该流数据。
	select {
	case b := <-st.Recv():
		t.Fatalf("end 之后收到该流数据：%x", b)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestStreamGoneWhenDialFails(t *testing.T) {
	// 目标主机不可达：stream.open 拒（stream_refused，不产生流）。
	ts := startTestServer(t, BusConfig{})
	ts.backend.mu.Lock()
	ts.backend.dialErr["aa"] = errors.New("unreachable")
	ts.backend.dialErr["nobody"] = ErrBackendNoHost
	ts.backend.mu.Unlock()
	c, _ := dialTest(t, ts)
	if _, err := c.OpenStream(context.Background(), "aa"); !errors.Is(err, CodeError(CodeStreamRefused)) {
		t.Fatalf("不可达应 stream_refused：%v", err)
	}
	// host 不在表：no_host。
	if _, err := c.OpenStream(context.Background(), "nobody"); !errors.Is(err, CodeError(CodeNoHost)) {
		t.Fatalf("主机不存在应 no_host：%v", err)
	}
}

func TestStreamNoStreamOnClosedAndData(t *testing.T) {
	// 未知/已关 streamId：close 回 no_stream 不断连；data 帧 → corr=0 回执 no_stream。
	ts := startTestServer(t, BusConfig{})
	echo := startEchoBackend(t)
	ts.backend.mu.Lock()
	ts.backend.dialAddr = echo.ln.Addr().String()
	ts.backend.mu.Unlock()
	c, _ := dialTest(t, ts)
	ctx := context.Background()

	// 未知流 close。
	if _, err := c.Request(ctx, OpStreamClose, StreamCloseArgs{StreamID: 99}); !errors.Is(err, CodeError(CodeNoStream)) {
		t.Fatalf("未知流 close 应 no_stream：%v", err)
	}
	// 开一条流、正常关闭，再对它 close。
	st, err := c.OpenStream(ctx, "aa")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(ctx); err != nil {
		t.Fatal(err)
	}
	<-st.End()
	if _, err := c.Request(ctx, OpStreamClose, StreamCloseArgs{StreamID: st.ID}); !errors.Is(err, CodeError(CodeNoStream)) {
		t.Fatalf("已关流 close 应 no_stream：%v", err)
	}
	// 对已关流发 data：corr=0 通知回执 no_stream，连接与其它流不受影响。
	// 2.2 起流终结后 Send 报 ErrStreamEnded（不再静默成功）——死流上行改用 raw 帧
	// 直写驱动，服务端 no_stream 回执路径的断言保持。
	if err := st.Send([]byte("ghost")); !errors.Is(err, ErrStreamEnded) {
		t.Fatalf("流终结后 Send 应报 ErrStreamEnded：%v", err)
	}
	if err := c.writeFrame(EncodeFrame(OpStreamData, EncodeStreamBody(st.ID, []byte("ghost")))); err != nil {
		t.Fatal(err)
	}
	select {
	case n := <-c.Notify():
		var m map[string]any
		if err := json.Unmarshal(n.Result, &m); err != nil || m["error"] != CodeNoStream {
			t.Fatalf("data 回执应为 no_stream：%s", n.Result)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no_stream 回执未到达")
	}
	// 连接仍可用（不断连）。
	if _, err := c.Request(ctx, OpHostList, nil); err != nil {
		t.Fatalf("no_stream 后连接应不断：%v", err)
	}
}

func TestStreamLimitPerConnection(t *testing.T) {
	// 每连接在册流上限（默认 8）：第 9 条 stream_refused；关闭后可再开。
	ts := startTestServer(t, BusConfig{})
	echo := startEchoBackend(t)
	ts.backend.mu.Lock()
	ts.backend.dialAddr = echo.ln.Addr().String()
	ts.backend.mu.Unlock()
	c, _ := dialTest(t, ts)
	ctx := context.Background()
	var last *ClientStream
	for i := 0; i < DefaultMaxStreams; i++ {
		st, err := c.OpenStream(ctx, "aa")
		if err != nil {
			t.Fatalf("第 %d 条应成功：%v", i+1, err)
		}
		last = st
	}
	if _, err := c.OpenStream(ctx, "aa"); !errors.Is(err, CodeError(CodeStreamRefused)) {
		t.Fatalf("超上限应 stream_refused：%v", err)
	}
	if last != nil {
		if err := last.Close(ctx); err != nil {
			t.Fatal(err)
		}
		<-last.End()
		// 关闭释放名额后可再开。
		if _, err := c.OpenStream(ctx, "aa"); err != nil {
			t.Fatalf("释放名额后应可再开：%v", err)
		}
	}
}

func TestSlowStreamDoesNotBlockControlFrames(t *testing.T) {
	// 慢流背压（spec「慢流不拖垮控制面」）：同连接上一条流积压（后端持续狂吐、
	// 前端停读）到流队列与 socket 缓冲上限，随后该连接发 daemon.status——控制
	// 帧必须在积压流数据**大量送达之前**到达（writer 优先级：控制 > 流——控制
	// 帧不被慢流队头阻塞）。
	ts := startTestServer(t, BusConfig{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ts.backend.mu.Lock()
	ts.backend.dialAddr = ln.Addr().String()
	ts.backend.mu.Unlock()
	stopWrite := make(chan struct{})
	// 后端：接受连接后持续吐数据（前端不读 → 服务器流队列满 → 暂停读后端 →
	// 后端 TCP 写满阻塞——完整的背压链），直到 stopWrite。
	go func() {
		bc, err := ln.Accept()
		if err != nil {
			return
		}
		block := make([]byte, streamChunkSize)
		for i := range block {
			block[i] = byte(i)
		}
		for {
			select {
			case <-stopWrite:
				_ = bc.Close()
				return
			default:
			}
			if _, err := bc.Write(block); err != nil {
				return
			}
		}
	}()
	defer close(stopWrite)

	nc, err := net.Dial("unix", ts.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	if _, err := nc.Write(EncodeFrame(OpHello, []byte(`{"protoVersion":1,"frontend":{"kind":"cli","name":"slow","version":"0"}}`))); err != nil {
		t.Fatal(err)
	}
	if _, err := nc.Write(EncodeFrame(OpReq, mustJSONBytes(t, RequestBody{Corr: 1, Op: OpStreamOpen, Args: mustJSONBytes(t, StreamOpenArgs{Kind: StreamKindTerm, Host: "aa"})}))); err != nil {
		t.Fatal(err)
	}
	// 读到 stream.open 的 rsp 即止（读 deadline 防无限阻塞）。
	r := bufio.NewReader(nc)
	gotOpen := false
	for !gotOpen {
		_ = nc.SetReadDeadline(time.Now().Add(5 * time.Second))
		op, body, err := ReadFrame(r, MaxControlBody)
		if err != nil {
			t.Fatalf("读握手/open 响应失败：%v", err)
		}
		if op == OpRsp {
			var rsp ResponseBody
			_ = json.Unmarshal(body, &rsp)
			if rsp.Corr == 1 {
				if !rsp.Ok {
					t.Fatalf("stream.open 失败：%s", rsp.Error)
				}
				gotOpen = true
			}
		}
	}
	// 停读窗口：让流队列（16×16KiB）+ 双侧 socket 缓冲灌满 = 真积压。
	time.Sleep(time.Second)
	// 恢复读 + 同连接发控制请求。
	_ = nc.SetReadDeadline(time.Time{})
	if _, err := nc.Write(EncodeFrame(OpReq, mustJSONBytes(t, RequestBody{Corr: 2, Op: OpDaemonStatus}))); err != nil {
		t.Fatal(err)
	}
	_ = nc.SetReadDeadline(time.Now().Add(10 * time.Second))
	dataSeen, rspSeen, frames := 0, false, 0
	for !rspSeen {
		op, body, err := ReadFrame(r, MaxControlBody)
		if err != nil {
			t.Fatalf("读帧失败（已读流数据 %d 字节）：%v", dataSeen, err)
		}
		frames++
		switch op {
		case OpRsp:
			var rsp ResponseBody
			_ = json.Unmarshal(body, &rsp)
			if rsp.Corr == 2 {
				if !rsp.Ok {
					t.Fatalf("daemon.status 失败：%s", rsp.Error)
				}
				rspSeen = true
			}
		case OpStreamData:
			dataSeen += len(body) - 4
			if dataSeen > 1<<20 && !rspSeen {
				t.Fatalf("控制响应被慢流队头阻塞：已读流数据 %d 字节（>1MiB）仍无 rsp", dataSeen)
			}
		}
	}
	t.Logf("rsp 在第 %d 帧、%d 字节流数据内到达（控制帧未被慢流阻塞）", frames, dataSeen)
	if dataSeen > 1<<20 {
		t.Fatalf("rsp 到达前读到的流数据 %d 字节超过 1MiB 阈值", dataSeen)
	}
}

func mustJSONBytes(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ---------- L4 背压显式化（term-remote 2.1/2.2） ----------

// TestStreamBackpressureNoLoss 下行不静默丢（2.1 红绿主路）：后端灌 >64 帧（recv
// 队列容量 64）而消费方停读一段（模拟 Ctrl-S 冻结输出）再恢复——断言零丢失（逐
// 字节重组）、本流 data/end 顺序不乱（end 前收齐全部字节）、另一条连接上的请求
// 照常应答（单流前端语义：同连接 Request 在停读窗口内不保证，已从判据删除——
// r1 P0-1）。
func TestStreamBackpressureNoLoss(t *testing.T) {
	ts := startTestServer(t, BusConfig{})
	// 后端：写 N 块（块内字节带序号模式）后主动关——EOF 触发 end(closed)。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ts.backend.mu.Lock()
	ts.backend.dialAddr = ln.Addr().String()
	ts.backend.mu.Unlock()
	const blocks = 200
	const blockSize = 4 << 10 // 共 ~800KB > 服务端流队列(16×16KiB)+双侧 socket 缓冲
	payload := make([]byte, blocks*blockSize)
	for i := range payload {
		payload[i] = byte(i * 7 % 251) // 无周期短重复的确定性模式
	}
	backendClosed := make(chan struct{})
	go func() {
		defer close(backendClosed)
		bc, err := ln.Accept()
		if err != nil {
			return
		}
		for off := 0; off < len(payload); off += blockSize {
			if _, err := bc.Write(payload[off : off+blockSize]); err != nil {
				return
			}
			time.Sleep(2 * time.Millisecond) // 防 TCP 合并：确保 backendPump 逐块成条目
			//（>64 条才能触发 recv 满槽——变异自证的必要条件）
		}
		_ = bc.Close() // 写完全部后关 ⇒ end(closed) 必在全部数据之后
	}()
	c, _ := dialTest(t, ts)
	st, err := c.OpenStream(context.Background(), "aa")
	if err != nil {
		t.Fatal(err)
	}

	// 停读窗口：不消费 recv，等背压链真积压（服务端 dataC 满 + backendPump 停读
	// + TCP 写满——后端写循环阻塞在 bc.Write 上）。
	time.Sleep(1200 * time.Millisecond)

	// 停读窗口内：另一条连接上的请求照常应答（既有判据保留）。
	c2, _ := dialTest(t, ts)
	c2ctx, c2cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer c2cancel()
	if _, err := c2.Request(c2ctx, OpDaemonStatus, nil); err != nil {
		t.Fatalf("停读窗口内另一条连接的请求应照常应答：%v", err)
	}

	// 恢复读：零丢失 + 顺序（end 之前收齐全部字节）。注意 select 的双就绪随机性：
	// end 到达时全部数据已在 recv 队列（reader 按帧序阻塞投递），收到 end 后先排干
	// recv 再断言顺序——不能让随机选择把 end「插」到未读数据前面造成假红。
	got := make([]byte, 0, len(payload))
	sawEnd := false
	endReason := ""
	deadline := time.After(20 * time.Second)
	for len(got) < len(payload) {
		select {
		case b := <-st.Recv():
			if sawEnd {
				t.Fatalf("end 之后仍收到本流数据（顺序破坏）：%d 字节", len(b))
			}
			got = append(got, b...)
		case r := <-st.End():
			sawEnd, endReason = true, r
			for { // end 已收 = reader 已投完全部数据：非阻塞排干 recv
				select {
				case b := <-st.Recv():
					got = append(got, b...)
					continue
				default:
				}
				break
			}
			if len(got) < len(payload) {
				t.Fatalf("end(closed=%q) 先于数据到齐：%d/%d 字节", r, len(got), len(payload))
			}
		case <-deadline:
			t.Fatalf("恢复读后未收齐：%d/%d（end=%v）", len(got), len(payload), sawEnd)
		}
	}
	for i := range payload {
		if got[i] != payload[i] {
			t.Fatalf("零丢失被破坏 @%d：%02x ≠ %02x（丢帧或乱序）", i, got[i], payload[i])
		}
	}
	// end(closed) 到达且在数据之后（主循环可能已顺带收走——那只消费一次）。
	if !sawEnd {
		select {
		case endReason = <-st.End():
		case <-time.After(3 * time.Second):
			t.Fatal("end 帧未到达")
		}
	}
	if endReason != StreamEndClosed {
		t.Fatalf("后端 EOF 应 end(closed)：%q", endReason)
	}
}

// TestStreamBackpressureOldDeliveryDropsFrames 变异自证（2.1 判据）：同一灌帧场景
// 下，旧投递形态（select/default 满则弃——改前 client.go 的 OpStreamData 分支）
// 确实丢帧。用独立的假投递循环复刻旧语义驱动真实 ClientStream，断言收到的字节
// 少于发送的字节（若旧形态不丢，本用例红——即 2.1 的红面对照）。
func TestStreamBackpressureOldDeliveryDropsFrames(t *testing.T) {
	// 构造与生产同参数的流（recv 64 槽）与一条供投递的通道；投递协程 = 旧形态。
	st := &ClientStream{recv: make(chan []byte, 64)}
	src := make(chan []byte)
	delivered := make(chan struct{})
	go func() {
		defer close(delivered)
		for b := range src {
			select { // 旧形态：满则弃（改前行为逐字复刻）
			case st.recv <- b:
			default:
			}
		}
	}()
	const blocks = 200
	sent := 0
	for i := 0; i < blocks; i++ {
		b := make([]byte, 4<<10)
		sent += len(b)
		src <- b
	}
	close(src)
	<-delivered
	// 停读后的队列余量 + 全部消费 < 发送总量 ⇒ 丢帧成立（旧形态的红面证据）。
	// 非阻塞排干（recv 永不 close——range 会挂死）。
	total := 0
	draining := true
	for draining {
		select {
		case b := <-st.recv:
			total += len(b)
		default:
			draining = false
		}
	}
	// 通道容量 64 条 × 4KiB = 256KiB < 800KiB ⇒ 必然丢弃；给一点余量防极端调度
	// 下发送侧还没灌满（src 无界通道不背压，投递侧全速）。
	if total >= sent {
		t.Fatalf("旧投递形态应丢帧：收到 %d ≥ 发送 %d（变异不成立，请核对新旧对照）", total, sent)
	}
	t.Logf("旧形态丢帧实证：投递 %d/%d 字节（丢 %d 字节）", total, sent, sent-total)
}

// TestStreamSendErrorsAfterEnd 上行终结报错（2.2 红绿）：后端持续不读，Send >8 帧
// 背靠背 → 服务端上行队列满按背压收流（finish(gone)）→ 流收尾后后续 Send 报
// ErrStreamEnded（非 nil、errors.Is 可判、含原因）。
func TestStreamSendErrorsAfterEnd(t *testing.T) {
	ts := startTestServer(t, BusConfig{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ts.backend.mu.Lock()
	ts.backend.dialAddr = ln.Addr().String()
	ts.backend.mu.Unlock()
	// 后端：接受连接后一个字节都不读（上行队列必满 → gone）。
	backendConn := make(chan net.Conn, 1)
	go func() {
		bc, err := ln.Accept()
		if err != nil {
			return
		}
		// 接收缓冲钉小：linux TCP loopback 的自调发送缓冲可把整段测试预算（96 帧 1.5MiB）
		// 吞进内核（CI ubuntu 两轮实拍：upC 永不満、无 gone、预算发完仍零背压）——接收窗口
		// 钉住后发送侧几帧内即阻塞，upC 必满，背压确定触发（darwin 缓冲小，不钉也触发）。
		if tc, ok := bc.(*net.TCPConn); ok {
			_ = tc.SetReadBuffer(16 << 10)
		}
		backendConn <- bc
	}()
	c, _ := dialTest(t, ts)
	st, err := c.OpenStream(context.Background(), "aa")
	if err != nil {
		t.Fatal(err)
	}
	// 背靠背连发直到背压收流：upC（8 槽）之外 socket 缓冲也会先吸收一段——吸收量是
	// **内核相关的**：darwin loopback 实测 ~700KB（host-cli exec-r2 ① 同发现）；linux TCP
	// 发送缓冲自调到 tcp_wmem[2]（CI ubuntu/docker 均 4MB）才封顶（接收侧钉小 rcvbuf 也
	// 拦不住——unsent 数据照进 sndbuf，CI ubuntu 两轮实拍：1.5MiB 预算整段被吞、零背压）。
	// 预算 768 帧（12MiB）> 全链吸收上限（sndbuf 4MB + 客户端 UDS ~208KB + upC 128KB +
	// 接收窗口），保证溢出；节拍 2ms（只给服务端 fill upC → finish(gone) 的窗口）。
t2:
	for i := 0; i < 768; i++ {
		if err := st.Send(make([]byte, streamChunkSize)); err != nil {
			// 流已终结但 End() 通道尚未被本测试消费——Send 的终结检查（markEnded
			// 先于 end 投递）即背压收流的**第一可见信号**，正是 2.2 的红面行为。
			if !errors.Is(err, ErrStreamEnded) {
				t.Fatalf("第 %d 帧 Send 报错应为 ErrStreamEnded：%v", i, err)
			}
			break t2
		}
		select {
		case r := <-st.End():
			if r != StreamEndGone {
				t.Fatalf("后端不读应收 end(gone)：%q", r)
			}
			break t2
		default:
			time.Sleep(2 * time.Millisecond)
		}
	}
	// end(gone) 必达（若上面经 Send 报错退出，这里非阻塞补收）。
	select {
	case r := <-st.End():
		if r != StreamEndGone {
			t.Fatalf("后端不读应收 end(gone)：%q", r)
		}
	default:
	}
	// 流收尾后：后续 Send 报错非 nil（2.2 主断言——改前为静默成功）。
	err = st.Send([]byte("after-end"))
	if err == nil {
		t.Fatal("流终结后 Send 应报错（改前 = 静默成功、数据丢失）")
	}
	if !errors.Is(err, ErrStreamEnded) {
		t.Fatalf("应 errors.Is ErrStreamEnded：%v", err)
	}
	if !strings.Contains(err.Error(), "gone") {
		t.Fatalf("错误文案应含原因：%v", err)
	}
	// 空载荷仍为 no-op（既有口径）。
	if err := st.Send(nil); err != nil {
		t.Fatalf("空载荷不该报错：%v", err)
	}
	select {
	case bc := <-backendConn:
		_ = bc.Close()
	default:
	}
}

// TestStreamSendErrorsAfterConnClose 连接级断开的终结状态化（2.2 另一面）：服务端
// 收工（连接断，无 end 帧）→ 在册流全部标记 ended（reason=conn）→ Send 报
// ErrStreamEnded（含「连接已断开」文案）。
func TestStreamSendErrorsAfterConnClose(t *testing.T) {
	ts := startTestServer(t, BusConfig{})
	echo := startEchoBackend(t)
	ts.backend.mu.Lock()
	ts.backend.dialAddr = echo.ln.Addr().String()
	ts.backend.mu.Unlock()
	c, _ := dialTest(t, ts)
	st, err := c.OpenStream(context.Background(), "aa")
	if err != nil {
		t.Fatal(err)
	}
	// 正常路径先过（Send/Recv 往返不回归）。
	if err := st.Send([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-st.Recv():
		if string(b) != "ping" {
			t.Fatalf("echo 字节不符：%q", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("echo 未回")
	}
	// 服务端收工 → 连接级断开（无 end）。
	ts.srv.Close()
	select {
	case <-c.Closed():
	case <-time.After(3 * time.Second):
		t.Fatal("连接未断")
	}
	err = st.Send([]byte("after-close"))
	if err == nil || !errors.Is(err, ErrStreamEnded) {
		t.Fatalf("连接断开后 Send 应报 ErrStreamEnded：%v", err)
	}
	if !strings.Contains(err.Error(), "连接") {
		t.Fatalf("错误文案应含连接断开归因：%v", err)
	}
}
