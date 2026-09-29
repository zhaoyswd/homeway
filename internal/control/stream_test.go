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
	"io"
	"net"
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
	if err := st.Send([]byte("ghost")); err != nil {
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
