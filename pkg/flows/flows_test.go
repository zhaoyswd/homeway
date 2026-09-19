package flows

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestConnectCodec(t *testing.T) {
	r := strings.NewReader("CONNECT example.com:443\n")
	host, port, err := ReadConnect(bufio.NewReader(r))
	if err != nil || host != "example.com" || port != 443 {
		t.Fatalf("host=%q port=%d err=%v", host, port, err)
	}
	if _, _, err := ParseConnectLine("GET / HTTP/1.1"); err == nil {
		t.Fatal("非 CONNECT 行必须报错")
	}
	if _, _, err := ParseConnectLine("CONNECT no-port"); err == nil {
		t.Fatal("缺端口必须报错")
	}
}

func TestResponseCodec(t *testing.T) {
	if err := ReadResponse(bufio.NewReader(strings.NewReader("OK\n"))); err != nil {
		t.Fatal(err)
	}
	err := ReadResponse(bufio.NewReader(strings.NewReader("ERR refused\n")))
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("err=%v", err)
	}
}

// 3.3 判据：TCP 流服务 dialok/dialfail 计数 + 数据管道。
func TestServeTCPHappyAndFail(t *testing.T) {
	// 本地回声目标
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					c.SetReadDeadline(time.Now().Add(5 * time.Second))
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					c.Write(buf[:n])
				}
			}()
		}
	}()
	echoPort := uint16(echo.Addr().(*net.TCPAddr).Port)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	st := &Stats{}
	stop, _ := ServeTCP(ln, nil, st)
	defer stop()

	// 成功路径
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	if err := WriteConnect(c, "127.0.0.1", echoPort); err != nil {
		t.Fatal(err)
	}
	if err := ReadResponse(br); err != nil {
		t.Fatalf("OK 缺失：%v", err)
	}
	c.Write([]byte("hello-flow"))
	got := make([]byte, 10)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := readFull(c, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello-flow" {
		t.Fatalf("回声=%q", got)
	}
	c.Close()
	time.Sleep(100 * time.Millisecond)

	// 失败路径：拨死端口
	c2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	WriteConnect(c2, "127.0.0.1", 1) // 端口 1 无监听
	if err := ReadResponse(bufio.NewReader(c2)); err == nil {
		t.Fatal("死端口应回 ERR")
	}
	time.Sleep(100 * time.Millisecond)

	snap := st.Snapshot()
	if snap["dialok"] != 1 || snap["dialfail"] != 1 {
		t.Fatalf("计数契约不符：%v", snap)
	}
}

// 半关闭回归（HANDOFF §5-3）：客户端 CloseWrite 后目标端必须收到 EOF、反向亦然，
// handler 才能收尾（修复前 stop() 会永久挂在 wg.Wait）。
func TestServeTCPHalfClose(t *testing.T) {
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetLn.Close()
	targetEOF := make(chan struct{})
	go func() {
		c, err := targetLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(io.Discard, c) // 读到 EOF（或出错）即返回
		close(targetEOF)
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	st := &Stats{}
	stop, _ := ServeTCP(ln, nil, st)

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	br := bufio.NewReader(c)
	if err := WriteConnect(c, "127.0.0.1", uint16(targetLn.Addr().(*net.TCPAddr).Port)); err != nil {
		t.Fatal(err)
	}
	if err := ReadResponse(br); err != nil {
		t.Fatalf("OK 缺失：%v", err)
	}
	if _, err := c.Write([]byte("half")); err != nil {
		t.Fatal(err)
	}
	// 客户端半关闭（FIN）→ 必须传播到目标端
	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-targetEOF:
	case <-time.After(5 * time.Second):
		t.Fatal("客户端 CloseWrite 后目标端未收到 EOF：半关闭未向目标传播")
	}
	// 目标端读到 EOF 后关连接 → 反向必须传播到客户端
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("客户端未收到目标端 EOF：%v", err)
	}
	// stop 必须能在期限内收工（修复前 handler 永久挂）
	done := make(chan struct{})
	go func() { stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stop() 未在期限内返回：handler 悬挂（半关闭未传播）")
	}
}

func readFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		if n > 0 {
			total += n
		}
		if err != nil {
			if total == len(buf) {
				return total, nil
			}
			return total, err
		}
	}
	return total, nil
}

func TestClassify(t *testing.T) {
	if got := classify(context.DeadlineExceeded); got != ErrCodeTimeout {
		t.Fatalf("timeout 归类=%s", got)
	}
	var dnsErr net.DNSError
	if got := classify(&dnsErr); got != ErrCodeNoDNS {
		t.Fatalf("dns 归类=%s", got)
	}
}

func TestDgramCodec(t *testing.T) {
	dst := netip.MustParseAddrPort("8.8.8.8:53")
	d := EncodeDgram(dst, []byte("query"))
	got, payload, err := DecodeDgram(d)
	if err != nil || got != dst || string(payload) != "query" {
		t.Fatalf("got=%v payload=%q err=%v", got, payload, err)
	}
	if _, _, err := DecodeDgram([]byte("short")); err == nil {
		t.Fatal("短包必须报错")
	}
}

// UDP 中继端到端：假 DNS 应答器 + 逐报中继。
func TestServeUDPRelay(t *testing.T) {
	dnsSrv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer dnsSrv.Close()
	dnsAddr := netip.MustParseAddrPort(dnsSrv.LocalAddr().String())
	go func() {
		buf := make([]byte, 1500)
		for {
			n, a, err := dnsSrv.ReadFromUDP(buf)
			if err != nil {
				return
			}
			dnsSrv.WriteToUDP(append([]byte("resp:"), buf[:n]...), a)
		}
	}()

	inner, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	st := &Stats{}
	stop, _ := ServeUDP(inner, st)
	defer stop()

	cli, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	innerAddr := netip.MustParseAddrPort(inner.LocalAddr().String())
	cli.WriteToUDPAddrPort(EncodeDgram(dnsAddr, []byte("q1")), innerAddr)
	cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := cli.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatal(err)
	}
	src, payload, err := DecodeDgram(buf[:n])
	if err != nil || src != dnsAddr || string(payload) != "resp:q1" {
		t.Fatalf("src=%v payload=%q err=%v", src, payload, err)
	}
	if st.Snapshot()["dialok"] != 1 {
		t.Fatalf("udp dialok=%v", st.Snapshot())
	}
}

// 并发闸 + 空闲回收（旧栈桥接闸教训）：超限连接立即被拒，空闲流被回收、handler 收工。
func TestServeTCPConnLimitAndIdle(t *testing.T) {
	// 目标服务：接受连接后什么都不做（保持流活着，用于占满并发闸）
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetLn.Close()
	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			c, aerr := targetLn.Accept()
			if aerr != nil {
				return
			}
			accepted <- c
		}
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	st := &Stats{}
	stop, _ := ServeTCP(ln, nil, st, WithMaxConns(1), WithIdleTimeout(400*time.Millisecond))
	defer stop()

	// 第一条：占住闸（CONNECT 成功后挂住不动）
	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	br1 := bufio.NewReader(c1)
	if err := WriteConnect(c1, "127.0.0.1", uint16(targetLn.Addr().(*net.TCPAddr).Port)); err != nil {
		t.Fatal(err)
	}
	if err := ReadResponse(br1); err != nil {
		t.Fatalf("第一条应建立：%v", err)
	}
	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("目标端未收到连接")
	}
	// 等闸里确实坐着一条（flows 计数 = 1）
	waitStats(t, st, "flows", 1, 2*time.Second)

	// 第二条：应被并发闸就地拒绝（连上即被关，读不到任何东西就 EOF）
	c2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := bufio.NewReader(c2).ReadByte(); err == nil {
		t.Fatal("超限连接应被拒绝（不应有数据）")
	}
	if got := st.Snapshot()["rejected"]; got != 1 {
		t.Fatalf("rejected 计数=%d 期望 1", got)
	}

	// 空闲回收：c1 静默超过 idle ⇒ 服务端断开，c1 读到 EOF
	_ = c1.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := br1.ReadByte(); err == nil {
		t.Fatal("空闲流应被回收（不应有数据）")
	}
	waitStats(t, st, "flows", 0, 5*time.Second)
}

func waitStats(t *testing.T, st *Stats, key string, want uint64, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if st.Snapshot()[key] == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("统计 %s 未到 %d：%v", key, want, st.Snapshot())
}

// 长会话 UDP（QUIC 语义）：同一条客户端会话内多次收发、且**一次请求可以收到多条应答**。
func TestServeUDPPinnedSessionMultiReply(t *testing.T) {
	// 目标服务器：每收到一条就回两条（模拟多发多收的长寿命 UDP 会话）。
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srvAddr := netip.MustParseAddrPort(srv.LocalAddr().String())
	go func() {
		buf := make([]byte, 1500)
		for {
			n, a, err := srv.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = srv.WriteToUDP(append([]byte("a:"), buf[:n]...), a)
			_, _ = srv.WriteToUDP(append([]byte("b:"), buf[:n]...), a)
		}
	}()

	inner, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	st := &Stats{}
	stop, _ := ServeUDP(inner, st, WithUDPIdle(500*time.Millisecond))
	defer stop()
	innerAddr := netip.MustParseAddrPort(inner.LocalAddr().String())

	cli, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)

	// 同一客户端 socket：连发两条请求 → 应收到 4 条应答（每条请求 2 条）
	for i, q := range []string{"q1", "q2"} {
		if _, err := cli.WriteToUDPAddrPort(EncodeDgram(srvAddr, []byte(q)), innerAddr); err != nil {
			t.Fatal(err)
		}
		_ = i
	}
	got := map[string]int{}
	for len(got) < 4 {
		n, _, err := cli.ReadFromUDPAddrPort(buf)
		if err != nil {
			t.Fatalf("等应答失败（已收 %v）：%v", got, err)
		}
		_, payload, err := DecodeDgram(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		got[string(payload)]++
	}
	for _, want := range []string{"a:q1", "b:q1", "a:q2", "b:q2"} {
		if got[want] != 1 {
			t.Fatalf("应答缺失/重复：%v（want %s 恰一次）", got, want)
		}
	}
	// 只有一次 dial（会话复用）
	if d := st.Snapshot()["dialok"]; d != 1 {
		t.Fatalf("dialok = %v，want 1（同一会话复用同一条真实 UDP socket）", d)
	}

	// 空闲回收：超过 idle 后再发 → 新会话（dialok=2）
	time.Sleep(800 * time.Millisecond)
	if _, err := cli.WriteToUDPAddrPort(EncodeDgram(srvAddr, []byte("q3")), innerAddr); err != nil {
		t.Fatal(err)
	}
	for {
		n, _, err := cli.ReadFromUDPAddrPort(buf)
		if err != nil {
			t.Fatalf("回收后等应答失败：%v", err)
		}
		_, payload, _ := DecodeDgram(buf[:n])
		if string(payload) == "a:q3" {
			break
		}
	}
	if d := st.Snapshot()["dialok"]; d != 2 {
		t.Fatalf("空闲回收后应新建会话：dialok = %v，want 2", d)
	}
}
