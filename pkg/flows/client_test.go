package flows

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// 2.4 判据之一：端口转发/命令流的客户端拨号——CONNECT → OK → 双向管道，
// 以及 ERR 的归因（*RemoteError.Code）。
func TestClientConnectAndPipe(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	st := &Stats{}
	stop, _ := ServeTCP(ln, nil, st)
	defer stop()

	cli := &Client{
		FlowAddr: ln.Addr().(*net.TCPAddr).AddrPort(),
		DialTCP: func(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", ap.String())
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := cli.Connect(ctx, "127.0.0.1", uint16(echo.Addr().(*net.TCPAddr).Port))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if _, err := conn.Write([]byte("ping-flow")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("ping-flow"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("读回声：%v", err)
	}
	if string(got) != "ping-flow" {
		t.Fatalf("回声=%q", got)
	}
	conn.Close()

	c2, err := cli.Connect(ctx, "127.0.0.1", 1)
	if err == nil {
		c2.Close()
		t.Fatal("死端口应返回 ERR")
	}
	var re *RemoteError
	if !errors.As(err, &re) || re.Code != ErrCodeRefused {
		t.Fatalf("归因应为 refused：%v", err)
	}
	time.Sleep(150 * time.Millisecond)
	snap := st.Snapshot()
	if snap["dialok"] != 1 || snap["dialfail"] != 1 {
		t.Fatalf("计数契约不符：%v", snap)
	}
}

// 2.4 判据之二：DNS 类一问一答（UDP 数据报承载过内部流协议）。
func TestClientDatagramRoundTrip(t *testing.T) {
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			echo.WriteToUDP(buf[:n], from)
		}
	}()

	flowPC, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	st := &Stats{}
	stop, _ := ServeUDP(flowPC, st)
	defer stop()

	cli := &Client{
		UDPFlowAddr: flowPC.LocalAddr().(*net.UDPAddr).AddrPort(),
		OpenUDP: func() (net.PacketConn, error) {
			return net.ListenPacket("udp4", "127.0.0.1:0")
		},
	}
	dst := echo.LocalAddr().(*net.UDPAddr).AddrPort()
	pc, err := cli.OpenUDP()
	if err != nil {
		t.Fatalf("OpenUDP: %v", err)
	}
	sess, err := OpenSession(pc, cli.UDPFlowAddr, dst)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer sess.Close()
	_ = sess.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := sess.Write([]byte("dns-query")); err != nil {
		t.Fatalf("会话写失败：%v", err)
	}
	buf := make([]byte, 512)
	n, err := sess.Read(buf)
	if err != nil {
		t.Fatalf("会话读失败：%v", err)
	}
	if string(buf[:n]) != "dns-query" {
		t.Fatalf("应答载荷=%q", buf[:n])
	}
	time.Sleep(150 * time.Millisecond)
	if snap := st.Snapshot(); snap["dialok"] != 1 {
		t.Fatalf("计数契约不符：%v", snap)
	}
	_ = sess.Close()

	dead := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 1)
	pc2, err := cli.OpenUDP()
	if err != nil {
		t.Fatalf("OpenUDP: %v", err)
	}
	defer pc2.Close()
	sess2, err := OpenSession(pc2, cli.UDPFlowAddr, dead)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer sess2.Close()
	_ = sess2.SetDeadline(time.Now().Add(300 * time.Millisecond))
	start := time.Now()
	if _, err := sess2.Write([]byte("no-answer")); err != nil {
		t.Fatalf("死目标写失败：%v", err)
	}
	if _, err := sess2.Read(buf); err == nil {
		t.Fatal("死目标应超时")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("超时未按 ctx 生效：%v", d)
	}
}
