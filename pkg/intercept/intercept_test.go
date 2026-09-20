package intercept

// 证伪点测试（openspec l3-exit-intercept 任务 1.1/1.2）：
// 两个 wgnet 内存对拉（交叉泵 tun.Device 双向），客户端拨「非本机地址」与
// 「隧道 IP」两种目的，验证过境拦截、豁免映射、UDP 会话与失败 RST。
//
// 客户端栈用 HandleLocal:true（手机 B 栈形态），服务端栈必须 HandleLocal:false
// （拦截前提，见包注释）——两种形态都在这里锁定行为。

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/zhaoyswd/homeway/pkg/wgnet"
)

const (
	cliAddr    = "100.64.0.2"
	srvAddr    = "100.64.255.1"
	foreignDst = "93.184.216.34" // 任意「互联网」目的（不在任何一方的地址表里）
)

// crossWire：把两个 tun.Device 交叉对接（A 的出站 → B 的入站，反之亦然）。
func crossWire(t *testing.T, a, b tun.Device) (stop func()) {
	t.Helper()
	done := make(chan struct{})
	pump := func(from, to tun.Device) {
		bufs := make([][]byte, 1)
		sizes := make([]int, 1)
		bufs[0] = make([]byte, 65535)
		for {
			n, err := from.Read(bufs, sizes, 0)
			if err != nil || n == 0 {
				return
			}
			for i := 0; i < n; i++ {
				pkt := make([]byte, sizes[i])
				copy(pkt, bufs[i][:sizes[i]])
				if _, werr := to.Write([][]byte{pkt}, 0); werr != nil {
					return
				}
			}
		}
	}
	go pump(a, b)
	go pump(b, a)
	return func() { close(done) }
}

type harness struct {
	cli, srv *wgnet.Net
	in       *Interceptor
	dialed   []string
	dialErr  map[string]error
}

// newHarness：客户端（HandleLocal:true）+ 服务端（HandleLocal:false，挂拦截）。
// dialChk/dialOverride 可注入（记目的 / 制造失败）。
func newHarness(t *testing.T, dialOverride func(ctx context.Context, network, address string) (net.Conn, error)) *harness {
	t.Helper()
	_, cli, err := wgnet.Create([]netip.Addr{netip.MustParseAddr(cliAddr)}, 1280)
	if err != nil {
		t.Fatalf("client wgnet: %v", err)
	}
	_, srv, err := wgnet.CreateOpts([]netip.Addr{netip.MustParseAddr(srvAddr)}, 1280, wgnet.Opts{HandleLocal: false})
	if err != nil {
		t.Fatalf("server wgnet: %v", err)
	}
	crossWire(t, cli, srv)
	h := &harness{cli: cli, srv: srv, dialErr: map[string]error{}}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		h.dialed = append(h.dialed, address)
		if dialOverride != nil {
			return dialOverride(ctx, network, address)
		}
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}
	h.in, err = Attach(srv, Config{
		TunnelIP: netip.MustParseAddr(srvAddr),
		Dial:     dial,
		TCPIdle:  30 * time.Second,
		UDPIdle:  30 * time.Second,
		Logf:     func(f string, a ...any) { t.Logf(f, a...) },
	}, nil)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	t.Cleanup(func() { h.in.Close(); cli.Close(); srv.Close() })
	return h
}

// echoTCP：真实 TCP 回显服务（模拟「后端本机服务」与「互联网目标」）。
func echoTCP(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

func echoUDP(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo udp listen: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], from)
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

func roundtrip(t *testing.T, c net.Conn, msg string) string {
	t.Helper()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte(msg + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return strings.TrimSpace(line)
}

// 1.1a 过境 TCP：dst 是外部地址 → 拦截重拨（Dial 注入把任意目标指到回显服务）。
func TestTransitTCP(t *testing.T) {
	echo := echoTCP(t)
	closed := make(chan string, 4)
	h := newHarness(t, func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, echo.String())
	})
	h.in.cfg.Logf = func(f string, a ...any) {
		if strings.HasPrefix(f, "intercept: tcp") && strings.Contains(f, "关闭") {
			closed <- fmt.Sprint(a...)
		}
	}
	c, err := h.cli.DialTCPAddrPort(netip.MustParseAddrPort(foreignDst + ":443"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if got := roundtrip(t, c, "ping-transit"); got != "ping-transit" {
		t.Fatalf("echo = %q", got)
	}
	if len(h.dialed) == 0 || !strings.HasSuffix(h.dialed[0], ":443") {
		t.Fatalf("重拨目的 = %v（期望 %s:443）", h.dialed, foreignDst)
	}
	if !strings.HasPrefix(h.dialed[0], foreignDst) {
		t.Fatalf("重拨应带原始目的，got %v", h.dialed[0])
	}
	// 拆除判据：客户端 FIN 后，拦截层应在秒级收工（bridgeConns 的半关闭传播）。
	c.Close()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("FIN 后 5s 内拦截层未收工")
	}
}

// 1.1b 豁免：dst 是隧道 IP → 转投 127.0.0.1:同端口。
func TestExemptTCP(t *testing.T) {
	echo := echoTCP(t) // 在 127.0.0.1:P
	h := newHarness(t, nil)
	c, err := h.cli.DialTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(srvAddr), echo.Port()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if got := roundtrip(t, c, "ping-exempt"); got != "ping-exempt" {
		t.Fatalf("echo = %q", got)
	}
	if len(h.dialed) != 1 || !strings.HasPrefix(h.dialed[0], "127.0.0.1:") {
		t.Fatalf("豁免应转投 127.0.0.1:同端口，got %v", h.dialed)
	}
}

// 1.1c 重拨失败 → RST（客户端拿到 connection refused）。
func TestTransitTCPRefused(t *testing.T) {
	h := newHarness(t, func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, fmt.Errorf("no route to anywhere")
	})
	_, err := h.cli.DialTCPAddrPort(netip.MustParseAddrPort(foreignDst + ":80"))
	if err == nil {
		t.Fatal("期望拨号失败（RST）")
	}
}

// 1.2a 过境 UDP：会话往返 + 多应答（拨外部目的，Dial 注入把 UDP 也重定向到回显）。
func TestTransitUDP(t *testing.T) {
	echo := echoUDP(t)
	h := newHarness(t, func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, echo.String())
	})
	pc, err := h.cli.DialUDPAddrPort(
		netip.AddrPortFrom(netip.MustParseAddr(cliAddr), 0),
		netip.MustParseAddrPort(foreignDst+":53"),
	)
	if err != nil {
		t.Fatalf("udp dial: %v", err)
	}
	defer pc.Close()
	pc.SetDeadline(time.Now().Add(10 * time.Second))
	for i := 0; i < 3; i++ {
		msg := fmt.Sprintf("udp-%d", i)
		if _, err := pc.Write([]byte(msg)); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, 1024)
		n, err := pc.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(buf[:n]) != msg {
			t.Fatalf("echo = %q", string(buf[:n]))
		}
	}
}

// 1.2b 豁免 UDP：dst 是隧道 IP:port → 转投 127.0.0.1:同端口。
func TestExemptUDP(t *testing.T) {
	echo := echoUDP(t)
	h := newHarness(t, nil)
	pc, err := h.cli.DialUDPAddrPort(
		netip.AddrPortFrom(netip.MustParseAddr(cliAddr), 0),
		netip.AddrPortFrom(netip.MustParseAddr(srvAddr), echo.Port()),
	)
	if err != nil {
		t.Fatalf("udp dial: %v", err)
	}
	defer pc.Close()
	pc.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := pc.Write([]byte("exempt-udp")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1024)
	n, err := pc.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "exempt-udp" {
		t.Fatalf("echo = %q", string(buf[:n]))
	}
}
