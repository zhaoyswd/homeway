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
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"

	"github.com/zhaoyswd/homeway/pkg/wgnet"
	"path/filepath"
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
	st       *Stats // 每个 harness 都挂计数器（UDP 归宿/拨号计数的断言用）
	dialed   []string
	dialErr  map[string]error

	logMu sync.Mutex
	logs  []string
}

// logf：拦截回调（非测试协程）唯一的日志出口——锁内收集；测试体收尾用
// dumpLogs 输出。不直接 t.Logf：测试结束后回调仍可能打日志，与 testing
// 框架回收 common 存在数据竞争（-race 偶发红）。
func (h *harness) logf(f string, a ...any) {
	h.logMu.Lock()
	h.logs = append(h.logs, fmt.Sprintf(f, a...))
	h.logMu.Unlock()
}

func (h *harness) dumpLogs(t *testing.T) {
	t.Helper()
	h.logMu.Lock()
	for _, l := range h.logs {
		t.Logf("[exit] %s", l)
	}
	h.logs = nil
	h.logMu.Unlock()
}

// newHarness：客户端（HandleLocal:true）+ 服务端（HandleLocal:false，挂拦截）。
// dialChk/dialOverride 可注入（记目的 / 制造失败）。
func newHarness(t *testing.T, dialOverride func(ctx context.Context, network, address string) (net.Conn, error)) *harness {
	return newHarnessCfg(t, dialOverride, nil)
}

// newHarnessCfg：newHarness + Config 变异缝（LocalServices 等映射形态用例用）。
func newHarnessCfg(t *testing.T, dialOverride func(ctx context.Context, network, address string) (net.Conn, error), mutate func(*Config)) *harness {
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
	h := &harness{cli: cli, srv: srv, dialErr: map[string]error{}, st: &Stats{}}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		h.dialed = append(h.dialed, address)
		if dialOverride != nil {
			return dialOverride(ctx, network, address)
		}
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}
	cfgI := Config{
		TunnelIP: netip.MustParseAddr(srvAddr),
		Dial:     dial,
		TCPIdle:  30 * time.Second,
		UDPIdle:  30 * time.Second,
		Logf:     h.logf,
	}
	if mutate != nil {
		mutate(&cfgI)
	}
	h.in, err = Attach(srv, cfgI, h.st)
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
	defer h.dumpLogs(t)
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

// 1.1b' 豁免端口命中 LocalServices → 走 UDS 承载（exit-service-uds）：cfg.Dial 不被调
// （dialed 为空，出口本地零 TCP 端口）、数据照常往返；未映射端口不受影响（上面 1.1b 已验）。
func TestExemptTCPViaUnixSocket(t *testing.T) {
	// 短目录：macOS 的 t.TempDir() 路径叠测试名会顶过 sun_path 上限（app 侧踩过同款）。
	dir, derr := os.MkdirTemp("", "it")
	if derr != nil {
		t.Fatal(derr)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "svc.sock")
	ln, lerr := net.Listen("unix", sock)
	if lerr != nil {
		t.Fatal(lerr)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, rerr := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if rerr != nil {
						return
					}
				}
			}(c)
		}
	}()

	h := newHarnessCfg(t, nil, func(c *Config) {
		c.LocalServices = map[uint16]string{7802: sock}
	})
	c, err := h.cli.DialTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(srvAddr), 7802))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if got := roundtrip(t, c, "ping-uds"); got != "ping-uds" {
		t.Fatalf("echo = %q", got)
	}
	if len(h.dialed) != 0 {
		t.Fatalf("UDS 承载不应走 cfg.Dial（TCP 拨号）：%v", h.dialed)
	}
	// 映射的 socket 消失（服务被摘）→ 快速失败回 RST，与端口没人听不可区分。
	_ = ln.Close()
	_ = os.Remove(sock)
	if _, err := h.cli.DialTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(srvAddr), 7802)); err == nil {
		t.Fatal("socket 消失后应拒绝")
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

// UDP 会话归宿计数的口径（flows-compat-remove 评审整改）：IncrUDPSession 只对
// transit 会话上报。豁免/本机回环（隧道 IP 同端口、DNS :53 改写代答）不走真实
// 转发路径，掺进去会让 udpcap 的「实测有回包」恒真（DNS 代答每查询必回包），
// 掏空这个位「QUIC 这类到底通不通」的含义。
func TestUDPSessionStatsScope(t *testing.T) {
	echo := echoUDP(t)
	h := newHarnessCfg(t, func(ctx context.Context, network, address string) (net.Conn, error) {
		if strings.HasSuffix(address, ":5354") { // ③ 号分支：写成功但永无回包的黑洞
			return newBlackholeConn(), nil
		}
		var d net.Dialer
		return d.DialContext(ctx, network, echo.String())
	}, func(c *Config) {
		c.UDPIdle = 300 * time.Millisecond // 会话快速按空闲收口，计数断言不用等
		c.DNSPort = echo.Port()
		c.DNSIdle = 300 * time.Millisecond
	})
	// waitIdle：等活跃会话数归零（会话关闭时才上报归宿计数）。
	waitIdle := func() {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			if h.st.Snapshot()["flows"] == 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("会话未收口：flows=%d", h.st.Snapshot()["flows"])
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	udpRoundtrip := func(dstPort string, msg string, wantReply bool) {
		t.Helper()
		pc, err := h.cli.DialUDPAddrPort(
			netip.AddrPortFrom(netip.MustParseAddr(cliAddr), 0),
			netip.MustParseAddrPort(foreignDst+":"+dstPort),
		)
		if err != nil {
			t.Fatalf("udp dial: %v", err)
		}
		pc.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := pc.Write([]byte(msg)); err != nil {
			t.Fatalf("write: %v", err)
		}
		if !wantReply {
			// write 异步入隧道，立刻 close 会与拦截层建会话竞速（包被丢）：
			// 等会话计数出现再关，让「只有上行」的会话真正建立过。
			deadline := time.Now().Add(5 * time.Second)
			for h.st.Snapshot()["flows"] == 0 {
				if time.Now().After(deadline) {
					t.Fatalf("会话未建立（flows=0）")
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		if wantReply {
			buf := make([]byte, 1024)
			n, err := pc.Read(buf)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(buf[:n]) != msg {
				t.Fatalf("echo = %q", string(buf[:n]))
			}
		}
		pc.Close()
		waitIdle()
	}

	// ① 豁免（DNS :53 改写 → 代答每查询必回包）：计数两组都必须是 0。
	udpRoundtrip("53", "dns-q", true)
	if r, n := h.st.UDPSessions(); r != 0 || n != 0 {
		t.Fatalf("豁免会话不得进归宿计数：replied=%d noReply=%d", r, n)
	}
	// ② transit 有回包 → replied+1。
	udpRoundtrip("5353", "transit-ok", true)
	if r, n := h.st.UDPSessions(); r != 1 || n != 0 {
		t.Fatalf("transit 有回包应 replied=1：replied=%d noReply=%d", r, n)
	}
	// ③ transit 无回包（黑洞，只有上行）→ noReply+1。
	udpRoundtrip("5354", "transit-dead", false)
	if r, n := h.st.UDPSessions(); r != 1 || n != 1 {
		t.Fatalf("transit 无回包应 noReply=1：replied=%d noReply=%d", r, n)
	}
}

// blackholeConn：写全收、读挂到 Close（「转发出去但永无回包」的确定性替身——
// 不能用 127.0.0.1:1 这类死端口：macOS 上连接型 UDP 首个 Write 就同步回
// ECONNREFUSED，拦截层走「首包写失败」不建会话，测不到归宿计数路径）。
type blackholeConn struct {
	once sync.Once
	done chan struct{}
}

func newBlackholeConn() *blackholeConn { return &blackholeConn{done: make(chan struct{})} }
func (c *blackholeConn) Read([]byte) (int, error) {
	<-c.done
	return 0, io.EOF
}
func (c *blackholeConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *blackholeConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return nil
}
func (c *blackholeConn) LocalAddr() net.Addr              { return nil }
func (c *blackholeConn) RemoteAddr() net.Addr             { return nil }
func (c *blackholeConn) SetDeadline(time.Time) error      { return nil }
func (c *blackholeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blackholeConn) SetWriteDeadline(time.Time) error { return nil }

// UDP 会话上限（review 2026-09-21：TCP 有 MaxConns 闸而 UDP 原先无闸）：
// MaxUDPSessions=2 时第三个五元组不建会话——目标收不到该流的包。
func TestUDPSessionCap(t *testing.T) {
	echo := echoUDP(t)
	h := newHarness(t, func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, echo.String())
	})
	h.in.cfg.MaxUDPSessions = 2 // harness 归一化后直接钳制（发包前设置，无并发）

	dial := func(port int) *gonet.UDPConn {
		pc, err := h.cli.DialUDPAddrPort(
			netip.AddrPortFrom(netip.MustParseAddr(cliAddr), 0),
			netip.MustParseAddrPort(fmt.Sprintf("%s:%d", foreignDst, port)),
		)
		if err != nil {
			t.Fatalf("udp dial: %v", err)
		}
		t.Cleanup(func() { pc.Close() })
		return pc
	}
	// 前两个五元组：正常建会话并收到回显。
	for _, port := range []int{5301, 5302} {
		pc := dial(port)
		pc.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := pc.Write([]byte("in-cap")); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, 256)
		if _, err := pc.Read(buf); err != nil {
			t.Fatalf("上限内会话不应失败（port %d）：%v", port, err)
		}
	}
	// 第三个五元组：超上限，不建会话（读侧等不到回显）。
	pc3 := dial(5303)
	pc3.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := pc3.Write([]byte("over-cap")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 256)
	if n, err := pc3.Read(buf); err == nil {
		t.Fatalf("超上限的会话竟然通了（%d 字节）——MaxUDPSessions 没拦住", n)
	}
}

// dns-host-resolver：任意目的 :53 改写到 127.0.0.1:DNSPort（单元级映射断言）。
func TestTargetDNSRewrite(t *testing.T) {
	in := &Interceptor{cfg: Config{TunnelIP: netip.MustParseAddr(srvAddr), DNSPort: 5300}}
	for _, dst := range []string{srvAddr + ":53", foreignDst + ":53", "8.8.8.8:53"} {
		tgt, exempt := in.target(netip.MustParseAddrPort(dst))
		if !exempt || tgt.String() != "127.0.0.1:5300" {
			t.Fatalf("%s 应改写到 127.0.0.1:5300，got %v exempt=%v", dst, tgt, exempt)
		}
	}
	// 非 53 的隧道 IP 豁免照旧
	if tgt, exempt := in.target(netip.MustParseAddrPort(srvAddr + ":7802")); !exempt || tgt.String() != "127.0.0.1:7802" {
		t.Fatalf("豁免语义应保持，got %v exempt=%v", tgt, exempt)
	}
	// 其它目的端口不受影响
	if tgt, exempt := in.target(netip.MustParseAddrPort(foreignDst + ":443")); exempt || tgt.String() != foreignDst+":443" {
		t.Fatalf("过境语义应保持，got %v exempt=%v", tgt, exempt)
	}
	// DNSPort=0 = 禁用改写
	in.cfg.DNSPort = 0
	if _, exempt := in.target(netip.MustParseAddrPort(foreignDst + ":53")); exempt {
		t.Fatal("DNSPort=0 不应改写 :53")
	}
}

// dns-host-resolver 端到端：客户端发往「任意 IP:53」的 UDP 查询被改写进本机代答端口。
func TestDNSRewriteUDP(t *testing.T) {
	echo := echoUDP(t)
	h := newHarness(t, func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	})
	h.in.cfg.DNSPort = echo.Port() // 发包前设置，无并发
	pc, err := h.cli.DialUDPAddrPort(
		netip.AddrPortFrom(netip.MustParseAddr(cliAddr), 0),
		netip.MustParseAddrPort(foreignDst+":53"), // 写死公共 DNS 形态的目的
	)
	if err != nil {
		t.Fatalf("udp dial: %v", err)
	}
	defer pc.Close()
	pc.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := pc.Write([]byte("dns-q")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1024)
	n, err := pc.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "dns-q" {
		t.Fatalf("echo = %q", string(buf[:n]))
	}
	if len(h.dialed) != 1 || h.dialed[0] != echo.String() {
		t.Fatalf("应改写拨到 %v，got %v", echo, h.dialed)
	}
}

// dns-host-resolver 端到端：TCP :53 同样改写（截断重试路径）。
func TestDNSRewriteTCP(t *testing.T) {
	echo := echoTCP(t)
	h := newHarness(t, func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	})
	h.in.cfg.DNSPort = echo.Port()
	c, err := h.cli.DialTCPAddrPort(netip.MustParseAddrPort(foreignDst + ":53"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if got := roundtrip(t, c, "dns-tcp"); got != "dns-tcp" {
		t.Fatalf("echo = %q", got)
	}
	if len(h.dialed) != 1 || h.dialed[0] != echo.String() {
		t.Fatalf("应改写拨到 %v，got %v", echo, h.dialed)
	}
}

// dns-host-resolver M4：DNS 会话用 DNSIdle（默认 10s）回收，普通 UDP 仍按 UDPIdle。
// 同五元组第二次发包时，DNS 会话已回收重建（dial 计数 +1），普通会话未回收（计数不变）。
func TestDNSUDPSessionShortIdle(t *testing.T) {
	echo := echoUDP(t)
	h := newHarness(t, func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, echo.String()) // 全部重定向到回显（含 transit 对照腿）
	})
	h.in.cfg.DNSPort = echo.Port() // 发包前设置，无并发（同 TestUDPSessionCap 手法）
	h.in.cfg.DNSIdle = 300 * time.Millisecond

	dialPort := func(port int) *gonet.UDPConn {
		pc, err := h.cli.DialUDPAddrPort(
			netip.AddrPortFrom(netip.MustParseAddr(cliAddr), 0),
			netip.MustParseAddrPort(fmt.Sprintf("%s:%d", foreignDst, port)),
		)
		if err != nil {
			t.Fatalf("udp dial: %v", err)
		}
		t.Cleanup(func() { pc.Close() })
		return pc
	}
	send := func(pc *gonet.UDPConn, msg string) {
		pc.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := pc.Write([]byte(msg)); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, 256)
		if _, err := pc.Read(buf); err != nil {
			h.dumpLogs(t)
			t.Fatalf("read: %v", err)
		}
	}

	dnsPC := dialPort(53)
	send(dnsPC, "dns-1")
	base := len(h.dialed)
	time.Sleep(600 * time.Millisecond) // 超过 DNSIdle（300ms），未超过 UDPIdle（30s）
	send(dnsPC, "dns-2")
	if got := len(h.dialed) - base; got != 1 {
		t.Fatalf("DNS 会话应在短 idle 后回收重建（dial +1）, got +%d", got)
	}

	plainPC := dialPort(5399)
	send(plainPC, "plain-1")
	base = len(h.dialed)
	time.Sleep(600 * time.Millisecond)
	send(plainPC, "plain-2")
	if got := len(h.dialed) - base; got != 0 {
		t.Fatalf("普通 UDP 会话不应在 DNSIdle 内回收, got +%d", got)
	}
}
