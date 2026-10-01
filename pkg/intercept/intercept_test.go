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
	// dialMu：dialed 的并发写保护——并发 UDP 会话（同目的多源端口回归用例）
	// 会在多条 serveUDP goroutine 里同时拨号。
	dialMu  sync.Mutex
	dialed  []string
	dialErr map[string]error

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
		h.dialMu.Lock()
		h.dialed = append(h.dialed, address)
		h.dialMu.Unlock()
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
		c.DNS = &fakeDNS{}
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
	udpRoundtrip := func(dstPort string, msg string, wantReply bool, want string) {
		t.Helper()
		if want == "" {
			want = msg // 回显形态：应答 = 请求
		}
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
			if string(buf[:n]) != want {
				t.Fatalf("应答 = %q（期望 %q）", string(buf[:n]), want)
			}
		}
		pc.Close()
		waitIdle()
	}

	// ① 豁免类会话（隧道 IP 同端口豁免 / 写死公共 DNS 的 :53 兜底——代答每查询必
	// 回包、豁免腿不落地）：计数两组都必须是 0。
	udpRoundtrip("53", "dns-q", true, "dns:dns-q")
	if r, n := h.st.UDPSessions(); r != 0 || n != 0 {
		t.Fatalf("DNS 兜底会话不得进归宿计数：replied=%d noReply=%d", r, n)
	}
	// ①b 隧道 IP 同端口豁免（dial 注入把回环目标重定向到 echo，必有回包）同样不计。
	exemptPC, err := h.cli.DialUDPAddrPort(
		netip.AddrPortFrom(netip.MustParseAddr(cliAddr), 0),
		netip.MustParseAddrPort(srvAddr+":7788"),
	)
	if err != nil {
		t.Fatalf("udp dial: %v", err)
	}
	exemptPC.SetDeadline(time.Now().Add(5 * time.Second))
	exemptPC.Write([]byte("exempt-q"))
	buf0 := make([]byte, 256)
	if _, rerr := exemptPC.Read(buf0); rerr != nil {
		t.Fatalf("豁免腿应拿到回显：%v", rerr)
	}
	exemptPC.Close()
	waitIdle()
	if r, n := h.st.UDPSessions(); r != 0 || n != 0 {
		t.Fatalf("豁免会话不得进归宿计数：replied=%d noReply=%d", r, n)
	}
	// ② transit 有回包 → replied+1。
	udpRoundtrip("5353", "transit-ok", true, "")
	if r, n := h.st.UDPSessions(); r != 1 || n != 0 {
		t.Fatalf("transit 有回包应 replied=1：replied=%d noReply=%d", r, n)
	}
	// ③ transit 无回包（黑洞，只有上行）→ noReply+1。
	udpRoundtrip("5354", "transit-dead", false, "")
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

// fakeDNS：进程内代答腿替身（FIX-60）——UDP 面把查询包成 "dns:<原文>" 回投，
// TCP 面按行回 "dns-tcp:<行>"；记录两面收到的报文供路由断言。
type fakeDNS struct {
	mu  sync.Mutex
	udp []string
	tcp []string
}

func (f *fakeDNS) Answer(q []byte) []byte {
	f.mu.Lock()
	f.udp = append(f.udp, string(q))
	f.mu.Unlock()
	return append([]byte("dns:"), q...)
}

func (f *fakeDNS) ServeStream(conn net.Conn) {
	defer conn.Close()
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		line := sc.Text()
		f.mu.Lock()
		f.tcp = append(f.tcp, line)
		f.mu.Unlock()
		if _, err := conn.Write([]byte("dns-tcp:" + line + "\n")); err != nil {
			return
		}
	}
}

func (f *fakeDNS) counts() (udp, tcp int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.udp), len(f.tcp)
}

// FIX-60：:53 的去向——生产里隧道 IP:53 由栈内真 listener 接（demux 直投，
// 本层看不到，机制判据在 internal/server TestTunnelDNSListeners）；本层兜底腿
// **不按目的地址筛选**：任何 :53 落到这里都进程内应答（listener 缺失时是降级
// 安全网，写死公共 DNS 时是泄漏面兜底）。这里锁兜底腿的开关与端口筛选。
func TestDNSRoutingShape(t *testing.T) {
	in := &Interceptor{cfg: Config{TunnelIP: netip.MustParseAddr(srvAddr), DNS: &fakeDNS{}}}
	if !in.isDNS(netip.MustParseAddrPort(srvAddr + ":53")) {
		t.Fatal("隧道 IP:53 落到本层时同样进程内应答（降级安全网）")
	}
	if !in.isDNS(netip.MustParseAddrPort("8.8.8.8:53")) || !in.isDNS(netip.MustParseAddrPort(foreignDst+":53")) {
		t.Fatal("写死公共 DNS 的 :53 应走进程内兜底")
	}
	if in.isDNS(netip.MustParseAddrPort(foreignDst + ":443")) {
		t.Fatal("非 :53 不得进兜底")
	}
	// DNS=nil = 关闭兜底（:53 按原目标过境重拨）
	in.cfg.DNS = nil
	if in.isDNS(netip.MustParseAddrPort("8.8.8.8:53")) {
		t.Fatal("DNS=nil 不应兜底")
	}
	// 隧道 IP 的豁免映射照旧（DNS 关时 :53 落本机同端口——与旧口径一致）
	if tgt, exempt := in.target(netip.MustParseAddrPort(srvAddr + ":53")); !exempt || tgt.String() != "127.0.0.1:53" {
		t.Fatalf("隧道 IP:53 豁免语义应保持，got %v exempt=%v", tgt, exempt)
	}
	if tgt, exempt := in.target(netip.MustParseAddrPort(srvAddr + ":7802")); !exempt || tgt.String() != "127.0.0.1:7802" {
		t.Fatalf("豁免语义应保持，got %v exempt=%v", tgt, exempt)
	}
	if tgt, exempt := in.target(netip.MustParseAddrPort(foreignDst + ":443")); exempt || tgt.String() != foreignDst+":443" {
		t.Fatalf("过境语义应保持，got %v exempt=%v", tgt, exempt)
	}
}

// FIX-60 端到端：写死公共 DNS（非隧道 IP 的 :53）的 UDP 查询走进程内代答——
// 应答从原目的地址回投（客户端是 connected socket，源地址不对就收不到），
// 且**不拨任何真实网络**（dial 记录为空）。
func TestDNSFallbackUDP(t *testing.T) {
	fake := &fakeDNS{}
	h := newHarnessCfg(t, nil, func(c *Config) { c.DNS = fake })
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
	if got := string(buf[:n]); got != "dns:dns-q" {
		t.Fatalf("应答应来自进程内代答 = %q", got)
	}
	if len(h.dialed) != 0 {
		t.Fatalf("DNS 兜底不得落地拨号：%v", h.dialed)
	}
	if u, _ := fake.counts(); u != 1 {
		t.Fatalf("代答器应收 1 条 UDP 查询，got %d", u)
	}
}

// FIX-60 端到端：TCP :53 同样走进程内代答（DNS 截断后的重试路径）。
func TestDNSFallbackTCP(t *testing.T) {
	fake := &fakeDNS{}
	h := newHarnessCfg(t, nil, func(c *Config) { c.DNS = fake })
	c, err := h.cli.DialTCPAddrPort(netip.MustParseAddrPort(foreignDst + ":53"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if got := roundtrip(t, c, "tcp-q"); got != "dns-tcp:tcp-q" {
		t.Fatalf("应答应来自进程内代答 = %q", got)
	}
	if len(h.dialed) != 0 {
		t.Fatalf("DNS 兜底不得落地拨号：%v", h.dialed)
	}
	if _, tc := fake.counts(); tc != 1 {
		t.Fatalf("代答器应收 1 条 TCP 查询，got %d", tc)
	}
}

// dns-host-resolver M4：DNS 兜底会话用 DNSIdle（默认 10s）回收，普通 UDP 仍按
// UDPIdle。同五元组第二次发包时，DNS 会话已回收重建（新会话编号 +1）、普通会话
// 未回收（编号不变）。FIX-60 起 DNS 腿不拨号（进程内代答），判据从 dial 计数换成
// 会话编号——旧判据在「零拨号」的新形态下恒真，会失去意义。
func TestDNSFallbackSessionShortIdle(t *testing.T) {
	echo := echoUDP(t)
	h := newHarnessCfg(t, func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, echo.String()) // 全部重定向到回显（含 transit 对照腿）
	}, func(c *Config) {
		c.DNS = &fakeDNS{}
		c.DNSIdle = 300 * time.Millisecond
	})

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
	base := h.in.seq.Load()
	time.Sleep(600 * time.Millisecond) // 超过 DNSIdle（300ms），未超过 UDPIdle（30s）
	send(dnsPC, "dns-2")
	if got := h.in.seq.Load() - base; got != 1 {
		t.Fatalf("DNS 兜底会话应在短 idle 后回收重建（新会话 +1）, got +%d", got)
	}

	plainPC := dialPort(5399)
	send(plainPC, "plain-1")
	base = h.in.seq.Load()
	time.Sleep(600 * time.Millisecond)
	send(plainPC, "plain-2")
	if got := h.in.seq.Load() - base; got != 0 {
		t.Fatalf("普通 UDP 会话不应在 DNSIdle 内回收, got +%d", got)
	}
}

// assertNoEndpointFail：拦截层日志里不得出现「建端点失败」——端口共享一旦失效
// （比如某类端点没带 reuse 旗标），先于超时暴露原因。
func assertNoEndpointFail(t *testing.T, h *harness) {
	t.Helper()
	h.logMu.Lock()
	defer h.logMu.Unlock()
	for _, l := range h.logs {
		if strings.Contains(l, "建端点失败") {
			t.Fatalf("拦截层出现建端点失败（同目的端口共享失效）：%s", l)
		}
	}
}

// 同一 (dst,port) 的并发多源端口 UDP 会话（2026-09-23 事故回归，transit 形态）：
// stub resolver 每查询换源端口、QUIC 多条连接打同一目的地址，都会产生「多条
// 五元组同时 spoof 绑定同一本地地址:端口」。修复前第二条流起 bind "port is in
// use"、整条流被丢——实测手机 DNS 建会话 96% 失败，每个新域名都要熬解析器
// 多轮超时（出口日志 bind udp <隧道IP>:53: port is in use 十分钟 503 次）。
// 用 UDPIdle=30s（harness 默认）保证写第 i 条时前面 0..i-1 的会话全部存活。
func TestUDPConcurrentSameDstTransit(t *testing.T) {
	echo := echoUDP(t)
	h := newHarness(t, func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, echo.String())
	})
	const flows = 8
	dst := netip.MustParseAddrPort(foreignDst + ":53") // 与 DNS 同端口最有代表性（QUIC 是 :443，同理）
	pcs := make([]*gonet.UDPConn, flows)
	for i := range pcs {
		pc, err := h.cli.DialUDPAddrPort(
			netip.AddrPortFrom(netip.MustParseAddr(cliAddr), 0),
			dst,
		)
		if err != nil {
			t.Fatalf("udp dial #%d: %v", i, err)
		}
		defer pc.Close()
		pcs[i] = pc
	}
	for i, pc := range pcs {
		pc.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := pc.Write([]byte(fmt.Sprintf("flow-%d", i))); err != nil {
			t.Fatalf("write #%d: %v", i, err)
		}
	}
	for i, pc := range pcs {
		want := fmt.Sprintf("flow-%d", i)
		buf := make([]byte, 1024)
		// 单流超时重传**一次**（UDP 客户端的真实语义，QUIC/普通套接字都自带重传）：并发建会话
		// 窗口里偶发丢一拍应答（本机实测 8 条流并发时；intercept_test.go 原 10s 超时档，与
		// TestUDPConcurrentDNSRewrite 的 ed9b991 同款 flake），生产路径由应用层重传兜底。
		// 重传一次不掩盖**整会话丢流**（那会连重传一起超时，照样失败）；单个首拍应答丢失会被
		// 一次重传吃掉——建会话窗口 pending 重放的产品回归由 intercept.go 生产路径保证
		//（:98/:368）；确定性单流重放用例列为后续测试强化项（exec-r4 低-1）。
		for attempt := 0; ; attempt++ {
			pc.SetDeadline(time.Now().Add(5 * time.Second))
			if attempt > 0 { // 首拍已在上面的并发写入循环里发过；这里只做重传
				if _, err := pc.Write([]byte(want)); err != nil {
					t.Fatalf("write #%d: %v", i, err)
				}
			}
			n, err := pc.Read(buf)
			if err == nil {
				if got := string(buf[:n]); got != want {
					t.Fatalf("flow #%d echo = %q", i, got)
				}
				break
			}
			if attempt > 0 {
				h.dumpLogs(t)
				t.Fatalf("read #%d: %v（重传一次仍无应答，会话建立失败）", i, err)
			}
		}
	}
	assertNoEndpointFail(t, h)
}

// 事故原样（DNS 兜底腿）：手机解析器把 :53 查询打到**写死的公共 DNS**（隧道 IP:53
// 是栈内 listener，不再走 spoof 绑定）——多条查询并发/背靠背到达时，同样共享
// (目的IP,53) 的 spoof 绑定。FIX-60 前这条腿的目的地址是隧道 IP；重构后事故形态
// 只剩公共 DNS 这一支，回归用例随之瞄准它。
func TestUDPConcurrentDNSFallback(t *testing.T) {
	h := newHarnessCfg(t, nil, func(c *Config) { c.DNS = &fakeDNS{} })
	const flows = 8
	dst := netip.MustParseAddrPort(foreignDst + ":53") // 手机解析器的实际目的（写死公共 DNS）
	pcs := make([]*gonet.UDPConn, flows)
	for i := range pcs {
		pc, err := h.cli.DialUDPAddrPort(
			netip.AddrPortFrom(netip.MustParseAddr(cliAddr), 0),
			dst,
		)
		if err != nil {
			t.Fatalf("udp dial #%d: %v", i, err)
		}
		defer pc.Close()
		pcs[i] = pc
	}
	for i, pc := range pcs {
		pc.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := pc.Write([]byte(fmt.Sprintf("q-%d", i))); err != nil {
			t.Fatalf("write #%d: %v", i, err)
		}
	}
	for i, pc := range pcs {
		want := fmt.Sprintf("q-%d", i)
		buf := make([]byte, 1024)
		// 单流超时重传**一次**（DNS 客户端的真实语义）：并发建会话窗口里偶发丢一拍应答
		// （本机与 CI 都实测过，intercept_test.go 原 10s 超时档），生产路径由 DNS 重传兜底。
		// 重传一次不掩盖 be2a4da 那类「整条会话丢流」——那会连重传一起超时，照样失败。
		for attempt := 0; ; attempt++ {
			pc.SetDeadline(time.Now().Add(5 * time.Second))
			if attempt > 0 { // 首拍已在上面的并发写入循环里发过；这里只做重传
				if _, err := pc.Write([]byte(want)); err != nil {
					t.Fatalf("write #%d: %v", i, err)
				}
			}
			n, err := pc.Read(buf)
			if err == nil {
				if got := string(buf[:n]); got != "dns:"+want {
					t.Fatalf("dns flow #%d 应答 = %q", i, got)
				}
				break
			}
			if attempt > 0 {
				h.dumpLogs(t)
				t.Fatalf("read #%d: %v（重传一次仍无应答，会话建立失败）", i, err)
			}
		}
	}
	assertNoEndpointFail(t, h)
}

// TestTCPRejectLineHasCounts（FIX-63）：并发闸拒绝行带**在册数**与**累计拒绝数**，
// 且拒绝会计入 Stats.rejected（排查不必另找统计面）。
func TestTCPRejectLineHasCounts(t *testing.T) {
	echo := echoTCP(t)
	var mu sync.Mutex
	var lines []string
	h := newHarnessCfg(t, func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, echo.String())
	}, func(c *Config) {
		c.Logf = func(f string, a ...any) {
			mu.Lock()
			lines = append(lines, fmt.Sprintf(f, a...))
			mu.Unlock()
		}
	})
	h.in.cfg.MaxConns = 1

	// 第一路占住在册名额（连上 echo 不关）。
	c1, err := h.cli.DialTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(srvAddr), 8080))
	if err != nil {
		t.Fatalf("第一路应放行：%v", err)
	}
	defer c1.Close()
	// 等第一路真正在册（dialok 行出现）。
	waitLogLine(t, &mu, &lines, "dialok")

	// 第二路：超上限被拒（连接直接不通）。
	if _, err := h.cli.DialTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(srvAddr), 8081)); err == nil {
		t.Fatal("超上限的第二路应被拒（连接不该建立）")
	}
	waitLogLine(t, &mu, &lines, "累计拒绝")
	mu.Lock()
	joined := strings.Join(lines, "\n")
	mu.Unlock()
	if !strings.Contains(joined, "在册") || !strings.Contains(joined, "累计拒绝 1") {
		t.Fatalf("拒绝行应含在册数与累计拒绝数：\n%s", joined)
	}
	if got := h.st.Rejects(); got != 1 {
		t.Fatalf("Stats.rejected 应计 1，got %d", got)
	}
}

// waitLogLine 轮询等日志出现子串（harness 日志是并发写的，加锁读快照）。
func waitLogLine(t *testing.T, mu *sync.Mutex, lines *[]string, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		joined := strings.Join(*lines, "\n")
		mu.Unlock()
		if strings.Contains(joined, want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("等日志 %q 超时", want)
}
