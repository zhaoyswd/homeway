// socks_test.go — SOCKS5 子集服务端（3e §2.3）：真 SOCKS5 字节流对拍。
package socks

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// echoUpstream 起 TCP 回显上游，返回地址。
func echoUpstream(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// startSocks 起服务端（注入 resolver/dialer 桩），返回本地监听地址。
func startSocks(t *testing.T, cfg ServerConfig) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	startSocksOn(t, cfg, ln)
	return ln.Addr().String()
}

// startSocksOn 在给定 listener 上起服务端（B3-a：accept 侧注入观测桩用）。
func startSocksOn(t *testing.T, cfg ServerConfig, ln net.Listener) *Server {
	t.Helper()
	srv := New(cfg)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })
	return srv
}

// lingerSpy accept 侧连接的 SetLinger 观测桩（exec-r1 B3-a：让「上游失败 RST 收口」
// 的判据有判别力——此前 FIN 也能过）。记录 SetLinger(0) 意图且不透传（保持 FIN
// 投递，rep 帧可靠到达；真 RST 对端的投递语义由 facade 层 off 用例〔真 TCP〕覆盖）。
type lingerSpy struct {
	net.Conn
	set atomic.Bool
}

func (c *lingerSpy) SetLinger(sec int) error {
	if sec == 0 {
		c.set.Store(true)
	}
	return nil
}

// spyListener 包装真 listener，Accept 回来的连接全部带 lingerSpy。
type spyListener struct {
	ln  net.Listener
	mu  sync.Mutex
	spy []*lingerSpy
}

func (l *spyListener) Accept() (net.Conn, error) {
	c, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}
	s := &lingerSpy{Conn: c}
	l.mu.Lock()
	l.spy = append(l.spy, s)
	l.mu.Unlock()
	return s, nil
}

func (l *spyListener) Close() error   { return l.ln.Close() }
func (l *spyListener) Addr() net.Addr { return l.ln.Addr() }

// waitLinger 等到任一 accept 连接记录到 SetLinger(0)。
func (l *spyListener) waitLinger(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		l.mu.Lock()
		for _, s := range l.spy {
			if s.set.Load() {
				l.mu.Unlock()
				return
			}
		}
		l.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("上游失败分支未置 SetLinger(0)（RST 收口判据未落地）")
}

// socksClient 最小 SOCKS5 客户端：no-auth 协商 + CONNECT。
// domain 非空 = ATYP=domain（经 resolver），否则按 IPv4 字面量。
type socksClient struct {
	conn net.Conn
	br   *bufio.Reader
	t    *testing.T
}

func dialSocks(t *testing.T, addr string) *socksClient {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	return &socksClient{conn: c, br: bufio.NewReader(c), t: t}
}

// negotiate 方法协商（methods 可定制）。
func (c *socksClient) negotiate(methods ...byte) []byte {
	c.t.Helper()
	c.w(byte(5), byte(len(methods)))
	for _, m := range methods {
		c.w(m)
	}
	return c.r(2)
}

// connect 发 CONNECT 请求，返回应答 REP 字节。
func (c *socksClient) connect(domain string, ip netip.Addr, port uint16) byte {
	c.t.Helper()
	if domain != "" {
		c.w(5, 1, 0, atypDomain, byte(len(domain)))
		c.conn.Write([]byte(domain))
	} else {
		a := ip.As4()
		c.w(5, 1, 0, atypIPv4, a[0], a[1], a[2], a[3])
	}
	c.w(byte(port>>8), byte(port))
	resp := c.r(4) // VER REP RSV ATYP
	rest := 6      // BND.ADDR(4) + BND.PORT(2)——ATYP=1
	buf := c.r(rest)
	_ = buf
	return resp[1]
}

func (c *socksClient) w(b ...byte) {
	c.t.Helper()
	if _, err := c.conn.Write(b); err != nil {
		c.t.Fatalf("写失败：%v", err)
	}
}

func (c *socksClient) r(n int) []byte {
	c.t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(c.br, buf); err != nil {
		c.t.Fatalf("读 %d 字节失败：%v", n, err)
	}
	return buf
}

// fixedResolver 固定候选列表的 resolver 桩。
func fixedResolver(addrs ...netip.Addr) Resolver {
	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		return addrs, nil
	}
}

// dialTo 拨指定地址的 dialer 桩（deadAddr = 拨不通的目标）。
func dialTo() Dialer {
	return func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", dst.String())
	}
}

// TestNegotiateConnectDomainIPv4Flow 主链路：no-auth 协商 → 域名 CONNECT（远程解析）
// → 成功回执 → 双向透传；IPv4 ATYP 照拨。
func TestNegotiateConnectDomainIPv4Flow(t *testing.T) {
	up := echoUpstream(t)
	upAP := netip.MustParseAddrPort(up)
	upIP, upPort := upAP.Addr(), upAP.Port()
	cfg := ServerConfig{Resolver: fixedResolver(upIP), Dialer: dialTo(), Logf: func(string, ...any) {}}

	// 域名形态。
	addr := startSocks(t, cfg)
	cl := dialSocks(t, addr)
	sel := cl.negotiate(0x00)
	if sel[0] != 5 || sel[1] != 0x00 {
		t.Fatalf("方法选择 = %v，期望 05 00", sel)
	}
	if rep := cl.connect("echo.example", netip.Addr{}, upPort); rep != repSucceeded {
		t.Fatalf("域名 CONNECT rep = %#x，期望 0", rep)
	}
	if _, err := cl.conn.Write([]byte("hello socks")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 11)
	_ = cl.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(cl.br, got); err != nil {
		t.Fatalf("回显未达：%v", err)
	}
	if string(got) != "hello socks" {
		t.Fatalf("回显不符：%q", got)
	}

	// IPv4 字面量形态（照拨，不经 resolver）。
	cl2 := dialSocks(t, addr)
	cl2.negotiate(0x00)
	if rep := cl2.connect("", upIP, upPort); rep != repSucceeded {
		t.Fatalf("IPv4 CONNECT rep = %#x，期望 0", rep)
	}
}

// TestLargeTransfer 双向透传大块（1MiB 回显，验证不设 deadline 的长流）。
func TestLargeTransfer(t *testing.T) {
	up := echoUpstream(t)
	upIP := netip.MustParseAddrPort(up).Addr()
	addr := startSocks(t, ServerConfig{Resolver: fixedResolver(upIP), Dialer: dialTo()})
	cl := dialSocks(t, addr)
	cl.negotiate(0x00)
	if rep := cl.connect("big.example", netip.Addr{}, netip.MustParseAddrPort(up).Port()); rep != repSucceeded {
		t.Fatalf("rep = %#x", rep)
	}
	payload := make([]byte, 1<<20)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	_ = cl.conn.SetDeadline(time.Now().Add(20 * time.Second))
	go func() {
		_, _ = cl.conn.Write(payload)
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(cl.br, got); err != nil {
		t.Fatalf("大块回显未达：%v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("1MiB 回显内容不符")
	}
}

// TestNegotiateRejectNoAuth 客户端不提供 no-auth → 回 0xFF 关。
func TestNegotiateRejectNoAuth(t *testing.T) {
	addr := startSocks(t, ServerConfig{Resolver: fixedResolver(netip.MustParseAddr("127.0.0.1")), Dialer: dialTo()})
	cl := dialSocks(t, addr)
	sel := cl.negotiate(0x02) // 只提供 username/password
	if sel[1] != 0xFF {
		t.Fatalf("无 no-auth 应回 0xFF，got %#x", sel[1])
	}
	// 连接应被关（EOF）。
	cl.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := cl.br.ReadByte(); err == nil {
		t.Fatal("协商拒绝后应有 EOF")
	}
}

// TestCommandAndATYPRejects BIND → rep=0x07；IPv6 ATYP → rep=0x08。
func TestCommandAndATYPRejects(t *testing.T) {
	addr := startSocks(t, ServerConfig{Resolver: fixedResolver(netip.MustParseAddr("127.0.0.1")), Dialer: dialTo()})

	cl := dialSocks(t, addr)
	cl.negotiate(0x00)
	cl.w(5, 2, 0, atypIPv4, 127, 0, 0, 1, 0x00, 0x50) // BIND
	resp := cl.r(10)
	if resp[1] != repCmdNotSup {
		t.Fatalf("BIND rep = %#x，期望 0x07", resp[1])
	}

	cl2 := dialSocks(t, addr)
	cl2.negotiate(0x00)
	cl2.w(5, 1, 0, atypIPv6)
	cl2.w(make([]byte, 16)...)
	cl2.w(0x00, 0x50)
	resp2 := cl2.r(10)
	if resp2[1] != repAddrNotSup {
		t.Fatalf("IPv6 rep = %#x，期望 0x08", resp2[1])
	}
}

// TestUpstreamFailureRST 上游失败 → rep=0x01 + 本地 RST 收口（SetLinger(0)——有判别力
// 形态：linger 意图经观测桩断言，exec-r1 B3-a 整改；此前只断言「读得错误」，FIN 也能过）。
func TestUpstreamFailureRST(t *testing.T) {
	// 注入恒失败 dialer（「首候选死次候选活」的按序回退用例见 TestMultiAFallback）。
	var dialed int
	dead := Dialer(func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		dialed++
		return nil, errors.New("boom（会话重建窗口）")
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	sln := &spyListener{ln: ln}
	startSocksOn(t, ServerConfig{Resolver: fixedResolver(netip.MustParseAddr("203.0.113.1")), Dialer: dead}, sln)
	cl := dialSocks(t, ln.Addr().String())
	cl.negotiate(0x00)
	if rep := cl.connect("dead.example", netip.Addr{}, 0); rep != repGeneralFailure {
		t.Fatalf("rep = %#x，期望 0x01", rep)
	}
	if dialed != 1 {
		t.Fatalf("单候选应只拨一次，实得 %d", dialed)
	}
	// RST 收口判据（B3-a 核心）：失败分支确实置了 SetLinger(0)。
	sln.waitLinger(t)
	// 连接随后收口（桩不透传 linger ⇒ FIN 投递——读到 EOF；rep 帧已完整到达）。
	cl.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := cl.br.ReadByte(); err == nil {
		t.Fatal("失败后连接应收口（读到字节）")
	}
}

// TestMultiAFallback 多 A 按序回退（r2 新-1）：首个候选拨不通换下一个；全部不通
// → rep=0x01。
func TestMultiAFallback(t *testing.T) {
	up := echoUpstream(t)
	goodAP := netip.MustParseAddrPort(up)
	good, goodPort := goodAP.Addr(), goodAP.Port()
	bad1 := netip.MustParseAddr("203.0.113.200") // TEST-NET-3：可拨但超时/拒
	var order []string
	dialer := func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		order = append(order, dst.Addr().String())
		if dst.Addr() == good {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", dst.String())
		}
		return nil, fmt.Errorf("桩拒：%v", dst)
	}
	addr := startSocks(t, ServerConfig{
		Resolver:   fixedResolver(bad1, good),
		Dialer:     dialer,
		DialBudget: 2 * time.Second,
	})
	cl := dialSocks(t, addr)
	cl.negotiate(0x00)
	if rep := cl.connect("multi.example", netip.Addr{}, goodPort); rep != repSucceeded {
		t.Fatalf("首候选不通应换下一个成功，rep = %#x", rep)
	}
	if len(order) != 2 || order[0] != bad1.String() || order[1] != good.String() {
		t.Fatalf("按序回退顺序不符：%v", order)
	}

	// 全部不通 → rep=0x01。
	allDead := Dialer(func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		return nil, errors.New("桩拒")
	})
	addr2 := startSocks(t, ServerConfig{Resolver: fixedResolver(bad1), Dialer: allDead})
	cl2 := dialSocks(t, addr2)
	cl2.negotiate(0x00)
	if rep := cl2.connect("all.example", netip.Addr{}, 0); rep != repGeneralFailure {
		t.Fatalf("全部不通 rep = %#x，期望 0x01", rep)
	}
}

// TestResolveFailureRep 解析否定（NXDOMAIN 类错误）→ rep=0x04。
func TestResolveFailureRep(t *testing.T) {
	resolver := func(ctx context.Context, host string) ([]netip.Addr, error) {
		return nil, errors.New("域名不存在（NXDOMAIN）")
	}
	addr := startSocks(t, ServerConfig{Resolver: resolver, Dialer: dialTo()})
	cl := dialSocks(t, addr)
	cl.negotiate(0x00)
	if rep := cl.connect("nx.example", netip.Addr{}, 0); rep != repHostUnreach {
		t.Fatalf("解析否定 rep = %#x，期望 0x04", rep)
	}
}

// TestConnLimit 上限拒绝：MaxConns=1，第二条连接在协商前被关。
func TestConnLimit(t *testing.T) {
	up := echoUpstream(t)
	upIP := netip.MustParseAddrPort(up).Addr()
	addr := startSocks(t, ServerConfig{
		Resolver: fixedResolver(upIP), Dialer: dialTo(), MaxConns: 1,
	})
	c1 := dialSocks(t, addr)
	c1.negotiate(0x00)
	if rep := c1.connect("hold.example", netip.Addr{}, netip.MustParseAddrPort(up).Port()); rep != repSucceeded {
		t.Fatalf("第一条应成功，rep = %#x", rep)
	}
	c2, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	if n, err := c2.Read(buf); err == nil && n > 0 {
		t.Fatalf("超限连接不应有应答，got %q", buf[:n])
	} else if err == nil {
		t.Fatal("超限连接应收口")
	}
}
