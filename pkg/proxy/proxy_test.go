package proxy

// 单测夹具：一个最小 SOCKS5 服务端（支持 CONNECT 与 UDP ASSOCIATE）+ 一个假 STUN 服务端。
// 用自建夹具而不是外部代理：能力探测的判据（REP 码、探针校验）必须能在没有真代理的机器上钉住。

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------- 夹具：SOCKS5 服务端 ----------

type testSocks5 struct {
	ln           net.Listener
	udpSupported bool
	authUser     string
	authPass     string
	mu           sync.Mutex
}

// setUDP 运行时切"代理支不支持 UDP"（测探测结论过期后能自愈）。
func (s *testSocks5) setUDP(v bool) {
	s.mu.Lock()
	s.udpSupported = v
	s.mu.Unlock()
}

func (s *testSocks5) udpOK() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.udpSupported
}

func startSocks5(t *testing.T, udpSupported bool) *testSocks5 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testSocks5{ln: ln, udpSupported: udpSupported}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(c)
		}
	}()
	return s
}

func (s *testSocks5) addr() string { return s.ln.Addr().String() }

func (s *testSocks5) handle(c net.Conn) {
	defer c.Close()
	var head [2]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	want := byte(methodNoAuth)
	if s.authUser != "" {
		want = methodUserPass
	}
	if _, err := c.Write([]byte{socks5Version, want}); err != nil {
		return
	}
	if want == methodUserPass {
		var h [2]byte
		if _, err := io.ReadFull(c, h[:]); err != nil {
			return
		}
		user := make([]byte, h[1])
		if _, err := io.ReadFull(c, user); err != nil {
			return
		}
		var pl [1]byte
		if _, err := io.ReadFull(c, pl[:]); err != nil {
			return
		}
		pass := make([]byte, pl[0])
		if _, err := io.ReadFull(c, pass); err != nil {
			return
		}
		if string(user) != s.authUser || string(pass) != s.authPass {
			_, _ = c.Write([]byte{0x01, 0x01})
			return
		}
		if _, err := c.Write([]byte{0x01, 0x00}); err != nil {
			return
		}
	}
	var req [3]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return
	}
	dst, name, err := readAddr(c)
	if err != nil {
		return
	}
	target := dst
	if name != "" {
		if ap, err := netip.ParseAddrPort(net.JoinHostPort(name, itoa(dst.Port()))); err == nil {
			target = ap
		} else {
			ips, _ := net.LookupIP(name)
			if len(ips) > 0 {
				if a, ok := netip.AddrFromSlice(ips[0]); ok {
					target = netip.AddrPortFrom(a, dst.Port())
				}
			}
		}
	}
	switch req[1] {
	case cmdConnect:
		up, err := net.Dial("tcp", target.String())
		if err != nil {
			_ = writeReply(c, 0x05)
			return
		}
		defer up.Close()
		if err := writeReply(c, repSuccess); err != nil {
			return
		}
		go func() { _, _ = io.Copy(up, c) }()
		_, _ = io.Copy(c, up)
	case cmdUDPAssociate:
		if !s.udpOK() {
			_ = writeReply(c, repCommandNotSupprt)
			return
		}
		pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			_ = writeReply(c, 0x01)
			return
		}
		defer pc.Close()
		if err := writeReplyAddr(c, repSuccess, pc.LocalAddr().(*net.UDPAddr).AddrPort()); err != nil {
			return
		}
		s.relayUDP(c, pc)
	}
}

func (s *testSocks5) relayUDP(ctrl net.Conn, pc *net.UDPConn) {
	// 控制连接断开 = 撤销关联
	closed := make(chan struct{})
	go func() {
		buf := make([]byte, 64)
		for {
			if _, err := ctrl.Read(buf); err != nil {
				close(closed)
				return
			}
		}
	}()
	var clientAddr netip.AddrPort
	ctrlIP, _, _ := net.SplitHostPort(ctrl.RemoteAddr().String())
	clientIP, _ := netip.ParseAddr(ctrlIP)
	buf := make([]byte, 65535)
	for {
		select {
		case <-closed:
			return
		default:
		}
		_ = pc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, from, err := pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			continue
		}
		// 客户端地址：控制连接的对端 IP + 第一条数据报的源端口（RFC 1928 的常见实现）
		if !clientAddr.IsValid() && clientIP.IsValid() && from.Addr().Unmap() == clientIP.Unmap() {
			clientAddr = from
		}
		// 来自真实目标的应答：按 SOCKS5 UDP 头包好回给客户端
		if from != clientAddr {
			if !clientAddr.IsValid() {
				continue
			}
			out := append([]byte{0, 0, 0}, mustAddr(from)...)
			out = append(out, buf[:n]...)
			_, _ = pc.WriteToUDPAddrPort(out, clientAddr)
			continue
		}
		// 来自客户端的数据报：剥头，发给目标
		if n < 4 || buf[2] != 0 {
			continue
		}
		dst, _, err := readAddr(sliceReader(buf[3:n]))
		if err != nil {
			continue
		}
		alen := addrSectionLen(buf[3:n])
		if alen <= 0 || 3+alen > n {
			continue
		}
		payload := buf[3+alen : n]
		clientAddr = from
		_, _ = pc.WriteToUDPAddrPort(payload, dst)
	}
}

func mustAddr(ap netip.AddrPort) []byte {
	b, err := encodeAddr(ap.Addr().String(), ap.Port())
	if err != nil {
		panic(err)
	}
	return b
}

func writeReply(c net.Conn, rep byte) error {
	return writeReplyAddr(c, rep, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
}

func writeReplyAddr(c net.Conn, rep byte, bound netip.AddrPort) error {
	out := []byte{socks5Version, rep, 0x00}
	out = append(out, mustAddr(bound)...)
	_, err := c.Write(out)
	return err
}

func itoa(p uint16) string { return strconv.Itoa(int(p)) }

// ---------- 夹具：假 STUN 服务端 ----------

func startFakeSTUN(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if n < 20 {
				continue
			}
			var tx [12]byte
			copy(tx[:], buf[8:20])
			_ = pc.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_, _ = pc.WriteToUDPAddrPort(stunResp(tx, from), from)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

func stunResp(tx [12]byte, mapped netip.AddrPort) []byte {
	attr := []byte{0x00, 0x20, 0x00, 0x08, 0x00, 0x01}
	port := mapped.Port() ^ uint16(0x2112)
	attr = binary.BigEndian.AppendUint16(attr, port)
	a4 := mapped.Addr().Unmap().As4()
	var cookie [4]byte
	binary.BigEndian.PutUint32(cookie[:], 0x2112A442)
	for i := 0; i < 4; i++ {
		attr = append(attr, a4[i]^cookie[i])
	}
	out := []byte{0x01, 0x01}
	out = binary.BigEndian.AppendUint16(out, uint16(len(attr)))
	out = binary.BigEndian.AppendUint32(out, 0x2112A442)
	out = append(out, tx[:]...)
	out = append(out, attr...)
	return out
}

// ---------- 测试 ----------

func TestConnectThroughProxy(t *testing.T) {
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
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()

	s5 := startSocks5(t, true)
	cli, err := New("socks5://"+s5.addr(), UDPAuto, nil, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := cli.DialContext(context.Background(), "tcp", echo.Addr().String())
	if err != nil {
		t.Fatalf("经代理拨号失败：%v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hello-proxy")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "hello-proxy" {
		t.Fatalf("回声异常：n=%d err=%v %q", n, err, buf[:n])
	}
}

func TestUDPProbeSupported(t *testing.T) {
	s5 := startSocks5(t, true)
	stun := startFakeSTUN(t)
	cli, err := New("socks5://"+s5.addr(), UDPAuto, []netip.AddrPort{stun}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	v := cli.UDPVerdict(context.Background())
	if !v.Supported {
		t.Fatalf("应判定支持：%+v", v)
	}
	if !strings.Contains(v.Detail, "可校验应答") {
		t.Fatalf("结论细节不符：%q", v.Detail)
	}
}

func TestUDPProbeUnsupported(t *testing.T) {
	s5 := startSocks5(t, false) // 代理回 REP=0x07
	stun := startFakeSTUN(t)
	cli, err := New("socks5://"+s5.addr(), UDPAuto, []netip.AddrPort{stun}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	v := cli.UDPVerdict(context.Background())
	if v.Supported {
		t.Fatalf("应判定不支持：%+v", v)
	}
	if !strings.Contains(v.Detail, "UDP ASSOCIATE") {
		t.Fatalf("结论细节不符：%q", v.Detail)
	}
}

func TestUDPProbeRelaysButNoReply(t *testing.T) {
	s5 := startSocks5(t, true)
	// 探针目标指向一个没人应答的端口：REP=0 但数据不通 ⇒ 不能判成支持
	dead, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.LocalAddr().(*net.UDPAddr).AddrPort()
	_ = dead.Close()
	cli, err := New("socks5://"+s5.addr(), UDPAuto, []netip.AddrPort{deadAddr}, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	v := cli.UDPVerdict(context.Background())
	if v.Supported {
		t.Fatalf("没有有效应答时不能判成支持：%+v", v)
	}
}

func TestUDPRoundTripThroughProxy(t *testing.T) {
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := echo.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDPAddrPort(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	s5 := startSocks5(t, true)
	cli, err := New("socks5://"+s5.addr(), UDPOn, nil, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := cli.OpenUDPConn(context.Background(), netip.AddrPort{})
	if err != nil {
		t.Fatalf("开 UDP 关联失败：%v", err)
	}
	defer conn.Close()
	dst := echo.LocalAddr().(*net.UDPAddr).AddrPort()
	if _, err := conn.WriteToUDPAddrPort([]byte("ping"), dst); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, src, err := conn.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("读失败：%v", err)
	}
	if string(buf[:n]) != "echo:ping" {
		t.Fatalf("载荷=%q", buf[:n])
	}
	if src != dst {
		t.Fatalf("来源=%v，want %v", src, dst)
	}
}

func TestDecideUDP(t *testing.T) {
	s5ok := startSocks5(t, true)
	stun := startFakeSTUN(t)
	s5no := startSocks5(t, false)
	cases := []struct {
		raw     string
		mode    UDPMode
		wantVia string
		wantErr bool
	}{
		{"socks5://" + s5ok.addr(), UDPAuto, "proxy", false},
		{"socks5://" + s5ok.addr(), UDPOn, "proxy", false},
		{"socks5://" + s5ok.addr(), UDPOff, "direct", false},
		{"socks5://" + s5no.addr(), UDPAuto, "direct", false},
		{"socks5://" + s5no.addr(), UDPOn, "direct", true},
		{"", UDPAuto, "direct", false},
	}
	for _, c := range cases {
		cli, err := New(c.raw, c.mode, []netip.AddrPort{stun}, 3*time.Second)
		if err != nil {
			t.Fatalf("New(%q): %v", c.raw, err)
		}
		d := cli.DecideUDP(context.Background())
		if d.Via != c.wantVia {
			t.Errorf("raw=%q mode=%v：via=%q want %q（%s）", c.raw, c.mode, d.Via, c.wantVia, d.Reason)
		}
		if (d.Err != nil) != c.wantErr {
			t.Errorf("raw=%q mode=%v：err=%v wantErr=%v", c.raw, c.mode, d.Err, c.wantErr)
		}
	}
}

func TestParseUDPMode(t *testing.T) {
	for _, v := range []string{"", "auto"} {
		if m, err := ParseUDPMode(v); err != nil || m != UDPAuto {
			t.Errorf("ParseUDPMode(%q) = %v, %v", v, m, err)
		}
	}
	if m, err := ParseUDPMode("on"); err != nil || m != UDPOn {
		t.Errorf("on 解析错误：%v %v", m, err)
	}
	if m, err := ParseUDPMode("off"); err != nil || m != UDPOff {
		t.Errorf("off 解析错误：%v %v", m, err)
	}
	if _, err := ParseUDPMode("maybe"); err == nil {
		t.Error("非法取值应报错")
	}
}

func TestNewRejectsHTTPProxy(t *testing.T) {
	if _, err := New("http://127.0.0.1:8080", UDPAuto, nil, time.Second); err == nil {
		t.Error("http 代理应被拒绝（承载不了 UDP ASSOCIATE）")
	}
}

// 结论会过期重探：出口先启动、代理后起（或代理升级后支持 UDP）时不用重启出口。
func TestUDPVerdictReprobesAfterTTL(t *testing.T) {
	s5 := startSocks5(t, false)
	stun := startFakeSTUN(t)
	cli, err := New("socks5://"+s5.addr(), UDPAuto, []netip.AddrPort{stun}, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cli.SetVerdictTTL(20 * time.Millisecond)
	if v := cli.UDPVerdict(context.Background()); v.Supported {
		t.Fatalf("初始应判定不支持：%+v", v)
	}
	s5.setUDP(true) // 代理"升级"成支持 UDP
	time.Sleep(40 * time.Millisecond)
	v := cli.UDPVerdict(context.Background())
	if !v.Supported {
		t.Fatalf("结论过期后应重探并判成支持：%+v", v)
	}
}

// sliceReader：测试夹具里读地址段用。
func sliceReader(b []byte) io.Reader { return bytes.NewReader(b) }
