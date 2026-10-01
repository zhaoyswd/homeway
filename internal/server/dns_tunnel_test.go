package server

// dns_tunnel_test.go — FIX-60 集成：DNS 代答的监听面在**隧道栈内**（真 listener）。
// 覆盖这次重构的核心机制假设：客户端发往「隧道 IP:53」的 UDP/TCP 查询由 demux
// 直投 listener（不经拦截层的 :53 兜底改写），应答源地址 = 隧道 IP:53；客户端
// 解析腿（隧道 IP:<DNSPort>）同栈可达。用两条 wgnet 内存对拉（crossWire）代替
// 真实 WG 隧道——datapath 之上的层次与应用侧形态一致（intercept_test 同款手法）。

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"

	"github.com/zhaoyswd/homeway/pkg/dns"
	"github.com/zhaoyswd/homeway/pkg/intercept"
	"github.com/zhaoyswd/homeway/pkg/wgnet"
)

const (
	tunTestCliIP = "100.64.0.9"
	tunTestSrvIP = "100.64.255.7"
	tunTestPort  = uint16(5399) // 客户端解析腿（生产缺省 5300，这里取高段避开在役出口）
)

// crossWireNS：两条 wgnet 栈交叉对拉（A 的出站 → B 的入站，反之亦然）。
func crossWireNS(t *testing.T, a, b tun.Device) {
	t.Helper()
	pump := func(from, to tun.Device) {
		bufs := [][]byte{make([]byte, 65535)}
		sizes := []int{0}
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
}

// buildDNSAnswer 一条带单 A 记录的最小应答（IP 编进末四字节，判据用）。
func buildDNSAnswer(q []byte, ip netip.Addr) []byte {
	r := append([]byte(nil), q...)
	r[2] = 0x81 // QR + RD
	r[3] = 0x80 // RA
	binary.BigEndian.PutUint16(r[6:8], 1)
	a := ip.As4()
	return append(r, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04,
		a[0], a[1], a[2], a[3])
}

// startFakeDNSUpstream：UDP fake 上游（应答 = 单 A 记录 192.0.2.7）。
func startFakeDNSUpstream(t *testing.T) (addr string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, rerr := pc.ReadFrom(buf)
			if rerr != nil {
				return
			}
			q := append([]byte(nil), buf[:n]...)
			pc.WriteTo(buildDNSAnswer(q, netip.MustParseAddr("192.0.2.7")), from)
		}
	}()
	return pc.LocalAddr().String()
}

// TestTunnelDNSListeners：隧道 IP:53（UDP+TCP）与解析腿 TCP 都由栈内 listener 接，
// 应答源地址 = 隧道 IP:53；拦截层的 :53 兜底腿**不得**被调用（demux 先投真 listener）。
func TestTunnelDNSListeners(t *testing.T) {
	srvTunIP := netip.MustParseAddr(tunTestSrvIP)
	cliTunIP := netip.MustParseAddr(tunTestCliIP)

	// 服务端栈（出口形态：HandleLocal:false + 拦截层挂上）。
	_, srvNS, err := wgnet.CreateOpts([]netip.Addr{srvTunIP}, 1280, wgnet.Opts{HandleLocal: false})
	if err != nil {
		t.Fatalf("srv wgnet: %v", err)
	}
	t.Cleanup(func() { srvNS.Close() })
	// DNS 代答 + 栈内监听（与 serve.go 同一装配函数）。
	up := startFakeDNSUpstream(t)
	resolv := filepath.Join(t.TempDir(), "resolv.conf")
	if werr := os.WriteFile(resolv, []byte("nameserver "+up+"\n"), 0o644); werr != nil {
		t.Fatal(werr)
	}
	dsrv := dns.New(dns.Config{
		ResolvPath:  resolv,
		FallbackDNS: "127.0.0.1:1",
		Budget:      time.Second,
		Logf:        func(string, ...any) {},
		DLogf:       func(string, ...any) {},
	})
	pcs, lns, errs := listenTunnelDNS(srvNS, srvTunIP, tunTestPort)
	if len(errs) != 0 {
		t.Fatalf("栈内 DNS 监听应全成：%v", errs)
	}
	if len(pcs) != 1 || len(lns) != 2 {
		t.Fatalf("应有 1 个 UDP + 2 个 TCP 监听（:53 与解析腿），got %d/%d", len(pcs), len(lns))
	}
	for _, pc := range pcs {
		dsrv.ServePacketConn(pc)
	}
	for _, ln := range lns {
		dsrv.ServeListener(ln)
	}
	t.Cleanup(func() { dsrv.Close() })

	// 拦截层：DNS 兜底腿设成「一被调用就失败」的哨兵——隧道 IP:53 走 listener，
	// 兜底腿在这条路径上不该出现（FIX-60 的机制假设）。
	var dnsMu sync.Mutex
	var fallbackHits int
	sentinel := &sentinelDNS{hit: func() {
		dnsMu.Lock()
		fallbackHits++
		dnsMu.Unlock()
	}}
	in, ierr := intercept.Attach(srvNS, intercept.Config{
		TunnelIP: srvTunIP,
		DNS:      sentinel,
		Logf:     func(string, ...any) {},
	}, &intercept.Stats{})
	if ierr != nil {
		t.Fatalf("intercept attach: %v", ierr)
	}
	t.Cleanup(in.Close)

	// 客户端栈（手机形态）。
	_, cliNS, err := wgnet.Create([]netip.Addr{cliTunIP}, 1280)
	if err != nil {
		t.Fatalf("cli wgnet: %v", err)
	}
	t.Cleanup(func() { cliNS.Close() })
	crossWireNS(t, cliNS, srvNS)

	// ① UDP 查询：隧道 IP:53。
	dst53 := tunFull(srvTunIP, 53)
	udpPC, err := gonet.DialUDP(cliNS.Stack(), nil, &dst53, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("udp dial: %v", err)
	}
	defer udpPC.Close()
	udpPC.SetDeadline(time.Now().Add(5 * time.Second))
	q := buildDNSQuery(0x1234, "example.test", 1)
	if _, werr := udpPC.Write(q); werr != nil {
		t.Fatalf("udp write: %v", werr)
	}
	buf := make([]byte, 4096)
	n, rerr := udpPC.Read(buf)
	if rerr != nil {
		t.Fatalf("udp read（隧道 IP:53 应被栈内 listener 应答）：%v", rerr)
	}
	resp := buf[:n]
	if binary.BigEndian.Uint16(resp[0:2]) != 0x1234 || resp[3]&0x0F != 0 {
		t.Fatalf("UDP 应答不合法：id=%x rcode=%d", binary.BigEndian.Uint16(resp[0:2]), resp[3]&0x0F)
	}
	if got := resp[len(resp)-4:]; got[0] != 192 || got[1] != 0 || got[2] != 2 || got[3] != 7 {
		t.Fatalf("UDP 应答应带 fake 上游的 A 记录（192.0.2.7），got %v", got)
	}

	// ② TCP 查询：隧道 IP:53（截断重试路径）。
	tcpConn, err := gonet.DialTCP(cliNS.Stack(), dst53, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("tcp dial: %v", err)
	}
	defer tcpConn.Close()
	tcpConn.SetDeadline(time.Now().Add(5 * time.Second))
	qt := buildDNSQuery(0x5678, "tcp.test", 1)
	framed := make([]byte, 2+len(qt))
	binary.BigEndian.PutUint16(framed[0:2], uint16(len(qt)))
	copy(framed[2:], qt)
	if _, werr := tcpConn.Write(framed); werr != nil {
		t.Fatalf("tcp write: %v", werr)
	}
	var lb [2]byte
	if _, rerr := ioReadFullT(t, tcpConn, lb[:]); rerr != nil {
		t.Fatalf("tcp 读长度：%v", rerr)
	}
	tr := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, rerr := ioReadFullT(t, tcpConn, tr); rerr != nil {
		t.Fatalf("tcp 读正文：%v", rerr)
	}
	if binary.BigEndian.Uint16(tr[0:2]) != 0x5678 {
		t.Fatalf("TCP 应答 ID 不符：%x", binary.BigEndian.Uint16(tr[0:2]))
	}

	// ③ 客户端解析腿：隧道 IP:<tunTestPort> TCP 同栈可达（socks 远程解析腿形态）。
	legConn, err := gonet.DialTCP(cliNS.Stack(), tunFull(srvTunIP, tunTestPort), ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("解析腿 dial: %v", err)
	}
	defer legConn.Close()
	legConn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, werr := legConn.Write(framed); werr != nil {
		t.Fatalf("解析腿 write: %v", werr)
	}
	if _, rerr := ioReadFullT(t, legConn, lb[:]); rerr != nil {
		t.Fatalf("解析腿读长度：%v", rerr)
	}
	tr2 := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, rerr := ioReadFullT(t, legConn, tr2); rerr != nil {
		t.Fatalf("解析腿读正文：%v", rerr)
	}
	if binary.BigEndian.Uint16(tr2[6:8]) != 1 {
		t.Fatalf("解析腿应拿到带答案的应答：ancount=%d", binary.BigEndian.Uint16(tr2[6:8]))
	}

	// 机制判据：全程不碰拦截层的 :53 兜底腿（隧道 IP:53 = 真 listener，demux 先投）。
	dnsMu.Lock()
	hits := fallbackHits
	dnsMu.Unlock()
	if hits != 0 {
		t.Fatalf("隧道 IP:53 的查询不该进拦截层兜底腿（demux 应先投真 listener），命中 %d 次", hits)
	}

	// 正向对照：兜底腿本身是活的、哨兵不是死计数器——发往**其它目的** :53 的查询
	// 必须命中它（写死公共 DNS 的泄漏面兜底；哨兵不回包，客户端超时属预期）。
	foreign53 := tunFull(netip.MustParseAddr("203.0.113.9"), 53)
	fbPC, err := gonet.DialUDP(cliNS.Stack(), nil, &foreign53, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("兜底腿 udp dial: %v", err)
	}
	defer fbPC.Close()
	fbPC.SetDeadline(time.Now().Add(3 * time.Second))
	if _, werr := fbPC.Write(buildDNSQuery(0x9abc, "fb.test", 1)); werr != nil {
		t.Fatalf("兜底腿 udp write: %v", werr)
	}
	_, _ = fbPC.Read(buf) // 哨兵不回包：读超时即可，命中与否看计数
	dl := time.Now().Add(3 * time.Second)
	for {
		dnsMu.Lock()
		hits = fallbackHits
		dnsMu.Unlock()
		if hits > 0 {
			break
		}
		if time.Now().After(dl) {
			t.Fatal("非隧道 IP 的 :53 查询应命中拦截层兜底腿（哨兵未被调用 = 判据失效）")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// tunFull：netip → gVisor FullAddress（测试内建）。
func tunFull(ip netip.Addr, port uint16) tcpip.FullAddress {
	return tcpip.FullAddress{Addr: tcpip.AddrFromSlice(ip.AsSlice()), Port: port}
}

// sentinelDNS：一被调用就记账的假代答腿（隧道路径不该调用它）。
type sentinelDNS struct{ hit func() }

func (s *sentinelDNS) Answer(q []byte) []byte { s.hit(); return nil }
func (s *sentinelDNS) ServeStream(conn net.Conn) {
	s.hit()
	conn.Close()
}

func ioReadFullT(t *testing.T, c net.Conn, b []byte) (int, error) {
	t.Helper()
	total := 0
	for total < len(b) {
		n, err := c.Read(b[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// TestDNSCloseAfterStackClose：收尾序回归——Shutdown 里 WG device（连带隧道栈）先关、
// 代答对象后关（serve.go 的 D5 顺序）。注入的 listener 就住在那个栈里：先关栈再关
// 代答不得 panic，也不得把 serve goroutine 永久挂住（栈关闭后 gonet 读/accept 应报错）。
func TestDNSCloseAfterStackClose(t *testing.T) {
	tunIP := netip.MustParseAddr(tunTestSrvIP)
	_, ns, err := wgnet.CreateOpts([]netip.Addr{tunIP}, 1280, wgnet.Opts{HandleLocal: false})
	if err != nil {
		t.Fatalf("wgnet: %v", err)
	}
	dsrv := dns.New(dns.Config{Logf: func(string, ...any) {}})
	pcs, lns, errs := listenTunnelDNS(ns, tunIP, tunTestPort)
	if len(errs) != 0 || len(pcs) != 1 || len(lns) != 2 {
		t.Fatalf("监听面应全成：pcs=%d lns=%d errs=%v", len(pcs), len(lns), errs)
	}
	for _, pc := range pcs {
		dsrv.ServePacketConn(pc)
	}
	for _, ln := range lns {
		dsrv.ServeListener(ln)
	}
	ns.Close() // ④ 关 WG socket/栈（D5 顺序）
	done := make(chan struct{})
	go func() {
		dsrv.Close() // ⑤ 代答收工：关栈内的 listener/连接（不得 panic）
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("栈先关后，代答 Close 挂住（gonet listener 在已关栈上的收工路径）")
	}
}
