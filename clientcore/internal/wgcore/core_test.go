package wgcore

// l3-exit-intercept 端到端判据：应用 transit（TUN → hub → WG 直通）→ 后端拦截层
// （transit 终结+重拨 / 隧道 IP 豁免）；UDP 过境长会话；DNS 包级钩子；PathProbe
// 的 refused 语义；Transport 门面。
//
// 后端用 homeway 的 servercore（ServerBind/PeerTable）+ pkg/intercept（与 homewayd
// 同一份拦截层）；应用侧用 wgnet 假扮（地址 = 派生隧道 IP，对齐 D4 的单一命名空间）。

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/internal/wtransport"
	"github.com/zhaoyswd/homeway/pkg/intercept"
	"github.com/zhaoyswd/homeway/pkg/proto"
	"github.com/zhaoyswd/homeway/pkg/servercore"
	"github.com/zhaoyswd/homeway/pkg/wgnet"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	srvTunnelIP = "100.64.255.1"
	targetIP    = "192.0.2.10" // 应用拨的「公网目标」：后端拦截层把它映射到本机
	testUDPIdle = 300 * time.Millisecond
)

func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

// startExit：与 homewayd 同构的出口（HandleLocal:false 的 wgnet + 拦截层）。
// mapTarget 把「公网目标」映射到本机（模拟出口可达）。
func startExit(t *testing.T, secret [32]byte, mapTarget func(netip.AddrPort) netip.AddrPort) (*intercept.Stats, [32]byte, netip.AddrPort) {
	t.Helper()
	srvPort := freeUDPPort(t)
	spriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	srvTun, ns, err := wgnet.CreateOpts([]netip.Addr{netip.MustParseAddr(srvTunnelIP)}, 1280, wgnet.Opts{HandleLocal: false})
	if err != nil {
		t.Fatal(err)
	}
	sbind := &servercore.ServerBind{Build: "wgcore-test"}
	sdev := device.NewDevice(srvTun, sbind, device.NewLogger(device.LogLevelError, "srv"))
	t.Cleanup(func() { sdev.Close() })
	sbind.Table = servercore.NewDeviceTable(servercore.NewIPCConfigurer(sdev), [][32]byte{secret}, servercore.DeviceConfig{MaxDevices: 8})
	if err := sdev.IpcSet(fmt.Sprintf("private_key=%x\nlisten_port=%d\n", spriv[:], srvPort)); err != nil {
		t.Fatal(err)
	}
	if err := sdev.Up(); err != nil {
		t.Fatal(err)
	}
	stats := &intercept.Stats{}
	inter, ierr := intercept.Attach(ns, intercept.Config{
		TunnelIP: netip.MustParseAddr(srvTunnelIP),
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			ap, perr := netip.ParseAddrPort(address)
			if perr == nil {
				mapped := mapTarget(ap)
				address = mapped.String()
			}
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, address)
		},
		UDPIdle: testUDPIdle,
		Logf:    func(f string, a ...any) { t.Logf("[exit] "+f, a...) },
	}, stats)
	if ierr != nil {
		t.Fatal(ierr)
	}
	t.Cleanup(inter.Close)
	return stats, spriv.PublicKey(), netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), srvPort)
}

func startClient(t *testing.T, secret [32]byte, peerID [32]byte, cand netip.AddrPort) (*Core, *wgnet.Net, netip.Addr) {
	t.Helper()
	id, err := wtransport.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	cliIP := proto.DeriveTunnelIP(secret, id.PublicKey())
	tunIP := proto.DeriveTunIP(secret, id.PublicKey())
	if tunIP == cliIP {
		t.Fatalf("派生冲突：tunIP == cliIP == %v", cliIP)
	}
	appTun, appStack, err := wgnet.Create([]netip.Addr{tunIP}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { appTun.Close() })
	core, err := start(Config{
		TUN:            appTun,
		MTU:            1280,
		PeerID:         peerID,
		Secret:         secret,
		Identity:       id,
		Candidates:     []wtransport.Candidate{{Addr: cand}},
		ServerTunnelIP: netip.MustParseAddr(srvTunnelIP),
		Logf:           func(f string, a ...any) { t.Logf(f, a...) },
	})
	if err != nil {
		t.Fatalf("wgcore.start: %v", err)
	}
	t.Cleanup(core.Close)
	return core, appStack, tunIP
}

func echoTCPListener(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

func echoUDPListener(t *testing.T) uint16 {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, rerr := pc.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			_, _ = pc.WriteToUDP(buf[:n], from)
		}
	}()
	return uint16(pc.LocalAddr().(*net.UDPAddr).Port)
}

func TestDataPlaneEndToEnd(t *testing.T) {
	secret := [32]byte{3, 1, 4, 1, 5, 9, 2, 6}

	echoTCPListener(t)
	udpPort := echoUDPListener(t)
	// 一问多答的 UDP 目标（QUIC 语义）
	udpMulti, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udpMulti.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, rerr := udpMulti.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			_, _ = udpMulti.WriteToUDP(append([]byte("a:"), buf[:n]...), from)
			_, _ = udpMulti.WriteToUDP(append([]byte("b:"), buf[:n]...), from)
		}
	}()
	udpMultiPort := uint16(udpMulti.LocalAddr().(*net.UDPAddr).Port)

	stats, peerID, cand := startExit(t, secret, func(ap netip.AddrPort) netip.AddrPort {
		if ap.Addr() == netip.MustParseAddr(targetIP) {
			return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), ap.Port())
		}
		return ap
	})
	core, appStack, tunIP := startClient(t, secret, peerID, cand)
	// ---- TCP transit：应用 → 任意公网目标 → 后端拦截重拨 ----
	tcpPort := echoTCPListener(t)
	appConn, err := appStack.DialTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(targetIP), tcpPort))
	if err != nil {
		t.Fatalf("应用拨号失败：%v", err)
	}
	payload := []byte("wgcore-l3-e2e-tcp")
	if _, err := appConn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	_ = appConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(appConn, got); err != nil {
		t.Fatalf("应用读回声失败：%v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("回声=%q", got)
	}
	appConn.Close()

	// ---- UDP transit：应用数据报 → 后端过境会话 ----
	appPC, err := appStack.ListenUDPAddrPort(netip.AddrPortFrom(tunIP, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer appPC.Close()
	dst := netip.AddrPortFrom(netip.MustParseAddr(targetIP), udpPort)
	if _, err := appPC.WriteTo([]byte("wgcore-l3-e2e-udp"), net.UDPAddrFromAddrPort(dst)); err != nil {
		t.Fatal(err)
	}
	_ = appPC.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 512)
	n, _, err := appPC.ReadFrom(buf)
	if err != nil {
		t.Fatalf("应用读 UDP 回声失败：%v", err)
	}
	if string(buf[:n]) != "wgcore-l3-e2e-udp" {
		t.Fatalf("UDP 回声=%q", buf[:n])
	}

	// ---- UDP 长会话：同一应用 socket 上每条请求收**两条**应答（QUIC 语义）----
	//
	// UDP 允许丢包（hub 出站队列、出口会话建立窗口、CI/并行构建的 CPU 抖动都可能吞掉
	// 一个数据报），所以这里按真实客户端（QUIC 重传）语义对**丢了的请求重发**；
	// 断言不变：每条请求都必须拿到 a:/b: 两条应答、且只出现自己那一条请求的应答
	//（一问多答 + 长会话复用，不允许跨请求串答）。
	multiDst := netip.AddrPortFrom(netip.MustParseAddr(targetIP), udpMultiPort)
	got4 := map[string]int{}
	askOnce := func(q string) bool {
		if _, werr := appPC.WriteTo([]byte(q), net.UDPAddrFromAddrPort(multiDst)); werr != nil {
			t.Fatal(werr)
		}
		missing := map[string]bool{"a:" + q: true, "b:" + q: true}
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) && len(missing) > 0 {
			_ = appPC.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			n, _, rerr := appPC.ReadFrom(buf)
			if rerr != nil {
				if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
					continue
				}
				t.Fatalf("应用读一问多答失败（已收 %v）：%v", got4, rerr)
			}
			got4[string(buf[:n])]++
			delete(missing, string(buf[:n]))
		}
		return len(missing) == 0
	}
	for _, q := range []string{"q1", "q2"} {
		ok := false
		for attempt := 0; attempt < 3 && !ok; attempt++ {
			ok = askOnce(q)
		}
		if !ok {
			t.Fatalf("一问多答应答缺失（%s，重发 3 次仍不齐）：%v", q, got4)
		}
	}
	for _, want := range []string{"a:q1", "b:q1", "a:q2", "b:q2"} {
		if got4[want] == 0 {
			t.Fatalf("一问多答应答缺失：%v（want %s 至少一次）", got4, want)
		}
	}
	for k := range got4 {
		switch k {
		case "a:q1", "b:q1", "a:q2", "b:q2":
		default:
			t.Fatalf("收到不属于本轮请求的应答：%q（%v）", k, got4)
		}
	}

	// ---- 豁免：核心自连（DialTCPPort）= 拨后端 localhost ----
	localEcho := echoTCPListener(t)
	tr, terr := NewTransport(TransportConfig{Core: core})
	if terr != nil {
		t.Fatal(terr)
	}
	c2, err := tr.DialTCPPort(context.Background(), localEcho)
	if err != nil {
		t.Fatalf("DialTCPPort（豁免）失败：%v", err)
	}
	if _, err := c2.Write([]byte("exempt\n")); err != nil {
		t.Fatal(err)
	}
	line := make([]byte, 64)
	_ = c2.SetReadDeadline(time.Now().Add(10 * time.Second))
	ln2, rerr := io.ReadFull(c2, line[:7])
	if rerr != nil || string(line[:ln2]) != "exempt\n" {
		t.Fatalf("豁免回声：n=%d err=%v data=%q", ln2, rerr, line[:ln2])
	}
	c2.Close()

	// ---- PathProbe 语义：1 号端口 RST ⇒ refused ⇒ 会话活着 ----
	if _, perr := tr.DialTCPPort(context.Background(), 1); perr == nil || !strings.Contains(perr.Error(), "refused") {
		t.Fatalf("PathProbe 语义（want refused-like）：err=%v", perr)
	}

	// ---- 状态快照 ----
	st := core.status()
	if st.Via != "direct" {
		t.Fatalf("状态快照不符：%+v", st)
	}

	// 收尾：等后端拦截会话收工（UDP 无 FIN 等短 idle；TCP 的 FIN 传播偶有秒级滞后）
	deadline := time.Now().Add(20 * time.Second)
	for stats.Snapshot()["flows"] != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("仍有拦截会话未收工：%v", stats.Snapshot())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// dns-host-resolver：出口隧道 IP 的常量契约（两侧共同 100.64.255.1，非 token 派生）。
// VpnConfig 的 dnsAddresses 声明它，查询经隧道命中出口 :53 改写进代答——若这里
// 漂移（比如误用 DeriveTunIP 之类派生地址），DNS 会指向无人拥有的地址静默超时。
// dns-host-resolver L6：1232 是跨仓共享契约（homeway pkg/proto.MaxDNSPayload53，
// tier 经 replace 引同一模块）——它由手机 TUN MTU（1280）扣头得出，两侧漂移则
// 出口截断点错/大应答被隧道丢。这里钉住「常量 ≤ MTU−余量」的关系，改 MTU 必须同步改它。
func TestMaxDNSPayload53FitsTunMTU(t *testing.T) {
	const tunMTU = 1280
	if proto.MaxDNSPayload53 > tunMTU-28-20 {
		t.Fatalf("MaxDNSPayload53=%d 超出 TUN MTU=%d 的 UDP 载荷上限（跨仓契约漂移）",
			proto.MaxDNSPayload53, tunMTU)
	}
}

func TestServerTunnelIPDefault(t *testing.T) {
	if got := defaultServerTunnelIP().String(); got != "100.64.255.1" {
		t.Fatalf("出口隧道 IP 兜底应为常量 100.64.255.1，got %s（两侧契约漂移）", got)
	}
}
