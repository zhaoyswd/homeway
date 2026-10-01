package relay

import (
	"context"
	"crypto/rand"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
	"golang.org/x/crypto/curve25519"
)

// ---------- 测试夹具：一个真的后端腿（X25519 私钥）+ 一条客户端 socket ----------

type fakeBackend struct {
	priv  [32]byte
	pub   [32]byte
	psk   [32]byte // 非零 = token 模式（用中继鉴权密钥算 PSK MAC）
	label [8]byte
	pc    *net.UDPConn
	relay netip.AddrPort
	t     *testing.T
}

func newFakeBackend(t *testing.T, relayAddr netip.AddrPort) *fakeBackend {
	t.Helper()
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	b := &fakeBackend{priv: priv, relay: relayAddr, t: t}
	copy(b.pub[:], pub)
	b.label = proto.RelayID(b.pub)
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	b.pc = pc
	t.Cleanup(func() { pc.Close() })
	return b
}

// register 走完 Hello → Challenge → Proof → OK，返回是否成功。
func (b *fakeBackend) register() bool {
	b.t.Helper()
	return b.registerWithVer(proto.RelayCtlVer)
}

// registerWithVer：register 的版本可注入变体（FIX-89 版本门用例）。
func (b *fakeBackend) registerWithVer(ver byte) bool {
	b.t.Helper()
	_, _ = b.pc.WriteToUDPAddrPort(proto.EncodeTagged(b.label, proto.FrameTypeRelayReg,
		proto.EncodeRelayHello(b.pub)), b.relay)
	buf := make([]byte, 2048)
	_ = b.pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := b.pc.ReadFromUDPAddrPort(buf)
	if err != nil {
		return false
	}
	typ, payload, err := proto.DecodeFrame(buf[:n])
	if err != nil || typ != proto.FrameTypeRelayReg {
		return false
	}
	ephPub, nonce, err := proto.DecodeRelayChallenge(payload)
	if err != nil {
		return false
	}
	dh, err := curve25519.X25519(b.priv[:], ephPub[:])
	if err != nil {
		return false
	}
	_, _ = b.pc.WriteToUDPAddrPort(proto.EncodeTagged(b.label, proto.FrameTypeRelayReg,
		proto.EncodeRelayProof(nonce, dh, b.pub, b.pskF(nonce), ver)), b.relay)
	n, _, err = b.pc.ReadFromUDPAddrPort(buf)
	if err != nil {
		return false
	}
	typ, payload, err = proto.DecodeFrame(buf[:n])
	if err != nil || typ != proto.FrameTypeRelayReg {
		return false
	}
	sub, _ := proto.RelaySubtype(payload)
	return sub == proto.RelaySubOK
}

// pskF：该后端在本次挑战里的 PSK MAC（没有 token 时返回 nil）。
func (b *fakeBackend) pskF(nonce [16]byte) []byte {
	if b.psk == ([32]byte{}) {
		return nil
	}
	return proto.RelayAuthMAC(b.psk, nonce, b.pub)
}

// keepalive 发一次保活。
func (b *fakeBackend) keepalive() {
	_, _ = b.pc.WriteToUDPAddrPort(proto.EncodeTagged(b.label, proto.FrameTypeRelayReg,
		proto.EncodeRelayKeepalive()), b.relay)
}

type fakeClient struct {
	label [8]byte
	pc    *net.UDPConn
	relay netip.AddrPort
	t     *testing.T
}

func newFakeClient(t *testing.T, label [8]byte, relayAddr netip.AddrPort) *fakeClient {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	return &fakeClient{label: label, pc: pc, relay: relayAddr, t: t}
}

func (c *fakeClient) send(payload []byte) {
	_, _ = c.pc.WriteToUDPAddrPort(proto.EncodeTagged(c.label, proto.FrameTypeData, payload), c.relay)
}

// readFrame 读一条腿帧（区分 hint 与 data）。
func (c *fakeClient) readFrame(d time.Duration) (byte, []byte, bool) {
	buf := make([]byte, 4096)
	_ = c.pc.SetReadDeadline(time.Now().Add(d))
	n, _, err := c.pc.ReadFromUDPAddrPort(buf)
	if err != nil {
		return 0, nil, false
	}
	typ, payload, err := proto.DecodeFrame(buf[:n])
	if err != nil {
		return 0, nil, false
	}
	return typ, payload, true
}

// readData / readHint：带过滤的读（hint 与 data 可能交错）。
func (c *fakeClient) readData(d time.Duration) ([]byte, bool) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		typ, payload, ok := c.readFrame(time.Until(deadline))
		if !ok {
			return nil, false
		}
		if typ == proto.FrameTypeData {
			return payload, true
		}
	}
	return nil, false
}

func (c *fakeClient) readHint(d time.Duration) (string, bool) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		typ, payload, ok := c.readFrame(time.Until(deadline))
		if !ok {
			return "", false
		}
		if typ == proto.FrameTypeControl {
			addr, err := proto.DecodeHintPayload(payload)
			if err == nil {
				return addr, true
			}
		}
	}
	return "", false
}

func startRelay(t *testing.T, cfg Config) *Relay {
	t.Helper()
	cfg.Addr = "127.0.0.1:0"
	if cfg.Secret == ([32]byte{}) {
		// 测试夹具层面显式声明开放（Config.Open 是唯一开放入口；生产路径恒设 Secret）。
		cfg.Open = true
	}
	if cfg.Logf == nil {
		cfg.Logf = func(f string, a ...any) { t.Logf("[relay] "+f, a...) }
	}
	// 中继的控制面 TCP 与 UDP **同号**（部署零新增口），UDP :0 由内核在临时口区间
	// 挑号——同号 TCP 可能恰好被**外部** socket（并行测试包的随机监听/系统进程的
	// 临时口连接）占住 ⇒ relay 静默退回纯 UDP 中继 ⇒ 需要控制腿的用例红（CI 并行包
	// 下实测；包内先后用例的串行性已由 Run 收尾关 ctlLn 保证，这里是外部占用面）。
	// 起后探测控制腿：不在就换口重起（有界重试——每次重起内核重挑 UDP 号）。
	for attempt := 1; ; attempt++ {
		r := New(cfg)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); _ = r.Run(ctx) }()
		for i := 0; i < 100 && !r.LocalAddr().IsValid(); i++ {
			time.Sleep(10 * time.Millisecond)
		}
		if !r.LocalAddr().IsValid() {
			cancel()
			t.Fatal("中继没起来")
		}
		ctl := net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(r.LocalAddr().Port())}
		if c, derr := net.DialTimeout("tcp", ctl.String(), time.Second); derr == nil {
			_ = c.Close()
			// 收工顺序：先 cancel 再等 Run 退出（LIFO 的 cleanup 顺序坑过）
			t.Cleanup(func() { cancel(); <-done })
			return r
		}
		cancel()
		<-done
		if attempt >= 5 {
			t.Fatalf("中继控制面 TCP 同号口连续 %d 次被外部占用——环境异常", attempt)
		}
		t.Logf("[relay] 控制面 TCP 同号口被外部占用，换口重起（第 %d 次）", attempt)
	}
}

// ---------- 测试 ----------

// 注册腿：正常注册成功；伪造私钥的注册被拒（挑战-证明过不去）。
func TestRegisterLegAndForgeRejected(t *testing.T) {
	r := startRelay(t, Config{})
	relayAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), r.LocalAddr().Port())

	real := newFakeBackend(t, relayAddr)
	if !real.register() {
		t.Fatal("真后端应当注册成功")
	}
	if _, ok := r.RegisterLeg(real.label); !ok {
		t.Fatal("注册腿没落表")
	}

	// 伪造：用另一把私钥声称同一个 peerId（label 相同、pubkey 不同 → Hello 就该被拒）
	forger := newFakeBackend(t, relayAddr)
	forger.label = real.label
	_, _ = forger.pc.WriteToUDPAddrPort(proto.EncodeTagged(forger.label, proto.FrameTypeRelayReg,
		proto.EncodeRelayHello(forger.pub)), relayAddr)
	_ = forger.pc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 512)
	if _, _, err := forger.pc.ReadFromUDPAddrPort(buf); err == nil {
		t.Fatal("伪造注册不该收到挑战")
	}
	if st := r.Stats(); st.Forged == 0 {
		t.Fatalf("伪造计数没记上：%+v", st)
	}
	if addr, ok := r.RegisterLeg(real.label); !ok || addr != realAddr(t, real) {
		t.Fatal("原后端的注册腿不该被伪造者影响")
	}
}

// readData：后端视角读一条**数据**腿帧（跳过 hint 控制帧）。
func (b *fakeBackend) readData(d time.Duration) ([]byte, netip.AddrPort, bool) {
	b.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		buf := make([]byte, 4096)
		_ = b.pc.SetReadDeadline(deadline)
		n, from, err := b.pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			return nil, netip.AddrPort{}, false
		}
		typ, payload, ferr := proto.DecodeFrame(buf[:n])
		if ferr != nil || typ != proto.FrameTypeData {
			continue
		}
		return payload, from, true
	}
	return nil, netip.AddrPort{}, false
}

func realAddr(t *testing.T, b *fakeBackend) netip.AddrPort {
	t.Helper()
	return b.pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

// 数据面：客户端 → 后端 → 客户端，双向都要通；后端看到的源地址是**分配 socket**（不是客户端地址）。
func TestForwardBothWays(t *testing.T) {
	r := startRelay(t, Config{})
	relayAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), r.LocalAddr().Port())
	be := newFakeBackend(t, relayAddr)
	if !be.register() {
		t.Fatal("注册失败")
	}
	cli := newFakeClient(t, be.label, relayAddr)
	cli.send([]byte("ping"))

	// 后端收到：应当来自中继的分配 socket（第一条可能是 hint，跳过）
	payload, from, ok := be.readData(2 * time.Second)
	if !ok || string(payload) != "ping" {
		t.Fatalf("后端没收到转发：payload=%q ok=%v", payload, ok)
	}
	if from == cli.pc.LocalAddr().(*net.UDPAddr).AddrPort() {
		t.Fatal("转发必须来自 per-client 分配 socket，而不是客户端地址")
	}
	// 后端回程（裸 WG 语义）→ 客户端应当收到包在数据腿帧里的同样字节
	if _, err := be.pc.WriteToUDPAddrPort(proto.EncodeFrame(proto.FrameTypeData, []byte{1, 2, 3, 4}), from); err != nil {
		t.Fatal(err)
	}
	got, ok := cli.readData(2 * time.Second)
	if !ok || string(got) != string([]byte{1, 2, 3, 4}) {
		t.Fatalf("客户端没收到回程：%q ok=%v", got, ok)
	}
	// 后端发的腿帧（hint）应当原样透传
	if _, err := be.pc.WriteToUDPAddrPort(proto.EncodeHint("1.2.3.4:5"), from); err != nil {
		t.Fatal(err)
	}
	if addr, ok := cli.readHint(2 * time.Second); !ok || addr != "1.2.3.4:5" {
		t.Fatalf("hint 透传失败：%q ok=%v", addr, ok)
	}
}

// 多客户端互不串流：两条分配 socket 不同、回程各回各家。
func TestTwoClientsIsolated(t *testing.T) {
	r := startRelay(t, Config{})
	relayAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), r.LocalAddr().Port())
	be := newFakeBackend(t, relayAddr)
	if !be.register() {
		t.Fatal("注册失败")
	}
	c1 := newFakeClient(t, be.label, relayAddr)
	c2 := newFakeClient(t, be.label, relayAddr)
	c1.send([]byte("one"))
	c2.send([]byte("two"))

	seen := map[string]netip.AddrPort{}
	for i := 0; i < 2; i++ {
		payload, from, ok := be.readData(2 * time.Second)
		if !ok {
			t.Fatalf("第 %d 条转发没到", i)
		}
		seen[string(payload)] = from
	}
	if seen["one"] == seen["two"] {
		t.Fatalf("两条客户端分配到了同一个 socket：%v", seen["one"])
	}
	// 分别回程
	_, _ = be.pc.WriteToUDPAddrPort(proto.EncodeFrame(proto.FrameTypeData, []byte("R-one")), seen["one"])
	_, _ = be.pc.WriteToUDPAddrPort(proto.EncodeFrame(proto.FrameTypeData, []byte("R-two")), seen["two"])
	got1, ok1 := c1.readData(2 * time.Second)
	got2, ok2 := c2.readData(2 * time.Second)
	if !ok1 || string(got1) != "R-one" || !ok2 || string(got2) != "R-two" {
		t.Fatalf("回程串流：c1=%q(%v) c2=%q(%v)", got1, ok1, got2, ok2)
	}
}

// 准入：没有注册腿的 peerId，客户端数据被丢（蹭不到转发）。
func TestUnknownPeerDropped(t *testing.T) {
	r := startRelay(t, Config{})
	relayAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), r.LocalAddr().Port())
	var label [8]byte
	cli := newFakeClient(t, label, relayAddr)
	cli.send([]byte("ping"))
	time.Sleep(300 * time.Millisecond)
	if st := r.Stats(); st.ForwardedUp != 0 {
		t.Fatalf("未知 peerId 不该被转发：%+v", st)
	}
	if _, ok := cli.readData(300 * time.Millisecond); ok {
		t.Fatal("未知 peerId 不该收到任何回包")
	}
}

// hint：客户端腿建立时双向各推一次（客户端拿后端腿地址，后端拿客户端观察地址）。
func TestHintsOnLegEstablish(t *testing.T) {
	r := startRelay(t, Config{})
	relayAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), r.LocalAddr().Port())
	be := newFakeBackend(t, relayAddr)
	if !be.register() {
		t.Fatal("注册失败")
	}
	cli := newFakeClient(t, be.label, relayAddr)
	cli.send([]byte("hello"))

	// 客户端应当收到「后端注册腿地址」提示
	if addr, ok := cli.readHint(2 * time.Second); !ok || addr != realAddr(t, be).String() {
		t.Fatalf("客户端 hint 不对：%q ok=%v（期望 %v）", addr, ok, realAddr(t, be))
	}
	// 后端应当收到「客户端观察地址」提示（它读到的第一条就是 hint 腿帧）
	buf := make([]byte, 2048)
	var hintAddr string
	for i := 0; i < 4 && hintAddr == ""; i++ {
		_ = be.pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := be.pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			break
		}
		typ, payload, ferr := proto.DecodeFrame(buf[:n])
		if ferr == nil && typ == proto.FrameTypeControl {
			hintAddr, _ = proto.DecodeHintPayload(payload)
		}
	}
	if hintAddr != cli.pc.LocalAddr().(*net.UDPAddr).AddrPort().String() {
		t.Fatalf("后端拿到的客户端 hint 不对：%q（期望 %v）", hintAddr,
			cli.pc.LocalAddr().(*net.UDPAddr).AddrPort())
	}
}

// 空闲回收：分配腿静默超过 IdleTimeout 后被回收。
func TestIdleReclaim(t *testing.T) {
	r := startRelay(t, Config{IdleTimeout: 300 * time.Millisecond})
	relayAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), r.LocalAddr().Port())
	be := newFakeBackend(t, relayAddr)
	if !be.register() {
		t.Fatal("注册失败")
	}
	cli := newFakeClient(t, be.label, relayAddr)
	cli.send([]byte("x"))
	time.Sleep(150 * time.Millisecond)
	if n := r.assocCount(); n != 1 {
		t.Fatalf("应当有 1 条分配腿，实际 %d", n)
	}
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if r.assocCount() == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("空闲分配腿没被回收（当前 %d）", r.assocCount())
}

// 注册腿过期：后端不保活 → 腿被摘掉，客户端数据随之被拒。
func TestLegExpiry(t *testing.T) {
	r := startRelay(t, Config{LegTimeout: 400 * time.Millisecond})
	relayAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), r.LocalAddr().Port())
	be := newFakeBackend(t, relayAddr)
	if !be.register() {
		t.Fatal("注册失败")
	}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := r.RegisterLeg(be.label); !ok {
			return // 已过期
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("注册腿没有过期")
}

// 保活续命：持续 keepalive 时腿不过期。
func TestKeepaliveKeepsLeg(t *testing.T) {
	r := startRelay(t, Config{LegTimeout: 500 * time.Millisecond})
	relayAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), r.LocalAddr().Port())
	be := newFakeBackend(t, relayAddr)
	if !be.register() {
		t.Fatal("注册失败")
	}
	for i := 0; i < 4; i++ {
		be.keepalive()
		time.Sleep(200 * time.Millisecond)
		if _, ok := r.RegisterLeg(be.label); !ok {
			t.Fatalf("第 %d 次保活后腿就不在了", i+1)
		}
	}
}

// 中继重启（腿表清空）后：后端的 keepalive 应当换来一条「请重新注册」，而不是被静默丢弃。
func TestKeepaliveOnUnknownLegAsksAgain(t *testing.T) {
	r := startRelay(t, Config{})
	relayAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), r.LocalAddr().Port())
	be := newFakeBackend(t, relayAddr)
	if !be.register() {
		t.Fatal("注册失败")
	}
	// 模拟"中继重启"：直接把腿表清掉
	r.mu.Lock()
	r.legs = map[[8]byte]*leg{}
	r.mu.Unlock()

	be.keepalive()
	buf := make([]byte, 512)
	_ = be.pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := be.pc.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("保活后应当收到「请重新注册」应答：%v", err)
	}
	typ, payload, err := proto.DecodeFrame(buf[:n])
	if err != nil || typ != proto.FrameTypeRelayReg {
		t.Fatalf("应答帧形态不对：typ=%d err=%v", typ, err)
	}
	if sub, _ := proto.RelaySubtype(payload); sub != proto.RelaySubAgain {
		t.Fatalf("应当是「请重新注册」，收到 subtype=%#x", sub)
	}
	// 重新走一遍注册应当成功（腿表已空，从 Hello 开始）
	if !be.register() {
		t.Fatal("收到 Again 后重注册应当成功")
	}
}

// TestShadowKeepaliveDoesNotExtendNoAddrLeg（FIX-68）：无 UDP 注册地址的腿（纯控制腿）
// 只认「有控制连接且同 IP」的保活——否则任何人知道 label 就能发影子保活把腿永久
// 占住。判据：腿的 last 不被影子保活推后，且回 RelayAgain（要求重走注册）。
func TestShadowKeepaliveDoesNotExtendNoAddrLeg(t *testing.T) {
	r := startRelay(t, Config{})
	// 造一条无 addr 的腿（模拟控制腿；不挂控制连接 = 影子形态）。
	label := [8]byte{'s', 'h', 'a', 'd', 'o', 'w', '0', '1'}
	lg := &leg{label: label, last: time.Now()}
	r.mu.Lock()
	r.legs[label] = lg
	lg.verified = true
	lg.addr = netip.AddrPort{}
	lg.last = time.Now().Add(-time.Minute)
	before := lg.last
	r.mu.Unlock()

	// 影子保活：来自任意源（不同 IP 或干脆没有控制连接）。
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	msg := proto.EncodeTagged(label, proto.FrameTypeRelayReg, proto.EncodeRelayKeepalive())
	if _, err := pc.WriteToUDPAddrPort(msg, r.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	// 等一小会：last 不得被推后（影子保活不续命）。
	time.Sleep(150 * time.Millisecond)
	r.mu.Lock()
	after := lg.last
	r.mu.Unlock()
	if !after.Equal(before) {
		t.Fatalf("影子保活不应续命：before=%v after=%v", before, after)
	}
	// 回包应为 Again（要求重注册）——读它。
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, _, rerr := pc.ReadFromUDPAddrPort(buf)
	if rerr != nil {
		t.Fatalf("应收到 Again 应答：%v", rerr)
	}
	typ, payload, derr := proto.DecodeFrame(buf[:n])
	if derr != nil || typ != proto.FrameTypeRelayReg {
		t.Fatalf("应答应是 RelayReg 帧：typ=0x%02x err=%v", typ, derr)
	}
	if sub, _ := proto.RelaySubtype(payload); sub != proto.RelaySubAgain {
		t.Fatalf("影子保活应回 RelayAgain（要求重注册），实际 sub=0x%02x", sub)
	}
}
