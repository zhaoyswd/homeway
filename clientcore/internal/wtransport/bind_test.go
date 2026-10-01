package wtransport

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
	"golang.zx2c4.com/wireguard/conn"
)

func mustLocalListener(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func udpAddr(c *net.UDPConn) netip.AddrPort {
	return netip.MustParseAddrPort(c.LocalAddr().String())
}

func readWithDeadline(t *testing.T, c *net.UDPConn, d time.Duration) []byte {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(d)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}

func newTestBind(t *testing.T, cfg Config) *Bind {
	t.Helper()
	if cfg.Identity == nil {
		id, err := NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		cfg.Identity = id
	}
	b := NewBind(cfg)
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	b.recv = fns[0] // 测试直驱收包
	return b
}

func callRecv(t *testing.T, b *Bind, d time.Duration) (int, []byte) {
	t.Helper()
	done := make(chan struct{})
	var n int
	var pkt []byte
	go func() {
		defer close(done)
		packets := [][]byte{make([]byte, 65535)}
		sizes := make([]int, 1)
		eps := make([]conn.Endpoint, 1)
		n, _ = b.recv(packets, sizes, eps)
		if n > 0 {
			pkt = append([]byte(nil), packets[0][:sizes[0]]...)
		}
	}()
	select {
	case <-done:
		return n, pkt
	case <-time.After(d):
		t.Fatal("recv 超时")
		return 0, nil
	}
}

// ---------- 2.1 判据：镜像计数 / 采纳切换 / 未知帧忽略 ----------

func TestMirrorCountAndAdoption(t *testing.T) {
	live := mustLocalListener(t)
	dead1 := netip.MustParseAddrPort("127.0.0.1:1")
	dead2 := netip.MustParseAddrPort("127.0.0.1:2")

	b := newTestBind(t, Config{
		Candidates: []Candidate{{Addr: udpAddr(live)}, {Addr: dead1}, {Addr: dead2}},
	})
	race, err := b.ParseEndpoint("race")
	if err != nil {
		t.Fatal(err)
	}

	wg := []byte{1, 0, 0, 0xde, 0xad}
	if err := b.Send([][]byte{wg}, race); err != nil {
		t.Fatal(err)
	}
	// 判据①：镜像计数=1（一个出站包镜像到 3 候选）
	if got := b.Status().Mirrored; got != 1 {
		t.Fatalf("镜像计数 = %d, want 1", got)
	}
	// 判据②：活候选收到「reg 搭车‖WG」单数据报，拆分后 WG 部分一致
	pkt := readWithDeadline(t, live, 2*time.Second)
	if pkt == nil {
		t.Fatal("活候选未收到镜像包")
	}
	reg, rest, ok := proto.SplitDirectReg(pkt)
	if !ok {
		t.Fatalf("镜像包缺 reg 前缀：% x", pkt[:4])
	}
	if string(rest) != string(wg) {
		t.Fatalf("WG 部分不匹配：% x", rest)
	}
	if _, _, err := proto.VerifyReg(b.cfg.Secret, reg, time.Now(), time.Minute); err != nil {
		t.Fatalf("搭车 reg 校验失败：%v", err)
	}

	// 判据③：活候选应答 → 采纳该来源；后续发送只走采纳路径且不再带 reg
	live.WriteToUDPAddrPort(wg, localAddr(b.Port()))
	n, got := callRecv(t, b, 2*time.Second)
	if n != 1 || string(got) != string(wg) {
		t.Fatalf("recv n=%d pkt=% x", n, got)
	}
	addr, relay, valid := b.Adopted()
	if !valid || relay || addr != udpAddr(live) {
		t.Fatalf("采纳状态 = %v %v %v", addr, relay, valid)
	}
	if err := b.Send([][]byte{wg}, race); err != nil {
		t.Fatal(err)
	}
	pkt2 := readWithDeadline(t, live, 2*time.Second)
	if pkt2 == nil || string(pkt2) != string(wg) {
		t.Fatalf("采纳后应裸发 WG：% x", pkt2)
	}
}

func TestAdoptionSwitch(t *testing.T) {
	l1, l2 := mustLocalListener(t), mustLocalListener(t)
	b := newTestBind(t, Config{Candidates: []Candidate{{Addr: udpAddr(l1)}, {Addr: udpAddr(l2)}}})
	race, _ := b.ParseEndpoint("race")
	wg := []byte{4, 0, 0}

	_ = b.Send([][]byte{wg}, race)
	// L2 先应答 → 采纳 L2
	l2.WriteToUDPAddrPort(wg, localAddr(b.Port()))
	callRecv(t, b, 2*time.Second)
	if a, _, ok := b.Adopted(); !ok || a != udpAddr(l2) {
		t.Fatalf("首个响应者应为 L2：%v", a)
	}
	// L1 后应答 → 漫游语义：最新合法来源胜出
	l1.WriteToUDPAddrPort(wg, localAddr(b.Port()))
	callRecv(t, b, 2*time.Second)
	if a, _, ok := b.Adopted(); !ok || a != udpAddr(l1) {
		t.Fatalf("后到来源应切换采纳：%v", a)
	}
}

func TestRelayLegHintAndUnknownFrame(t *testing.T) {
	rl := mustLocalListener(t) // 扮演中继 listener
	var hints []string
	var mu sync.Mutex
	b := newTestBind(t, Config{
		PeerID:     goldenPeerID,
		Candidates: []Candidate{{Addr: udpAddr(rl), Relay: true}},
		OnHint: func(addr string) {
			mu.Lock()
			hints = append(hints, addr)
			mu.Unlock()
		},
	})
	race, _ := b.ParseEndpoint("race")
	wg := []byte{1, 0x11}

	// 赛跑期发送：中继应收到 [tag reg] 与 [tag data] 两数据报
	_ = b.Send([][]byte{wg}, race)
	p1 := readWithDeadline(t, rl, 2*time.Second)
	p2 := readWithDeadline(t, rl, 2*time.Second)
	_, typ1, _, err := proto.DecodeTagged(p1)
	if err != nil || typ1 != proto.FrameTypeReg {
		t.Fatalf("首帧应为 tagged reg：err=%v typ=%d", err, typ1)
	}
	_, typ2, payload2, err := proto.DecodeTagged(p2)
	if err != nil || typ2 != proto.FrameTypeData || string(payload2) != string(wg) {
		t.Fatalf("次帧应为 tagged data：err=%v typ=%d", err, typ2)
	}

	// 回程：hint 帧 → 回调、不产包；未知类型 → 忽略；数据帧 → 入 device
	relay := localAddr(b.Port())
	rl.WriteToUDPAddrPort(proto.EncodeHint("203.0.113.99:41641"), relay)
	rl.WriteToUDPAddrPort(proto.EncodeFrame(0x7F, []byte("junk-from-future")), relay)
	rl.WriteToUDPAddrPort(proto.EncodeFrame(proto.FrameTypeData, wg), relay)

	n, got := callRecv(t, b, 2*time.Second)
	if n != 1 || string(got) != string(wg) {
		t.Fatalf("数据帧应穿透：%d % x", n, got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(hints) != 1 || hints[0] != "203.0.113.99:41641" {
		t.Fatalf("hints = %v（hint 与未知帧都不该打断数据帧）", hints)
	}
	if a, isRelay, ok := b.Adopted(); !ok || !isRelay || a != udpAddr(rl) {
		t.Fatalf("中继采纳状态错误：%v %v", a, isRelay)
	}

	// 采纳后发送 → 只发 tagged data
	_ = b.Send([][]byte{wg}, race)
	p3 := readWithDeadline(t, rl, 2*time.Second)
	if _, typ3, _, err := proto.DecodeTagged(p3); err != nil || typ3 != proto.FrameTypeData {
		t.Fatalf("采纳后应只发 data 帧：%v %d", err, typ3)
	}
}

func TestRearmRegAgain(t *testing.T) {
	live := mustLocalListener(t)
	b := newTestBind(t, Config{Candidates: []Candidate{{Addr: udpAddr(live)}}})
	race, _ := b.ParseEndpoint("race")
	wg := []byte{1, 0}

	_ = b.Send([][]byte{wg}, race)
	readWithDeadline(t, live, time.Second) // reg‖wg
	_ = b.Send([][]byte{wg}, race)
	p := readWithDeadline(t, live, time.Second)
	if _, _, ok := proto.SplitDirectReg(p); ok {
		t.Fatal("同轮赛跑内 reg 只应搭车一次")
	}

	b.Rearm()
	_ = b.Send([][]byte{wg}, race)
	p2 := readWithDeadline(t, live, time.Second)
	if _, _, ok := proto.SplitDirectReg(p2); !ok {
		t.Fatal("Rearm 后 reg 应重新武装")
	}
}

// ---------- 2.2 判据：同钥跨重连 / 异进程异钥 ----------

func TestIdentityLifecycle(t *testing.T) {
	id1, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	id2, _ := NewIdentity()
	// 异进程（实例）异钥
	if id1.PublicKey() == id2.PublicKey() {
		t.Fatal("两个 Identity 不应派生相同公钥")
	}

	live := mustLocalListener(t)
	b := newTestBind(t, Config{Identity: id1, Candidates: []Candidate{{Addr: udpAddr(live)}}})
	race, _ := b.ParseEndpoint("race")
	pubBefore := b.cfg.Identity.PublicKey()

	// 同钥跨重连：Rebind 换 socket 不换身份；reg 仍可验证
	if err := b.Rebind(); err != nil {
		t.Fatal(err)
	}
	b.Rearm() // 重连=新一轮赛跑
	if pubAfter := b.cfg.Identity.PublicKey(); pubAfter != pubBefore {
		t.Fatal("Rebind 不应更换身份密钥")
	}
	_ = b.Send([][]byte{{1, 0}}, race)
	pkt := readWithDeadline(t, live, 2*time.Second)
	reg, _, ok := proto.SplitDirectReg(pkt)
	if !ok {
		t.Fatal("重连后镜像包应重新搭车 reg")
	}
	if _, _, err := proto.VerifyReg(b.cfg.Secret, reg, time.Now(), time.Minute); err != nil {
		t.Fatalf("重连后 reg 校验失败：%v", err)
	}
}

var goldenPeerID = func() [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = byte(i + 3)
	}
	return k
}()

func localAddr(port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
}

// tasks 2.6 契约：状态上报的 via/ep/新鲜度与候选快照。
func TestBindStatusContract(t *testing.T) {
	secret := [32]byte{7, 7, 7}
	peer := mustLocalListener(t)
	peerAP := udpAddr(peer)
	b := newTestBind(t, Config{
		PeerID:     testPeerID(),
		Secret:     secret,
		Candidates: []Candidate{{Addr: peerAP}},
	})

	// 还没收到任何包：via=none，无 ep
	if st := b.Status(); st.Via != "none" || st.Ep != "" || st.At != 0 {
		t.Fatalf("未建连状态不符：%+v", st)
	}

	// 直连包到达 → via=direct + ep + 新鲜度时间戳
	dst := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), b.Port())
	if _, err := peer.WriteToUDPAddrPort([]byte("wg"), dst); err != nil {
		t.Fatal(err)
	}
	if n, pkt := callRecv(t, b, time.Second); n != 1 || string(pkt) != "wg" {
		t.Fatalf("收包失败：n=%d pkt=%q", n, pkt)
	}
	st := b.Status()
	if st.Via != "direct" || st.Ep != peerAP.String() || st.At == 0 || st.AdoptedAt == 0 {
		t.Fatalf("直连状态不符：%+v", st)
	}
	if len(st.Candidates) != 1 || !st.Candidates[0].Adopted || st.Candidates[0].Relay {
		t.Fatalf("候选快照不符：%+v", st.Candidates)
	}

	// 中继腿帧到达 → via=relay（且入 device 的是解出的载荷）
	relay := mustLocalListener(t)
	relayAP := udpAddr(relay)
	b2 := newTestBind(t, Config{
		PeerID:     testPeerID(),
		Secret:     secret,
		Candidates: []Candidate{{Addr: relayAP, Relay: true}},
	})
	dst2 := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), b2.Port())
	if _, err := relay.WriteToUDPAddrPort(proto.EncodeFrame(proto.FrameTypeData, []byte("leg-payload")), dst2); err != nil {
		t.Fatal(err)
	}
	if n, pkt := callRecv(t, b2, time.Second); n != 1 || string(pkt) != "leg-payload" {
		t.Fatalf("腿帧解包失败：n=%d pkt=%q", n, pkt)
	}
	if st := b2.Status(); st.Via != "relay" || st.Ep != relayAP.String() {
		t.Fatalf("中继状态不符：%+v", st)
	}
	if cs := b2.Status().Candidates; len(cs) != 1 || !cs[0].Relay || !cs[0].Adopted {
		t.Fatalf("中继候选快照不符：%+v", cs)
	}

	// JSON 键名回归：扩展侧 tunStatusJSON 的 link 段就是靠 via/ep（手工映射，这里锁键名）
	statusRaw, err := json.Marshal(b.Status())
	if err != nil {
		t.Fatalf("状态序列化失败：%v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(statusRaw, &m); err != nil {
		t.Fatalf("状态 JSON 不可解析：%v", err)
	}
	if m["via"] != "direct" || m["ep"] != peerAP.String() {
		t.Fatalf("状态 JSON 键名/取值不符：%v", m)
	}
}

// IPv6 承载（tasks IPv6）：候选是 v6 地址时，双栈 socket 要能镜像、采纳、裸发。
func TestMirrorAndAdoptOverIPv6(t *testing.T) {
	live, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("::1")})
	if err != nil {
		t.Skipf("环境不支持 v6 loopback: %v", err)
	}
	t.Cleanup(func() { live.Close() })
	liveAddr := netip.MustParseAddrPort(live.LocalAddr().String())
	if !liveAddr.Addr().Is6() || liveAddr.Addr().Is4In6() {
		t.Skipf("监听地址不是纯 v6: %v", liveAddr)
	}

	b := newTestBind(t, Config{Candidates: []Candidate{{Addr: liveAddr}}})
	race, err := b.ParseEndpoint("race")
	if err != nil {
		t.Fatal(err)
	}
	wg := []byte{1, 0, 0, 0xbe, 0xef}
	if err := b.Send([][]byte{wg}, race); err != nil {
		t.Fatal(err)
	}
	pkt := readWithDeadline(t, live, 2*time.Second)
	if pkt == nil {
		t.Fatal("v6 候选未收到镜像包")
	}
	if _, rest, ok := proto.SplitDirectReg(pkt); !ok || string(rest) != string(wg) {
		t.Fatalf("v6 镜像包内容不符：% x", pkt)
	}

	// v6 来源应答 → 采纳；后续裸发
	if _, err := live.WriteToUDPAddrPort(wg, localPortOf(t, b)); err != nil {
		t.Fatal(err)
	}
	n, got := callRecv(t, b, 2*time.Second)
	if n != 1 || string(got) != string(wg) {
		t.Fatalf("v6 recv n=%d pkt=% x", n, got)
	}
	addr, relay, valid := b.Adopted()
	if !valid || relay || addr != liveAddr {
		t.Fatalf("v6 采纳状态 = %v relay=%v valid=%v，want %v", addr, relay, valid, liveAddr)
	}
	if err := b.Send([][]byte{wg}, race); err != nil {
		t.Fatal(err)
	}
	if pkt2 := readWithDeadline(t, live, 2*time.Second); pkt2 == nil || string(pkt2) != string(wg) {
		t.Fatalf("v6 采纳后应裸发 WG：% x", pkt2)
	}
}

// localPortOf：Bind 当前 socket 的本地地址（测试里手工回包用；v4/v6 都适用）。
func localPortOf(t *testing.T, b *Bind) netip.AddrPort {
	t.Helper()
	c := b.curConn()
	if c == nil {
		t.Fatal("bind 未打开")
	}
	ap, err := netip.ParseAddrPort(c.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if ap.Addr().IsUnspecified() {
		// 双栈 Bind 监听在 [::]（未指定地址）：回包要发到 loopback。
		if ap.Addr().Is6() {
			return netip.AddrPortFrom(netip.MustParseAddr("::1"), ap.Port())
		}
		return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), ap.Port())
	}
	return ap
}

// Close 与 Rebind 并发（评审 P0-2）：收工后再 Rebind 报错且不留野 socket；
// 竞态窗口内 Close 关掉的永远是「当前」socket（锁内置位+关当前），不 panic、不泄漏。
func TestBindCloseRebindRace(t *testing.T) {
	b := NewBind(Config{Candidates: []Candidate{{Addr: netip.MustParseAddrPort("127.0.0.1:1")}}})
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_ = b.Rebind() // 竞态期允许成功也允许「已收工」错误，唯独不允许野 socket
		}
	}()
	if err := b.Close(); err != nil {
		t.Fatalf("Close 失败：%v", err)
	}
	wg.Wait()
	if err := b.Rebind(); err == nil {
		t.Fatal("收工后 Rebind 应报错（不留野 socket）")
	}
	if b.RefreshReg() {
		t.Fatal("收工后 RefreshReg 应返回 false")
	}
	// 幂等收工
	if err := b.Close(); err != nil {
		t.Fatalf("二次 Close 应幂等：%v", err)
	}
}

// Close→Open 复活（wireguard-go BindUpdate 的真实序列）：重开后 Rebind/Close 恢复正常，
// 收工位不会把「换绑流程中的 Close」误当终局（挂死根因的回归用例）。
func TestBindReopenAfterClose(t *testing.T) {
	b := NewBind(Config{Candidates: []Candidate{{Addr: netip.MustParseAddrPort("127.0.0.1:1")}}})
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil { // 模拟 BindUpdate 第一步：closeBindLocked
		t.Fatal(err)
	}
	if _, _, err := b.Open(0); err != nil { // 第二步：重开
		t.Fatal(err)
	}
	if err := b.Rebind(); err != nil {
		t.Fatalf("重开后 Rebind 应正常：%v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("重开后的终局 Close 应关活 socket：%v", err)
	}
}

// TestReceiveFuncSurvivesNonCloseErrors 「非收工类读错误不交回 wg-go」的契约
// （真机 2026-09-22 冻结唤醒根因：OS 作废 socket 后读侧返回 ECONNABORTED 一族错误，
// 旧实现把错误原样交回 wireguard-go——它的 RoutineReadFrom 对 non-Temporary 错误
// 直接 return，读 goroutine 死亡 ⇒ Bind 永久失聪（发得出/收不到），R1-R3 换源救
// 不回、只剩整会话重建）。三断言：①持续错误期间 fn 不返回（wg-go 的读 goroutine
// 不会死）；②Rebind 换入新 socket 后 fn 恢复读到真实数据包；③Close 后 fn 带错误
// 返回（收工语义不变）。
func TestReceiveFuncSurvivesNonCloseErrors(t *testing.T) {
	var logLines []string
	cfg := Config{Logf: func(f string, a ...any) { logLines = append(logLines, fmt.Sprintf(f, a...)) }}
	b := NewBind(cfg)
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	fn := fns[0]

	deadErr := &net.OpError{Op: "read", Net: "udp", Err: syscall.ECONNABORTED}
	calls := int32(0)
	b.mu.Lock()
	b.readFrom = func(c *net.UDPConn, buf []byte) (int, netip.AddrPort, error) {
		// 只注入 2 次（评审⑤：次数与 300ms 慢转常量解耦——间隔将来放宽也不 flaky）
		if atomic.AddInt32(&calls, 1) <= 2 {
			return 0, netip.AddrPort{}, deadErr // 冻结唤醒后的 socket 错误
		}
		return c.ReadFromUDPAddrPort(buf) // 之后落到真实读
	}
	b.mu.Unlock()

	packets := make([][]byte, 1)
	packets[0] = make([]byte, 1500)
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)

	type res struct {
		n   int
		err error
	}
	done := make(chan res, 1)
	go func() {
		n, err := fn(packets, sizes, eps)
		done <- res{n, err}
	}()

	// ① 错误期间 fn 不得返回，且确实在重试（calls 增长=在慢转，不是阻塞在真实读上）
	select {
	case r := <-done:
		t.Fatalf("fn 在非收工类错误下返回了（n=%d err=%v）——读 goroutine 会死亡", r.n, r.err)
	case <-time.After(600 * time.Millisecond):
	}
	if n := atomic.LoadInt32(&calls); n < 2 {
		t.Fatalf("错误期间应持续重试（calls=%d）", n)
	}

	// ② Rebind 换新 socket + 真实发包：fn 应读到包
	if err := b.Rebind(); err != nil {
		t.Fatalf("rebind: %v", err)
	}
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("peer listen: %v", err)
	}
	defer peer.Close()
	cur := b.curConn()
	dst := net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cur.LocalAddr().(*net.UDPAddr).Port}
	if _, err := peer.WriteToUDP([]byte("hello-after-rebind"), &dst); err != nil {
		t.Fatalf("peer write: %v", err)
	}
	select {
	case r := <-done:
		if r.err != nil || r.n != 1 {
			t.Fatalf("rebind 后未恢复收包：包数=%d err=%v", r.n, r.err)
		}
		if string(packets[0][:sizes[0]]) != "hello-after-rebind" {
			t.Fatalf("收到的内容不对：%q", packets[0][:sizes[0]])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("3s 内未恢复收包（Rebind 后应立即可读）")
	}

	// ③ 收工语义：Close 后 fn 返回错误（wg-go 的读 goroutine 干净退出）
	done2 := make(chan error, 1)
	go func() {
		_, err := fn(packets, sizes, eps)
		done2 <- err
	}()
	_ = b.Close()
	select {
	case err := <-done2:
		if err == nil {
			t.Fatal("Close 后 fn 应返回错误")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close 后 3s 未返回")
	}
	errLogs := 0
	for _, l := range logLines {
		if strings.Contains(l, "接收读错误") {
			errLogs++
		}
	}
	if errLogs != 1 {
		t.Fatalf("读错误限流日志应恰 1 行（2 次错误 5s 窗口内），实际 %d 行：%v", errLogs, logLines)
	}
}

// ---- demand-driven-recovery D2：本地发送错误分类与粘性旁路信号 ----

func TestIsLocalSendErr(t *testing.T) {
	// sendto 被拒（挂起态网络禁用的形态）：*net.OpError 且 Op 为写系。
	perm := &net.OpError{Op: "write", Net: "udp", Err: syscall.EPERM}
	if !isLocalSendErr(perm) {
		t.Fatal("EPERM 写错误应判本地类")
	}
	// 拨号超时/上下文类（对端无响应的巡检形态）：非 OpError-write，不判本地。
	if isLocalSendErr(errors.New("wgnet: connect 取消: context deadline exceeded")) {
		t.Fatal("超时类不应判本地类")
	}
	if isLocalSendErr(nil) {
		t.Fatal("nil 不判本地类")
	}
}

func TestLocalSendErrStickySignal(t *testing.T) {
	b := NewBind(Config{Logf: func(string, ...any) {}})
	if b.LocalSendErrWithin(time.Minute) {
		t.Fatal("从未出错不应命中")
	}
	// 采纳路径（noteSendErr）注入一次本地错误：粘性信号命中。
	b.noteSendErr(netip.MustParseAddrPort("192.0.2.1:41641"), &net.OpError{Op: "write", Net: "udp", Err: syscall.EPERM})
	if !b.LocalSendErrWithin(time.Minute) {
		t.Fatal("采纳路径本地错误应命中粘性信号")
	}
	if b.AdoptedLocalErrCount() != 1 {
		t.Fatalf("采纳路径计数应为 1：%d", b.AdoptedLocalErrCount())
	}
	// 远端类错误不影响粘性信号与计数。
	b.noteSendErr(netip.MustParseAddrPort("192.0.2.1:41641"), errors.New("i/o timeout"))
	if b.AdoptedLocalErrCount() != 1 {
		t.Fatal("远端类错误不应累计本地计数")
	}
}

// 评审 H4：镜像候选的本地失败（LAN 端点在异网下的必然 ENETUNREACH）**不刷粘性信号**
// ——否则未采纳期「出口真不可达」被整体掩盖成环境噪声。
func TestMirrorSendErrNotSticky(t *testing.T) {
	b := NewBind(Config{Logf: func(string, ...any) {}})
	b.noteMirrorSendErr(netip.MustParseAddrPort("192.168.3.12:41641"), &net.OpError{Op: "write", Net: "udp", Err: syscall.EHOSTUNREACH})
	if b.LocalSendErrWithin(time.Minute) {
		t.Fatal("镜像候选本地失败不应命中粘性信号（收窄到采纳路径）")
	}
	if b.LocalSendErrCount() != 1 {
		t.Fatalf("诊断计数（全部）应为 1：%d", b.LocalSendErrCount())
	}
	if b.AdoptedLocalErrCount() != 0 {
		t.Fatalf("采纳路径计数应为 0：%d", b.AdoptedLocalErrCount())
	}
}

// 评审 3-1：按拍发送统计——「全候选本地失败 ⇒ 环境性禁发」判据的数据源。
func TestSwapSendStats(t *testing.T) {
	b := NewBind(Config{Logf: func(string, ...any) {}})
	// 成功路径：向真实 listener 发一发（tries=1, localFails=0）。
	lst := mustLocalListener(t)
	defer lst.Close()
	laddr := lst.LocalAddr().(*net.UDPAddr)
	c, err := net.ListenUDP("udp", &net.UDPAddr{}) // 未连接 socket：WriteToUDPAddrPort 语义
	if err != nil {
		t.Fatal(err)
	}
	if err := b.writeUDP(c, []byte("x"), laddr.AddrPort()); err != nil {
		t.Fatal(err)
	}
	tries, fails := b.SwapSendStats()
	if tries != 1 || fails != 0 {
		t.Fatalf("成功一发应计 (1,0)：%d/%d", tries, fails)
	}
	// 本地失败路径：closed conn 的写是本地类错误（Op=write 系）→ 计 (tries, fails) 同增。
	c.Close()
	_ = b.writeUDP(c, []byte("x"), laddr.AddrPort())
	tries, fails = b.SwapSendStats()
	if tries != 1 || fails != 1 {
		t.Fatalf("失败一发应计 (1,1)：%d/%d", tries, fails)
	}
	// 取走即清零。
	tries, fails = b.SwapSendStats()
	if tries != 0 || fails != 0 {
		t.Fatalf("取走后应为零：%d/%d", tries, fails)
	}
}

// TestAdoptionHandoverDualSend（FIX-09）：稳态下从未知来源（非候选）切采纳 → 旧路径
// 宽限双发（伪造源/错投不再形成「出站全打给错误地址 → 出口收不到 → 再无纠正包」的
// 悬崖）；切回合法候选 → 过渡清除。
func TestAdoptionHandoverDualSend(t *testing.T) {
	live := mustLocalListener(t)
	spoof := mustLocalListener(t)
	b := newTestBind(t, Config{Candidates: []Candidate{{Addr: udpAddr(live)}}})
	race, err := b.ParseEndpoint("race")
	if err != nil {
		t.Fatal(err)
	}
	wg := []byte{9, 0, 0}

	// 镜像期：live 收镜像包（先排空）。
	if err := b.Send([][]byte{wg}, race); err != nil {
		t.Fatal(err)
	}
	if pkt := readWithDeadline(t, live, 2*time.Second); pkt == nil {
		t.Fatal("live 未收镜像包")
	}
	// live 应答 → 采纳 live（稳态）。
	live.WriteToUDPAddrPort(wg, localAddr(b.Port()))
	if n, _ := callRecv(t, b, 2*time.Second); n != 1 {
		t.Fatal("live 应答未被读入")
	}
	if a, _, ok := b.Adopted(); !ok || a != udpAddr(live) {
		t.Fatalf("应采纳 live：%v", a)
	}

	// 未知来源应答 → 采纳切换（漫游学习语义保留）+ 登记过渡双发。
	spoof.WriteToUDPAddrPort(wg, localAddr(b.Port()))
	if n, _ := callRecv(t, b, 2*time.Second); n != 1 {
		t.Fatal("spoof 应答未被读入")
	}
	if a, _, ok := b.Adopted(); !ok || a != udpAddr(spoof) {
		t.Fatalf("未知来源应被采纳（漂移学习路径）：%v", a)
	}
	// 判据①：此后一发 Send 同时到达新路径与旧路径（宽限双发）。
	if err := b.Send([][]byte{wg}, race); err != nil {
		t.Fatal(err)
	}
	if got := readWithDeadline(t, spoof, 1*time.Second); string(got) != string(wg) {
		t.Fatalf("新路径未收包：% x", got)
	}
	if got := readWithDeadline(t, live, 1*time.Second); string(got) != string(wg) {
		t.Fatalf("旧路径未收宽限双发（单发悬崖回归）：% x", got)
	}
	// 判据②：切回合法候选（live 再应答）→ 过渡清除，不再向 spoof 双发。
	live.WriteToUDPAddrPort(wg, localAddr(b.Port()))
	if n, _ := callRecv(t, b, 2*time.Second); n != 1 {
		t.Fatal("live 再应答未被读入")
	}
	if err := b.Send([][]byte{wg}, race); err != nil {
		t.Fatal(err)
	}
	if got := readWithDeadline(t, live, 1*time.Second); string(got) != string(wg) {
		t.Fatalf("切回后 live 应收包：% x", got)
	}
	if got := readWithDeadline(t, spoof, 300*time.Millisecond); got != nil {
		t.Fatalf("切回候选后不应再双发到未知来源（过渡未清除）：% x", got)
	}
}

// TestMirrorLogThrottled（FIX-13）：未采纳期 MIRROR 行每轮限 3 条（旧行为：每包一行，
// 长连未采纳期把 8MB 日志轮转冲爆、吃掉故障现场）；全量计数仍在 Status().Mirrored。
func TestMirrorLogThrottled(t *testing.T) {
	live := mustLocalListener(t)
	var mu sync.Mutex
	mirrorLines := 0
	b := newTestBind(t, Config{
		Candidates: []Candidate{{Addr: udpAddr(live)}},
		Logf: func(format string, args ...any) {
			if strings.HasPrefix(format, "MIRROR 镜像包") {
				mu.Lock()
				mirrorLines++
				mu.Unlock()
			}
		},
	})
	race, err := b.ParseEndpoint("race")
	if err != nil {
		t.Fatal(err)
	}
	wg := []byte{1, 2, 3}
	for i := 0; i < 10; i++ {
		if err := b.Send([][]byte{wg}, race); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	got := mirrorLines
	mu.Unlock()
	if got == 0 {
		t.Fatal("首条 MIRROR 行必须打出（判据不丢）")
	}
	if got > 3 {
		t.Fatalf("MIRROR 行应每轮限 3 条，实得 %d", got)
	}
	if n := b.Status().Mirrored; n != 10 {
		t.Fatalf("全量镜像计数应照记（10），实得 %d", n)
	}
}
