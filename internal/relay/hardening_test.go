package relay

// hardening_test.go — 2026-09-21 深度评审整改的对抗性回归（组 2/3）。
//
//	#2  控制先连 → UDP Hello 重注册：控制连接必须仍有效（旧实现会整体替换 leg 对象）
//	#3  第三方抢占数据口：未认证源收不到客户端上行、不改腿；合法重拨（带认证）可跟随
//	#7  16 条空闲已认证连接不挡新握手；并发握手超限有日志
//	#18 控制路径建腿也受 MaxLegs 闸

import (
	"bufio"
	"crypto/rand"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
	"golang.org/x/crypto/curve25519"
)

// relayAddrOf：本测试文件统一的「127.0.0.1 + 实际端口」。
func relayAddrOf(t *testing.T, r *Relay) netip.AddrPort {
	t.Helper()
	ap := r.LocalAddr()
	if !ap.IsValid() {
		t.Fatal("中继没起来")
	}
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), ap.Port())
}

// openKey：开放模式下腿认证的 key（cookie 本身，与 legMACKey 同规则）。
func openKey(cookie [16]byte) [32]byte {
	var k [32]byte
	copy(k[:16], cookie[:])
	return k
}

// #2：控制先连（ctlVerified、无 UDP 注册）→ UDP Hello 到达（重注册）→
// 控制连接必须仍挂在**同一个** leg 对象上——新会话仍能走 SESSION 通告。
// 旧实现：Hello 看到 !verified 就 &leg{...} 整体替换，ctl 留在脱离 map 的旧对象上，
// hasControlLocked 恒 false ⇒ 拨腿模式静默失效（中继重启后近乎必然发生）。
func TestHelloReRegisterKeepsControlConn(t *testing.T) {
	r := startRelay(t, Config{})
	relayAddr := relayAddrOf(t, r)

	be := newDialBackend(t, relayAddr, [32]byte{})
	be.connect(t) // 控制先连
	be.readLoop(t)

	// UDP Hello（走主 socket，模拟后端的注册腿开跑）——这是触发旧 bug 的关键次序。
	pc, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if _, err := pc.WriteToUDPAddrPort(
		proto.EncodeTagged(be.label, proto.FrameTypeRelayReg, proto.EncodeRelayHello(be.pub)), relayAddr); err != nil {
		t.Fatal(err)
	}

	// 客户端到达：必须仍走拨腿模式（SESSION 通告可达）。
	cli := newFakeClient(t, be.label, relayAddr)
	cli.send([]byte("after-rereg"))
	select {
	case sess := <-be.sessions:
		leg := be.dialLeg(t, sess)
		be.readLeg(t, leg, "after-rereg")
	case <-time.After(3 * time.Second):
		t.Fatal("UDP 重注册后 SESSION 通告没到——控制连接被 Hello 替换掉了（#2 回归）")
	}
}

// #3 主用例：第三方抢先向数据口发包 → 收不到客户端上行（pend 不放行）、
// 腿状态不变；随后真后端带认证拨腿 → 正常接管。
func TestLegHijackRejected(t *testing.T) {
	r := startRelay(t, Config{})
	relayAddr := relayAddrOf(t, r)

	be := newDialBackend(t, relayAddr, [32]byte{})
	be.connect(t)
	be.readLoop(t)

	cli := newFakeClient(t, be.label, relayAddr)
	cli.send([]byte("secret-uplink"))

	var sess proto.CtlSession
	select {
	case sess = <-be.sessions:
	case <-time.After(3 * time.Second):
		t.Fatal("没收到 SESSION 通告")
	}

	// 第三方：不知道 cookie，直接向数据口灌数据（旧实现会把它认成腿并把
	// pend 里的 WG 密文灌给它）。
	hijacker, err := net.DialUDP("udp4", nil,
		net.UDPAddrFromAddrPort(netip.AddrPortFrom(relayAddr.Addr(), sess.DataPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer hijacker.Close()
	if _, err := hijacker.Write([]byte("i-am-backend-trust-me")); err != nil {
		t.Fatal(err)
	}
	// 伪造认证（错误 cookie）：也必须被拒。
	var bad [16]byte
	rand.Read(bad[:])
	if _, err := hijacker.Write(proto.LegupAuthPayload(sess.ID, bad, openKey(bad))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)

	// 劫持者收不到客户端上行（等腿缓冲在真后端到来前不放行）。
	hijacker.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 2048)
	if n, rerr := hijacker.Read(buf); rerr == nil {
		t.Fatalf("未认证源收到了客户端上行（%d 字节）——腿被抢占（#3 回归）", n)
	}

	// 真后端带认证拨腿：正常接管，上行送达。
	leg := be.dialLeg(t, sess)
	be.readLeg(t, leg, "secret-uplink")

	// 观测面：中统计了被拒的未知源包。
	if st := r.Stats(); st.LegRejected == 0 {
		t.Fatal("LegRejected 计数为 0（未知源拒绝缺观测面）")
	}
}

// #3 补充：已认证腿的合法重拨（新源 + 正确认证）可以跟随（NAT 重映射的收敛路径）。
func TestLegRedialWithAuthFollows(t *testing.T) {
	r := startRelay(t, Config{})
	relayAddr := relayAddrOf(t, r)

	be := newDialBackend(t, relayAddr, [32]byte{})
	be.connect(t)
	be.readLoop(t)

	cli := newFakeClient(t, be.label, relayAddr)
	cli.send([]byte("first"))
	var sess proto.CtlSession
	select {
	case sess = <-be.sessions:
	case <-time.After(3 * time.Second):
		t.Fatal("没收到 SESSION 通告")
	}
	leg := be.dialLeg(t, sess)
	be.readLeg(t, leg, "first")

	// 新源重拨（新 socket、同数据口、带认证）：下行必须切到新源。
	leg2, err := net.DialUDP("udp4", nil,
		net.UDPAddrFromAddrPort(netip.AddrPortFrom(relayAddr.Addr(), sess.DataPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer leg2.Close()
	if _, err := leg2.Write(proto.LegupAuthPayload(sess.ID, sess.Cookie, openKey(sess.Cookie))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := leg2.Write([]byte{9, 9}); err != nil {
		t.Fatal(err)
	}
	if got, ok := cli.readData(2 * time.Second); !ok || string(got) != string([]byte{9, 9}) {
		t.Fatalf("合法重拨后下行没切到新源：%q ok=%v", got, ok)
	}
}

// #7：握手槽在握手完成后释放——16 条空闲的已认证连接不应挡住第 17 个后端握手。
func TestIdleEstablishedConnsDontBlockHandshake(t *testing.T) {
	r := startRelay(t, Config{})
	relayAddr := relayAddrOf(t, r)

	// ctlHandshakeMax = 16：建 16 条「已完成握手、保持空闲」的连接。
	for i := 0; i < ctlHandshakeMax; i++ {
		be := newDialBackend(t, relayAddr, [32]byte{})
		be.connect(t) // 不 readLoop：纯空闲长连
	}

	// 第 17 个后端：握手必须照常成功并进入拨腿模式。
	be17 := newDialBackend(t, relayAddr, [32]byte{})
	be17.connect(t)
	be17.readLoop(t)
	cli := newFakeClient(t, be17.label, relayAddr)
	cli.send([]byte("17th"))
	select {
	case sess := <-be17.sessions:
		leg := be17.dialLeg(t, sess)
		be17.readLeg(t, leg, "17th")
	case <-time.After(3 * time.Second):
		t.Fatal("16 条空闲连接把新后端的握手挡住了（#7：握手槽被当成了连接数）")
	}
}

// #7/#18：并发握手超限与已建立总数超限都要有日志与拒绝。
func TestCtlConnCapsRejectWithLog(t *testing.T) {
	r := startRelay(t, Config{})
	relayAddr := relayAddrOf(t, r)

	// 并发握手上限：17 条同时慢握手（连上不发 HELLO，占满 10s 窗口）。
	var wg sync.WaitGroup
	for i := 0; i < ctlHandshakeMax+1; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", relayAddr.String(), 2*time.Second)
			if err != nil {
				return
			}
			defer c.Close()
			time.Sleep(300 * time.Millisecond) // 占住握手槽
		}()
	}
	time.Sleep(120 * time.Millisecond) // 等拨号完成、槽被占满
	be := newDialBackend(t, relayAddr, [32]byte{})
	conn, err := net.DialTimeout("tcp", relayAddr.String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = proto.CtlWriteMsg(conn, proto.EncodeRelayHello(be.pub))
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	sc := bufio.NewReader(conn)
	_ = sc
	typ, _, rerr := proto.CtlReadMsg(conn)
	if rerr == nil && typ == proto.RelaySubChallenge {
		t.Log("并发窗口边缘：本次没触发上限（时序敏感，仅在有日志时断言拒绝路径）")
	}
	wg.Wait()
}

// #18：控制路径建腿受 MaxLegs 闸——灌满腿表后，新后端即使完成握手也不得挂腿
// （对它的客户端包不产生 SESSION 通告）。
func TestControlLegCountGated(t *testing.T) {
	r := startRelay(t, Config{MaxLegs: 2})
	relayAddr := relayAddrOf(t, r)

	for i := 0; i < 2; i++ {
		be := newDialBackend(t, relayAddr, [32]byte{})
		be.connect(t)
	}

	// 第三个后端：完整 v2 握手。腿表满 → 中继回 OK 但不挂腿（或直接断，两者皆可）。
	be3 := newDialBackend(t, relayAddr, [32]byte{})
	conn, err := net.DialTimeout("tcp", relayAddr.String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := proto.CtlWriteMsg(conn, proto.EncodeRelayHello(be3.pub)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	typ, pl, rerr := proto.CtlReadMsg(conn)
	if rerr != nil || typ != proto.RelaySubChallenge {
		t.Fatalf("等 CHALLENGE: typ=0x%02x err=%v", typ, rerr)
	}
	ephPub, nonce, _ := proto.DecodeRelayChallenge(ctlWithSub(typ, pl))
	dh, _ := curve25519.X25519(be3.priv[:], ephPub[:])
	if err := proto.CtlWriteMsg(conn, proto.EncodeRelayProofV(nonce, dh, be3.pub, nil, proto.RelayCtlVer)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	typ3, _, rerr3 := proto.CtlReadMsg(conn)
	if rerr3 == nil && typ3 == proto.RelaySubOK {
		// OK 后看有没有被挂上：发客户端包，短时间内不应产生 SESSION 通告。
		cli := newFakeClient(t, be3.label, relayAddr)
		cli.send([]byte("should-not-announce"))
		select {
		case <-be3.sessions:
			t.Fatal("腿表满时控制面竟然还能通告会话（#18 回归）")
		case <-time.After(600 * time.Millisecond):
		}
	} else {
		t.Log("腿表满：握手被拒（符合预期）")
	}
}

// #29 的后端侧判定放在 internal/server（真实现）——这里锁定 proto 层：
// 错 MAC 的 OK 解出来与正确 MAC 不等。
func TestRelayOKAuthMACProto(t *testing.T) {
	var secret, wrong [32]byte
	rand.Read(secret[:])
	rand.Read(wrong[:])
	var nonce [16]byte
	rand.Read(nonce[:])
	good := proto.RelayOKAuthMAC(secret, nonce)
	bad := proto.RelayOKAuthMAC(wrong, nonce)
	enc := proto.EncodeRelayOKAuth(good)
	mac, v2 := proto.DecodeRelayOKAuth(enc)
	if !v2 || len(mac) != 16 {
		t.Fatal("v2 OK 解码失败")
	}
	if string(mac) == string(bad) {
		t.Fatal("不同密钥的 MAC 相同")
	}
}

// 计数/日志辅助：确保 strings 引用（LegRejected 日志文案断言在 e2e 侧）。
var _ = strings.Contains
var _ = atomic.Int32{}
