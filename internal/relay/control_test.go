package relay

// control_test.go — relay-backend-dial 的中继侧集成测试：
// 真 relay（UDP + TCP 控制面）+ 迷你控制客户端（HELLO/PROOF/拨腿）+ fakeClient。
//
// 覆盖：拨腿会话双向流、等腿窗口缓冲保序、RELEASE（空闲回收）、
// 兼容路径（无控制连接 = 现状行为，由既有 TestForwardBothWays 锁定）。

import (
	"bufio"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
	"golang.org/x/crypto/curve25519"
)

// dialBackend：接控制面并按通告拨腿的假后端（不复用 internal/server 的实现——层次隔离，
// 这里的目标是验证「中继侧行为」，后端逻辑用最小复刻）。
type dialBackend struct {
	label    [8]byte
	pub      [32]byte
	priv     [32]byte
	relay    netip.AddrPort
	secret   [32]byte
	conn     net.Conn
	sessions chan proto.CtlSession
	releases chan uint64
}

func newDialBackend(t *testing.T, relayAddr netip.AddrPort, secret [32]byte) *dialBackend {
	t.Helper()
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	b := &dialBackend{
		priv: priv, relay: relayAddr, secret: secret,
		sessions: make(chan proto.CtlSession, 8), releases: make(chan uint64, 8),
	}
	copy(b.pub[:], pub)
	b.label = proto.RelayID(b.pub)
	return b
}

// connect：TCP 控制面握手（HELLO → CHALLENGE → PROOF → OK）。
func (b *dialBackend) connect(t *testing.T) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", b.relay.String(), 3*time.Second)
	if err != nil {
		t.Fatalf("拨控制面: %v", err)
	}
	b.conn = conn
	t.Cleanup(func() { conn.Close() })
	if err := proto.CtlWriteMsg(conn, proto.EncodeRelayHello(b.pub)); err != nil {
		t.Fatalf("发 HELLO: %v", err)
	}
	typ, payload, err := proto.CtlReadMsg(conn)
	if err != nil || typ != proto.RelaySubChallenge {
		t.Fatalf("等 CHALLENGE: typ=%d err=%v", typ, err)
	}
	ephPub, nonce, cerr := proto.DecodeRelayChallenge(ctlWithSub(typ, payload))
	if cerr != nil {
		t.Fatalf("解析 CHALLENGE: %v", cerr)
	}
	dh, derr := curve25519.X25519(b.priv[:], ephPub[:])
	if derr != nil {
		t.Fatalf("算 DH: %v", derr)
	}
	var macPSK []byte
	if b.secret != ([32]byte{}) {
		macPSK = proto.RelayAuthMAC(b.secret, nonce, b.pub)
	}
	if err := proto.CtlWriteMsg(conn, proto.EncodeRelayProof(nonce, dh, b.pub, macPSK)); err != nil {
		t.Fatalf("发 PROOF: %v", err)
	}
	typ, _, err = proto.CtlReadMsg(conn)
	if err != nil || typ != proto.RelaySubOK {
		t.Fatalf("等 OK: typ=0x%02x err=%v", typ, err)
	}
}

// readLoop：消费控制面消息（SESSION/RELEASE）。dialLeg 按通告即时拨。
func (b *dialBackend) readLoop(t *testing.T) {
	t.Helper()
	go func() {
		sc := bufio.NewReader(b.conn)
		_ = sc
		for {
			typ, payload, err := proto.CtlReadMsg(b.conn)
			if err != nil {
				return
			}
			switch typ {
			case proto.RelayCtlSession:
				sess, serr := proto.DecodeCtlSession(ctlWithSub(typ, payload))
				if serr == nil {
					select {
					case b.sessions <- sess:
					default:
					}
				}
			case proto.RelayCtlRelease:
				id, rerr := proto.DecodeCtlRelease(ctlWithSub(typ, payload))
				if rerr == nil {
					select {
					case b.releases <- id:
					default:
					}
				}
			}
		}
	}()
}

// dialLeg：向通告的数据口拨 connected UDP 腿 + LEGUP。
func (b *dialBackend) dialLeg(t *testing.T, sess proto.CtlSession) *net.UDPConn {
	t.Helper()
	remote := netip.AddrPortFrom(b.relay.Addr(), sess.DataPort)
	leg, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(remote))
	if err != nil {
		t.Fatalf("拨腿: %v", err)
	}
	t.Cleanup(func() { leg.Close() })
	if _, err := leg.Write([]byte("LEGUP")); err != nil {
		t.Fatalf("发 LEGUP: %v", err)
	}
	return leg
}

// readLeg：从腿上读一条数据帧并比对载荷（0xBB 帧剥壳）。
func (b *dialBackend) readLeg(t *testing.T, leg *net.UDPConn, want string) string {
	t.Helper()
	buf := make([]byte, 2048)
	_ = leg.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := leg.Read(buf)
	if err != nil {
		t.Fatalf("腿读（want %q）：%v", want, err)
	}
	typ, payload, derr := proto.DecodeFrame(buf[:n])
	if derr != nil || typ != proto.FrameTypeData || string(payload) != want {
		t.Fatalf("腿上数据：want %q got typ=%d payload=%q err=%v", want, typ, payload, derr)
	}
	return string(payload)
}

// ---------- 用例 ----------

// 拨腿模式双向流：客户端 → 中继 → （通告+拨腿）→ 后端腿；回程同腿回客户端。
func TestControlDialSession(t *testing.T) {
	r := startRelay(t, Config{})
	relayAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), r.LocalAddr().Port())
	be := newDialBackend(t, relayAddr, [32]byte{})
	be.connect(t)
	be.readLoop(t)

	cli := newFakeClient(t, be.label, relayAddr)
	t0 := time.Now()
	cli.send([]byte("ping-dial"))

	select {
	case sess := <-be.sessions:
		leg := be.dialLeg(t, sess)
		// 等腿窗口的缓冲应在拨腿后放行（首包不丢；腿上是 0xBB 数据帧，剥帧比对）
		be.readLeg(t, leg, "ping-dial")
		t.Logf("通告+拨腿+首包送达 = %v（会话 #%d 数据口 %d）", time.Since(t0), sess.ID, sess.DataPort)
		// 回程（裸 WG 语义）→ 客户端
		if _, err := leg.Write([]byte{9, 8, 7}); err != nil {
			t.Fatal(err)
		}
		got, ok := cli.readData(2 * time.Second)
		if !ok || string(got) != string([]byte{9, 8, 7}) {
			t.Fatalf("客户端没收到回程：%q ok=%v", got, ok)
		}
		// 第二包起稳态直通
		cli.send([]byte("second"))
		be.readLeg(t, leg, "second")
	case <-time.After(3 * time.Second):
		t.Fatal("没收到 SESSION 通告（拨腿模式未启用？）")
	}
}

// 等腿窗口缓冲保序：客户端连发 3 包，后端延迟拨腿 → 3 包按序全到。
func TestControlDialPendingOrder(t *testing.T) {
	r := startRelay(t, Config{})
	relayAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), r.LocalAddr().Port())
	be := newDialBackend(t, relayAddr, [32]byte{})
	be.connect(t)
	be.readLoop(t)

	cli := newFakeClient(t, be.label, relayAddr)
	cli.send([]byte("p1"))
	cli.send([]byte("p2"))
	cli.send([]byte("p3"))

	select {
	case sess := <-be.sessions:
		time.Sleep(150 * time.Millisecond) // 故意晚拨：三包都应躺在缓冲里
		leg := be.dialLeg(t, sess)
		for _, want := range []string{"p1", "p2", "p3"} {
			be.readLeg(t, leg, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("没收到 SESSION 通告")
	}
}

// 空闲回收 → RELEASE 通告。
func TestControlDialReleaseOnIdle(t *testing.T) {
	r := startRelay(t, Config{IdleTimeout: 300 * time.Millisecond})
	relayAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), r.LocalAddr().Port())
	be := newDialBackend(t, relayAddr, [32]byte{})
	be.connect(t)
	be.readLoop(t)

	cli := newFakeClient(t, be.label, relayAddr)
	cli.send([]byte("bye"))
	select {
	case sess := <-be.sessions:
		leg := be.dialLeg(t, sess)
		buf := make([]byte, 128)
		_ = leg.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = leg.Read(buf) // 收掉缓冲的包，让 idle 计时从静默开始
		select {
		case id := <-be.releases:
			if id != sess.ID {
				t.Fatalf("RELEASE 的会话号不符：%d want %d", id, sess.ID)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("空闲回收后没收到 RELEASE 通告")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("没收到 SESSION 通告")
	}
}

// token 模式的控制面鉴权：拿错 secret 的后端被拒（拿不到 OK）。
func TestControlAuthRejected(t *testing.T) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	r := startRelay(t, Config{Secret: secret})
	relayAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), r.LocalAddr().Port())

	var wrong [32]byte
	wrong[0] = 1
	be := newDialBackend(t, relayAddr, wrong)
	conn, err := net.DialTimeout("tcp", relayAddr.String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := proto.CtlWriteMsg(conn, proto.EncodeRelayHello(be.pub)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	typ, payload, rerr := proto.CtlReadMsg(conn)
	if rerr != nil || typ != proto.RelaySubChallenge {
		t.Fatalf("等 CHALLENGE: typ=%d err=%v", typ, rerr)
	}
	ephPub, nonce, _ := proto.DecodeRelayChallenge(ctlWithSub(typ, payload))
	dh, _ := curve25519.X25519(be.priv[:], ephPub[:])
	// 用错误 secret 的 PSK MAC —— 中继必须拒绝（连接被关，读不到 OK）
	bad := proto.RelayAuthMAC(wrong, nonce, be.pub)
	if err := proto.CtlWriteMsg(conn, proto.EncodeRelayProof(nonce, dh, be.pub, bad)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	typ, _, rerr = proto.CtlReadMsg(conn)
	if rerr == nil && typ == proto.RelaySubOK {
		t.Fatal("错误 secret 竟然拿到了 OK —— 控制面鉴权失效")
	}
}

var _ = fmt.Sprintf
var _ = context.Background

// ctlWithSub：CtlReadMsg 的 payload 不含子类型字节，proto 编解码按整条解。
func ctlWithSub(typ byte, payload []byte) []byte {
	out := make([]byte, 0, 1+len(payload))
	out = append(out, typ)
	out = append(out, payload...)
	return out
}

// 控制空窗期建立的 fallback 会话（sid==0，走 lg.addr 旧路径）在控制上线后被
// **提升**为拨腿会话（review D1）：重放通告必须是全新 sid（!=0，不互相顶掉），
// 后端拨腿后数据无缝继续。同时锁定「不重放 id=0」（C1 的原始断言）。
func TestControlReplayPromotesFallbackAssocs(t *testing.T) {
	r := startRelay(t, Config{})
	relayAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), r.LocalAddr().Port())

	// 后端：UDP 注册腿（控制空窗形态）。
	be := newFakeBackend(t, relayAddr)
	if !be.register() {
		t.Fatal("UDP 注册失败")
	}
	cli := newFakeClient(t, be.label, relayAddr)
	cli.send([]byte("fallback-flow"))
	payload, from, ok := be.readData(2 * time.Second)
	if !ok || string(payload) != "fallback-flow" {
		t.Fatalf("fallback 会话不通：payload=%q ok=%v", payload, ok)
	}
	if _, err := be.pc.WriteToUDPAddrPort([]byte("R-fb"), from); err != nil {
		t.Fatal(err)
	}
	if got, ok := cli.readData(2 * time.Second); !ok || string(got) != "R-fb" {
		t.Fatalf("fallback 回程失败：%q ok=%v", got, ok)
	}

	// 同一身份再挂控制连接（模拟控制恢复/重连）。
	conn, err := net.DialTimeout("tcp", relayAddr.String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := proto.CtlWriteMsg(conn, proto.EncodeRelayHello(be.pub)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	typ, pl, rerr := proto.CtlReadMsg(conn)
	if rerr != nil || typ != proto.RelaySubChallenge {
		t.Fatalf("等 CHALLENGE: %v", rerr)
	}
	ephPub, nonce, _ := proto.DecodeRelayChallenge(ctlWithSub(typ, pl))
	dh, _ := curve25519.X25519(be.priv[:], ephPub[:])
	if err := proto.CtlWriteMsg(conn, proto.EncodeRelayProof(nonce, dh, be.pub, nil)); err != nil {
		t.Fatal(err)
	}
	typ, _, rerr = proto.CtlReadMsg(conn)
	if rerr != nil || typ != proto.RelaySubOK {
		t.Fatalf("等 OK: typ=0x%02x err=%v", typ, rerr)
	}

	// 重放：fallback 会话必须被提升——通告一条 sid!=0 的 SESSION（不是 0）。
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var sess proto.CtlSession
	gotPromote := false
	for !gotPromote {
		typ, pl, rerr := proto.CtlReadMsg(conn)
		if rerr != nil {
			t.Fatalf("没等到提升通告：%v", rerr)
		}
		if typ != proto.RelayCtlSession {
			continue
		}
		s, serr := proto.DecodeCtlSession(ctlWithSub(typ, pl))
		if serr != nil {
			continue
		}
		if s.ID == 0 {
			t.Fatal("重放通告了 id=0（C1 回归：会互相顶掉且永无 RELEASE）")
		}
		sess = s
		gotPromote = true
	}

	// 拨腿（后端收到提升通告后的动作）。
	remote := netip.AddrPortFrom(relayAddr.Addr(), sess.DataPort)
	leg, derr := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(remote))
	if derr != nil {
		t.Fatalf("拨腿: %v", derr)
	}
	defer leg.Close()
	if _, err := leg.Write([]byte("LEGUP")); err != nil {
		t.Fatal(err)
	}

	// 提升后会话无缝继续：客户端发包 → 等腿缓冲放行 → 腿上送达。
	cli.send([]byte("promoted-flow"))
	buf := make([]byte, 2048)
	_ = leg.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, lerr := leg.Read(buf)
	if lerr != nil {
		t.Fatalf("提升后腿上没收到数据：%v", lerr)
	}
	if typ, payload, derr := proto.DecodeFrame(buf[:n]); derr != nil || typ != proto.FrameTypeData || string(payload) != "promoted-flow" {
		t.Fatalf("腿上数据：typ=%d payload=%q err=%v", typ, payload, derr)
	}
	// 回程照走腿 → 客户端。
	if _, err := leg.Write([]byte{5, 5}); err != nil {
		t.Fatal(err)
	}
	if got, ok := cli.readData(2 * time.Second); !ok || string(got) != string([]byte{5, 5}) {
		t.Fatalf("提升后回程失败：%q ok=%v", got, ok)
	}
}
