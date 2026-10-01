package relay

// v2only_test.go — FIX-89（v2-only 单一版本矩阵）的判据：
//  1. 版本门：UDP 注册腿与控制面的 PROOF 版本不符（老形态 1 / 未来版本）一律被拒；
//  2. 显式开放开关：构造期拒绝「Secret 为空且未显式 Open」（静默开放）与矛盾配置。

import (
	"crypto/rand"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
	"golang.org/x/crypto/curve25519"
)

// TestRegisterRejectsWrongProtoVer：UDP 注册腿的协议版本门。
func TestRegisterRejectsWrongProtoVer(t *testing.T) {
	r := startRelay(t, Config{})
	relayAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), r.LocalAddr().Port())

	old := newFakeBackend(t, relayAddr)
	if old.registerWithVer(1) {
		t.Fatal("协议版本 1（老后端形态）的 PROOF 竟然注册成功——版本门失效")
	}
	future := newFakeBackend(t, relayAddr)
	if future.registerWithVer(proto.RelayCtlVer + 1) {
		t.Fatal("未来版本的 PROOF 竟然注册成功——版本门失效")
	}
	good := newFakeBackend(t, relayAddr)
	if !good.registerWithVer(proto.RelayCtlVer) {
		t.Fatal("版本正确的 PROOF 注册失败——正向路径被误伤")
	}
}

// handshakeWithVer：手写控制握手（不 t.Fatal——预期失败用例用），返回是否拿到 OK。
func handshakeWithVer(t *testing.T, addr netip.AddrPort, priv [32]byte, pub [32]byte, ver byte) bool {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr.String(), 3*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if werr := proto.CtlWriteMsg(conn, proto.EncodeRelayHello(pub)); werr != nil {
		return false
	}
	typ, payload, rerr := proto.CtlReadMsg(conn)
	if rerr != nil || typ != proto.RelaySubChallenge {
		return false
	}
	ephPub, nonce, cerr := proto.DecodeRelayChallenge(ctlWithSub(typ, payload))
	if cerr != nil {
		return false
	}
	dh, derr := curve25519.X25519(priv[:], ephPub[:])
	if derr != nil {
		return false
	}
	if werr := proto.CtlWriteMsg(conn, proto.EncodeRelayProof(nonce, dh, pub, nil, ver)); werr != nil {
		return false
	}
	typ, _, rerr = proto.CtlReadMsg(conn)
	return rerr == nil && typ == proto.RelaySubOK
}

// TestControlHandshakeRejectsWrongProtoVer：控制面的协议版本门。
func TestControlHandshakeRejectsWrongProtoVer(t *testing.T) {
	r := startRelay(t, Config{})
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), r.LocalAddr().Port())

	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	pubB, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	var pub [32]byte
	copy(pub[:], pubB)

	if handshakeWithVer(t, addr, priv, pub, 1) {
		t.Fatal("协议版本 1 的控制面 PROOF 竟然拿到 OK——版本门失效")
	}
	if handshakeWithVer(t, addr, priv, pub, proto.RelayCtlVer+1) {
		t.Fatal("未来版本的控制面 PROOF 竟然拿到 OK——版本门失效")
	}
	if !handshakeWithVer(t, addr, priv, pub, proto.RelayCtlVer) {
		t.Fatal("版本正确的控制面握手失败——正向路径被误伤")
	}
}

// TestNewRejectsImplicitOpen：拒绝「Secret 为空且未显式 Open」的静默开放。
func TestNewRejectsImplicitOpen(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Secret 为空且未显式 Open 竟然通过构造——静默开放路径未堵")
		}
	}()
	New(Config{Addr: "127.0.0.1:0"})
}

// TestNewRejectsOpenWithSecret：拒绝「既给密钥又喊开放」的矛盾配置。
func TestNewRejectsOpenWithSecret(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Open 与 Secret 同时设置竟然通过构造——矛盾配置未拒")
		}
	}()
	New(Config{Addr: "127.0.0.1:0", Open: true, Secret: [32]byte{1}})
}
