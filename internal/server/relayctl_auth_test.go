package server

// relayctl_auth_test.go — 控制面**中继身份**的对抗性回归（review 复审 #29 降级窗口）：
// token 模式下，未提供 OK-MAC 的控制通道（裸 1B = v1 形状）不得拥有拨腿指挥权——
// 此前它会拿到 SESSION 的指挥权，能应答 TCP 的一方只要**省略 MAC** 就能让后端往
// 中继主机任意端口拨腿（端口注入 + 伪造会话）。合法旧中继不发 SESSION，因此
// 「未认证通道一律拒绝 SESSION」不会破坏兼容矩阵里的 v1 中继回退。

import (
	"context"
	"crypto/rand"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
	"github.com/zhaoyswd/homeway/pkg/servercore"
	"golang.org/x/crypto/curve25519"
)

// fakeControlRelay：只做控制握手（不校验 PROOF），按 withMAC 决定 OK 是否带认证材料，
// 然后通告一个 SESSION 指向 dataPort。返回被拨腿次数（= 数据口收到的包数）。
func fakeControlRelay(t *testing.T, secret [32]byte, withMAC bool) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dataLn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer dataLn.Close()
	dataPort := uint16(dataLn.LocalAddr().(*net.UDPAddr).Port)
	relayAddr := netip.MustParseAddrPort(ln.Addr().String())

	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	pub := wgPub(priv)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sbind := &servercore.ServerBind{Logf: func(string, ...any) {}}
	if _, _, err := sbind.Open(0); err != nil {
		t.Fatal(err)
	}
	defer sbind.Close()

	served := make(chan struct{})
	go func() {
		defer close(served)
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if typ, _, rerr := proto.CtlReadMsg(c); rerr != nil || typ != proto.RelaySubHello {
			return
		}
		var ephPriv, ephPub [32]byte
		_, _ = rand.Read(ephPriv[:])
		curve25519.ScalarBaseMult(&ephPub, &ephPriv)
		var nonce [16]byte
		_, _ = rand.Read(nonce[:])
		if werr := proto.CtlWriteMsg(c, proto.EncodeRelayChallenge(ephPub, nonce)); werr != nil {
			return
		}
		if typ, _, rerr := proto.CtlReadMsg(c); rerr != nil || typ != proto.RelaySubProof {
			return
		}
		ok := proto.EncodeRelayOK()
		if withMAC {
			ok = proto.EncodeRelayOKAuth(proto.RelayOKAuthMAC(secret, nonce))
		}
		if werr := proto.CtlWriteMsg(c, ok); werr != nil {
			return
		}
		// SESSION 通告（v1 形状：11B 无 cookie）——未认证通道下必须被后端拒绝。
		_ = proto.CtlWriteMsg(c, proto.EncodeCtlSession(proto.CtlSession{ID: 1, DataPort: dataPort}))
		time.Sleep(700 * time.Millisecond) // 留给后端决定是否拨腿
	}()

	startControlClient(ctx, sbind, relayAddr, priv, pub, secret, func(string, ...any) {})

	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("假中继的控制握手没走完")
	}
	// 数数据口收到的包：合法拨腿会先发一个 LEGUP 标记。
	n := 0
	buf := make([]byte, 256)
	_ = dataLn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	for {
		if _, _, rerr := dataLn.ReadFromUDP(buf); rerr != nil {
			break
		}
		n++
	}
	return n
}

func TestControlUntrustedRelayCannotSteerLegs(t *testing.T) {
	secret := [32]byte{0x5a}
	if got := fakeControlRelay(t, secret, false); got != 0 {
		t.Fatalf("未认证（无 OK-MAC）的控制通道指挥了拨腿：数据口收到 %d 个包（#29 降级回归）", got)
	}
	if got := fakeControlRelay(t, secret, true); got == 0 {
		t.Fatal("已认证（OK-MAC 通过）的控制通道没能拨腿——正向路径被误伤")
	}
}
