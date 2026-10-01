package server

// relayctl_auth_test.go — 控制面**中继身份**的对抗性回归（review 复审 #29 降级窗口，
// FIX-89 v2-only 形态）：
//  1. 形状不符的 OK（裸 1B = 老中继形态）不再被容纳——握手直接判失败，拿不到拨腿指挥权；
//  2. token 模式下 OK-MAC 算错（对端不持有本 token 的密钥）同样拒握手；
//  3. 正向路径（v2 OK-MAC + 27B 带 cookie SESSION）必须能拨腿。

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

// fakeControlRelay：只做控制握手（不校验 PROOF），按 okShape 决定 OK 形态
// （"v2" = 带正确 MAC；"badmac" = 带错误 MAC；"v1" = 裸 1B 老形状），
// 然后通告一个 SESSION 指向 dataPort。返回被拨腿次数（= 数据口收到的包数）。
func fakeControlRelay(t *testing.T, secret [32]byte, okShape string) int {
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
		var ok []byte
		switch okShape {
		case "v2":
			ok = proto.EncodeRelayOKAuth(proto.RelayOKAuthMAC(secret, nonce))
		case "badmac":
			wrong := [32]byte{0xEE}
			ok = proto.EncodeRelayOKAuth(proto.RelayOKAuthMAC(wrong, nonce))
		default: // "v1"：裸 1B 老形状
			ok = proto.EncodeRelayOK()
		}
		if werr := proto.CtlWriteMsg(c, ok); werr != nil {
			return
		}
		// SESSION 通告（v2 形状：27B 带 cookie）。形状不符的情形下后端已断开连接，
		// 这里的通告落空，不应产生任何拨腿。
		var cookie [16]byte
		_, _ = rand.Read(cookie[:])
		_ = proto.CtlWriteMsg(c, proto.EncodeCtlSession(
			proto.CtlSession{ID: 1, DataPort: dataPort, Cookie: cookie}))
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
	// 老形状（裸 1B OK）：v2-only 下握手直接失败，不得拨腿。
	if got := fakeControlRelay(t, secret, "v1"); got != 0 {
		t.Fatalf("形状不符（裸 1B OK）的控制通道指挥了拨腿：数据口收到 %d 个包（#29 降级回归）", got)
	}
	// MAC 算错（对端不持有本 token 密钥）：同样拒握手。
	if got := fakeControlRelay(t, secret, "badmac"); got != 0 {
		t.Fatalf("OK-MAC 错误的控制通道指挥了拨腿：数据口收到 %d 个包（#29 回归）", got)
	}
	// 正向路径（v2 OK-MAC + 27B cookie SESSION）必须能拨腿。
	if got := fakeControlRelay(t, secret, "v2"); got == 0 {
		t.Fatal("已认证（OK-MAC 通过）的控制通道没能拨腿——正向路径被误伤")
	}
}
