package server

// 集成：真中继 + 真 ServerBind（出口的 WG socket）+ 假客户端。
// 覆盖：注册腿（挑战响应）→ per-client 分配 → 双向转发 → hint → 盲打。

import (
	"context"
	"crypto/rand"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/internal/relay"
	"github.com/zhaoyswd/homeway/pkg/proto"
	"github.com/zhaoyswd/homeway/pkg/servercore"
	"golang.zx2c4.com/wireguard/conn"
)

func TestRelayLegEndToEnd(t *testing.T) {
	// ---- 中继 ----
	rl := relay.New(relay.Config{Addr: "127.0.0.1:0", IdleTimeout: 5 * time.Second,
		Logf: func(f string, a ...any) { t.Logf("[relay] "+f, a...) }})
	rctx, rcancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = rl.Run(rctx) }()
	t.Cleanup(func() { rcancel(); <-done })
	for i := 0; i < 100 && !rl.LocalAddr().IsValid(); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	relayAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), rl.LocalAddr().Port())

	// ---- 出口：真 ServerBind（WG socket）+ 注册腿 ----
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	pub := wgPub(priv)
	label := proto.RelayID(pub)
	sbind := &servercore.ServerBind{
		Logf:  func(f string, a ...any) { t.Logf("[backend] "+f, a...) },
		Table: servercore.NewPeerTable(nil, [][32]byte{{1}}, 8, 0),
	}
	fns, port, err := sbind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer sbind.Close()
	t.Logf("出口 WG socket 端口 %d", port)

	// device 侧收包循环：把腿帧解出来的裸 WG 放进通道
	type got struct {
		payload []byte
		from    netip.AddrPort
	}
	recv := make(chan got, 8)
	go func() {
		packets := make([][]byte, 1)
		packets[0] = make([]byte, 65535)
		sizes := make([]int, 1)
		eps := make([]conn.Endpoint, 1)
		for {
			n, err := fns[0](packets, sizes, eps)
			if err != nil {
				return
			}
			if n == 0 {
				continue
			}
			from, _ := netip.ParseAddrPort(eps[0].DstToString())
			t.Logf("[device] 收到 %dB（来自 %v）前 2 字节=% x", sizes[0], from, packets[0][:min(2, sizes[0])])
			recv <- got{payload: append([]byte(nil), packets[0][:sizes[0]]...), from: from}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startRelayLeg(ctx, sbind, relayAddr, priv, pub, func(f string, a ...any) { t.Logf("[leg] "+f, a...) })

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := rl.RegisterLeg(label); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("中继没看到注册腿（挑战响应没过？）stats=%+v", rl.Stats())
		}
		time.Sleep(50 * time.Millisecond)
	}

	// ---- 假客户端 ----
	cli, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	sendFromClient := func(typ byte, payload []byte) {
		_, _ = cli.WriteToUDPAddrPort(proto.EncodeTagged(label, typ, payload), relayAddr)
	}
	sendFromClient(proto.FrameTypeData, []byte("wg-handshake-1"))

	// 出口侧应当收到裸 WG（腿帧已被 Bind 剥掉）
	select {
	case g := <-recv:
		if string(g.payload) != "wg-handshake-1" {
			t.Fatalf("出口收到的载荷不对：%q", g.payload)
		}
		// 回程：device 会往"看到这条腿帧的来源地址"发裸 WG → 中继包成数据帧给客户端
		if err := sbind.SendRawTo(g.from, []byte("wg-response-1")); err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("出口没收到客户端的腿帧")
	}

	// 客户端读回程（跳过 hint），并应当同时看到后端盲打的包
	var gotReply, gotPunch bool
	buf := make([]byte, 4096)
	_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		n, _, err := cli.ReadFromUDPAddrPort(buf)
		if err != nil {
			break
		}
		typ, payload, ferr := proto.DecodeFrame(buf[:n])
		if ferr != nil {
			continue
		}
		switch {
		case typ == proto.FrameTypeData && string(payload) == "wg-response-1":
			gotReply = true
		case typ == proto.FrameTypeData && len(payload) == 4:
			gotPunch = true
		}
		if gotReply && gotPunch {
			break
		}
	}
	if !gotReply {
		t.Fatal("客户端没收到回程数据帧")
	}
	if !gotPunch {
		t.Fatal("客户端没收到后端盲打包（hint → punch 没生效）")
	}
	if st := rl.Stats(); st.ForwardedUp == 0 || st.ForwardedDown == 0 {
		t.Fatalf("中继计数不对：%+v", st)
	}
}
