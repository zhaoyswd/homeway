package server

// relayctl_test.go — relay-backend-dial 的端到端（真 relay + 真 ServerBind +
// 真 startControlClient + 假客户端）：SESSION 通告 → 自动拨腿 → 腿收发 →
// Send 按端点路由 → 回程到客户端。这是「生产实现」的全链路验证
//（中继侧行为由 internal/relay/control_test.go 锁定）。

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

func TestControlDialEndToEnd(t *testing.T) {
	// ---- 中继（UDP + TCP 控制面同号）----
	rl := relay.New(relay.Config{Addr: "127.0.0.1:0", IdleTimeout: 5 * time.Second,
		Logf: func(f string, a ...any) { t.Logf("[relay] "+f, a...) }})
	rctx, rcancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = rl.Run(rctx) }()
	t.Cleanup(func() { rcancel(); <-done })
	for i := 0; i < 100 && !rl.LocalAddr().IsValid(); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if !rl.LocalAddr().IsValid() {
		t.Fatal("中继没起来")
	}
	relayAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), rl.LocalAddr().Port())

	// ---- 出口：真 ServerBind（不注册 UDP 腿——纯控制面 + 拨腿，验证目标本体）----
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	pub := wgPub(priv)
	label := proto.RelayID(pub)
	sbind := &servercore.ServerBind{
		Logf:  func(f string, a ...any) { t.Logf("[backend] "+f, a...) },
		Table: servercore.NewDeviceTable(nil, [][32]byte{{1}}, servercore.DeviceConfig{MaxDevices: 8}),
	}
	fns, port, err := sbind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer sbind.Close()
	if len(fns) < 2 {
		t.Fatalf("Open 应返回主接收 + 腿聚合两个 ReceiveFunc（got %d）", len(fns))
	}
	t.Logf("出口 WG socket 端口 %d（控制面纯拨腿模式）", port)

	// device 侧收包：两个 ReceiveFunc 都消费，数据进同一通道。
	type got struct {
		payload []byte
		from    netip.AddrPort
	}
	recv := make(chan got, 16)
	consume := func(fn conn.ReceiveFunc) {
		go func() {
			packets := make([][]byte, 1)
			packets[0] = make([]byte, 65535)
			sizes := make([]int, 1)
			eps := make([]conn.Endpoint, 1)
			for {
				n, err := fn(packets, sizes, eps)
				if err != nil {
					return
				}
				if n == 0 {
					continue
				}
				from, _ := netip.ParseAddrPort(eps[0].DstToString())
				recv <- got{payload: append([]byte(nil), packets[0][:sizes[0]]...), from: from}
			}
		}()
	}
	consume(fns[0])
	consume(fns[1])

	// ---- 控制面客户端（生产实现）----
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startControlClient(ctx, sbind, relayAddr, priv, pub, [32]byte{}, func(f string, a ...any) { t.Logf("[ctl] "+f, a...) })

	// ---- 假客户端 ----
	cli, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	sendFromClient := func(payload []byte) {
		_, _ = cli.WriteToUDPAddrPort(proto.EncodeTagged(label, proto.FrameTypeData, payload), relayAddr)
	}

	// ① 客户端首包 → 通告 → 自动拨腿 → 腿上送达（等腿缓冲不丢首包）。
	// 重试发送：控制面握手与首包之间存在固有竞态窗口（中继侧对「无可达路径」
	// 的首包是丢弃的），真实客户端靠 WG 握手重传覆盖——假客户端手动重发同款。
	var firstFrom netip.AddrPort
	for retry := 0; ; retry++ {
		sendFromClient([]byte("wg-init"))
		select {
		case g := <-recv:
			if string(g.payload) != "wg-init" {
				continue
			}
			firstFrom = g.from
			t.Logf("[device] 首包经腿送达（来自 %v，第 %d 次尝试）", g.from, retry+1)
			goto firstOK
		case <-time.After(700 * time.Millisecond):
			if retry >= 8 {
				t.Fatal("控制面拨腿路径上没收到客户端首包（通告/拨腿/腿接收任一环断了）")
			}
		}
	}
firstOK:

	// ② 回程：SendTo 与 WG device 的 Send 同款路由（端点命中腿表 → 腿 socket）→
	// 中继 → 客户端。**不能用 SendRawTo**：主 socket 的源未过腿认证（#3），中继
	// 会当未知源拒绝——旧测试能过恰是因为旧实现「任意源漂移跟随」的漏洞。
	if err := sbind.SendTo(firstFrom, []byte("wg-response")); err != nil {
		t.Fatal(err)
	}
	gotReply := false
	buf := make([]byte, 4096)
	_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	for !gotReply {
		n, _, rerr := cli.ReadFromUDPAddrPort(buf)
		if rerr != nil {
			t.Fatalf("客户端没等到回程：%v", rerr)
		}
		typ, payload, ferr := proto.DecodeFrame(buf[:n])
		if ferr != nil || typ != proto.FrameTypeData {
			continue // hint 等其它帧
		}
		if string(payload) == "wg-response" {
			gotReply = true
		}
	}

	// ③ 稳态：第二条包应复用同一条腿（同 from），不重建会话。
	sendFromClient([]byte("wg-second"))
	deadline := time.After(3 * time.Second)
	for {
		select {
		case g := <-recv:
			if string(g.payload) != "wg-second" {
				continue // 重试轮的积压（若有）
			}
			if g.from != firstFrom {
				t.Fatalf("稳态包换了腿：%v → %v（会话被重建了？）", firstFrom, g.from)
			}
			goto steadyOK
		case <-deadline:
			t.Fatal("稳态包没到")
		}
	}
steadyOK:

	if st := rl.Stats(); st.ForwardedUp < 2 || st.ForwardedDown < 1 {
		t.Fatalf("中继计数不对：%+v", st)
	}
}

// runControlConn 的 handshakeOK 信号（backoff 重置的依据，review 2026-09-21）：
// 握手成功并进入读循环的连接断开 → true（重连从最小退避起）；
// 连握都没握上（被拒）→ false（退避继续翻倍）。
func TestRunControlConnHandshakeSignal(t *testing.T) {
	newBind := func(t *testing.T) *servercore.ServerBind {
		t.Helper()
		b := &servercore.ServerBind{
			Logf:  func(f string, a ...any) { t.Logf("[backend] "+f, a...) },
			Table: servercore.NewDeviceTable(nil, [][32]byte{{1}}, servercore.DeviceConfig{MaxDevices: 8}),
		}
		if _, _, err := b.Open(0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { b.Close() })
		return b
	}
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	pub := wgPub(priv)
	logf := func(f string, a ...any) { t.Logf("[ctl] "+f, a...) }

	// ① 开放模式中继：握手成功 → cancel ctx 断开 → handshakeOK 必须为 true。
	rl := relay.New(relay.Config{Addr: "127.0.0.1:0", Logf: logf})
	rctx, rcancel := context.WithCancel(context.Background())
	rlDone := make(chan struct{})
	go func() { defer close(rlDone); _ = rl.Run(rctx) }()
	t.Cleanup(func() { rcancel(); <-rlDone })
	for i := 0; i < 100 && !rl.LocalAddr().IsValid(); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	relayAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), rl.LocalAddr().Port())

	ctx1, cancel1 := context.WithCancel(context.Background())
	okCh := make(chan bool, 1)
	go func() {
		ok, _ := runControlConn(ctx1, newBind(t), relayAddr, priv, pub, [32]byte{}, logf)
		okCh <- ok
	}()
	time.Sleep(500 * time.Millisecond) // 等握手完成进入读循环
	cancel1()
	select {
	case ok := <-okCh:
		if !ok {
			t.Fatal("健康连接断开后 handshakeOK=false（backoff 会被历史退避拖满 30s）")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runControlConn 没退出")
	}

	// ② token 模式中继 + 错 secret：握手被拒 → handshakeOK 必须为 false。
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	rl2 := relay.New(relay.Config{Addr: "127.0.0.1:0", Secret: secret, Logf: logf})
	r2ctx, r2cancel := context.WithCancel(context.Background())
	rl2Done := make(chan struct{})
	go func() { defer close(rl2Done); _ = rl2.Run(r2ctx) }()
	t.Cleanup(func() { r2cancel(); <-rl2Done })
	for i := 0; i < 100 && !rl2.LocalAddr().IsValid(); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	relayAddr2 := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), rl2.LocalAddr().Port())

	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	ok2, err2 := runControlConn(ctx2, newBind(t), relayAddr2, priv, pub, [32]byte{}, logf)
	if ok2 {
		t.Fatal("被拒的握手 handshakeOK=true（会把 backoff 重置当成连上过）")
	}
	if err2 == nil {
		t.Fatal("被拒的握手 err 为空")
	}
}
