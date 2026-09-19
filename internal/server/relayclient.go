package server

// 出口侧的中继注册腿（wg-native-stack tasks 6.1/6.3/6.5）。
//
// 为什么要"反向注册"：出口多半在 NAT 后，中继打不进来。所以由出口**出站**把自己的注册腿
// 建到中继上，中继记下这条腿的源地址（= 出口 WG 端口在公网上的映射，也正好是给客户端的 hint）。
//
// 三条硬约束（design D4）：
//  1. **注册腿与数据面同一本地端口**：全部包都从 ServerBind 的 WG socket 发出（SendRawTo），
//     否则 NAT 映射不一致、打洞打不开；
//  2. 注册必须证明持有 peerId 私钥（X25519 挑战响应），否则中继拒绝 —— 防 peerId 劫持；
//  3. hint 是不可信线索：只用来**盲打**（开自己的 NAT 过滤），路径是否真通仍由 WG 握手决定。

import (
	"context"
	"crypto/rand"
	"net/netip"
	"sync"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
	"github.com/zhaoyswd/homeway/pkg/servercore"
	"golang.org/x/crypto/curve25519"
)

const (
	relayKeepaliveEvery = 25 * time.Second // 注册腿保活（中继侧 90s 过期 ⇒ 3 次容错）
	relayRetryEvery     = 5 * time.Second  // 注册没成功时的重试节拍
	punchBurst          = 3                // 每次 hint 的盲打包数（上限，不做放大器）
	punchGap            = 150 * time.Millisecond
	punchMinInterval    = 3 * time.Second // 同一地址的盲打节流
)

// relayClient 出口侧的中继注册腿。
type relayClient struct {
	relay netip.AddrPort
	priv  [32]byte
	pub   [32]byte
	label [8]byte // 中继路由键 = RelayID(pub)；发往中继的包都要带这层标签
	bind  *servercore.ServerBind
	logf  func(string, ...any)

	mu       sync.Mutex
	pending  [16]byte    // 未完成的挑战 nonce
	ephPriv  [32]byte    // 对应临时私钥
	challAt  time.Time
	verified bool
	lastPunch map[netip.Addr]time.Time
}

// startRelayLeg：起注册腿（非阻塞）。relayAddr 为 token/CLI 里的 relay 端点。
func startRelayLeg(ctx context.Context, bind *servercore.ServerBind, relayAddr netip.AddrPort,
	priv [32]byte, pub [32]byte, logf func(string, ...any)) {
	if !relayAddr.IsValid() {
		return
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	rc := &relayClient{
		relay: relayAddr, priv: priv, pub: pub, label: proto.RelayID(pub), bind: bind, logf: logf,
		lastPunch: map[netip.Addr]time.Time{},
	}
	// 腿上帧钩子：中继控制帧（type=3）由这里消费，不进 device。
	bind.OnLegFrame = func(typ byte, payload []byte, src netip.AddrPort) bool {
		if typ != proto.FrameTypeRelayReg {
			return false
		}
		rc.handleControl(src, payload)
		return true
	}
	// 后端也在"两端之一"：中继把客户端的观察地址作为 hint 推给我们，我们据此**盲打**。
	bind.OnHint = func(addr string) {
		ap, err := netip.ParseAddrPort(addr)
		if err != nil {
			return
		}
		rc.punch(ap)
	}
	go rc.loop(ctx)
	logf("中继：注册腿开跑（中继 %v）", relayAddr)
}

// loop：Hello → Challenge → Proof → OK，之后周期保活；断了就重来。
func (rc *relayClient) loop(ctx context.Context) {
	t := time.NewTicker(relayRetryEvery)
	defer t.Stop()
	rc.sendHello()
	lastKeepalive := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		rc.mu.Lock()
		ok := rc.verified
		rc.mu.Unlock()
		if !ok {
			rc.sendHello()
			continue
		}
		if time.Since(lastKeepalive) >= relayKeepaliveEvery {
			rc.sendKeepalive()
			lastKeepalive = time.Now()
		}
	}
}

func (rc *relayClient) sendHello() {
	// 注意：发往**中继 listener** 的包必须带 [0xAA][label] 路由标签（中继靠它认腿）；
	// 中继回给我们的则是无标签的腿上帧（本端 Bind 直接按腿帧处理）。
	if err := rc.bind.SendRawTo(rc.relay,
		proto.EncodeTagged(rc.label, proto.FrameTypeRelayReg, proto.EncodeRelayHello(rc.pub))); err != nil {
		rc.logf("中继：注册 Hello 发送失败（%v）", err)
	}
}

func (rc *relayClient) sendKeepalive() {
	_ = rc.bind.SendRawTo(rc.relay,
		proto.EncodeTagged(rc.label, proto.FrameTypeRelayReg, proto.EncodeRelayKeepalive()))
}

// handleControl：处理中继回的挑战 / 注册成功。
func (rc *relayClient) handleControl(src netip.AddrPort, payload []byte) {
	if src != rc.relay {
		return // 只认中继自己的地址（其余来源冒充中继控制帧一律忽略）
	}
	sub, _ := proto.RelaySubtype(payload)
	switch sub {
	case proto.RelaySubChallenge:
		ephPub, nonce, err := proto.DecodeRelayChallenge(payload)
		if err != nil {
			return
		}
		var priv [32]byte
		if _, err := rand.Read(priv[:]); err != nil {
			return
		}
		_ = priv
		dh, err := curve25519.X25519(rc.priv[:], ephPub[:])
		if err != nil {
			rc.logf("中继：挑战 DH 计算失败（%v）", err)
			return
		}
		proof := proto.EncodeRelayProof(nonce, dh, rc.pub)
		frame := proto.EncodeTagged(rc.label, proto.FrameTypeRelayReg, proof)
		if err := rc.bind.SendRawTo(rc.relay, frame); err != nil {
			rc.logf("中继：注册证明发送失败（%v）", err)
		}
	case proto.RelaySubAgain:
		// 中继说"腿不在了"（它重启过/腿过期）：清掉本地状态，下一拍重新走注册
		rc.mu.Lock()
		was := rc.verified
		rc.verified = false
		rc.mu.Unlock()
		if was {
			rc.logf("中继：对方要求重新注册（中继重启过或注册腿过期）—— 重新走挑战响应")
		}
		rc.sendHello()
	case proto.RelaySubOK:
		rc.mu.Lock()
		first := !rc.verified
		rc.verified = true
		rc.mu.Unlock()
		if first {
			rc.logf("中继：注册成功（腿 %v → %v）—— 客户端可经它到达本机", rc.bind.LocalPort(), rc.relay)
		}
	default:
		// 未知 subtype：忽略（前向兼容）
	}
}

// punch：对 hint 地址盲打几包 —— 自己 NAT 的过滤要先被打开，对端握手才可能进来。
// 速率上限（每地址 punchMinInterval 一次、每次 punchBurst 包）保证不被当放大器用。
func (rc *relayClient) punch(client netip.AddrPort) {
	rc.mu.Lock()
	if last, ok := rc.lastPunch[client.Addr()]; ok && time.Since(last) < punchMinInterval {
		rc.mu.Unlock()
		return
	}
	rc.lastPunch[client.Addr()] = time.Now()
	if len(rc.lastPunch) > 64 { // 防无界增长：清了重来（都是消耗品）
		rc.lastPunch = map[netip.Addr]time.Time{}
	}
	rc.mu.Unlock()

	rc.logf("中继：收到对端地址线索 %v → 盲打 %d 包（开自己 NAT 过滤；能否直连仍由 WG 握手决定）",
		client, punchBurst)
	for i := 0; i < punchBurst; i++ {
		// 盲打包用小载荷腿帧：对端解析不出数据会静默丢弃，但 NAT 过滤已被打开。
		frame := proto.EncodeFrame(proto.FrameTypeData, []byte{0, 0, 0, 0})
		if err := rc.bind.SendRawTo(client, frame); err != nil {
			return
		}
		time.Sleep(punchGap)
	}
}
