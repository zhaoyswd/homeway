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
	// secret：中继 token（rl1…）里的鉴权密钥；非零 = token 模式（中继会校验 PSK MAC）。
	secret [32]byte
	bind   *servercore.ServerBind
	logf   func(string, ...any)

	mu        sync.Mutex
	pending   [16]byte // 未完成的挑战 nonce
	ephPriv   [32]byte // 对应临时私钥
	challAt   time.Time
	verified  bool
	lastPunch map[netip.Addr]time.Time
}

// startRelayLeg：起注册腿（非阻塞）。relayAddr 为 token/CLI 里的 relay 端点。
func startRelayLeg(ctx context.Context, bind *servercore.ServerBind, relayAddr netip.AddrPort,
	priv [32]byte, pub [32]byte, relaySecret [32]byte, logf func(string, ...any)) {
	if !relayAddr.IsValid() {
		return
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	rc := &relayClient{
		relay: relayAddr, priv: priv, pub: pub, label: proto.RelayID(pub), bind: bind, logf: logf,
		secret: relaySecret, lastPunch: map[netip.Addr]time.Time{},
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
	// 来源必须校验（#23）：hint 的源是中继的 per-client 分配 socket（端口动态、IP 恒为
	// 中继地址）——只比 IP。未知源的 hint 只记日志，绝不盲打（hint 是「向任意地址发包」
	// 的触发器，不能被第三方当放大器注入）。
	bind.OnHint = func(addr string, src netip.AddrPort) {
		if src.Addr().Unmap() != rc.relay.Addr().Unmap() {
			rc.logf("中继：忽略来自未知源 %v 的地址线索（应为中继 %v）", src, rc.relay.Addr())
			return
		}
		ap, err := netip.ParseAddrPort(addr)
		if err != nil {
			return
		}
		// 盲打移出接收 goroutine（#23）：punch 内有 3×150ms 的节奏 sleep，同步跑会把
		// 腿/主 socket 的 ReceiveFunc 卡住几百毫秒（突发 hint 时 transit 全排队）。
		go rc.punch(ap)
	}
	go rc.loop(ctx)
	mode := "开放模式（无 token）"
	if rc.secret != ([32]byte{}) {
		mode = "token 模式（rl1 凭据）"
	}
	logf("中继：注册腿开跑（中继 %v，%s）", relayAddr, mode)
}

// loop：Hello → Challenge → Proof → OK，之后周期保活；断了就重来。
func (rc *relayClient) loop(ctx context.Context) {
	t := time.NewTicker(relayRetryEvery)
	defer t.Stop()
	rc.sendHello()
	lastKeepalive := time.Now()
	started := time.Now()
	warned := false
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
			// 中继现在是**纯启动参数**（不落盘），地址写错/中继没起时给一条明确告警，
			// 别让运维对着"没反应"猜。
			if !warned && time.Since(started) > 30*time.Second {
				warned = true
				rc.logf("⚠️ 中继 %v 30s 未确认注册：检查地址是否正确、中继是否在跑、UDP 是否通（本机 → 中继）", rc.relay)
			}
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
		dh, err := curve25519.X25519(rc.priv[:], ephPub[:])
		if err != nil {
			rc.logf("中继：挑战 DH 计算失败（%v）", err)
			return
		}
		var psk []byte
		if rc.secret != ([32]byte{}) {
			psk = proto.RelayAuthMAC(rc.secret, nonce, rc.pub)
		}
		proof := proto.EncodeRelayProof(nonce, dh, rc.pub, psk)
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

	// 摘要级（不是 dlogf）：这是「hint → 盲打」链路的判据行，且每地址 3s 节流，量可控。
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
