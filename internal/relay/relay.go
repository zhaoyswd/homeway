// Package relay：Homeway 中继（wg-native-stack tasks 6.1–6.5）。
//
// 定位：中继是**路径而不是参与方** —— 只见密文、零 WG 感知、零落盘状态（重启即清）。
// 安全由两件事构造性保证：
//   - 控制面：后端注册腿要证明持有 peerId 私钥（X25519 DH 挑战响应），否则拒绝；
//   - 数据面：转发的都是端到端加密的 WG 报文，中继改不了也读不了。
//
// 两条腿：
//
//	后端(NAT 后) ──出站注册腿──► 中继                       （NAT 友好：出站即可）
//	客户端       ──标签帧──────► 中继 ──per-client socket──► 后端注册腿源地址
//
// **per-client 分配 socket 是正确性要求**：后端 WG 靠**源地址**区分客户端 endpoint，
// 共用一条 socket 会让多客户端互踩（files 独立身份那次的教训）。
//
// hint（对端观察地址）在三个时机递送：客户端腿建立、后端注册腿源地址变化、客户端首包。
// hint 一律是不可信线索：只用于发起握手尝试，路径迁移以对端认证握手成功为前提。
package relay

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
	"golang.org/x/crypto/curve25519"
)

// 默认参数（可用 Config 覆盖）。
const (
	defaultIdleTimeout = 90 * time.Second // 分配腿空闲回收
	defaultLegTimeout  = 90 * time.Second // 注册腿过期（后端 keepalive 间隔的 3 倍）
	defaultMaxPerPeer  = 32               // 每个后端最多并发的客户端分配
	defaultRateLimit   = 200              // 每个源地址每秒允许的包数（准入限流）
	defaultMaxLegs     = 256              // 注册腿总数上限（白名单为空时的兜底）
	challengeTTL       = 15 * time.Second // 挑战有效期
	// defaultDialWait：拨腿等待窗口——通告后等后端 LEGUP 的上限。后端拨腿失败
	// （本地 socket 分配失败/腿上限）只记日志不回报，中继若无限等待，客户端上行
	// 会一直刷新 a.last，空闲回收永不触发（review 2026-09-21：会话永久悬挂）。
	defaultDialWait = 15 * time.Second
	// defaultDownSilent：会话**下行**静默上限——上行仍活跃（a.last 新鲜）而腿/后端
	// 方向零下行超过该值即拆会话。半死会话的兜底：后端腿被 RELEASE 丢失/控制空窗
	// 期回收后，客户端包持续灌进死地址、谁也不报错。拆会话安全：端到端状态
	// （WG 会话密钥、出口过境会话）不键在中继会话上，下一包即重建（亚秒抖动）；
	// 纯单向 UDP 流会每过该窗口吃到一次重建抖动——QUIC/TCP 恒有下行不受影响。
	defaultDownSilent = 5 * time.Minute
	// legBootstrap：未完成验证的腿（Hello 后/控制握手中）只保留这么久的注册窗口。
	// 防「匿名 Hello 占位」（MaxLegs 之外的第二道闸），同时让慢握手不与 reap 轮
	// 竞争（review 2026-09-21：建腿 last 零值 + verified=false，5s 一轮的 reap 会
	// 把握手中的腿摘出 map——TCP 控制路径此后不自愈，dialUp 模式静默失效）。
	// 覆盖 UDP challengeTTL(15s) 与 TCP 握手 deadline(10s) 两条窗口。
	legBootstrap = 30 * time.Second
)

// Config 中继参数。
type Config struct {
	Addr        string        // 监听地址（如 :41641）
	IdleTimeout time.Duration // 分配腿空闲回收（0 = 默认 90s）
	LegTimeout  time.Duration // 注册腿过期（0 = 默认 90s）
	// DialWait：拨腿等待窗口（0 = 默认 15s；测试可调短）。
	DialWait time.Duration
	// DownSilent：会话下行静默上限（0 = 默认 5min；测试可调短）。
	DownSilent time.Duration
	MaxPerPeer int // 每个后端的最大并发分配（0 = 默认 32）
	RateLimit  int // 每源每秒包数上限（0 = 默认 200）
	// Secret：中继**鉴权密钥**（非零 = token 模式：只接受持有 rl1 token 的后端）。
	// 零值 = 开放模式（谁都能注册，仅测试用）。密钥由 cmd 从 --state 加载/生成。
	Secret [32]byte
	// MaxLegs：注册腿总数上限（0 = 默认 256）—— 防"匿名 Hello 洪水"把表撑爆（腿不注册成功也占位）。
	MaxLegs int
	Logf    func(format string, args ...any)
}

// Relay 中继实例。
type Relay struct {
	cfg Config
	pc  *net.UDPConn

	onReady func(netip.AddrPort)
	mu      sync.Mutex
	legs    map[[8]byte]*leg
	assocs  map[assocKey]*assoc
	rates   map[netip.Addr]*rateBucket

	stats Stats

	nextSid uint64
	ctlLn   net.Listener
}

// Stats 中继计数（诊断/测试用）。
type Stats struct {
	Registered    uint64 // 成功注册的后端腿次数
	Forged        uint64 // 注册挑战/证明失败次数
	Denied        uint64 // 被白名单/腿数上限拒绝的注册
	Assigned      uint64 // 新建的客户端分配数
	Reclaimed     uint64 // 回收的分配数
	Dropped       uint64 // 被丢弃的包（未知 peerId/超限/畸形）
	ForwardedUp   uint64 // 客户端 → 后端 转发包数
	ForwardedDown uint64 // 后端 → 客户端 转发包数
}

type assocKey struct {
	label  [8]byte
	client netip.AddrPort
}

type leg struct {
	label    [8]byte
	pubkey   [32]byte
	addr     netip.AddrPort // 注册腿源地址（后端公网映射，也是给客户端的 hint）
	last     time.Time
	ephPriv  [32]byte
	nonce    [16]byte
	challAt  time.Time
	verified bool
	// ctlVerified：控制面（TCP 挑战）认证过。与 verified（UDP 注册挑战）是**两种
	// 证明**，转发准入与过期判定用「任一」——不再让控制面认证直接置 verified，
	// 否则孤儿清理的 !verified 恒假成死代码（review B4）。
	ctlVerified bool
	// ctl：控制通道（relay-backend-dial）。非 nil 时客户端到达走「通告+等后端拨腿」，
	// 而不是 per-client socket 主动发往 lg.addr（那条路在严格 NAT 上恒不通）。
	ctl *ctlConn
}

type assoc struct {
	key     assocKey
	backend netip.AddrPort // 注册腿地址（回程发给它；拨腿模式下 = 后端腿的实际源地址）
	sock    *net.UDPConn   // 该客户端专属的上游 socket（后端看到的"客户端地址"）
	last    time.Time      // 最近一次任一方向活动（空闲回收判据）
	// lastDown：最近一次**下行**（腿/后端方向到达）时刻。与 last 分开记：
	// 半死会话（上行活跃、下行恒零）光看 last 永远活着——DownSilent 用它判死。
	lastDown time.Time
	// 拨腿模式（relay-backend-dial）：等后端来拨。首包（LEGUP）到达前，
	// 客户端包缓冲在 pend（≤16）；到达后 backend = 腿源地址，缓冲放行。
	// dialed 是**持久**标志（本会话由拨腿承载——backend=腿源地址，与 lg.addr
	// 是两个概念，地址漂移检查不适用）；dialUp 只标「等待中」。
	// dialUpAt：等待开始时刻（DialWait 超时判据——后端拨腿失败不回报，
	// 中继侧必须自持看门狗，否则客户端上行会让会话悬挂到天荒地老）。
	sid      uint64
	dialed   bool
	dialUp   bool
	dialUpAt time.Time
	pendMu   sync.Mutex
	pend     [][]byte
}

// ctlPendMax：拨腿等待窗口的客户端包缓冲上限（同直连引导的 pending 语义）。
const ctlPendMax = 16

type rateBucket struct {
	window time.Time
	count  int
}

// New 建中继（不监听）。
func New(cfg Config) *Relay {
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = defaultIdleTimeout
	}
	if cfg.LegTimeout <= 0 {
		cfg.LegTimeout = defaultLegTimeout
	}
	if cfg.DialWait <= 0 {
		cfg.DialWait = defaultDialWait
	}
	if cfg.DownSilent <= 0 {
		cfg.DownSilent = defaultDownSilent
	}
	if cfg.MaxPerPeer <= 0 {
		cfg.MaxPerPeer = defaultMaxPerPeer
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = defaultRateLimit
	}
	if cfg.MaxLegs <= 0 {
		cfg.MaxLegs = defaultMaxLegs
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	return &Relay{
		cfg:    cfg,
		legs:   map[[8]byte]*leg{},
		assocs: map[assocKey]*assoc{},
		rates:  map[netip.Addr]*rateBucket{},
	}
}

// LocalAddr 监听地址（Run 之后可用；测试里取随机端口）。
// pc 的跨协程访问只有 Run 写 / 这里读：持 r.mu 同步（曾在 -race 下报
// Run 写 vs 测试轮询 LocalAddr 读的竞争）。
func (r *Relay) LocalAddr() netip.AddrPort {
	r.mu.Lock()
	pc := r.pc
	r.mu.Unlock()
	if pc == nil {
		return netip.AddrPort{}
	}
	if ua, ok := pc.LocalAddr().(*net.UDPAddr); ok {
		return ua.AddrPort()
	}
	return netip.AddrPort{}
}

// Stats 读计数快照。
func (r *Relay) Stats() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stats
}

// RunWithReady：同 Run，但绑定成功后回调一次（实际地址）—— token 必须在**实际端口**确定后生成。
func (r *Relay) RunWithReady(ctx context.Context, onReady func(actual netip.AddrPort)) error {
	r.onReady = onReady
	return r.Run(ctx)
}

// Run 监听并服务直到 ctx 结束。
//
// 端口冲突自动退让（配置口 → +1…+9 → 随机）：中继也要"零参数就能起"，
// 撞车时把实际端口打出来并写进 token（token 里的端口必须是我们真正在听的）。
func (r *Relay) Run(ctx context.Context) error {
	pc, err := r.listen()
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.pc = pc
	r.mu.Unlock()
	if r.onReady != nil {
		r.onReady(netip.AddrPortFrom(netip.Addr{}, uint16(pc.LocalAddr().(*net.UDPAddr).Port)))
	}
	// TCP 控制监听（relay-backend-dial）：与 UDP **实际**端口同号（配置口可能被退让过；
	// 随机口(:0)时两边各自随机会对不上）。两个独立端口空间 ⇒ 部署零新增、token 不变。
	// 起不来**不致命**：中继退回纯 UDP 模式（后端拨腿特性整体缺席）。
	ctlAddr := mustResolve(r.cfg.Addr)
	ctlAddr.Port = pc.LocalAddr().(*net.UDPAddr).Port
	if tcpLn, terr := net.Listen("tcp", ctlAddr.String()); terr == nil {
		r.ctlLn = tcpLn
		go r.serveControl(tcpLn)
		go func() {
			<-ctx.Done()
			_ = tcpLn.Close()
		}()
		r.cfg.Logf("中继控制面：TCP %v 就绪（后端拨腿模式可用）", tcpLn.Addr())
	} else {
		r.cfg.Logf("⚠️ 控制面 TCP %v 监听失败（%v）—— 退回纯 UDP 中继（拨腿特性缺席）", ctlAddr.String(), terr)
	}
	who := "⚠️ 开放注册：任何知道本地址的后端都能用它中转（正常路径下不会出现）"
	if r.cfg.Secret != ([32]byte{}) {
		rid := proto.RelaySecretID(r.cfg.Secret)
		who = fmt.Sprintf("token 模式（中继 ID %x）", rid[:6])
	}
	r.cfg.Logf("中继就绪：%v（%s；分配回收 %v，注册腿过期 %v，每源限速 %d pps，每后端最多 %d 条分配，腿总数上限 %d）",
		pc.LocalAddr(), who, r.cfg.IdleTimeout, r.cfg.LegTimeout, r.cfg.RateLimit, r.cfg.MaxPerPeer, r.cfg.MaxLegs)
	go r.reapLoop(ctx)
	go r.statsLoop(ctx)
	go func() {
		<-ctx.Done()
		_ = pc.Close()
		r.closeAll()
	}()
	r.readLoop(ctx)
	return nil
}

// listen：按配置口监听，被占用就 +1…+9，再不行随机。
func (r *Relay) listen() (*net.UDPConn, error) {
	laddr := mustResolve(r.cfg.Addr)
	want := laddr.Port
	pc, err := net.ListenUDP("udp", laddr)
	if err == nil {
		return pc, nil
	}
	_ = 0 // （TCP 控制监听在 Serve 里另起；此处保持原 UDP 退让逻辑不动）
	r.cfg.Logf("⚠️ 监听端口 %d 被占用（%v）—— 自动往后找", want, err)
	for p := want + 1; want != 0 && p <= want+9; p++ {
		la := *laddr
		la.Port = p
		if c, e := net.ListenUDP("udp", &la); e == nil {
			r.cfg.Logf("中继改用端口 %d（token 里写的就是它）", p)
			return c, nil
		}
	}
	la := *laddr
	la.Port = 0
	c, e := net.ListenUDP("udp", &la)
	if e != nil {
		return nil, e
	}
	return c, nil
}

func mustResolve(addr string) *net.UDPAddr {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return &net.UDPAddr{}
	}
	return ua
}

// readLoop：listener 上的收包（客户端腿 + 后端注册腿共用同一个端口）。
func (r *Relay) readLoop(ctx context.Context) {
	buf := make([]byte, 65535)
	for {
		n, src, err := r.pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			return // ctx 结束或 socket 关闭
		}
		src = unmap(src)
		if !r.rateOK(src.Addr()) {
			r.bump(func(s *Stats) { s.Dropped++ })
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)
		r.handlePacket(ctx, src, pkt)
	}
}

// handlePacket：一条入包的分派。
func (r *Relay) handlePacket(_ context.Context, src netip.AddrPort, pkt []byte) {
	label, typ, payload, err := proto.DecodeTagged(pkt)
	if err != nil {
		// 不带标签的包（比如误发到中继端口的 WG）：直接丢
		r.bump(func(s *Stats) { s.Dropped++ })
		return
	}
	r.mu.Lock()
	lg := r.legs[label]
	r.mu.Unlock()

	if typ == proto.FrameTypeRelayReg {
		r.handleControl(src, label, lg, payload)
		return
	}
	if lg == nil || !(lg.verified || lg.ctlVerified) {
		// 准入：没有已注册的后端，谁也别想转发（蹭不到资源）
		r.bump(func(s *Stats) { s.Dropped++ })
		return
	}
	r.forwardUp(src, lg, typ, payload)
}

// handleControl：后端注册腿的控制消息（Hello/Proof/Keepalive）。
func (r *Relay) handleControl(src netip.AddrPort, label [8]byte, lg *leg, payload []byte) {
	sub, _ := proto.RelaySubtype(payload)
	switch sub {
	case proto.RelaySubHello:
		pubkey, err := proto.DecodeRelayHello(payload)
		if err != nil || proto.RelayID(pubkey) != label {
			r.bump(func(s *Stats) { s.Forged++ })
			return
		}
		// 出题：临时 X25519 密钥对 + 随机数
		var ephPriv [32]byte
		if _, err := rand.Read(ephPriv[:]); err != nil {
			return
		}
		ephPub, err := curve25519.X25519(ephPriv[:], curve25519.Basepoint)
		if err != nil {
			return
		}
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return
		}
		var pub [32]byte
		copy(pub[:], ephPub)
		r.mu.Lock()
		cur := r.legs[label]
		if cur == nil || !cur.verified {
			if cur == nil && len(r.legs) >= r.cfg.MaxLegs {
				r.mu.Unlock()
				r.bump(func(s *Stats) { s.Denied++ })
				r.cfg.Logf("中继：注册腿总数已达上限 %d，拒绝新的 %x（防匿名洪水）", r.cfg.MaxLegs, label[:])
				return
			}
			cur = &leg{label: label, pubkey: pubkey, last: time.Now()} // last=now：未验证腿的注册窗口起点（见 reapLoop 的 legBootstrap 分支）
			r.legs[label] = cur
		}
		cur.ephPriv, cur.nonce, cur.challAt = ephPriv, nonce, time.Now()
		r.mu.Unlock()
		_, _ = r.pc.WriteToUDPAddrPort(proto.EncodeFrame(proto.FrameTypeRelayReg,
			proto.EncodeRelayChallenge(pub, nonce)), src)
	case proto.RelaySubProof:
		if lg == nil {
			r.bump(func(s *Stats) { s.Forged++ })
			return
		}
		gotNonce, macDH, macPSK, err := proto.DecodeRelayProof(payload)
		if err != nil {
			r.bump(func(s *Stats) { s.Forged++ })
			return
		}
		r.mu.Lock()
		if time.Since(lg.challAt) > challengeTTL || lg.nonce != gotNonce {
			r.mu.Unlock()
			r.bump(func(s *Stats) { s.Forged++ })
			return
		}
		var dh []byte
		if r.cfg.Secret == ([32]byte{}) {
			dh, err = curve25519.X25519(lg.ephPriv[:], lg.pubkey[:])
			if err != nil {
				r.mu.Unlock()
				r.bump(func(s *Stats) { s.Forged++ })
				return
			}
		}
		// token 模式只认鉴权 MAC（DH 谁都算得出来，不能当准入）；开放模式看 DH。
		if r.cfg.Secret != ([32]byte{}) {
			want := proto.RelayAuthMAC(r.cfg.Secret, lg.nonce, lg.pubkey)
			if len(macPSK) != 16 || subtle.ConstantTimeCompare(want, macPSK) != 1 {
				r.mu.Unlock()
				r.bump(func(s *Stats) { s.Forged++ })
				r.cfg.Logf("中继：后端 %x 的 token 校验不过（密钥不对/没带 token）—— 拒绝", label[:])
				return
			}
		} else {
			want := proto.RelayProofMAC(dh, lg.nonce, lg.pubkey)
			if subtle.ConstantTimeCompare(want, macDH) != 1 {
				r.mu.Unlock()
				r.bump(func(s *Stats) { s.Forged++ })
				return
			}
		}
		moved := lg.addr.IsValid() && lg.addr != src
		lg.verified, lg.addr, lg.last = true, src, time.Now()
		// 内存里的挑战私钥用完即弃
		lg.ephPriv = [32]byte{}
		var stale []assocKey
		var staleSids []uint64
		if moved {
			// 后端换网/重映射：它的旧分配腿对端地址已变，全部作废重建。
			// 拨腿会话补发 RELEASE（review B1）：后端侧的腿等它重拨/重放对账。
			for k, a := range r.assocs {
				if k.label == label {
					stale = append(stale, k)
					if a.sid != 0 {
						staleSids = append(staleSids, a.sid)
					}
					_ = a.sock.Close()
				}
			}
			for _, k := range stale {
				delete(r.assocs, k)
			}
		}
		r.stats.Registered++
		r.mu.Unlock()
		for _, sid := range staleSids {
			r.releaseSession(lg, sid)
		}
		if moved {
			r.cfg.Logf("中继：后端 %x 注册腿地址变化 → %v（旧分配 %d 条已作废，等客户端重建）",
				label[:], src, len(stale))
		} else {
			r.cfg.Logf("中继：后端 %x 注册成功（腿 %v）", label[:], src)
		}
		_, _ = r.pc.WriteToUDPAddrPort(proto.EncodeFrame(proto.FrameTypeRelayReg, proto.EncodeRelayOK()), src)
	case proto.RelaySubKeepalive:
		if lg == nil || !(lg.verified || lg.ctlVerified) {
			// 腿不在了（中继刚重启/已过期）：明确让后端重注册 —— 否则它以为还在，只发保活，
			// 两边就永远对不上（实测踩过：中继重启后后端一直不重注册）。
			_, _ = r.pc.WriteToUDPAddrPort(proto.EncodeFrame(proto.FrameTypeRelayReg, proto.EncodeRelayAgain()), src)
			return
		}
		if lg.addr.IsValid() && lg.addr != src {
			// 换了地址的保活不算数：要求重新走一遍注册（防地址冒用）。
			_, _ = r.pc.WriteToUDPAddrPort(proto.EncodeFrame(proto.FrameTypeRelayReg, proto.EncodeRelayAgain()), src)
			return
		}
		// 无 UDP 注册（纯控制腿）的 keepalive：addr 无从比对，静默续命即可——
		// 回 Again 只会让后端无意义地重注册刷屏（review B7③）。
		r.mu.Lock()
		lg.last = time.Now()
		r.mu.Unlock()
	default:
		r.bump(func(s *Stats) { s.Dropped++ })
	}
}

// forwardUp：客户端 → 后端（必要时新建分配 socket），并按需递送 hint。
func (r *Relay) forwardUp(client netip.AddrPort, lg *leg, typ byte, payload []byte) {
	key := assocKey{label: lg.label, client: client}
	r.mu.Lock()
	a := r.assocs[key]
	if a != nil && !a.dialed && a.backend != lg.addr {
		// 后端注册腿换了地址（重映射）：老分配作废，重建。
		// 拨腿模式不适用：backend = 腿源地址（与 lg.addr 是两个概念，
		// 无 UDP 注册时 lg.addr 为零值，按它比对会恒不等 → 每包都拆会话重建。
		_ = a.sock.Close()
		delete(r.assocs, key)
		a = nil
	}
	if a == nil {
		// 无可达路径不建会话：既无 UDP 注册腿（lg.addr 无效）也无控制连接时，
		// 建了也只能指向零值地址（死会话，客户端首包竞态在控制面握手窗口里
		// 会踩中）——丢弃让客户端重试，等后端任一路径就绪。
		if !lg.addr.IsValid() && !r.hasControlLocked(lg) {
			r.mu.Unlock()
			r.bump(func(s *Stats) { s.Dropped++ })
			return
		}
		if r.countAssocsLocked(lg.label) >= r.cfg.MaxPerPeer {
			r.mu.Unlock()
			r.bump(func(s *Stats) { s.Dropped++ })
			r.cfg.Logf("中继：后端 %x 的分配腿已达上限 %d，丢弃新客户端 %v", lg.label[:], r.cfg.MaxPerPeer, client)
			return
		}
		sock, err := net.ListenUDP("udp", nil)
		if err != nil {
			r.mu.Unlock()
			r.bump(func(s *Stats) { s.Dropped++ })
			return
		}
		a = &assoc{key: key, backend: lg.addr, sock: sock, last: time.Now(), lastDown: time.Now()}
		// relay-backend-dial：有控制连接的后端走「通告 + 等拨腿」——
		// 不主动发往 lg.addr（严格 NAT 上恒不通），首包缓冲、等后端的 LEGUP。
		if r.hasControlLocked(lg) {
			r.nextSid++
			a.sid = r.nextSid
			a.dialUp = true
			a.dialed = true
			a.dialUpAt = time.Now()
		}
		r.assocs[key] = a
		r.stats.Assigned++
		sid, dialUp := a.sid, a.dialUp
		r.mu.Unlock()
		go r.assocReadLoop(a)
		// 腿建立：两端各推一次对端观察地址（不可信线索）
		r.sendHintToClient(a, lg)
		r.sendHintToBackend(a, client)
		if dialUp {
			port := uint16(sock.LocalAddr().(*net.UDPAddr).Port)
			if r.announceSession(lg, proto.CtlSession{ID: sid, DataPort: port}) {
				r.cfg.Logf("中继：客户端 %v 起会话 #%d（拨腿模式）→ 后端 %x（数据口 %v）",
					client, sid, lg.label[:], sock.LocalAddr())
			} else {
				// 通告失败（连接刚断）：这条会话没腿可等——回收掉，客户端重试会再触发
				_ = sock.Close()
				r.mu.Lock()
				delete(r.assocs, key)
				r.mu.Unlock()
				r.bump(func(s *Stats) { s.Dropped++ })
				return
			}
		} else {
			r.cfg.Logf("中继：客户端 %v 起一条分配腿 → 后端 %x（中继侧出口 %v）",
				client, lg.label[:], a.sock.LocalAddr())
		}
	} else {
		a.last = time.Now()
		r.mu.Unlock()
	}
	frame := proto.EncodeFrame(typ, payload)
	r.mu.Lock()
	if a.dialUp {
		// 等腿窗口：缓冲（上限外丢弃——QUIC 首包风暴也就 1-2 个包）
		a.pendMu.Lock()
		if len(a.pend) < ctlPendMax {
			a.pend = append(a.pend, frame)
			a.pendMu.Unlock()
			r.mu.Unlock()
			r.bump(func(s *Stats) { s.ForwardedUp++ })
			return
		}
		a.pendMu.Unlock()
		r.mu.Unlock()
		r.bump(func(s *Stats) { s.Dropped++ })
		return
	}
	dst := a.backend
	r.mu.Unlock()
	_, _ = a.sock.WriteToUDPAddrPort(frame, dst)
	r.bump(func(s *Stats) { s.ForwardedUp++ })
}

// hasControlLocked：leg 是否挂着控制连接（调用方持 r.mu）。
func (r *Relay) hasControlLocked(lg *leg) bool {
	return lg != nil && lg.ctl != nil
}

// assocReadLoop：后端 → 客户端。后端回程是**裸 WG**（device 不知道帧），也可能带 hint 腿帧。
// 拨腿模式下首个到达包 = 后端拨腿的标记（"LEGUP"，纯标记）或首批数据：登记腿源地址、
// 放掉等腿窗口的缓冲，之后进入常态转发。
func (r *Relay) assocReadLoop(a *assoc) {
	buf := make([]byte, 65535)
	for {
		n, from, err := a.sock.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		pkt := buf[:n]
		from = unmap(from) // 与 readLoop 同款：4in6 映射形态统一成 v4，否则后续比较恒不等
		r.mu.Lock()
		// 双向任一活跃即续命（与出口 intercept 的共享时间戳同哲学）；下行时刻
		// 单独记（DownSilent 判据），LEGUP 这类纯标记也算下行到达。
		now := time.Now()
		a.last, a.lastDown = now, now
		if a.dialUp {
			a.dialUp = false
			a.backend = from
			r.mu.Unlock()
			a.pendMu.Lock()
			pend := a.pend
			a.pend = nil
			a.pendMu.Unlock()
			for _, p := range pend {
				_, _ = a.sock.WriteToUDPAddrPort(p, from)
			}
		} else if a.dialed && a.backend != from {
			// 常态源校正（review B5）：**只对拨腿会话**（a.dialed）生效——后端腿的
			// NAT 映射漂移（重拨/换网）时，不更新的话下行会持续发往死地址、而客户端
			// 发包让 a.last 一直新鲜——会话半死到空闲回收。源变化即跟随（腿由后端
			// 拨出，能从此地址发来即证明可达）。
			// fallback 会话（sid==0，backend 恒为 lg.addr）不跟随：它的"源变化"
			// 属于 UDP 注册腿换源，由 forwardUp 的既有重建路径处理（曾因 4in6 形态
			// 差异被误改写 → 误判漂移 → 误重建，测试 TestControlReplaySkipsFallbackAssocs 抓到）。
			a.backend = from
			r.mu.Unlock()
			r.cfg.Logf("中继：会话 #%d 的后端腿源漂移 → %v（跟随）", a.sid, from)
		} else {
			r.mu.Unlock()
		}
		// LEGUP 吞包：首腿与重拨腿（控制重连重放后的再拨）都会发这个标记。
		// 判定必须在分支外——重拨腿的 LEGUP 是"新源首包"，走漂移跟随分支，
		// 若只在 dialUp 分支里吞，它会被当数据转发给客户端（review 2026-09-21；
		// WG 层虽会丢弃 5 字节残包，但别把标记泄给对端）。
		if len(pkt) == 5 && string(pkt) == "LEGUP" {
			continue
		}
		frame := pkt
		if len(pkt) == 0 || pkt[0] != 0xBB {
			// 裸 WG：包成数据腿帧再发给客户端
			frame = proto.EncodeFrame(proto.FrameTypeData, pkt)
		}
		if _, err := r.pc.WriteToUDPAddrPort(frame, a.key.client); err != nil {
			return
		}
		r.bump(func(s *Stats) { s.ForwardedDown++ })
	}
}

// sendHintToClient：把**后端注册腿的源地址**告诉客户端（客户端据此打洞）。
func (r *Relay) sendHintToClient(a *assoc, lg *leg) {
	r.mu.Lock()
	addr := lg.addr
	r.mu.Unlock()
	if !addr.IsValid() {
		return
	}
	frame := proto.EncodeHint(addr.String())
	_, _ = r.pc.WriteToUDPAddrPort(frame, a.key.client)
}

// sendHintToBackend：把**客户端在中继眼里的源地址**告诉后端（后端据此盲打 + 学习）。
func (r *Relay) sendHintToBackend(a *assoc, client netip.AddrPort) {
	frame := proto.EncodeHint(client.String())
	// 持锁读 backend（review B5）：assocReadLoop 在锁内写它，裸读是数据竞争。
	r.mu.Lock()
	dst := a.backend
	r.mu.Unlock()
	if !dst.IsValid() {
		return // 拨腿等待中（无 backend 可发）
	}
	_, _ = a.sock.WriteToUDPAddrPort(frame, dst)
}

// reapInterval：回收扫描节拍。默认 5s；配置了更短的回收窗时按其一半收缩
// （测试用百毫秒级超时，不必等 5s 一轮；生产默认值都不收缩）。
func (r *Relay) reapInterval() time.Duration {
	d := 5 * time.Second
	for _, c := range []time.Duration{r.cfg.IdleTimeout, r.cfg.DialWait, r.cfg.DownSilent} {
		if c > 0 && c/2 < d {
			d = c / 2
		}
	}
	if d < 20*time.Millisecond {
		d = 20 * time.Millisecond
	}
	return d
}

// reapLoop：回收空闲分配腿 + 过期注册腿。
func (r *Relay) reapLoop(ctx context.Context) {
	t := time.NewTicker(r.reapInterval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now()
		var reclaim int
		var released []*leg
		var releasedIds []uint64
		r.mu.Lock()
		for k, a := range r.assocs {
			why := ""
			switch {
			case now.Sub(a.last) > r.cfg.IdleTimeout:
				why = "" // 普通空闲：走既有聚合计数，不逐条打日志
			case a.dialUp && now.Sub(a.dialUpAt) > r.cfg.DialWait:
				why = fmt.Sprintf("拨腿等待超 %v（通告后无 LEGUP——后端拨腿失败/通告丢失）", r.cfg.DialWait)
			case now.Sub(a.lastDown) > r.cfg.DownSilent:
				why = fmt.Sprintf("下行静默超 %v（上行仍活跃——半死会话兜底）", r.cfg.DownSilent)
			default:
				continue
			}
			if why != "" {
				r.cfg.Logf("中继：会话 #%d 回收：%s", a.sid, why)
			}
			_ = a.sock.Close()
			delete(r.assocs, k)
			reclaim++
			if a.sid != 0 {
				if lg := r.legs[k.label]; lg != nil {
					released = append(released, lg)
					releasedIds = append(releasedIds, a.sid)
				}
			}
		}
		r.mu.Unlock()
		// 拨腿会话回收 → 通告后端放腿（锁外写，避免与 announceSession 抢锁序）。
		for i, lg := range released {
			r.releaseSession(lg, releasedIds[i])
		}
		r.mu.Lock()
		r.stats.Reclaimed += uint64(reclaim)
		for label, lg := range r.legs {
			// 存活判定：挂着控制连接的腿由控制保活续命（readControlLoop 刷 last）；
			// 已验证（UDP 注册挑战或控制面挑战任一）按 last 在 LegTimeout 内；
			// **未验证的腿只保留 legBootstrap 注册窗口**——建腿时 last=now（见
			// legForControl / handleControl Hello），窗口内完成不了验证就摘，
			// 既防匿名 Hello 占位、又让慢握手不与 reap 轮竞争（见 legBootstrap 注释）。
			alive := now.Sub(lg.last) <= r.cfg.LegTimeout
			if lg.ctl == nil && !lg.verified && !lg.ctlVerified {
				alive = now.Sub(lg.last) <= legBootstrap
			}
			if !alive {
				r.cfg.Logf("中继：后端 %x 注册腿过期（%v 无保活）—— 摘掉", label[:], now.Sub(lg.last).Round(time.Second))
				if lg.ctl != nil {
					lg.ctl.close()
				}
				for k, a := range r.assocs {
					if k.label == label {
						_ = a.sock.Close()
						delete(r.assocs, k)
					}
				}
				delete(r.legs, label)
			}
		}
		// 限流桶清理（窗口外的直接丢）
		for ip, b := range r.rates {
			if now.Sub(b.window) > 2*time.Second {
				delete(r.rates, ip)
			}
		}
		r.mu.Unlock()
		if reclaim > 0 {
			r.cfg.Logf("中继：回收 %d 条空闲分配腿（当前 %d 条）", reclaim, r.assocCount())
		}
	}
}

// statsLoop：分钟级统计一行（运维判据：转发量/分配数/丢弃数）。
func (r *Relay) statsLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		st := r.Stats()
		r.mu.Lock()
		legs, assocs := len(r.legs), len(r.assocs)
		r.mu.Unlock()
		r.cfg.Logf("中继统计：注册腿 %d（累计成功 %d，伪造 %d）｜分配腿 %d（累计 %d，回收 %d）｜转发 上 %d / 下 %d 包｜丢弃 %d",
			legs, st.Registered, st.Forged, assocs, st.Assigned, st.Reclaimed,
			st.ForwardedUp, st.ForwardedDown, st.Dropped)
	}
}

func (r *Relay) closeAll() {
	// 拨腿会话补发 RELEASE（review B1，尽力而为——进程即将退出，写不进 TCP 就算了；
	// 后端还有 ClearLegs+重放对账与空闲回收两层兜底）。
	r.mu.Lock()
	type rel struct {
		lg  *leg
		sid uint64
	}
	var rels []rel
	for k, a := range r.assocs {
		if a.sid != 0 {
			if lg := r.legs[k.label]; lg != nil {
				rels = append(rels, rel{lg: lg, sid: a.sid})
			}
		}
		_ = a.sock.Close()
		delete(r.assocs, k)
	}
	r.mu.Unlock()
	for _, x := range rels {
		r.releaseSession(x.lg, x.sid)
	}
}

func (r *Relay) assocCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.assocs)
}

func (r *Relay) countAssocsLocked(label [8]byte) int {
	n := 0
	for k := range r.assocs {
		if k.label == label {
			n++
		}
	}
	return n
}

// rateOK：每源每秒包数限流（准入闸：防蹭转发资源/放大器）。
func (r *Relay) rateOK(ip netip.Addr) bool {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.rates[ip]
	if b == nil || now.Sub(b.window) >= time.Second {
		r.rates[ip] = &rateBucket{window: now, count: 1}
		return true
	}
	b.count++
	return b.count <= r.cfg.RateLimit
}

func (r *Relay) bump(f func(*Stats)) {
	r.mu.Lock()
	f(&r.stats)
	r.mu.Unlock()
}

func unmap(ap netip.AddrPort) netip.AddrPort {
	if ap.Addr().Is4In6() {
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return ap
}

// RegisterLeg：查一条注册腿是否在（测试/诊断）。
func (r *Relay) RegisterLeg(label [8]byte) (netip.AddrPort, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	lg := r.legs[label]
	if lg == nil || !(lg.verified || lg.ctlVerified) {
		return netip.AddrPort{}, false
	}
	return lg.addr, true
}
