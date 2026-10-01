// Package relay：Homeway 中继（wg-native-stack tasks 6.1–6.5）。
//
// 文件划分（FIX-74：原 relay.go 1114 行四职责混排——纯搬移，零行为变更）：
//
//	relay.go  装配与生命周期（Config/Relay/New/Run/listen/readLoop/handlePacket/closeAll）
//	leg.go    注册腿与控制消息（handleControl/腿密钥/登记面）
//	assoc.go  每客户端分配（forwardUp/回程泵/hint 递送）
//	reap.go   回收与限速（reapLoop 空闲/过期、每源令牌桶）
//	status.go 状态面（BackendBriefs/Snapshot/statsLoop）
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
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zhaoyswd/homeway/pkg/probe"
	"github.com/zhaoyswd/homeway/pkg/proto"
)

// 默认参数（可用 Config 覆盖）。
const (
	defaultIdleTimeout = 90 * time.Second // 分配腿空闲回收
	defaultLegTimeout  = 90 * time.Second // 注册腿过期（后端 keepalive 间隔的 3 倍）
	defaultMaxPerPeer  = 32               // 每个后端最多并发的客户端分配
	defaultRateLimit   = 200              // 每个源地址每秒允许的包数（准入限流）
	defaultMaxLegs     = 256              // 注册腿总数上限（白名单为空时的兜底）
	defaultMaxCtlConns = 64               // 已建立控制连接总数上限（≥ MaxLegs 时等于不设限）
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
	// MaxCtlConns：已建立控制连接总数上限（0 = 默认 64；review #7——此前只有
	// 「握手中」的并发闸，认证后的长连不设限，被灌满后每个连接各挂一个读协程）。
	MaxCtlConns int
	// Build：探测应答里回报的构建标记（add-host-connectivity；空 = "relay-dev"）。
	// 与出口侧 ServerBind.Build 同语义——客户端（添加主机的连通性验证）排障对照用。
	Build string
	Logf  func(format string, args ...any)
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
	// legRates：被拒腿包的**独立**限速桶（review 复审）：与准入限流共用一张表时，
	// 数据口上的垃圾包会吃掉同源 IP 在主口的合法配额（同 NAT 下的用户互相影响）。
	legRates map[netip.Addr]*rateBucket

	stats Stats

	// 控制面计数（**每实例独立**，review 复审 nit：此前是包级全局，
	// 同进程起两个 Relay 会互相吃配额，测试之间也会串）。
	//   ctlHandshaking：「握手中」的并发数（认证完成即释放）；
	//   ctlEstablished：已建立的控制连接总数（长连闸）。
	ctlHandshaking atomic.Int32
	ctlEstablished atomic.Int32

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
	// LegRejected：拨腿会话上被拒的未认证/未知源包数（review #3 的观测面——
	// 有值说明有人在扫数据口或后端腿重拨丢了 cookie，配「未知源被拒绝」日志）。
	LegRejected uint64
}

// ctlPendMax：拨腿等待窗口的客户端包缓冲上限（同直连引导的 pending 语义）。
const ctlPendMax = 16

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
	if cfg.MaxCtlConns <= 0 {
		cfg.MaxCtlConns = defaultMaxCtlConns
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Build == "" {
		cfg.Build = "relay-dev"
	}
	return &Relay{
		cfg:      cfg,
		legs:     map[[8]byte]*leg{},
		assocs:   map[assocKey]*assoc{},
		rates:    map[netip.Addr]*rateBucket{},
		legRates: map[netip.Addr]*rateBucket{},
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

// BackendBrief 注册出口列表条目（relay.status 数据源——role-management 2.2，r1 低-14：
// label 短指纹 + 源地址 + 最近活跃 + 验证态）。

// StatusSnapshot relay 状态快照（实际监听地址 + 注册出口列表）。
// **relay 侧看不到 APP**（在中继注册的是出口、手机流量在 WG 密文里）——事实约束进
// spec（role-management）；本结构因此只有后端维。

// BackendBriefs 注册出口列表快照（锁内拷贝；未跑 = nil）。

// Snapshot 状态快照（relay.status 数据源）。

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
		// 不为它单起一个"ctx 到了才关"的 goroutine：那样 Run 返回 ≠ 端口已释放
		//（复审复现的抖动：上一个中继的 TCP 监听还占着端口，下一个中继的 UDP 退让端口
		// 恰好撞上它 ⇒ 控制面 listen 失败、静默退回纯 UDP ⇒ 测试卡在等 CHALLENGE）。
		// 统一在 Run 的收尾里关（见下方 readLoop 之后）。
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
		_ = pc.Close() // 打断 readLoop（Run 的收尾在下面同步做）
	}()
	r.readLoop(ctx)
	// Run 返回 ⇒ 本实例的监听器与会话**一定**已释放（确定性收工）：调用方（测试/嵌入方）
	// 看到 Run 返回即可安全重用同端口，不需要"再等一会儿"。
	if r.ctlLn != nil {
		_ = r.ctlLn.Close()
	}
	r.closeAll()
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
	// 参照点探测（add-host-connectivity）：与出口侧同款语义的明文一问一答——客户端
	// （添加主机等场景）借此验证中继腿可达。无状态、不进帧协议分派、不受后端注册
	// 准入约束；防放大不变量由 probe.Respond 协议层保证（应答 ≤ 请求 + 45B）。
	if resp := probe.Respond(pkt, src, r.cfg.Build, 0); resp != nil {
		_, _ = r.pc.WriteToUDPAddrPort(resp, src)
		return
	}
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

// forwardUp：客户端 → 后端（必要时新建分配 socket），并按需递送 hint。

// hasControlLocked：leg 是否挂着**v2**控制连接（调用方持 r.mu）。v1 控制连接不算——
// 它解不开 v2 SESSION（cookie），硬通告只会让后端反复拨腿失败（review #25）。

// legMACKey：腿认证 MAC 的密钥——token 模式 = 中继鉴权密钥（与后端共享）；
// 开放模式 = cookie 本身（只防盲攻击者；能读线路的观察者在开放模式下本就无防）。

// legRejectThrottle：未认证源被拒日志的节流（每会话首几条 + 之后抽样）。

// assocReadLoop：后端 → 客户端。后端回程是**裸 WG**（device 不知道帧），也可能带 hint 腿帧。
//
// 拨腿会话（sid!=0）走腿身份认证状态机（review #3）：
//   - 首个合法的 LEGUP‖cookie‖MAC 才把该源认作腿（authOK/authSrc），放行等腿缓冲；
//   - 已认证源漂移（NAT 重映射/重拨）必须**重新出示合法认证**——未知源不改变 backend、
//     不放行 pend、不续命（旧实现「信任首个发包者 + 常态跟随源漂移」，任何扫到数据口
//     的第三方都能收走 WG 密文/黑洞上行/注入 hint，相对旧模型是安全回归）；
//   - v1 会话（无 cookie，仅存在于 v1 后端的 fallback 路径）维持旧行为：backend 恒为
//     lg.addr，源变化由 forwardUp 的既有重建路径处理。

// legRateOKLocked：被拒路径的每源限速（**调用方持 r.mu**——它在认证拒绝分支内使用，
// 包一层 Lock 会当场死锁）。只约束**日志与认证计算**的代价，不碰转发——转发只对
// 已认证源发生，真实后端不会被限。阈值取准入限流的 10 倍。

// sendHintToClient：把**后端注册腿的源地址**告诉客户端（客户端据此打洞）。

// sendHintToBackend：把**客户端在中继眼里的源地址**告诉后端（后端据此盲打 + 学习）。

// reapInterval：回收扫描节拍。默认 5s；配置了更短的回收窗时按其一半收缩
// （测试用百毫秒级超时，不必等 5s 一轮；生产默认值都不收缩）。

// reapLoop：回收空闲分配腿 + 过期注册腿。

// statsLoop：分钟级统计一行（运维判据：转发量/分配数/丢弃数）。

// closeAll：收工（幂等）。关全部会话 socket + 全部控制连接，并尽力给拨腿会话补发
// RELEASE（review B1——进程即将退出，写不进 TCP 就算了；后端还有 ClearLegs+重放对账
// 与空闲回收两层兜底）。控制连接必须显式关：accept 出来的长连不随监听器关闭而结束，
// 不关就要等 90s 读超时，Run 也就"返回了但还挂着 socket/goroutine"。
func (r *Relay) closeAll() {
	r.mu.Lock()
	type rel struct {
		lg  *leg
		sid uint64
	}
	var rels []rel
	var ctls []*ctlConn
	for _, lg := range r.legs {
		if lg.ctl != nil {
			ctls = append(ctls, lg.ctl)
		}
	}
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
	for _, cc := range ctls {
		cc.close()
	}
}

// rateOK：每源每秒包数限流（准入闸：防蹭转发资源/放大器）。

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

// sameIPAsControl 保活源 IP 是否与控制连接同源（FIX-68 的无 addr 腿判据；控制连接
// 不在/地址取不到 = 不接受该保活）。
