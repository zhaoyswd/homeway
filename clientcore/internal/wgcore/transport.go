package wgcore

// Transport：手机核「出口会话」的门面——把旧核用到的传输调用面（DialTCPPort / DialTCP /
// DialUDP + 换网重绑/重连/状态）整套搬到新栈上，方法名与语义对齐旧 tailcat 客户端，
// 于是 tunmode 换代只需要换「t.cl 的构造与类型」，调用点不用动。
//
// 接线（tasks 2.5/3.6 的消费端 + endpoint-freshness §3）：
//   - hint → 端点学习缓存（Bind.OnHint → ObserveAndSave(SourceHint)，触发 punch 盲打）；
//   - 探测线索 → 学习缓存（Bind.OnProbed → ObserveAndSave(SourceProbe)，**不**触发 punch——
//     探测列表没有「对端在等我打洞」的语义；旁路探测 ProbeCandidates 是生产者）；
//   - 真实往返 → 已验证（MarkRoundTrip：拨号成功 / PathProbe 判活 / 阶梯验证探测通过，
//     按地址去重——旧 sessionMarked 布尔漏掉「会话中途路径切换」与「R3 救回后闲置」）；
//   - 域名重解析（Rearm 时并发、不占恢复阶梯动作预算，结果补投进赛跑/t.static）；
//   - 三档归因：Probe 用参照点探测（pkg/probe）测「本机网络到该地址」是否通。

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/internal/wtransport"
	"github.com/zhaoyswd/homeway/pkg/probe"
	"github.com/zhaoyswd/homeway/pkg/wgnet"
)

// DomainEndpoint 域名形态的 token 端点（endpoint-freshness D5：重赛跑时重解析用）。
// Relay 必须随端口一起携带（FIX-14）：token 里写中继域名时，重解析产出的候选若不标
// Relay，会按直连裸发——中继只认腿帧路由头，该腿静默失效。
type DomainEndpoint struct {
	Host  string
	Port  uint16
	Relay bool
}

// TransportConfig 会话门面参数。
type TransportConfig struct {
	Core  *Core
	Cache *wtransport.EndpointCache // 可 nil（无学习缓存）
	// StaticCandidates：IP 字面量展开后的静态候选（LAN/公网/中继；不含域名解析产物）。
	StaticCandidates []wtransport.Candidate
	// DomainCandidates：域名条目**建会话时**的解析产物（session_endpoints 展开）。
	// 之后每次重赛跑（Rearm/RearmSoft）都会重解析并替换这批候选。
	DomainCandidates []wtransport.Candidate
	// DomainEndpoints + LookupHost：域名原始条目与解析器（任一为空 = 无域名重解析）。
	DomainEndpoints []DomainEndpoint
	LookupHost      func(ctx context.Context, host string) ([]netip.Addr, error)
	Logf            func(format string, args ...any)
}

// Transport 出口会话门面。
type Transport struct {
	core  *Core
	cache *wtransport.EndpointCache
	logf  func(format string, args ...any)

	// 域名重解析状态（endpoint-freshness D5）。
	resolveMu       sync.Mutex
	staticBase      []wtransport.Candidate // IP 字面量（永不变）
	domainEps       []DomainEndpoint
	domainCands     []wtransport.Candidate // 最近一次解析产物（static = staticBase + domainCands）
	lookup          func(ctx context.Context, host string) ([]netip.Addr, error)
	resolveInflight atomic.Bool
	lastSoftRearm   time.Time // 「赛跑已结算 + 中继获胜」时补投软赛跑的节流

	mu           sync.Mutex
	lastMarked   netip.AddrPort // 已验证标记按地址去重（替代旧 sessionMarked 布尔）
	lastMarkedAt time.Time      // 同地址的复标节流（长连路径每小时刷新一次 VerifiedAt）
	lastPunchAt  time.Time
}

// NewTransport 建门面并把学习缓存/候选接上。
func NewTransport(cfg TransportConfig) (*Transport, error) {
	if cfg.Core == nil {
		return nil, errors.New("wgcore: Transport 需要 Core")
	}
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	t := &Transport{
		core: cfg.Core, cache: cfg.Cache, logf: logf,
		staticBase:  cfg.StaticCandidates,
		domainEps:   cfg.DomainEndpoints,
		domainCands: cfg.DomainCandidates,
		lookup:      cfg.LookupHost,
	}
	bind := cfg.Core.Bind()
	if cfg.Cache != nil {
		// hint（中继观察）→ 学习缓存（非认证线索，最新鲜）。
		bind.SetOnHint(func(addr string) {
			ap, err := netip.ParseAddrPort(addr)
			if err != nil {
				return
			}
			cfg.Cache.ObserveAndSave(ap, wtransport.SourceHint, time.Now())
			bind.SetCandidates(cfg.Cache.Merge(t.static(), time.Now()))
			t.punchTo(ap)
		})
		// 探测线索（旁路探测应答的端点列表）→ 学习缓存（endpoint-freshness）。
		// 不触发 punch：见文件头。消费卫兵在这里（与出口侧对称）：非全球单播/
		// fake-IP 段/多播/回环一律拒绝——应答无认证，不能让投喂污染候选表。
		bind.SetOnProbed(func(addr string) {
			ap, err := netip.ParseAddrPort(addr)
			if err != nil || !probeAddrAcceptable(ap.Addr()) {
				return
			}
			cfg.Cache.ObserveAndSave(ap, wtransport.SourceProbe, time.Now())
			bind.SetCandidates(cfg.Cache.Merge(t.static(), time.Now()))
		})
		bind.SetCandidates(cfg.Cache.Merge(t.static(), time.Now()))
	}
	return t, nil
}

// static 当前静态候选集（IP 字面量 + 最近一次域名解析产物）。
func (t *Transport) static() []wtransport.Candidate {
	t.resolveMu.Lock()
	defer t.resolveMu.Unlock()
	return append(append([]wtransport.Candidate(nil), t.staticBase...), t.domainCands...)
}

// IsRefusedLike：RST 类拨号错误（隧道通、目标端口无服务）。PathProbe/打洞探测
// 的存活判据——「出口对必然无服务的端口回 RST」说明会话活着。wgnet 在包装点恒挂
// ErrRefused 哨兵（errors.Is 可判，本地 replace 钉版本 ⇒ 不留子串兜底——纯子串匹配
// 会误吞任何恰好含 "refused" 的无关错误，review 2026-09-21 曾因此翻过判据）。
func IsRefusedLike(err error) bool {
	return err != nil && errors.Is(err, wgnet.ErrRefused)
}

// RearmSoft：软赛跑 —— 中继立即参与（用于"已在用中继、只想升直连"的时刻，见 Bind.RearmSoft）。
func (t *Transport) RearmSoft() {
	t.core.Bind().RearmSoft()
	if t.cache != nil {
		t.core.Bind().SetCandidates(t.cache.Merge(t.static(), time.Now()))
	}
	t.refreshDomainAsync()
}

// punchTo：收到对端地址线索后打一发"握手兼打洞"（specs/wg-native-relay「打洞配合」）。
//
// 做法（不碰 wireguard-go 内部）：重新武装候选赛跑（清采纳 + 重新武装 reg），再制造一个出站包 ——
// Bind 在未采纳时会把出站包**镜像到全部候选**，其中就含刚学到的 hint 地址，于是那发 WG 握手
// 同时充当打洞包。制造出站包用内部流拨号（PathProbe），对隧道只是一个小 SYN；不通也无副作用
// （拨不通就继续停在原路径）。节流：5s 内只打一次，避免 hint 抖动引发镜像风暴。
func (t *Transport) punchTo(addr netip.AddrPort) {
	t.mu.Lock()
	if time.Since(t.lastPunchAt) < 5*time.Second {
		t.mu.Unlock()
		return
	}
	t.lastPunchAt = time.Now()
	t.mu.Unlock()

	t.RearmSoft() // 软赛跑：中继立即参与（不中断在用路径），同时把 hint 也纳入镜像
	t.logf("中继 hint %v → 重新武装候选赛跑，打一发握手兼打洞", addr)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// 拨出口的 1 号端口（必然没有服务）：出站 SYN 就是那发"握手兼打洞"；
		// 拿到 ERR refused 说明隧道活着（路径通不通由 Bind 的采纳结果决定）。
		conn, err := t.DialTCPPort(ctx, 1)
		if err != nil {
			// l3-exit-intercept：出口对 1 号端口回 RST（豁免转投本机、无人听）——
			// refused 类错误说明握手与路径都通了（判据统一走 IsRefusedLike）。
			if !IsRefusedLike(err) {
				t.logf("打洞后探测未成功（%v）—— 继续停留在原路径（中继/旧直连）", err)
				return
			}
		} else {
			_ = conn.Close()
		}
		t.logf("打洞后探测成功：会话可能已漂移到直连（看 link 行确认）")
	}()
}

// DialTCPPort 拨**出口主机本机**的端口（files 7802 / 终端 7724 / 端口转发的本机目标）。
// l3-exit-intercept 语义：「拨隧道 IP = 拨后端 localhost」（出口豁免规则转投 127.0.0.1:同端口）。
func (t *Transport) DialTCPPort(ctx context.Context, port uint16) (net.Conn, error) {
	return t.dial(ctx, netip.AddrPortFrom(t.core.ServerTunnelIP(), port))
}

// DialTCP 拨任意目标（端口转发到出口可达的 IP；出口按过境流拦截重拨）。
func (t *Transport) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return t.dial(ctx, dst)
}

func (t *Transport) dial(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	conn, err := t.core.DialTCPTunnel(ctx, dst)
	t.noteDialResult(err)
	return conn, err
}

// Rebind 换网：换本地 socket（同钥，会话保持）。
func (t *Transport) Rebind() error {
	if err := t.core.Bind().Rebind(); err != nil {
		return err
	}
	return nil
}

// Rearm 重连：重启候选赛跑 + 重新武装 reg（自愈/后端 peer 过期后用）。
// 域名重解析**并发**另跑（endpoint-freshness D5：Rearm 动作本体零 DNS 等待——恢复阶梯的
// 动作预算是 2s 有界，塞进 5s DNS 预算会把蜂窝下常态 DNS 空等打成 rc=-3「本地动作超时」
// 误升整套重建）；解析结果到达后补投（见 refreshDomainLocked）。
func (t *Transport) Rearm() {
	t.core.Bind().Rearm()
	if t.cache != nil {
		t.core.Bind().SetCandidates(t.cache.Merge(t.static(), time.Now()))
	}
	t.refreshDomainAsync()
}

// refreshDomainAsync：异步重解析域名条目（Rearm/RearmSoft 触发；单飞防重入）。
func (t *Transport) refreshDomainAsync() {
	if len(t.domainEps) == 0 || t.lookup == nil {
		return
	}
	if !t.resolveInflight.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer t.resolveInflight.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		t.refreshDomainLocked(ctx)
	}()
}

// refreshDomainLocked：解析全部域名条目 → 替换 domainCands 与候选集（t.static 随之更新——
// 出处判定与 Merge 都吃它，不刷新则新地址会被误标来源且旧解析一直被 Merge 带回）。
// **补投两分支**（评审 B-3）：赛跑未结算 → SetCandidates 即可（下一发镜像就带新候选）；
// 已结算且落中继 → 仅改候选表不发新包，经节流的软赛跑让新候选立刻获得一次赛跑机会
// （否则要等 RELAY-UPGRADE 5 拍 × 60s）。解析失败：退回上次解析结果（本函数直接返回）。
func (t *Transport) refreshDomainLocked(ctx context.Context) {
	var fresh []wtransport.Candidate
	for _, de := range t.domainEps {
		ips, err := t.lookup(ctx, de.Host)
		if err != nil {
			t.logf("域名重解析 %s 失败（退回上次解析结果）：%v", de.Host, err)
			return
		}
		for _, ip := range ips {
			if ip.IsValid() {
				fresh = append(fresh, wtransport.Candidate{Addr: netip.AddrPortFrom(ip.Unmap(), de.Port), Relay: de.Relay})
			}
		}
	}
	if len(fresh) == 0 {
		return
	}
	changed := !sameCandidates(fresh, t.domainCandsSnapshot())
	t.setDomainCands(fresh)
	if t.cache != nil {
		t.core.Bind().SetCandidates(t.cache.Merge(t.static(), time.Now()))
	}
	if !changed {
		return
	}
	t.logf("域名重解析：%d 条候选已刷新（%s）", len(fresh), wtransport.DescribeCandidates(fresh))
	addr, relay, valid := t.core.Bind().Adopted()
	if valid && relay && addr.IsValid() {
		t.mu.Lock()
		due := time.Since(t.lastSoftRearm) >= 15*time.Second
		if due {
			t.lastSoftRearm = time.Now()
		}
		t.mu.Unlock()
		if due {
			t.logf("域名重解析晚于赛跑结算（当前中继 %v）→ 节流软赛跑补投新候选", addr)
			t.RearmSoft()
		}
	}
}

func (t *Transport) domainCandsSnapshot() []wtransport.Candidate {
	t.resolveMu.Lock()
	defer t.resolveMu.Unlock()
	return append([]wtransport.Candidate(nil), t.domainCands...)
}

func (t *Transport) setDomainCands(c []wtransport.Candidate) {
	t.resolveMu.Lock()
	t.domainCands = append([]wtransport.Candidate(nil), c...)
	t.resolveMu.Unlock()
}

func sameCandidates(a, b []wtransport.Candidate) bool {
	if len(a) != len(b) {
		return false
	}
	// Relay 位参与比较（FIX-14）：同地址、不同腿类型的集合变化必须判「变了」
	// （否则重解析后的中继腿会被当成等价而无日志、且旧 relayEps 语义残留）。
	seen := map[netip.AddrPort]bool{}
	for _, x := range a {
		seen[x.Addr] = x.Relay
	}
	for _, y := range b {
		relay, ok := seen[y.Addr]
		if !ok || relay != y.Relay {
			return false
		}
	}
	return true
}

// RefreshReg 补发一条独立注册报文（周期刷新 / 探测失败后的快速恢复）。
// 出口的设备表按「最近一次成功注册」判活跃，长连设备靠它保持新鲜；出口重启或记录被回收后，
// 它也是本地无感故障的唯一恢复入口（配合 Rearm 触发全新握手）。
func (t *Transport) RefreshReg() bool { return t.core.Bind().RefreshReg() }

// ---- demand-driven-recovery 的信号透出（Bind 旁路信号，巡检/下推器消费） ----

// LocalSendErrWithin 最近 d 内是否发生过本地类发送错误（巡检失败拍的分类口径）。
func (t *Transport) LocalSendErrWithin(d time.Duration) bool {
	return t.core.Bind().LocalSendErrWithin(d)
}

// LocalSendErrCount / AdoptedLocalErrCount 本地类发送错误累计（诊断字段：全部/采纳路径）。
func (t *Transport) LocalSendErrCount() int64    { return t.core.Bind().LocalSendErrCount() }
func (t *Transport) AdoptedLocalErrCount() int64 { return t.core.Bind().AdoptedLocalErrCount() }

// LastRecvAt 最近一次收到对端包的时刻（待发包下推器的「接收静默」判据）。
func (t *Transport) LastRecvAt() time.Time { return t.core.Bind().LastRecvAt() }

// SwapTunOutboundPackets 取走自上次调用以来的 App 出站包数（巡检拍的需求判定）。
func (t *Transport) SwapTunOutboundPackets() int64 { return t.core.SwapTunOutboundPackets() }

// SwapSendStats 取走自上次调用以来的发送尝试数/本地失败数（评审 3-1 的
// 「全候选本地失败 ⇒ 环境性禁发」判据，与需求计数同拍对齐）。
func (t *Transport) SwapSendStats() (tries, localFails int64) {
	return t.core.Bind().SwapSendStats()
}

// LastTunOutboundAt 最近一次 App 出站包时刻（下推器的「出站新鲜」判据）。
func (t *Transport) LastTunOutboundAt() time.Time { return t.core.LastTunOutboundAt() }

// ResetPeerSession 丢弃本地 WG 会话（**保采纳**）：peer 移除再按原配置写回，
// 下一发出站包立即全新握手，但不清采纳路径、不重启赛跑。恢复阶梯的轻档
// （openspec recovery-ladder：会话死而路径/socket 活）用这档——
// 「网络没变、旧采纳地址仍有效」时比重赛跑少一轮镜像，也不抖路径。
func (t *Transport) ResetPeerSession() error {
	return t.core.ResetPeerSession()
}

// forceRehandshake 丢弃本地会话并重新武装候选赛跑（= 清采纳 + 丢会话）：下一发出站包
// 会立刻发起全新握手（而不是等客户端自己的 rekey 计时，最长 ~2 分钟）。
// 用于「出口重启 / 本设备记录被回收」：对端已经没有这段会话，本地却还以为它是好的。
func (t *Transport) forceRehandshake() {
	t.core.Bind().Rearm()
	if err := t.ResetPeerSession(); err != nil {
		t.logf("丢弃本地会话失败（%v）—— 继续按原会话重试", err)
	}
}

// Identity 本世代的设备身份（状态/诊断暴露短指纹；私钥不外出）。
func (t *Transport) Identity() *wtransport.Identity { return t.core.Identity() }

// Core 底层核（tunStatusJSON 取 TunIP 等核内派生值用）。
func (t *Transport) Core() *Core { return t.core }

// Status 传输层状态快照（映射进 tunStatusJSON 的 link 段）。
func (t *Transport) Status() wtransport.Status { return t.core.Bind().Status() }

// markSessionReady 会话跑通一次（首个成功往返）后调用：把采纳地址标为已验证、
// 用学习缓存重排候选。重复调用无副作用。
func (t *Transport) markSessionReady() {
	addr, relay, ok := t.core.Bind().Adopted()
	if !ok || relay || !addr.IsValid() {
		return
	}
	t.MarkRoundTrip(addr)
}

// NotePathAlive：一次存活探测（PathProbe 判活 / 阶梯验证探测）成功后调用——把**该时刻
// 的采纳地址**（探测所走路径）落已验证。覆盖「R3 刚救回会话后的闲置期」（无隧道内拨号
// 发生，旧 sessionMarked 只认拨号成功，那个窗口什么都不落——恰是漂移恢复的常态）。
func (t *Transport) NotePathAlive() {
	addr, relay, ok := t.core.Bind().Adopted()
	if !ok || relay || !addr.IsValid() {
		return
	}
	t.MarkRoundTrip(addr)
}

// MarkRoundTrip：**该地址完成一次真实往返**（隧道内拨号成功 / PathProbe 判活 / 阶梯验证
// 探测通过）→ 按地址去重落已验证（endpoint-freshness 评审 C-2 判定链：对象 = 该往返所用
// 地址；同地址 1 小时内不重复标——既防每拍巡检都写盘，又给长连路径留 VerifiedAt 刷新）。
// 仅凭「收到来自该地址的包」不落（防未认证源污染已验证标记）——调用方必须先确认往返成立。
func (t *Transport) MarkRoundTrip(addr netip.AddrPort) {
	if !addr.IsValid() {
		return
	}
	t.mu.Lock()
	if addr == t.lastMarked && time.Since(t.lastMarkedAt) < time.Hour {
		t.mu.Unlock()
		return
	}
	t.lastMarked = addr
	t.lastMarkedAt = time.Now()
	t.mu.Unlock()
	if t.cache == nil {
		return
	}
	src := wtransport.SourceHint
	for _, s := range t.static() {
		if s.Addr == addr {
			src = wtransport.SourceToken
			break
		}
	}
	t.cache.MarkVerifiedAndSave(addr, src, time.Now())
	t.core.Bind().SetCandidates(t.cache.Merge(t.static(), time.Now()))
}

// Probe 参照点探测：不依赖隧道状态，测「本机网络 → 该地址」的 UDP 可达性（三档归因数据源），
// 并顺带取回**出口能力位**（flags bit0 = 出口默认路径可承载 UDP，见 homeway server.UDPCapFlag）。
func (t *Transport) Probe(ctx context.Context, target netip.AddrPort) (time.Duration, string, byte, error) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return 0, "", 0, err
	}
	defer pc.Close()
	return probe.Ping(ctx, pc, target, "")
}

// probePad：旁路探测的请求填充长度——要拿到端点列表就得 pad 到期望最大应答长度
// （基础应答 ~47B + 满配列表 1+8×18=145B；200 留裕量）。与 pkg/probe.ReachPad
// （reach.go，add-host 连通性探测编排）**登记同源**：同值两处、注释互指、改必同改
// ——这里是巡检旁路探测的独立调用点，不为合并而合并（host-cli 1.1）。
const probePad = 200

// ProbeCandidates：**旁路观测**（endpoint-freshness）：对候选全集（仅直连条目——探测中继
// 端点拿到的是中继自己的端点列表，污染候选表）并发发起带 pad 的载荷探测，应答端点列表经
// Bind.OnProbed → 学习缓存（SourceProbe）。
//
// 旁路纪律（spec MUST）：候选全集必然含死地址（漂移后的旧 IP、蜂窝下的 LAN），失败是预期
// ——调用方不得把结果计入 failStreak/健康判定/恢复阶梯触发。本方法只写缓存与日志。
// 顺带触发一轮域名重解析（等待有界——DNS 慢不能拖死探测本身）。
func (t *Transport) ProbeCandidates(ctx context.Context) {
	if len(t.domainEps) > 0 && t.lookup != nil {
		rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		t.refreshDomainLocked(rctx) // 单飞由调用频度（60s 巡检拍）天然限住
		cancel()
	}
	cands := t.directCandidates()
	if len(cands) == 0 {
		return
	}
	var wg sync.WaitGroup
	learned := make([]int, len(cands))
	for i, cand := range cands {
		wg.Add(1)
		go func(i int, target netip.AddrPort) {
			defer wg.Done()
			pc, err := net.ListenUDP("udp", &net.UDPAddr{})
			if err != nil {
				return
			}
			defer pc.Close()
			pctx, cancel := context.WithTimeout(ctx, 4*time.Second)
			defer cancel()
			res, err := probe.PingEx(pctx, pc, target, "", probePad)
			if err != nil {
				return // 死候选是预期：静默
			}
			n := 0
			for _, ep := range res.Endpoints {
				if ep.IsValid() && probeAddrAcceptable(ep.Addr()) {
					t.core.Bind().DeliverProbed(ep.String())
					n++
				}
			}
			learned[i] = n
		}(i, cand)
	}
	wg.Wait()
	total := 0
	for _, n := range learned {
		total += n
	}
	if total > 0 {
		t.logf("旁路探测：%d 个直连候选，应答端点列表 %d 条已入学习缓存（来源=探测线索）",
			len(cands), total)
	}
}

// directCandidates：当前候选表里的直连条目（旁路探测目标）。
func (t *Transport) directCandidates() []netip.AddrPort {
	st := t.core.Bind().Status()
	var out []netip.AddrPort
	for _, c := range st.Candidates {
		if c.Relay {
			continue
		}
		if ap, err := netip.ParseAddrPort(c.Addr); err == nil && ap.IsValid() {
			out = append(out, ap)
		}
	}
	return out
}

// probeAddrAcceptable：探测线索的消费卫兵（与出口侧对称）：只要全球单播且不落
// fake-IP 段（198.18.0.0/15，代理 fake-IP）——应答无认证，不能让投喂污染候选表。
func probeAddrAcceptable(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.Is4() && (fakeIPRange.Contains(ip) || cgnatRange.Contains(ip)) {
		return false
	}
	return true
}

var (
	fakeIPRange = netip.MustParsePrefix("198.18.0.0/15") // Surge 等代理的 fake-IP 段
	cgnatRange  = netip.MustParsePrefix("100.64.0.0/10") // CGNAT（运营商大内网）
)

// Close 关闭会话门面（不关 Core；Core 生命周期由调用方管）。
func (t *Transport) Close() error { return nil }

func (t *Transport) noteDialResult(err error) {
	if err == nil {
		t.markSessionReady()
	}
}
