// Package wtransport：Homeway 手机核的自管 conn.Bind（wg-native-stack tasks 2.1/2.2）。
//
// 设计要点（对照 spike 01/02 与 tools/spikes/FINDINGS.md）：
//   - 单 UDP socket；device 的 peer endpoint 恒为伪端点 raceEP——路径知识全部收在
//     Bind 内（镜像/采纳/漫游/中继腿/reg 搭车），SetEndpointFromPacket(raceEP) 恒等、
//     不破坏间接层，候选集可随学习缓存动态更新而无需重配 device。
//   - 未采纳时出站包镜像到全部候选；reg 报文搭车：direct=同数据报 "HR" 前缀，
//     relay=type=2 帧先行（两数据报背靠背）。
//   - 收包：来自中继 listener 的腿帧 [0xBB][type][payload]（0=数据入 device /
//     1=hint 回调 / 2=忽略 / 未知=忽略）；其余来源视为直连裸 WG。
//   - Rebind 换本地 socket 不换 Identity（漫游=同钥换源地址，会话保持的关键）；
//     陈旧 socket 的读错在 ReceiveFunc 内换新重试，仅当前 socket 关闭才上抛
//     net.ErrClosed（device 只对它终止接收循环，FINDINGS 0.1 第 3 条）。
//   - Rearm 重启一轮赛跑：清采纳 + 重新武装 reg（自愈/重连/后端 peer 过期后调用）。
package wtransport

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
	"golang.zx2c4.com/wireguard/conn"
)

// Candidate 一条候选路径。
type Candidate struct {
	Addr  netip.AddrPort
	Relay bool
}

// handoverGrace 过渡双发宽限（FIX-09）：切到未知来源后旧路径保活时长——覆盖「出口
// 收一发回一发」的单次往返（真漂移时新路径即通，宽限后旧路径淡出；伪造源时旧路径
// 回包把采纳纠回）。
const handoverGrace = 10 * time.Second

// candidateKnownLocked src 是否属于候选/中继表（b.mu 内调用）。
func (b *Bind) candidateKnownLocked(src netip.AddrPort) bool {
	if _, ok := b.relayEps[src]; ok {
		return true
	}
	for _, c := range b.cfg.Candidates {
		if c.Addr == src {
			return true
		}
	}
	return false
}

// HintHandler 收到不可信地址线索（中继 hint）。回调里不得阻塞。
type HintHandler func(addr string)

type Config struct {
	PeerID     [32]byte // 后端静态公钥（中继路由键派生）
	Secret     [32]byte // token 凭证种子（reg HMAC）
	Identity   *Identity
	Candidates []Candidate
	OnHint     HintHandler
	// OnProbed：探测应答端点列表的线索回调（endpoint-freshness；非认证、hint 级——
	// 与 OnHint 分开：不触发 punch 盲打）。回调里不得阻塞。
	OnProbed HintHandler
	// DirectFirst：**直连优先窗口** —— 新一轮赛跑开始时，先只打直连候选；
	// 窗口内没有任何直连响应，才解锁中继候选（并立刻补发一次）。0 = 不启用（全部候选同时打）。
	// 口径（2026-09-19 用户定）：**中继永远只是直连的后备**，首次连接与重连都先试直连。
	DirectFirst time.Duration
	Logf        func(format string, args ...any)
}

// raceEP：device 侧恒定伪端点。
type raceEP struct{}

func (raceEP) ClearSrc()           {}
func (raceEP) SrcToString() string { return "unset" }
func (raceEP) DstToString() string { return "wtransport:race" }
func (raceEP) DstToBytes() []byte  { return nil }
func (raceEP) DstIP() netip.Addr   { return netip.Addr{} }
func (raceEP) SrcIP() netip.Addr   { return netip.Addr{} }

// Bind 实现 conn.Bind。
type Bind struct {
	cfg     Config
	relayID [8]byte

	mu             sync.Mutex
	conn           *net.UDPConn
	closed         bool             // 收工标志：Close 后 Rebind/RefreshReg 不再产生野 socket（见 Close 注释）
	recv           conn.ReceiveFunc // Open 时置位（测试直驱收包用）
	adopted        netip.AddrPort
	adoptedIsRelay bool
	valid          bool
	adoptedAt      time.Time
	lastRecvAt     time.Time
	mirrored       int
	regArmed       bool
	relayEps       map[netip.AddrPort]struct{}

	raceStart     time.Time // 本轮赛跑开始（解锁中继的计时基准）
	relayUnlocked bool      // 中继候选是否已解锁
	unlockOnce    bool      // 本轮是否已安排解锁补发
	lastMirror    []byte    // 最近一条镜像包（解锁时补发给中继候选）
	// 过渡双发（FIX-09）：稳态下从未知来源（非候选/非中继）切采纳时，旧路径保留为
	// 次要发送目标至 handoverUntil——出口不发无端包，「单发」会让伪造源/错投一票
	// 改写路径后形成「出站全打给错误地址 → 出口收不到我们 → 再无纠正包」的悬崖；
	// 双发下旧路径的回包会把采纳纠回（真漂移则新路径正常，宽限后自然淡出）。
	handoverTo    netip.AddrPort
	handoverRelay bool
	handoverUntil time.Time
	lastPathLogAt time.Time // 上一条「路径确立/切换」日志时刻（两条路同时有回包时限流）
	// recvErrAt：接收读错误的限流（每 5s 一行）——冻结唤醒后 OS 作废 socket 会持续报错。
	recvErrAt time.Time
	// readFrom 读接缝（生产 = (*net.UDPConn).ReadFromUDPAddrPort；单测注入错误序列验证
	// 「非收工类错误不交回 wg-go」的契约）。
	readFrom func(c *net.UDPConn, buf []byte) (int, netip.AddrPort, error)

	// raceSeen：本轮赛跑期间**出现过回包的来源**（排障判据：哪些候选路径是双向通的）。
	// 结算行在首次采纳时打出（胜者/响应过/未响应），之后静默——「直连候选到底有没有回包」
	// 从此有据可查（2026-09-20 真机「直连时好时坏」排查时的缺口）。
	raceSeen map[netip.AddrPort]bool
	// mirrorLogAt / mirrorLogN：MIRROR 行节流（FIX-13）——未采纳期每包一行会把 8MB
	// 日志轮转冲爆、吃掉故障现场；每轮赛跑限 3 行且间隔 ≥1s（全量计数在
	// Status().Mirrored，判据不丢）。
	mirrorLogAt time.Time
	mirrorLogN  int
	// lastSendErrAt：候选发送错误的限流（每候选 5s 一行；本地错误如「无路由」会每包重复）。
	lastSendErrAt map[netip.AddrPort]time.Time
	// lastLocalSendErrAt：最近一次**采纳路径**上本地类发送错误的时刻（demand-driven-
	// recovery D2 的粘性旁路信号；评审 H4 收窄：只认采纳路径——token 恒含 LAN 端点，
	// 蜂窝/异网下每次镜像发送都 ENETUNREACH，未采纳期若把它算进信号，会把「出口真
	// 不可达」整体掩盖成环境噪声。挂起禁发形态下采纳路径同样报 EPERM，收窄不削弱
	// 2026-09-23 事故的修复）。巡检失败拍消费 LocalSendErrWithin 而不是 err——写错误
	// 不回传拨号方，巡检只见超时。
	lastLocalSendErrAt time.Time
	// localErrCount / adoptedLocalErrCount：本地类发送错误的累计计数（诊断字段：
	// 前者含镜像候选（LAN 端点在异网下的必然 ENETUNREACH），后者只数采纳路径——
	// 两者之差即「环境性本地失败」的量级）。
	localErrCount        atomic.Int64
	adoptedLocalErrCount atomic.Int64
	// sendTries / sendLocalFails：**按巡检拍取走清零**的发送统计（评审 3-1）：
	// 尝试>0 且全部本地失败 = 环境性禁发（挂起 EPERM 全候选皆败；蜂窝下 LAN 候选
	// ENETUNREACH 但中继发得出去 ⇒ 不算全失败）——覆盖非采纳（赛跑）态下采纳路径
	// 粘性信号够不着的盲区，且与需求计数同拍对齐（消除 15s 尾窗的粒度错配）。
	sendTries      atomic.Int64
	sendLocalFails atomic.Int64
	// rxBytes / txBytes：WG 传输层的累计字节数（读 = 从对端收 / 写 = 向对端发）。
	// 隧道域的流量计数在 hub fd 层（TUN 面，FdStats）；服务会话没有 TUN，界面
	// 「上下行流量」用这一份（含握手/保活与封装开销，量级与 fd 计数相当）。
	rxBytes atomic.Int64
	txBytes atomic.Int64
}

func NewBind(cfg Config) *Bind {
	b := &Bind{
		cfg:      cfg,
		relayID:  proto.RelayID(cfg.PeerID),
		regArmed: true,
	}
	b.rebuildRelayEps()
	if b.cfg.Logf == nil {
		b.cfg.Logf = func(string, ...any) {}
	}
	return b
}

// SetCandidates 更新候选集（学习缓存刷新后调用），并重建中继端点表。
// **只在集合真的变了时**打一行：多 IP 选择的现场证据（学到新端点/端点被剔掉的时刻）。
func (b *Bind) SetCandidates(cands []Candidate) {
	b.mu.Lock()
	changed := !sameCandidates(b.cfg.Candidates, cands)
	b.cfg.Candidates = cands
	b.rebuildRelayEpsLocked() // 同临界区内重建（FIX-10）：收包路径在锁内读 relayEps，
	b.mu.Unlock()             // 分离重建会让新中继候选在窗口内被误判直连（裸发被中继丢）
	if changed {
		b.cfg.Logf("候选集更新：%d 条（%s）", len(cands), DescribeCandidates(cands))
	}
}

// sameCandidates：集合比较（忽略顺序）：学习缓存合并出来的列表顺序可能不同，但内容一样不应刷日志。
func sameCandidates(a, c []Candidate) bool {
	if len(a) != len(c) {
		return false
	}
	// Relay 位参与比较（FIX-14 同源修正）：腿类型变化也是「集合变了」。
	seen := make(map[netip.AddrPort]bool, len(a))
	for _, x := range a {
		seen[x.Addr] = x.Relay
	}
	for _, x := range c {
		relay, ok := seen[x.Addr]
		if !ok || relay != x.Relay {
			return false
		}
	}
	return true
}

// DescribeCandidates：候选一行摘要（直连/中继 + LAN/公网v4/IPv6），日志/诊断用。
func DescribeCandidates(cands []Candidate) string {
	return DescribeCandidatesWithLearned(cands, nil)
}

// DescribeCandidatesWithLearned：同 DescribeCandidates，但把**不在 static 里**的候选标成「·学习」——
// 学习端点（巡检落盘 + 中继 hint）与 token 里写死的端点混在一张表里，复盘时必须能一眼分开。
func DescribeCandidatesWithLearned(cands, static []Candidate) string {
	known := make(map[netip.AddrPort]bool, len(static))
	for _, c := range static {
		known[c.Addr] = true
	}
	parts := make([]string, 0, len(cands))
	for _, c := range cands {
		tag := candidateTag(c.Addr, c.Relay)
		if len(known) > 0 && !known[c.Addr] {
			tag += "·学习"
		}
		parts = append(parts, fmt.Sprintf("%s(%s)", c.Addr, tag))
	}
	return strings.Join(parts, "、")
}

func candidateTag(ap netip.AddrPort, relay bool) string {
	if relay {
		return "中继"
	}
	switch {
	case ap.Addr().Is6():
		return "IPv6"
	case ap.Addr().IsPrivate() || ap.Addr().IsLoopback() || ap.Addr().IsLinkLocalUnicast():
		return "LAN"
	default:
		return "公网v4"
	}
}

func pathKind(relay bool) string {
	if relay {
		return "中继"
	}
	return "直连"
}

func (b *Bind) rebuildRelayEps() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rebuildRelayEpsLocked()
}

// rebuildRelayEpsLocked 由候选集重建中继端点表（调用方持锁——FIX-10：与
// cfg.Candidates 的写入同临界区，收包路径的 relay 判定不再有旧表窗口）。
func (b *Bind) rebuildRelayEpsLocked() {
	b.relayEps = make(map[netip.AddrPort]struct{}, len(b.cfg.Candidates))
	for _, c := range b.cfg.Candidates {
		if c.Relay {
			b.relayEps[c.Addr] = struct{}{}
		}
	}
}

// Rearm 重启一轮**新鲜赛跑**：先试直连，直连全无响应才解锁中继（见 Config.DirectFirst）。
// 用于：首次连接、换网重绑、自愈重建等"当前没有可用路径"的时刻。
func (b *Bind) Rearm() {
	b.mu.Lock()
	b.valid = false
	b.regArmed = true
	b.raceStart = time.Now()
	b.relayUnlocked = len(b.directCountLocked()) == 0 // 没有直连候选就没什么可等的
	b.unlockOnce = false
	b.raceSeen = nil // 新一轮赛跑：清掉上一轮的来源记录
	b.mirrorLogN = 0 // 新一轮：MIRROR 行配额复位（FIX-13）
	b.mu.Unlock()
	b.cfg.Logf("RARM 候选赛跑重启（直连优先：中继在 %v 后才解锁）", b.cfg.DirectFirst)
}

// RearmSoft 重启一轮**软赛跑**：中继立刻参与。用于"当前已经在用中继，只想试着升到直连"的时刻
// （hint 打洞、停留中继的定期升级）—— 这些时刻不能因为等直连而把在用的中继路径停掉。
func (b *Bind) RearmSoft() {
	b.mu.Lock()
	b.valid = false
	b.regArmed = true
	b.raceStart = time.Now()
	b.relayUnlocked = true
	b.unlockOnce = true
	b.raceSeen = nil
	b.mirrorLogN = 0 // 新一轮：MIRROR 行配额复位（FIX-13）
	b.mu.Unlock()
	b.cfg.Logf("RARM 软赛跑（中继立即参与，同时试直连）")
}

// directCountLocked：直连候选数（调用方持锁）。
func (b *Bind) directCountLocked() []Candidate {
	var out []Candidate
	for _, c := range b.cfg.Candidates {
		if !c.Relay {
			out = append(out, c)
		}
	}
	return out
}

// SetOnHint 设置 hint 回调（学习缓存接线用：核心把它接到 cache.Observe(SourceHint)）。
func (b *Bind) SetOnHint(h HintHandler) {
	b.mu.Lock()
	b.cfg.OnHint = h
	b.mu.Unlock()
}

// deliverHint 主动投递一条地址线索给 hint 回调（带内通告/测试注入用；
// 中继腿上的控制帧走收包路径，最终也落到同一个回调）。
func (b *Bind) deliverHint(addr string) {
	b.mu.Lock()
	h := b.cfg.OnHint
	b.mu.Unlock()
	if h != nil {
		h(addr)
	}
}

// SetOnProbed 设置探测线索回调（endpoint-freshness：旁路探测应答的端点列表 →
// cache.Observe(SourceProbe)。与 hint 分开两条通道：探测线索**不触发** punchTo 盲打
// ——它没有「对端在等我打洞」的语义，最多对赛跑获胜那条发）。
func (b *Bind) SetOnProbed(h HintHandler) {
	b.mu.Lock()
	b.cfg.OnProbed = h
	b.mu.Unlock()
}

// DeliverProbed 投递一条探测应答端点（旁路探测消费/测试注入用）。
func (b *Bind) DeliverProbed(addr string) {
	b.mu.Lock()
	h := b.cfg.OnProbed
	b.mu.Unlock()
	if h != nil {
		h(addr)
	}
}

// Adopted 返回当前采纳路径。
func (b *Bind) Adopted() (addr netip.AddrPort, relay, valid bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.adopted, b.adoptedIsRelay, b.valid
}

// via 词表（链路形态三态——contract-ledger 台账族⑪ via 子族，只增不改；App 的
// applyLink/ExitHealth 按值分派。历史值 tunnel 仅 App 侧保留分支，本仓零产出者
// = legacy-unreachable。4b 2.1 提常量前是 Status() 里的赋值字面量）。
const (
	viaNone   = "none"
	viaRelay  = "relay"
	viaDirect = "direct"
)

// Status：状态上报数据源（tasks 2.6）。核心把它映射进既有 tunStatusJSON 的 link 段
// （契约键名 via/ep 不变：via ∈ direct|relay|none），其余字段供诊断/候选展示。
type Status struct {
	Via        string            `json:"via"`                 // direct | relay | none
	Ep         string            `json:"ep,omitempty"`        // 当前采纳路径地址
	At         int64             `json:"at,omitempty"`        // 最后一次从采纳路径收到包（unix 毫秒）
	AdoptedAt  int64             `json:"adoptedAt,omitempty"` // 当前路径最近一次被确认（unix 毫秒）
	Mirrored   int               `json:"mirrored"`            // 未采纳前的镜像计数
	Candidates []CandidateStatus `json:"candidates,omitempty"`
}

// CandidateStatus 候选快照（addr/relay/adopted）。
type CandidateStatus struct {
	Addr    string `json:"addr"`
	Relay   bool   `json:"relay,omitempty"`
	Adopted bool   `json:"adopted,omitempty"`
}

// Status 取当前传输层状态快照。
func (b *Bind) Status() Status {
	b.mu.Lock()
	defer b.mu.Unlock()
	st := Status{Via: viaNone, Mirrored: b.mirrored}
	if b.valid {
		if b.adoptedIsRelay {
			st.Via = viaRelay
		} else {
			st.Via = viaDirect
		}
		st.Ep = b.adopted.String()
	}
	if !b.adoptedAt.IsZero() {
		st.AdoptedAt = b.adoptedAt.UnixMilli()
	}
	if !b.lastRecvAt.IsZero() {
		st.At = b.lastRecvAt.UnixMilli()
	}
	for _, c := range b.cfg.Candidates {
		st.Candidates = append(st.Candidates, CandidateStatus{
			Addr:    c.Addr.String(),
			Relay:   c.Relay,
			Adopted: b.valid && c.Addr == b.adopted,
		})
	}
	return st
}

func (b *Bind) curConn() *net.UDPConn {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.conn
}

// readOnce 一次 socket 读（生产 = 真实系统调用；单测经 readFrom 接缝注入错误序列）。
func (b *Bind) readOnce(c *net.UDPConn, buf []byte) (int, netip.AddrPort, error) {
	b.mu.Lock()
	rf := b.readFrom
	b.mu.Unlock()
	if rf != nil {
		return rf(c, buf)
	}
	return c.ReadFromUDPAddrPort(buf)
}

func unmap4in6(ap netip.AddrPort) netip.AddrPort {
	if ap.Addr().Is4In6() {
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return ap
}

// ---------- conn.Bind ----------

func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	// 双栈：同一个 socket 既能发 IPv4 也能发 IPv6 —— 出口若公布 [2408:...]:41641，
	// 客户端就能直接走 v6 承载（v6 无 NAT，通常比 v4 更容易直连）。
	c, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	b.mu.Lock()
	b.conn = c
	// 重开即复活：wireguard-go 的 BindUpdate 先 closeBindLocked（会 Close 一个从未/已打开的
	// bind）再 Open——那次 Close 是换绑流程的一部分，不是终局；不复位的话最终 teardown 的
	// Close 会被幂等位吞掉、不关活 socket，接收 goroutine 永远退不出去（真机测试挂死根因）。
	b.closed = false
	b.recvErrAt = time.Time{} // 限流复位（评审②）：新 socket 的首个错误要能立刻打出日志
	b.raceStart = time.Now()
	b.relayUnlocked = len(b.directCountLocked()) == 0
	b.mu.Unlock()
	actual := uint16(c.LocalAddr().(*net.UDPAddr).Port)

	fn := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			c := b.curConn()
			if c == nil {
				// 防御（评审②）：curConn 在 Close 后不置 nil，今天不可达；但
				// (*net.UDPConn)(nil).ReadFromUDPAddrPort 实测是 panic——将来有人在
				// Close 里顺手置 nil 就会从「慢转」变成 goroutine 内 panic（c-shared
				// 会带走 App 进程）。按契约返回 ErrClosed。
				return 0, net.ErrClosed
			}
			n, src, err := b.readOnce(c, packets[0])
			if err == nil {
				b.rxBytes.Add(int64(n))
			}
			if err != nil {
				b.mu.Lock()
				closed, stale := b.closed, c != b.conn
				b.mu.Unlock()
				if stale {
					continue // 陈旧 socket（Rebind 已换新）：换新重试（不走慢转，立即接新）
				}
				if closed {
					// 收工：Bind.Close 语义。契约（conn/conn.go）要求 Close 后必须返回
					// net.ErrClosed——交回原样错误时实测也是它，这里显式钉死意图。
					return 0, net.ErrClosed
				}
				// 当前 socket 的**非收工类**读错误（真机 2026-09-22 冻结唤醒：OS 作废
				// socket，读侧 ECONNABORTED 一族、与 sendto 同款 errno）：绝不把错误
				// 交回 wg-go——它的 RoutineReceiveIncoming 对 non-Temporary 错误直接
				// return（Temporary 类也一样：deathSpiral 上限 10 次 ≈3.3s 后照样
				// return），读 goroutine 就此死亡 ⇒ Bind 永久失聪（发得出/收不到，
				// 换源也救不回，曾只剩整会话重建一条路）。吞掉错误原地慢转：R2 换源
				// 把新 socket 换进来时本循环自动接上，阶梯恢复秒级。
				b.mu.Lock()
				now := time.Now()
				shouldLog := now.Sub(b.recvErrAt) >= 5*time.Second
				if shouldLog {
					b.recvErrAt = now
				}
				b.mu.Unlock()
				if shouldLog {
					b.cfg.Logf("接收读错误（%v）：原地重试等换源/收工（不交回 wg-go——读 goroutine 死亡=永久失聪）", err)
				}
				time.Sleep(300 * time.Millisecond)
				continue
			}
			src = unmap4in6(src)

			b.mu.Lock()
			_, isRelayEp := b.relayEps[src]
			now := time.Now()
			prevWasRelay := b.valid && b.adoptedIsRelay
			prevAdopted, wasValid := b.adopted, b.valid
			b.adopted, b.adoptedIsRelay, b.valid = src, isRelayEp, true
			// 过渡双发登记（FIX-09）：稳态下切到「未知来源」= 保留旧路径宽限双发；
			// 切到候选/中继（hint/probe 学习路径）或首次采纳 = 清过渡（无需保旧）。
			if wasValid && prevAdopted != src && !isRelayEp && !b.candidateKnownLocked(src) {
				b.handoverTo, b.handoverRelay = prevAdopted, prevWasRelay
				b.handoverUntil = now.Add(handoverGrace)
			} else if prevAdopted != src {
				b.handoverTo, b.handoverUntil = netip.AddrPort{}, time.Time{}
			}
			// 已知限制（demand-driven-recovery 评审）：lastRecvAt 在帧解码前刷新——任意
			// 来源的包（含中继 hint/控制帧与未知来源）都会重置待发包判据的 90s 静默，
			// 下推器由此退化为巡检兜底（不产生错误状态）。收紧到「数据帧/候选来源」
			// 属收包热路径改动，留待后续按需做。
			b.adoptedAt, b.lastRecvAt = now, now
			if b.raceSeen == nil {
				b.raceSeen = make(map[netip.AddrPort]bool)
			}
			b.raceSeen[src] = true
			// 路径确立/切换：**多 IP 选择的核心证据**（巡检的 link 行是 60s 采样，会漏掉中途的跳变）。
			// 只在地址真的变了时记，且 3s 内最多一条 —— 两条路径同时有回包时不会刷屏。
			logPath := (!wasValid || prevAdopted != src) && now.Sub(b.lastPathLogAt) >= 3*time.Second
			if logPath {
				b.lastPathLogAt = now
			}
			directN := len(b.directCountLocked())
			// 赛跑结算（本轮首次采纳时打一次）：胜者 / 响应过的候选 / 全程未响应的候选。
			// 这是「直连候选有没有回包」的直接判据（镜像行只说明发过，不说明对方应过）。
			var settle string
			if !wasValid {
				var okList, missList []string
				for _, c := range b.cfg.Candidates {
					if b.raceSeen[c.Addr] {
						okList = append(okList, c.Addr.String())
					} else {
						missList = append(missList, candidateTag(c.Addr, c.Relay)+" "+c.Addr.String())
					}
				}
				settle = fmt.Sprintf("赛跑结算：胜出 %s %v（镜像 %d 包，耗时 %v）；响应过=%v；未响应=%v",
					pathKind(isRelayEp), src, b.mirrored, now.Sub(b.raceStart).Round(time.Millisecond),
					strings.Join(okList, "、"), strings.Join(missList, "、"))
			}
			b.mu.Unlock()

			if settle != "" {
				b.cfg.Logf("%s", settle)
			}

			if logPath {
				if !wasValid {
					b.cfg.Logf("路径确立：%s %v（首个回包来源）", pathKind(isRelayEp), src)
				} else {
					b.cfg.Logf("路径切换：%s %v → %s %v", pathKind(prevWasRelay), prevAdopted, pathKind(isRelayEp), src)
				}
			}

			// 「走中继」= 需要排查的 bug（口径 2026-09-19）：出口有公网端点/UPnP 时客户端应当直连，
			// 只有直连候选全部失败才允许落到中继。**在采纳点记**（这里 100% 能看到每一次跳变，
			// 而 App/巡检是采样，1 秒的中继窗口会被漏掉）；真落到中继时把判据一并带上。
			if isRelayEp && !prevWasRelay {
				b.cfg.Logf("⚠️ 链路走了中继（本应直连，属需排查的 bug）：ep=%v，直连候选 %d 个全未响应"+
					"（可能原因：直连地址不可达 / 出口公网映射失效 / 打洞失败）", src, directN)
			}

			if isRelayEp {
				typ, payload, err := proto.DecodeFrame(packets[0][:n])
				if err != nil {
					continue // 畸形腿帧：丢弃继续读
				}
				switch typ {
				case proto.FrameTypeData:
					sizes[0] = len(payload)
					copy(packets[0], payload)
					eps[0] = raceEP{}
					return 1, nil
				case proto.FrameTypeControl:
					// 判据日志：hint 到达/缺失一眼可见（打洞链路的第一环）
					if addr, err := proto.DecodeHintPayload(payload); err == nil {
						b.mu.Lock()
						hasHint := b.cfg.OnHint != nil
						b.mu.Unlock()
						if hasHint {
							b.cfg.Logf("HINT 收到对端地址线索 %s（来自中继 %v）", addr, src)
						} else {
							b.cfg.Logf("HINT 收到对端地址线索 %s，但没有处理器（缓存未接？）", addr)
						}
						// 锁内取、锁外调（FIX-15）：回调会经 SetCandidates 回锁——持锁调必死锁。
						b.deliverHint(addr)
					}
					continue
				default: // reg（服务端概念）与未知类型：忽略
					continue
				}
			}
			// 直连裸 WG
			sizes[0] = n
			eps[0] = raceEP{}
			return 1, nil
		}
	}
	b.mu.Lock()
	b.recv = fn
	b.mu.Unlock()
	return []conn.ReceiveFunc{fn}, actual, nil
}

// Close 收工（幂等）。**锁内完成「置位 + 关当前」**（评审 P0-2）：与 Rebind 的
// 「换入新 socket → 关旧」竞态时，若 Close 先在锁外读到旧 conn、Rebind 随后换入新 conn，
// 新 socket 就没人关——接收循环还会按「陈旧 socket 换新重试」继续读它，成为僵尸 Bind
// （每 5s 重试握手、搅乱出口 peer 表的经典事故形态）。收工位同时挡住之后的 Rebind/RefreshReg。
// conn 不置 nil：接收循环靠「读错且仍是当前 socket」判定 ErrClosed 语义退出。
func (b *Bind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil // 已收工（幂等）
	}
	b.closed = true
	if b.conn == nil {
		return nil
	}
	return b.conn.Close()
}

func (b *Bind) SetMark(mark uint32) error { return nil }

func (b *Bind) BatchSize() int { return 1 }

func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if _, ok := ep.(raceEP); !ok {
		return fmt.Errorf("wtransport: 未知 endpoint 类型 %T（应恒为 raceEP）", ep)
	}
	c := b.curConn()
	if c == nil {
		return fmt.Errorf("wtransport: bind 未打开")
	}

	b.mu.Lock()
	valid, adopted, adoptedIsRelay := b.valid, b.adopted, b.adoptedIsRelay
	handover, handoverRelay := b.handoverTo, b.handoverRelay
	handoverOn := handover.IsValid() && time.Now().Before(b.handoverUntil)
	var regPkt []byte
	if b.regArmed && b.cfg.Identity != nil {
		regPkt = b.cfg.Identity.Reg(b.cfg.Secret)
		b.regArmed = false
	}
	b.mu.Unlock()

	for _, buf := range bufs {
		if valid {
			err := b.sendTo(c, adopted, adoptedIsRelay, buf)
			if err != nil {
				b.noteSendErr(adopted, err)
			} else {
				b.txBytes.Add(int64(len(buf)))
			}
			if handoverOn && handover != adopted {
				// 过渡双发（FIX-09，见 handoverGrace 注释）：尽力语义，不进发送计数。
				_ = b.sendToSilent(c, handover, handoverRelay, buf)
			}
			continue
		}
		b.mu.Lock()
		b.mirrored++
		m := b.mirrored
		cands := append([]Candidate(nil), b.cfg.Candidates...)
		// 直连优先：窗口内只打直连；窗口到了（或没有直连候选）才解锁中继并补发一次。
		relayOK := b.relayUnlocked || len(b.directCountLocked()) == 0 ||
			b.cfg.DirectFirst <= 0 || time.Since(b.raceStart) >= b.cfg.DirectFirst
		if relayOK && !b.relayUnlocked {
			b.relayUnlocked = true
		}
		needTimer := !relayOK && !b.unlockOnce
		if needTimer {
			b.unlockOnce = true
		}
		lastReg := regPkt
		b.lastMirror = append([]byte(nil), buf...)
		b.mu.Unlock()

		sent, relaySent := 0, 0
		for _, cd := range cands {
			if cd.Relay && !relayOK {
				continue
			}
			b.writeCandidate(c, cd, buf, regPkt)
			sent++
			if cd.Relay {
				relaySent++
			}
		}
		// 赛跑期的一条包镜像到多个候选，但这只是一条逻辑出站包：按包记一次。
		b.txBytes.Add(int64(len(buf)))
		b.mu.Lock()
		now := time.Now()
		logMirror := b.mirrorLogN < 3 && now.Sub(b.mirrorLogAt) >= time.Second
		if logMirror {
			b.mirrorLogN++
			b.mirrorLogAt = now
		}
		b.mu.Unlock()
		if logMirror {
			b.cfg.Logf("MIRROR 镜像包#%d → %d 候选（直连优先：本次直连 %d / 中继 %d；本行每轮限 3 条）", m, sent, sent-relaySent, relaySent)
		}
		if needTimer {
			window := b.cfg.DirectFirst
			go func(pkt, reg []byte) {
				time.Sleep(window)
				b.mu.Lock()
				if b.valid || b.relayUnlocked { // 直连已经赢了 / 已解锁：收工
					b.mu.Unlock()
					return
				}
				b.relayUnlocked = true
				cands := append([]Candidate(nil), b.cfg.Candidates...)
				b.mu.Unlock()
				n := 0
				for _, cd := range cands {
					if !cd.Relay {
						continue
					}
					b.writeCandidate(c, cd, pkt, reg)
					n++
				}
				if n > 0 {
					b.cfg.Logf("MIRROR 直连窗口 %v 内无响应 → 解锁中继候选 %d 个并补发一次", window, n)
				}
			}(append([]byte(nil), buf...), lastReg)
		}
	}
	return nil
}

// writeCandidate：把一条包发到某个候选（中继候选要套腿帧与路由标签；直连搭车 reg）。
// 发送失败显式记录（每候选 5s 限流，走 noteMirrorSendErr——镜像口径：不刷粘性信号，
// 评审 H4）——「无路由/EHOSTUNREACH」这类**本地就失败**的候选与「发出去石沉大海」
// 从此可分（2026-09-20 直连排查缺口：之前错误全被丢弃）。
func (b *Bind) writeCandidate(c *net.UDPConn, cd Candidate, buf, regPkt []byte) {
	if cd.Relay {
		if regPkt != nil {
			if err := b.writeUDP(c, proto.EncodeTagged(b.relayID, proto.FrameTypeReg, regPkt), cd.Addr); err != nil {
				b.noteMirrorSendErr(cd.Addr, err)
			}
		}
		if err := b.writeUDP(c, proto.EncodeTagged(b.relayID, proto.FrameTypeData, buf), cd.Addr); err != nil {
			b.noteMirrorSendErr(cd.Addr, err)
		}
		return
	}
	if regPkt != nil {
		joined := append(append([]byte{}, regPkt...), buf...)
		if err := b.writeUDP(c, joined, cd.Addr); err != nil {
			b.noteMirrorSendErr(cd.Addr, err)
		}
		return
	}
	if err := b.writeUDP(c, buf, cd.Addr); err != nil {
		b.noteMirrorSendErr(cd.Addr, err)
	}
}

// writeUDP：UDP 写的统一计数点（评审 3-1 的按拍统计——所有数据/reg 写都过这里，
// 含采纳与镜像、同步路径与解锁补发 goroutine）。
func (b *Bind) writeUDP(c *net.UDPConn, buf []byte, addr netip.AddrPort) error {
	b.sendTries.Add(1)
	_, err := c.WriteToUDPAddrPort(buf, addr)
	if err != nil && isLocalSendErr(err) {
		b.sendLocalFails.Add(1)
	}
	return err
}

// sendTo 采纳路径的封装发送（按目标类型决定是否套腿帧）。
func (b *Bind) sendTo(c *net.UDPConn, addr netip.AddrPort, isRelay bool, buf []byte) error {
	if isRelay {
		return b.writeUDP(c, proto.EncodeTagged(b.relayID, proto.FrameTypeData, buf), addr)
	}
	return b.writeUDP(c, buf, addr)
}

// sendToSilent 同 sendTo 但不进发送计数（过渡双发为尽力语义：旧路径的本地错误
// 不得污染「环境性禁发」判据的 sendTries/sendLocalFails）。
func (b *Bind) sendToSilent(c *net.UDPConn, addr netip.AddrPort, isRelay bool, buf []byte) error {
	if isRelay {
		_, err := c.WriteToUDPAddrPort(proto.EncodeTagged(b.relayID, proto.FrameTypeData, buf), addr)
		return err
	}
	_, err := c.WriteToUDPAddrPort(buf, addr)
	return err
}

// RxTx WG 传输层的累计字节数（rx = 从对端收 / tx = 向对端发；服务会话的流量面，
// 见字段注释）。随世代清零（新会话 = 新 Bind）。
func (b *Bind) RxTx() (rx, tx int64) { return b.rxBytes.Load(), b.txBytes.Load() }

// SwapSendStats 取走并清零「自上次调用以来的发送尝试数 / 其中本地失败数」
// （巡检拍头与 SwapTunOutboundPackets 同拍消费）。
func (b *Bind) SwapSendStats() (tries, localFails int64) {
	return b.sendTries.Swap(0), b.sendLocalFails.Swap(0)
}

// isLocalSendErr：本地类发送错误——sendto/write 同步返回的错误（EPERM/EACCES/
// 无路由等），与「发出去石沉大海」的对端无响应相反。挂起态下系统禁发网络正是这个
// 形态（2026-09-23 弹窗事故：整夜唤醒窗口全部命中），它对路径质量零信息量。
// UDP 写失败基本只有本地类（无连接语义），判据即 *net.OpError 且 Op 为写系。
func isLocalSendErr(err error) bool {
	var oe *net.OpError
	if errors.As(err, &oe) {
		switch oe.Op {
		case "write", "send", "sendto", "writeto":
			return true
		}
	}
	return false
}

// noteSendErr：**采纳路径**发送失败（限流日志 + H4 收窄后的粘性信号）——本地类刷
// lastLocalSendErrAt（巡检的证据分类口径）并累计 adoptedLocalErrCount。
func (b *Bind) noteSendErr(addr netip.AddrPort, err error) {
	if isLocalSendErr(err) {
		b.mu.Lock()
		b.lastLocalSendErrAt = time.Now()
		b.mu.Unlock()
		b.adoptedLocalErrCount.Add(1)
	}
	b.logSendErr(addr, err)
}

// noteMirrorSendErr：镜像候选发送失败——只日志与诊断计数，**不刷粘性信号**（评审 H4：
// 候选集必含 LAN 端点，异网下必然本地失败，不能把「出口真不可达」掩盖成环境噪声）。
func (b *Bind) noteMirrorSendErr(addr netip.AddrPort, err error) {
	if isLocalSendErr(err) {
		b.localErrCount.Add(1)
	}
	b.logSendErr(addr, err)
}

// logSendErr：发送错误一行（每目标 5s 条；本地错误是粘性的，不限流会每包刷屏）。
func (b *Bind) logSendErr(addr netip.AddrPort, err error) {
	b.mu.Lock()
	if b.lastSendErrAt == nil {
		b.lastSendErrAt = make(map[netip.AddrPort]time.Time)
	}
	last := b.lastSendErrAt[addr]
	now := time.Now()
	if now.Sub(last) < 5*time.Second {
		b.mu.Unlock()
		return
	}
	b.lastSendErrAt[addr] = now
	b.mu.Unlock()
	b.cfg.Logf("发送失败：%v（%v；本地错误=该候选在本机就发不出去，与对端无响应是两回事）", addr, err)
}

// LocalSendErrWithin：最近 d 内**采纳路径**是否发生过本地类发送错误（巡检失败拍的
// 消费口径——命中即该拍失败按环境噪声处理、清零计数，demand-driven-recovery D2）。
func (b *Bind) LocalSendErrWithin(d time.Duration) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.lastLocalSendErrAt.IsZero() && time.Since(b.lastLocalSendErrAt) < d
}

// LocalSendErrCount / AdoptedLocalErrCount 本地类发送错误累计（诊断字段：全部/采纳路径）。
func (b *Bind) LocalSendErrCount() int64    { return b.localErrCount.Load() }
func (b *Bind) AdoptedLocalErrCount() int64 { return b.adoptedLocalErrCount.Load() }

// LastRecvAt 最近一次收到对端包的时刻（待发包下推器的「接收静默」判据数据源；
// 零值 = 从未收到）。
func (b *Bind) LastRecvAt() time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lastRecvAt
}

func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	if s == "race" {
		return raceEP{}, nil
	}
	return nil, fmt.Errorf("wtransport: endpoint %q 不支持（只认 race 伪端点）", s)
}

// Rebind 换本地 socket（换网）；不换 Identity。收工后调用报错并关掉新起的 socket
// （此时没有接收循环接管它，留着就是野 socket——tunStopWait 收工窗口期的并发下推
// 会走到这里，评审 P0-2）。
func (b *Bind) Rebind() error {
	c, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		return err
	}
	b.mu.Lock()
	if b.closed {
		port := c.LocalAddr().(*net.UDPAddr).Port
		b.mu.Unlock()
		c.Close()
		return fmt.Errorf("wtransport: bind 已收工（新起的 %d 端口 socket 已关）", port)
	}
	old := b.conn
	b.conn = c
	b.recvErrAt = time.Time{} // 限流复位（评审②）：新 socket 的首个错误要能立刻打出日志
	port := c.LocalAddr().(*net.UDPAddr).Port
	b.mu.Unlock()
	old.Close()
	b.cfg.Logf("REBIND 本地端口 → %d（Identity 不变）", port)
	return nil
}

// RefreshReg 补发一条**独立**注册报文：不依赖 WG 会话可用、不改 valid/adopted。
//
// 为什么需要它：已采纳路径的 Send 分支会把搭车的 regPkt 丢掉（见 Send），所以隧道存活期间
// 无法靠搭车重新注册。出口重启（设备表清空）或本设备记录被 TTL/淘汰回收之后，手机侧原本
// 没有任何信号——只能等巡检 3 连败（≈2–4 分钟）走整套自重绑。周期调用它可推进出口的活跃时间；
// 探测失败时立即调用它，可以把恢复提前到「一次巡检内」。
//
// 发送路径 = 已采纳地址（direct = 裸腿帧 [0xBB][2][reg]；relay = 带路由标签的腿帧）。
// 未采纳（从未连上）时返回 false —— 首次建连的注册由 Send 搭车负责。
func (b *Bind) RefreshReg() bool {
	if b.cfg.Identity == nil {
		return false
	}
	c := b.curConn()
	if c == nil {
		return false
	}
	b.mu.Lock()
	adopted, isRelay, closed := b.adopted, b.adoptedIsRelay, b.closed
	b.mu.Unlock()
	if closed || !adopted.IsValid() {
		return false
	}
	reg := b.cfg.Identity.Reg(b.cfg.Secret)
	var err error
	if isRelay {
		err = b.writeUDP(c, proto.EncodeTagged(b.relayID, proto.FrameTypeReg, reg), adopted)
	} else {
		err = b.writeUDP(c, proto.EncodeFrame(proto.FrameTypeReg, reg), adopted)
	}
	if err != nil {
		b.cfg.Logf("RREG 注册刷新发送失败（%v）", err)
		return false
	}
	b.cfg.Logf("RREG 注册刷新 → %v（dev=%s，中继=%v）", adopted, b.cfg.Identity.ShortDev(), isRelay)
	return true
}

// Port 当前本地端口（诊断）。
func (b *Bind) Port() uint16 {
	c := b.curConn()
	if c == nil {
		return 0
	}
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}
