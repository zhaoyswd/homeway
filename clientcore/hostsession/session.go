package hostsession

// session.go — 「出口会话」的传输面（wg-native-stack tasks 4.1 起的唯一实现；
// 随迁自 cshared session.go，host-registry-daemon D1）。
//
// 核里对外只有三件事：拨出口主机本机端口、拨任意目标、存活探测；外加关闭。
// 实现 = *wgcore.Transport（WG + 隧道侧 netstack）。**换传输 = 换这里的构造**，
// 留守 cshared 的调用点一行不动。接缝保留为接口（ExitSession）是给测试假会话
// （fakeExitSession）用的——生产构造（BuildExitSession）只会产出 newSession。
//
// 差异随迁说明：原文件的 startSession（隧道世代装配，引用留守的 tunRun）**留守
// cshared**，经 BuildExitSession 走本构造；隧道域与本包的差异只在生命周期管理
// （run/世代 vs 独立状态机）。

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/internal/wgcore"
	"github.com/zhaoyswd/homeway/clientcore/internal/wtransport"
	"github.com/zhaoyswd/homeway/pkg/proto"
)

// ExitSession：本世代出口会话（传输面）。
//
// 只有 TCP 面：L3 直通后应用 UDP 由 TUN 直通出口过境拦截，手机核不再承载 UDP 会话
// （review 复审 #1 收尾：DialUDP/exitUDP 整条死管线已删）。
type ExitSession interface {
	DialTCPPort(ctx context.Context, port uint16) (net.Conn, error)
	DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
	// PathProbe 存活判据（巡检/换网重绑/自重绑共用）：返回 nil = 对端可达。
	// 旧栈 = 两级判据（已注册走 disco ping，未注册走握手+隧道内往返）；
	// 新栈 = 隧道内 TCP 拨一个必然被拒的端口（拿到 connection refused/RST 就说明会话活着）。
	PathProbe(ctx context.Context) error
	// ServerTunnelIP 出口隧道 IP（dns-host-resolver：VpnConfig 的 dnsAddresses 声明它，
	// 经隧道的 :53 查询由出口改写进本机代答）。两侧共同常量 100.64.255.1，非 token 派生。
	ServerTunnelIP() netip.Addr
	Close() error
}

// newSession 新栈（wgcore 传输门面）适配。
//
// ⚠️ 必须持有 Core 并在 Close 时一起关掉：Core 里有 WG device + Bind + UDP socket，
// 只关 Transport 等于把整个数据面原地泄漏（Transport.Close 刻意不碰 Core）。
// 实测症状：每个世代留下一个僵尸 Bind，每 5s 重试一次握手（日志里两串 MIRROR 交错），
// 服务端 peer 表被反复占用/搅乱，新世代反而 warmup 超时、应用流全挂。
type newSession struct {
	tr   *wgcore.Transport
	core *wgcore.Core
}

func (n newSession) DialTCPPort(ctx context.Context, port uint16) (net.Conn, error) {
	return n.tr.DialTCPPort(ctx, port)
}

func (n newSession) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return n.tr.DialTCP(ctx, dst)
}

// PathProbe：拨出口主机的 1 号端口（必然没有服务）—— 出口按隧道本地豁免转投它的
// 127.0.0.1:1，内核回 RST ⇒「隧道通、出口在、拦截层可用」；RST 很快、超时/不可达才算死。
// l3-exit-intercept 语义变化：旧内部流协议（flows，已随兼容期退役）的结构化 ERR 拒绝
// 已不存在，现在是裸 TCP 的 connection refused（wgnet 拨号错误文本携带 tcpip.ErrConnectionRefused）。
func (n newSession) PathProbe(ctx context.Context) error {
	conn, err := n.tr.DialTCPPort(ctx, 1)
	if err != nil {
		if isRefusedLike(err) {
			return nil // 出口应答了 RST：会话活着
		}
		return err
	}
	_ = conn.Close()
	return nil
}

// isRefusedLike：RST 类错误（出口活着、目标没服务）。判定统一在 wgcore.IsRefusedLike
// （wgnet.ErrRefused 哨兵 + 子串兜底，见其注释——两处调用点共享同一判据）。
func isRefusedLike(err error) bool {
	return wgcore.IsRefusedLike(err)
}

// ---------- tunAttachSurface（l3-exit-intercept：L3 attach 能力透出，留守 cshared 经
// ExitSession 接口断言到本类型） ----------

func (n newSession) AttachFD(fd, mtu int) error      { return n.core.AttachFD(fd, mtu) }
func (n newSession) SetOnTunError(f func(err error)) { n.core.SetOnTunError(f) }
func (n newSession) FdStats() (read, write int64)    { return n.core.FdStats() }
func (n newSession) ServerTunnelIP() netip.Addr      { return n.core.ServerTunnelIP() }

func (n newSession) Close() error {
	if n.tr != nil {
		_ = n.tr.Close()
	}
	if n.core != nil {
		n.core.Close()
	}
	return nil
}

// 编译期保证：两个实现都满足接缝。
var _ ExitSession = newSession{}

// NewTransport 取传输门面：新栈特有的能力（Rebind/Rearm/Probe/学习缓存接线/状态快照）
// 都从这里走。返回 nil 仅发生在测试假会话（fakeExitSession 不实现传输面）——生产
// 构造（BuildExitSession）只会产出 newSession。
func NewTransport(s ExitSession) *wgcore.Transport {
	if n, ok := s.(newSession); ok {
		return n.tr
	}
	return nil
}

// newCore 取核：服务会话的流量计数（WG 传输层字节数，Bind.RxTx）从这里走；
// 隧道域不经过它（流量面在 hub fd 层）。nil 语义同 NewTransport（仅测试假会话）。
// 未导出：消费面（状态快照）在本包内。
func newCore(s ExitSession) *wgcore.Core {
	if n, ok := s.(newSession); ok {
		return n.core
	}
	return nil
}

// errIdentityEphemeral：StrictIdentity 下身份不可持久化的哨兵（Options.StrictIdentity
// 的降级口径，r1 N2）——Session 侧据此把 reason 记为 identity_ephemeral。
var errIdentityEphemeral = errors.New("身份不可持久化（identity_ephemeral）")

// BuildExitSession 出口会话的**共用构造**（openspec app-service-session 任务 2.1；
// 手机语义：非严格身份——身份不可持久化时降级临时身份继续连）。
// 严格身份（daemon：SourceEphemeral 视为失败）走包内 buildExitSession + Options。
func BuildExitSession(cfg Config, logf Logf) (ExitSession, *wtransport.EndpointCache, error) {
	return buildExitSession(cfg, Options{}, logf)
}

// buildExitSession 出口会话构造本体：token 解码 → 候选解析 → 设备身份（同目录落盘
// 复用）→ wgcore.Prepare → Transport → 候选清单落日志 → 参照点探测（出口能力位）。
// 隧道世代（留守 startSession）与服务会话（本包状态机）都从这里起会话；差异只在
// 生命周期管理（run/世代 vs 独立状态机）。
// 返回的 EndpointCache 由调用方持有并在收工时显式 Save（Observe/NoteFailure 只改内存）。
// opts.StrictIdentity = true 时：身份不可持久化（SourceEphemeral）返回
// errIdentityEphemeral（调用方按该主机会话 failed reason=identity_ephemeral 收工，
// 可重试）——杜绝「每次重启换临时钥匙在出口多占一条设备记录」。
func buildExitSession(cfg Config, opts Options, logf Logf) (ExitSession, *wtransport.EndpointCache, error) {
	if strings.TrimSpace(cfg.Token) == "" {
		return nil, nil, errors.New("新栈需要 homeway token（cfg.token 为空）")
	}
	tok, err := proto.DecodeToken(cfg.Token)
	if err != nil {
		return nil, nil, fmt.Errorf("token 解析失败：%w", err)
	}
	cands := resolveCandidates(tok.Endpoints, lookupIPv4, logf)
	if len(cands) == 0 {
		return nil, nil, errors.New("token 里没有任何可用端点")
	}
	// 域名条目拆出（endpoint-freshness D5）：静态 IP 组与域名首次解析组分开喂给 Transport，
	// 重赛跑（Rearm）时域名组重解析并替换（静态组不动）。
	staticEps, domainEps := splitTokenEndpoints(tok.Endpoints)
	staticCands := resolveCandidates(staticEps, lookupIPv4, logf)
	var domainCands []wtransport.Candidate
	if len(domainEps) > 0 {
		domainCands = resolveCandidates(domainEps, lookupIPv4, logf)
		if len(domainCands) > 0 {
			logf("token 域名条目 %d 个 → 建会话解析 %d 条候选（重赛跑时会重解析）",
				len(domainEps), len(domainCands))
		}
	}
	// 设备身份：按后端（token 里的静态公钥）从本设备主密钥派生，落盘复用。
	// 身份稳定 ⇒ 出口设备表里一台设备只占一条记录（重连只刷新），
	// 也修掉了「B 重连 8 次把长连的 A 挤掉」这条事故路径。
	id, idSrc, idErr := wtransport.LoadOrCreateIdentity(cfg.IdentityDir, tok.PeerID)
	if idErr != nil {
		if idSrc == wtransport.SourceEphemeral {
			if opts.StrictIdentity {
				return nil, nil, fmt.Errorf("%w：%v", errIdentityEphemeral, idErr)
			}
			logf("身份：不可持久化（%v）—— 本次用临时身份建连；重连会换钥匙（出口会多占一条记录）", idErr)
		} else {
			return nil, nil, fmt.Errorf("身份加载失败：%w", idErr)
		}
	}
	switch idSrc {
	case wtransport.SourceCreated:
		logf("身份：新建（dev=%s pub=%s，目录 %s）", id.ShortDev(), id.ShortPub(), cfg.IdentityDir)
	case wtransport.SourceReused:
		logf("身份：复用（dev=%s pub=%s）", id.ShortDev(), id.ShortPub())
	case wtransport.SourceRebuilt:
		logf("⚠️ 身份：既有密钥损坏已归档并重建（dev=%s pub=%s）—— 出口会按同设备身份轮换替换记录", id.ShortDev(), id.ShortPub())
	case wtransport.SourceTagDerived:
		logf("⚠️ 身份：设备标签文件不可用，已从主密钥派生（dev=%s pub=%s）—— 重连稳定，但重置身份会换标签（出口会多一条记录）", id.ShortDev(), id.ShortPub())
	}
	core, err := wgcore.Prepare(wgcore.Config{
		MTU:        int(cfg.MTU),
		PeerID:     tok.PeerID,
		Secret:     tok.Secret,
		Identity:   id,
		Candidates: cands,
		Logf:       logf,
	})
	if err != nil {
		return nil, nil, err
	}
	var cache *wtransport.EndpointCache
	if cfg.EndpointCacheDir != "" {
		cache = wtransport.OpenEndpointCache(cfg.EndpointCacheDir, tok.PeerID)
		cache.SetLogger(logf)
	}
	tr, err := wgcore.NewTransport(wgcore.TransportConfig{
		Core:             core,
		Cache:            cache,
		StaticCandidates: staticCands,
		DomainCandidates: domainCands,
		DomainEndpoints:  domainEndpointPorts(domainEps, logf),
		LookupHost: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return lookupIPv4(ctx, host)
		},
		Logf: logf,
	})
	if err != nil {
		core.Close()
		return nil, nil, err
	}
	sess := newSession{tr: tr, core: core}
	logf("新栈会话已建立（token 端点 %d 个，后端隧道地址 %v）", len(cands), core.ClientTunnelIP())
	// 候选清单落日志（多 IP 选择的现场证据）：token 里的端点 + 学习缓存里的端点，
	// 每条标出 直连/中继 与 LAN/公网v4/IPv6 —— 复盘时不用再猜"它到底在试哪些地址"。
	if st := core.Bind().Status(); len(st.Candidates) > 0 {
		list := make([]wtransport.Candidate, 0, len(st.Candidates))
		for _, c := range st.Candidates {
			ap, err := netip.ParseAddrPort(c.Addr)
			if err != nil {
				continue
			}
			list = append(list, wtransport.Candidate{Addr: ap, Relay: c.Relay})
		}
		logf("候选端点（%d 条，标记·学习=来自巡检缓存/中继 hint）：%s", len(list),
			wtransport.DescribeCandidatesWithLearned(list, cands))
	}
	// 参照点探测一次：既是三档归因的"本机网络 → 出口"基线，也顺带取回**出口能力位**
	// （bit0 = 出口默认路径能承载 UDP）。这条日志会进 App 的运行日志，用户据此判断
	// "这台出口的 QUIC/UDP 能不能用"，不用等浏览器超时才发现。
	go func(target netip.AddrPort) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		rtt, build, flags, err := tr.Probe(ctx, target)
		if err != nil {
			logf("出口能力：参照点探测失败（%v）—— 本机网络到出口的 UDP 不通或出口未应答", err)
			return
		}
		if build == "" {
			build = "（未标注）"
		}
		dns := "不可用"
		if flags&udpCapDNSFlag != 0 {
			dns = "可用"
		}
		gen := "不可用"
		if flags&udpCapGenericFlag != 0 {
			gen = "可用"
		}
		saw := "还没实测样本（这台出口还没转发过 UDP）"
		if flags&udpCapObservedFlag != 0 {
			saw = "有回包（可用）"
		} else if flags&udpCapSeenFlag != 0 {
			saw = "无回包 —— 这条路不回这类 UDP，QUIC 会超时回落 TCP"
		}
		logf("出口能力：构建 %s ｜ 默认路径 UDP：DNS:53 %s / 通用（非 53）%s / 实测 %s ｜ 探测往返 %v",
			build, dns, gen, saw, rtt.Round(time.Millisecond))
	}(cands[0].Addr)
	return sess, cache, nil
}

// 出口能力位（与 homeway internal/server/udpcap.go 的同名常量同源）：
//
//	bit0 = 出口默认路径能承载 UDP:53（DNS 类）；bit1 = 能承载通用 UDP（非 53，QUIC 那类）。
//	分两位是必须的：TUN 型代理对 UDP 按端口区别对待（Surge 转发 DNS 但丢 QUIC）。
const (
	udpCapDNSFlag     = byte(1 << 0)
	udpCapGenericFlag = byte(1 << 1)
	// udpCapObservedFlag：**实测证据** —— 最近一轮里有转发的 UDP 会话收到过回包（才对应 QUIC 能不能用）。
	udpCapObservedFlag = byte(1 << 2)
	// udpCapSeenFlag：那轮里有过**真实转发**的 UDP 会话（区分"没样本"与"实测确实无回包"）。
	udpCapSeenFlag = byte(1 << 4)
)
