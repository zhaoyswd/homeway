package hostsession

// service.go — 服务会话状态机（openspec app-service-session 任务 2.1/2.2；
// 随迁自 cshared app_service.go，host-registry-daemon D1/1.3——逻辑与常量逐字，
// 单例守卫段随迁为 Default() 单例管理器）。
//
// 会话形态：进程内、无 TUN 的 WG 会话（手机 = VPN 未连接时承载 files/term 两座回环桥；
// daemon = Registry 直构、无桥直通）。与隧道会话（留守 cshared tunmode.go，跑在扩展
// 进程）的关系：
//   - 共用设备身份（同 identityDir）与端点学习缓存（同 endpointCacheDir）；两类会话
//     **同一把钥匙、MUST NOT 并发** —— 手机侧 App 编排保证（连 VPN 前 await ServiceStop），
//     本状态机保证 Stop 完整收工（桥 → Transport+Core.Close → 缓存 Save）后才退出；
//     该编排约束不下沉本包（Default() 只是单例容器，不承载它）。
//   - 生命周期独立：starting → ready →（stop）idle；failed 可重试。没有 TUN/attach。
//     陈旧恢复三层：①拨号/巡检触发恢复阶梯 R1-R3（补注册+丢会话 → 换本地 socket →
//     清采纳重赛跑，见 recoverStaleSession：进程挂起唤醒后旧 socket 会失效）；
//     ②阶梯连续耗尽 → 整会话重建（rebuildSession，force-stop 同机理：全新握手状态/
//     新 socket/新赛跑，桥不动、消费方无感知——2026-09-22 真机：冻结 >10 分钟唤醒后
//     阶梯对该形态每轮都失败，只有整套重建能救）；③重建失败按 failed 收工交上层重试。
//
// ⚠️ 坑 56 纪律（随迁保留）：本文件禁 log.Fatal*（c-shared 宿主进程会被 os.Exit 杀死），
// 失败一律走状态机的 failed + reason。

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/internal/wtransport"
)

// 服务会话的节拍与预算（对照隧道侧同类常量；可在真机数据上微调，不改契约形状）。
const (
	// serviceWarmTimeout 服务会话暖机窗口：等一发出口可达探测。超时算**软失败**
	//（与隧道暖机同理：会话在、注册可能后到，桥照常起，由首个真实拨号触发注册）。
	serviceWarmTimeout = 12 * time.Second
	// serviceProbeTimeout 每次巡检探测的预算。
	serviceProbeTimeout = 10 * time.Second
	// servicePatrolInterval 巡检间隔：保活（NAT 映射 / 路径信任 / rekey 驱动）
	// 与可达性观测，与隧道侧 patrolInterval 同节拍。
	servicePatrolInterval = 60 * time.Second
	// serviceFailStreakReset 连续巡检失败到这个数就丢会话重握手 + 补注册
	//（坑 60 的恢复语义：ResetPeerSession + 补发注册让恢复秒级，而不是等 rekey 计时）。
	serviceFailStreakReset = 3
	// serviceDialFirstTry 拨号自愈的首段预算：App 进程后台被挂起期间巡检不跑，
	// WG 路径大概率作废（NAT 映射过期 / 出口路径信任超时）——回前台后的首个真实
	// 拨号若给满预算只会超时报 op_failed。先用短预算试探，失败立刻按坑 60 配方
	// 自愈（丢会话重握手 + 补注册，走 recoverStaleSession）再用剩余预算重试一次（真机实测：挂起 40s 后
	// 首个 files 连接 15s 超时失败；健康路径全新握手 1–2s，4s 试探足够分诊）。
	serviceDialFirstTry = 4 * time.Second
	// serviceStopWait Stop 等待收工的上限。各阶段都有界且响应取消，这里只是兜底 ——
	// 超时返回 -1 且不清引用（旧实例未死前 Start 一律 -1，防同钥匙双会话）。
	serviceStopWait = 6 * time.Second
	// serviceLadderExhaustRebuild 恢复阶梯连续耗尽这个次数就整会话重建（rebuildSession）。
	// 真机 2026-09-22：冻结 >10 分钟唤醒后阶梯每轮走完仍失败（26s/轮），两级耗尽
	// （约 1~3 分钟）仍在失败 = R1-R3 对这种形态无解，别再循环烧时间。
	serviceLadderExhaustRebuild = 2
	// serviceRebuildCooldown 整会话重建的限频：出口真宕机时重建后的会话同样失败，
	// 限频把拆建节拍压到最慢一次/冷却期（而非每两级耗尽拆一次）。
	serviceRebuildCooldown = 10 * time.Minute
	// servicePatrolFailWindow 「巡检连败」时间窗（4a §6.1，D5——与手机 10 分钟窗
	// 同源）：相邻两次**计入证据**的失败间隔超过它 ⇒ 计数作废重来，不跨长时间
	// 挂起拼凑。**只在 Demand 钩子非 nil 的桌面路径生效**（nil = 旧语义，零行为
	// 变化——手机路径不经过）。
	servicePatrolFailWindow = 10 * time.Minute
	// serviceNoiseWindow 巡检失败拍的本地噪声回看窗（r2 新-18：手机同款
	// perTry+5s——探测预算 10s + 5s 尾窗，覆盖「探测期间有本地发送错误」的采样
	// 滞后）。nil 传输实例兜底 = 无噪声（localSendErrWithin）。
	serviceNoiseWindow = serviceProbeTimeout + 5*time.Second
)

// 服务会话状态（状态面的 state 值）。
const (
	svcStateIdle     = "idle"
	svcStateStarting = "starting"
	svcStateReady    = "ready"
	svcStateFailed   = "failed"
	// stopping：Stop 在途（review A4）。此前 Stop 收工期间 state 仍是 ready，
	// Start 会返回 0「已在跑」——与注释「旧实例未退出前 Start 一律 -1」不符。
	svcStateStopping = "stopping"
)

// 诊因原因值（4a §6.3，D6）：session.diag 载荷 reason 的值域 = gated/budget/
// probe_window（词表冻结、只增不改；真源在 facade/vocab.go 的 Diag*——本包与
// facade 单向依赖〔facade → hostsession〕不 import facade，值按字面镜像，两侧
// 测试以同值断言对齐）。三点落位：gated = 巡检证据门丢弃分支（notePatrolResult）、
// budget = rebuildSession 的限频拦截分支、probe_window = recoverGate.merge 的
// 「有轮在跑 → 等待共享结果」分支（recover.go）。
const (
	diagGated       = "gated"
	diagBudget      = "budget"
	diagProbeWindow = "probe_window"
)

// Session：一个服务会话实例（手机经 Default() 单例持有；daemon 经 Registry 每主机一个）。
type Session struct {
	mu     sync.Mutex
	state  string
	reason string
	since  time.Time

	stopCh   chan struct{} // close = 收工请求（取消暖机与巡检）
	stopOnce sync.Once
	done     chan struct{} // close = start goroutine（含巡检）已完全退出

	sess   ExitSession
	cache  *wtransport.EndpointCache
	bridge Bridge
	// build 会话构造接缝：生产 = 闭包（捕获本会话 Options，走 buildExitSession）；
	// 测试经包级 sessionBuild var 注入假会话（withFakeServiceBuild）。
	build sessionBuilder
	// bridgeFactory 回环桥构造（nil = 无桥直通，daemon 形态）。
	bridgeFactory BridgeFactory
	// observer 状态迁移观察者（nil = 不通知）。
	observer Observer
	// cfg 重建用（run 入口存一份；rebuildSession 换新会话时原样重放）。
	cfg Config
	// rebuildAt 上次整会话重建时刻（限频 serviceRebuildCooldown；零值=从未）。
	rebuildAt time.Time
	// ladderExhausted 连续「阶梯走完仍失败」的轮数（noteLadderResult 只记数；到
	// serviceLadderExhaustRebuild 由 maybeRebuildIfExhausted 触发整会话重建并归零——
	// 严格「连续」语义）。**按轮记不按观察记**：记数点在 recGate 的 run 回调里（每轮
	// 恰好执行一次）——放调用方会把同一轮被多入口共享的 rc 数多次（2026-09-23 修：
	// 此前只有巡检的触发计数，拨号路径的耗尽被忽略，真机多白等一轮 3 连败+26s 阶梯）。
	ladderExhausted int
	// recGate 服务腿自己的恢复闸（openspec recovery-ladder）：与隧道域（闸挂在 tunRun 上，
	// 按世代隔离）操作的是两个不同 WG 会话，互不等待。
	recGate recoverGate

	// 最近一次链路探测的结果 + 时间戳（与隧道侧 link* 同形）：状态面
	// 下发给扩展/界面，连接卡的「延迟」数据源。巡检 60s 一拍，暖机成功即有首拍。
	linkMu    sync.Mutex
	linkVia   string // direct | relay
	linkEP    string // 采纳路径端点
	linkRttMs int64
	linkAt    int64 // unix **毫秒**（0 = 还没探过；单位口径与隧道侧一致）

	// demand 巡检拍需求钩子（4a §6.1，D5；nil = 手机/未接线——零行为变化）与
	// diag 诊因发射钩子（§6.3，D6；nil = 不发射）。均为 NewSession 从 Options 接线。
	demand func() (bool, string)
	diag   func(reason string)
	// diagActive 诊因边沿状态（D6：同因单飞——状态离开〔clearDiag〕前不发第二条）。
	diagActive map[string]bool
	// 桌面门状态（§6.1；仅 patrol goroutine 读写——无锁）：
	patrolStreak      int       // 巡检连败计数（证据门推进后的值）
	patrolLastCounted time.Time // 上次计入证据的失败时刻（时间窗基线）
	patrolGated       bool      // 门控态边沿（进入一行 + gated 诊因单飞）

	logf    Logf
	logFile *os.File
}

// sessionBuilder 生产会话的接缝（生产 = buildExitSession；单测注入假会话验证状态机）。
// 随迁自 cshared 的 serviceBuilder/serviceBuild var（D1：随迁为包内未导出 var + 同包
// 测试注入——不导出，无外部消费者；daemon/cshared 均用默认构造）。
type sessionBuilder func(cfg Config, logf Logf) (ExitSession, *wtransport.EndpointCache, error)

// sessionBuild 测试注入位（nil = 生产）。withFakeServiceBuild 改写。
var sessionBuild sessionBuilder

// buildSession 会话构造的统一入口：NewSession 构造的会话带自己的闭包（捕获
// Options——StrictIdentity 等；测试注入时为 var 快照）；**直接手工构造的会话**
// （测试里 &Session{…} 起板，不经 NewSession）build 为 nil，回退到**当前** var 值
// （原 cshared serviceBuild 包级 var 的语义），再退到非严格生产构造。
func (s *Session) buildSession(cfg Config, logf Logf) (ExitSession, *wtransport.EndpointCache, error) {
	if s.build != nil {
		return s.build(cfg, logf)
	}
	if sessionBuild != nil {
		return sessionBuild(cfg, logf)
	}
	// 手工构造的会话没有入口 decode 的 stash：这里即它的「入口」，decode 一次
	//（重建走 buildSession 同一兜底时**不会**再走到这——手工会话的重建复用
	// sessionBuild/生产闭包之外的路径仅出现在未注入且未 Start 的测试形态）。
	return BuildExitSession(cfg, logf)
}

// NewSession 构造服务会话（starting 态、未启动——调 Start 起生命周期）。
// 手机经 Default().Start（单例守卫在前）；daemon 经 Registry 直构（每主机一个）。
// cfg.Out 非空时追加写该文件为会话日志（行格式与核日志一致 LstdFlags）——
// 打不开即返回错误（手机包装映射为 -2；手机形态刻意不劫持进程 stdout，
// 那是 tunStdioBegin 的领地）。
func NewSession(cfg Config, opts Options) (*Session, error) {
	Normalize(&cfg) // 默认值（MTU 1280 等；服务会话只用其中一部分字段）
	var logf Logf = Discard
	var logFile *os.File
	if cfg.Out != "" {
		f, err := os.OpenFile(cfg.Out, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, err
		}
		logFile = f
		lg := log.New(f, "", log.LstdFlags)
		logf = WithPrefix(lg.Printf, "服务会话: ")
	}
	// token 单轨（1.4/D2）：入口 decode 一次落结构；生产构造与整会话重建（rebuildSession
	// 复用同一闭包）不再 decode token 串——判据：tokenDecodes 在重建路径零增量。
	tok, tokErr := decodeTokenOnce(cfg.Token)
	build := func(cfg Config, logf Logf) (ExitSession, *wtransport.EndpointCache, error) {
		if tokErr != nil {
			// 入口已判定 token 坏：构造期失败按原语义走异步 failed（finish 留 reason）。
			return nil, nil, tokErr
		}
		return buildExitSession(cfg, opts, tok, logf)
	}
	if sessionBuild != nil {
		build = sessionBuild // 测试注入优先（withFakeServiceBuild）
	}
	s := &Session{
		state:         svcStateStarting,
		since:         time.Now(),
		stopCh:        make(chan struct{}),
		done:          make(chan struct{}),
		build:         build,
		bridgeFactory: opts.BridgeFactory,
		observer:      opts.Observer,
		demand:        opts.Demand,
		diag:          opts.Diag,
		cfg:           cfg,
		logf:          logf,
		logFile:       logFile,
	}
	if opts.Diag != nil {
		// probe_window 诊因接缝（§6.3 ③）：recoverGate.merge 的「有轮在跑 →
		// 等待共享结果」分支。隧道域（cshared）的 gate 零值构造 = nil 钩子零行为。
		s.diagActive = make(map[string]bool)
		s.recGate.onWait = func() { s.noteDiag(diagProbeWindow) }
		s.recGate.onRoundEnd = func() { s.clearDiag(diagProbeWindow) }
	}
	if s.bridgeFactory != nil {
		s.logf("启动（无 TUN 服务会话，App 进程内承载 files/term）")
	} else {
		s.logf("启动（无 TUN 服务会话）")
	}
	return s, nil
}

// Start 起生命周期 goroutine（建会话 → 暖机 → 起桥 → 巡检；一次性入口，
// 幂等/在途守卫在 Manager.Start / Registry 归一）。
func (s *Session) Start() {
	go func() {
		defer close(s.done)
		defer func() {
			if r := recover(); r != nil {
				s.logf("panic：%v（按失败收工）", r)
				// review #21：只记日志会把状态留在 ready（闩锁）——桥还挂着、
				// Manager 还指着尸体，下一次 Start 被「幂等」挡掉，永远起不来。
				// 走终态收工：finish 会拆桥/会话并置 failed，可再次 Start。
				// recover 先于 close(done)（LIFO），finish 在 done 关闭前完成。
				s.finish(svcStateFailed, fmt.Sprintf("会话 panic：%v", r))
			}
		}()
		s.run(s.cfg)
	}()
}

// setState 状态迁移（带时间戳）。observer 非 nil 且发生实际迁移时同步通知
// （不得在回调里调本会话的变更方法——会重入锁）。
func (s *Session) setState(state, reason string) {
	s.mu.Lock()
	from := s.state
	s.state, s.reason, s.since = state, reason, time.Now()
	s.mu.Unlock()
	if s.observer != nil && from != state {
		s.observer.StateChanged(s, from, state, reason)
	}
}

// setLink 记录一次探测往返（见 link* 字段）。
func (s *Session) setLink(via, ep string, rttMs int64) {
	s.linkMu.Lock()
	s.linkVia, s.linkEP, s.linkRttMs, s.linkAt = via, ep, rttMs, time.Now().UnixMilli()
	s.linkMu.Unlock()
}

// linkSnapshot 读一份链路快照给状态面用。
func (s *Session) linkSnapshot() (via, ep string, rttMs, at int64) {
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	return s.linkVia, s.linkEP, s.linkRttMs, s.linkAt
}

// noteLink 探测往返成功后记录链路快照：via/ep 取传输状态，rtt 用本次往返
// （与隧道域巡检的 setLink 同法——「界面 xx ms」就是这一发探测的往返时延）。
func (s *Session) noteLink(sess ExitSession, rtt time.Duration) {
	tr := NewTransport(sess)
	if tr == nil {
		return
	}
	st := tr.Status()
	s.setLink(st.Via, st.Ep, rtt.Milliseconds())
}

func (s *Session) snapshotState() (state, reason string, since time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state, s.reason, s.since
}

// setStopping：Stop 在途标记（只在尚未终态时置——不覆盖 failed/idle 的收尾原因）。
func (s *Session) setStopping() {
	s.mu.Lock()
	if s.state == svcStateStarting || s.state == svcStateReady {
		s.state = svcStateStopping
		s.since = time.Now()
	}
	s.mu.Unlock()
}

// isDone start goroutine 是否已退出（收工完成）。
func (s *Session) isDone() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// run start goroutine 主体：建会话 → 暖机探测 → 起桥 → 巡检；任何一步收工/失败都走
// finish（桥 → 会话 → 缓存 Save → 终态）。
func (s *Session) run(cfg Config) {
	s.mu.Lock()
	s.cfg = cfg // 重建用（rebuildSession 在 patrol 里、同 goroutine 串行读）
	s.mu.Unlock()
	sess, cache, err := s.buildSession(cfg, s.logf)
	if err != nil {
		s.logf("会话建立失败：%v", err)
		if errors.Is(err, errIdentityEphemeral) {
			// StrictIdentity（r1 N2）：身份不可持久化按 identity_ephemeral 收工——
			// 状态面可归因、可重试，杜绝「每次重启换临时钥匙在出口多占一条设备记录」。
			s.finish(svcStateFailed, "identity_ephemeral")
			return
		}
		s.finish(svcStateFailed, "会话建立失败："+err.Error())
		return
	}
	s.mu.Lock()
	s.sess, s.cache = sess, cache
	s.mu.Unlock()

	// 暖机：一发出口可达探测。stopCh 到 → 收工；超时算**软失败**——桥照常起，
	// 由首个真实拨号触发注册（与隧道暖机同语义）。
	probeCtx, probeCancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-s.stopCh:
			probeCancel()
		case <-probeCtx.Done():
		}
	}()
	warmCtx, warmCancel := context.WithTimeout(probeCtx, serviceWarmTimeout)
	warmStarted := time.Now()
	err = sess.PathProbe(warmCtx)
	warmCancel()
	if err == nil {
		s.noteLink(sess, time.Since(warmStarted)) // 暖机这一发就是首拍链路快照（rtt 有了）
	}
	probeCancel()
	select {
	case <-s.stopCh:
		s.logf("暖机期间收到停止请求，收工")
		s.finish(svcStateIdle, "已收工")
		return
	default:
	}
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			s.logf("暖机 %v 内出口未应答：按软失败继续（首个拨号会触发注册）", serviceWarmTimeout)
		} else {
			s.logf("暖机硬失败：%v", err)
			s.finish(svcStateFailed, "出口不可达："+err.Error())
			return
		}
	} else {
		s.logf("暖机就绪（出口可达，rtt=%dms）", time.Since(warmStarted).Milliseconds())
	}

	// 回环桥（手机形态）：谁持会话谁 host（消费方仍连 127.0.0.1:7722/7723，无感知）。
	// 拨号走 healingDial 且**动态取当前会话**（rebuildSession 整会话重建换 s.sess 时，
	// 桥/鉴权/sock 全不动，dial 自动落到新会话上——重建对消费方透明）。
	// daemon 无桥（bridgeFactory = nil）直通。
	if s.bridgeFactory != nil {
		bridge := s.bridgeFactory(cfg, s.logf, func(ctx context.Context, port uint16) (net.Conn, error) {
			return s.healingDialCurrent(ctx, port)
		}, time.Duration(cfg.DialMs)*time.Millisecond)
		bridge.Start()
		s.mu.Lock()
		s.bridge = bridge
		s.mu.Unlock()
	}

	s.setState(svcStateReady, "")
	s.logf("就绪（会话在位%s）", bridgeSuffix(s.bridgeFactory != nil))

	s.patrol()
}

// bridgeSuffix 就绪日志的桥形态注记（手机 = 桥起；daemon = 无桥直通）。
func bridgeSuffix(hasBridge bool) string {
	if hasBridge {
		return "，files/term 桥已起，无 VPN 承载"
	}
	return "，无桥直通"
}

// ErrSessionNotCurrent 会话不在（收工/重建窗口）哨兵——消费方（daemon 流腿，
// host-registry-daemon §3）据此映射 stream_refused。
var ErrSessionNotCurrent = errors.New("服务会话不在（收工/重建窗口）")

// healingDialCurrent 服务桥拨号入口：动态取当前会话（rebuildSession 换会后 dial 自动
// 落到新会话），会话不在（收工窗口）按错误返回。
func (s *Session) healingDialCurrent(ctx context.Context, port uint16) (net.Conn, error) {
	sess := s.curSession()
	if sess == nil {
		return nil, ErrSessionNotCurrent
	}
	return s.healingDial(sess, ctx, func(c context.Context, cur ExitSession) (net.Conn, error) {
		return cur.DialTCPPort(c, port)
	})
}

// DialPort 重建感知的隧道端口拨号（D1 导出面；daemon 流腿用，D5）：动态取当前会话，
// 拨出口主机本机端口；首段短预算试探 + 失败自愈（healingDial 同路径）。
func (s *Session) DialPort(ctx context.Context, port uint16) (net.Conn, error) {
	return s.healingDialCurrent(ctx, port)
}

// DialAddr 重建感知的任意目标隧道拨号（3e §2.1，D5）：与 DialPort 同 healing 路径、
// 同重建感知——消费方 = facade.Host.Dial（forward 任意 IP 目标 / socks 承载面）。
func (s *Session) DialAddr(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	sess := s.curSession()
	if sess == nil {
		return nil, ErrSessionNotCurrent
	}
	return s.healingDial(sess, ctx, func(c context.Context, cur ExitSession) (net.Conn, error) {
		return cur.DialTCP(c, dst)
	})
}

// healingDial 服务桥的拨号路径（files/term 的内部流都从这里走）：
// 首段短预算试探，失败即「重绑本地 socket + 丢本地会话重握手 + 补注册」（坑 60 配方
// 的拨号路径版，加 Rebind 见 recoverStaleSession），再用调用方的剩余预算重试一次。
// 覆盖两类场景：
//   - 后台挂起唤醒：会话陈旧、首个操作原地自愈，用户无感；
//   - 出口真不可达：总耗时仍受调用方预算约束（4s 试探 + 剩余重试），
//     行为与原先「一路等到超时」等价，只是错误归因更早。
//
// 幂等安全：Rebind/Rearm/RefreshReg 只动本地状态；并发拨号（files+term
// 同时失败）各自触发一次也无害。dial 参数 = 对「某一代会话」的一次拨号闭包
// （DialPort/DialAddr 两缝共用本路径——同试探、同自愈、同重试语义）。
func (s *Session) healingDial(sess ExitSession, ctx context.Context, dial func(context.Context, ExitSession) (net.Conn, error)) (net.Conn, error) {
	firstCtx, cancel := context.WithTimeout(ctx, serviceDialFirstTry)
	conn, err := dial(firstCtx, sess)
	cancel()
	if err == nil {
		return conn, nil
	}
	if ctx.Err() != nil {
		// 调用方预算比试探段还短（或已取消）：没有重试的意义。
		return nil, ctx.Err()
	}
	s.recoverStaleSession(sess, "拨号失败")
	// 阶梯若连续耗尽，这里可能已整会话重建（旧 sess 已 Close）——重试要打到**当前**
	// 会话上（本请求就地骑过恢复，不用等消费方重试一轮）。
	if cur := s.curSession(); cur != nil && cur != sess {
		sess = cur
	}
	return dial(ctx, sess)
}

// curSession 当前会话（收工/重建窗口为 nil）。
func (s *Session) curSession() ExitSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sess
}

// noteLadderResult 记一笔阶梯结果（恢复→归零；耗尽→+1）。**只记数**——重建决策在
// recoverStaleSession 的 merge 返回之后做（maybeRebuildIfExhausted）：放在 run 回调里
// 会把整轮重建拉进 gate 的临界区（并发拨号在 merge 里裸等 r.done、不看 ctx），且
// 留下「run 内再进同一 gate = 互等死锁」的结构隐患（评审③-1）。
func (s *Session) noteLadderResult(rc int) {
	s.mu.Lock()
	if rc >= 0 {
		s.ladderExhausted = 0
	} else {
		s.ladderExhausted++
	}
	s.mu.Unlock()
}

// maybeRebuildIfExhausted 耗尽计数到阈值就整会话重建；**触发即归零**（严格「连续 N 轮」
// 语义——评审③-2：不归零的话重建后每次单发耗尽都会撞一次限频，语义漂移）。多入口的
// merge 等待者都会走到这：先到者归零+重建，后来者看到 0 直接返回，天然去重；并发双
// 重建再被 rebuildSession 的限频 check-and-set 兜住。
func (s *Session) maybeRebuildIfExhausted() {
	s.mu.Lock()
	n := s.ladderExhausted
	if n < serviceLadderExhaustRebuild {
		s.mu.Unlock()
		return
	}
	s.ladderExhausted = 0
	s.mu.Unlock()
	s.rebuildSession(fmt.Sprintf("恢复阶梯连续 %d 轮走完仍未恢复", n))
}

// markLadderHealthy 会话确认健康（巡检探测成功）：耗尽计数归零——与「阶梯恢复归零」
// 同语义，防很久以前的一次耗尽与之后的一次不相关耗尽拼成 2。
func (s *Session) markLadderHealthy() {
	s.mu.Lock()
	s.ladderExhausted = 0
	s.mu.Unlock()
}

// recoverStaleSession 陈旧会话恢复（挂起唤醒后首个操作 / 拨号失败 / 巡检连败共用）。
// openspec recovery-ladder：收编到统一阶梯（本会话自己的恢复域，与隧道域互不等待），
// **R2 起跑**——该函数的实测场景就是「App 进程后台被冻结 15 分钟后旧 socket 失效、
// 采纳地址仍有效」：R2 = 换源（保采纳）+ 补注册 + 丢会话；失败自动升 R3 清采纳重赛跑
// （学习缓存候选兜底）。每档探测先行：会话其实还活着时零动作。
// 返回阶梯结果（≥1=恢复于该档；-1=走完仍失败）。耗尽计数在 run 回调里统一记
// （noteLadderResult，每轮恰好一次），重建决策在 merge 之后（maybeRebuildIfExhausted），
// 巡检/拨号两个入口同权——拨号路径的耗尽是用户请求真实失败的旁证。
func (s *Session) recoverStaleSession(sess ExitSession, why string) int {
	// 入口防陈旧（评审③-3）：调用方抓 sess 与真正起跑之间可能隔了 4s 拨号试探——期间
	// 别的入口若已整会话重建，手里的 sess 是已 Close 的尸体（对它跑阶梯必失败、虚增
	// 耗尽计数）。以当前会话为准，不匹配就直接不跑。
	if cur := s.curSession(); cur == nil || cur != sess {
		return 0
	}
	tr := NewTransport(sess)
	if tr == nil {
		return 0
	}
	rc := s.recGate.merge(recoverR2, why, func(from recoverLevel) int {
		rc := runRecoverLadder(RecoverDeps{
			Probe: func(ctx context.Context) error { return sess.PathProbe(ctx) },
			Tr:    tr,
			Logf:  s.logf,
		}, from, why)
		s.noteLadderResult(rc) // 每轮恰好执行一次（merge 只让一个入口跑 run）
		return rc
	})
	s.maybeRebuildIfExhausted() // gate 之外：见其注释（临界区/重入/多等待者去重）
	return rc
}

// patrol 轻量巡检：60s 一发保活探测；连续失败重绑 socket + 丢会话重握手 + 补注册；
// **恢复阶梯连续走完仍失败 → 整会话重建**（计数在 recoverStaleSession 的 run 回调里，
// 巡检/拨号两入口同权；patrol 只负责探测与触发）。失败证据经桌面门推进
// （notePatrolResult，§6.1——Demand 钩子 nil 时 = 旧语义，手机路径零行为变化）。
func (s *Session) patrol() {
	ticker := time.NewTicker(servicePatrolInterval)
	defer ticker.Stop()
	last := time.Now()
	for {
		select {
		case <-s.stopCh:
			s.finish(svcStateIdle, "已收工")
			return
		case <-ticker.C:
		}
		now := time.Now()
		gap := now.Sub(last)
		last = now
		sess := s.curSession()
		if sess == nil {
			return
		}
		// 长时空窗 = 进程被系统冻结（后台/熄屏时巡检整段不跑）。唤醒后旧 socket 大概率
		// 已失效，不等用户操作失败，主动恢复（判据行：巡检空窗 + REBIND 端口）。
		// 耗尽计数由 recoverStaleSession 内部统一记（noteLadderResult）。
		if gap > 2*servicePatrolInterval {
			s.logf("巡检空窗 %v（判为进程被挂起）——主动重绑本地 socket", gap.Round(time.Second))
			s.recoverStaleSession(sess, "挂起唤醒")
			// 阶梯若连续耗尽会整会话重建：本 tick 手里的 sess 已是旧引用，刷新后再
			// 探测（评审③-4：拿尸体探测只会虚记一次巡检失败）。
			if cur := s.curSession(); cur != sess {
				if cur == nil {
					return
				}
				sess = cur
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), serviceProbeTimeout)
		started := time.Now()
		err := sess.PathProbe(ctx)
		cancel()
		rtt := time.Since(started)
		tr := NewTransport(sess)
		// 需求判定每拍恰一次（§6.1，D5：桌面三源合成经钩子——结果 sticky 落 facade
		// 的 demand 观测面〔daemon.status〕，失败拍由证据门消费同一判定；nil = 恒真，
		// 门不生效——手机路径不经过）。
		demand, demandWhy := true, ""
		if s.demand != nil {
			demand, demandWhy = s.demand()
		}
		if err == nil {
			s.markLadderHealthy() // 巡检确认健康：耗尽计数归零
			s.noteLink(sess, rtt)
			if tr != nil {
				st := tr.Status()
				s.logf("link: via=%s ep=%s rtt=%dms（服务会话巡检）", st.Via, st.Ep, rtt.Milliseconds())
			}
			s.notePatrolResult(sess, nil, demand, demandWhy, now)
			continue
		}
		s.notePatrolResult(sess, err, demand, demandWhy, now)
		if s.patrolStreak >= serviceFailStreakReset {
			s.recoverStaleSession(sess, "巡检连续失败")
			s.logf("连续 %d 次失败：已重绑本地 socket 并补注册（下一发探测全新握手）", s.patrolStreak)
			s.patrolStreak = 0
			// 重建若已触发（maybeRebuildIfExhausted），刷新本 tick 的会话引用，
			// 下一 tick 起用新会话（新会话首个出站包自带注册+赛跑，通常一拍内恢复）。
			if cur := s.curSession(); cur != sess {
				if cur == nil {
					return
				}
			}
		}
	}
}

// PatrolEvidenceGate 巡检拍的证据推进（纯函数，4a §6.1/§6.4——手机门
// cmd/clientcore/demand.go patrolEvidenceGate 的**全量镜像**：五分支真值表
// 「成功拍清零 / localNoise 清零 / 无需求清零 / 窗口作废 / 正常计数」两侧共享
// 向量，对齐审计的桌面侧真源；窗口常量两侧同源 10 分钟）：
//   - 探测成功 ⇒ 计数清零（counted=false——成功拍不计失败证据；F,S,F,F 停在 2，
//     不拼出 3 连败）；
//   - localNoise（探测窗内有采纳路径本地发送错误）或 !demand ⇒ 计数清零、不计证据；
//   - 计数拍之间间隔超过窗口（servicePatrolFailWindow）⇒ 计数作废重来；
//   - 正常计数拍 ⇒ +1。
//
// 返回推进后的计数与「本拍是否计入失败证据」。
func PatrolEvidenceGate(localNoise, demand bool, failStreak int, lastCountedFail, now time.Time, probeErr error) (int, bool) {
	if probeErr == nil {
		return 0, false // 成功拍清零（「连败」的连续语义）
	}
	if localNoise || !demand {
		return 0, false
	}
	if failStreak > 0 && !lastCountedFail.IsZero() && now.Sub(lastCountedFail) > servicePatrolFailWindow {
		failStreak = 0
	}
	return failStreak + 1, true
}

// localSendErrWithin 本地噪声源接缝（r2 新-18：NewTransport(sess).
// LocalSendErrWithin(window)；会话无传输实例时 nil 兜底 = 无噪声）。同包测试
// 注入驱动 localNoise 分支。
var localSendErrWithin = func(sess ExitSession, window time.Duration) bool {
	if tr := NewTransport(sess); tr != nil {
		return tr.LocalSendErrWithin(window)
	}
	return false
}

// notePatrolResult 一拍巡检结果的证据推进（桌面门接线点，§6.1）。Demand 钩子
// nil = 旧语义（失败 +1 / 成功清零；localNoise/时间窗/需求分支都不经过——
// 「钩子 nil = 零行为变化」的前提，手机路径不受影响）；非 nil = 门全量镜像
// 五分支 + gated 诊因边沿（§6.3 ①：无需求/localNoise 清零均归 gated，进入
// 拦下态发一条、期间静默、离开时清态）。
func (s *Session) notePatrolResult(sess ExitSession, err error, demand bool, demandWhy string, now time.Time) {
	if err == nil {
		s.patrolStreak = 0
		if s.patrolGated {
			s.patrolGated = false
			s.clearDiag(diagGated)
			s.logf("巡检恢复：门控态结束（成功拍清零）")
		}
		return
	}
	if s.demand == nil {
		s.patrolStreak++
		s.logf("巡检失败（连续 %d）：%v", s.patrolStreak, err)
		return
	}
	noise := localSendErrWithin(sess, serviceNoiseWindow)
	n, counted := PatrolEvidenceGate(noise, demand, s.patrolStreak, s.patrolLastCounted, now, err)
	s.patrolStreak = n
	if !counted {
		if !s.patrolGated {
			s.patrolGated = true
			why := demandWhy
			if noise {
				why = "本地发送错误（环境噪声）"
			}
			s.noteDiag(diagGated)
			s.logf("巡检失败被门控拦下（%s）→ 计数清零仅记录", why)
		}
		return
	}
	if s.patrolGated {
		s.patrolGated = false
		s.clearDiag(diagGated)
		s.logf("需求恢复（%s）：巡检失败重新计入证据", demandWhy)
	}
	s.patrolLastCounted = now
	s.logf("巡检失败（连续 %d）：%v", n, err)
}

// noteDiag 诊因边沿发射（§6.3，D6：状态进入才发一条、每主机单飞——同因不发
// 第二条直至状态离开〔clearDiag〕；Diag 钩子 nil = 零行为）。
func (s *Session) noteDiag(reason string) {
	if s.diag == nil {
		return
	}
	s.mu.Lock()
	if s.diagActive[reason] {
		s.mu.Unlock()
		return
	}
	if s.diagActive == nil {
		s.diagActive = make(map[string]bool)
	}
	s.diagActive[reason] = true
	s.mu.Unlock()
	s.diag(reason)
}

// clearDiag 诊因状态离开（同因的下一次进入可再发）。
func (s *Session) clearDiag(reason string) {
	if s.diag == nil {
		return
	}
	s.mu.Lock()
	delete(s.diagActive, reason)
	s.mu.Unlock()
}

// rebuildSession 恢复阶梯连续耗尽后的**整套重建**（真机 2026-09-22 立项）：App 冻结
// >10 分钟唤醒后 R1→R3 每轮走完仍失败（出口侧持续收到握手发起但会话永不完成——
// 手机发得出、收不到任何应答），force-stop 重开 App 立即恢复。本函数把 force-stop 的
// 机理搬进进程内：旧会话 Close（Transport+Core 全弃 = 全新握手状态/新 socket/新赛跑），
// 换入新会话。**桥不动**（dial 经 healingDialCurrent 动态取当前会话，鉴权/sock 不变，
// ArkTS 与在飞消费方无感知；重建窗口内的拨号打到新会话上，首个出站包自带注册）。
// 限频 serviceRebuildCooldown：出口真宕机时别无限拆建（重建后的会话同样会阶梯耗尽，
// 再耗尽再限频，形成最慢 ~10 分钟一次的重试节拍）。重建失败按 failed 收工，等上层
// （ArkTS ensureStarted / 用户重试）再拉起。
func (s *Session) rebuildSession(reason string) {
	s.mu.Lock()
	if time.Since(s.rebuildAt) < serviceRebuildCooldown {
		s.mu.Unlock()
		s.logf("REBUILD 整会话重建被限频（%v 内已重建过，继续观察）：原因=%s", serviceRebuildCooldown, reason)
		s.noteDiag(diagBudget) // §6.3 ②：budget = 限频拦截分支（边沿——实际重建时清态）
		return
	}
	old, oldCache, cfg := s.sess, s.cache, s.cfg
	s.rebuildAt = time.Now()
	s.mu.Unlock()
	s.clearDiag(diagBudget) // 实际重建执行 = 离开 budget 态（下一次拦截可再发）

	s.logf("REBUILD 整会话重建（%s）：拆旧会话换新（force-stop 同机理，进程内完成）", reason)
	if oldCache != nil {
		_ = oldCache.Save(time.Now()) // 旧实例学到的端点先落盘（新实例 D8 合并会读回）
	}
	if old != nil {
		_ = old.Close()
	}
	sess, cache, err := s.buildSession(cfg, s.logf)
	if err != nil {
		s.logf("REBUILD 新会话建立失败：%v（按 failed 收工）", err)
		if errors.Is(err, errIdentityEphemeral) {
			s.finish(svcStateFailed, "identity_ephemeral")
			return
		}
		s.finish(svcStateFailed, "重建失败："+err.Error())
		return
	}
	s.mu.Lock()
	s.sess, s.cache = sess, cache
	s.mu.Unlock()
	s.logf("REBUILD 新会话已换入（首个出站包将重新注册+赛跑）")
}

// finish 收工的统一路径（design D4 顺序）：桥 → 会话（Transport+Core）→ 缓存 Save → 终态。
// idle（正常收工）与 failed（硬失败）共用；failed 保留 reason 供状态面呈现。
func (s *Session) finish(state, reason string) {
	s.mu.Lock()
	bridge, sess, cache := s.bridge, s.sess, s.cache
	s.bridge, s.sess, s.cache = nil, nil, nil
	s.mu.Unlock()
	if bridge != nil {
		bridge.Stop()
	}
	if sess != nil {
		_ = sess.Close() // newSession.Close = Transport.Close + Core.Close（防僵尸 Bind）
	}
	if cache != nil {
		if err := cache.Save(time.Now()); err != nil {
			s.logf("端点缓存落盘失败：%v", err)
		}
	}
	s.setState(state, reason)
	s.logf("已收工（state=%s）", state)
	s.closeLog()
}

// closeLog 收工时关日志文件。
func (s *Session) closeLog() {
	s.mu.Lock()
	f := s.logFile
	s.logFile = nil
	s.mu.Unlock()
	if f != nil {
		_ = f.Close()
	}
}

// Stop 请求收工并等待（上限 serviceStopWait）。
// 返回 0 = 已收工（或本就没在跑）｜-1 = 等待超时（旧实例仍在收尾；此后 Start 会
// 一直 -1 直到它真正退出 —— 防止同钥匙双会话，调用方应重试 Stop）。
func (s *Session) Stop() int {
	s.stopOnce.Do(func() { close(s.stopCh) })
	// 置 stopping（review A4）：让在途窗口内的 Start 明确拿到 -1，
	// 而不是把正在被拆的会话当「已在跑」。
	s.setStopping()
	select {
	case <-s.done:
		return 0
	case <-time.After(serviceStopWait):
		return -1
	}
}

// ---------- 状态快照（D1 新接缝：cshared 包装据此拼状态 JSON；daemon 状态面直读） ----------

// Snapshot 状态快照（只读）。指针字段 nil = 该块缺省（与状态 JSON 的键缺省语义一致）。
type Snapshot struct {
	State  string
	Reason string
	Since  time.Time // 当前态起点（零值 = 未记录）

	// 会话/桥在位性（无会话 = link/identity/stats 全缺省）。
	HasSession bool

	BridgeAuth      string
	BridgeFilesSock string
	BridgeTermSock  string
	BridgeSpeedSock string
	Link            *LinkSnapshot
	Identity        *IdentitySnapshot
	Stats           *StatsSnapshot
}

// LinkSnapshot 链路快照（link 块）。
type LinkSnapshot struct {
	Via   string
	Ep    string
	At    int64 // unix 毫秒
	RttMs int64
}

// IdentitySnapshot 身份短指纹（只公钥侧；诊断报告不含私钥）。
type IdentitySnapshot struct {
	Dev string
	Pub string
}

// StatsSnapshot 流量面（WG 传输层字节数；随世代清零）。
type StatsSnapshot struct {
	RxBytes int64 // 下行
	TxBytes int64 // 上行
}

// StatusSnapshot 取只读快照（无锁读桥/会话引用 + 各自快照锁；状态 JSON 的数据源）。
func (s *Session) StatusSnapshot() Snapshot {
	state, reason, since := s.snapshotState()
	snap := Snapshot{State: state, Reason: reason, Since: since}
	s.mu.Lock()
	sess, bridge := s.sess, s.bridge
	s.mu.Unlock()
	if bridge != nil {
		snap.BridgeAuth = bridge.AuthHex()
		snap.BridgeFilesSock, snap.BridgeTermSock, snap.BridgeSpeedSock = bridge.SockJSON()
	}
	if sess != nil {
		snap.HasSession = true
		if tr := NewTransport(sess); tr != nil {
			st := tr.Status()
			_, _, rttMs, _ := s.linkSnapshot()
			snap.Link = &LinkSnapshot{Via: st.Via, Ep: st.Ep, At: st.At, RttMs: rttMs}
			if id := tr.Identity(); id != nil {
				snap.Identity = &IdentitySnapshot{Dev: id.ShortDev(), Pub: id.ShortPub()}
			}
		}
		// 流量面（2026-09-26）：服务会话没有 TUN，用 WG 传输层字节数（Bind.RxTx，
		// 含握手/保活与封装开销）；随世代清零（rebuildSession 换会话即新 Bind）。
		if core := newCore(sess); core != nil {
			if bind := core.Bind(); bind != nil {
				rx, tx := bind.RxTx()
				snap.Stats = &StatsSnapshot{RxBytes: rx, TxBytes: tx}
			}
		}
	}
	return snap
}

// ---------- 单例管理器（随迁 serviceMu/serviceCur + 守卫段；1.3 Default()） ----------

// Manager 服务会话单例管理器。手机包装（ClientCoreServiceStart/Stop/Status）经它编排；
// daemon 不用——走 Registry 每主机直构（D2）。「同钥匙两类会话不并发」的编排约束
// 仍属 App/扩展侧，不下沉本包（Default 只是单例容器）。
type Manager struct {
	mu  sync.Mutex
	cur *Session
}

var defaultManager Manager

// Default 取进程级单例管理器。
func Default() *Manager { return &defaultManager }

// current 当前实例（同包测试用；外部消费者走 Snapshot）。
func (m *Manager) current() *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cur
}

// reset 清空当前实例引用（仅测试收尾用；生产路径经 Stop 收口）。
func (m *Manager) reset() {
	m.mu.Lock()
	m.cur = nil
	m.mu.Unlock()
}

// Start 起会话（单例守卫 → 构造 → 起生命周期）。
// 返回码：0 已启动（幂等：starting/ready 下重复调用直接 0）｜-1 上一个实例还在收工｜
// -2 服务日志文件打不开（NewSession 的唯一错误源）。
func (m *Manager) Start(cfg Config, opts Options) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cur != nil {
		state, _, _ := m.cur.snapshotState()
		switch state {
		case svcStateStarting, svcStateReady:
			return 0 // 幂等：已在跑
		case svcStateStopping:
			return -1 // Stop 在途：旧实例未退出，调用方应等 stop 完成后再试
		case svcStateIdle, svcStateFailed:
			if !m.cur.isDone() {
				// teardownAll 已清资源、goroutine 即将退出：等下一拍再试（窗口微秒级）。
				return -1
			}
		default:
			return -1
		}
	}
	s, err := NewSession(cfg, opts)
	if err != nil {
		return -2
	}
	m.cur = s
	s.Start()
	return 0
}

// Stop 收工当前实例（无实例 = 0）。
func (m *Manager) Stop() int {
	m.mu.Lock()
	s := m.cur
	m.mu.Unlock()
	if s == nil {
		return 0
	}
	return s.Stop()
}

// Snapshot 当前实例的只读快照；无实例 = idle 空闲形状。
func (m *Manager) Snapshot() Snapshot {
	m.mu.Lock()
	s := m.cur
	m.mu.Unlock()
	if s == nil {
		return Snapshot{State: svcStateIdle}
	}
	return s.StatusSnapshot()
}
