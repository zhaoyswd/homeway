//go:build cshared

// app_service.go — 服务会话（openspec app-service-session 任务 2.1/2.2）：
// App 进程内、无 TUN 的 WG 会话，VPN 未连接时承载 files/term 两座回环桥。
//
// 与隧道会话（tunmode.go，跑在扩展进程）的关系：
//   - 共用设备身份（同 identityDir）与端点学习缓存（同 endpointCacheDir）；两类会话
//     **同一把钥匙、MUST NOT 并发** —— App 侧编排保证（连 VPN 前 await ServiceStop），
//     本状态机保证 Stop 完整收工（桥 → Transport+Core.Close → 缓存 Save）后才退出；
//   - 生命周期独立：starting → ready →（stop）idle；failed 可重试。没有 TUN/attach。
//     陈旧恢复三层：①拨号/巡检触发恢复阶梯 R1-R3（补注册+丢会话 → 换本地 socket →
//     清采纳重赛跑，见 recoverStaleSession：进程挂起唤醒后
//     旧 socket 会失效）；②阶梯连续耗尽 → 整会话重建（rebuildSession，force-stop 同
//     机理：全新握手状态/新 socket/新赛跑，桥不动、消费方无感知——2026-09-22 真机：
//     冻结 >10 分钟唤醒后阶梯对该形态每轮都失败，只有整套重建能救）；③重建失败按
//     failed 收工交上层重试。
//
// 导出风格与 tun 导出同构（Start 快速返回 + 轮询 Status；Stop 同步等待收工）：
//
//	ClientCoreServiceStart / ClientCoreServiceStop / ClientCoreServiceStatus
//
// ⚠️ 坑 56 纪律：本文件禁 log.Fatal*（c-shared 里会 os.Exit 杀死宿主 App 进程），
// 失败一律走状态机的 failed + reason。
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/hostsession"
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
)

// 服务会话状态（状态 JSON 的 state 值）。
const (
	svcStateIdle     = "idle"
	svcStateStarting = "starting"
	svcStateReady    = "ready"
	svcStateFailed   = "failed"
	// stopping：Stop 在途（review A4）。此前 Stop 收工期间 state 仍是 ready，
	// Start 会返回 0「已在跑」——与注释「旧实例未退出前 Start 一律 -1」不符。
	svcStateStopping = "stopping"
)

// serviceSession：一个服务会话实例（全局至多一个活跃）。
type serviceSession struct {
	mu     sync.Mutex
	state  string
	reason string
	since  time.Time

	stopCh   chan struct{} // close = 收工请求（取消暖机与巡检）
	stopOnce sync.Once
	done     chan struct{} // close = start goroutine（含巡检）已完全退出

	sess   exitSession
	cache  *wtransport.EndpointCache
	bridge *bridgeHost
	// cfg 重建用（run 入口存一份；rebuildSession 换新会话时原样重放）。
	cfg tunConfig
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

	// 最近一次链路探测的结果 + 时间戳（与 tunRunner.link* 同形）：serviceStatusJSON
	// 下发给扩展/界面，App 模式连接卡的「延迟」数据源。巡检 60s 一拍，暖机成功即有首拍。
	linkMu    sync.Mutex
	linkVia   string // direct | relay
	linkEP    string // 采纳路径端点
	linkRttMs int64
	linkAt    int64 // unix **毫秒**（0 = 还没探过；单位口径与 tunRunner 一致）

	logf    Logf
	logFile *os.File
}

var (
	serviceMu  sync.Mutex
	serviceCur *serviceSession
)

// serviceBuilder 生产会话的接缝（生产 = buildExitSession；单测注入假会话验证状态机）。
type serviceBuilder func(cfg tunConfig, logf Logf) (exitSession, *wtransport.EndpointCache, error)

var serviceBuild serviceBuilder = func(cfg tunConfig, logf Logf) (exitSession, *wtransport.EndpointCache, error) {
	return hostsession.BuildExitSession(cfg, logf) // 构造本体已随迁 hostsession（D1）
}

// setState 状态迁移（带时间戳）。
func (s *serviceSession) setState(state, reason string) {
	s.mu.Lock()
	s.state, s.reason, s.since = state, reason, time.Now()
	s.mu.Unlock()
}

// setLink 记录一次探测往返（见 link* 字段）。
func (s *serviceSession) setLink(via, ep string, rttMs int64) {
	s.linkMu.Lock()
	s.linkVia, s.linkEP, s.linkRttMs, s.linkAt = via, ep, rttMs, time.Now().UnixMilli()
	s.linkMu.Unlock()
}

// linkSnapshot 读一份链路快照给状态 JSON 用。
func (s *serviceSession) linkSnapshot() (via, ep string, rttMs, at int64) {
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	return s.linkVia, s.linkEP, s.linkRttMs, s.linkAt
}

// noteLink 探测往返成功后记录链路快照：via/ep 取传输状态，rtt 用本次往返
// （与隧道域巡检的 setLink 同法——「界面 xx ms」就是这一发探测的往返时延）。
func (s *serviceSession) noteLink(sess exitSession, rtt time.Duration) {
	tr := newTransport(sess)
	if tr == nil {
		return
	}
	st := tr.Status()
	s.setLink(st.Via, st.Ep, rtt.Milliseconds())
}

func (s *serviceSession) snapshotState() (state, reason string, since time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state, s.reason, s.since
}

// setStopping：Stop 在途标记（只在尚未终态时置——不覆盖 failed/idle 的收尾原因）。
func (s *serviceSession) setStopping() {
	s.mu.Lock()
	if s.state == svcStateStarting || s.state == svcStateReady {
		s.state = svcStateStopping
		s.since = time.Now()
	}
	s.mu.Unlock()
}

// isDone start goroutine 是否已退出（收工完成）。
func (s *serviceSession) isDone() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// serviceStartFromJSON ClientCoreServiceStart 的逻辑体（导出壳只做 C 字符串转换；
// 纯 Go 形态供单测直接调用）。
// 返回码：0 已启动（幂等：starting/ready 下重复调用直接 0）｜-1 上一个实例还在收工｜
// -2 服务日志文件打不开｜-3 配置不是合法 JSON｜-4 token 为空。
func serviceStartFromJSON(config string) int {
	var cfg tunConfig
	if err := json.Unmarshal([]byte(config), &cfg); err != nil {
		return -3
	}
	if cfg.Token == "" {
		return -4
	}
	normalizeTunConfig(&cfg) // 默认值（MTU 1280 等；服务会话只用其中一部分字段）

	serviceMu.Lock()
	defer serviceMu.Unlock()
	if serviceCur != nil {
		state, _, _ := serviceCur.snapshotState()
		switch state {
		case svcStateStarting, svcStateReady:
			return 0 // 幂等：已在跑
		case svcStateStopping:
			return -1 // Stop 在途：旧实例未退出，调用方应等 stop 完成后再试
		case svcStateIdle, svcStateFailed:
			if !serviceCur.isDone() {
				// teardownAll 已清资源、goroutine 即将退出：等下一拍再试（窗口微秒级）。
				return -1
			}
		default:
			return -1
		}
	}

	// 服务日志：**不走** tunStdioBegin（那是进程级 stdout/log 重定向，会劫持 App 进程
	// 自己的输出）；用自己的 log.Logger 追加写独立文件，行格式与核日志一致（LstdFlags）。
	var logf Logf = Discard
	var logFile *os.File
	if cfg.Out != "" {
		f, err := os.OpenFile(cfg.Out, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return -2
		}
		logFile = f
		lg := log.New(f, "", log.LstdFlags)
		logf = WithPrefix(lg.Printf, "服务会话: ")
	}

	s := &serviceSession{
		state:   svcStateStarting,
		since:   time.Now(),
		stopCh:  make(chan struct{}),
		done:    make(chan struct{}),
		logf:    logf,
		logFile: logFile,
	}
	s.logf("启动（无 TUN 服务会话，App 进程内承载 files/term）")
	serviceCur = s

	go func() {
		defer close(s.done)
		defer func() {
			if r := recover(); r != nil {
				s.logf("panic：%v（按失败收工）", r)
				// review #21：只记日志会把状态留在 ready（闩锁）——桥还挂着、
				// serviceCur 指着尸体，下一次 Start 被「幂等」挡掉，永远起不来。
				// 走终态收工：finish 会拆桥/会话并置 failed，可再次 Start。
				// recover 先于 close(done)（LIFO），finish 在 done 关闭前完成。
				s.finish(svcStateFailed, fmt.Sprintf("会话 panic：%v", r))
			}
		}()
		s.run(cfg)
	}()
	return 0
}

//export ClientCoreServiceStart
func ClientCoreServiceStart(cConfig *C.char) C.int {
	return C.int(serviceStartFromJSON(C.GoString(cConfig)))
}

// run start goroutine 主体：建会话 → 暖机探测 → 起桥 → 巡检；任何一步收工/失败都走
// finish（桥 → 会话 → 缓存 Save → 终态）。
func (s *serviceSession) run(cfg tunConfig) {
	s.mu.Lock()
	s.cfg = cfg // 重建用（rebuildSession 在 patrol 里、同 goroutine 串行读）
	s.mu.Unlock()
	sess, cache, err := serviceBuild(cfg, s.logf)
	if err != nil {
		s.logf("会话建立失败：%v", err)
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

	// 回环桥：谁持会话谁 host（消费方仍连 127.0.0.1:7722/7723，无感知）。
	// 拨号走 healingDial 且**动态取当前会话**（rebuildSession 整会话重建换 s.sess 时，
	// 桥/鉴权/sock 全不动，dial 自动落到新会话上——重建对消费方透明）。
	bridge := newBridgeHost("服务桥", bridgeDirFromCfg(cfg), s.logf, func(ctx context.Context, port uint16) (net.Conn, error) {
		return s.healingDialCurrent(ctx, port)
	}, time.Duration(cfg.DialMs)*time.Millisecond)
	bridge.start()
	s.mu.Lock()
	s.bridge = bridge
	s.mu.Unlock()

	s.setState(svcStateReady, "")
	s.logf("就绪（files/term 桥已起，无 VPN 承载）")

	s.patrol()
}

// healingDialCurrent 服务桥拨号入口：动态取当前会话（rebuildSession 换会后 dial 自动
// 落到新会话），会话不在（收工窗口）按错误返回。
func (s *serviceSession) healingDialCurrent(ctx context.Context, port uint16) (net.Conn, error) {
	sess := s.curSession()
	if sess == nil {
		return nil, errors.New("服务会话不在（收工/重建窗口）")
	}
	return s.healingDial(sess, ctx, port)
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
// 同时失败）各自触发一次也无害。
func (s *serviceSession) healingDial(sess exitSession, ctx context.Context, port uint16) (net.Conn, error) {
	firstCtx, cancel := context.WithTimeout(ctx, serviceDialFirstTry)
	conn, err := sess.DialTCPPort(firstCtx, port)
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
	return sess.DialTCPPort(ctx, port)
}

// curSession 当前会话（收工/重建窗口为 nil）。
func (s *serviceSession) curSession() exitSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sess
}

// noteLadderResult 记一笔阶梯结果（恢复→归零；耗尽→+1）。**只记数**——重建决策在
// recoverStaleSession 的 merge 返回之后做（maybeRebuildIfExhausted）：放在 run 回调里
// 会把整轮重建拉进 gate 的临界区（并发拨号在 merge 里裸等 r.done、不看 ctx），且
// 留下「run 内再进同一 gate = 互等死锁」的结构隐患（评审③-1）。
func (s *serviceSession) noteLadderResult(rc int) {
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
func (s *serviceSession) maybeRebuildIfExhausted() {
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
func (s *serviceSession) markLadderHealthy() {
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
func (s *serviceSession) recoverStaleSession(sess exitSession, why string) int {
	// 入口防陈旧（评审③-3）：调用方抓 sess 与真正起跑之间可能隔了 4s 拨号试探——期间
	// 别的入口若已整会话重建，手里的 sess 是已 Close 的尸体（对它跑阶梯必失败、虚增
	// 耗尽计数）。以当前会话为准，不匹配就直接不跑。
	if cur := s.curSession(); cur == nil || cur != sess {
		return 0
	}
	tr := newTransport(sess)
	if tr == nil {
		return 0
	}
	rc := s.recGate.Merge(recoverR2, why, func(from recoverLevel) int {
		rc := runRecoverLadder(hostsession.RecoverDeps{
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
// 巡检/拨号两入口同权；patrol 只负责探测与触发）。
func (s *serviceSession) patrol() {
	ticker := time.NewTicker(servicePatrolInterval)
	defer ticker.Stop()
	failStreak := 0
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
		tr := newTransport(sess)
		if err == nil {
			failStreak = 0
			s.markLadderHealthy() // 巡检确认健康：耗尽计数归零
			s.noteLink(sess, rtt)
			if tr != nil {
				st := tr.Status()
				s.logf("link: via=%s ep=%s rtt=%dms（服务会话巡检）", st.Via, st.Ep, rtt.Milliseconds())
			}
			continue
		}
		failStreak++
		s.logf("巡检失败（连续 %d）：%v", failStreak, err)
		if failStreak >= serviceFailStreakReset {
			s.recoverStaleSession(sess, "巡检连续失败")
			s.logf("连续 %d 次失败：已重绑本地 socket 并补注册（下一发探测全新握手）", failStreak)
			failStreak = 0
			// 重建若已触发（maybeRebuildIfExhausted），刷新本 tick 的会话引用，
			// 下一 tick 起用新会话（新会话首个出站包自带注册+赛跑，通常一拍内恢复）。
			if cur := s.curSession(); cur != sess {
				if cur == nil {
					return
				}
				sess = cur
			}
		}
	}
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
func (s *serviceSession) rebuildSession(reason string) {
	s.mu.Lock()
	if time.Since(s.rebuildAt) < serviceRebuildCooldown {
		s.mu.Unlock()
		s.logf("REBUILD 整会话重建被限频（%v 内已重建过，继续观察）：原因=%s", serviceRebuildCooldown, reason)
		return
	}
	old, oldCache, cfg := s.sess, s.cache, s.cfg
	s.rebuildAt = time.Now()
	s.mu.Unlock()

	s.logf("REBUILD 整会话重建（%s）：拆旧会话换新（force-stop 同机理，进程内完成）", reason)
	if oldCache != nil {
		_ = oldCache.Save(time.Now()) // 旧实例学到的端点先落盘（新实例 D8 合并会读回）
	}
	if old != nil {
		_ = old.Close()
	}
	sess, cache, err := serviceBuild(cfg, s.logf)
	if err != nil {
		s.logf("REBUILD 新会话建立失败：%v（按 failed 收工）", err)
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
func (s *serviceSession) finish(state, reason string) {
	s.mu.Lock()
	bridge, sess, cache := s.bridge, s.sess, s.cache
	s.bridge, s.sess, s.cache = nil, nil, nil
	s.mu.Unlock()
	if bridge != nil {
		bridge.stop()
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
func (s *serviceSession) closeLog() {
	s.mu.Lock()
	f := s.logFile
	s.logFile = nil
	s.mu.Unlock()
	if f != nil {
		_ = f.Close()
	}
}

// serviceStopInternal ClientCoreServiceStop 的逻辑体（纯 Go 形态供单测）。
// 返回 0 = 已收工（或本就没在跑）｜-1 = 等待超时（旧实例仍在收尾；此后 Start 会
// 一直 -1 直到它真正退出 —— 防止同钥匙双会话，调用方应重试 Stop）。
func serviceStopInternal() int {
	serviceMu.Lock()
	s := serviceCur
	serviceMu.Unlock()
	if s == nil {
		return 0
	}
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

// serviceStatusJSON ClientCoreServiceStatus 的数据源。
// bridgeAuth = 桥鉴权首包 blob 的 hex（魔数+令牌）：只经本进程内存到 ArkTS，
// 不落盘、不进日志/诊断报告（隧道宿主的同名键经 IPC 状态通道分发，语义相同）。
func serviceStatusJSON() string {
	serviceMu.Lock()
	s := serviceCur
	serviceMu.Unlock()
	if s == nil {
		return `{"state":"idle"}`
	}
	state, reason, since := s.snapshotState()
	m := map[string]any{
		"state":  state,
		"reason": reason,
	}
	if !since.IsZero() {
		m["elapsedMs"] = time.Since(since).Milliseconds()
	}
	s.mu.Lock()
	sess, bridge := s.sess, s.bridge
	s.mu.Unlock()
	if bridge != nil {
		if auth := bridge.authHex(); auth != "" {
			m["bridgeAuth"] = auth
		}
		fs, ts, ss := bridge.sockJSON()
		if fs != "" {
			m["bridgeFilesSock"], m["bridgeTermSock"], m["bridgeSpeedSock"] = fs, ts, ss
		}
	}
	if sess != nil {
		if tr := newTransport(sess); tr != nil {
			st := tr.Status()
			_, _, rttMs, _ := s.linkSnapshot()
			m["link"] = map[string]any{"via": st.Via, "ep": st.Ep, "at": st.At, "rttMs": rttMs}
			if id := tr.Identity(); id != nil {
				m["identity"] = map[string]any{"dev": id.ShortDev(), "pub": id.ShortPub()}
			}
		}
		// 流量面（2026-09-26）：服务会话没有 TUN，用 WG 传输层字节数（Bind.RxTx，
		// 含握手/保活与封装开销）；随世代清零（rebuildSession 换会话即新 Bind）。
		// 键名与隧道域 stats 的消费方向一致：rxBytes=下行 / txBytes=上行。
		if core := newCore(sess); core != nil {
			if bind := core.Bind(); bind != nil {
				rx, tx := bind.RxTx()
				m["stats"] = map[string]any{"rxBytes": rx, "txBytes": tx}
			}
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return `{"state":"unknown"}`
	}
	return string(b)
}

//export ClientCoreServiceStop
func ClientCoreServiceStop() C.int { return C.int(serviceStopInternal()) }

//export ClientCoreServiceStatus
func ClientCoreServiceStatus() *C.char { return cstr(serviceStatusJSON()) }
