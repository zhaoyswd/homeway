//go:build cshared

// recover.go — 统一恢复阶梯（openspec recovery-ladder）。
//
// 四份各自为政的恢复组合（巡检失败档 / 巡检 3 连败档 / 扩展换网档 / files/term 服务腿档）
// 收编为一条阶梯：R1 重握手（保采纳）→ R2 换源（保采纳）→ R3 重赛跑（清采纳）→
// R4 整套重建（扩展，tunmode 之外）。每档**探测先行**（已恢复则零动作）、失败自动升级、
// 成功即止；单飞 + 执行中触发合并（后来者可提高本轮承诺档位）。
//
// 档位语义（specs/wg-native-transport「统一恢复阶梯」）：
//
//	R1 = 补注册 + 丢本地会话（Bind 采纳不动）—— 会话死、路径/socket 活
//	R2 = R1 动作 + Rebind 换本地 socket（采纳仍不动）—— socket 失效、网络没变
//	R3 = R2 动作 + Rearm 清采纳重赛跑（学习缓存候选兜底）—— 出口端点/网络变了
package main

import (
	"context"
	"errors"
	"sync"
	"time"
)

// recoverLevel 阶梯档位：数字越大动作越重。
type recoverLevel int

const (
	recoverR1 recoverLevel = 1 // 重握手（保采纳）
	recoverR2 recoverLevel = 2 // 换源（保采纳）
	recoverR3 recoverLevel = 3 // 重赛跑（清采纳）
)

// recoverLevelName 档位名（日志判据行用）。
func recoverLevelName(l recoverLevel) string {
	switch l {
	case recoverR1:
		return "R1 重握手"
	case recoverR2:
		return "R2 换源"
	case recoverR3:
		return "R3 重赛跑"
	}
	return "R?"
}

// clampRecoverLevel 把外部输入（NAPI int）钳到合法档位。
func clampRecoverLevel(from int) recoverLevel {
	l := recoverLevel(from)
	if l < recoverR1 {
		return recoverR1
	}
	if l > recoverR3 {
		return recoverR3
	}
	return l
}

// 阶梯预算：
//
//	探测先行用短预算 —— 会话活着时一个 RTT 内必答；死等满验证预算再起步会把
//	「唤醒即恢复」的目标（解锁后 ≤5s）吃掉。
//	动作后的验证探测用巡检同宽的 perTry=10s —— 要容纳 WG 首发握手丢失后的 5s 重发。
//	本地动作（Rebind 起 socket）预算 2s：把「本地网络栈卡住/被系统限制」（rc=-3）和
//	「包发出去没回音」（rc=-1）分开 —— 两者归因完全不同（旧 tunRebindWait 时代的教训）。
//
// ⚠️ 探测是**契约的一半**，不是可选优化（旧 tunRebindWait 注释的教训，随其收编搬到这里）：
// Rebind 只做 `net.ListenUDP + 换 fd`，拿不到 socket 才会失败 ⇒ 少了 PathProbe 就等于把
// 「本地换了个 socket」谎报成「对端可达」，换网 + 出口不可达会被判成已恢复、界面假已连接
// 直到巡检 3 连败。阶梯每档动作后必带验证探测，正是这条契约的延续。
// var 而非 const：进程内集成测试（app_service_recover_test.go）会把它们缩到毫秒级
// 让用例秒级跑完；生产路径无并发改写。
var (
	recoverPreProbeTimeout = 3 * time.Second
	recoverVerifyTimeout   = 10 * time.Second
	recoverActionTimeout   = 2 * time.Second
)

// recoverTransport 阶梯要的传输动作面（*wgcore.Transport 满足；单测注入假实现）。
type recoverTransport interface {
	RefreshReg() bool
	ResetPeerSession() error // 保采纳：只丢会话
	Rebind() error           // 换本地 socket，采纳不动
	Rearm()                  // 清采纳、重赛跑
	// NotePathAlive：验证探测通过后调用——该路径完成一次真实往返，落缓存已验证
	//（endpoint-freshness C-2：覆盖「R3 救回后闲置」窗口）。
	NotePathAlive()
}

// recoverDeps 阶梯依赖面（生产 = 当前世代会话；单测注入）。
type recoverDeps struct {
	probe func(ctx context.Context) error // 有界存活探测（PathProbe：nil = 对端可达）
	tr    recoverTransport
	logf  Logf
}

// recoverProbeOK 一发有界探测。假实现即时返回时预算不构成等待，测试因此不慢。
func recoverProbeOK(d recoverDeps, budget time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	return d.probe(ctx) == nil
}

// runRecoverLadder 阶梯本体：从 from 起、失败自动升级直到 R3（核内最后一档）。
func runRecoverLadder(d recoverDeps, from recoverLevel, cause string) int {
	// 返回码契约（**扩展侧据此区分"该怪谁"**；改这里要同步 ArkTS 侧 rebindRcText/attribute 与 AGENTS）：
	//	 0 = 某档探测通过（恢复）
	//	-1 = 走完 R3 仍有界探测失败——网络能用，问题在出口/路径侧（应升级整套重建）
	//	-3 = 本地动作超时（挂起期/低功耗/路由表空）——与 -1 归因完全不同
	//	-4 = 本地动作立即失败（err 带原因；也含"没有新栈传输门面"）
	// （-2 = 没有 attached 隧道，由外层 runRecoverAt 判定，这里不产。）
	started := time.Now()
	// 本轮已执行过的动作（档位推进只做增量；直入高档时把低档动作补齐）。
	didReset, didRebind, didRearm := false, false, false
	for lvl := from; lvl <= recoverR3; lvl++ {
		// 探测先行：已恢复（或上一档动作的应答迟到了一拍）则不再加码。复探通过时
		// 归因到上一档（评审 P2-1：否则先打「恢复于 R1」再打「零档位动作」，
		// 按判据行统计命中率会把治愈记到起查头上）。
		if recoverProbeOK(d, recoverPreProbeTimeout) {
			d.tr.NotePathAlive() // 验证探测通过 = 该路径完成一次真实往返 → 落已验证
			if lvl > from {
				d.logf("RECOVER %s 动作生效（%s 复探通过——上一发验证探测只是丢包，原因=%s，起跑=%s，耗时 %v）",
					recoverLevelName(lvl-1), recoverLevelName(lvl), cause, recoverLevelName(from),
					time.Since(started).Round(time.Millisecond))
			} else {
				d.logf("RECOVER 已恢复（%s 起查，原因=%s，零档位动作，耗时 %v）",
					recoverLevelName(from), cause, time.Since(started).Round(time.Millisecond))
			}
			return 0
		}
		// 档位动作**一律有界**（评审 P0-1：ResetPeerSession 走 dev.IpcSet，无界卡住会
		// 占死恢复闸与巡检 goroutine——巡检失败路径是同步调用，卡住连 3 连败都不再上报）。
		// 超时按 -3 收轮；动作自身的立即失败只记日志（沿用「丢会话失败——按既有状态验证」语义）。
		if lvl >= recoverR1 && !didReset {
			didReset = true
			if err := runBoundedAction(recoverActionTimeout, func() error {
				if !d.tr.RefreshReg() {
					// false = bind 已收工或无采纳地址：R1 注定无效，留一行现场证据。
					d.logf("RECOVER R1 重握手（原因=%s）：补注册未发出（bind 已收工或无采纳地址）", cause)
				}
				if rerr := d.tr.ResetPeerSession(); rerr != nil {
					// 失败含两个子情形（core 的错误文本可区分）：移除失败 = 原会话仍在，
					// 按原会话验证；回写失败 = peer 已删且无会话，验证探测必然失败 →
					// 逐级升级直至 -1 交 R4 重建。高档位因 didReset 去重不再重试丢会话：
					// 两步同 device 同 UAPI、一成一败极罕见，不值得在这里加专门重试。
					d.logf("RECOVER R1 重握手（原因=%s）：丢会话失败（%v）—— 按既有状态验证", cause, rerr)
				}
				return nil
			}); err != nil {
				return recoverLocalFail(d, lvl, cause, err)
			}
			d.logf("RECOVER R1 重握手（原因=%s）：补注册 + 丢会话（保采纳）", cause)
		}
		if lvl >= recoverR2 && !didRebind {
			didRebind = true
			if err := runBoundedAction(recoverActionTimeout, d.tr.Rebind); err != nil {
				return recoverLocalFail(d, lvl, cause, err) // Rebind 立即失败 = -4，超时 = -3
			}
			d.logf("RECOVER R2 换源（原因=%s）：换本地 socket（保采纳）", cause)
		}
		if lvl >= recoverR3 && !didRearm {
			didRearm = true
			if err := runBoundedAction(recoverActionTimeout, func() error {
				d.tr.Rearm()
				return nil
			}); err != nil {
				return recoverLocalFail(d, lvl, cause, err)
			}
			d.logf("RECOVER R3 重赛跑（原因=%s）：清采纳，学习缓存候选兜底", cause)
		}
		if recoverProbeOK(d, recoverVerifyTimeout) {
			d.logf("RECOVER 恢复于 %s（原因=%s，起跑=%s，耗时 %v）",
				recoverLevelName(lvl), cause, recoverLevelName(from), time.Since(started).Round(time.Millisecond))
			return 0
		}
	}
	d.logf("RECOVER 走完 R1→R3 仍未恢复（起跑=%s，原因=%s，耗时 %v）—— 交上层升级",
		recoverLevelName(from), cause, time.Since(started).Round(time.Millisecond))
	return -1
}

// recoverLocalFail 本地动作失败（-3 超时 / -4 立即失败）：路径还没轮到被判，是本机起不了 socket。
//
// ⚠️ 超时动作的 goroutine 仍会跑完（runBoundedAction 语义），而 ResetPeerSession 的
// IpcSet 无法取消——若它**晚到成功**，本地会话会在阶梯返回之后才被丢掉。后果保守：
// 下一拍巡检探测失败、再走一轮阶梯（会被记因为新故障，而非「上一轮超时动作的迟到
// 生效」），不会假活。这是 Go 取消不了阻塞 IpcSet 的固有限制；超时后强制再验一发
// （+10s）代价大于收益，接受并在此留档。
func recoverLocalFail(d recoverDeps, lvl recoverLevel, cause string, err error) int {
	rc := -4
	if errors.Is(err, errActionTimeout) {
		rc = -3
	}
	d.logf("RECOVER %s 本地动作失败（原因=%s，rc=%d）：%v", recoverLevelName(lvl), cause, rc, err)
	return rc
}

// ---------- 单飞与触发合并 ----------
//
// 同一时刻每个恢复域只跑一轮阶梯；执行中的再次触发**合并**：等当前轮结束、共享其结果。
// 不需要抬高档位——阶梯本就从起跑档自动升级到 R3，先到的轮次失败时自然会覆盖后来者要的
// 重档；而先到的轮次在轻档成功 = 旧路径仍在应答（重档诉求本来就不成立）。跨世代的陈旧
// 轮次不构成死等：旧会话收工后探测即时报错，旧轮秒级自灭。
//
// 闸是**按恢复域实例化**的：隧道域挂在 tunRun 上（评审 P1-1：按**世代**隔离——旧世代
// 的陈旧轮最多占自己的闸一轮预算，新世代的恢复不必等死世代的结论；此前的包级单例
// 会让新隧道最坏等 ~13s 拿一个无意义的 rc）；服务腿域（app_service 的独立 WG 会话）
// 挂在 serviceSession 上——两个域操作不同会话，互不等待。

// recoverRound 一轮执行中的阶梯：结果随轮次对象走（不落在闸的共享字段上）——
// 等待方读到的**必然是自己等的那一轮**的 rc，不会被紧接的下一轮覆写
// （rc 写入先于 close(done)，经 channel close 的 happens-before 对等待方可见）。
type recoverRound struct {
	done chan struct{}
	rc   int
}

type recoverGate struct {
	mu  sync.Mutex
	cur *recoverRound // 非 nil = 有轮在执行
}

// merge 单飞入口：执行中触发 → 等待共享结果；否则起新一轮。
func (g *recoverGate) merge(from recoverLevel, cause string, run func(from recoverLevel) int) int {
	g.mu.Lock()
	if g.cur != nil {
		r := g.cur
		g.mu.Unlock()
		<-r.done
		return r.rc
	}
	r := &recoverRound{done: make(chan struct{})}
	g.cur = r
	g.mu.Unlock()

	rc := run(from)

	g.mu.Lock()
	g.cur = nil
	r.rc = rc
	close(r.done)
	g.mu.Unlock()
	return rc
}

// runRecoverAt 在**当前世代**的隧道上执行恢复阶梯（巡检失败 / 挂起唤醒 / 扩展下推共用）。
// 没有已接管数据面的隧道时返回 -2（语义沿用旧 tunRebindWait：不构成网络结论——
// 两阶段启动下 prepare 阶段锁也已持有，但那时还没有数据面，必须按"没有隧道"回答，
// 否则扩展会在启动窗口里做无意义恢复、甚至据此触发整套重建）。
// recoverTunnelReady 「有没有可恢复的隧道」的判定（-2 的唯一真源；纯判断，单测钉住）。
// prepare 期必须回答 false：那时单飞锁已持有但没有数据面，扩展在启动窗口里做恢复毫无
// 意义、甚至据此触发整套重建（旧 tunRebindWait 的事故口径）。
func recoverTunnelReady(hasRun, coreRunning bool, stage tunStage, hasClient bool) bool {
	return hasRun && coreRunning && stage == stageAttached && hasClient
}

func runRecoverAt(from recoverLevel, cause string) int {
	r := currentTunRun()
	var cl exitSession
	if r != nil {
		cl = r.client()
	}
	st, _, _, _ := tunStageSnapshot()
	if !recoverTunnelReady(r != nil, probeRunning.Load() != 0, st, cl != nil) {
		return -2
	}
	tr := newTransport(cl)
	if tr == nil {
		return -4
	}
	logf := tunLogf(r)
	return r.recoverGate.merge(from, cause, func(from recoverLevel) int {
		return runRecoverLadder(recoverDeps{
			probe: func(ctx context.Context) error { return cl.PathProbe(ctx) },
			tr:    tr,
			logf:  logf,
		}, from, cause)
	})
}
