package hostsession

// recover.go — 统一恢复阶梯（openspec recovery-ladder；随迁自 cshared recover.go，
// host-registry-daemon D1/r2 A1-1：隧道与服务两域共用）。隧道域入口 runRecoverAt/
// recoverTunnelReady **留守 cshared**（recover.go 尾段），经壳清单的恢复闭包接缝
// 引用本文件的导出面。
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
// var 而非 const：进程内集成测试（同包 app_service_recover_test.go）会把它们缩到毫秒级
// 让用例秒级跑完；生产路径无并发改写。【非串扰共享点 #2（D1 登记）：只读共享、仅同包
// 测试改写。】
var (
	recoverPreProbeTimeout = 3 * time.Second
	recoverVerifyTimeout   = 10 * time.Second
	recoverActionTimeout   = 2 * time.Second
)

// ---- 导出版（cshared 留守壳与隧道域入口消费；r2 A1-2：扩列项均有跨包消费者） ----
//
// 类型/常量/函数保留未导出原名（随迁用例零改动），导出版走别名/薄壳——r4 认可的路径。
// 1.2 过渡：三个预算 var 暂以导出名透出（留守 cshared 的进程内集成测试要改写它们；
// 1.3 该用例随迁同包后即收回）。

// RecoverLevel 是 recoverLevel 的导出别名（cshared 留守壳 `type recoverLevel =
// hostsession.RecoverLevel` 经它引用同一类型）。
type RecoverLevel = recoverLevel

const (
	RecoverR1 = recoverR1 // 重握手（保采纳）
	RecoverR2 = recoverR2 // 换源（保采纳）
	RecoverR3 = recoverR3 // 重赛跑（清采纳）
)

var (
	// RunRecoverLadder 阶梯本体的导出版（留守 runRecoverAt 经壳调用）。
	RunRecoverLadder = runRecoverLadder
	// RecoverLevelName / ClampRecoverLevel 的导出版（probe_lib 的 NAPI 入口壳用）。
	RecoverLevelName  = recoverLevelName
	ClampRecoverLevel = clampRecoverLevel
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

// RecoverDeps 阶梯依赖面（生产 = 当前世代会话；单测注入）。字段导出——留守 cshared
// 的隧道域入口（runRecoverAt）与跨包测试经复合字面量构造（D1 恢复闭包接缝）。
// Tr 的类型是未导出接口 recoverTransport：跨包构造只要求字段可赋值
// （*wgcore.Transport 方法集全导出，满足）。
type RecoverDeps struct {
	Probe func(ctx context.Context) error // 有界存活探测（PathProbe：nil = 对端可达）
	Tr    recoverTransport
	Logf  Logf
}

// recoverProbeOK 一发有界探测。假实现即时返回时预算不构成等待，测试因此不慢。
func recoverProbeOK(d RecoverDeps, budget time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	return d.Probe(ctx) == nil
}

// runRecoverLadder 阶梯本体：从 from 起、失败自动升级直到 R3（核内最后一档）。
func runRecoverLadder(d RecoverDeps, from recoverLevel, cause string) int {
	// 返回码契约（**扩展侧据此区分"该怪谁"**；改这里要同步 ArkTS 侧 rebindRcText/attribute 与 AGENTS）：
	//	 0 = 某档探测通过（恢复）
	//	-1 = 走完 R3 仍有界探测失败——网络能用，问题在出口/路径侧（应升级整套重建）
	//	-3 = 本地动作超时（挂起期/低功耗/路由表空）——与 -1 归因完全不同
	//	-4 = 本地动作立即失败（err 带原因；也含"没有新栈传输门面"）
	// （-2 = 没有 attached 隧道，由留守的 runRecoverAt 判定，这里不产。）
	started := time.Now()
	// 本轮已执行过的动作（档位推进只做增量；直入高档时把低档动作补齐）。
	didReset, didRebind, didRearm := false, false, false
	for lvl := from; lvl <= recoverR3; lvl++ {
		// 探测先行：已恢复（或上一档动作的应答迟到了一拍）则不再加码。复探通过时
		// 归因到上一档（评审 P2-1：否则先打「恢复于 R1」再打「零档位动作」，
		// 按判据行统计命中率会把治愈记到起查头上）。
		if recoverProbeOK(d, recoverPreProbeTimeout) {
			d.Tr.NotePathAlive() // 验证探测通过 = 该路径完成一次真实往返 → 落已验证
			if lvl > from {
				d.Logf("RECOVER %s 动作生效（%s 复探通过——上一发验证探测只是丢包，原因=%s，起跑=%s，耗时 %v）",
					recoverLevelName(lvl-1), recoverLevelName(lvl), cause, recoverLevelName(from),
					time.Since(started).Round(time.Millisecond))
			} else {
				d.Logf("RECOVER 已恢复（%s 起查，原因=%s，零档位动作，耗时 %v）",
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
				if !d.Tr.RefreshReg() {
					// false = bind 已收工或无采纳地址：R1 注定无效，留一行现场证据。
					d.Logf("RECOVER R1 重握手（原因=%s）：补注册未发出（bind 已收工或无采纳地址）", cause)
				}
				if rerr := d.Tr.ResetPeerSession(); rerr != nil {
					// 失败含两个子情形（core 的错误文本可区分）：移除失败 = 原会话仍在，
					// 按原会话验证；回写失败 = peer 已删且无会话，验证探测必然失败 →
					// 逐级升级直至 -1 交 R4 重建。高档位因 didReset 去重不再重试丢会话：
					// 两步同 device 同 UAPI、一成一败极罕见，不值得在这里加专门重试。
					d.Logf("RECOVER R1 重握手（原因=%s）：丢会话失败（%v）—— 按既有状态验证", cause, rerr)
				}
				return nil
			}); err != nil {
				return recoverLocalFail(d, lvl, cause, err)
			}
			d.Logf("RECOVER R1 重握手（原因=%s）：补注册 + 丢会话（保采纳）", cause)
		}
		if lvl >= recoverR2 && !didRebind {
			didRebind = true
			if err := runBoundedAction(recoverActionTimeout, d.Tr.Rebind); err != nil {
				return recoverLocalFail(d, lvl, cause, err) // Rebind 立即失败 = -4，超时 = -3
			}
			d.Logf("RECOVER R2 换源（原因=%s）：换本地 socket（保采纳）", cause)
		}
		if lvl >= recoverR3 && !didRearm {
			didRearm = true
			if err := runBoundedAction(recoverActionTimeout, func() error {
				d.Tr.Rearm()
				return nil
			}); err != nil {
				return recoverLocalFail(d, lvl, cause, err)
			}
			d.Logf("RECOVER R3 重赛跑（原因=%s）：清采纳，学习缓存候选兜底", cause)
		}
		if recoverProbeOK(d, recoverVerifyTimeout) {
			d.Logf("RECOVER 恢复于 %s（原因=%s，起跑=%s，耗时 %v）",
				recoverLevelName(lvl), cause, recoverLevelName(from), time.Since(started).Round(time.Millisecond))
			return 0
		}
	}
	d.Logf("RECOVER 走完 R1→R3 仍未恢复（起跑=%s，原因=%s，耗时 %v）—— 交上层升级",
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
func recoverLocalFail(d RecoverDeps, lvl recoverLevel, cause string, err error) int {
	rc := -4
	if errors.Is(err, errActionTimeout) {
		rc = -3
	}
	d.Logf("RECOVER %s 本地动作失败（原因=%s，rc=%d）：%v", recoverLevelName(lvl), cause, rc, err)
	return rc
}

// errActionTimeout：runBoundedAction 的预算用尽哨兵，区别于被调动作自己返回的本地错误。
// （随迁自 cshared tunmode.go，r4 订正：随迁、包内未导出——共享阶梯是唯一消费者，
// 无跨包消费者故不导出。）
var errActionTimeout = errors.New("本地动作超时")

// runBoundedAction 在预算内跑一个同步动作，把"卡住"变成可判定的失败。
//
// 超时后动作的 goroutine 仍会跑完（不泄漏锁、不重复加锁）；调用方只当它失败。这条路径上
// 真正危险的是**无界等待**：换网重绑会一直占着扩展那次调用，巡检里的自重绑则会
// 让整个巡检 goroutine 永久停摆（连"3 连败"都不再上报）。Rebind 是幂等的换 socket，重复调用无害。
// （随迁自 cshared tunmode.go，包内未导出——796c0fb 实测调用点全在本包共享阶梯内。）
func runBoundedAction(budget time.Duration, f func() error) error {
	done := make(chan error, 1)
	go func() { done <- f() }()
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		return errActionTimeout
	}
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
// 会让新隧道最坏等 ~13s 拿一个无意义的 rc）；服务腿域（本包 Session 的独立 WG 会话）
// 挂在 Session 上——两个域操作不同会话，互不等待。

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

// RecoverGate 是 recoverGate 的导出别名（cshared tunRun 字段类型经壳引用同一类型）。
type RecoverGate = recoverGate

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

// Merge 是 merge 的导出包装（D1 恢复闭包接缝：留守 cshared 的 runRecoverAt 经它调用；
// 保留未导出 merge 使随迁用例零改动——r4 认可路径）。
func (g *recoverGate) Merge(from RecoverLevel, cause string, run func(from RecoverLevel) int) int {
	return g.merge(from, cause, run)
}
