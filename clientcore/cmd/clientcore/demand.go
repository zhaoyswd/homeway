//go:build cshared

// demand.go — 真实流量需求判定与待发包驱动的立即恢复（openspec demand-driven-recovery）。
//
// 背景（2026-09-23 弹窗事故）：熄屏挂起期及其唤醒活动窗口里，巡检把「本地 EPERM 禁发」
// 与「零流量需求期的对端无响应」当失败证据累积 → markUnhealthy → failed 悬置两小时。
// 本文件把「需求」变成核内一等信号：
//   - 计证据档（每巡检拍）：本拍 App 出站包数 > 0，或新鲜的亮屏位（前台位仅诊断）；
//   - 触发档（下推器）：App 出站新鲜 + 对端接收静默 → 立即异步下推阶梯（不等巡检拍）；
//   - 本地发送错误（EPERM 等）恒为环境噪声：清零计数、不触发换源（进程级禁用下换源无效）。
package main

import (
	"sync/atomic"
	"time"
)

// activityFreshness：扩展下发的亮屏/前台位的新鲜期。挂起期间两侧一起冻结、值停在冻结
// 前——空窗唤醒的第一拍若照读旧值，会把「睡前亮屏」误当「此刻有需求」。核侧巡检的
// 空窗检测与扩展侧的唤醒拍补发（notePumpGap 后立即 SetActivity）共同保证：陈旧位
// 不参与合成，下一拍推送即恢复。取 90s（> 泵节拍 5s × 若干抖动，<< 巡检 60s×2）。
const activityFreshness = 90 * time.Second

// tunActivity：扩展经 NAPI（ClientCoreTunSetActivity）下发的「App 前台 / 设备亮屏」。
// pushedAt 参与新鲜度判定；初始为零值（两处都按 false + 陈旧处理——prepare 早期
// 扩展还没来得及推值，保守不算需求，首拍推送后恢复）。
var tunActivity struct {
	fg       atomic.Bool // 诊断用（需求合成只看 screen——见 activitySignal 的实测依据）
	screen   atomic.Bool
	pushedAt atomic.Int64 // unix nano
}

// setTunActivity 记录扩展下发的亮屏/前台诊断位（每拍必发；唤醒拍扩展会立即补一次）。
func setTunActivity(fg, screen bool) {
	tunActivity.fg.Store(fg)
	tunActivity.screen.Store(screen)
	tunActivity.pushedAt.Store(time.Now().UnixNano())
}

// activitySignal 返回（值, 新鲜）。**值 = 亮屏位**（fg 不参与合成——2026-09-23 真机实测：
// 熄屏不触发 App 的 onBackground，「前台」名义残留 true 而用户已看不见任何 UI；需求的
// 语义是「用户在用网」，熄屏时的名义前台不代表需求。fg 位保留仅作诊断）。新鲜 =
// 距上次推送未超过 activityFreshness——挂起空窗后旧值自然过期（两侧一起冻结，醒来时
// Since(pushedAt) 已巨大），唤醒拍扩展先推新值、巡检后评估（spec「先刷新再评估」由时序保证）。
func activitySignal(now time.Time) (active, fresh bool) {
	ns := tunActivity.pushedAt.Load()
	if ns == 0 {
		return false, false
	}
	return tunActivity.screen.Load(), now.Sub(time.Unix(0, ns)) < activityFreshness
}

// demandState 最近一次巡检拍的需求判定结果（状态 JSON 的 demand 段；扩展门控同源消费）。
type demandState struct {
	active atomic.Bool
	reason atomic.Value // string：依据（出站包/前台/亮屏/无）
	at     atomic.Int64
}

var lastDemand demandState

// noteDemand 记录一拍的需求判定（巡检循环每拍调用；下推器不写）。
func noteDemand(active bool, reason string, now time.Time) {
	lastDemand.active.Store(active)
	lastDemand.reason.Store(reason)
	lastDemand.at.Store(now.UnixNano())
}

// demandSnapshotJSON 供 tunStatusJSON 拼 demand 段。
func demandSnapshotJSON() map[string]any {
	ns := lastDemand.at.Load()
	at := int64(0)
	if ns != 0 {
		at = time.Unix(0, ns).UnixMilli()
	}
	r, _ := lastDemand.reason.Load().(string)
	if r == "" {
		r = "未判定"
	}
	return map[string]any{
		"active": lastDemand.active.Load(),
		"reason": r,
		"at":     at,
		// fg 仅诊断（不参与需求合成，见 activitySignal 的实测依据）——评审 3-7：
		// 死字段问题，进 JSON 给诊断面一个出口。
		"fg": tunActivity.fg.Load(),
	}
}

// patrolEvidenceGate 巡检拍的证据推进（纯函数，单测覆盖；评审 H3 整改后成功拍也走这里）：
//   - 探测成功 ⇒ 计数清零（counted=false——成功拍不计失败证据；旧 patrolFailStreak 的
//     成功清零语义在此恢复：F,S,F,F 必须停在 2，而不是拼出 3 连败）；
//   - localNoise（探测窗内有采纳路径本地发送错误）或 !demand ⇒ 计数清零、不计证据；
//   - 计数拍之间间隔超过 patrolFailWindow ⇒ 计数作废重来（不跨长时间拼凑）；
//   - 正常计数拍 ⇒ +1。
//
// 返回推进后的计数与「本拍是否计入失败证据」。
func patrolEvidenceGate(localNoise, demand bool, failStreak int, lastCountedFail, now time.Time, probeErr error) (int, bool) {
	if probeErr == nil {
		return 0, false // 成功拍清零（"连败"的连续语义）
	}
	if localNoise || !demand {
		return 0, false
	}
	if failStreak > 0 && !lastCountedFail.IsZero() && now.Sub(lastCountedFail) > patrolFailWindow {
		failStreak = 0
	}
	return failStreak + 1, true
}

// patrolDemand 巡检拍的需求合成：本拍 App 出站包数（hub 计数取走）‖ 新鲜的前台/亮屏位。
// 返回（active, reason）。reason 进边沿日志与状态 JSON，排障时「为什么这拍算/不算需求」
// 有据可查。TUN 位只代表进隧道的应用流量（栈 B 核心自连与被绕过应用不产生）——
// 「用户在 App 内用 files/终端」由前台位承载（见 design D1 的限制说明）。
func patrolDemand(outPkts int64, now time.Time) (bool, string) {
	if outPkts > 0 {
		return true, "出站包"
	}
	if act, fresh := activitySignal(now); fresh {
		if act {
			return true, "亮屏"
		}
		return false, "熄屏"
	}
	return false, "熄屏（位陈旧）"
}

// ---------- 待发包下推器（demand-driven-recovery D4） ----------

// 下推判据的常量：
//   - outboundFresh：App 出站包新鲜窗——「有包在等」的口径（下推器 1s 节拍检查，
//     最近 5s 内有过出站即视为等待中）；
//   - recvStale：接收静默阈值——已采纳路径上太久没收到对端任何包 = 隧道大概率死了。
//     取 90s（阈值与旧 handshakeheal 机制的历史取值同源，该机制已随 4.4 退役——
//     健康会话 rekey 120s，正常浏览请求-响应对称，90s 无任何接收且持续有出站 =
//     确实过不去）；
//   - pushCooldown：下推限频。R1 探测先行、恢复即零动作，但别让持续黑洞刷屏——
//     一轮 R1（最坏 ~13s）+ 60s 冷却内不重复。
const (
	outboundFresh = 5 * time.Second
	recvStale     = 90 * time.Second
	pushCooldown  = 60 * time.Second
)

// shouldPush：待发包下推的判据纯函数（表驱动单测钉住语义——三轮评审反复点名的
// 「判据链无单测」收口）。判据见常量注释；零值 recvAt = 从未收到对端包，按静默的
// 极端形态处理（软失败世代）。
func shouldPush(outAt, recvAt, now time.Time, hasFreshLocalErr bool, sinceLastPush time.Duration) bool {
	if outAt.IsZero() || now.Sub(outAt) > outboundFresh {
		return false // 没有出站在等
	}
	if !recvAt.IsZero() && now.Sub(recvAt) < recvStale {
		return false // 链路最近有回包：不构成「过不去」
	}
	if hasFreshLocalErr {
		return false // 采纳路径本地错误（挂起禁发）：换源无效，等环境恢复
	}
	return sinceLastPush >= pushCooldown
}

// startDemandPusher 待发包驱动的立即恢复（跟随世代：stop 即退）。
// 与巡检（60s 拍）互补：用户亮屏后第一个包到达的瞬间即触发，不等下一拍。
// 铁律（design D4）：下推一律 `go` 异步——recoverGate.merge 对执行中的再触发是
// **阻塞等待整轮**，在本循环或 Bind 调用栈内同步执行会卡死触发链。
// panic 兜底在**循环体每轮**（评审 4 低-3）：一轮 panic 不废整代下推器。
func startDemandPusher(run *tunRun, cl exitSession, logf Logf) {
	go func() {
		lastPush := time.Time{}
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-run.stop:
				return
			case <-tick.C:
			}
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						logf("⚠️ 待发包下推器本轮 panic（已恢复，下推器继续运行）：%v", rec)
					}
				}()
				tr := newTransport(cl)
				if tr == nil {
					return // 旧栈无门面：本轮跳过（不退出——cl 世代内可能换实现）
				}
				now := time.Now()
				if !shouldPush(tr.LastTunOutboundAt(), tr.LastRecvAt(), now,
					tr.LocalSendErrWithin(outboundFresh), now.Sub(lastPush)) {
					return
				}
				lastPush = now
				recvAt := tr.LastRecvAt()
				staleDesc := "从未收到对端包"
				if !recvAt.IsZero() {
					staleDesc = now.Sub(recvAt).Round(time.Second).String()
				}
				logf("待发包在等但链路静默 %s：异步下推阶梯（R1 起跑，不等巡检拍）", staleDesc)
				go func() {
					// 异步且吞错：阶梯自身有探测先行与重入合并（阻塞等待语义——正因为
					// 它会等整轮，才必须在独立 goroutine 里调）。panic 兜底独立。
					defer func() {
						if rec := recover(); rec != nil {
							logf("⚠️ 待发包下推的阶梯调用 panic（已恢复，仅本轮受影响）：%v", rec)
						}
					}()
					_ = runRecoverAt(recoverR1, "待发包")
				}()
			}()
		}
	}()
}
