//go:build cshared

// recover.go — 隧道域恢复入口（openspec recovery-ladder 的隧道侧消费面）。
//
// 共享阶梯（档位/依赖面/单飞闸/预算，r1 A1 拆分：recoverLevel/recoverDeps/
// runRecoverLadder/recoverGate 及三个预算 var）已随迁 host-registry-daemon D1 至
// clientcore/hostsession/recover.go——隧道与服务两域共用；本文件只剩**隧道域**两件：
//   - recoverTunnelReady：「有没有可恢复的隧道」的判定（-2 的唯一真源；纯判断，单测钉住）；
//   - runRecoverAt：在当前世代的隧道上执行恢复阶梯（巡检失败 / 挂起唤醒 / 扩展下推共用）。
//
// 对随迁符号的引用经 hostsession_shell.go 的恢复闭包接缝（D1 壳清单 13-16）：
// recoverLevel 类型别名、RecoverDeps 导出字段直接构造、RunRecoverLadder var 别名、
// recoverGate.Merge 导出版方法。
package main

import (
	"context"

	"github.com/zhaoyswd/homeway/clientcore/hostsession"
)

// recoverTunnelReady 「有没有可恢复的隧道」的判定（-2 的唯一真源；纯判断，单测钉住）。
// prepare 期必须回答 false：那时单飞锁已持有但没有数据面，扩展在启动窗口里做恢复毫无
// 意义、甚至据此触发整套重建（旧 tunRebindWait 的事故口径）。
func recoverTunnelReady(hasRun, coreRunning bool, stage tunStage, hasClient bool) bool {
	return hasRun && coreRunning && stage == stageAttached && hasClient
}

// runRecoverAt 在**当前世代**的隧道上执行恢复阶梯（巡检失败 / 挂起唤醒 / 扩展下推共用）。
// 没有已接管数据面的隧道时返回 -2（语义沿用旧 tunRebindWait：不构成网络结论——
// 两阶段启动下 prepare 阶段锁也已持有，但那时还没有数据面，必须按"没有隧道"回答，
// 否则扩展会在启动窗口里做无意义恢复、甚至据此触发整套重建）。
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
	return r.recoverGate.Merge(from, cause, func(from recoverLevel) int {
		return runRecoverLadder(hostsession.RecoverDeps{
			Probe: func(ctx context.Context) error { return cl.PathProbe(ctx) },
			Tr:    tr,
			Logf:  logf,
		}, from, cause)
	})
}
