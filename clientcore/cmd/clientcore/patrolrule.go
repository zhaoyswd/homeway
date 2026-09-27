//go:build cshared

// patrolrule.go — 链路巡检的**纯决策**部分。
//
// 4.4 起只剩「失败计数怎么走」这一条：探测结果的判读（via/ep/学习缓存）随旧栈删除 ——
// 新栈的链路快照直接取 wgcore 的 `Transport.Status()`，端点学习由 wtransport 自己管。
package main

import "time"

// regRefreshEvery：隧道建立后补发注册的周期。
//
// 出口设备表按「最近一次成功注册」判活跃（见 openspec/changes/device-identity-persist）：
// 长连设备只有周期性补发注册，活跃时间才会前进，TTL/容量回收才不会误伤它。
// 5 分钟 ≪ 10 分钟活跃宽限期（容忍一次丢包或一次巡检停顿）。
const regRefreshEvery = 5 * time.Minute

// shouldRefreshReg：到点该不该补发注册（纯函数）。last 零值 = 本世代还没发过 —— 首拍就补一发，
// 让出口日志里尽快出现该设备的活跃判据。
func shouldRefreshReg(last, now time.Time) bool {
	if last.IsZero() {
		return true
	}
	return now.Sub(last) >= regRefreshEvery
}

// suspendGapDetected 巡检空窗判定（openspec recovery-ladder）：本拍实际间隔远超 2× 巡检
// 周期 = 进程被系统冻结过（平台冻结不停系统单调钟，Go 定时器在解冻后补发，迟到量即挂起
// 时长；与服务腿巡检 app_service.go 的「gap > 2×间隔」同款口径）。
// 挂起唤醒后 WG 会话大概率已死（>180s 必死）、本地 socket 可能已失效——判定命中即触发
// 恢复阶梯（R1 起跑），不再等本拍探测失败走 3 连败。last 零值（首拍）无基线，恒 false。
func suspendGapDetected(last, now time.Time, interval time.Duration) bool {
	if last.IsZero() {
		return false
	}
	return now.Sub(last) > 2*interval
}
