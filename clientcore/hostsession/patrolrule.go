package hostsession

// patrolrule.go — 巡检循环节拍的共享纯决策（FIX-21 收口：手机门〔cmd/clientcore〕
// 与桌面门〔Session.patrol〕共用的三个节拍判定，单一真源。此前手机侧一份
// 〔cshared patrolrule.go〕、桌面侧零份——评审点名的两处漂移〔缺补注册节拍、
// 缺噪声长停逃逸〕正是「桌面没接这些规则」的直接后果）。

import "time"

// RegRefreshEvery：隧道建立后补发注册的周期。
//
// 出口设备表按「最近一次成功注册」判活跃（openspec/changes/device-identity-persist）：
// 长连设备只有周期性补发注册，活跃时间才会前进，TTL/容量回收才不会误伤它。
// 5 分钟 ≪ 10 分钟活跃宽限期（容忍一次丢包或一次巡检停顿）。
const RegRefreshEvery = 5 * time.Minute

// ShouldRefreshReg：到点该不该补发注册（纯函数）。last 零值 = 本世代还没发过——
// 首拍就补一发，让出口日志里尽快出现该设备的活跃判据。
func ShouldRefreshReg(last, now time.Time) bool {
	if last.IsZero() {
		return true
	}
	return now.Sub(last) >= RegRefreshEvery
}

// NoiseEscalateAfter：本地错误门控的长停逃逸阈值。本地类错误混着两种形态——进程级
// 禁发（挂起 EPERM，换源无效，分钟内随环境恢复解除）与「采纳路径本身发不出去」
// （换网后陈 LAN 采纳地址 ENETUNREACH 等）。后者若被噪声门控无限期抑制，核内将无
// 任何逃逸；持续超过本阈值即按质量失败计，进入正常升级链。
const NoiseEscalateAfter = 3 * time.Minute

// NoiseEscalated：噪声长停逃逸推进（纯函数状态机，每巡检拍恰调用一次）。
// noise=true：首拍记起点（since 零值）；持续超过 NoiseEscalateAfter 判逃逸
// （escalated=true，调用方按质量失败计——R2 换源是解药），并把起点清零重新计时。
// noise=false：清零返回。返回推进后的起点（调用方回写自己的状态）。
func NoiseEscalated(noise bool, since, now time.Time) (escalated bool, newSince time.Time) {
	if !noise {
		return false, time.Time{}
	}
	if since.IsZero() {
		return false, now
	}
	if now.Sub(since) >= NoiseEscalateAfter {
		return true, time.Time{}
	}
	return false, since
}

// SuspendGapDetected 巡检空窗判定（openspec recovery-ladder）：本拍实际间隔远超
// 2× 巡检周期 = 进程被系统冻结过（平台冻结不停系统单调钟，Go 定时器在解冻后补发，
// 迟到量即挂起时长）。挂起唤醒后 WG 会话大概率已死（>180s 必死）、本地 socket 可能
// 已失效——判定命中即触发恢复，不等本拍探测失败走连败。last 零值（首拍）无基线，
// 恒 false。
func SuspendGapDetected(last, now time.Time, interval time.Duration) bool {
	if last.IsZero() {
		return false
	}
	return now.Sub(last) > 2*interval
}
