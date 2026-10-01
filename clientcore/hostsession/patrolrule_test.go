//go:build !cshared

package hostsession

import (
	"testing"
	"time"
)

// 巡检节拍三件套（FIX-21 共享纯决策）的向量：补注册节流 / 挂起空窗 / 噪声长停逃逸。
// 手机门（cmd/clientcore）与桌面门（Session.patrol）同源消费——测试钉在共享件上。

// 注册刷新节流：首拍必发（零值），之后每 RegRefreshEvery 一次；未到点不发。
func TestShouldRefreshReg(t *testing.T) {
	now := time.Now()
	if !ShouldRefreshReg(time.Time{}, now) {
		t.Fatal("零值（本世代还没发过）应触发补发")
	}
	if ShouldRefreshReg(now.Add(-time.Minute), now) {
		t.Fatal("未到周期不应补发")
	}
	if !ShouldRefreshReg(now.Add(-RegRefreshEvery), now) {
		t.Fatal("到周期应补发")
	}
	if !ShouldRefreshReg(now.Add(-2*RegRefreshEvery), now) {
		t.Fatal("超过周期应补发")
	}
}

// 挂起空窗判定（openspec recovery-ladder）：首拍无基线恒 false；正常节拍 false；
// 恰好 2× 周期不算（严格大于，给调度抖动留整周期余量）；超过 2× 周期 = 冻结过。
func TestSuspendGapDetected(t *testing.T) {
	now := time.Now()
	if SuspendGapDetected(time.Time{}, now, servicePatrolInterval) {
		t.Fatal("首拍（无基线）不应判定挂起")
	}
	if SuspendGapDetected(now.Add(-servicePatrolInterval), now, servicePatrolInterval) {
		t.Fatal("正常节拍不应判定挂起")
	}
	if SuspendGapDetected(now.Add(-2*servicePatrolInterval), now, servicePatrolInterval) {
		t.Fatal("恰好 2× 周期不应判定（严格大于）")
	}
	if !SuspendGapDetected(now.Add(-2*servicePatrolInterval-time.Second), now, servicePatrolInterval) {
		t.Fatal("超过 2× 周期应判定挂起")
	}
	if !SuspendGapDetected(now.Add(-10*time.Minute), now, servicePatrolInterval) {
		t.Fatal("长冻结应判定挂起")
	}
}

// 噪声长停逃逸状态机：噪声首拍记起点不逃逸；持续超阈值判逃逸并重置计时；
// 噪声消失即清零；非噪声恒清零。
func TestNoiseEscalated(t *testing.T) {
	now := time.Now()
	// 首拍（since 零值）：记起点、不逃逸。
	esc, since := NoiseEscalated(true, time.Time{}, now)
	if esc || !since.Equal(now) {
		t.Fatalf("噪声首拍应记起点不逃逸：esc=%v since=%v", esc, since)
	}
	// 窗内持续：不逃逸、起点保持。
	esc2, since2 := NoiseEscalated(true, since, now.Add(time.Minute))
	if esc2 || !since2.Equal(since) {
		t.Fatalf("窗内持续不应逃逸：esc=%v since=%v", esc2, since2)
	}
	// 超过 3 分钟：逃逸、计时重置。
	esc3, since3 := NoiseEscalated(true, since, now.Add(NoiseEscalateAfter+time.Second))
	if !esc3 || !since3.IsZero() {
		t.Fatalf("超阈值应逃逸并重置：esc=%v since=%v", esc3, since3)
	}
	// 噪声消失：清零。
	esc4, since4 := NoiseEscalated(false, since, now.Add(2*time.Minute))
	if esc4 || !since4.IsZero() {
		t.Fatalf("噪声消失应清零：esc=%v since=%v", esc4, since4)
	}
	// 恰好阈值（>= 边界）：逃逸。
	esc5, _ := NoiseEscalated(true, since, now.Add(NoiseEscalateAfter))
	if !esc5 {
		t.Fatal("恰好阈值应逃逸（>= 判定）")
	}
}
