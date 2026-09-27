//go:build cshared

package main

import (
	"testing"
	"time"
)

// 注册刷新节流：首拍必发（零值），之后每 regRefreshEvery 一次；未到点不发。
func TestShouldRefreshReg(t *testing.T) {
	now := time.Now()
	if !shouldRefreshReg(time.Time{}, now) {
		t.Fatal("零值（本世代还没发过）应触发补发")
	}
	if shouldRefreshReg(now.Add(-time.Minute), now) {
		t.Fatal("未到周期不应补发")
	}
	if !shouldRefreshReg(now.Add(-regRefreshEvery), now) {
		t.Fatal("到周期应补发")
	}
	if !shouldRefreshReg(now.Add(-2*regRefreshEvery), now) {
		t.Fatal("超过周期应补发")
	}
}

// 挂起空窗判定（openspec recovery-ladder）：首拍无基线恒 false；正常节拍 false；
// 恰好 2× 周期不算（严格大于，给调度抖动留整周期余量）；超过 2× 周期 = 冻结过。
func TestSuspendGapDetected(t *testing.T) {
	now := time.Now()
	if suspendGapDetected(time.Time{}, now, patrolInterval) {
		t.Fatal("首拍（无基线）不应判定挂起")
	}
	if suspendGapDetected(now.Add(-patrolInterval), now, patrolInterval) {
		t.Fatal("正常节拍不应判定挂起")
	}
	if suspendGapDetected(now.Add(-2*patrolInterval), now, patrolInterval) {
		t.Fatal("恰好 2× 周期不应判定（严格大于）")
	}
	if !suspendGapDetected(now.Add(-2*patrolInterval-time.Second), now, patrolInterval) {
		t.Fatal("超过 2× 周期应判定挂起")
	}
	if !suspendGapDetected(now.Add(-10*time.Minute), now, patrolInterval) {
		t.Fatal("长冻结应判定挂起")
	}
}
