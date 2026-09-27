//go:build cshared

package main

import "testing"

// 停留中继时的升级判定：连续 5 拍（5 分钟）才试一次；一旦不是中继立刻清零。
func TestRelayUpgradePolicy(t *testing.T) {
	streak := 0
	for i := 1; i <= relayUpgradeEvery; i++ {
		streak = relayUpgradeStreak("relay", streak)
		if got := relayUpgradeDue("relay", streak); got != (i == relayUpgradeEvery) {
			t.Fatalf("第 %d 拍：due=%v（want %v）", i, got, i == relayUpgradeEvery)
		}
	}
	// 直连时清零、不触发
	streak = relayUpgradeStreak("direct", streak)
	if streak != 0 || relayUpgradeDue("direct", streak) {
		t.Fatalf("直连应清零且不触发：streak=%d", streak)
	}
	// 没有路径（none）同样不触发
	if relayUpgradeDue("none", relayUpgradeStreak("none", 0)) {
		t.Fatal("none 不该触发升级")
	}
}
