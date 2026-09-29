//go:build cshared

// recover_test.go — 隧道域恢复入口的用例（host-registry-daemon D8 账本·留守 14 之一）。
// 共享阶梯的 8 例已随迁 clientcore/hostsession/recover_test.go（纯迁）；本文件只剩
// 隧道域专属的 TestRecoverTunnelReady（判定依赖留守的 tunStage 族）。
package main

import (
	"testing"
)

// recoverTunnelReady：-2 的判定条件唯一真源——四条守卫缺一不可，
// 特别是 prepare 期（stageReady，锁已持有但无数据面）必须回答「没有隧道」。
func TestRecoverTunnelReady(t *testing.T) {
	if !recoverTunnelReady(true, true, stageAttached, true) {
		t.Fatal("四条齐备应可恢复")
	}
	for _, c := range []struct {
		name            string
		hasRun, running bool
		stage           tunStage
		hasClient       bool
	}{
		{"无世代", false, true, stageAttached, true},
		{"核未跑", true, false, stageAttached, true},
		{"prepare 期", true, true, stageReady, true},
		{"failed 期", true, true, stageFailed, true},
		{"无会话", true, true, stageAttached, false},
	} {
		if recoverTunnelReady(c.hasRun, c.running, c.stage, c.hasClient) {
			t.Fatalf("%s：应判没有可恢复的隧道", c.name)
		}
	}
}
