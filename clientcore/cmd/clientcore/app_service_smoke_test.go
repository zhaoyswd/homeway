//go:build cshared

// app_service_smoke_test.go — ClientCoreService 包装面的冒烟（host-registry-daemon
// tasks 1.3：cshared 新增——返回码 −3/−4、状态 JSON 形状）。
//
// 状态面形状：idle 逐字节 + failed 键集合与 reason 流通走真生产构造；「ready +
// 有桥」的键集合经纯函数 serviceSnapshotJSON 直接喂构造的 Snapshot 守（exec-r1
// M6 补——此前该组装路径无用例）；Snapshot 侧字段由 hostsession 快照用例守。
package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/hostsession"
)

func TestServiceWrapperSmokeCodesAndShape(t *testing.T) {
	// ① 无实例基线：idle 形状**逐字节**（迁移前捕获同串：{"state":"idle"}）。
	if got := serviceStatusJSON(); got != `{"state":"idle"}` {
		t.Fatalf("idle 状态 JSON = %q（期望逐字节 {\"state\":\"idle\"}）", got)
	}

	// ② 返回码：非法 JSON → -3；token 为空 → -4（导出契约逐字不变）。
	if rc := serviceStartFromJSON(`{not json`); rc != -3 {
		t.Fatalf("非法 JSON 应 -3，实得 %d", rc)
	}
	if rc := serviceStartFromJSON(`{"mtu":1280}`); rc != -4 {
		t.Fatalf("空 token 应 -4，实得 %d", rc)
	}

	// ③ 组装路径（真生产构造、注定失败的 token）：Start 返回 0，随后 failed 终态；
	// 状态 JSON 键集合 = {elapsedMs, reason, state}（无 bridge*/link/identity/stats——
	// 无桥会话），reason 携带归因（token 解析失败）。
	if rc := serviceStartFromJSON(`{"token":"hmw1-smoke-bad"}`); rc != 0 {
		t.Fatalf("start rc=%d（应受理 0）", rc)
	}
	defer func() { _ = serviceStopInternal() }()
	deadline := time.Now().Add(5 * time.Second)
	var keys []string
	var reason, state string
	for time.Now().Before(deadline) {
		var m map[string]any
		if err := json.Unmarshal([]byte(serviceStatusJSON()), &m); err != nil {
			t.Fatalf("状态 JSON 解析失败：%v（%s）", err, serviceStatusJSON())
		}
		keys = keys[:0]
		for k := range m {
			keys = append(keys, k)
		}
		if s, ok := m["state"].(string); ok && s == "failed" {
			if r, ok := m["reason"].(string); ok {
				reason = r
			}
			state = s
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if state != "failed" {
		t.Fatalf("5s 内未到 failed（当前 %s）", serviceStatusJSON())
	}
	sortStrings(keys)
	want := []string{"elapsedMs", "reason", "state"}
	if len(keys) != len(want) {
		t.Fatalf("failed 态键集合 = %v（期望 %v）", keys, want)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("failed 态键集合 = %v（期望 %v）", keys, want)
		}
	}
	if reason == "" {
		t.Fatal("failed 态缺 reason")
	}

	// ④ Stop 归位。
	if rc := serviceStopInternal(); rc != 0 {
		t.Fatalf("stop rc=%d", rc)
	}
}

// TestServiceSnapshotJSONReadyWithBridgeKeys 「ready + 有桥」的键集合守卫
// （exec-r1 M6：此前 cshared 面只剩 idle 短路与 failed 无桥两条，「Snapshot → JSON
// 的 bridge 键组装」无任何用例——design D1/A6 把「状态 JSON 形状不变」记为快照
// 测试守，守卫比声称的弱）。经纯函数 serviceSnapshotJSON 直接喂构造的 Snapshot，
// 不依赖真桥：键集合恰为 {bridgeAuth, bridgeFilesSock, bridgeSpeedSock,
// bridgeTermSock, elapsedMs, reason, state}，bridgeAuth 原样流通、三座 sock 路径
// 三键齐出（与旧 serviceStatusJSON 的 ready 形状逐键对齐）。
func TestServiceSnapshotJSONReadyWithBridgeKeys(t *testing.T) {
	snap := hostsession.Snapshot{
		State:           "ready",
		Since:           time.Now(),
		BridgeAuth:      strings.Repeat("ab", 48), // 96 hex（真桥同长度）
		BridgeFilesSock: "/br/files.sock",
		BridgeTermSock:  "/br/term.sock",
		BridgeSpeedSock: "/br/speed.sock",
		// Link/Identity/Stats 缺省 = ready 无会话期（假会话形态）：三个嵌套键不出。
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(serviceSnapshotJSON(snap)), &m); err != nil {
		t.Fatalf("ready+桥 状态 JSON 解析失败：%v", err)
	}
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sortStrings(keys)
	want := []string{"bridgeAuth", "bridgeFilesSock", "bridgeSpeedSock", "bridgeTermSock", "elapsedMs", "reason", "state"}
	if len(keys) != len(want) {
		t.Fatalf("ready+桥 键集合 = %v（期望 %v）", keys, want)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("ready+桥 键集合 = %v（期望 %v）", keys, want)
		}
	}
	if got, _ := m["bridgeAuth"].(string); got != snap.BridgeAuth {
		t.Fatalf("bridgeAuth 应原样流通：%q", got)
	}
	for k, wantV := range map[string]string{
		"bridgeFilesSock": snap.BridgeFilesSock,
		"bridgeTermSock":  snap.BridgeTermSock,
		"bridgeSpeedSock": snap.BridgeSpeedSock,
	} {
		if got, _ := m[k].(string); got != wantV {
			t.Fatalf("%s = %q（期望 %q）", k, got, wantV)
		}
	}
	if ems, ok := m["elapsedMs"].(float64); !ok || ems < 0 {
		t.Fatalf("elapsedMs 应为非负数值：%v", m["elapsedMs"])
	}
	// 对照：failed/无桥（快照指针缺省）不吐 bridge 键——缺省条件仍与旧实现一致。
	var noBridge map[string]any
	if err := json.Unmarshal([]byte(serviceSnapshotJSON(hostsession.Snapshot{State: "failed", Reason: "x", Since: time.Now()})), &noBridge); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"bridgeAuth", "bridgeFilesSock", "bridgeTermSock", "bridgeSpeedSock"} {
		if _, has := noBridge[k]; has {
			t.Fatalf("无桥快照不应含 %s", k)
		}
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
