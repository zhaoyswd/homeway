//go:build cshared

// app_service_smoke_test.go — ClientCoreService 包装面的冒烟（host-registry-daemon
// tasks 1.3：cshared 新增——返回码 −3/−4、状态 JSON 形状）。
//
// 状态面形状的完整对拍（键集合 = bridgeAuth/bridgeFilesSock/bridgeSpeedSock/
// bridgeTermSock/elapsedMs/reason/state）在本包无法注入假会话（builder 接缝在
// hostsession 包内），由 hostsession 的快照用例守 Snapshot 侧 + 本用例守
// 「快照 → JSON」的组装路径（idle 逐字节、failed 键集合与 reason 流通）。
package main

import (
	"encoding/json"
	"testing"
	"time"
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

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
