//go:build cshared

// app_marshal_fallback_test.go — 三处序列化兜底的**逐字节回归**（contract-ledger 2.1，
// r2 N-1）：marshalFiles/termMarshalJSON/speedMarshalJSON 的失败兜底原为原始 JSON
// 字面量，2.1 收进构造器调用（filesErrf/termErrf/speedFail 首参进词表提取）——本测试
// 把「收构造器输出 JSON 逐字同形」钉成机器判据（值不可序列化 ⇒ 触发兜底路径）。
package main

import (
	"math"
	"testing"
)

func TestMarshalFallbackByteIdentity(t *testing.T) {
	// +Inf 是 encoding/json 的不可序列化值：注入它强制走兜底分支。
	bad := map[string]any{"v": math.Inf(1)}

	if got := marshalFiles(bad, nil); got != `{"error":{"code":"marshal","msg":"结果序列化失败"}}` {
		t.Errorf("marshalFiles 兜底字节漂移：%s", got)
	}
	if got := termMarshalJSON(bad, nil); got != `{"error":{"code":"marshal","msg":"结果序列化失败"}}` {
		t.Errorf("termMarshal 兜底字节漂移：%s", got)
	}
	if got := speedMarshalJSON(bad); got != `{"ok":false,"reason":"invalid_arg","msg":"结果序列化失败"}` {
		t.Errorf("speedMarshal 兜底字节漂移：%s", got)
	}
}
