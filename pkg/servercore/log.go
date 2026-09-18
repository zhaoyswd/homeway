// Package servercore：后端 WG 端点的可复用装配件（ServerBind + 动态 peer 表）。
//
// 从 internal/server 提升为公开包（2026-09-19）：下游（tier 手机核的集成测试/自测工具）
// 需要能起一个**与生产同一份代码**的后端端点——此前 tier 测试里有一份手抄的 srvHarness，
// 已经出现过「harness 与生产实现漂移」的风险（见 tier HANDOFF §7）。
package servercore

import "fmt"

// logf 包内兜底日志（homewayd 装配时由 ServerBind.Logf 覆盖成正式日志）。
func logf(format string, args ...any) {
	fmt.Printf("[servercore] "+format+"\n", args...)
}
