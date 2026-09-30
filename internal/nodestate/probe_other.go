//go:build !unix

package nodestate

// probe_other.go — 非 unix 降级：恒「无活进程」（与 internal/daemon/lock_other.go
// 同款桩——windows 只有构建门禁、无部署面）。import/reset cache 在这些平台照常执行。

// lockHeld 非 unix 桩：恒 false（单实例互斥在非 unix 不成立，参照 daemon 口径）。
func lockHeld(dir string) (bool, error) { return false, nil }
