//go:build !unix

package daemon

import "syscall"

// spawnSysProcAttr 非 unix 桩（windows 桩门可编；拉起在该平台 = 可行动错误，
// 见 spawn.go 的 GOOS 检查——本函数理论不可达）。
func spawnSysProcAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{} }
