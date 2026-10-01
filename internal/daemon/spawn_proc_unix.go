//go:build unix

package daemon

import "syscall"

// spawnSysProcAttr 拉起子进程的进程属性（unix = setsid 脱离会话：CLI 退出不带走
// 统一进程）。windows 桩见 spawn_proc_other.go（该平台不拉起——dialControlSpawn
// 在 GOOS 检查处已报可行动错误，本函数理论不可达）。
func spawnSysProcAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setsid: true} }
