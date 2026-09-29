//go:build !unix

package daemon

// lockFile 非 unix 降级：恒成功（无单实例互斥；参照 pkg/egress/bind_other.go 先例，
// host-registry-daemon 2.1/r1 A3）。生产面（macOS/Linux/OHOS）全走 unix 侧 flock；
// 本桩只为 windows 桩门可编。单实例互斥在这类平台不再成立——守护进程的正式部署
// 面不含它们，如未来需要按平台补原生锁（如 Windows LockFileEx）再替换。
func lockFile(fd int) error { return nil }

func unlockFile(fd int) error { return nil }
