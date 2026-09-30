//go:build unix

package nodestate

// probe_unix.go — flock 试探（import「目标进程在停」/reset cache「在跑拒绝」与迁移
// 瞬态清理共用）。口径与 internal/daemon/lock.go 一致：flock(LOCK_EX|LOCK_NB) 拿得到
// = 无活进程；拿不到 = 有人持有。「pid 文件 + kill -0」已被 3a 否决（竞态窗口 +
// 僵尸 pid 误判），不引入。

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// lockHeld 试探 <dir>/lock 是否被活进程持有。文件不存在 = 无人持有（顺手创建，
// 与 daemon.AcquireInstanceLock 同款 O_CREATE）。
func lockHeld(dir string) (bool, error) {
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return false, err
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return true, nil // EWOULDBLOCK：有人持有
	}
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	return false, nil
}
