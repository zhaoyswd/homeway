//go:build unix

package nodestate

import "golang.org/x/sys/unix"

// lockFile unix 实现：排他 | 非阻塞（拿不到立刻失败——由调用方读持有者报错）。
func lockFile(fd int) error {
	return unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
}

func unlockFile(fd int) error {
	return unix.Flock(fd, unix.LOCK_UN)
}
