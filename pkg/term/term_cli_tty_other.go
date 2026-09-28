//go:build !windows && !darwin && !linux

// term_cli_tty_other.go — CLI raw 终端的 termios ioctl 兜底（BSD 系：TIOCGETA/TIOCSETA；
// 发行矩阵只有 linux/darwin/windows，这里只是让其余 unix 可编译）。
package term

import "golang.org/x/sys/unix"

func termiosGet(fd int) (*termiosT, error) {
	return unix.IoctlGetTermios(fd, unix.TIOCGETA)
}

func termiosSet(fd int, t *termiosT) error {
	return unix.IoctlSetTermios(fd, unix.TIOCSETA, t)
}
