//go:build freebsd || netbsd || openbsd || dragonfly

// term_cli_tty_bsd.go — CLI raw 终端的 termios ioctl（BSD 系四平台：TIOCGETA/TIOCSETA）。
package term

import "golang.org/x/sys/unix"

func termiosGet(fd int) (*termiosT, error) {
	return unix.IoctlGetTermios(fd, unix.TIOCGETA)
}

func termiosSet(fd int, t *termiosT) error {
	return unix.IoctlSetTermios(fd, unix.TIOCSETA, t)
}
