//go:build linux

// term_cli_tty_linux.go — CLI raw 终端的 termios ioctl（linux：TCGETS/TCSETS）。
package term

import "golang.org/x/sys/unix"

func termiosGet(fd int) (*termiosT, error) {
	return unix.IoctlGetTermios(fd, unix.TCGETS)
}

func termiosSet(fd int, t *termiosT) error {
	return unix.IoctlSetTermios(fd, unix.TCSETS, t)
}
