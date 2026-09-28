//go:build !windows && !darwin && !linux && !freebsd && !netbsd && !openbsd && !dragonfly

// term_cli_tty_other.go — 发行矩阵外 unix（solaris 等）的桩：raw 终端未实现、返回错误，
// 保证包在这些平台可编译（exec-r3 低6：原「其余 unix」用 TIOCGETA 的写法在 solaris 上
// 引用不存在的常量、属新增构建破损；release 矩阵只有 linux/darwin/windows）。
package term

import "errors"

func termiosGet(fd int) (*termiosT, error) {
	_ = fd
	return nil, errors.New("term: 本平台未实现 raw 终端（发行矩阵外）")
}

func termiosSet(fd int, t *termiosT) error {
	_ = fd
	_ = t
	return errors.New("term: 本平台未实现 raw 终端（发行矩阵外）")
}
