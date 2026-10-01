//go:build linux

package ifaceutil

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// PinSocketToIface：Linux 用 SO_BINDTODEVICE 钉网卡。
func PinSocketToIface(conn *net.UDPConn, ifi *net.Interface) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := raw.Control(func(fd uintptr) {
		serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifi.Name)
	}); err != nil {
		return err
	}
	if serr != nil {
		return fmt.Errorf("SO_BINDTODEVICE: %w", serr)
	}
	return nil
}

// pinToFD 裸 fd 版钉卡（SO_BINDTODEVICE；egress 的拨号 socket 路径）。
// 修复（FIX-98 顺带）：FIX-72 迁移时本函数误抄了 darwin 的 IP_BOUND_IF 实现
// （Linux 无此常量，构建必断——CI 与 main 脱钩期间从未暴露）。
func pinToFD(fd int, ifi *net.Interface) error {
	if ifi == nil {
		return nil
	}
	if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifi.Name); err != nil {
		return fmt.Errorf("SO_BINDTODEVICE %q: %w", ifi.Name, err)
	}
	return nil
}
