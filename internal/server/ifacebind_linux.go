//go:build linux

package server

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// bindSocketToIface：Linux 用 SO_BINDTODEVICE 把 socket 钉在网卡上
// （容器/主机都可能被 VPN 类接口抢默认路由，SSDP 组播尤其明显）。
func bindSocketToIface(conn *net.UDPConn, ifi *net.Interface) error {
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
