//go:build darwin

package server

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// bindSocketToIface：macOS 用 IP_BOUND_IF 把 socket 钉在指定网卡上。
// 这正是「默认路由被 TUN 型代理抢走」场景下组播（SSDP）唯一可靠的出路：
// 只 bind 源地址 + IP_MULTICAST_IF 仍会按默认路由选路，实测 sendto: no route to host。
func bindSocketToIface(conn *net.UDPConn, ifi *net.Interface) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := raw.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, ifi.Index)
	}); err != nil {
		return err
	}
	if serr != nil {
		return fmt.Errorf("IP_BOUND_IF: %w", serr)
	}
	return nil
}
