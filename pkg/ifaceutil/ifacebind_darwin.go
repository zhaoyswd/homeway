//go:build darwin

package ifaceutil

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// PinSocketToIface：macOS 用 IP_BOUND_IF 把 socket 钉在网卡上。
// 出口绑物理网卡（--bind-interface）时必须连这一步一起做：只 bind 源地址时，默认路由被
// TUN 型代理（Surge 等）抢走的机器上，报文仍可能走代理出去 —— 那 STUN 观测到的就是代理的
// NAT 映射，和路由器上的真实映射（UPnP 建的那条）对不上，公网端点会永久"暂不公布"。
func PinSocketToIface(conn *net.UDPConn, ifi *net.Interface) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := raw.Control(func(fd uintptr) { serr = pinToFD(int(fd), ifi) }); err != nil {
		return err
	}
	return serr
}

// pinToFD 裸 fd 版钉卡（两族都设、单栈容错）。
func pinToFD(fd int, ifi *net.Interface) error {
	if ifi == nil {
		return nil
	}
	serr4 := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_BOUND_IF, ifi.Index)
	serr6 := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, ifi.Index)
	if serr4 != nil && serr6 != nil {
		return fmt.Errorf("IP_BOUND_IF/IPV6_BOUND_IF: %v / %v", serr4, serr6)
	}
	return nil
}
