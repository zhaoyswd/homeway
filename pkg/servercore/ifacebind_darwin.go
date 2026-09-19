//go:build darwin

package servercore

import (
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/sys/unix"
)

// pinSocketToIface：macOS 用 IP_BOUND_IF 把 socket 钉在网卡上。
// 出口绑物理网卡（--bind-interface）时必须连这一步一起做：只 bind 源地址时，默认路由被
// TUN 型代理（Surge 等）抢走的机器上，报文仍可能走代理出去 —— 那 STUN 观测到的就是代理的
// NAT 映射，和路由器上的真实映射（UPnP 建的那条）对不上，公网端点会永久"暂不公布"。
func pinSocketToIface(conn *net.UDPConn, ifi *net.Interface) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var serr4, serr6 error
	if err := raw.Control(func(fd uintptr) {
		// 双栈 socket 上两族都要钉：IP_BOUND_IF 管 v4（含 v4-mapped），IPV6_BOUND_IF 管真 v6。
		// 单栈 socket 上对另一族设置会报 EINVAL/ENOPROTOOPT —— 忽略它，只要有一族成功即可。
		serr4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, ifi.Index)
		serr6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, ifi.Index)
	}); err != nil {
		return err
	}
	if serr4 != nil && serr6 != nil {
		return fmt.Errorf("IP_BOUND_IF/IPV6_BOUND_IF: %v / %v", serr4, serr6)
	}
	return nil
}

// ifaceForAddr：找出拥有该地址的网卡。
func ifaceForAddr(ip netip.Addr) *net.Interface {
	ifis, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for i := range ifis {
		addrs, err := ifis[i].Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if got, ok := netip.AddrFromSlice(ipn.IP); ok && got.Unmap() == ip.Unmap() {
				return &ifis[i]
			}
		}
	}
	return nil
}
