//go:build darwin

package egress

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// bindSocketToIface：macOS 用 IP_BOUND_IF（v4）/ IPV6_BOUND_IF（v6）把 socket 钉在网卡上。
// 双栈 socket 两族都要设；单栈 socket 上对另一族设置会报 EINVAL/ENOPROTOOPT —— 只要一族成功即可
// （与 pkg/servercore 的 pinSocketToIface 同一套判据，两处别漂）。
func bindSocketToIface(fd int, ifi *net.Interface) error {
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
