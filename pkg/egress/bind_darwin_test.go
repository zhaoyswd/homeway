//go:build darwin

package egress

import (
	"net"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

// checkSocketBound：darwin 上按家族读回 IP_BOUND_IF（v4 socket）/ IPV6_BOUND_IF（v6 socket），
// 必须等于目标网卡索引。
func checkSocketBound(t *testing.T, conn *net.UDPConn, ifi *net.Interface, target netip.AddrPort) {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	proto, opt, name := unix.IPPROTO_IP, unix.IP_BOUND_IF, "IP_BOUND_IF"
	if target.Addr().Unmap().Is6() {
		proto, opt, name = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, "IPV6_BOUND_IF"
	}
	var idx int
	if err := raw.Control(func(fd uintptr) {
		idx, err = unix.GetsockoptInt(int(fd), proto, opt)
	}); err != nil {
		t.Fatalf("读 %s: %v", name, err)
	}
	if idx != ifi.Index {
		t.Fatalf("%s = %d，want %d（socket 没绑上网卡）", name, idx, ifi.Index)
	}
}
