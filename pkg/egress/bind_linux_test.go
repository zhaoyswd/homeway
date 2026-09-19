//go:build linux

package egress

import (
	"net"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

// checkSocketBound：Linux 上读回 SO_BINDTODEVICE，必须等于目标网卡名（与目标家族无关）。
func checkSocketBound(t *testing.T, conn *net.UDPConn, ifi *net.Interface, _ netip.AddrPort) {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var name string
	if err := raw.Control(func(fd uintptr) {
		name, err = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	}); err != nil {
		t.Fatalf("读 SO_BINDTODEVICE: %v", err)
	}
	if name != ifi.Name {
		t.Fatalf("SO_BINDTODEVICE = %q，want %q（socket 没绑上网卡）", name, ifi.Name)
	}
}
