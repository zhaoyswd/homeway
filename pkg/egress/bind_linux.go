//go:build linux

package egress

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// bindSocketToIface：Linux 用 SO_BINDTODEVICE 钉网卡（容器里跑要 --network host + 足够权限）。
func bindSocketToIface(fd int, ifi *net.Interface) error {
	if ifi == nil {
		return nil
	}
	if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifi.Name); err != nil {
		return fmt.Errorf("SO_BINDTODEVICE %q: %w", ifi.Name, err)
	}
	return nil
}
