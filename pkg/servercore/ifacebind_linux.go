//go:build linux

package servercore

import (
	"fmt"
	"net"
	"net/netip"

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
