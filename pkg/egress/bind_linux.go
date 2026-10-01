//go:build linux

package egress

import (
	"net"

	"github.com/zhaoyswd/homeway/pkg/ifaceutil"
)

// bindSocketToIface 单实现在 pkg/ifaceutil（FIX-72）。
func bindSocketToIface(fd int, ifi *net.Interface) error {
	return ifaceutil.PinSocketToFD(fd, ifi)
}
