package servercore

// ifaceutil_shim.go — 钉卡/网卡判定收单实现（FIX-72：原 ifacebind_*.go 与
// pkg/egress/bind_*.go 是两份逐字相同的实现）。此处只留导出面薄壳。

import (
	"net"

	"github.com/zhaoyswd/homeway/pkg/ifaceutil"
)

// PinSocketToIface 见 pkg/ifaceutil（darwin=IP_BOUND_IF / linux=SO_BINDTODEVICE）。
func PinSocketToIface(conn *net.UDPConn, ifi *net.Interface) error {
	return ifaceutil.PinSocketToIface(conn, ifi)
}
