//go:build !darwin && !linux

package servercore

import (
	"net"
	"net/netip"
)

func pinSocketToIface(*net.UDPConn, *net.Interface) error      { return nil }
func ifaceForAddr(netip.Addr) *net.Interface                   { return nil }
