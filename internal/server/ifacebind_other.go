//go:build !darwin && !linux

package server

import "net"

// 其它平台：不做 socket 级绑卡（Windows 的 IP_UNICAST_IF 语义不同，出口也不跑在那里）。
func bindSocketToIface(*net.UDPConn, *net.Interface) error { return nil }
