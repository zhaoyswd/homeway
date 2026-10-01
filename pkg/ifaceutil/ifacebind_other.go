//go:build !darwin && !linux

package ifaceutil

import "net"

// PinSocketToIface 非 darwin/linux 平台无钉卡手段（no-op，与旧 servercore 桩一致）。
func PinSocketToIface(*net.UDPConn, *net.Interface) error { return nil }

func pinToFD(int, *net.Interface) error { return nil }
