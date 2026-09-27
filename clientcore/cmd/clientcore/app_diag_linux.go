//go:build cshared && linux

// app_diag_linux.go — 诊断用的 socket 家族常量（Linux 值）。
// 只服务 sockDesc 的 fd 分类；OHOS（linux）构建走这里。
package main

import "golang.org/x/sys/unix"

const (
	soDomain  = unix.SO_DOMAIN
	afNetlink = unix.AF_NETLINK
	afPacket  = unix.AF_PACKET
)
