//go:build cshared && !linux

// app_diag_other.go — 诊断用的 socket 家族常量（非 Linux 占位）。
// sockDesc 只在 Linux 上做 fd 家族的精确分类；其它平台（宿主单测用）取 0，
// 分类退化为 "afN/af0"，不影响任何真实功能。
package main

const (
	soDomain  = 0
	afNetlink = -1
	afPacket  = -2
)
