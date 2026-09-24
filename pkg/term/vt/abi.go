//go:build (darwin || linux) && (amd64 || arm64) && cgo

// abi.go — sized-struct ABI 核对（**回归门**，不是调试残留）。
//
// 为什么需要它：libghostty-vt 的 sized struct 靠调用方填 `size` 字段，cgo 侧的 Go 结构与 C 侧的
// sizeof 必须**逐字节一致**——不一致时库会按自己的 sizeof 写内存，踩坏相邻的 Go 变量，症状是
// 莫名其妙的 GC 崩溃（本层实测过：枚举输出用窄类型接就是同一类事故）。换 vendor 基线（改补丁、
// 升上游）后 sizeof 可能变，所以用单测把它钉住：见 vt_test.go 的 TestStructABI。
package vt

/*
#include <ghostty/vt.h>
#include <stddef.h>

// C 侧真实 sizeof（Go 侧用 unsafe.Sizeof 对照）。
static size_t tier_c_sizeof_style(void) { return sizeof(GhosttyStyle); }
static size_t tier_c_sizeof_cursor(void) { return sizeof(GhosttyRenderStateCursor); }
static size_t tier_c_sizeof_formatter(void) { return sizeof(GhosttyFormatterTerminalOptions); }
static size_t tier_c_sizeof_mouse_size(void) { return sizeof(GhosttyMouseEncoderSize); }
static size_t tier_c_sizeof_style_color(void) { return sizeof(GhosttyStyleColor); }
static size_t tier_c_sizeof_mode_cfg(void) { return sizeof(GhosttyTerminalModeConfig); }
static size_t tier_c_sizeof_buffer(void) { return sizeof(GhosttyBuffer); }
static size_t tier_c_sizeof_cell(void) { return sizeof(GhosttyCell); }
static size_t tier_c_sizeof_string(void) { return sizeof(GhosttyString); }

// 枚举输出类型的宽度（必须与 Go 侧用 C 枚举类型接的假设一致）。
static size_t tier_c_sizeof_enum(void) { return sizeof(GhosttyCellWide); }
*/
import "C"

import "unsafe"

// structSizes 返回每个 C 类型在 Go 侧与 C 侧的尺寸（测试用）。
func structSizes() map[string][2]uintptr {
	return map[string][2]uintptr{
		"GhosttyStyle":                    {unsafe.Sizeof(C.GhosttyStyle{}), uintptr(C.tier_c_sizeof_style())},
		"GhosttyRenderStateCursor":        {unsafe.Sizeof(C.GhosttyRenderStateCursor{}), uintptr(C.tier_c_sizeof_cursor())},
		"GhosttyFormatterTerminalOptions": {unsafe.Sizeof(C.GhosttyFormatterTerminalOptions{}), uintptr(C.tier_c_sizeof_formatter())},
		"GhosttyMouseEncoderSize":         {unsafe.Sizeof(C.GhosttyMouseEncoderSize{}), uintptr(C.tier_c_sizeof_mouse_size())},
		"GhosttyStyleColor":               {unsafe.Sizeof(C.GhosttyStyleColor{}), uintptr(C.tier_c_sizeof_style_color())},
		"GhosttyTerminalModeConfig":       {unsafe.Sizeof(C.GhosttyTerminalModeConfig{}), uintptr(C.tier_c_sizeof_mode_cfg())},
		"GhosttyBuffer":                   {unsafe.Sizeof(C.GhosttyBuffer{}), uintptr(C.tier_c_sizeof_buffer())},
		"GhosttyCell":                     {unsafe.Sizeof(C.GhosttyCell(0)), uintptr(C.tier_c_sizeof_cell())},
		"GhosttyString":                   {unsafe.Sizeof(C.GhosttyString{}), uintptr(C.tier_c_sizeof_string())},
		"GhosttyCellWide(enum)":           {unsafe.Sizeof(C.GhosttyCellWide(0)), uintptr(C.tier_c_sizeof_enum())},
	}
}
