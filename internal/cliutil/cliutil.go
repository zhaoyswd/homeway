// Package cliutil：CLI 侧跨命令面的小工具（单实现收口，FIX-57）。
//
// 由来：state 目录默认值曾在 daemon / pkg/term / pkg/files 三处各写一遍（两处返回
// 空串、一处返回相对路径兜底），值相同但漂移面在——改一处忘一处就出现「CLI 找错
// state 目录」的静默错。这里收一份，各命令面薄壳引用。
package cliutil

import (
	"os"
	"path/filepath"
)

// DefaultStateDir 默认 state 目录（~/.config/homeway）。无 HOME（极少数测试环境）
// 返回空串——调用方自行决定兜底文案/相对路径。
func DefaultStateDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".config", "homeway")
}
