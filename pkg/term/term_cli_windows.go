//go:build windows

// term_cli_windows.go — `homeway term` 子命令的 Windows 桩：终端服务本平台不提供
// （与 service_windows.go 同款约定），子命令直接报错。
package term

import "errors"

// CLI windows 桩。
func CLI(args []string) error {
	_ = args
	return errors.New("term: windows 不提供终端子命令")
}
