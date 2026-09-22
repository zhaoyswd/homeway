// homeway：Homeway 单二进制入口 —— 一个程序同时承载「出口（exit）」与「中继（relay）」两个角色。
//
//	homeway                    # 出口（默认角色），零参数即可
//	homeway exit [flags]       # 出口（显式）
//	homeway relay [flags]      # 中继
//	homeway --version
//
// 一台机器上可以同时跑多个进程（例如一个出口 + 一个中继）：各进程用 --state 区分身份、
// 用 --listen 区分端口（端口被占用会自动退让并打印实际端口）。同一角色也能起多份（不同 --state）。
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/zhaoyswd/homeway/internal/relay"
	"github.com/zhaoyswd/homeway/internal/server"
)

// version 由 CI 用 -ldflags "-X main.version=<tag>" 注入（必须是 var：-X 对 const 无效）。
var version = "0.0.0-dev"

func main() {
	if code := run(os.Args[1:]); code != 0 {
		os.Exit(code)
	}
}

// run 返回进程退出码，便于测试（不直接 os.Exit）。
func run(args []string) int {
	// 顶层元命令：homeway --version / homeway --help
	if meta(args) {
		return 0
	}

	role, rest := resolveRole(args)
	// 角色后的版本号：homeway relay --version。
	// 注意 **不** 在这里截 --help —— 角色的 --help 由各自的 flag 集打印（参数列表不同）。
	if onlyVersion(rest) {
		return 0
	}
	relay.Version = version // 探测应答的构建标记（add-host-connectivity）

	var err error
	switch role {
	case "exit":
		err = server.CLI(rest)
	case "relay":
		err = relay.CLI(rest)
	default:
		fmt.Fprintf(os.Stderr, "homeway: 不认识的子命令 %q（可用：exit、relay）\n", role)
		usage(os.Stderr)
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "homeway:", err)
		return 1
	}
	return 0
}

// meta：顶层 --version / --help。命中即处理并返回 true。
func meta(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "--version", "-v", "version":
		fmt.Println("homeway", version)
		return true
	case "--help", "-h", "help":
		usage(os.Stdout)
		return true
	}
	return false
}

// onlyVersion：角色后的 --version（角色的 --help 交给各自 flag 集处理）。
func onlyVersion(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "--version", "-v", "version":
		fmt.Println("homeway", version)
		return true
	}
	return false
}

// resolveRole：从首个位置参数解析角色，返回角色与剩余参数。
func resolveRole(args []string) (role string, rest []string) {
	if len(args) == 0 {
		return "exit", nil // 裸 `homeway` = 出口（最常用角色）
	}
	switch args[0] {
	case "exit":
		return "exit", args[1:]
	case "relay":
		return "relay", args[1:]
	}
	// `homeway --relay 'rl1…'` 这类省略子命令的写法：首参是 flag 时按默认角色（出口）走。
	if strings.HasPrefix(args[0], "-") {
		return "exit", args
	}
	return args[0], args[1:] // 未知角色 —— 交给上层报错
}

func usage(w *os.File) {
	fmt.Fprint(w, `homeway —— Homeway 出口与中继（单二进制，按角色运行）

用法：
  homeway [flags]              启动出口（默认角色，零参数即可）
  homeway exit [flags]         同上（显式角色）
  homeway relay [flags]        启动中继
  homeway --version            打印版本

一台机器上可以同时运行多个进程（如一个出口 + 一个中继）：用 --state 区分身份、
用 --listen 区分端口；端口被占用会自动退让并打印实际端口。

角色参数：
  homeway exit --help          出口参数（WG 监听、UPnP/STUN、中继注册腿、设备表…）
  homeway relay --help         中继参数（监听地址、对外公布地址、state 目录）
`)
}
