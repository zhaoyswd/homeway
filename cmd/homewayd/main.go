// homewayd：Homeway 后端（出口）——WG 端点 + token 签发 + 流服务（files / 终端 / 端口转发目标）。
//
//	homewayd                     # 零参数即可：UPnP/STUN 默认开，WG socket 自动挑卡，端口冲突自动退让，
//	                             # 启动即打印客户端 token（粘进 App 的「添加主机」）
//	homewayd --relay 'rl1…'      # 需要中继时只多这一个参数（中继 token 由 homeway-relay 启动时打印）
//	homewayd --state <dir>       # 换身份/换端口才需要（默认 ~/.config/homeway）
//
// 设计口径（2026-09-19 与用户定）：**不要生成/查询类命令**。出口的身份、token 台账、
// 实际监听端口、已公布的公网端点全部是 state 目录里的文件；token 由 serve 自己打印
// （启动时 + 端点变化时），要看当前值就读日志，不另设命令。
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/zhaoyswd/homeway/internal/server"
)

// version 由 CI 用 -ldflags "-X main.version=<tag>" 注入（必须是 var：-X 对 const 无效）。
var version = "0.0.0-dev"

func main() {
	args := os.Args[1:]
	if len(args) > 0 && (args[0] == "--version" || args[0] == "version") {
		fmt.Println("homewayd", version)
		return
	}
	// 裸 `homewayd` = `homewayd serve`（用户口径：普通用户不需要任何参数）。
	if len(args) > 0 && args[0] == "serve" {
		args = args[1:]
	}
	if err := serve(args); err != nil {
		fmt.Fprintln(os.Stderr, "homewayd:", err)
		os.Exit(1)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("homewayd", flag.ExitOnError)
	stateDir := fs.String("state", defaultStateDir(), "state 目录（身份密钥 + token 台账）")
	listen := fs.Uint("listen", 41641, "WG 监听端口（被占用自动退让）")
	relayServer := fs.String("relay", "", "中继 token（rl1…，由 homeway-relay 启动时打印；空 = 不用中继）")
	bindIface := fs.String("bind-interface", "auto", "WG socket 钉哪张卡：auto（默认，探针自动挑能出网的物理网卡）/ none（不绑，走系统默认路由）/ 网卡名 / IP 字面量")
	upnp := fs.Bool("upnp", true, "向路由器申请 UDP 端口映射（默认开；--upnp=false 关）")
	stunServer := fs.String("stun", "stun.cloudflare.com:3478", "STUN 服务器（观测 IPv4 公网映射；空 = 关）")
	stun6Server := fs.String("stun6", "stun.cloudflare.com:3478", "IPv6 路径校验用的 STUN（空 = 关）")
	verbose := fs.Bool("verbose", false, "打印 wireguard-go 详细日志（排障用）")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `用法：
  homewayd                     # 零参数启动；启动日志里的「客户端 token」就是手机要粘的地址
  homewayd --relay 'rl1…'      # 需要中继时只加这一个参数`)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	bindAddr, bindIf, bindMode, err := resolveBind(*bindIface)
	if err != nil {
		return err
	}
	return server.Run(ctx, server.ServeConfig{
		StateDir:   *stateDir,
		ListenPort: uint16(*listen),
		Verbose:    *verbose,
		BindAddr:   bindAddr,
		BindIface:  bindIf,
		BindMode:   bindMode,
		UPnP:       *upnp,
		STUN:       *stunServer,
		STUN6:      *stun6Server,
		Relay:      *relayServer,
	})
}

// resolveBind：--bind-interface 的取值（WG socket 钉哪张卡）。
//
//	auto / 空（默认）：候选物理网卡逐个探针，自动挑**能出网**的那张（换网自动重挑）；
//	none / off：不绑（走系统默认路由）。TUN 型代理抢默认路由的机器上不要用；
//	网卡名（如 en0）：显式钉这张，换网时按名字重解析；
//	IPv4/IPv6 字面量：单栈绑该地址（历史上用于绕开 Surge 抢路由）。
func resolveBind(v string) (netip.Addr, *net.Interface, server.BindMode, error) {
	v = strings.TrimSpace(v)
	switch strings.ToLower(v) {
	case "", "auto":
		return netip.Addr{}, nil, server.BindAuto, nil
	case "none", "off", "no":
		return netip.Addr{}, nil, server.BindOff, nil
	}
	if ip, err := netip.ParseAddr(v); err == nil {
		return ip, nil, server.BindOff, nil
	}
	ifi, err := net.InterfaceByName(v)
	if err != nil {
		// 名字写错/网卡暂时不在：**告警后退回 auto**（探针挑一张能出网的），不让出口起不来。
		logf("⚠️ --bind-interface %q 找不到（%v）—— 退回 auto（自动挑卡）", v, err)
		return netip.Addr{}, nil, server.BindAuto, nil
	}
	return netip.Addr{}, ifi, server.BindExplicit, nil
}

func defaultStateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "./homeway-state"
	}
	return home + "/.config/homeway"
}

func logf(format string, args ...any) {
	fmt.Printf("[homewayd] "+format+"\n", args...)
}
