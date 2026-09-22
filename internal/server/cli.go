// CLI：出口（exit）角色的命令行入口。由 cmd/homeway 按角色分发调用。
//
// 本文件只做参数解析与调用 Run，不含任何数据面逻辑。
package server

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
	"time"
)

// CLI 解析出口参数并启动，阻塞到进程收到 SIGINT/SIGTERM。
func CLI(args []string) error {
	fs := flag.NewFlagSet("homeway exit", flag.ExitOnError)
	stateDir := fs.String("state", defaultStateDir(), "state 目录（身份密钥 + token 台账；换身份/多开才需要）")
	listen := fs.Uint("listen", 41641, "WG 监听端口（被占用自动退让）")
	relayServer := fs.String("relay", "", "中继 token（rl1…，由 `homeway relay` 启动时打印；空 = 不用中继）")
	bindIface := fs.String("bind-interface", "auto", "WG socket 钉哪张卡：auto（默认，探针自动挑能出网的物理网卡）/ none（不绑，走系统默认路由）/ 网卡名 / IP 字面量")
	upnp := fs.Bool("upnp", true, "向路由器申请 UDP 端口映射（默认开；--upnp=false 关）")
	stunServer := fs.String("stun", "stun.cloudflare.com:3478", "STUN 服务器（观测 IPv4 公网映射；空 = 关）")
	stun6Server := fs.String("stun6", "stun.cloudflare.com:3478", "IPv6 路径校验用的 STUN（空 = 关）")
	ddns := fs.String("ddns", "", "DDNS 域名（如 home.example.com）：token 额外带上 host:端口 条目（既有端点全保留），手机重连/重赛跑时解析取当前地址——端点漂移后不再需要重取 token。域名记录由你的 DDNS 设施（路由器自带/脚本/DNS API）维护，出口只读不自更")
	maxPeers := fs.Int("max-peers", 32, "设备表容量（同时记住的设备数上限；表满只淘汰超过活跃宽限期未刷新的失联设备）")
	peerTTL := fs.Duration("peer-ttl", 7*24*time.Hour, "长期不活跃设备的回收期限（0 = 关闭 TTL 回收）")
	dnsPort := fs.Uint("dns-port", uint(DefaultDNSPort), "DNS 代答监听端口（任意目的 :53 的隧道查询改写到这里，上游=主机系统解析；0 = 关闭代答，:53 按原目标过境重拨）")
	verbose := fs.Bool("verbose", false, "摘要+细节日志同时回显终端（现场排障用）；默认终端只出 token 与端点变化")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `用法：
  homeway                      # 零参数启动出口；启动日志里的「客户端 token」就是手机要粘的地址
  homeway exit                 # 同上（显式角色）
  homeway exit --relay 'rl1…'  # 需要中继时只加这一个参数
  homeway relay                # 启动中继（homeway relay --help）`)
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if *dnsPort > 65535 {
		return fmt.Errorf("--dns-port 超出端口范围：%d（1–65535；0 = 关闭代答）", *dnsPort)
	}
	if *ddns != "" && strings.ContainsAny(*ddns, ":/ ") {
		return fmt.Errorf("--ddns 只要裸域名（不带端口/路径）：%q", *ddns)
	}
	if rest := fs.Args(); len(rest) > 0 {
		// 没有子命令：多出来的位置参数一定是写错了。
		// 这条是**实测踩出来的**：`homeway foo` 会被当成裸启动，真的起一个出口
		// （抢不到 41641 就退让），还会把真出口的 UPnP 映射改成指向它自己。宁可报错。
		return fmt.Errorf("不认识的参数：%v（直接 `homeway [--relay 'rl1…']` 即可，没有其它子命令）", rest)
	}

	// 文件日志先立起来（resolveBind 的告警也得有地方落）：events.log（摘要）+ debug.log（细节）。
	initLogs(*stateDir, *verbose)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	bindAddr, bindIf, bindMode, err := resolveBind(*bindIface)
	if err != nil {
		return err
	}
	return Run(ctx, ServeConfig{
		StateDir:   *stateDir,
		ListenPort: uint16(*listen),
		Verbose:    *verbose,
		BindAddr:   bindAddr,
		BindIface:  bindIf,
		BindMode:   bindMode,
		UPnP:       *upnp,
		STUN:       *stunServer,
		STUN6:      *stun6Server,
		DDNS:       *ddns,
		Relay:      *relayServer,
		MaxDevices: *maxPeers,
		PeerTTL:    *peerTTL,
		DNSPort:    uint16(*dnsPort),
	})
}

// resolveBind：--bind-interface 的取值（WG socket 钉哪张卡）。
//
//	auto / 空（默认）：候选物理网卡逐个探针，自动挑**能出网**的那张（换网自动重挑）；
//	none / off：不绑（走系统默认路由）。TUN 型代理抢默认路由的机器上不要用；
//	网卡名（如 en0）：显式钉这张，换网时按名字重解析；
//	IPv4/IPv6 字面量：单栈绑该地址（历史上用于绕开 Surge 抢路由）。
func resolveBind(v string) (netip.Addr, *net.Interface, BindMode, error) {
	v = strings.TrimSpace(v)
	switch strings.ToLower(v) {
	case "", "auto":
		return netip.Addr{}, nil, BindAuto, nil
	case "none", "off", "no":
		return netip.Addr{}, nil, BindOff, nil
	}
	if ip, err := netip.ParseAddr(v); err == nil {
		return ip, nil, BindOff, nil
	}
	ifi, err := net.InterfaceByName(v)
	if err != nil {
		// 名字写错/网卡暂时不在：**告警后退回 auto**（探针挑一张能出网的），不让出口起不来。
		logf("⚠️ --bind-interface %q 找不到（%v）—— 退回 auto（自动挑卡）", v, err)
		return netip.Addr{}, nil, BindAuto, nil
	}
	return netip.Addr{}, ifi, BindExplicit, nil
}

func defaultStateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "./homeway-state"
	}
	return home + "/.config/homeway"
}
