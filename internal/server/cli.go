// CLI：出口（serve）角色的前台单角色命令行入口（role-management 2.1，D1/D3）。
// 由 cmd/homeway 按角色分发调用；一次性前台形态：**不改期望态**（config 的 enabled
// 不动），flag 全集保留为一次性覆盖（覆盖序 flag > config > 内置默认，NS「覆盖序」）。
//
// `--state` 即统一 state 根（r2 新-2 / r3 新-10）：CLI 装配层按 D3 拆分表注入——
// L2 = <state>/serve/、L3 = <state>/cache/、瞬态 socket = <state>/。本文件只做参数
// 解析与装配，数据面逻辑在 serve.go/role.go。
package server

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/zhaoyswd/homeway/internal/nodeconfig"
	"github.com/zhaoyswd/homeway/internal/nodestate"
)

// CLI 解析出口参数并启动，阻塞到进程收到 SIGINT/SIGTERM（前台单角色形态保留
// 自带信号处理——统一进程的唯一信号入口在 daemon 装配层，D3）。
func CLI(args []string) error {
	fs := flag.NewFlagSet("homeway serve", flag.ExitOnError)
	stateDir := fs.String("state", defaultStateDir(), "统一 state 根（L2=<state>/serve、L3=<state>/cache、socket=<state>；首启自动迁移旧布局）")
	listen := fs.Uint("listen", 41641, "WG 监听端口（被占用自动退让；未显式给 = 用 config）")
	relayServer := fs.String("relay", "", "中继 token（rl1…，由 `homeway relay` 启动时打印；空 = 不用中继；未显式给 = 用 config）")
	bindIface := fs.String("bind-interface", "auto", "WG socket 钉哪张卡：auto（默认，探针自动挑能出网的物理网卡）/ none（不绑，走系统默认路由）/ 网卡名 / IP 字面量")
	upnp := fs.Bool("upnp", true, "向路由器申请 UDP 端口映射（默认开；--upnp=false 关）")
	stunServer := fs.String("stun", "stun.cloudflare.com:3478", "STUN 服务器（观测 IPv4 公网映射；空 = 关）")
	stun6Server := fs.String("stun6", "stun.cloudflare.com:3478", "IPv6 路径校验用的 STUN（空 = 关）")
	ddns := fs.String("ddns", "", "DDNS 域名（如 home.example.com）：token 额外带上 host:端口 条目（显式给 = 覆盖 config 的全部条目）；域名记录由你的 DDNS 设施维护，出口只读不自更")
	maxPeers := fs.Int("max-peers", 32, "设备表容量（同时记住的设备数上限；表满只淘汰超过活跃宽限期未刷新的失联设备）")
	peerTTL := fs.Duration("peer-ttl", 7*24*time.Hour, "长期不活跃设备的回收期限（0 = 关闭 TTL 回收）")
	dnsPort := fs.Uint("dns-port", uint(DefaultDNSPort), "DNS 代答监听端口（任意目的 :53 的隧道查询改写到这里，上游=主机系统解析；0 = 关闭代答，:53 按原目标过境重拨）")
	verbose := fs.Bool("verbose", false, "摘要+细节日志同时回显终端（现场排障用）；默认终端只出 token 与端点变化")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `用法：
  homeway                      # 零参 = 统一进程前台（按 config 期望态装配全部启用角色）
  homeway serve                # 前台只跑出口（不改期望态；flag 为一次性覆盖，未给的键用 config）
  homeway serve --relay 'rl1…' # 需要中继时只加这一个参数
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
		return fmt.Errorf("不认识的参数：%v（前台出口直接 `homeway serve [--relay 'rl1…']`；启停/查询命令组见 `homeway serve --help` 之后的版本）", rest)
	}

	// 单实例锁（role-management 2.3：统一进程与前台单角色共用 <state>/lock——
	// 角色名归一 homeway；同 state 双进程互斥）。装配最早处取，进程退出释放。
	lock, err := nodestate.AcquireInstanceLock(*stateDir, "serve")
	if err != nil {
		return err
	}
	defer lock.Release()

	// 三层 state 打开（含同根自动迁移 + config 缺失生成默认）——迁移摘要行先进
	// <state>/cache/events.log；随后关句柄，events/debug 日志交由 serve 角色接管
	// （append-only，同文件续写；两写者不同时在世）。
	nst, err := nodestate.OpenNodeState(*stateDir)
	if err != nil {
		return fmt.Errorf("打开 state %s：%w", *stateDir, err)
	}
	nst.Close()
	cfgFile, err := nodeconfig.Load(nodeconfig.Path(*stateDir))
	if err != nil {
		return err // 坏 config = fail-fast 可行动错误（文件+行号/字段+值域），不静默按默认
	}

	// 覆盖序（flag 显式设值 > config > 内置默认）：fs.Visit 只含显式设过的键。
	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	sc := cfgFile.Serve
	listenPort := sc.Listen
	if explicit["listen"] {
		listenPort = uint16(*listen)
	}
	relay := sc.Relay
	if explicit["relay"] {
		relay = *relayServer
	}
	bind := sc.BindInterface
	if explicit["bind-interface"] {
		bind = *bindIface
	}
	useUPnP := sc.UPnP
	if explicit["upnp"] {
		useUPnP = *upnp
	}
	stun := sc.STUN
	if explicit["stun"] {
		stun = *stunServer
	}
	stun6 := sc.STUN6
	if explicit["stun6"] {
		stun6 = *stun6Server
	}
	// --ddns 单值 flag 显式给出 = 覆盖 config 的**全部**条目（一次性覆盖语义）。
	var ddnsList []string
	if explicit["ddns"] {
		if *ddns != "" {
			ddnsList = []string{*ddns}
		}
	} else {
		ddnsList = sc.DDNS
	}
	maxDevices := sc.MaxPeers
	if explicit["max-peers"] {
		maxDevices = *maxPeers
	}
	ttl := sc.PeerTTL
	if explicit["peer-ttl"] {
		ttl = *peerTTL
	}
	dns := sc.DNSPort
	if explicit["dns-port"] {
		dns = uint16(*dnsPort)
	}

	// 文件日志先立起来（resolveBind 的告警也得有地方落）：events.log（摘要）+ debug.log（细节），
	// 落注入的 L3 目录（Start 内同目录幂等跳过）。
	cacheDir := filepath.Join(*stateDir, "cache")
	initLogs(cacheDir, *verbose)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	bindAddr, bindIf, bindMode, err := ResolveBind(bind)
	if err != nil {
		return err
	}
	return Run(ctx, ServeConfig{
		// D3 拆分表注入（r2 新-2）：两条进程形态都按表落位，不在状态目录长出旧布局。
		StateDir:    filepath.Join(*stateDir, "serve"),
		LogDir:      cacheDir,
		PortFileDir: cacheDir,
		SockDir:     *stateDir,
		ListenPort:  listenPort,
		Verbose:     *verbose,
		BindAddr:    bindAddr,
		BindIface:   bindIf,
		BindMode:    bindMode,
		UPnP:        useUPnP,
		STUN:        stun,
		STUN6:       stun6,
		DDNS:        ddnsList,
		Relay:       relay,
		MaxDevices:  maxDevices,
		PeerTTL:     ttl,
		DNSPort:     dns,
		FilesRoot:   sc.FilesRoot,
	})
}

// ResolveBind：--bind-interface 的取值（WG socket 钉哪张卡；daemon 装配层共用）。
//
//	auto / 空（默认）：候选物理网卡逐个探针，自动挑**能出网**的那张（换网自动重挑）；
//	none / off：不绑（走系统默认路由）。TUN 型代理抢默认路由的机器上不要用；
//	网卡名（如 en0）：显式钉这张，换网时按名字重解析；
//	IPv4/IPv6 字面量：单栈绑该地址（历史上用于绕开 Surge 抢路由）。
func ResolveBind(v string) (netip.Addr, *net.Interface, BindMode, error) {
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
	if ifi, err := net.InterfaceByName(v); err == nil {
		return netip.Addr{}, ifi, BindExplicit, nil
	} else {
		// 名字写错/网卡暂时不在：**告警后退回 auto**（探针挑一张能出网的），不让出口起不来。
		logf("⚠️ --bind-interface %q 找不到（%v）—— 退回 auto（自动挑卡）", v, err)
	}
	return netip.Addr{}, nil, BindAuto, nil
}

func defaultStateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "./homeway-state"
	}
	return home + "/.config/homeway"
}
