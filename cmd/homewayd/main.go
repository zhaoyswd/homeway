// homewayd：Homeway 后端——WG 端点 + token 签发 + 流服务（exit redial / files / 终端 / 端口转发目标）。
//
//	homewayd issue --state <dir> --direct a.b.c.d:port[,e.f.g.h:port] [--relay r:port]
//	homewayd serve --state <dir> --listen :41641
//
// serve 的流服务（files/终端/转发）在阶段 3.3+ 落地；当前骨架=完整 WG 数据面
// （ServerBind + 动态 peer 表 + reg 验证）。
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
	"time"

	"github.com/zhaoyswd/homeway/internal/server"
	"github.com/zhaoyswd/homeway/pkg/egress"
	"github.com/zhaoyswd/homeway/pkg/proto"
)

const version = "0.0.0-dev"

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Println("homewayd", version)
		return
	}
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "issue":
		err = cmdIssue(os.Args[2:])
	case "serve":
		err = cmdServe(os.Args[2:])
	case "upnp":
		err = cmdUPnP(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "homewayd:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `用法：
  homewayd serve [--state <dir>]      # 零参数即可：UPnP/STUN 默认开、WG socket 自动挑卡（端口冲突自动退让）
  homewayd issue [--state <dir>]      # 零参数：自动带 LAN 端点 + 已公布的公网端点
  homewayd serve [--listen 41641] [--upnp=false] [--stun host:3478|空] [--bind-interface auto|none|网卡|IP]
  homewayd upnp list | clean [--port N] [--desc 前缀]
  homewayd upnp probe --port N              # 试申请该外部端口（判断是否被占用；成功即删）
  homewayd version`)
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

// localV4s：本机物理网卡的 IPv4 地址（非回环/非虚拟，按 egress 的口径）。
func localV4s() []netip.Addr {
	var out []netip.Addr
	for _, ifi := range egress.PhysicalCandidates() {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if ok && ip.Unmap().Is4() {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out
}

func parseEndpoints(comma string, relay bool) ([]proto.Endpoint, error) {
	var out []proto.Endpoint
	for _, p := range strings.Split(comma, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, proto.Endpoint{Addr: p, Relay: relay})
	}
	return out, nil
}

// cmdUPnP：路由器 UPnP 映射的运维口（list 看现状、clean 清掉我们建的）。
// 为什么需要：映射是路由器上的持久状态，出口重启/换端口会留下旧的 —— 有这条命令才能查清/收拾干净。
func cmdUPnP(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("用法：homewayd upnp list | clean [--port N]")
	}
	sub := args[0]
	fs := flag.NewFlagSet("upnp", flag.ExitOnError)
	port := fs.Uint("port", 0, "只处理这个外部端口（0 = 全部）")
	desc := fs.String("desc", "homeway-exit", "只清理描述以该前缀开头的映射")
	probeIP := fs.String("ip", "", "probe 用：内网目标地址（默认本机）")
	cleanAny := fs.Bool("any-client", false, "clean 用：连别的内网地址上的同前缀映射也一起清（默认只清本机）")
	fs.Parse(args[1:])

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	g, local, err := server.FindIGD(ctx)
	if err != nil {
		return fmt.Errorf("找路由器（SSDP）：%w", err)
	}
	fmt.Printf("路由器 IGD：%s（本机 %s）\n", g.ControlURL(), local)
	switch sub {
	case "list":
		list, err := g.ListMappings(ctx, 200)
		if err != nil {
			return err
		}
		if len(list) == 0 {
			fmt.Println("（没有任何端口映射）")
			return nil
		}
		for _, m := range list {
			mine := ""
			if strings.HasPrefix(m.Description, *desc) {
				mine = "  ← 我们的"
			}
			fmt.Printf("[%3d] %s %5d → %-15s %5d  租期=%ds  描述=%q%s\n",
				m.Index, m.Protocol, m.ExternalPort, m.InternalClient, m.InternalPort,
				m.LeaseDuration, m.Description, mine)
		}
		return nil
	case "probe":
		// 排障：试着申请一条映射（不删同名），成功就立刻删掉；用来回答"这个外部端口是不是被占了"。
		if *port == 0 {
			return fmt.Errorf("probe 需要 --port")
		}
		ip := local
		if *probeIP != "" {
			parsed, err := netip.ParseAddr(*probeIP)
			if err != nil {
				return fmt.Errorf("--ip %q 不是 IPv4: %w", *probeIP, err)
			}
			ip = parsed
		}
		body, err := g.ProbeAdd(ctx, uint16(*port), ip, 60)
		if err != nil {
			frag := strings.Join(strings.Fields(body), " ")
			if len(frag) > 600 {
				frag = frag[:600]
			}
			fmt.Printf("申请 外部 UDP %d → %s:%d 失败：%v\n%s\n", *port, ip, *port, err, frag)
			return nil // 排障命令：失败不是"命令失败"
		}
		fmt.Printf("申请成功（说明该外部端口当前空闲）：外部 UDP %d → %s:%d\n", *port, ip, *port)
		if derr := g.DeleteMapping(ctx, uint16(*port), "UDP"); derr != nil {
			fmt.Printf("（清理失败：%v —— 60s 租期后会自己过期）\n", derr)
		} else {
			fmt.Println("（已立刻删除，不留痕迹）")
		}
		return nil
	case "clean":
		client := local
		if *cleanAny {
			client = netip.Addr{}
		}
		n, kept, err := g.CleanMappings(ctx, *desc, uint16(*port), client)
		if err != nil {
			return err
		}
		fmt.Printf("已删除 %d 条「%s」映射；保留 %d 条：\n", n, *desc, len(kept))
		for _, k := range kept {
			fmt.Println("  ", k)
		}
		return nil
	default:
		return fmt.Errorf("未知子命令 %q（用法：homewayd upnp list | clean）", sub)
	}
}

func cmdIssue(args []string) error {
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	stateDir := fs.String("state", defaultStateDir(), "state 目录（身份密钥+token 台账）")
	direct := fs.String("direct", "", "直连端点，逗号分隔 host:port（可含域名/LAN 地址）")
	relay := fs.String("relay", "", "中继端点，逗号分隔 host:port")
	noPublic := fs.Bool("no-public", false, "不自动附加出口公布的公网端点")
	fs.Parse(args)

	var eps []proto.Endpoint
	eps = append(eps, mustEps(parseEndpoints(*direct, false))...)
	// 没给 --direct 时**自动带上本机 LAN 端点**（物理网卡的 IPv4 + 实际监听端口）：
	// 手机在同一局域网时优先走它（最快），出了门才用公网端点。
	if strings.TrimSpace(*direct) == "" {
		port := server.ReadListenPort(*stateDir)
		if port == 0 {
			port = 41641
		}
		for _, ip := range localV4s() {
			ep := proto.Endpoint{Addr: netip.AddrPortFrom(ip, port).String()}
			eps = append(eps, ep)
			fmt.Fprintf(os.Stderr, "homewayd: 已附上本机 LAN 端点 %s（--direct 可覆盖）\n", ep.Addr)
		}
	}
	// 出口若已自动公布公网端点（UPnP + 同 socket STUN 一致才写），自动拼进直连候选：
	// 家里/外面都能连。--no-public 可关掉。
	if !*noPublic {
		for _, pub := range server.ReadPublicEndpoints(*stateDir) {
			eps = append(eps, proto.Endpoint{Addr: pub})
			fmt.Fprintf(os.Stderr, "homewayd: 已附上自动公布的公网端点 %s（--no-public 可关）\n", pub)
		}
	}
	eps = append(eps, mustEps(parseEndpoints(*relay, true))...)
	if len(eps) == 0 {
		return fmt.Errorf("没有可用端点：既没有 --direct/--relay，也没能自动发现 LAN 地址或已公布的公网端点")
	}

	st, err := server.OpenState(*stateDir)
	if err != nil {
		return err
	}
	tok, err := st.IssueToken(eps)
	if err != nil {
		return err
	}
	enc, err := proto.EncodeToken(tok)
	if err != nil {
		return err
	}
	fmt.Println(enc)
	return nil
}

func mustEps(eps []proto.Endpoint, err error) []proto.Endpoint {
	if err != nil {
		panic(err)
	}
	return eps
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	stateDir := fs.String("state", defaultStateDir(), "state 目录（身份密钥+token 台账）")
	listen := fs.Uint("listen", 41641, "WG 监听端口")
	verbose := fs.Bool("verbose", false, "打印 wireguard-go 详细日志")
	upnp := fs.Bool("upnp", true, "向路由器申请 UDP 端口映射（默认开，30 分钟续期；--upnp=false 关）")
	stunServer := fs.String("stun", "stun.cloudflare.com:3478", "STUN 服务器（在监听 socket 上观测 IPv4 公网映射；空 = 关）")
	stun6Server := fs.String("stun6", "stun.cloudflare.com:3478", "做 IPv6 路径校验用的 STUN（要有 AAAA；空 = 关）")
	bindIface := fs.String("bind-interface", "auto", "WG socket 钉哪张卡：auto（默认，探针自动挑能出网的物理网卡）/ none（不绑，走系统默认路由）/ 网卡名 / IP 字面量")
	fs.Parse(args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	bindAddr, bindIf, bindMode, err := resolveBind(*bindIface)
	if err != nil {
		return err
	}
	return server.Run(ctx, server.ServeConfig{
		StateDir:        *stateDir,
		ListenPort:      uint16(*listen),
		Verbose:         *verbose,
		BindAddr:        bindAddr,
		BindIface:       bindIf,
		BindMode:        bindMode,
		UPnP:            *upnp,
		STUN:            *stunServer,
		STUN6:           *stun6Server,
	})
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

func shortB64(b []byte) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	_ = chars
	// 简短指纹（前 6 字节 hex）
	if len(b) >= 6 {
		return fmt.Sprintf("%x", b[:6])
	}
	return fmt.Sprintf("%x", b)
}
