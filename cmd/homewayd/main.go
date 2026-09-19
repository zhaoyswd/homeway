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
	"github.com/zhaoyswd/homeway/pkg/proto"
	"github.com/zhaoyswd/homeway/pkg/proxy"
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
  homewayd issue --state <dir> --direct host:port[,host:port...] [--relay host:port...]
  homewayd serve --state <dir> [--listen 41641] [--upnp] [--stun host:3478] [--stun6 host:3478] [--bind-interface <网卡|IPv4>]
  homewayd upnp list | clean [--port N] [--desc 前缀]
  homewayd upnp probe --port N              # 试申请该外部端口（判断是否被占用；成功即删）
  homewayd version`)
}

// resolveBind：--bind-interface 支持三种写法（空 = 不绑）：
//   - 网卡名（如 en0）：**双栈监听 + 整条 socket 钉在该网卡**（同时服务 v4/v6 客户端；v6 走物理网卡）；
//   - IPv4 字面量：单栈绑该地址（历史上用于绕开 Surge 抢路由）；
//   - IPv6 字面量：单栈绑该地址。
func resolveBind(v string) (netip.Addr, *net.Interface, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return netip.Addr{}, nil, nil
	}
	if ip, err := netip.ParseAddr(v); err == nil {
		return ip, nil, nil
	}
	ifi, err := net.InterfaceByName(v)
	if err != nil {
		return netip.Addr{}, nil, fmt.Errorf("找不到网卡 %q（可传网卡名或 IP 字面量）: %w", v, err)
	}
	return netip.Addr{}, ifi, nil
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
		return fmt.Errorf("至少需要一个 --direct 或 --relay 端点")
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
	upnp := fs.Bool("upnp", false, "启动后向路由器申请 UDP 端口映射（30 分钟续期）")
	stunServer := fs.String("stun", "", "STUN 服务器（在监听 socket 上观测 IPv4 公网映射，如 stun.miwifi.com:3478）")
	stun6Server := fs.String("stun6", "", "做 IPv6 路径校验用的 STUN 服务器（要有 AAAA，如 stun.cloudflare.com:3478）")
	bindIface := fs.String("bind-interface", "", "把 WG socket 绑到该网卡/地址（物理网卡名或 IPv4；绕开 TUN 型代理）")
	forwardProxy := fs.String("forward-via-proxy", "", "被转发的用户流量经该 SOCKS5 代理出网（socks5://host:port；出口自身 socket 仍直连）")
	forwardUDP := fs.String("forward-udp", "auto", "UDP 是否经代理：auto（探测 UDP ASSOCIATE 能力）/on（必须）/off（不经）")
	forwardProbe := fs.String("forward-udp-probe", "", "UDP 能力探测的 STUN 目标（逗号分隔的字面 IP:port；默认 Cloudflare+Google）")
	forwardEgress := fs.String("forward-egress", "bind", "转发流量走哪条路：bind（钉物理网卡，默认）/ default（系统默认路由 = TUN 型代理按自己的规则处理）；可分开写 tcp=default,udp=bind")
	fs.Parse(args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	bindAddr, bindIf, err := resolveBind(*bindIface)
	if err != nil {
		return err
	}
	udpMode, err := proxy.ParseUDPMode(*forwardUDP)
	if err != nil {
		return err
	}
	probeTargets, err := parseProbeTargets(*forwardProbe)
	if err != nil {
		return err
	}
	egressMode, err := server.ParseForwardEgress(*forwardEgress)
	if err != nil {
		return err
	}
	return server.Run(ctx, server.ServeConfig{
		StateDir:        *stateDir,
		ListenPort:      uint16(*listen),
		Verbose:         *verbose,
		BindAddr:        bindAddr,
		BindIface:       bindIf,
		ForwardEgress:   egressMode,
		ForwardProxy:    *forwardProxy,
		ForwardUDPMode:  udpMode,
		ForwardUDPProbe: probeTargets,
		UPnP:            *upnp,
		STUN:            *stunServer,
		STUN6:           *stun6Server,
	})
}

// parseProbeTargets 解析 --forward-udp-probe（逗号分隔的字面 IP:port；空 = 用内置兜底）。
// 只收字面 IP：规则型代理会把域名解析成 fake-IP，域名探针根本测不到真实服务。
func parseProbeTargets(v string) ([]netip.AddrPort, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, nil
	}
	var out []netip.AddrPort
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		ap, err := netip.ParseAddrPort(part)
		if err != nil {
			return nil, fmt.Errorf("--forward-udp-probe %q：%q 不是字面 IP:port（%w）", v, part, err)
		}
		out = append(out, ap)
	}
	return out, nil
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
