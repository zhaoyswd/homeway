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
  homewayd serve --state <dir> [--listen 41641] [--upnp] [--stun host:3478] [--bind-interface <网卡|IPv4>]
  homewayd upnp list | clean [--port N] [--desc 前缀]
  homewayd upnp probe --port N              # 试申请该外部端口（判断是否被占用；成功即删）
  homewayd version`)
}

// resolveBindAddr：--bind-interface 支持「网卡名」或「IPv4 字面量」（空 = 不绑）。
func resolveBindAddr(v string) (netip.Addr, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return netip.Addr{}, nil
	}
	if ip, err := netip.ParseAddr(v); err == nil {
		if !ip.Is4() {
			return netip.Addr{}, fmt.Errorf("bind-interface %q 不是 IPv4", v)
		}
		return ip, nil
	}
	ifi, err := net.InterfaceByName(v)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("找不到网卡 %q（可传网卡名或 IPv4）: %w", v, err)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip, ok := netip.AddrFromSlice(ipn.IP); ok && ip.Unmap().Is4() {
			return ip.Unmap(), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("网卡 %q 上没有 IPv4 地址", v)
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
		if pub := server.ReadPublicEndpoint(*stateDir); pub != "" {
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
	stunServer := fs.String("stun", "", "STUN 服务器（在监听 socket 上观测公网映射，如 stun.miwifi.com:3478）")
	bindIface := fs.String("bind-interface", "", "把 WG socket 绑到该网卡/地址（物理网卡名或 IPv4；绕开 TUN 型代理）")
	fs.Parse(args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	bindAddr, err := resolveBindAddr(*bindIface)
	if err != nil {
		return err
	}
	return server.Run(ctx, server.ServeConfig{
		StateDir:   *stateDir,
		ListenPort: uint16(*listen),
		Verbose:    *verbose,
		BindAddr:   bindAddr,
		UPnP:       *upnp,
		STUN:       *stunServer,
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

