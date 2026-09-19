// homeway-relay：Homeway 中继——多租户注册腿 + per-client 分配式转发 + hint 控制帧。
//
//	homeway-relay [--state <dir>] [--listen :41641] [--advertise a.b.c.d:port] …
//	homeway-relay token [--state <dir>] [--advertise …] [--listen :41641]   # 重打 token
//
// **凭据方向**（2026-09-19 与用户定的口径）：中继启动时生成/加载自己的鉴权密钥，
// 并打印一个 **中继 token（rl1…）**，内容 = 中继地址 + 该密钥。后端拿 token 启动：
//
//	homewayd serve --state <出口 state> --relay 'rl1…'
//
// 于是中继侧**不需要预先知道任何后端身份**：换后端、换身份都不用动中继配置、更不用重启。
// （早先的 --allow 白名单仍保留，作为"开放模式下的兜底"，token 模式下用不着。）
//
// 定位：中继是**路径而不是参与方**——只见密文、零 WG 感知、零业务落盘
//（--state 只存自己的鉴权密钥，重启不变 ⇒ token 稳定）。
package main

import (
	"context"
	"crypto/rand"
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

	"github.com/zhaoyswd/homeway/internal/relay"
	"github.com/zhaoyswd/homeway/pkg/egress"
	"github.com/zhaoyswd/homeway/pkg/proto"
)

// version 由 CI 用 -ldflags "-X main.version=<tag>" 注入（必须是 var：-X 对 const 无效）。
var version = "0.0.0-dev"

func main() {
	args := os.Args[1:]
	if len(args) > 0 && (args[0] == "--version" || args[0] == "version") {
		fmt.Println("homeway-relay", version)
		return
	}
	if err := cmdServe(args); err != nil {
		fmt.Fprintln(os.Stderr, "homeway-relay:", err)
		os.Exit(1)
	}
}

func defaultStateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "./homeway-relay-state"
	}
	return filepath.Join(home, ".config", "homeway-relay")
}

// loadSecret：从 state 目录加载中继鉴权密钥；没有就生成一个（0600）。
// 重启不变 ⇒ 打印出来的 token 稳定，后端不用跟着改。
func loadSecret(stateDir string) ([32]byte, bool, error) {
	var secret [32]byte
	path := filepath.Join(stateDir, "relay.key")
	if b, err := os.ReadFile(path); err == nil && len(b) == 32 {
		copy(secret[:], b)
		return secret, false, nil
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return secret, false, err
	}
	if _, err := rand.Read(secret[:]); err != nil {
		return secret, false, err
	}
	if err := os.WriteFile(path, secret[:], 0o600); err != nil {
		return secret, false, err
	}
	return secret, true, nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("homeway-relay", flag.ExitOnError)
	state := fs.String("state", defaultStateDir(), "state 目录（存中继鉴权密钥；重启不变 ⇒ token 稳定）")
	listen := fs.String("listen", ":41641", "监听地址（UDP）")
	advertise := fs.String("advertise", "", "token 里公布的中继地址（逗号分隔 host:port；默认用本机网卡地址）")
	idle := fs.Duration("idle", 90*time.Second, "客户端分配腿空闲回收")
	legTimeout := fs.Duration("leg-timeout", 90*time.Second, "后端注册腿过期（不保活即摘掉）")
	rate := fs.Int("rate", 200, "每源地址每秒包数上限（准入限流）")
	maxPerPeer := fs.Int("max-per-peer", 32, "每个后端最多并发的客户端分配腿")
	maxLegs := fs.Int("max-legs", 256, "注册腿总数上限（防匿名 Hello 洪水）")
	allow := fs.String("allow", "", "（可选）后端白名单：8 字节标签 hex 或 64 位公钥 hex，逗号分隔。token 模式用不到")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "用法：")
		fmt.Fprintln(os.Stderr, "  homeway-relay [--state <dir>] [--listen :41641] [--advertise a.b.c.d:port]")
		fmt.Fprintln(os.Stderr, "  homeway-relay token [--state <dir>] [--advertise …]   # 重打中继 token")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	secret, created, err := loadSecret(*state)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	r := relay.New(relay.Config{
		Addr:        *listen,
		IdleTimeout: *idle,
		LegTimeout:  *legTimeout,
		RateLimit:   *rate,
		MaxPerPeer:  *maxPerPeer,
		MaxLegs:     *maxLegs,
		Allow:       splitList(*allow),
		Secret:      secret,
		Logf:        logf,
	})
	if created {
		logf("已生成中继鉴权密钥（%s/relay.key，0600）—— 重启不变，token 因此稳定", *state)
	}
	// 绑定之后再打 token：端口冲突会自动退让，token 里必须是**实际**端口。
	go func() {
		<-ctx.Done()
	}()
	return r.RunWithReady(ctx, func(actual netip.AddrPort) {
		token, eps, terr := buildToken(secret, *advertise, actual.Port())
		if terr != nil {
			logf("⚠️ token 生成失败（%v）—— 后端可用裸地址走开放模式", terr)
			return
		}
		logf("中继 token：%s", token)
		logf("  端点 %v ｜ 后端这样用：homewayd serve --relay '%s'", eps, token)
		if allPrivate(eps) {
			logf("  ⚠️ 公布的地址都在内网：公网中继请加 --advertise <公网IP:端口>")
		}
	})
}

// buildToken：把中继地址（--advertise 优先，否则本机物理网卡地址）+ 端口 + 鉴权密钥编成 rl1 token。
//
// 端口以**实际监听口**为准：--advertise 只给 host 时补上实际端口；给了不同端口则按它写
//（NAT 场景下外部口可以不同），但打一行告警 —— token 里的端口必须真的能连到我们。
func buildToken(secret [32]byte, advertise string, port uint16) (string, []string, error) {
	var eps []proto.Endpoint
	var addrs []string
	for _, a := range splitList(advertise) {
		host, p, err := net.SplitHostPort(a)
		if err != nil {
			return "", nil, fmt.Errorf("--advertise %q 不是 host:port", a)
		}
		var pn uint16
		_, _ = fmt.Sscanf(p, "%d", &pn)
		if pn != port {
			logf("⚠️ --advertise %q 的端口 %d 与实际监听口 %d 不一致：token 里写的是 %d —— 除非前面有 NAT 端口映射，否则后端连不上", a, pn, port, pn)
		}
		addrs = append(addrs, net.JoinHostPort(host, p))
	}
	var skipped []string
	prefixes := map[string]struct{}{}
	if len(addrs) == 0 {
		// 自动探测**只取公网地址**（永远不把非公网 IP 写进 token）。
		for _, ifi := range egress.PhysicalCandidates() {
			as, err := ifi.Addrs()
			if err != nil {
				continue
			}
			for _, a := range as {
				ipn, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				ip, ok := netip.AddrFromSlice(ipn.IP)
				if !ok {
					continue
				}
				ip = ip.Unmap()
				if !egress.IsPublicAddr(ip) {
					skipped = append(skipped, netip.AddrPortFrom(ip, port).String())
					continue
				}
				// 同一 /64 只留一个：macOS 的 IPv6 临时地址（privacy extensions）会轮换，
				// 同一前缀下往往挂着 7–8 个，全写进 token 既长又容易过期。
				if ip.Is6() {
					pfx, perr := ip.Prefix(64)
					if perr != nil {
						continue
					}
					if _, seen := prefixes[pfx.String()]; seen {
						continue
					}
					prefixes[pfx.String()] = struct{}{}
				}
				addrs = append(addrs, netip.AddrPortFrom(ip, port).String())
			}
		}
	}
	if len(addrs) == 0 {
		if len(skipped) > 0 {
			return "", nil, fmt.Errorf("本机只有非公网地址（%v）—— token 里不放非公网 IP："+
				"公网中继请加 --advertise <公网IP:端口>；局域网内使用也请显式 --advertise <局域网IP:端口>",
				skipped)
		}
		return "", nil, fmt.Errorf("没找到可公布的地址（用 --advertise 指定）")
	}
	for _, a := range addrs {
		eps = append(eps, proto.Endpoint{Addr: a})
	}
	tok, err := proto.EncodeRelayToken(secret, eps)
	return tok, addrs, err
}

// portOf：从 --listen（如 ":41741" 或 "0.0.0.0:41741"）里取端口。
func portOf(listen string) uint16 {
	_, p, err := net.SplitHostPort(listen)
	if err != nil {
		return 41641
	}
	var n uint16
	_, _ = fmt.Sscanf(p, "%d", &n)
	if n == 0 {
		n = 41641
	}
	return n
}

// allPrivate：公布的地址全在内网吗（提醒加 --advertise）。
func allPrivate(addrs []string) bool {
	for _, a := range addrs {
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			continue
		}
		ip, err := netip.ParseAddr(host)
		if err == nil && !ip.IsPrivate() && !ip.IsLoopback() {
			return false
		}
	}
	return true
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func logf(format string, args ...any) {
	fmt.Printf("[homeway-relay] "+format+"\n", args...)
}
