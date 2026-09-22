// CLI：中继（relay）角色的命令行入口。由 cmd/homeway 按角色分发调用。
//
// 本文件只做参数解析、密钥加载与 token 打印，转发逻辑在 relay.go。
package relay

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

	"github.com/zhaoyswd/homeway/pkg/egress"
	"github.com/zhaoyswd/homeway/pkg/proto"
)

// Version：二进制版本串（cmd/homeway/main.go 把 -ldflags 注入的 main.version 赋进来；
// 探测应答的构建标记由此取值，add-host-connectivity）。
var Version string

// CLI 解析中继参数并启动，阻塞到进程收到 SIGINT/SIGTERM。
func CLI(args []string) error {
	fs := flag.NewFlagSet("homeway relay", flag.ExitOnError)
	state := fs.String("state", defaultStateDir(), "state 目录（存中继鉴权密钥；重启不变 ⇒ token 稳定）")
	listen := fs.String("listen", ":41641", "监听地址（UDP）")
	advertise := fs.String("advertise", "", "token 里公布的中继地址（逗号分隔 host:port；默认用本机网卡地址）")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `用法：
  homeway relay                            # 零参数启动；启动日志里的「中继 token（rl1…）」给出口用
  homeway relay --advertise a.b.c.d:port   # 公网机才需要：指定 token 里公布的对外地址`)
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if rest := fs.Args(); len(rest) > 0 {
		// 本角色**没有子命令**：位置参数一定是写错了。早先文档里写过并不存在的 `token` 子命令，
		// 它被静默忽略、把中继又起了一遍（还占了另一个端口）。宁可报错。
		return fmt.Errorf("不认识的参数：%v（直接 `homeway relay [--advertise …]` 即可，没有子命令）", rest)
	}

	// 文件日志先立起来（loadSecret 的提示也有地方落）：终端从此只出 token/端点行。
	initRelayLog(*state)
	secret, created, err := loadSecret(*state)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	r := New(Config{
		Addr:   *listen,
		Secret: secret,
		Build:  Version,
		Logf:   logf,
	})
	if created {
		logf("已生成中继鉴权密钥（%s/relay.key，0600）—— 重启不变，token 因此稳定", *state)
	}
	// 启动时带一行日志落点（只此一次；终端不再输出其它信息）。
	if p := relayLogPath(); p != "" {
		ulogf("日志：%s —— 终端只出 token 与端点变化", p)
	}
	return r.RunWithReady(ctx, func(actual netip.AddrPort) {
		token, eps, terr := buildToken(secret, *advertise, actual.Port())
		if terr != nil {
			logf("⚠️ token 生成失败（%v）—— 后端可用裸地址走开放模式", terr)
			return
		}
		ulogf("中继 token：%s", token)
		ulogf("端点：%s", strings.Join(eps, "、"))
		if allPrivate(eps) {
			ulogf("⚠️ 公布的地址都在内网：公网中继请加 --advertise <公网IP:端口>")
		}
		// 用法提示进文件（终端不再输出）：token 里已含全部端点与密钥。
		logf("后端这样用：homeway exit --relay '%s'", token)
	})
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

// buildToken：把中继地址（--advertise 优先，否则本机物理网卡地址）+ 端口 + 鉴权密钥编成 rl1 token。
//
// 端口以**实际监听口**为准：--advertise 只给 host 时补上实际端口；给了不同端口则按它写
// （NAT 场景下外部口可以不同），但打一行告警 —— token 里的端口必须真的能连到我们。
// 告警走 ulogf：它属于「token 里的端口信息」且只在配置错误时出现一次。
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
			ulogf("⚠️ --advertise %q 的端口 %d 与实际监听口 %d 不一致：token 里写的是 %d —— 除非前面有 NAT 端口映射，否则后端连不上", a, pn, port, pn)
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
