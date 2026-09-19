// homeway-relay：Homeway 中继——多租户注册腿 + per-client 分配式转发 + hint 控制帧。
//
//	homeway-relay [--listen :41641] [--idle 90s] [--leg-timeout 90s] [--rate 200] [--max-per-peer 32]
//
// 定位：中继是**路径而不是参与方**——只见密文、零 WG 感知、零落盘状态（重启即清）。
// 后端用 `homewayd serve --relay <中继地址>` 反向注册（出站即可，NAT 友好），
// 客户端用 token 里的 relay 端点（`homewayd issue --relay <中继地址>`）经它建连。
package main

import (
	"context"
	"flag"
	"strings"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zhaoyswd/homeway/internal/relay"
)

const version = "0.0.0-dev"

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Println("homeway-relay", version)
		return
	}
	fs := flag.NewFlagSet("homeway-relay", flag.ExitOnError)
	listen := fs.String("listen", ":41641", "监听地址（UDP）")
	idle := fs.Duration("idle", 90*time.Second, "客户端分配腿空闲回收")
	legTimeout := fs.Duration("leg-timeout", 90*time.Second, "后端注册腿过期（不保活即摘掉）")
	rate := fs.Int("rate", 200, "每源地址每秒包数上限（准入限流）")
	maxPerPeer := fs.Int("max-per-peer", 32, "每个后端最多并发的客户端分配腿")
	allow := fs.String("allow", "", "后端白名单（逗号分隔：8 位标签 hex 或 64 位公钥 hex）；空 = 开放注册，任何知道本地址的后端都能用它中转")
	maxLegs := fs.Int("max-legs", 256, "注册腿总数上限（防匿名 Hello 洪水）")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "用法：")
		fmt.Fprintln(os.Stderr, "  homeway-relay [--listen :41641] [--allow 39638668,<hex>] [--max-legs 256] [--idle 90s] [--leg-timeout 90s]")
		fs.PrintDefaults()
	}
	_ = fs.Parse(os.Args[1:])

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	r := relay.New(relay.Config{
		Addr:        *listen,
		IdleTimeout: *idle,
		LegTimeout:  *legTimeout,
		RateLimit:   *rate,
		MaxPerPeer:  *maxPerPeer,
		Allow:       splitList(*allow),
		MaxLegs:     *maxLegs,
		Logf:        logf,
	})
	if err := r.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "homeway-relay:", err)
		os.Exit(1)
	}
}

// splitList：逗号分隔 → 列表（空白项丢掉）。
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
