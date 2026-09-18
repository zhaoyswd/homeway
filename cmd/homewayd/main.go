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
	"os"
	"os/signal"
	"strings"
	"syscall"

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
  homewayd serve --state <dir> [--listen :41641]
  homewayd version`)
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

func cmdIssue(args []string) error {
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	stateDir := fs.String("state", defaultStateDir(), "state 目录（身份密钥+token 台账）")
	direct := fs.String("direct", "", "直连端点，逗号分隔 host:port（可含域名/LAN 地址）")
	relay := fs.String("relay", "", "中继端点，逗号分隔 host:port")
	fs.Parse(args)

	var eps []proto.Endpoint
	eps = append(eps, mustEps(parseEndpoints(*direct, false))...)
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
	fs.Parse(args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return server.Run(ctx, server.ServeConfig{
		StateDir:   *stateDir,
		ListenPort: uint16(*listen),
		Verbose:    *verbose,
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

