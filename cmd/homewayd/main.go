// homewayd：Homeway 后端——WG 端点 + token 签发 + 流服务（exit redial / files / 终端 / 端口转发目标）。
//
//	homewayd issue --state <dir> --direct a.b.c.d:port[,e.f.g.h:port] [--relay r:port]
//	homewayd serve --state <dir> --listen :41641
//
// serve 的流服务（files/终端/转发）在阶段 3.3+ 落地；当前骨架=完整 WG 数据面
// （ServerBind + 动态 peer 表 + reg 验证）。
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/zhaoyswd/homeway/internal/server"
	"github.com/zhaoyswd/homeway/pkg/proto"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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
	stateDir := fs.String("state", defaultStateDir(), "state 目录")
	listen := fs.Uint("listen", 41641, "WG 监听端口")
	verbose := fs.Bool("verbose", false, "打印 wireguard-go 详细日志")
	fs.Parse(args)

	st, err := server.OpenState(*stateDir)
	if err != nil {
		return err
	}
	priv, err := st.PrivateKey()
	if err != nil {
		return err
	}
	secrets, err := st.Secrets()
	if err != nil {
		return err
	}

	// WG device：内存 tun（netstack 接管在 3.3）+ ServerBind + 动态 peer 表
	tun := tuntest.NewChannelTUN()
	level := device.LogLevelError
	if *verbose {
		level = device.LogLevelVerbose
	}
	sbind := &server.ServerBind{Logf: logf}
	dev := device.NewDevice(tun.TUN(), sbind, device.NewLogger(level, "homewayd"))
	defer dev.Close()

	// deviceConfigurer：把 PeerTable 的表项落到 device（IpcSet）。
	dc := &deviceConfigurer{dev: dev}
	table := server.NewPeerTable(dc, secrets, 8, 0)
	sbind.Table = table

	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", hex.EncodeToString(priv[:]), *listen)); err != nil {
		return err
	}
	if err := dev.Up(); err != nil { // FINDINGS 0.1-1：NewDevice 后必须显式 Up()
		return err
	}

	// 隧道内出站包（当前无流服务，drain 记日志防阻塞）
	go func() {
		for pkt := range tun.Outbound {
			logf("tun outbound %d bytes（流服务未接入，丢弃）", len(pkt))
		}
	}()

	pub := priv.PublicKey()
	logf("serve 就绪：port=%d peers(已签发token)=%d key=%s…（issue 子命令出 token）", *listen, len(secrets), shortB64(pub[:]))

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	logf("退出")
	return nil
}

type deviceConfigurer struct{ dev *device.Device }

func (d *deviceConfigurer) AddPeer(pc server.PeerConfig) error {
	return d.dev.IpcSet(fmt.Sprintf(
		"public_key=%s\npreshared_key=%s\nallowed_ip=%s/32\npersistent_keepalive_interval=%d\n",
		hex.EncodeToString(pc.Pubkey[:]), hex.EncodeToString(pc.PSK[:]), pc.TunnelIP, pc.Keepalive))
}

func (d *deviceConfigurer) RemovePeer(pub [32]byte) error {
	return d.dev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", hex.EncodeToString(pub[:])))
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

var _ = wgtypes.Key{} // 保留引用（后续流服务使用）
