package daemon

// socks_cli.go — homeway socks on/off/status（forward-socks-speedtest 3e §3.3，spec
// forward-socks-cli「socks 命令面」）：按主机开关的 SOCKS5 承载面入口。守护托管
//（监听器住 daemon 进程、仅回环）；--host 寻址/--state 语义/daemon 未跑文案与
// forward 面一致（共用 forward_cli.go 的装配缝）。

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/facade"
	"github.com/zhaoyswd/homeway/internal/cliopts"
	"github.com/zhaoyswd/homeway/internal/control"
)

// socksCLI socks 子命令入口（cmd/homeway 转发）。
// SocksCLI socks 命令面入口（cmd/homeway 顶层名词直连）。
func SocksCLI(args []string, version string, w io.Writer) error {
	return socksCLI(args, version, w)
}

func socksCLI(args []string, version string, w io.Writer) error {
	if len(args) == 0 {
		usageSocks(w)
		return errors.New("socks 需要子命令：on / off / status")
	}
	switch args[0] {
	case "on":
		return socksOnCLI(args[1:], version, w)
	case "off":
		return socksOffCLI(args[1:], version, w)
	case "status":
		return socksStatusCLI(args[1:], version, w)
	}
	usageSocks(w)
	return fmt.Errorf("socks 不认识的子命令 %q（可用：on / off / status）", args[0])
}

func usageSocks(w io.Writer) {
	fmt.Fprint(w, `用法：
  homeway socks on --host <ref> [--listen 1080]
                     该主机开 SOCKS5 监听（127.0.0.1；域名经该主机出口远程解析）
  homeway socks off --host <ref>
                     关监听并显式关在世连接（端口记忆保留，下次 on 缺省沿用）
  homeway socks status [--json]
                     每主机开关态 + 端口 + 在世连接数 + 链路态（via/rtt）
全部子命令可加 --state DIR（恒指 daemon state）与 --timeout；监听端口 1024–65535、
与 forward 规则全局唯一。多主机 = 多端口，浏览器按端口选出口。
`)
}

// socksOnCLI on --host <ref> [--listen P]。
func socksOnCLI(args []string, version string, w io.Writer) error {
	fs := flag.NewFlagSet("homeway socks on", flag.ContinueOnError)
	fs.SetOutput(w)
	stateDir := fs.String("state", DefaultStateDir(), "统一 state 根（从中找 control.sock）")
	noSpawn := fs.Bool("no-spawn", false, "守护进程未运行时不按需拉起（直接报可行动错误；脚本友好）")
	hostRef := fs.String("host", "", "主机（名称/完整 ID/无歧义短前缀，同 host delete）")
	listen := fs.Uint("listen", 0, "监听端口（缺省 = 沿用该主机上次端口，无记忆则 1080；1024–65535）")
	timeout := fs.Duration("timeout", 10*time.Second, "连接与请求的总预算")
	if err := fs.Parse(flagsFirst(args, carrierFlagBools)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("socks on 不接受位置参数（got %q）", fs.Args())
	}
	if strings.TrimSpace(*hostRef) == "" {
		return errors.New("socks on 需要 --host <ref>（homeway host list 查看在表主机）")
	}
	if *listen != 0 && (*listen < 1024 || *listen > 65535) {
		return fmt.Errorf("--listen %d 越界（监听端口须在 1024–65535，与 forward 同一条）", *listen)
	}

	ctx, cancel := context.WithTimeout(cliopts.With(context.Background(), cliopts.Opts{NoSpawn: *noSpawn}), *timeout)
	defer cancel()
	c, err := dialCarrierCLI(ctx, *stateDir, version, "homeway-socks")
	if err != nil {
		return err
	}
	defer c.Close()
	hosts, err := hostsOnConn(ctx, c)
	if err != nil {
		return err
	}
	id, dname, err := resolveHostTarget(hosts, strings.TrimSpace(*hostRef))
	if err != nil {
		return err
	}
	raw, err := c.Request(ctx, facade.OpSocksOn, control.SocksOnArgs{Host: id, Listen: uint16(*listen)})
	if err != nil {
		var code control.CodeError
		if errors.As(err, &code) && string(code) == facade.CodeBadRequest {
			// 冲突现场诊断（FS Scenario「第二主机需另选端口」：文案含占用方与 --listen
			// 提示；占用复查含 off 记忆端口〔exec-r1 L1〕且排除请求主机自己〔L2——防
			// 「被自己占用」的误导文案〕）。
			port := uint16(*listen)
			if port == 0 {
				port = rememberedSocksPort(ctx, c, id)
			}
			if owner, found := findPortOwner(ctx, c, hosts, port, id); found {
				return fmt.Errorf("监听端口 %d 已被 %s 占用（可用 --listen 另选端口）", port, owner)
			}
			return errors.New("socks.on 被拒（bad_request；核对 --listen（1024–65535，与 forward 全局唯一）后重试）")
		}
		return carrierOpErr("socks.on", err)
	}
	var res control.SocksOnResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return fmt.Errorf("socks.on 载荷解析失败：%w", err)
	}
	fmt.Fprintf(w, "socks 已开启：%s 127.0.0.1:%d（域名经 %s 出口远程解析，不在本机解析）\n", dname, res.Listen, dname)
	return nil
}

// rememberedSocksPort 该主机记住的端口（无记忆 = 1080；冲突诊断用——缺省 on 抢的
// 就是这个端口）。
func rememberedSocksPort(ctx context.Context, c *control.Client, host string) uint16 {
	raw, err := c.Request(ctx, facade.OpSocksStatus, nil)
	if err != nil {
		return 1080
	}
	var st control.SocksStatusResult
	if json.Unmarshal(raw, &st) != nil {
		return 1080
	}
	for _, s := range st.Socks {
		if s.Host == host && s.Listen != 0 {
			return s.Listen
		}
	}
	return 1080
}

// socksOffCLI off --host <ref>。
func socksOffCLI(args []string, version string, w io.Writer) error {
	fs := flag.NewFlagSet("homeway socks off", flag.ContinueOnError)
	fs.SetOutput(w)
	stateDir := fs.String("state", DefaultStateDir(), "统一 state 根（从中找 control.sock）")
	noSpawn := fs.Bool("no-spawn", false, "守护进程未运行时不按需拉起（直接报可行动错误；脚本友好）")
	hostRef := fs.String("host", "", "主机（名称/完整 ID/无歧义短前缀，同 host delete）")
	timeout := fs.Duration("timeout", 10*time.Second, "连接与请求的总预算")
	if err := fs.Parse(flagsFirst(args, carrierFlagBools)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("socks off 不接受位置参数（got %q）", fs.Args())
	}
	if strings.TrimSpace(*hostRef) == "" {
		return errors.New("socks off 需要 --host <ref>（homeway socks status 查看）")
	}

	ctx, cancel := context.WithTimeout(cliopts.With(context.Background(), cliopts.Opts{NoSpawn: *noSpawn}), *timeout)
	defer cancel()
	c, err := dialCarrierCLI(ctx, *stateDir, version, "homeway-socks")
	if err != nil {
		return err
	}
	defer c.Close()
	hosts, err := hostsOnConn(ctx, c)
	if err != nil {
		return err
	}
	id, dname, err := resolveHostTarget(hosts, strings.TrimSpace(*hostRef))
	if err != nil {
		return err
	}
	raw, err := c.Request(ctx, facade.OpSocksOff, control.SocksOffArgs{Host: id})
	if err != nil {
		var code control.CodeError
		if errors.As(err, &code) && string(code) == facade.CodeBadRequest {
			return fmt.Errorf("%s 没有开着的 socks 监听（homeway socks status 查看）", dname)
		}
		return carrierOpErr("socks.off", err)
	}
	var res control.SocksOffResult
	_ = json.Unmarshal(raw, &res)
	hint := ""
	if res.Listen != 0 {
		hint = fmt.Sprintf("；端口 %d 记忆保留，下次 on 缺省沿用", res.Listen)
	}
	fmt.Fprintf(w, "socks 已关闭：%s（在世连接已 RST 收口%s）\n", dname, hint)
	return nil
}

// socksStatusCLI status [--json]。
func socksStatusCLI(args []string, version string, w io.Writer) error {
	fs := flag.NewFlagSet("homeway socks status", flag.ContinueOnError)
	fs.SetOutput(w)
	stateDir := fs.String("state", DefaultStateDir(), "统一 state 根（从中找 control.sock）")
	noSpawn := fs.Bool("no-spawn", false, "守护进程未运行时不按需拉起（直接报可行动错误；脚本友好）")
	jsonOut := fs.Bool("json", false, "机器可读 JSON（含 off 但记住的端口）")
	timeout := fs.Duration("timeout", 5*time.Second, "连接与请求的总预算")
	if err := fs.Parse(flagsFirst(args, carrierFlagBools)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("socks status 不接受位置参数（got %q）", fs.Args())
	}

	ctx, cancel := context.WithTimeout(cliopts.With(context.Background(), cliopts.Opts{NoSpawn: *noSpawn}), *timeout)
	defer cancel()
	c, err := dialCarrierCLI(ctx, *stateDir, version, "homeway-socks")
	if err != nil {
		return err
	}
	defer c.Close()
	hosts, err := hostsOnConn(ctx, c)
	if err != nil {
		return err
	}
	raw, err := c.Request(ctx, facade.OpSocksStatus, nil)
	if err != nil {
		return carrierOpErr("socks.status", err)
	}
	var res control.SocksStatusResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return fmt.Errorf("socks.status 载荷解析失败：%w", err)
	}
	linkOf := func(hexID string) (via string, rtt int64, ok bool) {
		for _, h := range hosts {
			if h.ID == hexID && h.Link != nil {
				return h.Link.Via, h.Link.RttMs, true
			}
		}
		return "", 0, false
	}
	if *jsonOut {
		out := make([]map[string]any, 0, len(res.Socks))
		for _, s := range res.Socks {
			m := map[string]any{
				"host": s.Host, "name": nameOfHost(hosts, s.Host),
				"on": s.On, "listen": s.Listen, "conns": s.Conns,
			}
			if s.Err != "" {
				m["err"] = s.Err
			}
			if via, rtt, ok := linkOf(s.Host); ok {
				m["via"], m["rttMs"] = via, rtt
			}
			out = append(out, m)
		}
		b, err := json.Marshal(out)
		if err != nil {
			return err
		}
		fmt.Fprintln(w, string(b))
		return nil
	}
	if len(res.Socks) == 0 {
		fmt.Fprintln(w, "无 socks 记录（homeway socks on --host <ref> 开启）")
		return nil
	}
	fmt.Fprintf(w, "%-12s %-4s %-7s %-6s %-18s %s\n", "主机", "开关", "端口", "连接", "链路", "备注")
	for _, s := range res.Socks {
		on := "off"
		if s.On {
			on = "on"
		}
		link := "-"
		if via, rtt, ok := linkOf(s.Host); ok {
			link = fmt.Sprintf("%s %dms", via, rtt)
		}
		fmt.Fprintf(w, "%-12s %-4s %-7d %-6d %-18s %s\n",
			truncRunes(nameOfHost(hosts, s.Host), 12), on, s.Listen, s.Conns, link, truncRunes(s.Err, 30))
	}
	return nil
}
