package daemon

// forward_cli.go — homeway forward add/list/delete（forward-socks-speedtest 3e §3.2，
// spec forward-socks-cli）：桌面 daemon 侧端口转发规则的用户入口。命令归属 =
// 守护托管（规则/监听器由 daemon 持有，CLI 是薄前端；daemon 未跑 = 可行动错误）。
// --state 恒指 daemon state（三面均无本地面、无双面指代）；--host 寻址与 host
// delete/status 同一份 resolveHostTarget（同规则同文案）。
//
// 错误文案是 CLI 侧映射（不进契约）：bad_request 的冲突/占用细节由 CLI 复查
// forward.list + socks.status 现场拼出占用方（错误码面上只有稳定码）。

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/facade"
	"github.com/zhaoyswd/homeway/internal/control"
)

// carrierFlagBools forward/socks/speedtest 命令面的布尔 flag 集（flagsFirst 用）。
var carrierFlagBools = map[string]bool{
	"json": true, "quiet": true, "help": true, "h": true,
}

// dialCarrierCLI 连 control.sock（承载面命令共用的前端标识）。
func dialCarrierCLI(ctx context.Context, stateDir, version, name string) (*control.Client, error) {
	sock := filepath.Join(stateDir, control.ControlSockName)
	c, _, err := control.Dial(ctx, sock, control.FrontendInfo{Kind: "cli", Name: name, Version: version})
	if err != nil {
		return nil, controlDialErr(stateDir, sock, err)
	}
	return c, nil
}

// hostsOnConn 经已建连接拉主机表（寻址/名称映射/链路态标签共用）。
func hostsOnConn(ctx context.Context, c *control.Client) ([]control.HostState, error) {
	raw, err := c.Request(ctx, facade.OpDaemonStatus, nil)
	if err != nil {
		return nil, fmt.Errorf("daemon.status 失败：%w", err)
	}
	var st control.DaemonStatusResult
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("daemon.status 载荷解析失败：%w", err)
	}
	return st.Hosts, nil
}

// nameOfHost hex → 显示名（无名的用短 id；表外 = 短 id）。
func nameOfHost(hosts []control.HostState, hexID string) string {
	for _, h := range hosts {
		if h.ID == hexID {
			if h.Name != "" {
				return h.Name
			}
			return shortHostID(hexID)
		}
	}
	return shortHostID(hexID)
}

// carrierOpErr 控制面错误码 → 可行动文案（三命令面共用）。
func carrierOpErr(op string, err error) error {
	var code control.CodeError
	if errors.As(err, &code) {
		switch string(code) {
		case facade.CodeNoHost:
			return errors.New("主机不在守护进程表中（no_host）；homeway host list 查看在表主机")
		case facade.CodeNotReady:
			return errors.New("守护进程注册表未就绪（not_ready；client 角色启动中/重建窗口），稍后重试")
		case facade.CodeUnknownOp:
			return fmt.Errorf("%s 得 unknown_op——守护进程代际过旧（无承载面 op），请同批升级 daemon 后重试", op)
		}
	}
	return fmt.Errorf("%s 失败：%w", op, err)
}

// forwardCLI forward 子命令入口（cmd/homeway 转发；输出写 w 便于测试）。
func forwardCLI(args []string, version string, w io.Writer) error {
	if len(args) == 0 {
		usageForward(w)
		return errors.New("forward 需要子命令：add / list / delete")
	}
	switch args[0] {
	case "add":
		return forwardAddCLI(args[1:], version, w)
	case "list":
		return forwardListCLI(args[1:], version, w)
	case "delete":
		return forwardDeleteCLI(args[1:], version, w)
	}
	usageForward(w)
	return fmt.Errorf("forward 不认识的子命令 %q（可用：add / list / delete）", args[0])
}

func usageForward(w io.Writer) {
	fmt.Fprint(w, `用法：
  homeway forward add --host <ref> --listen <P> [--target <ip:P>|:<P>]
                     建规则并立即起监听（127.0.0.1:P；目标缺省 = 该主机出口自己同端口）
  homeway forward list [--host <ref>] [--json]
                     规则表 + 运行态（listening/failed/在世连接数）
  homeway forward delete --host <ref> --listen <P>
                     删规则并关监听（在世连接不强关、自然收口）
全部子命令可加 --state DIR（恒指 daemon state，默认 ~/.config/homeway/daemon）与 --timeout。
监听端口 1024–65535、每主机 ≤8 条、与全部规则及 socks 监听全局唯一。
`)
}

// parseForwardTarget --target 形态：<空> = 出口自己同端口；":P" = 出口自己指定端口；
// "ip:P" = 任意 IPv4 目标。
func parseForwardTarget(s string) (ip string, port uint16, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, nil
	}
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return "", 0, fmt.Errorf("--target %q 须为 <ip:port> 或 :<port>（目标缺省 = 出口自己同端口）", s)
	}
	if i == 0 { // ":P"
		p, perr := strconv.ParseUint(s[1:], 10, 16)
		if perr != nil {
			return "", 0, fmt.Errorf("--target 端口 %q 非法：%v", s[1:], perr)
		}
		return "", uint16(p), nil
	}
	ip = s[:i]
	if net.ParseIP(ip) == nil || !isIPv4Literal(ip) {
		return "", 0, fmt.Errorf("--target 目标 %q 须为 IPv4 字面量（隧道只承载 IPv4）", ip)
	}
	p, perr := strconv.ParseUint(s[i+1:], 10, 16)
	if perr != nil {
		return "", 0, fmt.Errorf("--target 端口 %q 非法：%v", s[i+1:], perr)
	}
	return ip, uint16(p), nil
}

// isIPv4Literal IPv4 字面量判定（net.ParseIP 接受 v6——目标值域只要 v4）。
func isIPv4Literal(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return false // v6 形态
		}
	}
	return net.ParseIP(s) != nil
}

// forwardAddCLI add --host <ref> --listen <P> [--target …]。
func forwardAddCLI(args []string, version string, w io.Writer) error {
	fs := flag.NewFlagSet("homeway forward add", flag.ContinueOnError)
	fs.SetOutput(w)
	stateDir := fs.String("state", DefaultStateDir(), "守护进程 state 目录（从中找 control.sock）")
	hostRef := fs.String("host", "", "主机（名称/完整 ID/无歧义短前缀，同 host delete）")
	listen := fs.Uint("listen", 0, "本机回环监听端口（1024–65535）")
	target := fs.String("target", "", "目标：<ip:port>（出口可达的任意 IPv4）| :<port>（出口自己指定端口）| 缺省 = 出口自己同端口")
	timeout := fs.Duration("timeout", 10*time.Second, "连接与请求的总预算")
	if err := fs.Parse(flagsFirst(args, carrierFlagBools)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("forward add 不接受位置参数（got %q）", fs.Args())
	}
	if strings.TrimSpace(*hostRef) == "" {
		return errors.New("forward add 需要 --host <ref>（homeway host list 查看在表主机）")
	}
	if *listen == 0 {
		return errors.New("forward add 需要 --listen <端口>（1024–65535）")
	}
	if *listen < 1024 || *listen > 65535 {
		return fmt.Errorf("--listen %d 越界（监听端口须在 1024–65535）", *listen)
	}
	targetIP, targetPort, err := parseForwardTarget(*target)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	c, err := dialCarrierCLI(ctx, *stateDir, version, "homeway-forward")
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

	a := control.ForwardAddArgs{Host: id, Listen: uint16(*listen), TargetIP: targetIP, TargetPort: targetPort}
	raw, err := c.Request(ctx, facade.OpForwardAdd, a)
	if err != nil {
		return forwardAddErr(ctx, c, hosts, a, err)
	}
	var res control.ForwardAddResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return fmt.Errorf("forward.add 载荷解析失败：%w", err)
	}
	fmt.Fprintf(w, "已建转发 %s 127.0.0.1:%d → %s（%s，目标经 %s 出网）\n",
		dname, res.Rule.Listen, describeForwardTarget(targetIP, targetPort, uint16(*listen)), res.Rule.State, dname)
	return nil
}

// describeForwardTarget 目标文案（与手机口径一致的两形态）。
func describeForwardTarget(ip string, port, listen uint16) string {
	if ip == "" {
		if port == 0 {
			return "出口自己（同端口）"
		}
		return fmt.Sprintf("出口自己:%d", port)
	}
	if port == 0 {
		port = listen
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

// forwardAddErr bad_request 的现场诊断：复查 forward.list + socks.status 找占用方
// （文案指明全局唯一与占用者）；两表都无 → 本机探听（守护外进程占用）；再无 → 通用。
func forwardAddErr(ctx context.Context, c *control.Client, hosts []control.HostState, a control.ForwardAddArgs, err error) error {
	var code control.CodeError
	if !errors.As(err, &code) || string(code) != facade.CodeBadRequest {
		return carrierOpErr("forward.add", err)
	}
	if owner, found := findPortOwner(ctx, c, hosts, a.Listen); found {
		return fmt.Errorf("监听端口 %d 已被 %s 占用（forward/socks 全局唯一，非每主机）——可用 --listen 另选", a.Listen, owner)
	}
	// 守护进程外占用探测：短暂在本机回环试听同端口（立即关闭；不做任何物理接口监听）。
	if ln, lerr := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", a.Listen)); lerr != nil {
		return fmt.Errorf("监听 127.0.0.1:%d 失败（bad_request；端口像是被守护进程外的本机进程占用：%v）——换端口或释放后重试，规则未入表", a.Listen, lerr)
	} else {
		_ = ln.Close()
	}
	return errors.New("forward.add 被拒（bad_request；参数值域/监听失败）——核对 --listen（1024–65535，全局唯一）与 --target 形态后重试")
}

// findPortOwner 端口占用方现场复查（forward.list + socks.status；文案含主机名）。
func findPortOwner(ctx context.Context, c *control.Client, hosts []control.HostState, port uint16) (string, bool) {
	if raw, err := c.Request(ctx, facade.OpForwardList, control.ForwardListArgs{}); err == nil {
		var lst control.ForwardListResult
		if json.Unmarshal(raw, &lst) == nil {
			for _, r := range lst.Forwards {
				if r.Listen == port {
					return nameOfHost(hosts, r.Host) + " 的 forward 规则", true
				}
			}
		}
	}
	if raw, err := c.Request(ctx, facade.OpSocksStatus, nil); err == nil {
		var st control.SocksStatusResult
		if json.Unmarshal(raw, &st) == nil {
			for _, s := range st.Socks {
				if s.On && s.Listen == port {
					return nameOfHost(hosts, s.Host) + " 的 socks 监听", true
				}
			}
		}
	}
	return "", false
}

// forwardListCLI list [--host <ref>] [--json]。
func forwardListCLI(args []string, version string, w io.Writer) error {
	fs := flag.NewFlagSet("homeway forward list", flag.ContinueOnError)
	fs.SetOutput(w)
	stateDir := fs.String("state", DefaultStateDir(), "守护进程 state 目录（从中找 control.sock）")
	hostRef := fs.String("host", "", "只列该主机（名称/完整 ID/无歧义短前缀）")
	jsonOut := fs.Bool("json", false, "机器可读 JSON（规则对象数组，stdout 一行）")
	timeout := fs.Duration("timeout", 5*time.Second, "连接与请求的总预算")
	if err := fs.Parse(flagsFirst(args, carrierFlagBools)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("forward list 不接受位置参数（got %q）", fs.Args())
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	c, err := dialCarrierCLI(ctx, *stateDir, version, "homeway-forward")
	if err != nil {
		return err
	}
	defer c.Close()
	hosts, err := hostsOnConn(ctx, c)
	if err != nil {
		return err
	}
	req := control.ForwardListArgs{}
	if strings.TrimSpace(*hostRef) != "" {
		id, _, rerr := resolveHostTarget(hosts, strings.TrimSpace(*hostRef))
		if rerr != nil {
			return rerr
		}
		req.Host = id
	}
	raw, err := c.Request(ctx, facade.OpForwardList, req)
	if err != nil {
		return carrierOpErr("forward.list", err)
	}
	var res control.ForwardListResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return fmt.Errorf("forward.list 载荷解析失败：%w", err)
	}
	if *jsonOut {
		out := make([]map[string]any, 0, len(res.Forwards))
		for _, r := range res.Forwards {
			out = append(out, map[string]any{
				"host": r.Host, "name": nameOfHost(hosts, r.Host),
				"listen": r.Listen, "targetIp": r.TargetIP, "targetPort": r.TargetPort,
				"state": r.State, "err": r.Err, "conns": r.Conns,
			})
		}
		b, err := json.Marshal(out)
		if err != nil {
			return err
		}
		fmt.Fprintln(w, string(b))
		return nil
	}
	if len(res.Forwards) == 0 {
		fmt.Fprintln(w, "无转发规则（homeway forward add --host <ref> --listen <P> 添加）")
		return nil
	}
	fmt.Fprintf(w, "%-12s %-7s %-24s %-10s %-6s %s\n", "主机", "监听", "目标", "状态", "连接", "错误")
	for _, r := range res.Forwards {
		st, conns, e := r.State, strconv.Itoa(r.Conns), ""
		if r.Err != "" {
			e = truncRunes(r.Err, 40)
		}
		fmt.Fprintf(w, "%-12s %-7d %-24s %-10s %-6s %s\n",
			truncRunes(nameOfHost(hosts, r.Host), 12), r.Listen,
			truncRunes(describeForwardTarget(r.TargetIP, r.TargetPort, r.Listen), 24),
			st, conns, e)
	}
	return nil
}

// forwardDeleteCLI delete --host <ref> --listen <P>。
func forwardDeleteCLI(args []string, version string, w io.Writer) error {
	fs := flag.NewFlagSet("homeway forward delete", flag.ContinueOnError)
	fs.SetOutput(w)
	stateDir := fs.String("state", DefaultStateDir(), "守护进程 state 目录（从中找 control.sock）")
	hostRef := fs.String("host", "", "主机（名称/完整 ID/无歧义短前缀，同 host delete）")
	listen := fs.Uint("listen", 0, "要删的监听端口")
	timeout := fs.Duration("timeout", 5*time.Second, "连接与请求的总预算")
	if err := fs.Parse(flagsFirst(args, carrierFlagBools)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("forward delete 不接受位置参数（got %q）", fs.Args())
	}
	if strings.TrimSpace(*hostRef) == "" {
		return errors.New("forward delete 需要 --host <ref>（homeway forward list 查看）")
	}
	if *listen == 0 {
		return errors.New("forward delete 需要 --listen <端口>（homeway forward list 查看）")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	c, err := dialCarrierCLI(ctx, *stateDir, version, "homeway-forward")
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
	if _, err := c.Request(ctx, facade.OpForwardRemove, control.ForwardRemoveArgs{Host: id, Listen: uint16(*listen)}); err != nil {
		var code control.CodeError
		if errors.As(err, &code) && string(code) == facade.CodeBadRequest {
			// 规则不存在 vs 其它 bad_request：复查规则表现场区分（不存在报错非静默）。
			raw, lerr := c.Request(ctx, facade.OpForwardList, control.ForwardListArgs{Host: id})
			if lerr == nil {
				var lst control.ForwardListResult
				if json.Unmarshal(raw, &lst) == nil {
					for _, r := range lst.Forwards {
						if r.Listen == uint16(*listen) {
							return fmt.Errorf("forward.delete 被拒（bad_request；该条状态 %s err=%q）", r.State, r.Err)
						}
					}
				}
			}
			return fmt.Errorf("规则不存在：%s 127.0.0.1:%d（homeway forward list 查看）", dname, *listen)
		}
		return carrierOpErr("forward.remove", err)
	}
	fmt.Fprintf(w, "已删转发 %s 127.0.0.1:%d（在世连接不强关，自然收口）\n", dname, *listen)
	return nil
}
