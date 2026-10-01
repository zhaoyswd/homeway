package daemon

// servegroup_cli.go — `homeway serve|relay <动词>` 命令组（role-management tasks
// 3.2/3.3，RM「serve / relay 命令组」「角色生命周期语义表」）。两组对称：
//
//	serve start/stop/restart/status [--json]/token/relay set|clear/ddns add|delete|list
//	relay start/stop/restart/status [--json]/token
//
// 归属：start/stop/restart = 守护托管（start 含按需拉起）；status = 守护托管读面
// （未跑 = 降级直跑读 config 报期望态）；token = 直跑可降级（控制面优先，未跑走
// L2——serve 台账末行 / relay D8a 推算）；relay set/clear 与 ddns = 一次性直跑
// （纯文件操作，token 形态校验在 CLI 侧）。
//
// 提示口径（r1 中-10）：只有纯配置写命令（relay set/clear、ddns add/delete）在
// **进程在跑**时打「需 `homeway serve restart` 生效」；start/stop 输出动作结果与
// 幂等态、MUST NOT 打该提示（语义相反——start/stop 是角色生命周期命令、立即生效）。
//
// 未跑 = 进程未跑**或**角色未装配（r1 中-6 混合态同款降级）；restart 角色停时 =
// 可行动错误提示 `serve start`。纯读（status/token 未跑路径）不拉起。

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/facade"
	"github.com/zhaoyswd/homeway/internal/cliopts"
	"github.com/zhaoyswd/homeway/internal/control"
	"github.com/zhaoyswd/homeway/internal/nodeconfig"
	"github.com/zhaoyswd/homeway/internal/nodestate"
	"github.com/zhaoyswd/homeway/internal/relay"
	"github.com/zhaoyswd/homeway/internal/server"
)

// ServeGroupCLI `homeway serve <动词>` 命令组入口（cmd/homeway 转发；动词已剥离）。
func ServeGroupCLI(args []string, version string, w io.Writer) error {
	if len(args) == 0 {
		usageServeGroup(w)
		return errors.New("serve 需要动词：start / stop / restart / status / token / relay / ddns（无动词 = 前台单角色 `homeway serve [flags]`）")
	}
	switch args[0] {
	case "start":
		return roleStartCLI("serve", args[1:], version, w)
	case "stop":
		return roleStopCLI("serve", args[1:], version, w)
	case "restart":
		return roleRestartCLI("serve", args[1:], version, w)
	case "status":
		return serveStatusCLI(args[1:], version, w)
	case "token":
		return serveTokenCLI(args[1:], version, w)
	case "relay":
		return serveRelayCLI(args[1:], w)
	case "ddns":
		return serveDDNSCLI(args[1:], w)
	}
	usageServeGroup(w)
	return fmt.Errorf("serve 不认识的动词 %q（可用：start / stop / restart / status / token / relay / ddns）", args[0])
}

// RelayGroupCLI `homeway relay <动词>` 命令组入口（对称）。
func RelayGroupCLI(args []string, version string, w io.Writer) error {
	if len(args) == 0 {
		usageRelayGroup(w)
		return errors.New("relay 需要动词：start / stop / restart / status / token（无动词 = 前台单角色 `homeway relay [flags]`）")
	}
	switch args[0] {
	case "start":
		return roleStartCLI("relay", args[1:], version, w)
	case "stop":
		return roleStopCLI("relay", args[1:], version, w)
	case "restart":
		return roleRestartCLI("relay", args[1:], version, w)
	case "status":
		return relayStatusCLI(args[1:], version, w)
	case "token":
		return relayTokenCLI(args[1:], version, w)
	}
	usageRelayGroup(w)
	return fmt.Errorf("relay 不认识的动词 %q（可用：start / stop / restart / status / token）", args[0])
}

// ---- 公共 flag 面 ----

// groupFlags 组命令的公共 flag 集（--state/--no-spawn/--timeout；--json 仅 status
// 注册）。
type groupFlags struct {
	stateDir *string
	noSpawn  *bool
	timeout  *time.Duration
	jsonOut  *bool // nil = 本动词无 --json
}

func newGroupFlags(fs *flag.FlagSet, withJSON bool) *groupFlags {
	g := &groupFlags{
		stateDir: fs.String("state", DefaultStateDir(), "统一 state 根（config.toml + control.sock 所在）"),
		noSpawn:  fs.Bool("no-spawn", false, "守护进程未运行时不按需拉起（直接报可行动错误；脚本友好）"),
		timeout:  fs.Duration("timeout", 30*time.Second, "连接与请求预算（restart 要等旧角色收尾〔≤10s 宽限〕后重建，勿给太短）"),
	}
	if withJSON {
		g.jsonOut = fs.Bool("json", false, "机器可读 JSON（stdout 一行）")
	}
	return g
}

// dialGroup start 的拨号（前端标识按组名；经按需拉起的统一注入缝——start 是组
// 命令里唯一「未跑则拉起」的动词）。
func dialGroup(ctx context.Context, stateDir, version, name string) (*control.Client, error) {
	return dialControlSpawn(ctx, stateDir, version, "homeway-"+name)
}

// dialGroupRead 纯读/降级路径的拨号（status/token/stop/restart 预检）：不拉起——
// 未跑按各动词的降级面走（status 读 config、token 走 L2、stop 直改 config）。
func dialGroupRead(ctx context.Context, stateDir, version, name string) (*control.Client, error) {
	c, _, err := control.Dial(ctx, controlSockOf(stateDir), control.FrontendInfo{Kind: "cli", Name: "homeway-" + name, Version: version})
	if err != nil {
		return nil, controlDialErr(stateDir, controlSockOf(stateDir), err)
	}
	return c, nil
}

// ---- start / stop / restart（两角色对称） ----

func roleStartCLI(role string, args []string, version string, w io.Writer) error {
	fs := flag.NewFlagSet("homeway "+role+" start", flag.ContinueOnError)
	fs.SetOutput(w)
	g := newGroupFlags(fs, false)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%s start 不接受位置参数（got %q）", role, fs.Args())
	}
	// 不显式给 Out：拉起提示走默认（stderr）——stdout 留给命令输出/--json（FIX-48）。
	ctx, cancel := context.WithTimeout(cliopts.With(context.Background(), cliopts.Opts{NoSpawn: *g.noSpawn}), *g.timeout)
	defer cancel()

	// 未跑：CLI 直改 config（enabled=true）再拉起——进程起来按期望态装配（D3：
	// 进程在跑时改写只经控制面〔进程内写〕，CLI 直改文件只在未跑时发生）。
	// 「未运行判定 + 启动窗口等待」走唯一注入缝 probeControl（FIX-49：此前这里裸拨
	// 一份，两个 CLI 同时冷启动时缺启动窗口的等待，会立刻误报不可达）。
	sock := controlSockOf(*g.stateDir)
	c, perr := probeControl(ctx, *g.stateDir, version, "homeway-"+role)
	if perr != nil {
		return perr
	}
	if c != nil {
		defer c.Close()
		return serveStartViaControl(ctx, c, role, w)
	}
	if *g.noSpawn {
		return fmt.Errorf("守护进程未运行且 --no-spawn 已给定（不拉起）\nsock=%s\n先手动启动：homeway --state %s", sock, *g.stateDir)
	}
	if err := nodeconfig.Update(nodeconfig.Path(*g.stateDir), func(c *nodeconfig.Config) error {
		if role == "serve" {
			c.Serve.Enabled = true
		} else {
			c.Relay.Enabled = true
		}
		return nil
	}); err != nil {
		return err // 坏 config 拒写不覆盖（r1 中-14）
	}
	if err := ensureRunning(*g.stateDir, w); err != nil {
		return err
	}
	fmt.Fprintf(w, "%s：期望已写为启用（config %s.enabled=true），统一进程按期望态装配\n", role, role)
	return nil
}

// serveStartViaControl 进程在跑：经控制面（进程内写 config + 装配角色；幂等语义
// 在成功载荷呈现）。
func serveStartViaControl(ctx context.Context, c *control.Client, role string, w io.Writer) error {
	opStart := facade.OpServeStart
	if role == "relay" {
		opStart = facade.OpRelayStart
	}
	raw, err := c.Request(ctx, opStart, nil)
	if err != nil {
		return opErr(err, role+" start")
	}
	var res control.RoleActionResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return fmt.Errorf("%s.start 载荷解析失败：%w", role, err)
	}
	if res.Action == "started" {
		fmt.Fprintf(w, "%s：已启动（config %s.enabled=true + 角色装配完成）\n", role, role)
	} else {
		fmt.Fprintf(w, "%s：已在运行（幂等，无动作）\n", role)
	}
	return nil
}

func roleStopCLI(role string, args []string, version string, w io.Writer) error {
	fs := flag.NewFlagSet("homeway "+role+" stop", flag.ContinueOnError)
	fs.SetOutput(w)
	g := newGroupFlags(fs, false)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%s stop 不接受位置参数（got %q）", role, fs.Args())
	}
	ctx, cancel := context.WithTimeout(context.Background(), *g.timeout)
	defer cancel()
	// stop 不拉起（进程未跑 = 直改 config 即达期望态；拉一个进程只为停它本末倒置）。
	// 先裸拨判在跑（不经拉起缝；dialGroupRead 的包装错误会丢原始 dial 错的分类位）。
	sock := controlSockOf(*g.stateDir)
	if c, _, derr := control.Dial(ctx, sock, control.FrontendInfo{Kind: "cli", Name: "homeway-" + role, Version: version}); derr == nil {
		defer c.Close()
		opStop := facade.OpServeStop
		if role == "relay" {
			opStop = facade.OpRelayStop
		}
		raw, rerr := c.Request(ctx, opStop, nil)
		if rerr != nil {
			return opErr(rerr, role+" stop")
		}
		var res control.RoleActionResult
		if err := json.Unmarshal(raw, &res); err != nil {
			return fmt.Errorf("%s.stop 载荷解析失败：%w", role, err)
		}
		if res.Action == "already" {
			fmt.Fprintf(w, "%s：已停（幂等，无动作）\n", role)
			return nil
		}
		// stop = 改期望态 + 取消 ctx 后立即应答；收尾异步（stopping 相位），宽限内
		// 存量隧道连接还能通最多 10s——显式语义（D5/r1 中-5），MUST NOT 打「需 restart」。
		fmt.Fprintf(w, "%s：停止已应答（config %s.enabled=false；收尾进行中——存量过境连接宽限至多 10s 后收口，`%s status` 可看相位）\n", role, role, role)
		return nil
	} else if !notRunningDial(derr, *g.stateDir) {
		return controlDialErr(*g.stateDir, sock, derr)
	}
	if err := nodeconfig.Update(nodeconfig.Path(*g.stateDir), func(c *nodeconfig.Config) error {
		if role == "serve" {
			c.Serve.Enabled = false
		} else {
			c.Relay.Enabled = false
		}
		return nil
	}); err != nil {
		return err
	}
	fmt.Fprintf(w, "%s：进程未运行——期望已写为停用（config %s.enabled=false），下次启动不再装配\n", role, role)
	return nil
}

func roleRestartCLI(role string, args []string, version string, w io.Writer) error {
	fs := flag.NewFlagSet("homeway "+role+" restart", flag.ContinueOnError)
	fs.SetOutput(w)
	g := newGroupFlags(fs, false)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%s restart 不接受位置参数（got %q）", role, fs.Args())
	}
	ctx, cancel := context.WithTimeout(context.Background(), *g.timeout)
	defer cancel()
	// restart 允许 running 与 failed（failed = 跳过剩余退避立即重建）；进程未跑 /
	// 角色未装配（stopped/absent）报可行动错误（r1 中-6）：语义 = 先 start。
	// status 预检（纯读，未跑面降级读 config 给出期望态）。
	raw, running := groupStatus(ctx, role, *g.stateDir, version)
	state := ""
	if running {
		state = roleRunState(role, raw)
	}
	if !running || (state != roleStateRunning && state != roleStateFailed) {
		phrase := "进程未运行"
		if running {
			phrase = roleStatePhrase(role, raw)
		}
		return fmt.Errorf("%s 未在运行（%s）——restart 无重建对象；先 homeway %s start", role, phrase, role)
	}
	c, err := dialGroupRead(ctx, *g.stateDir, version, role)
	if err != nil {
		return err
	}
	defer c.Close()
	opRestart := facade.OpServeRestart
	if role == "relay" {
		opRestart = facade.OpRelayRestart
	}
	rres, rerr := c.Request(ctx, opRestart, nil)
	if rerr != nil {
		return opErr(rerr, role+" restart")
	}
	var res control.RoleActionResult
	if err := json.Unmarshal(rres, &res); err != nil {
		return fmt.Errorf("%s.restart 载荷解析失败：%w", role, err)
	}
	fmt.Fprintf(w, "%s：重启完成（等旧角色收尾后同路径重建；期望态不变）\n", role)
	return nil
}

// opErr 控制面错误 → 可行动文案（unknown_op = 旧 daemon 锁步断点，spec 既有口径）。
func opErr(err error, what string) error {
	var code control.CodeError
	if errors.As(err, &code) && string(code) == facade.CodeUnknownOp {
		return fmt.Errorf("%s 失败：守护进程代际过旧（不识该 op）——请同批升级 homeway（unknown_op）", what)
	}
	return fmt.Errorf("%s 失败：%w", what, err)
}

// ---- status（两角色；未跑降级读 config） ----

// groupStatus 拉一份组 status（进程未跑 = running=false；降级面由调用方读 config）。
func groupStatus(ctx context.Context, role, stateDir, version string) (json.RawMessage, bool) {
	c, err := dialGroupRead(ctx, stateDir, version, role)
	if err != nil {
		return nil, false
	}
	defer c.Close()
	opStatus := facade.OpServeStatus
	if role == "relay" {
		opStatus = facade.OpRelayStatus
	}
	raw, err := c.Request(ctx, opStatus, nil)
	if err != nil {
		return nil, false // 理论不可达（dial 已过）；防御按未跑降级
	}
	return raw, true
}

// roleRunState 从 status 载荷取运行态字段。
func roleRunState(role string, raw json.RawMessage) string {
	if role == "serve" {
		var st control.ServeStatusResult
		if json.Unmarshal(raw, &st) == nil {
			return st.State
		}
		return ""
	}
	var st control.RelayStatusResult
	if json.Unmarshal(raw, &st) == nil {
		return st.State
	}
	return ""
}

// roleStatePhrase 语义表口径的相位短语（restart 预检与 status 输出共用）。
func roleStatePhrase(role string, raw json.RawMessage) string {
	if role == "serve" {
		var st control.ServeStatusResult
		if json.Unmarshal(raw, &st) != nil {
			return "状态面解析失败"
		}
		if !st.Enabled && (st.State == "stopped" || st.State == "absent") {
			return "期望停用（进程在跑）"
		}
		switch st.State {
		case "stopping":
			return "停止中（stopping——收尾进行中）"
		case "failed":
			return "failed（重建退避中）" + reasonSuffix(st.Reason)
		case "absent":
			return "未装配"
		}
		return "运行中" + reasonSuffix(st.Reason)
	}
	var st control.RelayStatusResult
	if json.Unmarshal(raw, &st) != nil {
		return "状态面解析失败"
	}
	if !st.Enabled && (st.State == "stopped" || st.State == "absent") {
		return "期望停用（进程在跑）"
	}
	switch st.State {
	case "stopping":
		return "停止中（stopping——收尾进行中）"
	case "failed":
		return "failed（重建退避中）" + reasonSuffix(st.Reason)
	case "absent":
		return "未装配"
	}
	return "运行中" + reasonSuffix(st.Reason)
}

func reasonSuffix(reason string) string {
	if reason == "" {
		return ""
	}
	return "：" + reason
}

// degradedRoleStatus 未跑降级面：读 config 组期望态（status 直跑读面的底座）。
type degradedRoleStatus struct {
	Enabled bool   `json:"enabled"`
	State   string `json:"state"` // 期望启用（未运行） | 期望停用
	Listen  string `json:"listen,omitempty"`
}

func degradedServe(stateDir string) degradedRoleStatus {
	cfg, err := nodeconfig.Load(nodeconfig.Path(stateDir))
	if err != nil {
		return degradedRoleStatus{State: "config 读取失败：" + err.Error()}
	}
	st := degradedRoleStatus{Enabled: cfg.Serve.Enabled, Listen: fmt.Sprintf(":%d（config）", cfg.Serve.Listen)}
	if cfg.Serve.Enabled {
		st.State = "期望启用（未运行）"
	} else {
		st.State = "期望停用"
	}
	return st
}

func degradedRelay(stateDir string) degradedRoleStatus {
	cfg, err := nodeconfig.Load(nodeconfig.Path(stateDir))
	if err != nil {
		return degradedRoleStatus{State: "config 读取失败：" + err.Error()}
	}
	st := degradedRoleStatus{Enabled: cfg.Relay.Enabled, Listen: cfg.Relay.Listen + "（config）"}
	if cfg.Relay.Enabled {
		st.State = "期望启用（未运行）"
	} else {
		st.State = "期望停用"
	}
	return st
}

func serveStatusCLI(args []string, version string, w io.Writer) error {
	fs := flag.NewFlagSet("homeway serve status", flag.ContinueOnError)
	fs.SetOutput(w)
	g := newGroupFlags(fs, true)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *g.timeout)
	defer cancel()
	raw, running := groupStatus(ctx, "serve", *g.stateDir, version)
	if !running {
		d := degradedServe(*g.stateDir)
		if *g.jsonOut {
			b, _ := json.Marshal(d)
			fmt.Fprintln(w, string(b))
		} else {
			fmt.Fprintf(w, "homeway serve：%s\n  期望：%v\n  监听：%s\n  说明：进程未运行，读 config 期望态（纯读不拉起）\n", d.State, d.Enabled, d.Listen)
		}
		return nil
	}
	if *g.jsonOut {
		fmt.Fprintln(w, string(raw))
		return nil
	}
	var st control.ServeStatusResult
	if err := json.Unmarshal(raw, &st); err != nil {
		return fmt.Errorf("serve.status 载荷解析失败：%w", err)
	}
	fmt.Fprintf(w, "homeway serve：%s\n", roleStatePhrase("serve", raw))
	fmt.Fprintf(w, "  期望：%v\n", st.Enabled)
	if st.ListenPort != 0 {
		fmt.Fprintf(w, "  监听：%d（实际口）\n", st.ListenPort)
	}
	if len(st.Published) > 0 {
		fmt.Fprintf(w, "  公布端点：%s\n", strings.Join(st.Published, "、"))
	}
	if len(st.Endpoints) > 0 {
		fmt.Fprintf(w, "  token 端点：%s\n", strings.Join(st.Endpoints, "、"))
	}
	if st.TokenMask != "" {
		fmt.Fprintf(w, "  token：%s（完整凭证经 `homeway serve token`）\n", st.TokenMask)
	}
	if len(st.DDNS) > 0 {
		fmt.Fprint(w, "  ddns：\n")
		for _, d := range st.DDNS {
			line := fmt.Sprintf("    - %s（连续不一致 %d 拍）", d.Domain, d.LagStreak)
			if d.WarnedLag {
				line += " 已告警滞后"
			}
			if d.WarnedAAAA {
				line += " 已告警缺 AAAA"
			}
			fmt.Fprintln(w, line)
		}
	}
	if len(st.Peers) > 0 {
		fmt.Fprintf(w, "  APP 设备：%d 台\n", len(st.Peers))
		for _, p := range st.Peers {
			fmt.Fprintf(w, "    - %s（隧道 %s，最近注册 %ds 前）\n", p.Dev, p.TunnelIP, p.IdleMs/1000)
		}
	}
	fmt.Fprintf(w, "  过境拦截：dialok=%d dialfail=%d 拒载=%d 会话=%d\n",
		st.Intercept.DialOK, st.Intercept.DialFail, st.Intercept.Reject, st.Intercept.Flows)
	return nil
}

func relayStatusCLI(args []string, version string, w io.Writer) error {
	fs := flag.NewFlagSet("homeway relay status", flag.ContinueOnError)
	fs.SetOutput(w)
	g := newGroupFlags(fs, true)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *g.timeout)
	defer cancel()
	raw, running := groupStatus(ctx, "relay", *g.stateDir, version)
	if !running {
		d := degradedRelay(*g.stateDir)
		if *g.jsonOut {
			b, _ := json.Marshal(d)
			fmt.Fprintln(w, string(b))
		} else {
			fmt.Fprintf(w, "homeway relay：%s\n  期望：%v\n  监听：%s\n  说明：进程未运行，读 config 期望态（纯读不拉起）\n", d.State, d.Enabled, d.Listen)
		}
		return nil
	}
	if *g.jsonOut {
		fmt.Fprintln(w, string(raw))
		return nil
	}
	var st control.RelayStatusResult
	if err := json.Unmarshal(raw, &st); err != nil {
		return fmt.Errorf("relay.status 载荷解析失败：%w", err)
	}
	fmt.Fprintf(w, "homeway relay：%s\n", roleStatePhrase("relay", raw))
	fmt.Fprintf(w, "  期望：%v\n", st.Enabled)
	if st.Listen != "" {
		fmt.Fprintf(w, "  监听：%s（实际）\n", st.Listen)
	}
	if st.Advertise != "" {
		fmt.Fprintf(w, "  公布：%s（config）\n", st.Advertise)
	}
	if st.TokenMask != "" {
		fmt.Fprintf(w, "  token：%s（完整凭证经 `homeway relay token`）\n", st.TokenMask)
	}
	fmt.Fprintf(w, "  开放注册：%v  分配会话：%d\n", st.Open, st.Assocs)
	if len(st.Backends) > 0 {
		fmt.Fprintf(w, "  注册出口：%d 台（中继看不到 APP——手机流量在 WG 密文里）\n", len(st.Backends))
		for _, b := range st.Backends {
			line := fmt.Sprintf("    - %s", b.Label)
			if b.Addr != "" {
				line += "（" + b.Addr + "）"
			}
			if b.LastActive > 0 {
				line += fmt.Sprintf(" 最近活跃 %ds 前", max(1, int(time.Since(time.UnixMilli(b.LastActive)).Seconds())))
			}
			if b.Verified {
				line += " UDP✓"
			}
			if b.CtlVerified {
				line += " 控制✓"
			}
			if b.HasCtl {
				line += " 控制通道在世"
			}
			fmt.Fprintln(w, line)
		}
	}
	return nil
}

// ---- token（双路径：控制面优先 / 未跑 L2 直读） ----

func serveTokenCLI(args []string, version string, w io.Writer) error {
	fs := flag.NewFlagSet("homeway serve token", flag.ContinueOnError)
	fs.SetOutput(w)
	g := newGroupFlags(fs, false)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *g.timeout)
	defer cancel()
	// 纯读不拉起：在跑走控制面；未跑直读台账末行（台账写入纪律下末行 = 最近在用
	// token——两源同源，spec 场景「token 双路径一致」）。
	if c, err := dialGroupRead(ctx, *g.stateDir, version, "serve"); err == nil {
		defer c.Close()
		raw, rerr := c.Request(ctx, facade.OpServeToken, nil)
		if rerr != nil {
			return opErr(rerr, "serve token")
		}
		var res control.ServeTokenResult
		if err := json.Unmarshal(raw, &res); err != nil {
			return fmt.Errorf("serve.token 载荷解析失败：%w", err)
		}
		printTokenReveal(w, "serve", res.Token, res.Source, res.Eps)
		warnNoEndpoints(w, res.Source, res.Eps)
		return nil
	}
	tok, eps, ok, err := server.RevealLastToken(nodestate.ServeDir(*g.stateDir))
	if err != nil {
		return fmt.Errorf("读 token 台账失败：%w", err)
	}
	if !ok {
		return errors.New("台账为空（serve 从未铸出 token）：先启动 `homeway serve start`，等首轮端点探测后重试")
	}
	printTokenReveal(w, "serve", tok, "ledger", eps)
	warnNoEndpoints(w, "ledger", eps)
	return nil
}

func relayTokenCLI(args []string, version string, w io.Writer) error {
	fs := flag.NewFlagSet("homeway relay token", flag.ContinueOnError)
	fs.SetOutput(w)
	g := newGroupFlags(fs, false)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *g.timeout)
	defer cancel()
	if c, err := dialGroupRead(ctx, *g.stateDir, version, "relay"); err == nil {
		defer c.Close()
		raw, rerr := c.Request(ctx, facade.OpRelayToken, nil)
		if rerr != nil {
			return opErr(rerr, "relay token")
		}
		var res control.RelayTokenResult
		if err := json.Unmarshal(raw, &res); err != nil {
			return fmt.Errorf("relay.token 载荷解析失败：%w", err)
		}
		printTokenReveal(w, "relay", res.Token, res.Source, res.Eps)
		return nil
	}
	// 未跑 = D8a 离线推算（relay.key + config 的 listen/advertise；advertise 为空时
	// 复刻公网地址探测——推算值与本机当前网络状态绑定，与在跑值不一致以控制面为准）。
	tok, eps, err := deriveRelayTokenOffline(*g.stateDir)
	if err != nil {
		return err
	}
	printTokenReveal(w, "relay", tok, "derived", eps)
	fmt.Fprintln(w, "⚠️ 离线推算口径：进程未运行——由 relay.key + config 推算（advertise 为空时按本机当前网卡探测）；与在跑值不一致时以控制面为准")
	return nil
}

// deriveRelayTokenOffline D8a 推算的 CLI 侧直跑形态（与 roleOps.deriveRelayToken
// 同一规则——secret/config 同源、BuildToken 同一函数；固定 advertise 时跑/停两路径
// 逐字一致，r1 中-7 对拍判据）。
func deriveRelayTokenOffline(stateDir string) (string, []string, error) {
	cfg, err := nodeconfig.Load(nodeconfig.Path(stateDir))
	if err != nil {
		return "", nil, err
	}
	port, err := relay.ListenPortOf(cfg.Relay.Listen)
	if err != nil {
		return "", nil, fmt.Errorf("config relay.listen %q 无端口可推算：%w", cfg.Relay.Listen, err)
	}
	secret, ok, err := relay.ReadSecret(nodestate.RelayDir(stateDir))
	if err != nil {
		return "", nil, err
	}
	if !ok {
		return "", nil, errors.New("relay/relay.key 不存在——中继从未启动过则无钥可推算（先 homeway relay start）")
	}
	return relay.BuildToken(secret, cfg.Relay.Advertise, port)
}

// printTokenReveal reveal 输出（完整凭证只经本命令族——reveal 纪律）。来源注记区分
// 「角色未装配/进程未跑」（ledger）与「角色已装配、本轮 token 未铸出」（ledger-early，
// 启动早期窗口——exec-r1 低-5：旧合并注记与实情不符）。
func printTokenReveal(w io.Writer, role, token, source string, eps []string) {
	srcNote := map[string]string{
		"runtime":      "运行态真源（控制面）",
		"ledger":       "台账末行（进程未跑/角色未装配——写入纪律下末行 = 最近在用 token）",
		"ledger-early": "台账末行（角色已装配、本轮 token 未铸出——等首轮端点探测，约 15s）",
		"derived":      "离线推算（relay.key + config）",
	}[source]
	if srcNote == "" {
		srcNote = source
	}
	fmt.Fprintf(w, "%s token：%s\n来源：%s\n", role, token, srcNote)
	if len(eps) > 0 {
		fmt.Fprintf(w, "端点：%s\n", strings.Join(eps, "、"))
	}
}

// warnNoEndpoints 无端点 token 的可行动提示（exec-r1 低-5）：台账末行是 endpoints=null
// 的预热行时，这枚 token 连不上（没有可拨的端点）——提示稍后重试或看 events.log 的
// 「客户端 token」行（首轮铸出后 token 行自带端点）。
// exec-r2 N1 兜底门控：提示只对台账路径（ledger/ledger-early）成立——runtime 真源的
// 端点与 token 同快照（铸出前提 eps 非空），快照边界缺端点 ≠「token 无端点」，
// 不得按无端点告警（在跑稳态曾因此打出与事实相反的假告警）。
func warnNoEndpoints(w io.Writer, source string, eps []string) {
	if len(eps) == 0 && source != "runtime" {
		fmt.Fprintln(w, "⚠️ 该 token 无端点（serve 首轮端点尚未铸出——启动后约 15s 完成首轮公网探测）；稍后重试，或看 <state>/cache/events.log 的「客户端 token」行")
	}
}

// ---- serve relay set/clear 与 ddns（一次性直跑：纯文件操作） ----

func serveRelayCLI(args []string, w io.Writer) error {
	if len(args) == 0 {
		fmt.Fprintln(w, "用法：homeway serve relay set <token> [--stdin] | homeway serve relay clear")
		fmt.Fprintln(w, "（serve.relay = 本出口注册到哪个**上游中继**的 token；[relay] 节 = 本机当中继——同词根不同义）")
		return errors.New("serve relay 需要动词：set / clear")
	}
	switch args[0] {
	case "set":
		return serveRelaySetCLI(args[1:], w)
	case "clear":
		return serveRelayClearCLI(args[1:], w)
	}
	return fmt.Errorf("serve relay 不认识的动词 %q（可用：set / clear）", args[0])
}

// daemonRunning 进程在跑判定（提示行依据：在跑的纯配置写要打「需 restart 生效」；
// dial 短试 + lock 试探兜〔control.sock 消失但进程在收尾窗口〕）。
func daemonRunning(stateDir string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if c, _, err := control.Dial(ctx, controlSockOf(stateDir), control.FrontendInfo{Kind: "cli", Name: "homeway-serve", Version: "0"}); err == nil {
		c.Close()
		return true
	}
	return nodestate.LockHeld(stateDir)
}

func serveRelaySetCLI(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("homeway serve relay set", flag.ContinueOnError)
	fs.SetOutput(w)
	stateDir := fs.String("state", DefaultStateDir(), "统一 state 根（config.toml 所在）")
	stdin := fs.Bool("stdin", false, "从 stdin 读单行 token（缓解 shell history 落凭证；推荐姿势）")
	if err := fs.Parse(flagsFirst(args, map[string]bool{"stdin": true, "help": true, "h": true})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	token := ""
	if *stdin {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return fmt.Errorf("读 stdin 失败：%w", err)
		}
		token = strings.TrimSpace(line)
	} else {
		if fs.NArg() != 1 {
			return errors.New("serve relay set 需要 <token>（rl1… 或裸 IP:port）或 --stdin（从 stdin 读单行）")
		}
		token = strings.TrimSpace(fs.Arg(0))
	}
	if token == "" {
		return errors.New("token 为空（--stdin 读到空行）")
	}
	// CLI 侧形态校验（与 config 校验同口径：rl1 前缀必须可解码，否则裸 IP:port）。
	if err := nodeconfig.ValidateRelayArg(token); err != nil {
		return err
	}
	if err := nodeconfig.Update(nodeconfig.Path(*stateDir), func(c *nodeconfig.Config) error {
		c.Serve.Relay = token
		return nil
	}); err != nil {
		return err // 坏 config 拒写不覆盖（r1 中-14）
	}
	fmt.Fprintf(w, "serve.relay 已写入 config（%s，0600 原子写）\n", maskForHint(token))
	if daemonRunning(*stateDir) {
		fmt.Fprintln(w, "⚠️ 不热更：需 `homeway serve restart` 生效（重启后中继注册腿以新 token 注册）")
	}
	return nil
}

func serveRelayClearCLI(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("homeway serve relay clear", flag.ContinueOnError)
	fs.SetOutput(w)
	stateDir := fs.String("state", DefaultStateDir(), "统一 state 根（config.toml 所在）")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("serve relay clear 不接受位置参数（got %q）", fs.Args())
	}
	if err := nodeconfig.Update(nodeconfig.Path(*stateDir), func(c *nodeconfig.Config) error {
		c.Serve.Relay = ""
		return nil
	}); err != nil {
		return err
	}
	fmt.Fprintln(w, "serve.relay 已从 config 清除")
	if daemonRunning(*stateDir) {
		fmt.Fprintln(w, "⚠️ 不热更：需 `homeway serve restart` 生效（重启后不再注册中继）")
	}
	return nil
}

func serveDDNSCLI(args []string, w io.Writer) error {
	if len(args) == 0 {
		fmt.Fprintln(w, "用法：homeway serve ddns add <domain> | homeway serve ddns delete <domain> | homeway serve ddns list")
		return errors.New("serve ddns 需要动词：add / delete / list")
	}
	switch args[0] {
	case "add", "delete":
		return serveDDNSWriteCLI(args[0], args[1:], w)
	case "list":
		return serveDDNSListCLI(args[1:], w)
	}
	return fmt.Errorf("serve ddns 不认识的动词 %q（可用：add / delete / list）", args[0])
}

func serveDDNSWriteCLI(verb string, args []string, w io.Writer) error {
	fs := flag.NewFlagSet("homeway serve ddns "+verb, flag.ContinueOnError)
	fs.SetOutput(w)
	stateDir := fs.String("state", DefaultStateDir(), "统一 state 根（config.toml 所在）")
	if err := fs.Parse(flagsFirst(args, map[string]bool{"help": true, "h": true})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("serve ddns %s 需要 <domain>（裸域名）", verb)
	}
	domain := strings.TrimSpace(fs.Arg(0))
	absent := false
	if err := nodeconfig.Update(nodeconfig.Path(*stateDir), func(c *nodeconfig.Config) error {
		idx := -1
		for i, d := range c.Serve.DDNS {
			if d == domain {
				idx = i
				break
			}
		}
		if verb == "add" {
			if idx >= 0 {
				return fmt.Errorf("ddns 条目 %s 已在 config（不重复添加）", domain)
			}
			c.Serve.DDNS = append(c.Serve.DDNS, domain)
		} else if idx >= 0 {
			c.Serve.DDNS = append(c.Serve.DDNS[:idx], c.Serve.DDNS[idx+1:]...)
		} else {
			absent = true // delete 不存在条目：幂等成功（不报错）
		}
		return nil
	}); err != nil {
		return err
	}
	if verb == "add" {
		fmt.Fprintf(w, "ddns 条目 %s 已写入 config\n", domain)
	} else if absent {
		fmt.Fprintf(w, "ddns 条目 %s 不在 config（幂等，无动作）\n", domain)
	} else {
		fmt.Fprintf(w, "ddns 条目 %s 已从 config 删除\n", domain)
	}
	if daemonRunning(*stateDir) {
		fmt.Fprintln(w, "⚠️ 不热更：需 `homeway serve restart` 生效")
	}
	return nil
}

func serveDDNSListCLI(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("homeway serve ddns list", flag.ContinueOnError)
	fs.SetOutput(w)
	stateDir := fs.String("state", DefaultStateDir(), "统一 state 根（config.toml 所在）")
	jsonOut := fs.Bool("json", false, "机器可读 JSON（字符串数组）")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	cfg, err := nodeconfig.Load(nodeconfig.Path(*stateDir))
	if err != nil {
		return err
	}
	if *jsonOut {
		b, _ := json.Marshal(cfg.Serve.DDNS)
		fmt.Fprintln(w, string(b))
		return nil
	}
	if len(cfg.Serve.DDNS) == 0 {
		fmt.Fprintln(w, "（config 无 ddns 条目）")
		return nil
	}
	for _, d := range cfg.Serve.DDNS {
		fmt.Fprintln(w, d)
	}
	return nil
}

// maskForHint 写入回显的 token 掩码（凭证纪律：输出面保持掩码习惯——全文在命令行
// 参数里，输出不再复述）。
func maskForHint(tok string) string {
	if len(tok) <= 12 {
		return tok[:min(4, len(tok))] + "…"
	}
	return tok[:12] + "…"
}

// ---- usage ----

func usageServeGroup(w io.Writer) {
	fmt.Fprint(w, `用法：
  homeway serve start [--state D] [--no-spawn]   启用并确保在跑（未跑则拉起统一进程；幂等）
  homeway serve stop [--state D]                 停角色并落期望态（收尾异步；幂等；其余角色不动）
  homeway serve restart [--state D]              进程内重建（期望态不变；角色停时报错先 start）
  homeway serve status [--json] [--state D]      期望+运行态+观测面（未跑降级读 config）
  homeway serve token [--state D]                完整 hmw1 凭证（在跑控制面 / 未跑台账末行）
  homeway serve relay set <token> [--stdin]      上游中继 token 写 config（纯文件操作）
  homeway serve relay clear                      清除上游中继 token
  homeway serve ddns add|delete <domain>|list    DDNS 条目（多条目，写 config）
`)
}

func usageRelayGroup(w io.Writer) {
	fmt.Fprint(w, `用法：
  homeway relay start [--state D] [--no-spawn]   启用并确保在跑（未跑则拉起统一进程；幂等）
  homeway relay stop [--state D]                 停角色并落期望态（收尾异步；幂等；其余角色不动）
  homeway relay restart [--state D]              进程内重建（期望态不变；角色停时报错先 start）
  homeway relay status [--json] [--state D]      期望+运行态+注册出口列表（未跑降级读 config）
  homeway relay token [--state D]                完整 rl1 凭证（在跑控制面 / 未跑离线推算）
`)
}
