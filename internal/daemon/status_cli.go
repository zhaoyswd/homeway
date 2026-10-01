package daemon

// status_cli.go — homeway status [--json] [--watch]（role-management tasks 3.4，D10
//「聚合 status 架构」；吸收旧 `homeway daemon status`——watch 平移且沿「观测即需求」
// 语义，r1 低-9）。**直跑底座 + 控制面叠加**：
//
//	底座（全停时这层就够，纯读不拉起）：config 期望态（serve/relay 的 enabled 与
//	  配置摘要）+ L2 存在性（serve tokens.jsonl 末行掩码、relay.key、client/
//	  hosts.json 台数）。
//	叠加（进程在跑时）：daemon.status（进程层 + client 域）+ serve.status +
//	  relay.status 三 op 并聚。
//
// 事实约束：**relay 节看不到 APP**（在中继注册的是出口、手机流量在 WG 密文里）——
// APP 维度只从 serve peer 表看；relay 节 = 经此中继的出口列表。
// 掩码纪律：全域 token 只见掩码指纹（完整凭证只经 serve/relay token）。

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/zhaoyswd/homeway/clientcore/facade"
	"github.com/zhaoyswd/homeway/internal/control"
	"github.com/zhaoyswd/homeway/internal/nodestate"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// StatusCLI `homeway status` 入口（cmd/homeway 分发；输出写 w 便于测试）。
func StatusCLI(args []string, version string, w io.Writer) error {
	fs := flag.NewFlagSet("homeway status", flag.ContinueOnError)
	fs.SetOutput(w)
	stateDir := fs.String("state", DefaultStateDir(), "统一 state 根（config.toml + control.sock 所在）")
	jsonOut := fs.Bool("json", false, "机器可读 JSON（stdout 一行；进程/serve/relay/client 四域）")
	watch := fs.Bool("watch", false, "live 渲染：client 域快照 + 订阅续播（state/reason/via/rtt 随事件刷新，Ctrl-C 退出）。⚠️ 观测副作用：watch 期间被显示主机（启动时列表）视为有需求（订阅视图参与需求合成），退出后贡献消失；serve/relay 域暂不进 watch 流（事件总线无该域，按只增后续补）")
	timeout := fs.Duration("timeout", 5*time.Second, "连接与请求的总预算")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *watch && *jsonOut {
		return fmt.Errorf("--json 与 --watch 互斥（--watch = 人类可读 live 渲染；机器可读消费走 --json）")
	}
	sock := controlSockOf(*stateDir)
	if *watch {
		// watch 需进程在位（纯读不拉起——未跑 = 可行动错误）。Ctrl-C/SIGTERM →
		// 正常退出（退订由连接关闭承载——view 的需求贡献消失）；timeout 只限定
		// 初始阶段（Dial+快照+订阅），渲染期不设预算。
		wctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return statusWatch(wctx, sock, version, *stateDir, *timeout, w)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	c, _, err := control.Dial(ctx, sock, control.FrontendInfo{Kind: "cli", Name: "homeway", Version: version})
	if err != nil {
		return printStatusDegraded(w, *stateDir, *jsonOut)
	}
	defer c.Close()
	return printStatusOnline(ctx, w, c, *stateDir, *jsonOut)
}

// aggProcess 进程层（--json 的 process 域）。
type aggProcess struct {
	Running    bool   `json:"running"`
	Pid        int    `json:"pid,omitempty"`
	Version    string `json:"version,omitempty"`
	Generation string `json:"generation,omitempty"`
	StateDir   string `json:"stateDir"`
}

// aggClient client 域（--json 的 client 域）。
type aggClient struct {
	Running bool                `json:"running"`
	Hosts   []control.HostState `json:"hosts"`
	HostCnt int                 `json:"hostCount"` // 未跑时从 client/hosts.json 点台数
	Note    string              `json:"note,omitempty"`
}

// printStatusDegraded 全停面：读 config 报期望态（纯读不拉起——全程无进程被拉起）。
func printStatusDegraded(w io.Writer, stateDir string, jsonOut bool) error {
	proc := aggProcess{Running: false, StateDir: stateDir}
	serveSt := degradedServe(stateDir)
	relaySt := degradedRelay(stateDir)
	cli := aggClient{Running: false, HostCnt: hostCountOnDisk(stateDir)}
	if cli.HostCnt >= 0 {
		cli.Note = fmt.Sprintf("未运行（host 表 %d 台于 config 外的 client/ 层）", cli.HostCnt)
	} else {
		cli.Note = "未运行"
		cli.HostCnt = 0
	}
	if jsonOut {
		out := map[string]any{"process": proc, "serve": serveSt, "relay": relaySt, "client": cli}
		b, _ := json.Marshal(out)
		fmt.Fprintln(w, string(b))
		return nil
	}
	fmt.Fprintf(w, "homeway：未运行（state=%s；纯读——本命令不拉起进程）\n", stateDir)
	fmt.Fprintf(w, "  serve：%s（期望 %v）\n", serveSt.State, serveSt.Enabled)
	fmt.Fprintf(w, "  relay：%s（期望 %v）\n", relaySt.State, relaySt.Enabled)
	fmt.Fprintf(w, "  client：%s\n", cli.Note)
	return nil
}

// printStatusOnline 运行面：三 op 并聚（daemon.status + serve.status + relay.status）。
func printStatusOnline(ctx context.Context, w io.Writer, c *control.Client, stateDir string, jsonOut bool) error {
	rawDaemon, err := c.Request(ctx, facade.OpDaemonStatus, nil)
	if err != nil {
		return fmt.Errorf("daemon.status 失败：%w", err)
	}
	var st control.DaemonStatusResult
	if err := json.Unmarshal(rawDaemon, &st); err != nil {
		return fmt.Errorf("daemon.status 载荷解析失败：%w", err)
	}
	// 叠加面失败不炸整份输出（角色 op 是只增面；旧代际 = unknown_op → 注明）。
	rawServe, serveErr := c.Request(ctx, facade.OpServeStatus, nil)
	rawRelay, relayErr := c.Request(ctx, facade.OpRelayStatus, nil)
	if jsonOut {
		proc := aggProcess{Running: true, Pid: st.Pid, Version: st.ServerVersion, Generation: st.Generation, StateDir: stateDir}
		out := map[string]any{
			"process": proc,
			"client":  aggClient{Running: true, Hosts: st.Hosts, HostCnt: len(st.Hosts)},
		}
		if serveErr == nil {
			var sv json.RawMessage = rawServe
			out["serve"] = sv
		} else {
			out["serve"] = degradedServe(stateDir)
		}
		if relayErr == nil {
			var rv json.RawMessage = rawRelay
			out["relay"] = rv
		} else {
			out["relay"] = degradedRelay(stateDir)
		}
		b, _ := json.Marshal(out)
		fmt.Fprintln(w, string(b))
		return nil
	}
	fmt.Fprintf(w, "homeway：运行中（pid %d，版本 %s，代际 %s，state=%s）\n", st.Pid, st.ServerVersion, st.Generation, stateDir)
	for _, r := range st.Roles {
		line := fmt.Sprintf("  角色： %s=%s（进程内重建 %d 次）", r.Name, r.State, r.Restarts)
		if r.Reason != "" {
			line += " reason=" + r.Reason
		}
		fmt.Fprintln(w, line)
	}
	if serveErr == nil {
		var sv control.ServeStatusResult
		if json.Unmarshal(rawServe, &sv) == nil {
			printServeSection(w, &sv)
		}
	} else {
		d := degradedServe(stateDir)
		fmt.Fprintf(w, "  serve：%s（期望 %v；运行面不可得：%v）\n", d.State, d.Enabled, serveErr)
	}
	if relayErr == nil {
		var rv control.RelayStatusResult
		if json.Unmarshal(rawRelay, &rv) == nil {
			printRelaySection(w, &rv)
		}
	} else {
		d := degradedRelay(stateDir)
		fmt.Fprintf(w, "  relay：%s（期望 %v；运行面不可得：%v）\n", d.State, d.Enabled, relayErr)
	}
	printClientSection(w, &st)
	return nil
}

func printServeSection(w io.Writer, st *control.ServeStatusResult) {
	phrase := "运行中"
	if !st.Enabled && (st.State == "stopped" || st.State == "absent") {
		phrase = "期望停用（进程在跑）"
	} else if st.State != "" && st.State != "running" {
		phrase = st.State
	}
	line := fmt.Sprintf("  serve：%s（期望 %v）", phrase, st.Enabled)
	if st.ListenPort != 0 {
		line += fmt.Sprintf("，监听 %d", st.ListenPort)
	}
	fmt.Fprintln(w, line)
	if st.TokenMask != "" {
		fmt.Fprintf(w, "    token：%s（掩码；完整凭证经 homeway serve token）\n", st.TokenMask)
	}
	if len(st.Published) > 0 {
		fmt.Fprintf(w, "    公布端点：%s\n", joinOr(st.Published))
	}
	if len(st.Peers) > 0 {
		fmt.Fprintf(w, "    APP 设备：%d 台\n", len(st.Peers))
	}
}

func printRelaySection(w io.Writer, st *control.RelayStatusResult) {
	phrase := "运行中"
	if !st.Enabled && (st.State == "stopped" || st.State == "absent") {
		phrase = "期望停用（进程在跑）"
	} else if st.State != "" && st.State != "running" {
		phrase = st.State
	}
	line := fmt.Sprintf("  relay：%s（期望 %v）", phrase, st.Enabled)
	if st.Listen != "" {
		line += "，监听 " + st.Listen
	}
	fmt.Fprintln(w, line)
	if len(st.Backends) > 0 {
		fmt.Fprintf(w, "    注册出口：%d 台（中继看不到 APP——手机流量在 WG 密文里）\n", len(st.Backends))
	}
}

func printClientSection(w io.Writer, st *control.DaemonStatusResult) {
	if len(st.Hosts) == 0 {
		fmt.Fprint(w, "  主机： 无\n")
		return
	}
	fmt.Fprintf(w, "  主机：%d 台\n", len(st.Hosts))
	for _, h := range st.Hosts {
		name := h.Name
		if name == "" {
			name = "-"
		}
		line := fmt.Sprintf("    - %s（%s）state=%s", shortHostID(h.ID), name, h.State)
		if h.Reason != "" {
			line += " reason=" + h.Reason
		}
		if h.Link != nil {
			line += fmt.Sprintf(" link=%s ep=%s rtt=%dms", h.Link.Via, h.Link.Ep, h.Link.RttMs)
		}
		if h.Stats != nil {
			line += fmt.Sprintf(" rx/tx=%s/%s", humanBytes(h.Stats.RxBytes), humanBytes(h.Stats.TxBytes))
		}
		fmt.Fprintln(w, line)
	}
}

func joinOr(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += "、"
		}
		out += s
	}
	return out
}

// hostCountOnDisk 未跑时从 client/hosts.json 点台数（登记面文件；读不到 = -1）。
func hostCountOnDisk(stateDir string) int {
	b, err := os.ReadFile(nodestate.HostsPath(stateDir))
	if err != nil {
		return -1
	}
	var hosts []any
	if json.Unmarshal(b, &hosts) == nil {
		return len(hosts)
	}
	var m map[string]any
	if json.Unmarshal(b, &m) == nil {
		return len(m)
	}
	return -1
}

// shortHostID 主机 ID 显示形式（前 8 hex；完整 64 hex 走 --json）。
func shortHostID(id string) string {
	if len(id) > 8 {
		return id[:8] + "…"
	}
	return id
}

// humanBytes 流量面的可读形式（CLI 映射，不进契约）。
func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fKB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%dB", n)
	}
}
