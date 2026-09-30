package daemon

// status_cli.go — homeway daemon status [--json] [--state DIR]（host-registry-daemon
// 4.1）：控制面的 CLI 消费面。命令归属 = 守护托管（读面）：经 §3.8 Go 客户端走完整
// 握手 → daemon.status（载荷 = 版本/代际/角色/主机摘要+链路态——snapshot 的超集），
// --json 原样打印机器可读全量快照（UI 半边判据的替代载体之一，design E2）。
// 守护进程未运行/不可达时报可行动错误（提示启动命令——spec「命令归属规则」场景）。

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/zhaoyswd/homeway/clientcore/facade"
	"io"
	"path/filepath"
	"time"

	"github.com/zhaoyswd/homeway/internal/control"
)

// statusCLI status 子命令入口（CLI 分发；输出写 w 便于测试）。
func statusCLI(args []string, version string, w io.Writer) error {
	fs := flag.NewFlagSet("homeway daemon status", flag.ContinueOnError)
	fs.SetOutput(w) // usage/解析错误随命令输出（生产 = stdout；--help 常规去向）
	stateDir := fs.String("state", DefaultStateDir(), "守护进程 state 目录（从中找 control.sock）")
	jsonOut := fs.Bool("json", false, "机器可读全量快照（stdout 一行 JSON，UI/脚本消费）")
	timeout := fs.Duration("timeout", 5*time.Second, "连接与请求的总预算")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil // usage 已由 flag 集打印
		}
		return err
	}
	sock := filepath.Join(*stateDir, control.ControlSockName)
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	c, _, err := control.Dial(ctx, sock, control.FrontendInfo{Kind: "cli", Name: "homeway", Version: version})
	if err != nil {
		// 可行动错误：直跑/托管两类场景里 status 属托管——未运行是常态而非异常，
		// 错误文案给出启动命令（spec「归属决定连接语义」场景）。
		return fmt.Errorf("homeway daemon 未在运行（sock=%s：%v）\n先启动：homeway daemon --state %s", sock, err, *stateDir)
	}
	defer c.Close()
	raw, err := c.Request(ctx, facade.OpDaemonStatus, nil)
	if err != nil {
		return fmt.Errorf("daemon.status 失败：%w", err)
	}
	if *jsonOut {
		fmt.Fprintln(w, string(raw)) // 服务端载荷原样（机器可读；键序不进契约）
		return nil
	}
	var st control.DaemonStatusResult
	if err := json.Unmarshal(raw, &st); err != nil {
		return fmt.Errorf("daemon.status 载荷解析失败：%w", err)
	}
	printStatus(w, &st, *stateDir)
	return nil
}

// printStatus 人类可读输出（中文文案是 CLI 侧映射，MUST NOT 进入契约——spec
// 「请求/响应与错误码表」）。主机 ID 截短显示（完整值走 --json）。
func printStatus(w io.Writer, st *control.DaemonStatusResult, stateDir string) {
	fmt.Fprintf(w, "homeway daemon：运行中\n  版本： %s\n  代际： %s（事件序号 %d）\n  state： %s\n", st.ServerVersion, st.Generation, st.Seq, stateDir)
	if len(st.Roles) == 0 {
		fmt.Fprint(w, "  角色： 无\n")
	}
	for _, r := range st.Roles {
		line := fmt.Sprintf("  角色： %s=%s（进程内重建 %d 次）", r.Name, r.State, r.Restarts)
		if r.Reason != "" {
			line += " reason=" + r.Reason
		}
		fmt.Fprintln(w, line)
	}
	if len(st.Hosts) == 0 {
		fmt.Fprint(w, "  主机： 无\n")
		return
	}
	fmt.Fprintf(w, "  主机： %d 台\n", len(st.Hosts))
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
