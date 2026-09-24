//go:build !windows

// term_cli.go — `homeway term explain`（任务 4.8）：把规则判定的**完整依据链**打出来。
//
// 两种用法（规格「explain 调试命令」）：
//
//	homeway term explain --file <屏幕文本> --agent <label> [--json]   # 离线：调规则
//	homeway term explain <会话名> [--state <dir>] [--json]            # 在线：取运行中会话的实时快照
//
// 离线模式是规则迭代的主路径：把误判的屏幕存成文件 → explain 看命中规则与评估轨迹 → 改 TOML →
// 复验（改的是**本地覆盖** `<state>/agent-detection/<id>.toml`，不动移植文件）。
//
// 在线模式经 `<state>/term.sock` 问出口进程要一份实时判定（EXPLAIN 帧，诊断用 op 0x16——
// 避开 surface 占用的 0x0D–0x15；出口不在跑时报可行动的错，不静默失败）。
package term

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/zhaoyswd/homeway/pkg/term/manifest"
)

// DefaultStateDir 是 state 目录默认值（与出口一致：~/.config/homeway）。
func DefaultStateDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", "homeway")
	}
	return ""
}

// CLI 是 `homeway term` 的入口。
func CLI(args []string) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		termUsage(os.Stdout)
		return nil
	}
	if args[0] != "explain" {
		return fmt.Errorf("不认识的子命令 %q（可用：explain）", args[0])
	}
	opt, err := parseExplainArgs(args[1:])
	if err != nil {
		return err
	}
	var out explainOutput
	if opt.file != "" {
		out, err = explainFile(opt)
	} else if opt.session != "" {
		out, err = explainSession(opt)
	} else {
		return errors.New("需要 --file <屏幕文本> 或 <会话名>（见 homeway term --help）")
	}
	if err != nil {
		return err
	}
	return printExplain(os.Stdout, out, opt.json)
}

type explainOpts struct {
	file     string
	agent    string
	session  string
	stateDir string
	json     bool
}

func parseExplainArgs(args []string) (explainOpts, error) {
	o := explainOpts{stateDir: DefaultStateDir()}
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s 后面缺参数", a)
			}
			i++
			return args[i], nil
		}
		var err error
		switch {
		case a == "--file":
			o.file, err = next()
		case a == "--agent":
			o.agent, err = next()
		case a == "--state":
			o.stateDir, err = next()
		case a == "--json":
			o.json = true
		case strings.HasPrefix(a, "-"):
			return o, fmt.Errorf("不认识的参数 %q", a)
		default:
			if o.session != "" {
				return o, fmt.Errorf("只能给一个会话名（已有 %q）", o.session)
			}
			o.session = a
		}
		if err != nil {
			return o, err
		}
	}
	if o.file != "" && o.agent == "" {
		return o, errors.New("--file 模式必须给 --agent（哪份 manifest）")
	}
	return o, nil
}

// explainOutput 是 explain 的输出（也是 EXPLAIN 帧的载荷，JSON 编解码）。
type explainOutput struct {
	Agent          string             `json:"agent"`
	Session        string             `json:"session,omitempty"`
	ManifestSource string             `json:"manifestSource,omitempty"`
	ManifestVer    string             `json:"manifestVersion,omitempty"`
	State          string             `json:"state"`
	Fallback       string             `json:"fallbackReason,omitempty"`
	Matched        *matchedRuleOut    `json:"matchedRule,omitempty"`
	VisibleIdle    bool               `json:"visibleIdle"`
	VisibleBlocker bool               `json:"visibleBlocker"`
	VisibleWorking bool               `json:"visibleWorking"`
	SkipUpdate     bool               `json:"skipStateUpdate"`
	Rules          []evaluatedRuleOut `json:"rules"`
	Warnings       []string           `json:"warnings,omitempty"`
	// ScreenBytes 是本次判定的屏幕文本长度（诊断「region 切空了」的第一手数据）。
	ScreenBytes int `json:"screenBytes"`
}

type matchedRuleOut struct {
	ID       string `json:"id"`
	Priority int    `json:"priority"`
	Region   string `json:"region"`
	State    string `json:"state"`
}

type evaluatedRuleOut struct {
	ID          string `json:"id"`
	Priority    int    `json:"priority"`
	Region      string `json:"region"`
	State       string `json:"state"`
	Matched     bool   `json:"matched"`
	RegionBytes int    `json:"regionBytes"`
}

// explainFile 离线模式：对一段保存的屏幕文本跑分类。
func explainFile(o explainOpts) (explainOutput, error) {
	data, err := os.ReadFile(o.file)
	if err != nil {
		return explainOutput{}, fmt.Errorf("读屏幕文件：%w", err)
	}
	l := loaderFor(o.stateDir)
	if _, ok := l.ForProcess(o.agent); !ok {
		if _, ok := l.ForID(o.agent); !ok {
			return explainOutput{}, fmt.Errorf("认不出 agent %q（可用：%s）", o.agent, strings.Join(l.IDs(), " "))
		}
	}
	return runExplain(l, o.agent, string(data), ""), nil
}

// explainSession 在线模式：经 term.sock 问出口要一份实时判定。
func explainSession(o explainOpts) (explainOutput, error) {
	if o.stateDir == "" {
		return explainOutput{}, errors.New("拿不到 state 目录（用 --state 指定）")
	}
	sock := filepath.Join(o.stateDir, "term.sock")
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return explainOutput{}, fmt.Errorf("连不上出口的 term 服务（%s）：%w\n"+
			"出口没在跑、或 HOMEWAY_TERM=off 时会这样；离线调规则用 --file 模式", sock, err)
	}
	defer conn.Close()
	if _, err := readTermFrame(conn); err != nil { // GREETING
		return explainOutput{}, fmt.Errorf("读 GREETING：%w", err)
	}
	if _, err := conn.Write(encodeTermFrame(opExplain, encName(o.session))); err != nil {
		return explainOutput{}, fmt.Errorf("发 EXPLAIN：%w", err)
	}
	f, err := readTermFrame(conn)
	if err != nil {
		return explainOutput{}, fmt.Errorf("读 EXPLAIN 应答：%w", err)
	}
	if f.op == opError {
		code, msg, _ := decError(f.payload)
		return explainOutput{}, fmt.Errorf("%s：%s", code, msg)
	}
	if f.op != opExplain {
		return explainOutput{}, fmt.Errorf("期望 EXPLAIN 应答，收到 op 0x%02x", f.op)
	}
	var out explainOutput
	if err := json.Unmarshal(f.payload, &out); err != nil {
		return explainOutput{}, fmt.Errorf("EXPLAIN 应答不是合法 JSON：%w", err)
	}
	return out, nil
}

func loaderFor(stateDir string) *manifest.Loader {
	override := ""
	if stateDir != "" {
		override = filepath.Join(stateDir, manifest.OverrideDirName)
	}
	return manifest.NewLoader(override)
}

// runExplain 是两种模式共用的判定 + 输出装配。
func runExplain(l *manifest.Loader, agent, screen, session string) explainOutput {
	comp, ok := l.ForProcess(agent)
	if !ok {
		comp, ok = l.ForID(agent)
	}
	if !ok {
		return explainOutput{Agent: agent, Session: session, State: "unknown",
			Warnings: []string{"没有该 agent 的 manifest"}, ScreenBytes: len(screen)}
	}
	res := comp.Evaluate(manifest.Input{Screen: screen})
	out := explainOutput{
		Agent:          agent,
		Session:        session,
		ManifestSource: string(comp.Manifest.Source),
		ManifestVer:    comp.Manifest.Version,
		State:          res.State.String(),
		Fallback:       res.FallbackReason,
		VisibleIdle:    res.VisibleIdle,
		VisibleBlocker: res.VisibleBlocker,
		VisibleWorking: res.VisibleWorking,
		SkipUpdate:     res.SkipStateUpdate,
		ScreenBytes:    len(screen),
		Warnings:       l.Warnings(),
	}
	if res.MatchedRule != nil {
		out.Matched = &matchedRuleOut{
			ID:       res.MatchedRule.ID,
			Priority: res.MatchedRule.Priority,
			Region:   res.MatchedRule.Region,
			State:    res.MatchedRule.State.String(),
		}
	}
	for _, r := range res.Rules {
		out.Rules = append(out.Rules, evaluatedRuleOut{
			ID: r.ID, Priority: r.Priority, Region: r.Region,
			State: r.State.String(), Matched: r.Matched, RegionBytes: r.RegionBytes,
		})
	}
	return out
}

func printExplain(w io.Writer, out explainOutput, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	if out.Session != "" {
		fmt.Fprintf(w, "会话：%s\n", out.Session)
	}
	fmt.Fprintf(w, "agent：%s（manifest=%s 版本=%s 来源=%s）\n",
		out.Agent, firstNonEmpty(out.ManifestVer, "-"), firstNonEmpty(out.ManifestVer, "-"), firstNonEmpty(out.ManifestSource, "-"))
	fmt.Fprintf(w, "屏幕文本：%d 字节\n", out.ScreenBytes)
	fmt.Fprintf(w, "判定：%s", out.State)
	if out.Fallback != "" {
		fmt.Fprintf(w, "（回落：%s）", out.Fallback)
	}
	fmt.Fprintln(w)
	if out.Matched != nil {
		fmt.Fprintf(w, "命中规则：%s（priority=%d region=%s state=%s）\n",
			out.Matched.ID, out.Matched.Priority, out.Matched.Region, out.Matched.State)
	} else {
		fmt.Fprintln(w, "命中规则：无")
	}
	fmt.Fprintf(w, "可见证据位：idle=%v blocker=%v working=%v；冻结状态=%v\n",
		out.VisibleIdle, out.VisibleBlocker, out.VisibleWorking, out.SkipUpdate)
	if len(out.Warnings) > 0 {
		fmt.Fprintf(w, "告警：%s\n", strings.Join(out.Warnings, "；"))
	}
	fmt.Fprintf(w, "\n全部规则评估轨迹（%d 条，★=命中）：\n", len(out.Rules))
	for _, r := range out.Rules {
		mark := " "
		if r.Matched {
			mark = "★"
		}
		fmt.Fprintf(w, " %s %-36s p=%-5d region=%-30s state=%-7s region字节=%d\n",
			mark, r.ID, r.Priority, r.Region, r.State, r.RegionBytes)
	}
	return nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func termUsage(w io.Writer) {
	fmt.Fprint(w, `homeway term —— 终端服务的诊断工具

用法：
  homeway term explain --file <屏幕文本> --agent <label> [--state <dir>] [--json]
        离线对一段保存的屏幕跑规则判定（调规则的主路径）
  homeway term explain <会话名> [--state <dir>] [--json]
        对运行中的会话取实时快照判定（经 <state>/term.sock）

说明：
  --state 默认 `+DefaultStateDir()+`（与出口一致）；本地规则覆盖目录是
  <state>/agent-detection/<agent>.toml（本地永远优先，改完重启出口或触发重载即生效）。
`)
}
