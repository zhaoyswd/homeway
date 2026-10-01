//go:build !windows

// term_cli.go — `homeway term` 主机命令面（term-host-cli 任务 7.1）+ `homeway term explain`
// （任务 4.8，规则判定的**完整依据链**）+ `--host` 远程模式（term-remote §1）。
//
// 命令面（与 App 同一份会话注册表；本地面经 `<state>/term.sock` 本地直连、不经隧道；
// `--host` 模式经注入缝（RemoteTerm）走 daemon 控制面 → 隧道 → 对端 term 服务）：
//
//	homeway term list [--json] [--host <ref>] [--state <dir>] [--timeout <T>]
//	homeway term new [name] [-d] [-A] [--host <ref>] …      # 默认创建并接入；-d 只创建不接入
//	homeway term attach [name] [-d] [--detach-key K] …       # raw 终端客户端（term_cli_attach.go）
//	homeway term delete <name> [--host <ref>] …
//	homeway term explain --file <屏幕文本> --agent <label>   # 离线：调规则（本地面，不接受 --host）
//	homeway term explain <会话名> [--host <ref>] …            # 在线：取运行中会话的实时快照
//
// explain 离线模式是规则迭代的主路径：把误判的屏幕存成文件 → explain 看命中规则与评估轨迹 → 改 TOML →
// 复验（改的是**本地覆盖** `<state>/agent-detection/<id>.toml`，不动移植文件）。
// 在线模式经 EXPLAIN 帧（诊断用 op 0x16——避开 surface 占用的 0x0D–0x15；出口不在跑时报可行动的错）。
//
// 错误面（design D1/D7 + term-remote D4/D5 三层）：连接层两态合并提示（ENOENT = 出口未运行或
// HOMEWAY_TERM=off；ECONNREFUSED = 残留 socket）；协议层错误码翻可行动中文。远程模式另有两层：
// 控制面连接层与 stream.open 错误码（internal/daemon/term_remote.go 翻文案）、流终结三态归因
// （RemoteEndError → remoteEndMessage）。**面向同代出口**（破坏性授权
// 2026-09-27），不做旧出口检测/告警/降级。
package term

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/zhaoyswd/homeway/internal/cliopts"
	"github.com/zhaoyswd/homeway/pkg/term/manifest"
)

// DefaultStateDir 是 state 目录默认值（与出口一致：~/.config/homeway）。
func DefaultStateDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", "homeway")
	}
	return ""
}

// CLI 是 `homeway term` 的入口（remote = `--host` 模式的注入缝；nil = 仅本地面）。
func CLI(args []string, remote RemoteTerm) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		termUsage(os.Stdout)
		return nil
	}
	// `--flag=value` 归一成 `--flag value`（手写解析器统一支持两种形态）。
	args = expandFlagEq(args)
	sub, rest := args[0], args[1:]
	var err error
	switch sub {
	case "explain":
		err = cliExplain(rest, remote)
	case "list":
		err = cliList(rest, remote)
	case "new":
		err = cliNew(rest, remote)
	case "attach":
		var o attachOpts
		if o, err = parseAttachArgs(rest); err == nil {
			o.remote = remote
			err = cliAttachCmd(o)
		}
	case "delete":
		err = cliDelete(rest, remote)
	default:
		return fmt.Errorf("不认识的子命令 %q（可用：list、new、attach、delete、explain）", sub)
	}
	return err
}

// expandFlagEq 把 `--flag=value` 拆成 `--flag value`。
func expandFlagEq(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if strings.HasPrefix(a, "--") {
			if i := strings.IndexByte(a, '='); i > 2 {
				out = append(out, a[:i], a[i+1:])
				continue
			}
		}
		out = append(out, a)
	}
	return out
}

// ---- 通用参数与连接层（任务 7.1；--host/--timeout = term-remote 1.2）----

// termCommon 是各子命令的公共参数（--state/--host/--timeout）。
//
// --host 非空 = 远程模式：--state 的指代切换为 daemon state 目录（control.sock
// 所在；空串 = 实现侧默认 ~/.config/homeway/daemon）——同一 flag 重载、非互斥
// 报错（r1 P2-5）；--timeout = 解析与打开**各**用一次的预算（CLI 侧两次独立
// context.WithTimeout；默认各 10s，最坏相加 20s——exec-r1 L1 校正，原「总预算
// 10s」措辞不准；attach 流本身不设 deadline——两口径分开，r1 P2-9）。
type termCommon struct {
	stateDir string
	hostRef  string
	timeout  time.Duration
	noSpawn  bool // --no-spawn：守护进程未运行时不按需拉起（role-management 4.1；随 ctx 传给远程缝）
}

// target 构造拨号目标（见 newTermTarget 的缺省决策）。
func (c termCommon) target(remote RemoteTerm) *termTarget {
	return newTermTarget(remote, c.stateDir, c.hostRef, c.timeout, c.noSpawn)
}

// defaultRemoteTimeout 远程「解析」与「连接 + stream.open」各一次的预算缺省
// （--timeout 缺省；exec-r1 L1 校正：不是一次性总预算——解析、打开两次独立
// context.WithTimeout 各取该值，默认各 10s、最坏相加 20s。参照 host add 的 10s
// 预算口径——host list/status/delete 为 5s，取宽者，r2 低④）。
const defaultRemoteTimeout = 10 * time.Second

// termTarget 拨号目标：本地面（remote == nil 或 hostRef == ""，连
// <stateDir>/term.sock）或远端（--host，经注入缝走 daemon 控制面 → 隧道 → 对端
// term 服务）。hostID 缓存首次解析结果——attach 省略名字（LIST）+ 接入（HELLO）
// 与自动命名重试不重复解析。
type termTarget struct {
	stateDir string        // 本地 = 出口 state；远程 = daemon state（空串 = 实现侧默认）
	remote   RemoteTerm    // nil = 本地面
	hostRef  string        // --host 原始 ref
	hostID   string        // 远程已解析 hex（拨号复用）
	timeout  time.Duration // 远程解析/打开各一次预算（默认各 10s、最坏相加 20s，仅 --host 可用）
	noSpawn  bool          // --no-spawn：未运行不按需拉起（cliopts 随 ctx 下传远程缝）
}

// newTermTarget 按参数构造目标：远程模式 timeout 缺省补 defaultRemoteTimeout、
// stateDir 留空交给实现侧默认（用户显式给 --state 才透传）；本地面 stateDir 缺省
// 补 DefaultStateDir()（现状语义）。
func newTermTarget(remote RemoteTerm, stateDir, hostRef string, timeout time.Duration, noSpawn bool) *termTarget {
	t := &termTarget{stateDir: stateDir, remote: remote, hostRef: hostRef, timeout: timeout, noSpawn: noSpawn}
	if hostRef != "" {
		if t.timeout <= 0 {
			t.timeout = defaultRemoteTimeout
		}
	} else if t.stateDir == "" {
		t.stateDir = DefaultStateDir()
	}
	return t
}

// remoteMode 远程模式判定（--host 给了且注入缝在）。
func (t *termTarget) remoteMode() bool { return t.remote != nil && t.hostRef != "" }

// nextArg 取第 i+1 个参数（flag 的值）；缺失报可行动错误。
func nextArg(args []string, i *int, flag string) (string, error) {
	if *i+1 >= len(args) {
		return "", fmt.Errorf("%s 后面缺参数", flag)
	}
	*i++
	return args[*i], nil
}

// applyCommon 解析 `--state <dir>`（写回 *stateDir）。
func applyCommon(stateDir *string, args []string, i *int) error {
	v, err := nextArg(args, i, "--state")
	if err != nil {
		return err
	}
	*stateDir = v
	return nil
}

// applyHostRef 解析 `--host <ref>`（空值就地报错——空串走不到远程解析层）。
func applyHostRef(dst *string, args []string, i *int) error {
	v, err := nextArg(args, i, "--host")
	if err != nil {
		return err
	}
	if strings.TrimSpace(v) == "" {
		return errors.New("--host 需要主机名或 ID（homeway host list 查看在表主机）")
	}
	*dst = v
	return nil
}

// applyTimeout 解析 `--timeout <时长>`（如 10s、1500ms；仅远程模式使用）。
func applyTimeout(dst *time.Duration, args []string, i *int) error {
	v, err := nextArg(args, i, "--timeout")
	if err != nil {
		return err
	}
	d, perr := time.ParseDuration(v)
	if perr != nil || d <= 0 {
		return fmt.Errorf("--timeout %q 不是合法时长（如 10s、1500ms）", v)
	}
	*dst = d
	return nil
}

// protoError 是服务端 ERROR 帧的 CLI 侧载体（错误码可被调用方按 code 分支，
// 如自动命名的 already_exists 重试；文案 = 服务端消息 + 可行动提示）。
type protoError struct{ code, msg string }

func (e *protoError) Error() string {
	switch e.code {
	case "no_session":
		// 场景含「命令期间会话恰好结束」的竞态（spec：报「会话已结束」并提示刷新）。
		return e.msg + "；用 homeway term list 查看当前会话"
	default:
		if e.msg != "" {
			return e.msg
		}
		return e.code
	}
}

func isProtoCode(err error, code string) bool {
	var pe *protoError
	return errors.As(err, &pe) && pe.code == code
}

// dialErrText 把连接层错误翻成可行动文案（D1：两态 + 合并提示）。
func dialErrText(sock string, err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("出口未在运行、或终端服务被关闭（HOMEWAY_TERM=off），或 --state 指错目录"+
			"（%s 不存在）；检查 --state 与出口状态", sock)
	case errors.Is(err, syscall.ECONNREFUSED):
		return fmt.Errorf("连接被拒：%s 像是残留 socket（出口进程已退出）；确认出口在跑，或删除该文件后重试", sock)
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return fmt.Errorf("无权连接 %s（term.sock 仅属主可用；命令面须与出口同一用户运行）", sock)
	}
	return fmt.Errorf("连不上 term 服务（%s）：%w", sock, err)
}

// cliDialTerm 按目标拨号并读 GREETING——list/new/delete/attach/explain 共用的
// 唯一拨号缝（1.1 收敛面：本地面连 <state>/term.sock；远端经注入缝 Resolve →
// DialTerm，term 帧协议端到端原样承载）。explainSession 原自带的独立拨号点
// （net.Dial 直连）已随动并入（r2 低⑥）。
func cliDialTerm(t *termTarget) (io.ReadWriteCloser, error) {
	var conn io.ReadWriteCloser
	if t.remoteMode() {
		// 远程：解析（幂等缓存）→ 拨号；两步各用一次 --timeout 预算（默认各 10s，
		// 最坏相加 20s——exec-r1 L1）。
		base := cliopts.With(context.Background(), cliopts.Opts{NoSpawn: t.noSpawn})
		if t.hostID == "" {
			rctx, rcancel := context.WithTimeout(base, t.timeout)
			id, _, rerr := t.remote.ResolveHostRef(rctx, t.stateDir, t.hostRef)
			rcancel()
			if rerr != nil {
				return nil, rerr
			}
			t.hostID = id
		}
		ctx, cancel := context.WithTimeout(base, t.timeout)
		defer cancel()
		var err error
		conn, err = t.remote.DialTerm(ctx, t.stateDir, t.hostID)
		if err != nil {
			return nil, err
		}
	} else {
		if t.hostRef != "" {
			// 防御：CLI 入口恒注入（cmd/homeway 接线）；只跑本地面的调用方给了 --host。
			return nil, errors.New("--host 需要远程接入缝（本构建未注入）；本地面请去掉 --host")
		}
		if t.timeout > 0 {
			// exec-r1 L6：本地面不设预算（连 <state>/term.sock 即时返回），静默忽略
			// --timeout 与本命令面「不认识的参数」严格风格不一致——显式报错。
			return nil, errors.New("--timeout 仅 --host 模式可用（远程的解析/打开预算）；本地面请去掉 --timeout")
		}
		if t.stateDir == "" {
			return nil, errors.New("拿不到 state 目录（用 --state 指定）")
		}
		sock := filepath.Join(t.stateDir, "term.sock")
		var err error
		conn, err = net.Dial("unix", sock)
		if err != nil {
			return nil, dialErrText(sock, err)
		}
	}
	f, err := readTermFrame(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("读 GREETING：%w", err)
	}
	if f.op != opGreeting {
		conn.Close()
		return nil, fmt.Errorf("首帧应为 GREETING，收到 op 0x%02x", f.op)
	}
	return conn, nil
}

// cliRoundTrip 一锤子命令：发一帧、读应答；ERROR 帧翻成 protoError。
func cliRoundTrip(conn io.ReadWriteCloser, op byte, payload []byte) (termFrame, error) {
	if _, err := conn.Write(encodeTermFrame(op, payload)); err != nil {
		return termFrame{}, fmt.Errorf("发 op 0x%02x 帧：%w", op, err)
	}
	f, err := readTermFrame(conn)
	if err != nil {
		return termFrame{}, fmt.Errorf("读应答：%w", err)
	}
	if f.op == opError {
		code, msg, _ := decError(f.payload)
		return f, &protoError{code: code, msg: msg}
	}
	return f, nil
}

// validateName 本地校验会话名（spec：就地报错、MUST NOT 发起连接）。
func validateName(name string) error {
	if !termNameRx.MatchString(name) {
		return fmt.Errorf("会话名 %q 不合法：只能是 [A-Za-z0-9._-]{1,64}", name)
	}
	return nil
}

// ---- list ----

// cliClientInfo / cliSessionInfo：LIST JSON 的 CLI 侧镜像（字段与出口同构、只增不改，D8）。
type cliClientInfo struct {
	Kind    string `json:"kind"` // app / host / legacy
	Cols    uint16 `json:"cols"`
	Rows    uint16 `json:"rows"`
	SinceMs int64  `json:"sinceMs"`
	Active  bool   `json:"active"`
}

type cliSessionInfo struct {
	Name         string          `json:"name"`
	CreatedMs    int64           `json:"createdMs"`
	LastActiveMs int64           `json:"lastActiveMs"`
	Attached     bool            `json:"attached"`
	Agent        string          `json:"agent"`
	StateV2      string          `json:"stateV2"` // 状态唯一字段（旧 state 键已退役，term-remote 3.3）
	Title        string          `json:"title"`
	Cwd          string          `json:"cwd,omitempty"`
	Cols         uint16          `json:"cols"`
	Rows         uint16          `json:"rows"`
	Pid          int             `json:"pid"`
	Clients      []cliClientInfo `json:"clients"`
}

func cliList(args []string, remote RemoteTerm) error {
	var c termCommon
	jsonOut := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--json":
			jsonOut = true
		case a == "--no-spawn":
			c.noSpawn = true
		case a == "--no-spawn":
			c.noSpawn = true
		case a == "--state":
			if err := applyCommon(&c.stateDir, args, &i); err != nil {
				return err
			}
		case a == "--host":
			if err := applyHostRef(&c.hostRef, args, &i); err != nil {
				return err
			}
		case a == "--timeout":
			if err := applyTimeout(&c.timeout, args, &i); err != nil {
				return err
			}
		case strings.HasPrefix(a, "-"):
			return fmt.Errorf("不认识的参数 %q（可用：--json、--state <dir>、--host <name|id>、--timeout <时长>、--no-spawn）", a)
		default:
			return fmt.Errorf("list 不接受会话名（%q）；省略名字接入最近活跃会话请用 attach", a)
		}
	}
	// 缺省补默认（newTermTarget 内：本地面 --state 沿用 ~/.config/homeway；远程
	// --state 留空 = daemon 侧默认 ~/.config/homeway/daemon）。
	entries, raw, err := cliListFetch(c.target(remote))
	if err != nil {
		return err
	}
	return cliListPrint(os.Stdout, entries, raw, jsonOut)
}

// cliListFetch 经拨号缝取 LIST（表格与「attach 省略名字」的最近活跃解析共用）。
func cliListFetch(t *termTarget) ([]cliSessionInfo, []byte, error) {
	conn, err := cliDialTerm(t)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()
	f, err := cliRoundTrip(conn, opList, nil)
	if err != nil {
		return nil, nil, err
	}
	if f.op != opList {
		return nil, nil, fmt.Errorf("期望 LIST-REPLY，收到 op 0x%02x", f.op)
	}
	var out struct {
		Sessions []cliSessionInfo `json:"sessions"`
	}
	if err := json.Unmarshal(f.payload, &out); err != nil {
		return nil, nil, fmt.Errorf("LIST-REPLY 不是合法 JSON：%w", err)
	}
	return out.Sessions, f.payload, nil
}

// cliListPrint 表格 / JSON 输出（--json 与出口 LIST JSON 同构：原样缩进重排、不改字段）。
func cliListPrint(w io.Writer, entries []cliSessionInfo, rawJSON []byte, asJSON bool) error {
	if asJSON {
		var buf bytes.Buffer
		if err := json.Indent(&buf, rawJSON, "", "  "); err != nil {
			return fmt.Errorf("LIST JSON 缩进失败：%w", err)
		}
		_, _ = buf.WriteTo(w)
		return nil
	}
	if len(entries) == 0 {
		fmt.Fprintln(w, "（当前没有会话；homeway term new 可创建）")
		return nil
	}
	// 最近活跃在前（与 attach 省略名字的选取一致）。
	sorted := append([]cliSessionInfo{}, entries...)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j].LastActiveMs > sorted[j-1].LastActiveMs; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	fmt.Fprintf(w, "%-20s %-9s %-9s %-10s %-24s %s\n", "NAME", "SIZE", "STATE", "AGENT", "TITLE", "CLIENTS")
	for _, s := range sorted {
		title := s.Title
		if title == "" {
			title = "-"
		}
		r := []rune(title)
		if len(r) > 22 {
			title = string(r[:21]) + "…"
		}
		clients := "-"
		if len(s.Clients) > 0 {
			kinds := make([]string, 0, len(s.Clients))
			for _, cl := range s.Clients {
				k := cl.Kind
				if cl.Active {
					k += "*"
				}
				kinds = append(kinds, k)
			}
			clients = strings.Join(kinds, ",")
		}
		fmt.Fprintf(w, "%-20s %dx%-5d %-9s %-10s %-24s %s\n",
			s.Name, s.Cols, s.Rows, s.StateV2, s.Agent, title, clients)
	}
	return nil
}

// ---- new / delete ----

// newOpts：`new [name] [-d] [-A]`（--host/--timeout 远程模式）。
type newOpts struct {
	name      string
	detached  bool          // -d：只创建不接入（CREATE op，不动 PTY 尺寸、不产生腿）
	reuse     bool          // -A：已存在则复用（不报 already_exists）
	stateDir  string        // 空 = 构造目标时按模式补默认
	hostRef   string        // --host
	timeout   time.Duration // --timeout
	autoNamed bool          // 省略名字：host-<4hex> + 重名重试
	noSpawn   bool          // --no-spawn（role-management 4.1）
}

func parseNewArgs(args []string) (newOpts, error) {
	o := newOpts{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-d":
			o.detached = true
		case a == "-A":
			o.reuse = true
		case a == "--state":
			if err := applyCommon(&o.stateDir, args, &i); err != nil {
				return o, err
			}
		case a == "--host":
			if err := applyHostRef(&o.hostRef, args, &i); err != nil {
				return o, err
			}
		case a == "--timeout":
			if err := applyTimeout(&o.timeout, args, &i); err != nil {
				return o, err
			}
		case strings.HasPrefix(a, "-"):
			return o, fmt.Errorf("不认识的参数 %q（可用：-d、-A、--state <dir>、--host <name|id>、--timeout <时长>）", a)
		default:
			if o.name != "" {
				return o, fmt.Errorf("只能给一个会话名（已有 %q）", o.name)
			}
			o.name = a
		}
	}
	if o.name == "" {
		o.autoNamed = true
	} else if err := validateName(o.name); err != nil {
		return o, err
	}
	return o, nil
}

func cliNew(args []string, remote RemoteTerm) error {
	o, err := parseNewArgs(args)
	if err != nil {
		return err
	}
	if o.detached {
		return cliNewDetached(o, remote)
	}
	// 默认：创建并接入（tmux 式 new-session）。
	return cliAttachCmd(attachOpts{
		name: o.name, stateDir: o.stateDir,
		create: true, reuse: o.reuse, autoNamed: o.autoNamed,
		hostRef: o.hostRef, timeout: o.timeout, remote: remote,
	})
}

// cliNewDetached：`new -d`（CREATE op 创建不接入；任务 6.2 的客户端半边）。
func cliNewDetached(o newOpts, remote RemoteTerm) error {
	// CREATE bit0 = reuse-if-exists（置位=存在则静默复用；与 HELLO bit1 的「置位=报
	// already_exists」极性相反，见 frames.go 的 createFlagReuseIfExists——exec-r3 中2）。
	flags := byte(0)
	if o.reuse {
		flags |= createFlagReuseIfExists
	}
	t := newTermTarget(remote, o.stateDir, o.hostRef, o.timeout, o.noSpawn)
	if o.autoNamed {
		// 自动命名不置 reuse-if-exists（置位会静默复用既有会话）：靠 already_exists 重试。
		for i := 0; i < 8; i++ {
			name := genAutoName()
			if err := cliCreateOnce(t, name, flags); err != nil {
				if isProtoCode(err, "already_exists") {
					continue
				}
				return err
			}
			fmt.Printf("已创建会话 %s（不接入）\n", name)
			return nil
		}
		return errors.New("自动命名连续重名 8 次（运气太差）；请显式给名字：homeway term new <名字> -d")
	}
	if err := cliCreateOnce(t, o.name, flags); err != nil {
		return err
	}
	fmt.Printf("已创建会话 %s（不接入）\n", o.name)
	return nil
}

func cliCreateOnce(t *termTarget, name string, flags byte) error {
	conn, err := cliDialTerm(t)
	if err != nil {
		return err
	}
	defer conn.Close()
	f, err := cliRoundTrip(conn, opCreate, encCreate(flags, name))
	if err != nil {
		return err
	}
	if f.op != opOK {
		return fmt.Errorf("期望 OK，收到 op 0x%02x", f.op)
	}
	return nil
}

// cliDelete：复用既有 KILL 帧（与 App 关闭会话同一路径；wire op 名不改，D1）。
func cliDelete(args []string, remote RemoteTerm) error {
	var c termCommon
	name := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--no-spawn":
			c.noSpawn = true
		case a == "--state":
			if err := applyCommon(&c.stateDir, args, &i); err != nil {
				return err
			}
		case a == "--host":
			if err := applyHostRef(&c.hostRef, args, &i); err != nil {
				return err
			}
		case a == "--timeout":
			if err := applyTimeout(&c.timeout, args, &i); err != nil {
				return err
			}
		case strings.HasPrefix(a, "-"):
			return fmt.Errorf("不认识的参数 %q（可用：--state <dir>、--host <name|id>、--timeout <时长>）", a)
		default:
			if name != "" {
				return fmt.Errorf("只能给一个会话名（已有 %q）", name)
			}
			name = a
		}
	}
	if name == "" {
		return errors.New("delete 需要会话名：homeway term delete <name>")
	}
	if err := validateName(name); err != nil {
		return err
	}
	conn, err := cliDialTerm(c.target(remote))
	if err != nil {
		return err
	}
	defer conn.Close()
	f, err := cliRoundTrip(conn, opKill, encName(name))
	if err != nil {
		return err
	}
	if f.op != opOK {
		return fmt.Errorf("期望 OK，收到 op 0x%02x", f.op)
	}
	fmt.Printf("会话 %s 已结束\n", name)
	return nil
}

// cliPickRecentSession 取最近活跃的会话名（attach 省略名字的语义，D7——远程模式
// 走同一拨号缝的远程 LIST，D4）。
func cliPickRecentSession(t *termTarget) (string, error) {
	entries, _, err := cliListFetch(t)
	if err != nil {
		return "", err
	}
	if len(entries) == 0 {
		return "", errors.New("当前没有会话；homeway term new 可创建一个，或 homeway term list 查看")
	}
	best := entries[0]
	for _, s := range entries[1:] {
		if s.LastActiveMs > best.LastActiveMs {
			best = s
		}
	}
	return best.Name, nil
}

// cliExplain 是 explain 子命令入口（--host = 在线模式远程化，r1 P1-6；--file 是
// 本地面、不接受 --host——组合就地报可行动错误）。
func cliExplain(args []string, remote RemoteTerm) error {
	opt, err := parseExplainArgs(args)
	if err != nil {
		return err
	}
	if opt.file != "" && opt.hostRef != "" {
		return errors.New("--file 是本地面（规则判定在本地 manifest），不接受 --host；对远程主机的会话取实时判定：homeway term explain <会话名> --host <name|id>")
	}
	if opt.file != "" && opt.timeout > 0 {
		// exec-r1 L6：--file 离线模式不经拨号缝，--timeout 同样只属 --host 模式。
		return errors.New("--timeout 仅 --host 模式可用（远程的解析/打开预算）；--file 离线模式请去掉 --timeout")
	}
	var out explainOutput
	if opt.file != "" {
		out, err = explainFile(opt)
	} else if opt.session != "" {
		out, err = explainSession(opt, remote)
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
	stateDir string // --file 模式的 manifest 覆盖目录（本地语义恒定；空 = 构造时补默认）
	json     bool
	hostRef  string        // 在线模式 --host（远程）
	timeout  time.Duration // 远程解析/打开各一次预算（默认各 10s、最坏相加 20s，仅 --host 可用）
	noSpawn  bool          // --no-spawn（role-management 4.1）
}

func parseExplainArgs(args []string) (explainOpts, error) {
	o := explainOpts{}
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
		case a == "--no-spawn":
			o.noSpawn = true
		case a == "--state":
			o.stateDir, err = next()
		case a == "--host":
			if err = applyHostRef(&o.hostRef, args, &i); err != nil {
				return o, err
			}
		case a == "--timeout":
			if err = applyTimeout(&o.timeout, args, &i); err != nil {
				return o, err
			}
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

// explainFile 离线模式：对一段保存的屏幕文本跑分类（本地面：--state 恒指出口
// state 的 manifest 覆盖目录，缺省补默认——与 --host 模式的指代切换无关）。
func explainFile(o explainOpts) (explainOutput, error) {
	data, err := os.ReadFile(o.file)
	if err != nil {
		return explainOutput{}, fmt.Errorf("读屏幕文件：%w", err)
	}
	stateDir := o.stateDir
	if stateDir == "" {
		stateDir = DefaultStateDir()
	}
	l := loaderFor(stateDir)
	if _, ok := l.ForProcess(o.agent); !ok {
		if _, ok := l.ForID(o.agent); !ok {
			return explainOutput{}, fmt.Errorf("认不出 agent %q（可用：%s）", o.agent, strings.Join(l.IDs(), " "))
		}
	}
	return runExplain(l, o.agent, string(data), ""), nil
}

// explainSession 在线模式：经统一拨号缝问出口（本地）或目标主机（--host）要一份
// 实时判定——EXPLAIN 一锤子往返零 wire 改动（1.4：原自带 net.Dial 的独立拨号点
// 已并入 cliDialTerm，r2 低⑥）。
func explainSession(o explainOpts, remote RemoteTerm) (explainOutput, error) {
	t := newTermTarget(remote, o.stateDir, o.hostRef, o.timeout, o.noSpawn)
	conn, err := cliDialTerm(t)
	if err != nil {
		return explainOutput{}, err
	}
	defer conn.Close()
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
	fmt.Fprint(w, `homeway term —— 终端服务的主机命令面（与 App 同一份会话注册表）

用法：
  homeway term list [--json] [--host <name|id>] [--state <dir>] [--timeout <T>]
        列会话（--json 输出与出口 LIST JSON 同构，可作脚本契约）
  homeway term new [name] [-d] [-A] [--host <name|id>] [--state <dir>] [--timeout <T>]
        新建并接入；-d 只创建不接入（默认尺寸、不占终端）；-A 已存在则复用接入；
        省略名字自动命名 host-<4hex>（与 App 的命名可区分，重名自动重试）
  homeway term attach [name] [-d] [--detach-key <K>] [--host <name|id>] [--state <dir>] [--timeout <T>]
        接入会话（raw 字节模式，本地终端自己渲染）；省略名字 = 最近活跃的会话；
        -d 显式接管（踢掉该会话的其它客户端）
  homeway term delete <name> [--host <name|id>] [--state <dir>] [--timeout <T>]
        结束会话（与 App 关闭会话同一路径）
  homeway term explain --file <屏幕文本> --agent <label> [--state <dir>] [--json]
        离线对一段保存的屏幕跑规则判定（调规则的主路径；本地面，不接受 --host）
  homeway term explain <会话名> [--host <name|id>] [--state <dir>] [--timeout <T>] [--json]
        对运行中的会话取实时快照判定（--host = 对远程主机会话跑 EXPLAIN 往返）

远程模式（--host，经 daemon 控制面转发；term 帧协议经隧道端到端原样复用）：
  --host <name|id>   目标主机（与 host delete/status 同规则：名称精确 / peerID 全长
                     hex / 无歧义短前缀；homeway host list 查看在表主机）
  ⚠ --host 模式下 --state 指守护进程 state 目录（control.sock 所在，默认
     ~/.config/homeway/daemon）——与本地面（出口 state，默认 ~/.config/homeway）
     指代不同；--timeout 为解析与打开各一次的预算（默认各 10s、最坏相加 20s，
     如 10s/1500ms），仅 --host 模式可用（本地面给出即报错）；attach 流本身不设
     deadline（长连接语义）。daemon 未运行时先启动：homeway daemon
  远程 attach 的流终结归因：gone = 主机不可达或上行过快（会话仍在目标主机运行，可
     重新 attach）；closed = 对端关闭（也可能是本端长时间停止读取、出口侧慢腿自治
     收尾）；连接级断开 = 与守护进程的连接断了，重新执行命令即可。

attach 中的分离与重对齐（前缀键默认 Ctrl-b，tmux 同款）：
  Ctrl-b d          分离（会话继续在出口运行）
  Ctrl-b r          重新对齐：会话尺寸被其它客户端改走后，重新上报本终端尺寸
  Ctrl-b Ctrl-b     输入字面量 Ctrl-b
  --detach-key '^x' 换前缀键（如 ^]）；--detach-key none 关闭（全部字节透传）
  ⚠ 默认前缀与 tmux 的前缀相同；会话里要跑 tmux 时请换键或关闭（示例：--detach-key=^]）

说明：
  --state 默认 `+DefaultStateDir()+`（与出口一致）；连接 <state>/term.sock（本地 UDS、不经隧道）。
  持有该 socket 访问权 = 拿到该主机的 shell（state 目录 0700 是权限边界）。
  attach 需要交互终端（stdin/stdout 都是 TTY）；管道/脚本里请用 list / new -d / delete。
  会话内经 TERM_SESSION_ID 检测接入自身会被拒绝（输出回环）。
  终端标题：attach 默认以 OSC 2 显示「会话 · agent · 状态」并尽力恢复原值（OSC 21 查询，
  150ms 内无应答则放弃恢复）；HOMEWAY_TERM_TITLE=off 可整体关闭。
  退出码：分离 / 会话结束（含被接管）/ 信号退出 = 0；连接层或协议层错误、断链 = 1；
  未知 term 子命令 = 1（顶层未知角色 = 2）。
  异常退出后画面混乱时执行 reset 修复。
  本地规则覆盖目录是 <state>/agent-detection/<agent>.toml（explain 离线模式；改完触发重载即生效）。
`)
}
