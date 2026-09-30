package files

// files_cli.go — `homeway files` 命令面（files-cli §1，design D1/D4/D5）：六子命令与
// 协议动词 1:1（list/stat/mkdir/read/get/put；get↔download、put↔write），本地 +
// `--host` 远程双面。CLI 全部经 files.Client{Dial} 复用（协议零重写）——拨号统一缝：
// 本地面 = net.Dial("<state>/files.sock")；远程面 = 注入缝 RemoteFiles（daemon 实现，
// pkg/files 保持零 internal/ 依赖）→ io.ReadWriteCloser → net.Conn 适配壳（deadline
// 族返回「不支持」——与「传输不设 deadline」自洽）→ Client。
//
// 预算口径（D1 + r3 新-10 写死）：`--host` 模式「解析」「连接+stream.open」「首响应
//（定义 = 问候帧——Client.Open 的第一读，本地面/远程面同一载体）」三段各用一次
// --timeout（默认各 10s，最坏相加 30s）；①② = 各自的 context.WithTimeout，③ =
// **看门 goroutine**（起于 Dial 返回：首响应阶段盯带预算的定时器，**问候帧返回后
// 切到命令级 signal ctx**——首响应预算的「cancel 不进 Close 路径」，否则第 10s 会
// 误杀传输中的流；r3 新-10）。**两面统一挂看门**（Close 真 net.Conn 同样有效——
// 本地面/远程面同一载体同一生命周期）；传输本身不设 deadline（get/put 长连接语义，
// 与首响应预算两口径分开）。取消 = signal.NotifyContext cancel，读循环检查 ctx.Err()
//（client.go 扩展），阻塞中的 Read 由看门 Close 打断——首信号即中断。
//
// 流终结归因（D4/D5）：终结错误 = streamend.Error（pkg/streamend 中立公共包）；读方向
// 经 files.Error 的 Errw/Unwrap 链可达、写方向经 daemon 适配层的 Write 翻译归一同型
// ——CLI 一份 errors.As(err, &streamend.Error) 覆盖读写两方向；三态各归各文案，与
// files 协议错误码（层③）先到先解释、不混淆。

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
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/zhaoyswd/homeway/pkg/streamend"
)

// DefaultStateDir 本地面的 state 目录默认值（= 出口 state，与 term 面一致）。
func DefaultStateDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", "homeway")
	}
	return ""
}

// RemoteFiles —— `--host` 模式的远程接入缝（与 term.RemoteTerm 同款注入模式；
// 实现落 internal/daemon/files_remote.go，测试注假实现）。
type RemoteFiles interface {
	// ResolveHostRef 把 --host 的名称/全长 hex/无歧义短前缀解析为 hex id（规则与
	// host delete/status 同源）。stateDir = daemon state 目录（control.sock 所在；
	// 空串 = 实现侧默认 ~/.config/homeway/daemon）。
	ResolveHostRef(ctx context.Context, stateDir, ref string) (hexID, name string, err error)
	// DialFiles 打开到目标主机 files 服务的字节流（files 协议端到端承载、零改写；
	// 返回的连接满足「可读问候帧」的普通流语义）。ctx = 「控制面连接 + stream.open」
	// 一段预算；问候帧（首响应）预算由 CLI 侧看门承接（本文件 dial 闭包）。
	DialFiles(ctx context.Context, stateDir, hexID string) (io.ReadWriteCloser, error)
}

// defaultFilesTimeout 三段（解析 / 连接+打开 / 首响应）各一次的预算缺省（--timeout
// 缺省；参照 host add 的 10s 口径）。本地面 --timeout 同样可用（连接+首响应两段）。
const defaultFilesTimeout = 10 * time.Second

// DefaultRateLimit put 上行限速缺省（bytes/s；1.4「发送端速率义务」）。保守起步值 =
// 2MiB/s（design D5「不可判定时取保守值」；实测定标数据见 tier 仓 exec-report——
// 真机各腿标定随 §6 采证，届时按「最慢实测腿吞吐一半以下」修订）。0 = 不限、风险
// 自担（越界被守护进程收流属可预期边界）。
const DefaultRateLimit = 2 << 20

// CLI 是 `homeway files` 的入口（remote = `--host` 模式的注入缝；nil = 仅本地面）。
func CLI(args []string, remote RemoteFiles) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		filesUsage(os.Stdout)
		return nil
	}
	args = expandEq(args)
	sub, rest := args[0], args[1:]
	// 命令级 signal ctx：Ctrl-C/SIGTERM = cancel（读循环检查 ctx、阻塞读由看门
	// Close 打断——首信号即中断，不再依赖 SIGKILL）。get/put 的取消语义挂在这。
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var err error
	switch sub {
	case "list":
		err = cliFilesList(ctx, rest, remote)
	case "stat":
		err = cliFilesStat(ctx, rest, remote)
	case "mkdir":
		err = cliFilesMkdir(ctx, rest, remote)
	case "read":
		err = cliFilesRead(ctx, rest, remote)
	case "get":
		err = cliFilesGet(ctx, rest, remote)
	case "put":
		err = cliFilesPut(ctx, rest, remote)
	default:
		return fmt.Errorf("不认识的子命令 %q（可用：list、stat、mkdir、read、get、put）", sub)
	}
	return err
}

// filesUsage 打印命令面用法。
func filesUsage(w io.Writer) {
	fmt.Fprint(w, `homeway files —— 文件命令面（类 sftp；与 App 同一份 files 协议，六子命令与协议动词 1:1）

用法：
  homeway files list [path] [--json] [--host <ref>] [--state <dir>] [--timeout <T>]
        列目录（--json = 单行 JSON 数组：name/isDir/size/mtimeMs + mode〔权限位，
        八进制，诊断用〕，可作脚本契约）
  homeway files stat <path> [--json] [--host <ref>] [--state <dir>] [--timeout <T>]
        单条目信息（--json = 单行 JSON，键同 list）
  homeway files mkdir <path> [--host <ref>] [--state <dir>] [--timeout <T>]
        新建目录（已存在报 already_exists）
  homeway files read <path> [--max N] [--host <ref>] …
        文本预览（默认 512KiB=协议文本默认；截断提示走 stderr；--max 超协议内联
        上限 16MiB 时报错而非静默截断）
  homeway files get <远端> [-o 本地] [--force] [--quiet] [--host <ref>] …
        下载（目标缺省 = 当前目录 basename；已存在默认拒、--force 覆盖；进度走
        stderr；本地原子落盘——写 <目标>.tierpart、成功 rename、中断即删，可重试）
  homeway files put <本地> <远端> [--rate-limit N] [--quiet] [--host <ref>] …
        上传（远端原子替换；Ctrl-C = 取消，远端清理 .tierpart、目标不变）
        --rate-limit <bytes/s> 上行限速（默认保守值 2MiB/s；0 = 不限、风险自担——
        守护进程每流缓冲满即收流）

双面与 --state 指代（term 面同款重载语义，非互斥）：
  无 --host   = 本地面：一次性直连 <state>/files.sock（--state 默认出口 state
               `+DefaultStateDir()+`，不要求 daemon 在位）
  --host <ref> = 远程面：经 daemon 控制面 stream.open{kind:files} 转发（ref = 名称
               精确 / peerID hex 全长 / 无歧义短前缀，与 host delete/status 同规则）；
               ⚠ 该模式下 --state 指守护进程 state 目录（control.sock 所在，默认
               ~/.config/homeway/daemon）。--timeout = 解析/连接+打开/首响应（问候帧）
               三段各一次的预算（默认各 10s，最坏相加 30s；传输本身不设 deadline）。
  daemon 未运行时远程面会报可行动错误（先启动：homeway daemon）。

流终结归因（get/put 中途）：gone = 流被守护进程收流（主机不可达或上行持续过快）；
closed = 对端已关闭（files 服务收工）；连接级断开 = 与守护进程的连接断了，重试即可。
`)
}

// expandEq 把 `--flag=value` 拆成 `--flag value`。
func expandEq(args []string) []string {
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

// ---- 目标与拨号（1.1）----

// filesTarget 拨号目标：本地面（连 <stateDir>/files.sock）或远端（--host，经注入缝）。
type filesTarget struct {
	stateDir string        // 本地 = 出口 state；远程 = daemon state（空串 = 实现侧默认）
	remote   RemoteFiles   // nil = 本地面
	hostRef  string        // --host 原始 ref
	hostID   string        // 远程已解析 hex（一次 CLI 调用内缓存，多命令不重复解析）
	timeout  time.Duration // 三段各一次预算（默认 10s）
}

// newFilesTarget 缺省决策（term 面同款）：远程 timeout 缺省补默认、stateDir 留空交给
// 实现侧；本地面 stateDir 缺省补 DefaultStateDir()、timeout 也补默认（files 面本地面
// 有首响应预算——连接+问候帧两段，与 term 面「本地面不设预算」不同）。
func newFilesTarget(remote RemoteFiles, stateDir, hostRef string, timeout time.Duration) *filesTarget {
	t := &filesTarget{stateDir: stateDir, remote: remote, hostRef: hostRef, timeout: timeout}
	if t.timeout <= 0 {
		t.timeout = defaultFilesTimeout
	}
	if hostRef == "" && t.stateDir == "" {
		t.stateDir = DefaultStateDir()
	}
	return t
}

func (t *filesTarget) remoteMode() bool { return t.remote != nil && t.hostRef != "" }

// dialPhase 首响应（问候帧）阶段的观察面（r3 新-10 归因）：greeted = 问候帧已回
// （看门此后不再受预算约束）；timedOut = 看门因首响应预算烧尽而 Close 过——错误
// 归因用它把「超预算」从 conn 态终结里分辨出来。
type dialPhase struct {
	greeted  atomic.Bool
	timedOut atomic.Bool
	greetCh  chan struct{}
	once     sync.Once
}

func newDialPhase() *dialPhase { return &dialPhase{greetCh: make(chan struct{})} }

func (p *dialPhase) markGreeted() {
	p.once.Do(func() {
		p.greeted.Store(true)
		close(p.greetCh)
	})
}

// cliEnv 一次命令执行的拨号环境（命令级 signal ctx + 目标 + 首响应观察）。
type cliEnv struct {
	t      *filesTarget
	cmdCtx context.Context // 命令级 signal ctx（看门第二阶段盯它；传输期承接 Ctrl-C）
	phase  *dialPhase
}

// client 构造本命令的 files.Client（Dial = 统一拨号缝）。
func (e *cliEnv) client() *Client {
	return &Client{Dial: e.dial}
}

// dial 统一拨号缝（每命令一条流；Client.Open 调用）：①解析（远程，独立预算、缓存）
// → ②连接+打开（WithTimeout(cmdCtx, T)，dial 返回即撤——预算不外溢到命令期）→
// ③适配壳 + 看门（首响应预算载体，两面统一）。
func (e *cliEnv) dial(cmdCtx context.Context) (net.Conn, error) {
	t := e.t
	if t.remoteMode() {
		if t.hostID == "" {
			rctx, rcancel := context.WithTimeout(cmdCtx, t.timeout)
			id, _, rerr := t.remote.ResolveHostRef(rctx, t.stateDir, t.hostRef)
			rcancel()
			if rerr != nil {
				return nil, rerr
			}
			t.hostID = id
		}
		dctx, dcancel := context.WithTimeout(cmdCtx, t.timeout)
		defer dcancel()
		rw, err := t.remote.DialFiles(dctx, t.stateDir, t.hostID)
		if err != nil {
			return nil, err
		}
		return e.wrapStream(rw), nil
	}
	if t.hostRef != "" {
		// 防御：CLI 入口恒注入（cmd/homeway 接线）；只跑本地面的调用方给了 --host。
		return nil, errors.New("--host 需要远程接入缝（本构建未注入）；本地面请去掉 --host")
	}
	if t.stateDir == "" {
		return nil, errors.New("拿不到 state 目录（用 --state 指定）")
	}
	sock := filepath.Join(t.stateDir, "files.sock")
	dctx, dcancel := context.WithTimeout(cmdCtx, t.timeout)
	defer dcancel()
	var d net.Dialer
	conn, err := d.DialContext(dctx, "unix", sock)
	if err != nil {
		return nil, filesDialErr(sock, err)
	}
	return e.wrapStream(conn), nil
}

// wrapStream：注入缝/本地面拿到的连接 → net.Conn 适配壳 + 看门。
func (e *cliEnv) wrapStream(rw io.ReadWriteCloser) net.Conn {
	armWatchdog(rw, e.cmdCtx, e.t.timeout, e.phase)
	return &streamAdapter{c: rw, phase: e.phase}
}

// armWatchdog 看门 goroutine（r3 新-10 生命周期写死）：起于 dial 返回；首响应阶段
// 盯带预算的定时器（到点 → conn.Close() 打断阻塞中的问候帧 Read——对端 7802 被占
// 不应答时不会永久挂死，Ctrl-C 也由它承接）；**问候帧返回后切到命令级 signal ctx**
// （首响应预算的 cancel 不进 Close 路径——传输中的流不会被第 10s 误杀；传输期同一
// 看门承接 Ctrl-C 对阻塞读的打断）。Close 真 net.Conn 与适配壳同样有效（两面统一）。
func armWatchdog(c io.ReadWriteCloser, cmdCtx context.Context, budget time.Duration, p *dialPhase) {
	go func() {
		timer := time.NewTimer(budget)
		defer timer.Stop()
		select {
		case <-p.greetCh:
			// 问候帧已回：预算停表（timer.Stop——cancel 不进 Close 路径），进入命令期。
		case <-timer.C:
			// 同一刻竞态再核对一次：问候帧优先（防到点误杀刚回问候的流）。
			select {
			case <-p.greetCh:
			default:
				p.timedOut.Store(true)
				c.Close()
				return
			}
		}
		// 命令级 signal ctx（无时限）：Ctrl-C → Close 打断阻塞读。Done() == nil
		//（context.Background）= 调用方声明永不取消 → 不挂命令期看门（防 nil
		// channel 永久挂起的 goroutine 泄漏——CLI 走 signal ctx 恒有 Done）。
		if cmdCtx == nil {
			return
		}
		if done := cmdCtx.Done(); done != nil {
			<-done
			c.Close()
		}
	}()
}

// streamAdapter io.ReadWriteCloser → net.Conn（files.StreamDial 收 net.Conn）。
// deadline 族三方法返回「不支持」——与 D1「传输不设 deadline」自洽（首响应预算的
// 载体是看门，不是 conn deadline）。Read 顺带承担问候帧观察（首个含换行的成功读 =
// 问候帧——files 协议恒以问候帧开头、每命令一条流，观察点成立）。
type streamAdapter struct {
	c     io.ReadWriteCloser
	phase *dialPhase
}

func (a *streamAdapter) Read(p []byte) (int, error) {
	n, err := a.c.Read(p)
	if n > 0 && !a.phase.greeted.Load() && bytes.IndexByte(p[:n], '\n') >= 0 {
		a.phase.markGreeted()
	}
	return n, err
}

func (a *streamAdapter) Write(p []byte) (int, error) { return a.c.Write(p) }
func (a *streamAdapter) Close() error                { return a.c.Close() }

func (a *streamAdapter) LocalAddr() net.Addr  { return dummyAddr("files-stream") }
func (a *streamAdapter) RemoteAddr() net.Addr { return dummyAddr("files-stream") }

func (a *streamAdapter) SetDeadline(time.Time) error {
	return errors.New("files: 传输流不支持 deadline（传输不设 deadline；首响应预算由看门承接）")
}
func (a *streamAdapter) SetReadDeadline(time.Time) error {
	return errors.New("files: 传输流不支持 deadline（传输不设 deadline；首响应预算由看门承接）")
}
func (a *streamAdapter) SetWriteDeadline(time.Time) error {
	return errors.New("files: 传输流不支持 deadline（传输不设 deadline；首响应预算由看门承接）")
}

type dummyAddr string

func (d dummyAddr) Network() string { return string(d) }
func (d dummyAddr) String() string  { return string(d) }

// filesDialErr 本地面连接层错误 → 可行动文案（层①；远程面由 daemon 侧 controlDialErr
// 族翻好经注入缝透传，不需 CLI 再翻）。双向错误提示：本地面 files.sock 不存在 →
// 「出口未在跑或不是出口 state 目录」+ 远程面指代提示（用户想远程时给了出口 state）。
func filesDialErr(sock string, err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("出口未在跑、或该目录不是出口 state 目录（%s 不存在）。\n"+
			"本地面 --state 默认 %s（出口 state）；对远程主机取放文件请用 --host <name|id>（该模式下 --state 指守护进程 state 目录，默认 ~/.config/homeway/daemon）",
			sock, DefaultStateDir())
	case errors.Is(err, syscall.ECONNREFUSED):
		return fmt.Errorf("连接被拒：%s 像是残留 socket（出口进程已退出）；确认出口在跑，或删除该文件后重试", sock)
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return fmt.Errorf("无权连接 %s（files.sock 仅属主可用；命令须与出口同一用户运行）", sock)
	}
	return fmt.Errorf("连不上 files 服务（%s）：%w", sock, err)
}

// ---- 公共参数解析 ----

// filesCommon 各子命令的公共参数（--state/--host/--timeout）。
type filesCommon struct {
	stateDir string
	hostRef  string
	timeout  time.Duration
}

// applyFilesCommon 处理 --state/--host/--timeout 三个公共 flag（值形态）。
func applyFilesCommon(c *filesCommon, args []string, i *int, flag string) error {
	switch flag {
	case "--state":
		v, err := nextFilesArg(args, i, flag)
		if err != nil {
			return err
		}
		c.stateDir = v
	case "--host":
		v, err := nextFilesArg(args, i, flag)
		if err != nil {
			return err
		}
		if strings.TrimSpace(v) == "" {
			return errors.New("--host 需要主机名或 ID（homeway host list 查看在表主机）")
		}
		c.hostRef = v
	case "--timeout":
		v, err := nextFilesArg(args, i, flag)
		if err != nil {
			return err
		}
		d, perr := time.ParseDuration(v)
		if perr != nil || d <= 0 {
			return fmt.Errorf("--timeout %q 不是合法时长（如 10s、1500ms）", v)
		}
		c.timeout = d
	}
	return nil
}

func nextFilesArg(args []string, i *int, flag string) (string, error) {
	if *i+1 >= len(args) {
		return "", fmt.Errorf("%s 后面缺参数", flag)
	}
	*i++
	return args[*i], nil
}

func (c filesCommon) env(ctx context.Context, remote RemoteFiles) *cliEnv {
	return &cliEnv{t: newFilesTarget(remote, c.stateDir, c.hostRef, c.timeout), cmdCtx: ctx, phase: newDialPhase()}
}

// unknownFlagErr 统一的未知 flag 报错（子命令各自给可用集）。
func unknownFlagErr(a, usage string) error {
	return fmt.Errorf("不认识的参数 %q（可用：%s）", a, usage)
}

// ---- 进度（stderr，不污染 stdout）----

// progress stderr 进度渲染（\r 刷新；--quiet 抑制）。
type progress struct {
	w     io.Writer
	quiet bool
	total int64
}

func (p *progress) setTotal(n int64) { p.total = n }

func (p *progress) show(cur int64, verb string) {
	if p.quiet || p.w == nil {
		return
	}
	if p.total > 0 {
		fmt.Fprintf(p.w, "\r%s中… %s / %s（%.1f%%）", verb, humanBytes(cur), humanBytes(p.total), float64(cur)/float64(p.total)*100)
	} else {
		fmt.Fprintf(p.w, "\r%s中… %s", verb, humanBytes(cur))
	}
}

func (p *progress) done(verb string) {
	if p.quiet || p.w == nil {
		return
	}
	fmt.Fprintln(p.w, "\r"+verb+"完成。                    ")
}

func humanBytes(n int64) string {
	const k = 1024
	switch {
	case n >= k*k*k:
		return fmt.Sprintf("%.2fGiB", float64(n)/(k*k*k))
	case n >= k*k:
		return fmt.Sprintf("%.2fMiB", float64(n)/(k*k))
	case n >= k:
		return fmt.Sprintf("%.1fKiB", float64(n)/k)
	}
	return fmt.Sprintf("%dB", n)
}

// ---- list / stat ----

func cliFilesList(ctx context.Context, args []string, remote RemoteFiles) error {
	var c filesCommon
	jsonOut := false
	path := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--json":
			jsonOut = true
		case a == "--state" || a == "--host" || a == "--timeout":
			if err := applyFilesCommon(&c, args, &i, a); err != nil {
				return err
			}
		case strings.HasPrefix(a, "-"):
			return unknownFlagErr(a, "--json、--state <dir>、--host <name|id>、--timeout <时长>")
		default:
			if path != "" {
				return fmt.Errorf("只能给一个路径（已有 %q）", path)
			}
			path = a
		}
	}
	if path == "" {
		path = "."
	}
	e := c.env(ctx, remote)
	ents, err := e.client().List(ctx, path)
	if err != nil {
		return e.mapErr(err, "", 0)
	}
	return printEntries(os.Stdout, ents, jsonOut, false)
}

func cliFilesStat(ctx context.Context, args []string, remote RemoteFiles) error {
	var c filesCommon
	jsonOut := false
	path := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--json":
			jsonOut = true
		case a == "--state" || a == "--host" || a == "--timeout":
			if err := applyFilesCommon(&c, args, &i, a); err != nil {
				return err
			}
		case strings.HasPrefix(a, "-"):
			return unknownFlagErr(a, "--json、--state <dir>、--host <name|id>、--timeout <时长>")
		default:
			if path != "" {
				return fmt.Errorf("只能给一个路径（已有 %q）", path)
			}
			path = a
		}
	}
	if path == "" {
		return errors.New("stat 需要路径：homeway files stat <path>")
	}
	e := c.env(ctx, remote)
	ent, err := e.client().Stat(ctx, path)
	if err != nil {
		return e.mapErr(err, "", 0)
	}
	return printEntries(os.Stdout, []Entry{ent}, jsonOut, true)
}

// printEntries 表格 / 单行 JSON（--json；脚本面契约）。
func printEntries(w io.Writer, ents []Entry, asJSON, single bool) error {
	if asJSON {
		var v any = ents
		if single {
			v = ents[0]
		}
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		fmt.Fprintln(w, string(b))
		return nil
	}
	if single {
		printEntryRow(w, ents[0])
		return nil
	}
	if len(ents) == 0 {
		fmt.Fprintln(w, "（空目录）")
		return nil
	}
	fmt.Fprintf(w, "%-6s %-40s %12s  %s\n", "TYPE", "NAME", "SIZE", "MTIME")
	for _, en := range ents {
		printEntryRow(w, en)
	}
	return nil
}

func printEntryRow(w io.Writer, en Entry) {
	typ := "file"
	if en.IsDir {
		typ = "dir"
	}
	name := en.Name
	if r := []rune(name); len(r) > 40 {
		name = string(r[:39]) + "…"
	}
	mt := "-"
	if en.MtimeMs > 0 {
		mt = time.UnixMilli(en.MtimeMs).Local().Format("2006-01-02 15:04")
	}
	fmt.Fprintf(w, "%-6s %-40s %12s  %s\n", typ, name, humanBytes(en.Size), mt)
}

// ---- mkdir ----

func cliFilesMkdir(ctx context.Context, args []string, remote RemoteFiles) error {
	var c filesCommon
	path := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--state" || a == "--host" || a == "--timeout":
			if err := applyFilesCommon(&c, args, &i, a); err != nil {
				return err
			}
		case strings.HasPrefix(a, "-"):
			return unknownFlagErr(a, "--state <dir>、--host <name|id>、--timeout <时长>")
		default:
			if path != "" {
				return fmt.Errorf("只能给一个路径（已有 %q）", path)
			}
			path = a
		}
	}
	if path == "" {
		return errors.New("mkdir 需要路径：homeway files mkdir <path>")
	}
	e := c.env(ctx, remote)
	if err := e.client().Mkdir(ctx, path); err != nil {
		return e.mapErr(err, "", 0)
	}
	fmt.Printf("已创建目录 %s\n", path)
	return nil
}

// ---- read ----

func cliFilesRead(ctx context.Context, args []string, remote RemoteFiles) error {
	var c filesCommon
	path := ""
	var maxBytes int64 = -1
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--max":
			v, err := nextFilesArg(args, &i, a)
			if err != nil {
				return err
			}
			n, perr := parseInt64(v)
			if perr != nil || n <= 0 {
				return fmt.Errorf("--max %q 不是合法正整数（字节数）", v)
			}
			maxBytes = n
		case a == "--state" || a == "--host" || a == "--timeout":
			if err := applyFilesCommon(&c, args, &i, a); err != nil {
				return err
			}
		case strings.HasPrefix(a, "-"):
			return unknownFlagErr(a, "--max <N>、--state <dir>、--host <name|id>、--timeout <时长>")
		default:
			if path != "" {
				return fmt.Errorf("只能给一个路径（已有 %q）", path)
			}
			path = a
		}
	}
	if path == "" {
		return errors.New("read 需要路径：homeway files read <path>")
	}
	// 超协议内联硬上限：报错非静默截断（上限在服务端强制，CLI 就地先拦——省一次往返）。
	if maxBytes > maxInlineRead {
		return fmt.Errorf("--max %d 超过协议内联读取上限 %s（read 是内联预览，大文件请用 get）", maxBytes, humanBytes(maxInlineRead))
	}
	e := c.env(ctx, remote)
	resp, err := e.client().Read(ctx, path, "", maxBytes)
	if err != nil {
		return e.mapErr(err, "", 0)
	}
	fmt.Print(resp.Text)
	if resp.Truncated {
		fmt.Fprintf(os.Stderr, "（截断：文件 %s 超过预览上限，仅显示前 %s；--max 可调）\n",
			humanBytes(resp.Size), humanBytes(int64(len(resp.Text))))
	}
	return nil
}

func parseInt64(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}

// ---- get ----

type getOpts struct {
	common filesCommon
	remote string
	local  string
	force  bool
	quiet  bool
}

func cliFilesGet(ctx context.Context, args []string, remote RemoteFiles) error {
	var o getOpts
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-o":
			v, err := nextFilesArg(args, &i, a)
			if err != nil {
				return err
			}
			o.local = v
		case a == "--force":
			o.force = true
		case a == "--quiet":
			o.quiet = true
		case a == "--state" || a == "--host" || a == "--timeout":
			if err := applyFilesCommon(&o.common, args, &i, a); err != nil {
				return err
			}
		case strings.HasPrefix(a, "-"):
			return unknownFlagErr(a, "-o <本地>、--force、--quiet、--state <dir>、--host <name|id>、--timeout <时长>")
		default:
			if o.remote != "" {
				return fmt.Errorf("只能给一个远端路径（已有 %q）", o.remote)
			}
			o.remote = a
		}
	}
	if o.remote == "" {
		return errors.New("get 需要远端路径：homeway files get <远端> [-o 本地]")
	}
	target := o.local
	if target == "" {
		target = filepath.Base(strings.TrimRight(o.remote, "/"))
		if target == "" || target == "." || target == "/" {
			return fmt.Errorf("从远端路径 %q 推不出本地文件名；用 -o 显式指定", o.remote)
		}
	}
	// 已存在默认拒（--force 覆盖）。该拒绝 MUST NOT 被下载中断残留触发——下载走
	// 临时文件 + 原子 rename、失败即删（下），残留只可能是 <目标>.tierpart，不是目标。
	if !o.force {
		if _, serr := os.Stat(target); serr == nil {
			return fmt.Errorf("本地目标 %s 已存在；覆盖请加 --force", target)
		}
	}
	e := o.common.env(ctx, remote)
	return e.get(o, target)
}

// getDir 下载方向的错误归因附注（mapErr 用）。
const getDir = "get"

func (e *cliEnv) get(o getOpts, target string) error {
	tmp := target + uploadPartSuffix // 与远端上传临时文件同款命名
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("写本地临时文件 %s：%w", tmp, err)
	}
	cleanup := func() {
		_ = f.Close()
		_ = os.Remove(tmp) // 中断/失败即删：本地无半截残留，可直接重试
	}
	var received int64
	pr := &progress{w: os.Stderr, quiet: o.quiet}
	cw := &countingWriter{f: f, n: &received, p: pr}
	n, derr := e.client().DownloadTo(e.cmdCtx, o.remote, cw, func(size int64) { pr.setTotal(size) })
	if derr != nil {
		cleanup()
		return e.mapErr(derr, getDir, received)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("关本地临时文件：%w", err)
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("落盘（rename %s → %s）：%w", tmp, target, err)
	}
	pr.done("下载")
	fmt.Fprintf(os.Stderr, "已下载 %s → %s\n", o.remote, target)
	_ = n
	return nil
}

// countingWriter 落盘 + 进度 + 计数（写进文件的字节数即已收字节；中断文案用它报
// 「已收 N」）。写失败（磁盘满等）原样上抛 → get 走取消（关流，服务端无需清理）+
// 删临时文件。
type countingWriter struct {
	f io.Writer
	n *int64
	p *progress
}

func (w *countingWriter) Write(b []byte) (int, error) {
	m, err := w.f.Write(b)
	*w.n += int64(m)
	w.p.show(*w.n, "下载")
	return m, err
}

// ---- put ----

type putOpts struct {
	common    filesCommon
	local     string
	remote    string
	rateLimit int64 // bytes/s；-1 = 缺省（DefaultRateLimit）；0 = 不限
	quiet     bool
}

func cliFilesPut(ctx context.Context, args []string, remote RemoteFiles) error {
	var o putOpts
	o.rateLimit = -1
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--rate-limit":
			v, err := nextFilesArg(args, &i, a)
			if err != nil {
				return err
			}
			n, perr := parseInt64(v)
			if perr != nil || n < 0 {
				return fmt.Errorf("--rate-limit %q 不是合法的非负整数（bytes/s；0 = 不限、风险自担）", v)
			}
			o.rateLimit = n
		case a == "--quiet":
			o.quiet = true
		case a == "--state" || a == "--host" || a == "--timeout":
			if err := applyFilesCommon(&o.common, args, &i, a); err != nil {
				return err
			}
		case strings.HasPrefix(a, "-"):
			return unknownFlagErr(a, "--rate-limit <bytes/s>、--quiet、--state <dir>、--host <name|id>、--timeout <时长>")
		default:
			if o.local == "" {
				o.local = a
			} else if o.remote == "" {
				o.remote = a
			} else {
				return fmt.Errorf("只能给本地与远端两个路径（已有 %q %q）", o.local, o.remote)
			}
		}
	}
	if o.local == "" || o.remote == "" {
		return errors.New("put 需要两个路径：homeway files put <本地> <远端>")
	}
	fi, err := os.Stat(o.local)
	if err != nil {
		return fmt.Errorf("读本地文件 %s：%w", o.local, err)
	}
	if fi.IsDir() {
		return fmt.Errorf("%s 是目录（put 只支持文件）", o.local)
	}
	e := o.common.env(ctx, remote)
	return e.put(o, fi.Size())
}

const putDir = "put"

func (e *cliEnv) put(o putOpts, size int64) error {
	f, err := os.Open(o.local)
	if err != nil {
		return fmt.Errorf("读本地文件 %s：%w", o.local, err)
	}
	defer f.Close()
	rate := newTokenBucket(resolveRateLimit(o.rateLimit))
	pr := &progress{w: os.Stderr, quiet: o.quiet, total: size}
	_, uerr := e.client().UploadRated(e.cmdCtx, o.remote, f, size, func(cur int64) { pr.show(cur, "上传") }, rate)
	if uerr != nil {
		return e.mapErr(uerr, putDir, 0)
	}
	pr.done("上传")
	fmt.Fprintf(os.Stderr, "已上传 %s → %s（%s）\n", o.local, o.remote, humanBytes(size))
	return nil
}

// ---- 错误面三层与流终结归因（1.3，design D5）----

// mapErr 把命令错误翻成 CLI 可行动文案。归因次序（两层信号先到先解释）：
// ① 命令级取消（Ctrl-C——signal ctx 已 done）② 首响应（问候帧）超预算（看门置位）
// ③ 流终结三态（streamend.Error，读写两方向同判型——读方向经 files.Error 的
// Unwrap 链、写方向经 daemon 适配层归一）④ files 协议错误码逐码清单。
func (e *cliEnv) mapErr(err error, dir string, received int64) error {
	if err == nil {
		return nil
	}
	// ① 取消：CLI 自己的 signal ctx 先到先解释（get/put 中途 Ctrl-C）。
	if cerr := e.cmdCtx.Err(); cerr != nil {
		if dir == getDir {
			return fmt.Errorf("已取消（收到 %s，本地无残留，可直接重试）： %w", humanBytes(received), err)
		}
		if dir == putDir {
			return fmt.Errorf("已取消、远端未收完整（服务端已清理 .tierpart，远端目标不变）：%w", err)
		}
		return fmt.Errorf("已取消：%w", err)
	}
	// ② 首响应超预算：看门因预算烧尽 Close 过且问候帧未回（r3 新-10 归因——超时
	// 不呈现成 conn 态「连接断开」）。
	if e.phase.timedOut.Load() && !e.phase.greeted.Load() {
		return fmt.Errorf("首响应（问候帧）超预算：对端未在 --timeout（%s）内回问候帧——files 服务被占或半死；可加大 --timeout 或检查对端（原错误：%v）",
			e.t.timeout, err)
	}
	// ③ 流终结三态（get/put 中途可区分文案：get 提示已收字节与可重试、put 提示
	// 远端已按取消清理）。
	var se *streamend.Error
	if errors.As(err, &se) {
		base := streamEndMessage(se.Reason)
		switch dir {
		case getDir:
			return fmt.Errorf("%s；已收 %s，本地无残留、可直接重试（%v）", base, humanBytes(received), err)
		case putDir:
			return fmt.Errorf("%s；远端已按取消语义清理（.tierpart 已删、目标不变）（%v）", base, err)
		}
		return fmt.Errorf("%s（%v）", base, err)
	}
	// ④ files 协议错误码逐码清单（协议 7 码 + stream_open + 客户端自产码）。
	var fe *Error
	if errors.As(err, &fe) {
		return fmt.Errorf("%s（%s）", codeMessage(fe.Code, fe.Msg), fe.Code)
	}
	return err
}

// streamEndMessage 流终结三态的 files CLI 文案（design D4；与 term 面各自翻、互不依赖）。
func streamEndMessage(reason string) string {
	switch reason {
	case streamend.Gone:
		return "流被守护进程收流（主机不可达，或上行持续过快超出每流缓冲 40 帧/640KiB）"
	case streamend.Closed:
		return "对端已关闭（files 服务收工）"
	case streamend.Conn:
		return "与守护进程的连接断开"
	}
	return "流已终结（" + reason + "）"
}

// codeMessage 协议错误码 → CLI 语境中文（文案对齐 App 同码但按 CLI 重写；归码细目：
// invalid_arg = 非法字符/`..` 段；not_found = 不存在或符号链接越根「不存在或不允许
// 访问」；is_dir 仅 read/get——put 到已存在目录 = op_failed 如实标注）。
func codeMessage(code, msg string) string {
	switch code {
	case "invalid_arg":
		return "路径不合法（含非法字符或 .. 越界段）：" + msg
	case "invalid_name":
		return "名字不合法：" + msg
	case "not_found":
		return "不存在或不允许访问：" + msg
	case "permission":
		return "拒绝访问（权限不足）：" + msg
	case "is_dir":
		return "是目录（read/get 只支持文件）：" + msg
	case "already_exists":
		return "同名条目已存在：" + msg
	case "op_failed":
		return "操作失败：" + msg
	case CodeStreamOpen:
		return "files 服务不可达（流开场失败——拨号后未收到问候帧或即断）：" + msg
	case "canceled":
		return "已取消：" + msg
	}
	return msg + "（" + code + "）"
}

// ---- 上行限速：令牌桶（1.4，design D5）----

// resolveRateLimit --rate-limit 解析值 → 实际应用值：缺省（-1，未给 flag）= 保守
// 默认 DefaultRateLimit；显式 0 = 不限（风险自担）；正值原样。
func resolveRateLimit(flag int64) int64 {
	if flag < 0 {
		return DefaultRateLimit
	}
	return flag
}

// tokenBurstCap 桶的**停顿后补充上限**（exec-r1 F2，2026-09-30）：独立于 rate 的
// 常量，取守护进程每流窗口 640KiB（40 帧×16KiB）的一半以下。旧口径「补充上限 =
// rate（1 秒的量）」只对空桶起步成立——稳态背靠背发送 tokens≈0（每帧恰花光），但
// 读发循环一旦出现 >0.3s 停顿（本地盘/慢 stderr/调度），桶会按 rate 补满，随后一次
// 性灌出 >640KiB 突刺——正是 v0.12.1 空桶起步修掉的失效模式的复活路径。压到窗口
// 一半以下后「任意时刻可立即灌入的增量 ≤ burstCap」恒真，稳态吞吐不受影响（稳态
// tokens≈0，只在停顿后削峰）。
const tokenBurstCap = 256 << 10 // 256KiB < 640KiB/2

// newTokenBucket 构造令牌桶。rate ≤ 0 = 不限（返回 nil 接口值等价处理——await 直通）。
// **初始令牌 = 0（纯节拍起步，2026-09-30 v0.12.1 修正）**：首版「桶满起步
// （burst = rate）」在慢腿上自毁——默认 2MiB/s 的首秒 2MiB 全速突刺远超守护进程
// 每流 640KiB 窗口 ⇒ WAN 腿 0.04s 内被收流（真机实测：100MiB put 对阿里云腿 gone、
// 桶 512KiB 同链路反而 63s 全程通过）。盲节流的安全条件 = 任意时刻的在途增量不超
// 窗口余量，突刺与匀速同受此约束；空桶起步的第一帧只多等 16KiB/rate（默认 8ms），
// 吞吐代价可忽略。补充上限 = min(rate, tokenBurstCap)（见 tokenBurstCap 注释）。
func newTokenBucket(rate int64) UploadLimiter {
	if rate <= 0 {
		return nil
	}
	burst := int64(tokenBurstCap)
	if rate < burst {
		burst = rate // 小速率下补充上限不超过 rate 本身（否则节拍失真）
	}
	return &tokenBucket{rate: rate, burst: burst, tokens: 0, last: time.Now()}
}

// tokenBucket 发送端速率义务的载体：**无 ack/credit 下的盲节流**（协议 write 方向
// 无回压信号；守护进程每流缓冲 = upC 8 + 工位 32 = 40 帧（16KiB 帧）= 640KiB，越界
// **即时**收流〔finish(gone)——非停滞上限超时〕。安全条件 = 发送速率 ≤ 隧道+远端
// 写入的排空速率；固定默认值必须取最慢预期腿之下（快腿绿不能当安全速率证据）。
// **补充上限 = burst（= min(rate, 256KiB)，窗口一半以下；exec-r1 F2），起步恒为
// 空桶**（见 newTokenBucket/tokenBurstCap 注释）。
type tokenBucket struct {
	rate   int64 // bytes/s
	burst  int64 // 停顿后补充上限（tokens 高水位；≤ min(rate, tokenBurstCap)）
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

// Await 为 n 字节的发送配额等待（每帧发送前调用；sleep 粒度 = 攒够本帧的差额）。
// ctx 取消即时打断等待并返回 ctx.Err()（exec-r1 F5，2026-09-30）：time.Sleep 不可
// 打断，小速率下单帧等待可达秒级（--rate-limit 1024 下 16KiB 帧 = 16s），Ctrl-C
// 退出不应被拖到单帧等待烧尽——由上传循环收流取消。
func (b *tokenBucket) Await(ctx context.Context, n int) error {
	for {
		b.mu.Lock()
		now := time.Now()
		b.tokens += now.Sub(b.last).Seconds() * float64(b.rate)
		if b.tokens > float64(b.burst) {
			b.tokens = float64(b.burst)
		}
		b.last = now
		if float64(n) <= b.tokens {
			b.tokens -= float64(n)
			b.mu.Unlock()
			return nil
		}
		need := (float64(n) - b.tokens) / float64(b.rate)
		b.mu.Unlock()
		if err := sleepCtx(ctx, time.Duration(need*float64(time.Second))); err != nil {
			return err
		}
	}
}

// sleepCtx 可被 ctx 取消打断的 sleep（F5）；d ≤ 0 时只查一次 ctx。
func sleepCtx(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
