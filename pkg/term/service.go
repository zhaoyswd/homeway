//go:build !windows

// term_service.go — 出口侧的终端服务：会话注册表 + PTY + 帧协议。
//
// 设计要点（见 openspec exit-terminal 设计 D3–D8）：
//   - **会话由出口持有**：客户端断开只摘泵、不杀进程；重进 attach 先回放有界历史。
//   - 默认开启（只要服务里有 exit-node）、零 CLI 旗标；调参走 HOMEWAY_TERM_* 环境变量。
//   - 历史是**输出字节环**（不存输入）⇒ 回放不会重复用户敲过的命令；
//     回放窗口 = 尾部优先 + 时间预算，起点对齐行边界/ESC，attach 完成后用**尺寸哨兵**逼 TUI 重绘。
//   - 私有模式位与 OSC 标题由旁路扫描器维护（term_modes.go），随 ATTACHED/STATE 下发。
//   - 资源回收四步硬规则：Wait → 关 master → 删注册表 → 释放历史（缺一会漏 fd/僵尸）。
package term

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/creack/pty"
	"github.com/zhaoyswd/homeway/pkg/term/manifest"
)

// termPlatformSupported 报告本平台是否支持终端服务（unix = 是；windows 见 *_windows.go）。
func termPlatformSupported() bool { return true }

const (
	termDefaultPort        = 7724
	termDefaultHistory     = 1 << 20   // 每会话保留的输出字节
	termDefaultReplay      = 256 << 10 // attach 时回放窗口上限
	termDefaultMaxSessions = 16
	termDefaultMaxClients  = 8 // 每会话腿数上限（term-host-cli 任务 2.4，HOMEWAY_TERM_MAX_CLIENTS）

	termReplayBudget  = 2 * time.Second
	termWriteTimeout  = 10 * time.Second
	termHelloTimeout  = 15 * time.Second
	termKillGrace     = 500 * time.Millisecond
	termSamplePeriod  = time.Second
	termReplayTrim    = 4096             // 起点对齐时最多前看这么多字节
	termRawStallLimit = 60 * time.Second // raw 腿连续停滞多久才断腿（任务 4.2）
	termRawStallRetry = time.Second      // 停滞退避的重试节拍（停滞上限的 1/4 内自适应缩短）

	// 单帧/队列上限的默认值（exec-r1 中4：经 HOMEWAY_TERM_PENDING_CAP_BYTES /
	// HOMEWAY_TERM_QUEUE_BYTES 可注入，测试用小上限驱动真实失败路径）。
	termDefaultPendingCap = perLegPendingCap
	termDefaultQueueBytes = perLegQueueBytes
)

var termNameRx = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// termConfig 服务配置（全部来自环境变量，默认值即可用）。
type termConfig struct {
	port        uint16
	shell       string // 空 = 用户登录 shell
	history     int
	replay      int
	replayEpoch string // all | last
	maxSessions int
	// maxClients 是每会话腿数上限（HOMEWAY_TERM_MAX_CLIENTS，任务 2.4；满则优先淘汰
	// 失活/最久空闲腿，显式接管 attach -d 始终可用）。
	maxClients int
	// writeTimeoutMs / rawStallLimitMs / pendingCapBytes / queueBytes 是 raw 写者停滞
	// 语义与 surface 背压的参数（exec-r1 高2/中4：会话级可注入——HOMEWAY_TERM_
	// WRITE_TIMEOUT_MS / HOMEWAY_TERM_STALL_LIMIT_MS / HOMEWAY_TERM_PENDING_CAP_BYTES /
	// HOMEWAY_TERM_QUEUE_BYTES，默认值即上面的常量；普通用户不需要知道它们）。
	writeTimeoutMs  int
	rawStallLimitMs int
	pendingCapBytes int
	queueBytes      int
	detect          bool
	// scrollbackLines 服务端 vt 的回滚行数上限（HOMEWAY_TERM_SCROLLBACK_LINES，默认 10000）。
	//
	// **内存预算口径（任务 1.3 定，7.4 验收）**：每会话常驻 ≈ 1MiB 字节环（history）+ vt 峰值
	// （回滚行数上限 × 每行 cell 开销，含样式/字素簇；粗算 10000 行 × 视口宽 × ~16B ≈ 十几 MiB
	// 量级的最坏值，实测曲线看 7.4）；整服务上限 = maxSessions（默认 16）× 每会话常驻。
	// 所以调大回滚行数要连带看会话上限——两个都是乘法项。
	scrollbackLines int
}

// termDisabledByEnv：HOMEWAY_TERM=off 是唯一的关闭方式（刻意不做 CLI 旗标）。
func termDisabledByEnv() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("HOMEWAY_TERM")), "off")
}

func termEnvInt(name string, def int) int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func termConfigFromEnv() termConfig {
	cfg := termConfig{
		port:            uint16(termEnvInt("HOMEWAY_TERM_PORT", termDefaultPort)),
		shell:           strings.TrimSpace(os.Getenv("HOMEWAY_TERM_SHELL")),
		history:         termEnvInt("HOMEWAY_TERM_HISTORY", termDefaultHistory),
		replay:          termEnvInt("HOMEWAY_TERM_REPLAY", termDefaultReplay),
		replayEpoch:     strings.ToLower(strings.TrimSpace(os.Getenv("HOMEWAY_TERM_REPLAY_EPOCH"))),
		maxSessions:     termEnvInt("HOMEWAY_TERM_MAX_SESSIONS", termDefaultMaxSessions),
		maxClients:      termEnvInt("HOMEWAY_TERM_MAX_CLIENTS", termDefaultMaxClients),
		writeTimeoutMs:  termEnvInt("HOMEWAY_TERM_WRITE_TIMEOUT_MS", int(termWriteTimeout/time.Millisecond)),
		rawStallLimitMs: termEnvInt("HOMEWAY_TERM_STALL_LIMIT_MS", int(termRawStallLimit/time.Millisecond)),
		pendingCapBytes: termEnvInt("HOMEWAY_TERM_PENDING_CAP_BYTES", termDefaultPendingCap),
		queueBytes:      termEnvInt("HOMEWAY_TERM_QUEUE_BYTES", termDefaultQueueBytes),
		detect:          !strings.EqualFold(strings.TrimSpace(os.Getenv("HOMEWAY_TERM_DETECT")), "off"),
		scrollbackLines: termEnvInt("HOMEWAY_TERM_SCROLLBACK_LINES", vtDefaultScrollbackLines),
	}
	if cfg.replayEpoch != "last" {
		cfg.replayEpoch = "all"
	}
	if cfg.replay > cfg.history {
		cfg.replay = cfg.history
	}
	// 低9（exec-r1）：防御性夹取——termEnvInt 对 ≤0 已回默认值，这里再夹一层，
	// 保证「腿数上限 0 导致完全无法接入」这类误配置在配置层就不可达。
	if cfg.maxClients < 1 {
		cfg.maxClients = termDefaultMaxClients
	}
	if cfg.pendingCapBytes < 1024 {
		cfg.pendingCapBytes = termDefaultPendingCap
	}
	if cfg.queueBytes < 4096 {
		cfg.queueBytes = termDefaultQueueBytes
	}
	return cfg
}

// warnInvalidTermEnv 对「设置了但非法」的 HOMEWAY_TERM_* 调参给一行提示（普通用户
// 不需要知道这些变量，误设时至少能在日志里看到被忽略了）。
func warnInvalidTermEnv(logf Logf) {
	if logf == nil {
		return
	}
	for _, c := range []struct {
		name string
		min  int
	}{
		{"HOMEWAY_TERM_MAX_CLIENTS", 1},
		{"HOMEWAY_TERM_WRITE_TIMEOUT_MS", 1},
		{"HOMEWAY_TERM_STALL_LIMIT_MS", 1},
		{"HOMEWAY_TERM_PENDING_CAP_BYTES", 1024},
		{"HOMEWAY_TERM_QUEUE_BYTES", 4096},
	} {
		v := strings.TrimSpace(os.Getenv(c.name))
		if v == "" {
			continue
		}
		if n, err := strconv.Atoi(v); err != nil || n < c.min {
			logf("term: ⚠️ %s=%q 非法（需 ≥%d），已忽略、用默认值", c.name, v, c.min)
		}
	}
}

// ---- 登录 shell 与登录环境：与「用户自己开一个终端」对齐 ----
//
// 出口进程常由 launchd / systemd / docker 拉起，继承的是**服务环境**：里面有
// XPC_SERVICE_NAME、OSLogRateLimit 这类只在服务上下文里成立的变量，$SHELL 也可能缺失
//（真机实测：LaunchAgent 拉起的出口，会话里带 XPC_SERVICE_NAME=me.zhaozhe.tailcat-exit、
// 没有 TERM_PROGRAM，而 SHELL 一旦缺失就会掉到 /bin/sh）。原样交给 PTY 里的 shell，
// 用户拿到的就是一个「像服务、不像终端」的环境。所以这里对齐三件事：
//
//  1. 选**账号数据库里的登录 shell**（macOS dscl / 其它 unix /etc/passwd），
//     逐级回退 $SHELL → 平台默认；候选项都要求可执行。
//  2. 只把「用户身份 + 临时目录 + 语言 + agent socket」白名单变量交给子进程，
//     服务变量一律不带（XPC_*/OSLogRateLimit/__CF*…）。
//  3. 终端标记（TERM/COLORTERM/TERM_PROGRAM[/_VERSION]/TERM_SESSION_ID）由我们写，
//     让会话里跑的工具知道自己在一个名为 Tailcat 的终端里（TERM_PROGRAM 是 Terminal/iTerm/vscode 的惯例）。
//
// 之后一律以**登录 shell** 起（默认 `shell -l`；命令模式 `shell -lc '<命令>'`）：
// PATH、brew、pnpm 等由用户自己的 /etc/zprofile → ~/.zprofile → ~/.zshrc 决定 ——
// 和用户直接开终端走同一条路径，用户改 rc 之后下一个会话即生效。

// termPlatformShells 平台默认 shell 候选（账号数据库与 $SHELL 都拿不到时的最后回退）。
func termPlatformShells() []string {
	if runtime.GOOS == "darwin" {
		return []string{"/bin/zsh", "/bin/bash", "/bin/sh"}
	}
	return []string{"/bin/bash", "/bin/sh"}
}

// termAccountShell 从账号数据库取该用户的登录 shell（取不到返回空串）。
func termAccountShell() string {
	name := strings.TrimSpace(os.Getenv("USER"))
	if name == "" {
		name = strings.TrimSpace(os.Getenv("LOGNAME"))
	}
	if name == "" {
		if u, err := user.Current(); err == nil {
			name = u.Username
		}
	}
	if name == "" {
		return ""
	}
	if runtime.GOOS == "darwin" {
		// macOS 本地账号在 Open Directory 里，/etc/passwd 通常查不到（本机实测：
		// `grep zhaozhe /etc/passwd` 无输出，必须问 dscl）。
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "/usr/bin/dscl", ".", "-read", "/Users/"+name, "UserShell").Output()
		if err != nil {
			return ""
		}
		s := strings.TrimSpace(string(out))
		if i := strings.LastIndex(s, ":"); i >= 0 {
			s = strings.TrimSpace(s[i+1:])
		}
		return s
	}
	raw, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 7 && f[0] == name {
			return strings.TrimSpace(f[6])
		}
	}
	return ""
}

// termExecutable 判定候选 shell 是否真的可执行（不存在/目录/无 x 位都不行）。
func termExecutable(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir() && st.Mode()&0o111 != 0
}

// pickShell 取第一个可执行的候选；全不可执行时返回首个非空候选
// （宁可让 spawn 明确失败，也不静默换一个用户没选的 shell）。
func pickShell(cands ...string) string {
	first := ""
	for _, c := range cands {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if first == "" {
			first = c
		}
		if termExecutable(c) {
			return c
		}
	}
	if first != "" {
		return first
	}
	return "/bin/sh"
}

// loginShell 解析顺序：账号数据库 > $SHELL（服务环境）> 平台默认。
func loginShell() string {
	return pickShell(append([]string{termAccountShell(), strings.TrimSpace(os.Getenv("SHELL"))},
		termPlatformShells()...)...)
}

// termEnvKeep 从服务环境里**白名单**保留的变量：身份、家目录、临时目录、语言、PATH。
// SSH_AUTH_SOCK 保留是有意的：macOS 的 Terminal 会话同样带一个 launchd 的 per-user
// listener socket，留着 ssh-agent 转发才继续可用。
var termEnvKeep = []string{
	"HOME", "USER", "LOGNAME", "TMPDIR", "SSH_AUTH_SOCK", "PATH",
	"LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES",
}

func termEnvKept(k string) bool {
	for _, want := range termEnvKeep {
		if k == want {
			return true
		}
	}
	return false
}

// termDefaultPATH 服务环境里没有 PATH 时的平台默认值。
func termDefaultPATH() string {
	if runtime.GOOS == "darwin" {
		return "/usr/bin:/bin:/usr/sbin:/sbin"
	}
	return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
}

// termEnvLookup 在 []string 形态的环境里取值（取不到返回空串）。
func termEnvLookup(env []string, key string) string {
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return v
		}
	}
	return ""
}

// termLoginEnv 构造 PTY 子进程环境：白名单 + 强制终端标记（详见本节开头）。
func termLoginEnv(shell, sessionID string) []string {
	env := make([]string, 0, len(termEnvKeep)+8)
	havePATH, haveHOME := false, false
	for _, kv := range os.Environ() {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || v == "" || !termEnvKept(k) {
			continue
		}
		switch k {
		case "PATH":
			havePATH = true
		case "HOME":
			haveHOME = true
		}
		env = append(env, kv)
	}
	if !haveHOME {
		if u, err := user.Current(); err == nil && u.HomeDir != "" {
			env = append(env, "HOME="+u.HomeDir)
		}
	}
	if !havePATH {
		env = append(env, "PATH="+termDefaultPATH())
	}
	env = append(env,
		"SHELL="+shell, // 解析出的登录 shell，覆盖服务环境里的值
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
		"TERM_PROGRAM=Tailcat",
		"TERM_PROGRAM_VERSION="+forkBuildTag(),
		"TERM_SESSION_ID="+sessionID,
	)
	return env
}

type termService struct {
	cfg       termConfig
	logf      Logf
	stopCh    chan struct{}
	closeOnce sync.Once
	// manifests 是 agent 检测规则表（nil = HOMEWAY_TERM_DETECT=off，不做屏幕证据）。
	manifests *manifest.Loader

	mu       sync.Mutex
	sessions map[string]*termSession
}

// New 起终端服务。stateDir 是出口 state 目录（本地 manifest 覆盖目录在
// <stateDir>/agent-detection/；空串 = 只用内嵌 manifest）。
func New(logf Logf, stateDir string) *termService {
	s := &termService{
		cfg:      termConfigFromEnv(),
		logf:     logf,
		stopCh:   make(chan struct{}),
		sessions: map[string]*termSession{},
	}
	warnInvalidTermEnv(logf)
	// 剪贴板写回调是**进程级**的（上游只给 userdata id）⇒ 全局装一次，按 id 分派到会话。
	installClipboardForwarder()
	if s.cfg.detect {
		override := ""
		if stateDir != "" {
			override = filepath.Join(stateDir, manifest.OverrideDirName)
		}
		s.manifests = manifest.NewLoader(override)
		if logf != nil {
			for _, w := range s.manifests.Warnings() {
				logf("term: ⚠️ 检测规则加载告警：%s", w)
			}
			logf("term: 检测规则已加载 %d 份（覆盖目录 %s）", len(s.manifests.IDs()), overrideDesc(override))
		}
	}
	go s.sampleLoop()
	return s
}

func overrideDesc(dir string) string {
	if dir == "" {
		return "无（只用内嵌）"
	}
	return dir
}

func (s *termService) Port() uint16      { return s.cfg.port }
func (s *termService) ShellText() string { return loginShell() }

// Disabled 报告环境变量是否显式关闭了终端服务（HOMEWAY_TERM=off）。
func Disabled() bool { return termDisabledByEnv() }

// VTText 报告服务端 vt 的现状（就绪行与诊断用）：off = 环境变量全局关闭，none = 本构建不带。
func VTText() string {
	if vtGloballyDisabled() {
		return "off（HOMEWAY_TERM_VT）"
	}
	return "on"
}

// FeaturesText 本构建支持的终端能力位（就绪行里打出来，供运维核对）。
func FeaturesText() string {
	out := make([]string, 0, 5)
	if termFeatures&featList != 0 {
		out = append(out, "list")
	}
	if termFeatures&featReplay != 0 {
		out = append(out, "replay")
	}
	if termFeatures&featModes != 0 {
		out = append(out, "modes")
	}
	if termFeatures&featAgent != 0 {
		out = append(out, "agent")
	}
	if termFeatures&featTitle != 0 {
		out = append(out, "title")
	}
	if termFeatures&featSurfaceBit != 0 {
		out = append(out, "surface")
	}
	return strings.Join(out, ",")
}

func (s *termService) HistoryText() string {
	return fmt.Sprintf("%dKiB", s.cfg.history>>10)
}

// Close 关停服务：全部会话走同一回收路径（不影响其它服务）。
func (s *termService) Close() {
	s.closeOnce.Do(func() {
		close(s.stopCh)
		s.mu.Lock()
		list := make([]*termSession, 0, len(s.sessions))
		for _, ss := range s.sessions {
			list = append(list, ss)
		}
		s.mu.Unlock()
		for _, ss := range list {
			ss.finish(termEndServiceStopped, "service_stopped")
		}
	})
}

// ---- 会话 ----

type termEpoch struct {
	off        int64
	cols, rows uint16
}

type termSession struct {
	svc     *termService
	name    string
	created time.Time
	pid     int

	mu      sync.Mutex
	ptmx    *os.File
	cmd     *exec.Cmd
	ring    []byte
	start   int64 // ring[0] 对应的绝对偏移
	written int64 // 累计输出字节数（ring 末端）
	epochs  []termEpoch
	scan    termScan
	// vt 是会话屏态的唯一持有者（surface/检测的真源）；nil = 本会话 legacy-only。
	// 由 term_vt.go / term_vt_off.go 按构建提供（design D1/D7）。
	vt *sessionVT
	// contentSeq 每批 PTY 输出自增：状态机卫生用它做「空闲会话零开销」的短路判据（任务 4.7）。
	surfaceWake chan struct{}
	// clipCachePub 是剪贴板读缓存的原子发布副本（= active 腿最近上报，任务 3.3）：剪贴板读
	// 回调在 vt.Write 内部同步触发（此时会话锁被 pump 持有），**不能取会话锁**。
	clipCachePub atomic.Pointer[string]
	lastNotified string
	// vtID 是服务端 vt 在回调注册表里的 id（剪贴板回调按它分派）。
	vtID uintptr
	// surfaceActive 是「当前有 surface 腿」的无锁标志（剪贴板回调在锁内触发，只能读原子量；
	// 由腿集合派生，任务 2.1b）。
	surfaceActive atomic.Bool
	// clipChan 承接程序写剪贴板的内容（锁外投递，见 clipboardRouter；只发 surface 腿）。
	clipChan chan string
	// surfaceStop 是会话级收工信号（finish 时 close）：surfaceLoop 据此退出。
	surfaceStop chan struct{}

	// ---- 多腿会话模型（term-host-cli 任务组 2；见 term_leg.go）----
	// legs 是在场腿集合（raw 与 surface 混合）；变更只发生在会话锁内的 attach/detach 路径。
	legs []*termClient
	// writers = 在跑的腿写者数（r5 M1：历史环的生命周期延长到最后一个写者退出——
	// endLegLocked 只把腿摘出 legs 表，写者还要把 ENDED/尾部字节送完才退）。
	writers int
	// active 是最近活动的腿（尺寸/主题/剪贴板读缓存的归属，design D4）。
	active *termClient
	// activitySeq 是活动到达序号（单调递增，不用墙钟——NTP 步进会翻转排序）。
	activitySeq uint64
	// attachSeq 是接入序号（tie-break「更晚接入者优先」用，design D4）。
	attachSeq uint64
	// rawTermLegs 是声明了 capsRawTerminal 的腿数（查询应答让位的判据，任务 5.1）。
	rawTermLegs int
	// responseFn 是服务端代答的接收方（spawn 时初始化为写 ptmx；updateResponseSinkLocked
	// 按腿况在它与 nil 之间切换——拆成字段是为了窄规则可单测：假 sink 计数，任务 5.1）。
	responseFn func([]byte)
	// 会话级写者/背压参数（exec-r1 高2/中4：spawn 时从 cfg 注入；cfg 在 New 后不变，
	// 写者 goroutine 并发只读安全）。
	writeTimeout  time.Duration // raw 腿写超时（= 停滞判定阈值）
	rawStallLimit time.Duration // raw 腿连续停滞多久断腿
	pendingCap    int           // surface 单帧（未压缩体）上限
	queueBytes    int           // surface 每腿队列上限
	// sentinelCount 是尺寸哨兵注入次数（低7 判据计数器：一次 attach 应恰 +1；
	// 只在 sentinelRepaintLocked 里自增，会话锁保护）。
	sentinelCount int

	contentSeq     uint64
	lastScanSeq    uint64
	lastScanProc   string // 上一次扫屏时的前台 agent 进程名（短路判据的「agent 变化」用）
	hygiene        stateHygiene
	lastScreenRule string // 上一拍命中的规则 id（agent 变化时用于清证据判定）
	agent          byte
	// stateV2 是状态唯一口径（term-remote 3.3：legacy 折价字段已删，STATE/LIST 对
	// 所有腿统一本枚举——值域见 agent.go）。
	stateV2   byte
	prevCPU   int64
	prevQuiet int // 截至上一采样的连续安静拍数（classifyAgent 磁滞输入）
	// outBuckets：按绝对秒键的输出字节桶（定长环形，countOutLocked 写、
	// outBytesLocked 求窗口和）——输出腿的数据源，见 term_agent.go 阈值注释。
	outBuckets [4]outBucket
	lastOut    time.Time
	lastActive time.Time
	cols, rows uint16
	done       bool
	killed     bool // App 主动 KILL（ENDED 的 code 用 termEndKilled 而不是信号退出码）
	exitCode   int32
	waitOnce   sync.Once
}

// outBucket 一秒的输出字节数（sec 是 Unix 秒）。
type outBucket struct {
	sec int64
	n   int64
}

// countOutLocked 把一批 PTY 输出记进当前秒的桶（没有就抢占最旧的）。必须持 mu。
func (s *termSession) countOutLocked(n int, now time.Time) {
	sec := now.Unix()
	for i := range s.outBuckets {
		if s.outBuckets[i].sec == sec {
			s.outBuckets[i].n += int64(n)
			return
		}
	}
	oldest := 0
	for i := range s.outBuckets {
		if s.outBuckets[i].sec < s.outBuckets[oldest].sec {
			oldest = i
		}
	}
	s.outBuckets[oldest] = outBucket{sec: sec, n: int64(n)}
}

// outBytesLocked 近 agentOutWindowSec 秒的输出字节总和（含当前秒）。必须持 mu。
// 空闲秒没有桶（值为 0），跨秒空洞天然正确——只按 sec 比较即可。
func (s *termSession) outBytesLocked(now time.Time) int64 {
	floor := now.Unix() - int64(agentOutWindowSec) + 1
	var sum int64
	for i := range s.outBuckets {
		if s.outBuckets[i].sec >= floor {
			sum += s.outBuckets[i].n
		}
	}
	return sum
}

// termClient 一条已 attach 的腿（term-host-cli 起多腿：raw 与 surface 混合）。
//
// 字段归属：conn/out/off 归本腿写者（term_leg.go，D10-2/3）；cols/rows/lastActivitySeq/
// clientID/removed 归会话锁；kind 是接入时定死的只读值。
type termClient struct {
	conn net.Conn
	wmu  sync.Mutex // 单帧不撕裂（写者唯一后基本只剩防御意义；一锤子连接 LIST/KILL 仍直用）
	off  int64      // raw 腿的字节环偏移（**只由本腿写者推进**，D10-2）
	// torn/tornWhole 是写超时留下的断尾（帧前半已进内核；writeFrameOnce 跨调用
	// 续完——2026-09-30 进度感知续写，见 term_leg.go）。只写者 goroutine 读写、
	// wmu 内；tornWhole 供「调用方重试的是否同一帧」的逐字节判等。
	torn, tornWhole []byte
	// out 是本腿的出站队列与写者唤醒（见 term_leg.go）。
	out legOut
	// handshake 是 raw 腿的握手计划（写者执行；surface 腿为 nil）。
	handshake *rawHandshake
	// leg 是 surface 投递状态（仅 surface 腿非 nil）。
	leg *surfaceLeg
	// surface 表示这条腿声明了 surface 能力（任务 2.1 的能力协商置位）。状态信令
	// 自 term-remote 3.3 起对 surface 与 raw 腿统一 stateV2 枚举（不再按腿分流折价），
	// 该位仍用于 surface 帧面（快照/差分/抽象输入）与应答代答的判别。
	surface bool
	// rawCapable：capability 块声明了 capsRawTerminal（真实终端客户端；应答让位与
	// kind=host 的判据，任务 5.1 / 2.5）。
	rawCapable bool
	// kind 是腿的呈现分类：app（surface）/ host（声明 raw 终端）/ legacy（旧 App raw 腿）。
	kind string
	// clientID 是客户端实例标识（HELLO 尾随 ID 块；空 = 未携带）。语义边界 = 「同一实例
	// 连续重连」替换自身旧腿（design D3）；跨实例的旧腿靠连接关闭 + 上限策略回收。
	clientID string
	// takeover：HELLO flags bit2（attach -d 显式接管：其它腿收 ENDED(replaced)）。
	takeover bool

	// ---- 会话锁保护的字段 ----
	cols, rows      uint16
	lastActivitySeq uint64 // 最近活动的到达序号（选举输入）
	attachSeq       uint64 // 接入序号（tie-break 用）
	since           time.Time
	lastTouch       time.Time // 最近活动墙钟（上限淘汰的「最久空闲」排序用）
	removed         bool
	// 每腿主题/剪贴板缓存（active 腿的值落到会话 vt / 读缓存，任务 3.3）。
	themeKnown       bool
	themeFg, themeBg [3]uint8
	clipCache        string
}

// stateForLeg 已随状态单轨化退役（term-remote 3.3，D6）：surface 与 raw 腿的
// STATE/ATTACHED state 字节统一 stateV2 枚举，不再按腿类折价。

// frame 握手/一锤子帧的写路径（GREETING/LIST/KILL/CREATE/HELLO 应答等——写者
// goroutine 尚未启动，由 serving goroutine 直发）。exec-r1 F7 起统一走 writeFrameOnce：
// 部分写（deadline 过期时 net.Conn.Write 可返回 n>0+timeout）会留断尾记录，后续帧
// （含 HELLO 成腿后写者 goroutine 的帧——同一 termClient 同一把 wmu 天然串行）先续
// 完旧尾再写新帧，消除「半帧之后拼新帧」的帧界失步；调用方语义不动（错误照旧上抛）。
func (c *termClient) frame(op byte, payload []byte) error {
	return c.writeFrameOnce(op, payload, termWriteTimeout)
}

func (c *termClient) close() { _ = c.conn.Close() }

// ---- 历史环 ----

// appendLocked 把输出写进**定长环**：ring 长度即历史上限，written 是累计字节数（绝对偏移），
// start = written - min(written, len(ring)) 是最旧可用字节的绝对偏移。
func (s *termSession) appendLocked(p []byte) {
	capBytes := len(s.ring)
	if capBytes == 0 {
		return
	}
	for len(p) > 0 {
		pos := int(s.written % int64(capBytes))
		n := copy(s.ring[pos:], p)
		s.written += int64(n)
		p = p[n:]
	}
	if start := s.written - int64(capBytes); start > s.start {
		s.start = start
	}
}

// readLocked 取 [off, off+max) 的输出字节（超出历史区间就从头开始）。
func (s *termSession) readLocked(off int64, max int) []byte {
	if off < s.start {
		off = s.start
	}
	if off >= s.written || max <= 0 {
		return nil
	}
	if int64(max) > s.written-off {
		max = int(s.written - off)
	}
	capBytes := len(s.ring)
	if capBytes == 0 {
		return nil
	}
	out := make([]byte, 0, max)
	for len(out) < max {
		pos := int(off % int64(capBytes))
		avail := capBytes - pos
		if avail > max-len(out) {
			avail = max - len(out)
		}
		out = append(out, s.ring[pos:pos+avail]...)
		off += int64(avail)
	}
	return out
}

// replayStartLocked 选回放起点：尾部优先（replay 上限）→ 行边界 → ESC 起点 → 原样。
func (s *termSession) replayStartLocked() (start int64, truncated bool) {
	start = s.start
	if s.svc.cfg.replayEpoch == "last" && len(s.epochs) > 0 {
		if off := s.epochs[len(s.epochs)-1].off; off > start {
			start = off
			truncated = true
		}
	}
	if s.svc.cfg.replay > 0 && s.written-start > int64(s.svc.cfg.replay) {
		start = s.written - int64(s.svc.cfg.replay)
		truncated = true
	}
	head := s.readLocked(start, termReplayTrim)
	if len(head) == 0 {
		return start, truncated
	}
	if i := indexByte(head, '\n'); i >= 0 {
		return start + int64(i) + 1, truncated
	}
	if i := indexByte(head, 0x1b); i > 0 {
		return start + int64(i), truncated
	}
	return start, truncated
}

func indexByte(p []byte, b byte) int {
	for i := range p {
		if p[i] == b {
			return i
		}
	}
	return -1
}

// noteSizeLocked 记录一次尺寸变化（同时更新当前尺寸）。
func (s *termSession) noteSizeLocked(cols, rows uint16) {
	s.cols, s.rows = cols, rows
	s.epochs = append(s.epochs, termEpoch{off: s.written, cols: cols, rows: rows})
	if len(s.epochs) > 64 {
		s.epochs = s.epochs[len(s.epochs)-64:]
	}
}

// ---- 客户端投递（多腿；注册/摘除/写者见 term_leg.go，surface 编排见 term_surface_session.go）----

// pushStateLocked 发布一次状态到所有腿（每腿投递、按腿编码——raw 腿读它设标题/状态，
// 任务 2.1b；surface 区段外的 STATE 对两类腿都合法）。
func (s *termSession) pushStateLocked() {
	s.pushStateToLegsLocked()
}

// focusNudgeLocked 向 PTY 写一个终端焦点事件（仅当 TUI 开了 ?1004 焦点上报时才写，
// 不开的程序读到这些字节只会当普通输入——绝不能发给 bare shell）。
//
// 为什么需要它：attach 回放只是**字节环的尾部窗口**，TUI 空闲期的输出全是闪烁级
// 增量帧——回放灌进客户端的新 vt 后就是「空白屏 + 光标在位」（2026-09-18 真机：
// codex 会话打开全空，敲一个键立即恢复）。sentinelRepaint 的两次 SIGWINCH 对
// ratatui 系 TUI 不可靠（它们只标记 pending-resize，等下一个事件才全屏重绘）。
// focus-in 是标准终端事件：TUI 会立刻全屏重绘——「打开即有内容」由此确定成立。
// focus-out 同理在 detach 时写：TUI 停止动画（省电），空闲闪烁输出不再进字节环
// （会话状态的 running 闪烁噪声也随之消失）。
func (s *termSession) focusNudgeLocked(focusIn bool) {
	if s.done || s.ptmx == nil || s.scan.modes&termModeFocus == 0 {
		return
	}
	seq := []byte("\x1b[O") // focus-out
	if focusIn {
		seq = []byte("\x1b[I") // focus-in
	}
	if _, err := s.ptmx.Write(seq); err != nil && s.svc.logf != nil {
		s.svc.logf("term: 会话 %s focus nudge 写入失败：%v", s.name, err)
	}
}

// ---- 生命周期 ----

// finish 结束会话：所有腿经各自写者回 ENDED → 关 master → 等子进程 → 从注册表删除。
// reason < 0 表示服务侧原因（killed/replaced/service_stopped）；0 表示子进程自己退出。
func (s *termSession) finish(reason int32, text string) {
	s.mu.Lock()
	if s.done {
		s.mu.Unlock()
		return
	}
	s.done = true
	code := s.exitCode
	if s.killed {
		code = termEndKilled
	}
	if reason < 0 {
		code = reason
	}
	// ENDED 经每腿写者送达后再关 conn（任务 4.1：ENDED 先于 close；客户端可区分
	// 「被接管 / 会话结束 / 断链」——被接管与会话结束带 ENDED，断链是裸 EOF）。
	for _, c := range append([]*termClient{}, s.legs...) {
		s.endLegLocked(c, code, text, "finish")
	}
	ptmx := s.ptmx
	s.mu.Unlock()

	if ptmx != nil {
		_ = ptmx.Close()
	}
	// 等子进程收工。**必须有界**（2026-09-24 评审整改）：master 关闭通常会让子进程
	// 读到 EOF/收到 SIGHUP 而退出，但实测存在不响应的形态（评审期间用 `cat` 会话复现：
	// master 关了、子进程仍活着 ⇒ cmd.Wait() 永久阻塞 ⇒ 服务关停挂死）。
	// 这里给 2s 宽限，超时 SIGKILL 兜底；与 kill() 的 SIGHUP→宽限→SIGKILL 同一套语义。
	s.waitOnce.Do(func() {
		if s.cmd == nil {
			return
		}
		done := make(chan struct{})
		go func() {
			_ = s.cmd.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			if s.cmd.Process != nil {
				_ = s.cmd.Process.Kill()
			}
			<-done
		}
	})
	s.mu.Lock()
	if s.cmd != nil && s.cmd.ProcessState != nil {
		s.exitCode = int32(s.cmd.ProcessState.ExitCode())
	}
	if s.writers == 0 {
		// 释放历史缓冲。还有写者在跑时**不在这里释放**（r5 M1）：腿上可能还有未排干的
		// 尾部字节要赶在 ENDED 前送出——环改由最后退出的写者释放（writerExited）。
		s.ring = nil
	}
	s.mu.Unlock()
	if s.vtID != 0 {
		unregisterVTSession(s.vtID)
	}
	s.vt.Close() // 释放服务端 vt（幂等；无 vt 的构建是空操作）
	// 会话级收工：surfaceLoop 退出（否则每建删一个会话漏一个常驻 goroutine）。
	// finish 由 s.done 守卫，只会走到这里一次，close 不会重复。
	close(s.surfaceStop)

	s.svc.remove(s.name, s)
}

func (s *termService) remove(name string, who *termSession) {
	s.mu.Lock()
	if cur, ok := s.sessions[name]; ok && cur == who {
		delete(s.sessions, name)
	}
	s.mu.Unlock()
}

// pump 常驻读 PTY：写历史、喂扫描器、唤醒各腿写者（永远读，子进程才不会阻塞）。
// B'（design D5）：pump 在锁内**只做入队/唤醒**，绝不碰任何 socket——慢腿由各腿写者消化。
func (s *termSession) pump() {
	buf := make([]byte, 32<<10)
	for {
		n, err := s.ptmx.Read(buf)
		if n > 0 {
			s.mu.Lock()
			now := time.Now()
			s.appendLocked(buf[:n])
			s.scan.write(buf[:n])
			// 屏态 vt 与 ring 同锁喂入：ring 仍是 raw 回放源与诊断，vt 是 surface/检测真源。
			s.vt.Write(buf[:n])
			s.contentSeq++ // 内容序号：检测侧的空闲短路判据（任务 4.7）
			// surface 投递：只做唤醒（取快照/压缩/入队在投递循环里，绝不占着 pump 的锁）。
			if s.anySurfaceLocked() {
				s.wakeSurface()
			}
			s.countOutLocked(n, now)
			s.lastOut = now
			s.lastActive = now
			if s.scan.changed {
				s.scan.changed = false
				s.pushStateLocked()
				// 裸 OSC 9 通知转发（surface 腿）：双语义判别已在 termScan 里做完（9;4 是 progress）。
				if s.anySurfaceLocked() {
					go s.notifyFromScan()
				}
			}
			s.wakeRawLegsLocked()
			s.mu.Unlock()
		}
		if err != nil {
			break
		}
	}
	// 子进程退出 / PTY 关闭：收尸 → 统一收尾（ENDED + 回收四步）。
	s.waitOnce.Do(func() {
		if s.cmd != nil {
			_ = s.cmd.Wait()
		}
	})
	s.mu.Lock()
	code := int32(0)
	if s.cmd != nil && s.cmd.ProcessState != nil {
		code = int32(s.cmd.ProcessState.ExitCode())
	}
	s.exitCode = code
	s.mu.Unlock()
	s.finish(0, "")
}

// ---- 采样：agent / 任务状态 ----

func (s *termService) sampleLoop() {
	t := time.NewTicker(termSamplePeriod)
	defer t.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case now := <-t.C:
			s.sampleOnce(now)
		}
	}
}

func (s *termService) sampleOnce(now time.Time) {
	if !s.cfg.detect {
		return
	}
	procs := readProcs()
	s.mu.Lock()
	list := make([]*termSession, 0, len(s.sessions))
	for _, ss := range s.sessions {
		list = append(list, ss)
	}
	s.mu.Unlock()
	for _, ss := range list {
		ss.sample(now, procs)
	}
}

func (s *termSession) sample(now time.Time, procs []procInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done || s.ptmx == nil {
		return
	}
	fg := foregroundPgid(s.ptmx.Fd())
	agentChanged := false

	// 身份腿先跑：屏幕证据的短路判据要「agent 已知/是否变化」（任务 4.7）。
	// ⚠️ 2026-09-24 整改：旧实现这里紧跟一行 `agentChanged = s.agent != prevAgent`——s.agent
	// 此刻还没更新，那个赋值**恒为 false**（死代码），而 screenEvidenceLocked 拿到的是
	// 「上一拍身份 + 变化=false」。现在短路判据用**本拍前台进程名**与上次扫屏的进程名比
	// （见 screenEvidenceLocked），与 s.agent 的更新时机解耦。
	prevAgent := s.agent
	ev, scanned := s.screenEvidenceLocked(now, procs, fg)

	v := classifyAgent(agentProbe{
		procs:     procs,
		fgPgid:    fg,
		prevCPU:   s.prevCPU,
		outBytes:  s.outBytesLocked(now),
		prevState: s.stateV2,
		prevQuiet: s.prevQuiet,
		shellPID:  s.pid,
		now:       now,
		screen:    ev,
		oscStatus: s.scan.OSCStatus(),
	})
	if v.cpu >= 0 {
		s.prevCPU = v.cpu
	}
	s.prevQuiet = v.quiet
	if v.agent != prevAgent {
		// 前景 agent 变了：旧进程留下的 OSC 证据（progress / 21337 直报 / 标题的判定资格）
		// 不得参与新进程的判定（term-agent-state「agent 切换清证据」）。
		s.scan.clearOSCEvidence()
		agentChanged = true
	}
	if scanned {
		s.lastScanSeq = s.contentSeq
	}

	// 状态机卫生（任务 4.7）：working→普通 idle 先按住（确认窗），blocked 定期重发。
	processExited := v.agent == agentUnknown && v.stateV2 == stateV2Idle
	visibleIdle := ev != nil && ev.visibleIdle
	visibleBlocker := ev != nil && ev.visibleBlocker
	// skip_state_update（历史查看器/选择器类覆盖屏，manifest 规则位）：这类屏**不反映
	// agent 的真实状态** ⇒ 本拍冻结状态（保持上一拍），身份照常更新。规格明文要求
	// （term-agent-state「规则可带 skip_state_update（命中时冻结状态不更新）」）。
	freeze := ev != nil && ev.skipUpdate
	if freeze && v.agent == prevAgent {
		return // 覆盖屏 + 身份未变：整拍不发布（状态冻结，列表停在上一状态）
	}
	nextState := v.stateV2
	if freeze {
		nextState = s.stateV2 // 冻结：状态不动，只让身份变化这一支发布
	}
	if nextState != s.stateV2 {
		if s.hygiene.shouldHoldWorkingToIdle(s.stateV2, nextState, visibleIdle, visibleBlocker,
			agentChanged, processExited, now) {
			return // 本拍按住不发（暂态空屏被确认窗吸收）
		}
	}
	publish := nextState != s.stateV2 || v.agent != prevAgent
	if !publish && s.hygiene.shouldRepublishBlocked(s.stateV2, now) {
		publish = true // blocked 持续期间定期重发，保持消费方新鲜
	}
	if !publish {
		return
	}
	s.agent, s.stateV2 = v.agent, nextState
	if s.svc.logf != nil {
		suffix := ""
		if freeze {
			suffix = "（skip_state_update 冻结）"
		}
		// 状态行带**依据**（哪条腿 + 规则/版本/来源），规格要求可追溯。
		s.svc.logf("term: 会话 %s 状态 %s/%s（fg=%d procs=%d 依据=%s）%s",
			s.name, agentName(v.agent), stateNameV2(nextState), fg, len(procs), v.evidence, suffix)
	}
	s.pushStateLocked()
}

// screenEvidenceLocked 取本拍的屏幕证据（任务 4.6/4.7）。**必须持 mu**。
//
// 返回 (证据, 是否真的扫了屏)。以下情况返回 nil：
//   - 本会话没有 vt（legacy-only）或引擎不可用（HOMEWAY_TERM_DETECT=off）
//   - 空闲短路命中（状态 idle + agent 已知 + 内容序号未变）⇒ 零开销
//   - 前台不是 agent（shell/other 的 blocked/idle 判定没有规则依据，交给输出/CPU 腿）
func (s *termSession) screenEvidenceLocked(now time.Time, procs []procInfo, fgPgid int) (*screenEvidence, bool) {
	if s.svc.manifests == nil || !s.vt.Available() {
		return nil, false
	}
	// 用规则表按**进程名**选 manifest（身份腿的 agent 枚举 → 进程名）。
	procName := foregroundAgentName(procs, fgPgid, func(n string) bool {
		_, ok := s.svc.manifests.ForProcess(n)
		return ok
	})
	if procName == "" {
		return nil, false
	}
	// 空闲短路：判据用**本拍进程名**（agentKnown = 有名字；agentChanged = 与上次扫屏不同），
	// 不用 s.agent（它的更新时机在扫屏之后，见 sample 的注释）。
	agentChanged := procName != s.lastScanProc
	if s.hygiene.shouldSkipScreenScan(s.stateV2, true, agentChanged, false, s.contentSeq, s.lastScanSeq, now) {
		return nil, false
	}
	comp, ok := s.svc.manifests.ForProcess(procName)
	if !ok {
		return nil, false
	}
	// 标题走 termScan（单一来源，design D1），progress 也是——不用 vt 的标题查询。
	res := comp.Evaluate(manifest.Input{
		// 只喂**一屏**（视口）纯文本：契约是「最近约一屏」，不是整条回滚。
		Screen:      s.vt.ScreenText(),
		OSCTitle:    s.scan.TitleEvidence(),
		OSCProgress: progressPayload(s.scan.Progress()),
	})
	ev := &screenEvidence{
		state:          stateV2FromManifest(res.State),
		visibleIdle:    res.VisibleIdle,
		visibleBlocker: res.VisibleBlocker,
		visibleWorking: res.VisibleWorking,
		skipUpdate:     res.SkipStateUpdate,
		version:        comp.Manifest.Version,
		source:         string(comp.Manifest.Source),
		fallback:       res.FallbackReason,
	}
	if res.MatchedRule != nil {
		ev.ruleID = res.MatchedRule.ID
	}
	s.lastScanProc = procName
	return ev, true
}

// progressPayload 把 progress 还原成 OSC 9;4 的载荷形态（region osc_progress 的判据是 `^4;0` 这类前缀）。
func progressPayload(p termProgress) string {
	if !p.ok {
		return ""
	}
	if p.value < 0 {
		return "4;" + strconv.Itoa(p.state)
	}
	return "4;" + strconv.Itoa(p.state) + ";" + strconv.Itoa(p.value)
}

// stateV2FromManifest 把 manifest 的状态映射到 stateV2。
func stateV2FromManifest(st manifest.State) byte {
	switch st {
	case manifest.StateWorking:
		return stateV2Working
	case manifest.StateBlocked:
		return stateV2Blocked
	case manifest.StateIdle:
		return stateV2Idle
	}
	return stateV2Unknown
}

// ---- 连接处理 ----

// ServeConn 处理一条客户端连接（由 serve 的 OnTCP 在 term 端口上调用）。
func (s *termService) ServeConn(c net.Conn) {
	defer c.Close()
	client := &termClient{conn: c, out: newLegOut()}
	if err := client.frame(opGreeting, encGreeting()); err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(termHelloTimeout))
	f, err := readTermFrame(c)
	if err != nil {
		return
	}
	switch f.op {
	case opList:
		_ = client.frame(opList, []byte(s.listJSON()))
	case opExplain:
		name, derr := decName(f.payload)
		if derr != nil {
			_ = client.frame(opError, encError("bad_name", derr.Error()))
			return
		}
		out, eerr := s.explainJSON(name)
		if eerr != nil {
			_ = client.frame(opError, encError(eerr.code, eerr.msg))
			return
		}
		_ = client.frame(opExplain, []byte(out))
	case opKill:
		name, derr := decName(f.payload)
		if derr != nil {
			_ = client.frame(opError, encError("bad_name", derr.Error()))
			return
		}
		if err := s.kill(name); err != nil {
			_ = client.frame(opError, encError(err.code, err.msg))
			return
		}
		_ = client.frame(opOK, nil)
	case opCreate:
		// 创建不接入（任务 6.2）：不动 PTY 尺寸、不产生腿、不触发哨兵/焦点。
		flags, name, derr := decCreate(f.payload)
		if derr != nil {
			_ = client.frame(opError, encError("bad_create", derr.Error()))
			return
		}
		if !termNameRx.MatchString(name) {
			_ = client.frame(opError, encError("invalid_name", "会话名只能是 [A-Za-z0-9._-]{1,64}"))
			return
		}
		if cerr := s.createOnly(name, flags&createFlagReuseIfExists != 0); cerr != nil {
			_ = client.frame(opError, encError(cerr.code, cerr.msg))
			return
		}
		_ = client.frame(opOK, nil)
	case opHello:
		cols, rows, flags, name, derr := decHello(f.payload)
		if derr != nil {
			_ = client.frame(opError, encError("bad_hello", derr.Error()))
			return
		}
		// 能力协商 + 实例标识（任务 2.1/2.3）：HELLO 尾随 [capLen][caps][idLen][clientID]，
		// 形状不符（如缺 caps 长度前缀的裸 ID 块）必须拒绝——沿用 bad_capability 错误码。
		caps, capsPresent, clientID, caperr := decHelloTail(helloTail(f.payload, name))
		if caperr != nil {
			_ = client.frame(opError, encError("bad_capability", caperr.Error()))
			return
		}
		if capsPresent && wantsSurface(caps) {
			if !surfaceCapable() {
				// 本会话/本构建没有服务端 vt ⇒ 明确报错，让客户端回落 legacy（不是静默降级）。
				_ = client.frame(opError, encError("surface_unavailable",
					"本出口没有服务端 vt（HOMEWAY_TERM_VT=off 或平台不支持）"))
				return
			}
			client.surface = true
			client.leg = newSurfaceLeg()
		}
		if capsPresent && caps&capsRawTerminal != 0 {
			client.rawCapable = true // 真实终端客户端：应答让位判据（任务 5.1）+ LIST kind=host
		}
		client.clientID = clientID
		client.takeover = flags&helloFlagTakeover != 0
		client.kind = legKindOf(client.surface, client.rawCapable)
		client.cols, client.rows = cols, rows
		if !termNameRx.MatchString(name) {
			_ = client.frame(opError, encError("invalid_name", "会话名只能是 [A-Za-z0-9._-]{1,64}"))
			return
		}
		ss, cerr := s.attachOrCreate(name, cols, rows, flags&helloFlagCreate != 0,
			flags&helloFlagOnlyIfAbsent != 0)
		if cerr != nil {
			_ = client.frame(opError, encError(cerr.code, cerr.msg))
			return
		}
		s.stream(ss, client, c)
	default:
		_ = client.frame(opError, encError("bad_op", fmt.Sprintf("首帧必须是 HELLO/LIST/KILL/CREATE（收到 0x%02x）", f.op)))
	}
}

// legKindOf 腿的呈现分类（LIST clients 的 kind，任务 2.5）：
// app = surface 腿（新 App）；host = 声明 capsRawTerminal 的 raw 腿（CLI）；
// legacy = 未声明的 raw 腿（旧 App）。
func legKindOf(surface, rawCapable bool) string {
	switch {
	case surface:
		return "app"
	case rawCapable:
		return "host"
	default:
		return "legacy"
	}
}

type termErr struct {
	code string
	msg  string
}

func (e *termErr) Error() string { return e.code + ": " + e.msg }

// ERROR 帧码词表（termErrf 首参——contract-ledger 台账族③，只增不改；App 桥层经族⑦
// 透传消费）。首参一律引用本表，散点字面量已随 4b 2.1 提常量收拢。
const (
	termErrAlreadyExists  = "already_exists"   // HELLO/CREATE：同名会话且不复用
	termErrDetectOff      = "detect_off"       // explain：出口侧检测被环境变量关掉
	termErrMarshal        = "marshal"          // explain：应答编码失败
	termErrNoAgent        = "no_agent"         // explain：前台不是已知 agent
	termErrNoSession      = "no_session"       // 会话不存在/已结束
	termErrNoVt           = "no_vt"            // explain：会话没有服务端 vt
	termErrSpawnFailed    = "spawn_failed"     // 会话进程起不来
	termErrTooMany        = "too_many"         // 会话数达上限
	termErrTooManyClients = "too_many_clients" // 同会话腿数达上限
)

func termErrf(code, format string, args ...any) *termErr {
	return &termErr{code: code, msg: fmt.Sprintf(format, args...)}
}

// attachOrCreate 解析 HELLO 的接入语义（任务 6.1 的 only-if-absent 在这里收口）：
//   - 不存在：create=false 报 no_session；create=true 起会话；
//   - 已存在：create+onlyIfAbsent 报 already_exists（`new` 不带 -A 的重名错误）；
//     其余（create 不带该位 = `-A` 复用；create=false = attach）照旧复用。
//
// 尺寸**不在这里动**：多腿模型下尺寸归活动选举（design D4，registerLeg 的 noteActivity）。
func (s *termService) attachOrCreate(name string, cols, rows uint16, create, onlyIfAbsent bool) (*termSession, *termErr) {
	s.mu.Lock()
	ss := s.sessions[name]
	if ss == nil {
		if !create {
			s.mu.Unlock()
			return nil, termErrf(termErrNoSession, "会话 %s 不存在", name)
		}
		if len(s.sessions) >= s.cfg.maxSessions {
			s.mu.Unlock()
			return nil, termErrf(termErrTooMany, "会话数已达上限 %d，请先关闭一些会话", s.cfg.maxSessions)
		}
		var err error
		ss, err = s.spawnLocked(name, cols, rows)
		if err != nil {
			s.mu.Unlock()
			return nil, termErrf(termErrSpawnFailed, "%v", err)
		}
		s.sessions[name] = ss
		s.mu.Unlock()
		return ss, nil
	}
	s.mu.Unlock()
	if create && onlyIfAbsent {
		return nil, termErrf(termErrAlreadyExists, "会话 %s 已存在；要接入请用 attach，或加 -A 复用", name)
	}
	return ss, nil
}

// createOnly 创建不接入（任务 6.2，`homeway term new -d`）：不动 PTY 尺寸（默认 80x24）、
// 不产生腿、不触发哨兵/焦点。reuseIfExists = `-A -d`（CREATE bit0 置位：存在则静默复用成功；
// 极性与 HELLO bit1 相反，见 frames.go 的 createFlagReuseIfExists）。
func (s *termService) createOnly(name string, reuseIfExists bool) *termErr {
	s.mu.Lock()
	if ss := s.sessions[name]; ss != nil {
		s.mu.Unlock()
		if reuseIfExists {
			return nil
		}
		return termErrf(termErrAlreadyExists, "会话 %s 已存在；要接入请用 attach，或加 -A 复用", name)
	}
	if len(s.sessions) >= s.cfg.maxSessions {
		s.mu.Unlock()
		return termErrf(termErrTooMany, "会话数已达上限 %d，请先关闭一些会话", s.cfg.maxSessions)
	}
	ss, err := s.spawnLocked(name, 0, 0)
	if err != nil {
		s.mu.Unlock()
		return termErrf(termErrSpawnFailed, "%v", err)
	}
	s.sessions[name] = ss
	s.mu.Unlock()
	if s.logf != nil {
		s.logf("term: 创建会话 %s（不接入，默认尺寸）", name)
	}
	return nil
}

// spawnLocked 起一个 PTY 会话（调用方持 s.mu）。
//
// 两种模式都走**登录 shell + 环境白名单**（见「登录 shell 与登录环境」一节）：
//   - 默认：`shell -l`（交互式登录 shell，rc 文件决定 PATH 等）
//   - HOMEWAY_TERM_SHELL：`shell -lc '<命令>'`（例如 tmux；profile 里的 PATH 同样生效，
//     所以 homebrew 装的 tmux 在 macOS 上也找得到）
func (s *termService) spawnLocked(name string, cols, rows uint16) (*termSession, error) {
	shell := loginShell()
	var cmd *exec.Cmd
	if s.cfg.shell != "" {
		// HOMEWAY_TERM_SHELL：一条命令（例如 tmux new -A -s tier / screen -dR）。
		// ⚠️ 不要退回硬编码的 /bin/sh：distroless 之类没有 /bin/sh 的镜像里那条逃生口会直接死。
		cmd = exec.Command(shell, "-lc", s.cfg.shell)
	} else {
		cmd = exec.Command(shell, "-l")
	}
	env := termLoginEnv(shell, "tailcat-"+name)
	cmd.Env = env
	if home := termEnvLookup(env, "HOME"); home != "" {
		cmd.Dir = home
	}
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, err
	}
	if err := pty.Setsize(ptmx, &pty.Winsize{Cols: cols, Rows: rows}); err != nil {
		_ = ptmx.Close()
		return nil, err
	}
	now := time.Now()
	ss := &termSession{
		svc:        s,
		name:       name,
		created:    now,
		pid:        cmd.Process.Pid,
		ptmx:       ptmx,
		cmd:        cmd,
		ring:       make([]byte, s.cfg.history), // 定长环：长度即历史上限
		agent:      agentUnknown,
		lastOut:    now,
		lastActive: now,
		cols:       cols,
		rows:       rows,
	}
	ss.epochs = append(ss.epochs, termEpoch{off: 0, cols: cols, rows: rows})
	// surface 通道（收工信号 + 唤醒/剪贴板投递）：**总是建**——nil channel 的 select
	// 会永久阻塞，而这些通道只在 surface 腿存在时被使用；建出来让收尾路径不必到处判 nil。
	// surfaceLoop 只在有服务端 vt 的构建里启动（没有 vt 就没有 surface 腿）。
	ss.surfaceWake = make(chan struct{}, 1)
	ss.clipChan = make(chan string, 8)
	ss.surfaceStop = make(chan struct{})
	// 会话级参数注入（exec-r1 高2/中4）。
	ss.writeTimeout = time.Duration(s.cfg.writeTimeoutMs) * time.Millisecond
	ss.rawStallLimit = time.Duration(s.cfg.rawStallLimitMs) * time.Millisecond
	ss.pendingCap = s.cfg.pendingCapBytes
	ss.queueBytes = s.cfg.queueBytes
	// 服务端 vt：失败只让**本会话**退化为 legacy（surface 客户端 attach 会得到明确错误码），
	// 既有 legacy 会话与其它会话都不受影响（term-surface-protocol 的降级场景）。
	if sv, verr := newSessionVT(s.cfg, cols, rows); verr == nil {
		// 剪贴板双向（OSC 52）：写 → CLIPBOARD 帧转给客户端；读 → 命中客户端最近上报的缓存。
		// 查询应答（DA1/DSR/OSC 10-11）的归属随腿况动态切换（任务 5.1 窄规则：
		// capsRawTerminal 腿在场时让位）——初始无腿 = 服务端代答，见 updateResponseSinkLocked。
		ptmxForSink := ptmx
		ss.responseFn = func(p []byte) { _, _ = ptmxForSink.Write(p) }
		ss.vt = sv
		sv.EnableClipboardWrite()
		sv.EnableClipboardRead()
		if id := sv.RegistryID(); id != 0 {
			ss.vtID = id
			registerVTSession(id, ss)
		}
		ss.updateResponseSinkLocked()
	} else if s.logf != nil {
		s.logf("term: 会话 %s 无服务端 vt（%v）→ 该会话仅 legacy 原始字节模式", name, verr)
	}
	if s.logf != nil {
		s.logf("term: 新建会话 %s（pid=%d %dx%d shell=%s）", name, ss.pid, cols, rows, shell)
	}
	go ss.pump()
	if surfaceCapable() {
		go ss.surfaceLoop()
	}
	return ss, nil
}

// resize 应用新尺寸（幂等；外部入口）。多腿模型下的真正归属是活动选举
// （applySizeLocked，design D4）——这里保留给无腿时的诊断/维护路径。
func (s *termSession) resize(cols, rows uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applySizeLocked(cols, rows)
}

// sentinelRepaint 尺寸哨兵：sentinel → 真实尺寸，两次 SIGWINCH 逼 TUI 重绘当前屏。
func (s *termSession) sentinelRepaint() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sentinelRepaintLocked()
}

// sentinelRepaintLocked 同 sentinelRepaint（调用方已持 s.mu）。
func (s *termSession) sentinelRepaintLocked() {
	if s.done || s.ptmx == nil {
		return
	}
	s.sentinelCount++ // 低7 判据计数器：一次 attach 只应 +1
	cols, rows := s.cols, s.rows
	sentinel := cols
	if sentinel > 1 {
		sentinel--
	} else {
		sentinel = cols + 1
	}
	_ = pty.Setsize(s.ptmx, &pty.Winsize{Cols: sentinel, Rows: rows})
	_ = pty.Setsize(s.ptmx, &pty.Winsize{Cols: cols, Rows: rows})
}

// stream：注册腿 + 读循环（连接存续期间一直跑）。
//
// 多腿模型（term-host-cli）：正常接入不顶掉任何腿（旧的单腿顶替语义已退役）；
// ENDED(replaced) 只剩显式接管（HELLO bit2，`attach -d`）与同实例重连（clientID）两条触发。
// 正常断开的 defer 走 endLegLocked（修掉旧实现「只置 attached=nil、不发 focus-out 不打日志」
// 的缺口，任务 2.1a）。
func (s *termService) stream(ss *termSession, client *termClient, c net.Conn) {
	ss.mu.Lock()
	if rerr := ss.registerLegLocked(client, client.takeover); rerr != nil {
		ss.mu.Unlock()
		_ = client.frame(opError, encError(rerr.code, rerr.msg))
		return
	}
	ss.mu.Unlock()
	go ss.runLegWriter(client)
	// 尺寸哨兵：raw 腿要在**回放之后**（写者按握手计划执行，哨兵的重绘输出落在实时流）；
	// surface 腿要在**快照下发前**（design D3：哨兵刚发完，投递循环还在合并窗里，
	// 取到的快照已经是远端按最终尺寸重绘过的屏）。
	ss.sentinelRepaint()
	if client.surface {
		ss.wakeSurface()
	}

	defer func() {
		ss.mu.Lock()
		ss.endLegLocked(client, termEndNone, "", "client_closed")
		ss.mu.Unlock()
	}()

	for {
		_ = c.SetReadDeadline(time.Time{})
		f, rerr := readTermFrame(c)
		if rerr != nil {
			return
		}
		switch f.op {
		case opData:
			ss.mu.Lock()
			ptmx := ss.ptmx
			// 输入 = 活动（design D4：活动 = 接入 / RESIZE / 输入；输入不改腿尺寸，
			// 不会触发哨兵——哨兵只在尺寸变化的 RESIZE/选举路径）。
			ss.noteActivityLocked(client, true)
			ss.mu.Unlock()
			if ptmx != nil && len(f.payload) > 0 {
				if _, werr := ptmx.Write(f.payload); werr != nil {
					return
				}
			}
		case opResize:
			cols, rows, derr := decResize(f.payload)
			if derr != nil {
				client.out.enqueue(writeItem{op: opError, payload: encError("bad_resize", derr.Error())}, 0)
				continue
			}
			ss.mu.Lock()
			client.cols, client.rows = cols, rows
			// RESIZE = 活动：选举决定是否真的改会话尺寸；尺寸真变 ⇒ 哨兵逼重绘。
			ss.noteActivityLocked(client, true)
			ss.mu.Unlock()
			if client.surface {
				// surface 的全量快照由 applySizeLocked 的「全腿标记」+ 唤醒负责
				//（旧 handleSurfaceResize 的等价路径）。
				ss.wakeSurface()
			}
		case opInput:
			if client.surface {
				ss.handleInput(client, f.payload)
			}
		case opTheme:
			if client.surface {
				ss.handleTheme(client, f.payload)
			}
		case opClipboard:
			if client.surface {
				ss.handleClipboardAnswer(client, f.payload)
			}
		case opFetchRows:
			if client.surface {
				ss.handleFetchRows(client, f.payload)
			}
		case opFetchSnapshot:
			if client.surface {
				ss.handleFetchSnapshot(client)
			}
		case opKill:
			name, derr := decName(f.payload)
			if derr != nil {
				client.out.enqueue(writeItem{op: opError, payload: encError("bad_name", derr.Error())}, 0)
				continue
			}
			if kerr := s.kill(name); kerr != nil {
				client.out.enqueue(writeItem{op: opError, payload: encError(kerr.code, kerr.msg)}, 0)
			} else {
				client.out.enqueue(writeItem{op: opOK}, 0)
			}
		case opList:
			client.out.enqueue(writeItem{op: opList, payload: []byte(s.listJSON())}, 0)
		case opExplain:
			name, derr := decName(f.payload)
			if derr != nil {
				client.out.enqueue(writeItem{op: opError, payload: encError("bad_name", derr.Error())}, 0)
				continue
			}
			out, eerr := s.explainJSON(name)
			if eerr != nil {
				client.out.enqueue(writeItem{op: opError, payload: encError(eerr.code, eerr.msg)}, 0)
				continue
			}
			client.out.enqueue(writeItem{op: opExplain, payload: []byte(out)}, 0)
		default:
			// 错误回执也走腿队列（每腿唯一写者 = 帧组原子性；修掉旧实现读循环直发 ERROR
			// 可能插进分片组的既有洞）。
			client.out.enqueue(writeItem{op: opError,
				payload: encError("bad_op", fmt.Sprintf("未知帧 0x%02x", f.op))}, 0)
		}
	}
}

// cwdLocked 取会话工作目录（vt 从 OSC 7 解析；剥成文件系统路径）。
// 无 vt（legacy-only）或 shell 未上报时返回空串——列表里该字段缺省不显示。
func (s *termSession) cwdLocked() string {
	if !s.vt.Available() {
		return ""
	}
	return vtPwdPath(s.vt.Pwd())
}

// explainJSON 对运行中的会话取实时快照跑一次 explain（任务 4.8 的在线模式）。
//
// 依据链与离线模式**同一套代码**（runExplain），所以两边结论一定一致（规格要求
// 「explain 与列表判定一致」）。
func (s *termService) explainJSON(name string) (string, *termErr) {
	if s.manifests == nil {
		return "", termErrf(termErrDetectOff, "本出口的检测被 HOMEWAY_TERM_DETECT=off 关闭")
	}
	s.mu.Lock()
	ss := s.sessions[name]
	s.mu.Unlock()
	if ss == nil {
		return "", termErrf(termErrNoSession, "会话 %s 不存在", name)
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if !ss.vt.Available() {
		return "", termErrf(termErrNoVt, "会话 %s 没有服务端 vt（legacy-only），没有屏幕证据可判", name)
	}
	screen := ss.vt.PlainText()
	agent := foregroundAgentNameFor(s.manifests, s, ss)
	if agent == "" {
		return "", termErrf(termErrNoAgent, "会话 %s 前台不是已知 agent，没有规则可跑", name)
	}
	out := runExplain(s.manifests, agent, screen, name)
	b, err := json.Marshal(out)
	if err != nil {
		return "", termErrf(termErrMarshal, "explain 输出编码失败：%v", err)
	}
	return string(b), nil
}

// foregroundAgentNameFor 取会话前台进程名（explain 的选表依据）。
func foregroundAgentNameFor(l *manifest.Loader, svc *termService, ss *termSession) string {
	if ss.ptmx == nil {
		return ""
	}
	procs := readProcs()
	return foregroundAgentName(procs, foregroundPgid(ss.ptmx.Fd()), func(n string) bool {
		_, ok := l.ForProcess(n)
		return ok
	})
}

// kill 主动结束会话（SIGHUP → 宽限 → SIGKILL）；由 pump 的收尾负责回 ENDED。
func (s *termService) kill(name string) *termErr {
	s.mu.Lock()
	ss := s.sessions[name]
	s.mu.Unlock()
	if ss == nil {
		return termErrf(termErrNoSession, "会话 %s 不存在", name)
	}
	ss.mu.Lock()
	pid := ss.pid
	done := ss.done
	ss.killed = true
	ss.mu.Unlock()
	if done {
		return termErrf(termErrNoSession, "会话 %s 已结束", name)
	}
	if err := signalPgid(pid, 1); err != nil { // 1 = SIGHUP
		// 组信号失败就退化为单进程终止。
		ss.mu.Lock()
		if ss.cmd != nil && ss.cmd.Process != nil {
			_ = ss.cmd.Process.Kill()
		}
		ss.mu.Unlock()
	}
	go func() {
		time.Sleep(termKillGrace)
		ss.mu.Lock()
		alive := !ss.done
		pid := ss.pid
		ss.mu.Unlock()
		if alive {
			_ = signalPgid(pid, 9) // SIGKILL
		}
	}()
	if s.logf != nil {
		s.logf("term: 关闭会话 %s（pid=%d）", name, pid)
	}
	return nil
}

// listJSON 回 LIST-REPLY 的 JSON（Go/ArkTS 消费；C++ 侧从不发 LIST）。
func (s *termService) listJSON() string {
	// clientEntry 是在场腿信息（term-host-cli 任务 2.5，design D8：字段只增不改——
	// kind/cols/rows/sinceMs/active；attached 保留为「至少一条腿」）。
	type clientEntry struct {
		Kind    string `json:"kind"` // app / host / legacy
		Cols    uint16 `json:"cols"`
		Rows    uint16 `json:"rows"`
		SinceMs int64  `json:"sinceMs"`
		Active  bool   `json:"active"`
	}
	type entry struct {
		Name         string `json:"name"`
		CreatedMs    int64  `json:"createdMs"`
		LastActiveMs int64  `json:"lastActiveMs"`
		Attached     bool   `json:"attached"`
		Agent        string `json:"agent"`
		// StateV2 是状态唯一字段（working/blocked/idle/unknown）。旧 `state` 键已随
		// 状态单轨化退役（term-remote 3.3，D6 破坏性授权：不识 stateV2 的历史客户端
		// 状态列降级为既有未知态；在役 App 已消费 stateV2，消费方同批改齐）。
		StateV2 string `json:"stateV2"`
		Title   string `json:"title"`
		// Cwd 是会话内 shell 经 OSC 7 上报的工作目录（缺省不显示）。
		Cwd     string        `json:"cwd,omitempty"`
		Cols    uint16        `json:"cols"`
		Rows    uint16        `json:"rows"`
		Pid     int           `json:"pid"`
		Clients []clientEntry `json:"clients"`
	}
	s.mu.Lock()
	out := make([]entry, 0, len(s.sessions))
	for _, ss := range s.sessions {
		ss.mu.Lock()
		done := ss.done
		if !done {
			clients := make([]clientEntry, 0, len(ss.legs))
			for _, l := range ss.legs {
				clients = append(clients, clientEntry{
					Kind:    l.kind,
					Cols:    l.cols,
					Rows:    l.rows,
					SinceMs: l.since.UnixMilli(),
					Active:  l == ss.active,
				})
			}
			out = append(out, entry{
				Name:         ss.name,
				CreatedMs:    ss.created.UnixMilli(),
				LastActiveMs: ss.lastActive.UnixMilli(),
				Attached:     len(ss.legs) > 0,
				Agent:        agentName(ss.agent),
				StateV2:      stateNameV2(ss.stateV2),
				Title:        ss.scan.title,
				Cwd:          ss.cwdLocked(),
				Cols:         ss.cols,
				Rows:         ss.rows,
				Pid:          ss.pid,
				Clients:      clients,
			})
		}
		ss.mu.Unlock()
	}
	s.mu.Unlock()
	b, err := json.Marshal(map[string]any{"sessions": out})
	if err != nil {
		return `{"sessions":[]}`
	}
	return string(b)
}

// vtDefaultScrollbackLines 是服务端 vt 回滚行数上限的默认值（与 pkg/term/vt 保持一致；
// 这里复制一份常量是为了让不带 vt 的构建（term_vt_off.go）也能引用默认值）。
const vtDefaultScrollbackLines = 10000
