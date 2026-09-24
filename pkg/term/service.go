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

	termReplayBudget = 2 * time.Second
	termWriteTimeout = 10 * time.Second
	termHelloTimeout = 15 * time.Second
	termKillGrace    = 500 * time.Millisecond
	termSamplePeriod = time.Second
	termReplayTrim   = 4096 // 起点对齐时最多前看这么多字节
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
	detect      bool
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
		detect:          !strings.EqualFold(strings.TrimSpace(os.Getenv("HOMEWAY_TERM_DETECT")), "off"),
		scrollbackLines: termEnvInt("HOMEWAY_TERM_SCROLLBACK_LINES", vtDefaultScrollbackLines),
	}
	if cfg.replayEpoch != "last" {
		cfg.replayEpoch = "all"
	}
	if cfg.replay > cfg.history {
		cfg.replay = cfg.history
	}
	return cfg
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
	// darkTheme / clipCache / lastNotified：surface 通道的会话侧缓存（任务 2.7）。
	darkTheme bool
	clipCache string
	// clipCachePub 是 clipCache 的原子发布副本：剪贴板读回调在 vt.Write 内部同步触发
	// （此时会话锁被 pump 持有），**不能取会话锁**去读 clipCache。
	clipCachePub atomic.Pointer[string]
	lastNotified string
	// vtID 是服务端 vt 在回调注册表里的 id（剪贴板回调按它分派）。
	vtID uintptr
	// surfaceActive 是「当前有 surface 腿」的无锁标志（剪贴板回调在锁内触发，只能读原子量）。
	surfaceActive atomic.Bool
	// clipChan 承接程序写剪贴板的内容（锁外投递，见 clipboardRouter）。
	clipChan chan string

	contentSeq     uint64
	lastScanSeq    uint64
	hygiene        stateHygiene
	lastScreenRule string // 上一拍命中的规则 id（agent 变化时用于清证据判定）
	agent          byte
	state          byte
	// stateV2 是新枚举口径的当前状态（state 是它的 legacy 折价，见 agent.go 的 legacyState）。
	stateV2   byte
	prevCPU   int64
	prevQuiet int // 截至上一采样的连续安静拍数（classifyAgent 磁滞输入）
	// outBuckets：按绝对秒键的输出字节桶（定长环形，countOutLocked 写、
	// outBytesLocked 求窗口和）——输出腿的数据源，见 term_agent.go 阈值注释。
	outBuckets [4]outBucket
	lastOut    time.Time
	lastActive time.Time
	cols, rows uint16
	attached   *termClient
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

// termClient 一条已 attach 的连接。off/live 由 session.mu 保护；wmu 串行化写。
type termClient struct {
	conn net.Conn
	wmu  sync.Mutex
	off  int64
	live bool
	// leg 是 surface 投递状态（仅 surface 腿非 nil）。
	leg *surfaceLeg
	// surface 表示这条腿声明了 surface 能力（任务 2.1 的能力协商置位）。
	// 任务 4.8 的枚举兼容靠它分流：**新枚举只发给声明了 surface 能力的腿**，
	// legacy 腿收到折价后的兼容值（旧 App 显示零回退）。M1 阶段恒 false。
	surface bool
}

// stateForLeg 按腿的能力选状态枚举值（任务 4.8 的兼容契约）。
func stateForLeg(surface bool, stateV2, legacy byte) byte {
	if surface {
		return stateV2
	}
	return legacy
}

func (c *termClient) frame(op byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(termWriteTimeout))
	_, err := c.conn.Write(encodeTermFrame(op, payload))
	return err
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

// epochsInRange 判断回放窗口内是否跨过尺寸变化（REPLAY-DONE flags bit1）。
func (s *termSession) epochsInRange(start, end int64) bool {
	for _, e := range s.epochs {
		if e.off > start && e.off < end {
			return true
		}
	}
	return false
}

// noteSizeLocked 记录一次尺寸变化（同时更新当前尺寸）。
func (s *termSession) noteSizeLocked(cols, rows uint16) {
	s.cols, s.rows = cols, rows
	s.epochs = append(s.epochs, termEpoch{off: s.written, cols: cols, rows: rows})
	if len(s.epochs) > 64 {
		s.epochs = s.epochs[len(s.epochs)-64:]
	}
}

// ---- 客户端投递 ----

func (s *termSession) deliverLocked() {
	c := s.attached
	if c == nil || !c.live {
		return
	}
	if c.surface {
		// surface 腿的画面由投递循环（快照/差分）负责；这里**绝不**发原始字节 DATA
		// ——那正是 surface 要消灭的路径，混着发会让客户端收到两套语义的内容。
		return
	}
	for {
		if c.off < s.start {
			c.off = s.start // 客户端太慢、历史被覆盖：跳到可用起点（宁可丢也不阻塞）
		}
		if c.off >= s.written {
			return
		}
		chunk := s.readLocked(c.off, termDataChunk)
		if len(chunk) == 0 {
			return
		}
		if err := c.frame(opData, chunk); err != nil {
			s.detachLocked(c)
			return
		}
		c.off += int64(len(chunk))
	}
}

func (s *termSession) detachLocked(c *termClient) {
	if s.attached == c {
		s.attached = nil
		s.surfaceActive.Store(false)
		// 焦点交还：TUI 停动画（空闲闪烁不再进字节环）。
		s.focusNudgeLocked(false)
	}
	if c.surface && c.leg != nil && s.svc.logf != nil {
		// surface 腿的计数器摘要（任务 2.9）：7.4 的真机流量对照要读这些数。
		st := c.leg.statsSnapshot()
		s.svc.logf("term: 会话 %s surface 腿断开｜快照=%d 差分=%d 降级=%d 背压=%d 分片=%d 下行=%dB "+
			"FETCH 命中=%d 落空=%d 写超时=%d",
			s.name, st.snapshots, st.diffs, st.degrades, st.backpressure, st.fragments,
			st.bytesOut, st.fetchHits, st.fetchMiss, st.writeTimeout)
	}
	c.close()
	if s.svc.logf != nil {
		s.svc.logf("term: 会话 %s 客户端断开（会话继续运行）", s.name)
	}
}

func (s *termSession) pushStateLocked() {
	if c := s.attached; c != nil {
		st := stateForLeg(c.surface, s.stateV2, s.state)
		if err := c.frame(opState, encState(s.agent, st, s.scan.title)); err != nil {
			s.detachLocked(c)
		}
	}
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

// attachLocked 把 c 接到会话上：顶掉旧客户端 → ATTACHED → 换屏前序 → 回放 → REPLAY-DONE → 实时。
func (s *termSession) attachLocked(c *termClient) error {
	if old := s.attached; old != nil && old != c {
		_ = old.frame(opEnded, encEnded(termEndReplaced, "replaced"))
		s.detachLocked(old)
	}
	s.attached = c
	c.live = false
	if c.surface {
		// surface 腿：ATTACHED（带几何/模式/名称）之后**不发回放**，由投递循环发全量快照。
		// 回放（原始字节重放）正是 surface 要消灭的那类正确性问题——快照是精确屏态。
		if err := c.frame(opAttached, encAttached(s.cols, s.rows, s.scan.modes, s.agent,
			stateForLeg(true, s.stateV2, s.state), s.name)); err != nil {
			s.detachLocked(c)
			return err
		}
		c.live = true
		c.off = s.written
		if c.leg != nil {
			c.leg.markNeedSnapshot("attach")
		}
		s.surfaceActive.Store(true)
		if s.svc.logf != nil {
			// 判据行：协商结果（surface 腿接管）+ 几何，供运维核对双轨。
			s.svc.logf("term: 会话 %s surface 腿接管（%dx%d 全量快照待发）", s.name, s.cols, s.rows)
		}
		return nil
	}
	start, truncated := s.replayStartLocked()
	c.off = start

	if err := c.frame(opAttached, encAttached(s.cols, s.rows, s.scan.modes, s.agent,
		stateForLeg(c.surface, s.stateV2, s.state), s.name)); err != nil {
		s.detachLocked(c)
		return err
	}
	// 换屏前序：客户端 vt 是新建的，这一步保证回放内容的起点是确定的。
	if err := c.frame(opData, []byte("\x1b[3J\x1b[2J\x1b[H")); err != nil {
		s.detachLocked(c)
		return err
	}
	deadline := time.Now().Add(termReplayBudget)
	end := s.written
	replayed := 0
	for c.off < end {
		chunk := s.readLocked(c.off, termDataChunk)
		if len(chunk) == 0 {
			break
		}
		if err := c.frame(opData, chunk); err != nil {
			s.detachLocked(c)
			return err
		}
		c.off += int64(len(chunk))
		replayed += len(chunk)
		if time.Now().After(deadline) && c.off < end {
			truncated = true // 时间预算用尽：丢头部保尾部（本循环本来就是从起点顺序发的）
			break
		}
	}
	sent := c.off
	flags := byte(0)
	if truncated {
		flags |= replayFlagTruncated
	}
	if s.epochsInRange(start, sent) {
		flags |= replayFlagSizeChange
	}
	if err := c.frame(opReplayDone, encReplayDone(uint32(replayed), flags)); err != nil {
		s.detachLocked(c)
		return err
	}
	if c.off < end {
		// 预算用尽（上面 break 的那一支）：剩余历史直接跳过，从「现在」接实时流。
		c.off = s.written
	}
	c.live = true
	// 回放期间新产生的字节 [c.off, s.written) 由这次 flush 补齐，然后交给 pump 持续投递。
	s.deliverLocked()
	// 回放完成后注入 focus-in：逼 TUI 立即全屏重绘（见 focusNudgeLocked 注释——
	// 回放尾部往往没有全屏帧，SIGWINCH sentinel 又会被 TUI 的 pending-resize 优化吞掉）。
	s.focusNudgeLocked(true)
	return nil
}

// ---- 生命周期 ----

// finish 结束会话：回 ENDED → 关 master → 等子进程 → 从注册表删除。
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
	if c := s.attached; c != nil {
		_ = c.frame(opEnded, encEnded(code, text))
		s.detachLocked(c)
	}
	ptmx := s.ptmx
	s.mu.Unlock()

	if ptmx != nil {
		_ = ptmx.Close()
	}
	s.waitOnce.Do(func() {
		if s.cmd != nil {
			_ = s.cmd.Wait()
		}
	})
	s.mu.Lock()
	if s.cmd != nil && s.cmd.ProcessState != nil {
		s.exitCode = int32(s.cmd.ProcessState.ExitCode())
	}
	s.ring = nil // 释放历史缓冲
	s.mu.Unlock()
	if s.vtID != 0 {
		unregisterVTSession(s.vtID)
	}
	s.vt.Close() // 释放服务端 vt（幂等；无 vt 的构建是空操作）

	s.svc.remove(s.name, s)
}

func (s *termService) remove(name string, who *termSession) {
	s.mu.Lock()
	if cur, ok := s.sessions[name]; ok && cur == who {
		delete(s.sessions, name)
	}
	s.mu.Unlock()
}

// pump 常驻读 PTY：写历史、喂扫描器、投递给已 attach 的客户端（永远读，子进程才不会阻塞）。
func (s *termSession) pump() {
	buf := make([]byte, 32<<10)
	for {
		n, err := s.ptmx.Read(buf)
		if n > 0 {
			s.mu.Lock()
			now := time.Now()
			s.appendLocked(buf[:n])
			s.scan.write(buf[:n])
			// 屏态 vt 与 ring 同锁喂入：ring 仍是 legacy 回放源与诊断，vt 是 surface/检测真源。
			// （surface 投递的「锁内取脏行快照、锁外编码发送」在 2.x 的投递路径上做。）
			s.vt.Write(buf[:n])
			s.contentSeq++ // 内容序号：检测侧的空闲短路判据（任务 4.7）
			// surface 投递：只做唤醒（实际取快照/压缩/发送在投递循环里，绝不占着 pump 的锁）。
			if c := s.attached; c != nil && c.surface {
				s.wakeSurface()
			}
			s.countOutLocked(n, now)
			s.lastOut = now
			s.lastActive = now
			if s.scan.changed {
				s.scan.changed = false
				s.pushStateLocked()
				// 裸 OSC 9 通知转发（surface 腿）：双语义判别已在 termScan 里做完（9;4 是 progress）。
				if c := s.attached; c != nil && c.surface {
					go s.notifyFromScan()
				}
			}
			s.deliverLocked()
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
	prevAgent := s.agent
	ev, scanned := s.screenEvidenceLocked(now, procs, fg)
	agentChanged = s.agent != prevAgent

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
	if v.stateV2 != s.stateV2 {
		if s.hygiene.shouldHoldWorkingToIdle(s.stateV2, v.stateV2, visibleIdle, visibleBlocker,
			agentChanged, processExited, now) {
			return // 本拍按住不发（暂态空屏被确认窗吸收）
		}
	}
	publish := v.stateV2 != s.stateV2 || v.agent != prevAgent
	if !publish && s.hygiene.shouldRepublishBlocked(s.stateV2, now) {
		publish = true // blocked 持续期间定期重发，保持消费方新鲜
	}
	if !publish {
		return
	}
	s.agent, s.stateV2 = v.agent, v.stateV2
	s.state = legacyState(v.stateV2)
	if s.svc.logf != nil {
		// 状态行带**依据**（哪条腿 + 规则/版本/来源），规格要求可追溯。
		s.svc.logf("term: 会话 %s 状态 %s/%s（fg=%d procs=%d 依据=%s）",
			s.name, agentName(v.agent), stateNameV2(v.stateV2), fg, len(procs), v.evidence)
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
	if s.svc.manifests == nil || s.vt == nil || s.vt.Terminal() == nil {
		return nil, false
	}
	agentKnown := s.agent != agentShell && s.agent != agentOther && s.agent != agentUnknown
	if s.hygiene.shouldSkipScreenScan(s.stateV2, agentKnown, false, false, s.contentSeq, s.lastScanSeq, now) {
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
	comp, ok := s.svc.manifests.ForProcess(procName)
	if !ok {
		return nil, false
	}
	term := s.vt.Terminal()
	// 标题走 termScan（单一来源，design D1），progress 也是——不用 vt 的标题查询。
	res := comp.Evaluate(manifest.Input{
		// 只喂**一屏**（视口）纯文本：契约是「最近约一屏」，不是整条回滚。
		Screen:      term.ScreenText(),
		OSCTitle:    s.scan.TitleEvidence(),
		OSCProgress: progressPayload(s.scan.Progress()),
	})
	ev := &screenEvidence{
		state:          stateV2FromManifest(res.State),
		visibleIdle:    res.VisibleIdle,
		visibleBlocker: res.VisibleBlocker,
		visibleWorking: res.VisibleWorking,
		version:        comp.Manifest.Version,
		source:         string(comp.Manifest.Source),
		fallback:       res.FallbackReason,
	}
	if res.MatchedRule != nil {
		ev.ruleID = res.MatchedRule.ID
	}
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
	client := &termClient{conn: c}
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
	case opHello:
		cols, rows, create, name, derr := decHello(f.payload)
		if derr != nil {
			_ = client.frame(opError, encError("bad_hello", derr.Error()))
			return
		}
		// 能力协商（任务 2.1）：HELLO 尾随 capability 块 → 这条腿走 surface 还是 legacy。
		// 畸形块用**独立错误码**（不得复用「协议版本不匹配」路径，规格要求二者可区分）。
		caps, present, caperr := decCapability(helloTail(f.payload, name))
		if caperr != nil {
			_ = client.frame(opError, encError("bad_capability", caperr.Error()))
			return
		}
		if present && wantsSurface(caps) {
			if !surfaceCapable() {
				// 本会话/本构建没有服务端 vt ⇒ 明确报错，让客户端回落 legacy（不是静默降级）。
				_ = client.frame(opError, encError("surface_unavailable",
					"本出口没有服务端 vt（HOMEWAY_TERM_VT=off 或平台不支持）"))
				return
			}
			client.surface = true
			client.leg = newSurfaceLeg()
		}
		if !termNameRx.MatchString(name) {
			_ = client.frame(opError, encError("invalid_name", "会话名只能是 [A-Za-z0-9._-]{1,64}"))
			return
		}
		ss, cerr := s.attachOrCreate(name, cols, rows, create)
		if cerr != nil {
			_ = client.frame(opError, encError(cerr.code, cerr.msg))
			return
		}
		s.stream(ss, client, c)
	default:
		_ = client.frame(opError, encError("bad_op", fmt.Sprintf("首帧必须是 HELLO/LIST/KILL（收到 0x%02x）", f.op)))
	}
}

type termErr struct {
	code string
	msg  string
}

func (e *termErr) Error() string { return e.code + ": " + e.msg }

func termErrf(code, format string, args ...any) *termErr {
	return &termErr{code: code, msg: fmt.Sprintf(format, args...)}
}

func (s *termService) attachOrCreate(name string, cols, rows uint16, create bool) (*termSession, *termErr) {
	s.mu.Lock()
	ss := s.sessions[name]
	if ss == nil {
		if !create {
			s.mu.Unlock()
			return nil, termErrf("no_session", "会话 %s 不存在", name)
		}
		if len(s.sessions) >= s.cfg.maxSessions {
			s.mu.Unlock()
			return nil, termErrf("too_many", "会话数已达上限 %d，请先关闭一些会话", s.cfg.maxSessions)
		}
		var err error
		ss, err = s.spawnLocked(name, cols, rows)
		if err != nil {
			s.mu.Unlock()
			return nil, termErrf("spawn_failed", "%v", err)
		}
		s.sessions[name] = ss
	}
	s.mu.Unlock()

	// 先定尺寸（SIGWINCH 触发的重绘落在回放快照之后），再做历史。
	ss.resize(cols, rows)
	return ss, nil
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
		state:      stateUnknown,
		lastOut:    now,
		lastActive: now,
		cols:       cols,
		rows:       rows,
	}
	ss.epochs = append(ss.epochs, termEpoch{off: 0, cols: cols, rows: rows})
	// 服务端 vt：失败只让**本会话**退化为 legacy（surface 客户端 attach 会得到明确错误码），
	// 既有 legacy 会话与其它会话都不受影响（term-surface-protocol 的降级场景）。
	if sv, verr := newSessionVT(s.cfg, cols, rows); verr == nil {
		// 查询应答写回 PTY：程序问终端（DA1/DSR/DECRQM/OSC 10-11），由服务端 vt 按真实模式答。
		// 不装这条腿，vim/htop/tmux 这类启动探测终端的程序会卡住（legacy 模式下是客户端 vt 在做）。
		ptmxForSink := ptmx
		sv.SetResponseSink(func(p []byte) { _, _ = ptmxForSink.Write(p) })
		// 剪贴板双向（OSC 52）：写 → CLIPBOARD 帧转给客户端；读 → 命中客户端最近上报的缓存。
		sv.EnableClipboardWrite()
		sv.EnableClipboardRead()
		if id := sv.RegistryID(); id != 0 {
			ss.vtID = id
			registerVTSession(id, ss)
		}
		ss.vt = sv
	} else if s.logf != nil {
		s.logf("term: 会话 %s 无服务端 vt（%v）→ 该会话仅 legacy 原始字节模式", name, verr)
	}
	if s.logf != nil {
		s.logf("term: 新建会话 %s（pid=%d %dx%d shell=%s）", name, ss.pid, cols, rows, shell)
	}
	go ss.pump()
	if surfaceCapable() {
		ss.surfaceWake = make(chan struct{}, 1)
		ss.clipChan = make(chan string, 8)
		go ss.surfaceLoop()
	}
	return ss, nil
}

// resize 应用新尺寸（幂等）：PTY setsize + 记录 epoch。
func (s *termSession) resize(cols, rows uint16) {
	if cols == 0 || rows == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done || s.ptmx == nil || (s.cols == cols && s.rows == rows) {
		return
	}
	_ = pty.Setsize(s.ptmx, &pty.Winsize{Cols: cols, Rows: rows})
	s.noteSizeLocked(cols, rows)
	s.vt.Resize(cols, rows) // vt 回滚重排（surface 的 Replace 语义依赖它）
}

// sentinelRepaint 尺寸哨兵：sentinel → 真实尺寸，两次 SIGWINCH 逼 TUI 重绘当前屏。
func (s *termSession) sentinelRepaint() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done || s.ptmx == nil {
		return
	}
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

// stream：回放 + 实时循环（连接存续期间一直跑）。
func (s *termService) stream(ss *termSession, client *termClient, c net.Conn) {
	ss.mu.Lock()
	err := ss.attachLocked(client)
	ss.mu.Unlock()
	if err != nil {
		return
	}
	ss.sentinelRepaint()
	if client.surface {
		// 尺寸哨兵要在**快照下发前**完成（design D3）：哨兵刚发完，投递循环还在合并窗里，
		// 所以这里唤醒后取到的快照已经是远端按最终尺寸重绘过的屏。
		ss.wakeSurface()
	}

	defer func() {
		ss.mu.Lock()
		if ss.attached == client {
			ss.attached = nil
		}
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
			ss.mu.Unlock()
			if ptmx != nil && len(f.payload) > 0 {
				if _, werr := ptmx.Write(f.payload); werr != nil {
					return
				}
			}
		case opResize:
			cols, rows, derr := decResize(f.payload)
			if derr != nil {
				_ = client.frame(opError, encError("bad_resize", derr.Error()))
				continue
			}
			if client.surface {
				// surface：vt 重排 + 哨兵 + 下一帧全量（隐含重建镜像 + 重置 revision）。
				ss.handleSurfaceResize(client, cols, rows)
				continue
			}
			ss.resize(cols, rows)
		case opInput:
			if client.surface {
				ss.handleInput(client, f.payload)
			}
		case opTheme:
			if client.surface {
				ss.handleTheme(f.payload)
			}
		case opClipboard:
			if client.surface {
				ss.handleClipboardAnswer(f.payload)
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
				_ = client.frame(opError, encError("bad_name", derr.Error()))
				continue
			}
			if kerr := s.kill(name); kerr != nil {
				_ = client.frame(opError, encError(kerr.code, kerr.msg))
			} else {
				_ = client.frame(opOK, nil)
			}
		case opList:
			_ = client.frame(opList, []byte(s.listJSON()))
		case opExplain:
			name, derr := decName(f.payload)
			if derr != nil {
				_ = client.frame(opError, encError("bad_name", derr.Error()))
				continue
			}
			out, eerr := s.explainJSON(name)
			if eerr != nil {
				_ = client.frame(opError, encError(eerr.code, eerr.msg))
				continue
			}
			_ = client.frame(opExplain, []byte(out))
		default:
			_ = client.frame(opError, encError("bad_op", fmt.Sprintf("未知帧 0x%02x", f.op)))
		}
	}
}

// cwdLocked 取会话工作目录（vt 从 OSC 7 解析；剥成文件系统路径）。
// 无 vt（legacy-only）或 shell 未上报时返回空串——列表里该字段缺省不显示。
func (s *termSession) cwdLocked() string {
	if s.vt == nil || s.vt.Terminal() == nil {
		return ""
	}
	return vtPwdPath(s.vt.Terminal().Pwd())
}

// explainJSON 对运行中的会话取实时快照跑一次 explain（任务 4.8 的在线模式）。
//
// 依据链与离线模式**同一套代码**（runExplain），所以两边结论一定一致（规格要求
// 「explain 与列表判定一致」）。
func (s *termService) explainJSON(name string) (string, *termErr) {
	if s.manifests == nil {
		return "", termErrf("detect_off", "本出口的检测被 HOMEWAY_TERM_DETECT=off 关闭")
	}
	s.mu.Lock()
	ss := s.sessions[name]
	s.mu.Unlock()
	if ss == nil {
		return "", termErrf("no_session", "会话 %s 不存在", name)
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.vt == nil || ss.vt.Terminal() == nil {
		return "", termErrf("no_vt", "会话 %s 没有服务端 vt（legacy-only），没有屏幕证据可判", name)
	}
	screen := ss.vt.Terminal().PlainText()
	agent := foregroundAgentNameFor(s.manifests, s, ss)
	if agent == "" {
		return "", termErrf("no_agent", "会话 %s 前台不是已知 agent，没有规则可跑", name)
	}
	out := runExplain(s.manifests, agent, screen, name)
	b, err := json.Marshal(out)
	if err != nil {
		return "", termErrf("marshal", "explain 输出编码失败：%v", err)
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
		return termErrf("no_session", "会话 %s 不存在", name)
	}
	ss.mu.Lock()
	pid := ss.pid
	done := ss.done
	ss.killed = true
	ss.mu.Unlock()
	if done {
		return termErrf("no_session", "会话 %s 已结束", name)
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
	type entry struct {
		Name         string `json:"name"`
		CreatedMs    int64  `json:"createdMs"`
		LastActiveMs int64  `json:"lastActiveMs"`
		Attached     bool   `json:"attached"`
		Agent        string `json:"agent"`
		// State 是**兼容字段**：对旧客户端保持既有取值语义（blocked 显示为既有的
		// 「等待操作」= waiting），绝不出现「未知」回退（任务 4.8 的枚举兼容）。
		State string `json:"state"`
		// StateV2 是新枚举（working/blocked/idle/unknown）：旧客户端忽略未知 JSON 字段，
		// 新客户端读它区分「跑完」与「等批准」。
		StateV2 string `json:"stateV2"`
		Title   string `json:"title"`
		// Cwd 是会话内 shell 经 OSC 7 上报的工作目录（缺省不显示）。
		Cwd  string `json:"cwd,omitempty"`
		Cols uint16 `json:"cols"`
		Rows uint16 `json:"rows"`
		Pid  int    `json:"pid"`
	}
	s.mu.Lock()
	out := make([]entry, 0, len(s.sessions))
	for _, ss := range s.sessions {
		ss.mu.Lock()
		done := ss.done
		if !done {
			out = append(out, entry{
				Name:         ss.name,
				CreatedMs:    ss.created.UnixMilli(),
				LastActiveMs: ss.lastActive.UnixMilli(),
				Attached:     ss.attached != nil,
				Agent:        agentName(ss.agent),
				State:        stateName(ss.state),
				StateV2:      stateNameV2(ss.stateV2),
				Title:        ss.scan.title,
				Cwd:          ss.cwdLocked(),
				Cols:         ss.cols,
				Rows:         ss.rows,
				Pid:          ss.pid,
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
