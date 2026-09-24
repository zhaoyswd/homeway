//go:build !windows

// term_agent.go — 会话里「现在在跑哪个 agent CLI」与「任务在干什么」的判定。
//
// 数据来源（五路，权威顺序见下）：
//
//	① 会话前台进程组 + 进程树 —— **身份腿**（终端语义：用户此刻在跟谁交互）
//	② 近几秒的 PTY 输出**字节数** —— 输出腿（TUI 有进展就必须重绘：spinner/流式/工具输出，
//	   实测任务期 2~5KB/s、空闲 0 B/s）
//	③ CPU 时间增量 —— **只对 shell/other 生效**（agent 的 CPU 信号全是噪声：MCP server 保活
//	   20~70ms/s 假阳性、codex 任务期 0 增量假阴性，见阈值注释）
//	④ 屏幕证据（pkg/term/manifest 的 region+谓词规则）—— blocked/idle 的权威
//	⑤ OSC 21337 状态直报（Fig/Amazon Q 集成 CLI）—— **最高权威**（agent 亲口说的）
//
// 权威顺序（design D6 / term-agent-state 的「证据融合与单一权威」）：
//
//	CLI 直报(⑤) > 输出腿(②，shell/other 叠加③) 与 屏幕证据(④) 分状态各管一段
//
// 具体：working 以输出腿为准（agent 永不看 CPU）；blocked 以屏幕证据为准（输出腿无法否决
// ——批准表单在等用户时 TUI 可能仍在闪烁重绘）；idle 由屏幕证据或「无命中回落」给出。
// 各腿 MUST NOT 同时作为同一状态的竞争权威。
//
// 判定是**纯函数**（喂进程表 + 上轮采样 + 当前时间 + 屏幕证据，出 agent/state/quiet），
// 因此可以用夹具单测，不依赖真跑起某个 CLI。平台差异只在「怎么拿到进程表」那一层
// （term_agent_unix.go）。
package term

import (
	"path"
	"strings"
	"time"
)

// procInfo 一条进程记录（平台的进程表拍平成这个样子）。
type procInfo struct {
	pid  int
	ppid int
	pgid int
	// cpu 是累计 CPU 时间的**单调刻度**（linux: jiffies；darwin: ps 的 time * 100）。
	// 只用来做两次采样之间的差值，单位本身不重要，但必须自洽。
	cpu int64
	// args 是命令行（argv 拼起来；darwin 用 ps 的 command= 列）。
	args string
}

// agentProbe：一轮采样需要的输入。
type agentProbe struct {
	procs  []procInfo
	fgPgid int // 会话前台进程组（0 = 拿不到）
	// prevCPU 上一轮同一进程组的 CPU 累计刻度（-1 = 没有上轮）。
	// 只对 shell/other 生效：agent 判定完全不看 CPU（见 agentCPUIgnored）。
	prevCPU   int64
	prevProcs []procInfo
	// outBytes 近 agentOutWindowSec 秒的 PTY 输出字节数（输出腿的输入，
	// 由 termSession 的秒桶累计、sample 求和后喂进来）。
	outBytes int64
	// prevState / prevQuiet 磁滞输入：上一拍状态与截至上一拍的连续安静拍数。
	prevState byte
	prevQuiet int
	shellPID  int // 会话 shell 的 pid（用于判定「前台就是 shell 本身」）
	now       time.Time

	// screen 是屏幕证据（manifest 引擎的判定结果）；nil = 本拍没扫屏（短路）或引擎不可用。
	screen *screenEvidence
	// oscStatus 是 OSC 21337 的直报状态值（空 = 无）。它是**最高权威**证据。
	oscStatus string
}

// screenEvidence 一次屏幕证据判定（manifest 引擎输出的、判定需要的那几个字段）。
//
// 为什么不直接传 manifest.Result：agent.go 要能被夹具单测（不引入引擎依赖的构造成本），
// 而且这里只需要「状态 + 三个可见位 + 依据」这几项。
type screenEvidence struct {
	state          byte // stateV2* 之一
	visibleIdle    bool
	visibleBlocker bool
	visibleWorking bool
	// 依据（进状态行日志：规则 id / manifest 版本 / 来源）——规格要求「状态行日志带规则/版本/来源依据」。
	ruleID   string
	version  string
	source   string
	fallback string
}

// agentVerdict：判定结果。
type agentVerdict struct {
	agent byte
	// state 是 **legacy 口径**（working→stateRunning、blocked→stateWaiting）——旧客户端的
	// 兼容值，见任务 4.8 的枚举兼容。
	state byte
	// stateV2 是新枚举（working/blocked/idle/unknown），新客户端读它区分「跑完」与「等批准」。
	stateV2 byte
	cpu     int64 // 本轮采到的 CPU 刻度（下次采样当 prevCPU 用）
	// quiet 截至本轮的连续安静拍数（working 时清零；调用方存下来当 prevQuiet）。
	quiet int
	// evidence 是本次判定的依据（哪条腿 + 规则/版本/来源），进状态行日志。
	evidence string
}

// stateV2 枚举（任务 4.8：LIST JSON 的 stateV2 字段与 STATE 帧的新枚举）。
const (
	stateV2Unknown byte = 0
	stateV2Working byte = 1
	stateV2Blocked byte = 2
	stateV2Idle    byte = 3
)

// stateNameV2 把新枚举渲染成字符串（LIST JSON 用）。
func stateNameV2(s byte) string {
	switch s {
	case stateV2Working:
		return "working"
	case stateV2Blocked:
		return "blocked"
	case stateV2Idle:
		return "idle"
	}
	return "unknown"
}

// legacyState 把 stateV2 折成旧客户端的 state 值（**兼容契约**：blocked 在旧客户端显示为
// 既有的「等待操作」语义 = stateWaiting，绝不出现「未知」回退）。
func legacyState(v2 byte) byte {
	switch v2 {
	case stateV2Working:
		return stateRunning
	case stateV2Blocked, stateV2Idle:
		// blocked 与 idle 在旧口径下都是「没在跑」的等待态：blocked 必须映射到 waiting
		// （旧 App 显示「等待操作」），idle 保持 idle。
		if v2 == stateV2Blocked {
			return stateWaiting
		}
		return stateIdle
	}
	return stateUnknown
}

// 判定阈值（2026-09-18 实测标定，Mac mini / codex 1.x / opencode 1.18）：
//   - codex、opencode 空闲时 PTY 输出 0 B/s（连光标都不闪）、任务期 2~5KB/s 持续；
//   - MCP server 子进程（uvx/python）保活烧 20~70ms/s CPU——「任何 CPU 增量就算
//     running」会让挂着的 opencode 永久显示运行中；
//   - codex 的 Rust 实现任务期 CPU 增量也常为 0（<10ms/s）——CPU 腿对 agent 既假阳
//     又假阴，因此 agent 判定**只用输出量**；
//   - zsh 空闲唤醒 <10ms/s、真跑安静命令（编译/压缩）≥100ms/s——shell/other 保留
//     CPU 腿但设阈值。cpu 刻度 1 = 10ms（darwin ps time*100 / linux jiffies）。
const (
	// agentOutWindowSec 输出量统计窗口（秒）。
	agentOutWindowSec = 3
	// agentOutThreshold 窗口内 ≥ 此字节数 = 在说话。闪烁级重绘（几十字节/次）
	// 与 spinner/流式（≥500B/s）之间取的分界。
	agentOutThreshold = 300
	// shellCPUBusyDelta shell/other 一拍 CPU 增量 ≥ 此刻度数（100ms）= 真在算。
	shellCPUBusyDelta = 10
	// agentQuietDegrade running 降级需要窗口排空后再连续安静的拍数（磁滞：
	// 升级即时，降级要 quiet > 此值）。
	agentQuietDegrade = 2
)

// agentNames 已知 agent 的可执行名（不含扩展名）。新增一种 CLI 只加这里一行。
var agentNames = []struct {
	name  string
	agent byte
}{
	{"codex", agentCodex},
	{"claude", agentClaude},
	{"opencode", agentOpencode},
	{"openclaw", agentOpenclaw},
}

// classifyAgent 从进程表里判断前台进程组「正在跑什么」。
func classifyAgent(p agentProbe) agentVerdict {
	v := agentVerdict{agent: agentShell, state: stateIdle, stateV2: stateV2Idle, cpu: -1}
	if len(p.procs) == 0 || p.fgPgid == 0 {
		v.agent = agentUnknown
		v.state, v.stateV2 = stateUnknown, stateV2Unknown
		v.evidence = "no-procs"
		return v
	}

	// 前台进程组里的成员（终端把前台任务放在同一个 pgid 下）。
	fg := make([]procInfo, 0, 4)
	for _, pr := range p.procs {
		if pr.pgid == p.fgPgid {
			fg = append(fg, pr)
		}
	}
	if len(fg) == 0 {
		v.agent = agentUnknown
		v.state, v.stateV2 = stateUnknown, stateV2Unknown
		v.evidence = "no-fg"
		return v
	}

	// 谁在跑 agent：取命中名字的进程里 **最深** 的那个（包一层 npx/node 也认）。
	matched := byte(agentOther)
	var matchedProc *procInfo
	for i := range fg {
		pr := &fg[i]
		a, ok := agentOfCommand(pr.args)
		if !ok {
			continue
		}
		if matchedProc == nil || isDescendantOf(pr.pid, matchedProc.pid, p.procs) {
			matched, matchedProc = a, pr
		}
	}
	if matchedProc != nil {
		v.agent = matched
	} else if anyShellInGroup(fg, p.shellPID) {
		v.agent = agentShell
	} else {
		v.agent = agentOther
	}
	// 已知 agent 在前台（codex/claude/opencode/openclaw…）——判定完全走输出腿，
	// CPU 腿只留给 shell/other（agentCPUIgnored 处的阈值注释有实测依据）。
	isAgent := matchedProc != nil

	// CPU 累计：前台进程组所有成员之和（含被 exec 换掉的子进程）。无论判定用不用，
	// 都要采出来返回给下一拍当 prevCPU（shell/other 的腿要用）。
	var cpu int64
	for _, pr := range fg {
		if pr.cpu > 0 {
			cpu += pr.cpu
		}
	}
	v.cpu = cpu

	// 输出腿：窗口内输出量 ≥ 阈值 = 在说话（闪烁级重绘被滤掉）。
	outTalking := p.outBytes >= agentOutThreshold
	// CPU 腿（仅 shell/other）：一拍增量 ≥ 100ms = 真在算（zsh 空闲唤醒被滤掉）。
	var cpuDelta int64
	if p.prevCPU >= 0 && cpu > p.prevCPU {
		cpuDelta = cpu - p.prevCPU
	}
	working := outTalking || (!isAgent && cpuDelta >= shellCPUBusyDelta)

	// 磁滞：安静拍计数（working 清零；否则累加，供降级判断与下一拍）。
	quiet := 0
	if !working {
		quiet = p.prevQuiet + 1
		if quiet > 99 {
			quiet = 99
		}
		// 降级保护：上一拍 running 且安静拍数未超限 → 维持 running（升级即时、
		// 降级要窗口排空后连续安静 agentQuietDegrade+1 拍）。
		if p.prevState == stateRunning && quiet <= agentQuietDegrade {
			working = true
		}
	}
	v.quiet = quiet

	v.stateV2, v.evidence = fuseState(fuseInput{
		agent:     v.agent,
		isAgent:   isAgent,
		working:   working,
		quiet:     quiet,
		oscStatus: p.oscStatus,
		screen:    p.screen,
		prevState: p.prevState,
	})
	v.state = legacyState(v.stateV2)
	return v
}

// fuseInput 是融合的纯输入（便于夹具单测：不碰进程表、不碰引擎）。
type fuseInput struct {
	agent     byte
	isAgent   bool
	working   bool // 输出腿（shell/other 已叠加 CPU 腿）
	quiet     int
	oscStatus string
	screen    *screenEvidence
	prevState byte
}

// fuseState 按权威顺序融合五路证据，输出 stateV2 + 依据字符串。
//
// 顺序（design D6）：
//  1. **CLI 直报（OSC 21337）= 最高权威**：agent 亲口说的状态压过一切推断。
//     只在识别到状态值时生效；认不出取值就不当证据（不猜）。
//  2. **working**：输出腿（shell/other 含 CPU 腿）——「在说话」就是工作中。
//  3. **blocked**：屏幕证据的 visible_blocker（严格命中批准/提问/权限 UI 规则）。
//     **输出腿无法否决**：批准表单在等用户时 TUI 仍可能闪烁重绘，不能因此显示「工作中」。
//  4. **idle**：屏幕证据的 visible_idle；或已知 agent 无命中时的回落。
//  5. 进程退出/拿不到进程表 ⇒ idle/unknown（由调用方在无 procs 时给出）。
func fuseState(in fuseInput) (byte, string) {
	// ① CLI 直报。
	if in.oscStatus != "" {
		if v2, ok := directReportState(in.oscStatus); ok {
			return v2, "osc21337:" + in.oscStatus
		}
	}
	// ② blocked 优先于输出腿（屏幕权威，输出腿无法否决）。
	if in.screen != nil && in.screen.visibleBlocker {
		return stateV2Blocked, "screen:" + in.screen.describe()
	}
	// ③ 输出腿。
	if in.working {
		return stateV2Working, "output"
	}
	// ④ 屏幕证据的 idle。
	if in.screen != nil && in.screen.visibleIdle {
		return stateV2Idle, "screen:" + in.screen.describe()
	}
	// ⑤ 回落：已知 agent 且没有 working 证据 ⇒ idle（带标签，见 manifest 的回落口径）。
	if in.isAgent {
		if in.screen != nil && in.screen.fallback != "" {
			return stateV2Idle, "fallback:" + in.screen.fallback
		}
		return stateV2Idle, "agent-idle-fallback"
	}
	return stateV2Idle, "shell-idle"
}

// directReportState 把 OSC 21337 的 status 值映射到 stateV2（认不出返回 false，不当证据）。
func directReportState(status string) (byte, bool) {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "working", "busy", "running", "in_progress", "in-progress":
		return stateV2Working, true
	case "blocked", "waiting", "needs_input", "needs-input", "waiting_for_input", "permission":
		return stateV2Blocked, true
	case "idle", "ready", "done", "complete", "completed":
		return stateV2Idle, true
	}
	return 0, false
}

// describe 给出屏幕证据的可读依据（规则 id + 版本 + 来源；规格要求日志带这三样）。
func (s *screenEvidence) describe() string {
	if s == nil {
		return ""
	}
	parts := make([]string, 0, 4)
	if s.ruleID != "" {
		parts = append(parts, "rule="+s.ruleID)
	}
	if s.version != "" {
		parts = append(parts, "ver="+s.version)
	}
	if s.source != "" {
		parts = append(parts, "src="+s.source)
	}
	if s.fallback != "" {
		parts = append(parts, "fallback="+s.fallback)
	}
	if len(parts) == 0 {
		return "no-rule"
	}
	return strings.Join(parts, ",")
}

// agentOfCommand 判断一条命令行是不是已知 agent。识别规则刻意保守（宁可不认，不要乱认：
// 认错会让界面显示错误的图标/状态）：
//   - argv[0] 的可执行名命中 → 命中（`codex`、`/usr/local/bin/codex`）
//   - 带路径的 token 命中 basename → 命中（`node .../@openai/codex/bin/codex.js`）
//   - 裸名字只在前面是 **runner** 时命中（`npx codex`、`npm exec codex`、`bunx claude`）
//
// ⇒ `grep codex /var/log/x` 这类「把名字当参数用」的命令不会误判。
func agentOfCommand(cmdline string) (byte, bool) {
	fields := strings.Fields(cmdline)
	if len(fields) == 0 {
		return 0, false
	}
	if a, ok := agentNameOfToken(fields[0]); ok {
		return a, true
	}
	for i := 1; i < len(fields); i++ {
		tok := fields[i]
		if strings.HasPrefix(tok, "-") {
			continue
		}
		a, ok := agentNameOfToken(tok)
		if !ok {
			continue
		}
		if strings.Contains(tok, "/") || isRunnerToken(fields[i-1]) {
			return a, true
		}
	}
	return 0, false
}

// agentNameOfToken 把单个 token 的可执行名（去扩展名）映射到 agent 枚举。
func agentNameOfToken(tok string) (byte, bool) {
	base := path.Base(tok)
	for _, ext := range []string{".js", ".mjs", ".cjs", ".exe"} {
		base = strings.TrimSuffix(base, ext)
	}
	if base == "" {
		return 0, false
	}
	for _, known := range agentNames {
		if base == known.name {
			return known.agent, true
		}
	}
	return 0, false
}

// isRunnerToken：包一层跑 agent 的常见 runner（npx/bunx/yarn dlx/pnpm dlx/npm exec）。
func isRunnerToken(tok string) bool {
	switch path.Base(tok) {
	case "npx", "bunx", "dlx", "exec":
		return true
	}
	return false
}

// anyShellInGroup 判断前台进程组里是不是「就是那个登录 shell」（没有别的前台程序）。
func anyShellInGroup(fg []procInfo, shellPID int) bool {
	for _, pr := range fg {
		if shellPID != 0 && pr.pid == shellPID {
			return true
		}
	}
	// shellPID 拿不到时退化为「命令行首 token 是常见 shell 名」。
	fields := strings.Fields(fg[0].args)
	if len(fields) == 0 {
		return false
	}
	switch path.Base(fields[0]) {
	case "sh", "bash", "zsh", "fish", "dash", "ksh", "tcsh", "csh":
		return true
	}
	return false
}

// isDescendantOf 判断 pid 是不是 anc 的后代（用于在多个命中里取「最深」的那个）。
func isDescendantOf(pid, anc int, procs []procInfo) bool {
	if anc == 0 {
		return false
	}
	ppid := map[int]int{}
	for _, pr := range procs {
		ppid[pr.pid] = pr.ppid
	}
	for cur, hops := pid, 0; hops < 16; hops++ {
		p, ok := ppid[cur]
		if !ok || p <= 1 {
			return false
		}
		if p == anc {
			return true
		}
		cur = p
	}
	return false
}

// foregroundAgentName 取前台进程组里「最像已知 agent」的可执行名（known 决定什么算已知——
// 由规则表 index.toml 决定，所以新增 agent 不必改 Go 代码）。
//
// 与身份腿同一套「取最深命中」的规则（包一层 npx/node 也认），只是这里要的是**进程名原文**。
func foregroundAgentName(procs []procInfo, fgPgid int, known func(string) bool) string {
	if fgPgid == 0 {
		return ""
	}
	best := ""
	var bestProc *procInfo
	for i := range procs {
		pr := &procs[i]
		if pr.pgid != fgPgid {
			continue
		}
		name := agentTokenName(pr.args, known)
		if name == "" {
			continue
		}
		if bestProc == nil || isDescendantOf(pr.pid, bestProc.pid, procs) {
			best, bestProc = name, pr
		}
	}
	return best
}

// agentTokenName 从命令行里取出「已知 agent 的可执行名」原文（认不出返回空串）。
// 匹配口径与 agentOfCommand 一致：argv[0] 的 basename、带路径的 token、runner 之后的裸名字。
func agentTokenName(cmdline string, known func(string) bool) string {
	fields := strings.Fields(cmdline)
	if len(fields) == 0 {
		return ""
	}
	cand := []string{fields[0]}
	for i := 1; i < len(fields); i++ {
		tok := fields[i]
		if strings.HasPrefix(tok, "-") {
			continue
		}
		if strings.Contains(tok, "/") || isRunnerToken(fields[i-1]) {
			cand = append(cand, tok)
		}
	}
	for _, tok := range cand {
		base := path.Base(tok)
		for _, ext := range []string{".js", ".mjs", ".cjs", ".exe"} {
			base = strings.TrimSuffix(base, ext)
		}
		if known(base) {
			return base
		}
	}
	return ""
}
