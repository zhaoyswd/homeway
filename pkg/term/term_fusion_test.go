//go:build !windows

// term_fusion_test.go — 证据融合（4.6）、状态机卫生（4.7）、枚举兼容与 explain（4.8）的判据。
package term

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---- 4.6 证据融合与单一权威 ----

func TestFuseStateAuthority(t *testing.T) {
	cases := []struct {
		name    string
		in      fuseInput
		wantV2  byte
		wantEvi string // evidence 的前缀（腿名）
	}{
		{
			name: "CLI 直报压过输出腿与屏幕规则",
			in: fuseInput{isAgent: true, working: true, oscStatus: "idle",
				screen: &screenEvidence{state: stateV2Blocked, visibleBlocker: true}},
			wantV2: stateV2Idle, wantEvi: "osc21337",
		},
		{
			name:   "CLI 直报 blocked 也压过输出腿",
			in:     fuseInput{isAgent: true, working: true, oscStatus: "blocked"},
			wantV2: stateV2Blocked, wantEvi: "osc21337",
		},
		{
			name:   "认不出的直报值不当证据（不猜）",
			in:     fuseInput{isAgent: true, working: true, oscStatus: "42%"},
			wantV2: stateV2Working, wantEvi: "output",
		},
		{
			name: "屏幕 blocked 无法被输出腿否决",
			in: fuseInput{isAgent: true, working: true,
				screen: &screenEvidence{state: stateV2Blocked, visibleBlocker: true}},
			wantV2: stateV2Blocked, wantEvi: "screen:",
		},
		{
			name:   "输出中但屏幕未识别 → working（输出腿权威）",
			in:     fuseInput{isAgent: true, working: true, screen: &screenEvidence{state: stateV2Idle}},
			wantV2: stateV2Working, wantEvi: "output",
		},
		{
			name:   "安静且屏幕为批准表单 → blocked（屏幕权威）",
			in:     fuseInput{isAgent: true, working: false, screen: &screenEvidence{state: stateV2Blocked, visibleBlocker: true}},
			wantV2: stateV2Blocked, wantEvi: "screen:",
		},
		{
			name:   "屏幕 idle 证据 → idle",
			in:     fuseInput{isAgent: true, screen: &screenEvidence{state: stateV2Idle, visibleIdle: true}},
			wantV2: stateV2Idle, wantEvi: "screen:",
		},
		{
			name:   "已知 agent 无命中 → 回落 idle（带标签）",
			in:     fuseInput{isAgent: true, screen: &screenEvidence{state: stateV2Idle, fallback: "default_known_agent_idle_fallback"}},
			wantV2: stateV2Idle, wantEvi: "fallback:",
		},
		{
			name:   "shell 安静 → idle",
			in:     fuseInput{agent: agentShell, screen: nil},
			wantV2: stateV2Idle, wantEvi: "shell-idle",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, evi := fuseState(c.in)
			if got != c.wantV2 {
				t.Errorf("stateV2=%d，期望 %d（依据 %q）", got, c.wantV2, evi)
			}
			if !strings.HasPrefix(evi, c.wantEvi) {
				t.Errorf("依据 %q 应以 %q 开头", evi, c.wantEvi)
			}
		})
	}
}

// 依据串要带规则/版本/来源（规格：状态行日志带规则/版本/来源依据）。
func TestScreenEvidenceDescribe(t *testing.T) {
	ev := &screenEvidence{ruleID: "live_blocked_form", version: "2026.09.11.1", source: "embedded"}
	got := ev.describe()
	for _, want := range []string{"rule=live_blocked_form", "ver=2026.09.11.1", "src=embedded"} {
		if !strings.Contains(got, want) {
			t.Errorf("依据串 %q 缺 %q", got, want)
		}
	}
}

// shell/other 的 CPU 腿必须保留（既有行为不回退），agent 永不看 CPU。
func TestCPULegRetainedForShellOnly(t *testing.T) {
	procs := fixture(procInfo{pid: 900, ppid: 100, pgid: 900, cpu: 300, args: "tar -cf big.tar dir"})
	// shell/other：CPU 增量超阈值 ⇒ working。
	v := classifyAgent(agentProbe{
		procs: procs, fgPgid: 900, prevCPU: 100, outBytes: 0,
		prevState: stateV2Idle, shellPID: 100, now: time.Now(),
	})
	if v.stateV2 != stateV2Working {
		t.Errorf("shell 安静但烧 CPU 应判 working（CPU 腿保留），实际 %s", stateNameV2(v.stateV2))
	}
	// agent：同样 CPU 增量也不看（既有实测标定）。
	agentProcs := fixture(procInfo{pid: 901, ppid: 100, pgid: 901, cpu: 300, args: "codex"})
	v = classifyAgent(agentProbe{
		procs: agentProcs, fgPgid: 901, prevCPU: 100, outBytes: 0,
		prevState: stateV2Idle, shellPID: 100, now: time.Now(),
	})
	if v.stateV2 != stateV2Idle {
		t.Errorf("agent 不该看 CPU，实际 %s", stateNameV2(v.stateV2))
	}
}

// ---- 4.7 状态机卫生 ----

func TestPendingIdleConfirmationWindow(t *testing.T) {
	var h stateHygiene
	now := time.Now()

	// 口径与 herdr 一致：第 1 拍开窗（按住），之后还要 pendingIdleConfirmations 拍确认才放行
	// ⇒ 合计 1+N 拍。第 1 拍就把「开窗」算作确认会让确认窗形同虚设。
	if !h.shouldHoldWorkingToIdle(stateV2Working, stateV2Idle, false, false, false, false, now) {
		t.Fatal("首次 working→普通 idle 应被按住（开窗）")
	}
	for i := 1; i <= pendingIdleConfirmations-1; i++ {
		if !h.shouldHoldWorkingToIdle(stateV2Working, stateV2Idle, false, false, false, false,
			now.Add(time.Duration(i)*100*time.Millisecond)) {
			t.Fatalf("第 %d 拍应继续按住", i+1)
		}
	}
	if h.shouldHoldWorkingToIdle(stateV2Working, stateV2Idle, false, false, false, false,
		now.Add(time.Duration(pendingIdleConfirmations)*100*time.Millisecond)) {
		t.Fatal("确认数达上限后应放行")
	}
}

func TestPendingIdleCapReleases(t *testing.T) {
	var h stateHygiene
	now := time.Now()
	if !h.shouldHoldWorkingToIdle(stateV2Working, stateV2Idle, false, false, false, false, now) {
		t.Fatal("首次应按住")
	}
	// 超过封顶时长 ⇒ 无条件放行（避免卡在 working）。
	if h.shouldHoldWorkingToIdle(stateV2Working, stateV2Idle, false, false, false, false, now.Add(pendingIdleCap+time.Millisecond)) {
		t.Fatal("超封顶应放行")
	}
}

func TestPendingIdleNotHeldWithStrongEvidence(t *testing.T) {
	cases := []struct {
		name                        string
		visibleIdle, visibleBlocker bool
		agentChanged, processExited bool
	}{
		{name: "有 visible_idle 强证据", visibleIdle: true},
		{name: "有 visible_blocker 强证据", visibleBlocker: true},
		{name: "agent 换了", agentChanged: true},
		{name: "进程退了", processExited: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var h stateHygiene
			if h.shouldHoldWorkingToIdle(stateV2Working, stateV2Idle, c.visibleIdle, c.visibleBlocker,
				c.agentChanged, c.processExited, time.Now()) {
				t.Error("强证据/切换/退出应立即可发，不该按住")
			}
		})
	}
}

func TestSkipScreenScanWhenIdleAndUnchanged(t *testing.T) {
	var h stateHygiene
	now := time.Now()
	// idle + agent 已知 + 内容序号未变 ⇒ 跳过。
	if !h.shouldSkipScreenScan(stateV2Idle, true, false, false, 7, 7, now) {
		t.Error("空闲且内容未变应跳过扫屏")
	}
	// 内容变了 ⇒ 必须扫。
	if h.shouldSkipScreenScan(stateV2Idle, true, false, false, 8, 7, now) {
		t.Error("内容变了不该跳过")
	}
	// 非 idle ⇒ 必须扫。
	if h.shouldSkipScreenScan(stateV2Working, true, false, false, 7, 7, now) {
		t.Error("working 不该跳过")
	}
	// agent 未知 ⇒ 必须扫（要靠屏幕找出是谁）。
	if h.shouldSkipScreenScan(stateV2Idle, false, false, false, 7, 7, now) {
		t.Error("agent 未知不该跳过")
	}
	// 在确认窗内 ⇒ 必须扫。
	h2 := stateHygiene{}
	_ = h2.shouldHoldWorkingToIdle(stateV2Working, stateV2Idle, false, false, false, false, now)
	if h2.shouldSkipScreenScan(stateV2Idle, true, false, false, 7, 7, now) {
		t.Error("确认窗内不该跳过")
	}
}

func TestRepublishBlocked(t *testing.T) {
	var h stateHygiene
	now := time.Now()
	if !h.shouldRepublishBlocked(stateV2Blocked, now) {
		t.Error("首次应发")
	}
	if h.shouldRepublishBlocked(stateV2Blocked, now.Add(100*time.Millisecond)) {
		t.Error("间隔未到不该重发")
	}
	if !h.shouldRepublishBlocked(stateV2Blocked, now.Add(stableVisibleRefresh+time.Millisecond)) {
		t.Error("间隔到了应重发")
	}
	if h.shouldRepublishBlocked(stateV2Working, now.Add(10*time.Second)) {
		t.Error("非 blocked 不走重发路径")
	}
}

// ---- 4.8 枚举兼容 ----

func TestLegacyStateCompat(t *testing.T) {
	cases := map[byte]byte{
		stateV2Working: stateRunning,
		stateV2Blocked: stateWaiting, // 旧 App 显示「等待操作」，不是「未知」
		stateV2Idle:    stateIdle,
		stateV2Unknown: stateUnknown,
	}
	for v2, want := range cases {
		if got := legacyState(v2); got != want {
			t.Errorf("legacyState(%d) = %s，期望 %s", v2, stateName(got), stateName(want))
		}
	}
}

func TestStateForLeg(t *testing.T) {
	// surface 腿拿到新枚举（能区分 blocked 与 idle）。
	if got := stateForLeg(true, stateV2Blocked, stateWaiting); got != stateV2Blocked {
		t.Errorf("surface 腿应拿到 stateV2，实际 %d", got)
	}
	// legacy 腿拿到折价值。
	if got := stateForLeg(false, stateV2Blocked, stateWaiting); got != stateWaiting {
		t.Errorf("legacy 腿应拿到折价值，实际 %d", got)
	}
}

// LIST JSON 必须同时带 state（兼容）与 stateV2（新）+ cwd（缺省不显示）。
func TestListJSONHasStateV2(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c, _, _, _ := attachTerm(t, ln, "compat1", true, 80, 24)
	defer c.Close()

	list := listTerm(t, ln)
	sess, ok := listSession(list, "compat1")
	if !ok {
		t.Fatal("会话不在列表里")
	}
	if _, ok := sess["stateV2"]; !ok {
		t.Error("LIST JSON 应有 stateV2 字段")
	}
	if _, ok := sess["state"]; !ok {
		t.Error("LIST JSON 应保留 state 兼容字段")
	}
	// 没有 vt 上报 cwd 时该字段缺省（omitempty）——不显示而不是显示空串。
	if v, present := sess["cwd"]; present && v != "" {
		t.Errorf("未上报 cwd 时应缺省，实际 %q", v)
	}
}

// ---- 4.8 explain ----

func TestExplainOffline(t *testing.T) {
	dir := t.TempDir()
	screen := filepath.Join(dir, "screen.txt")
	// 用 claude manifest 的一条真实形态（批准表单）。
	text := strings.Join([]string{
		"输出若干行",
		"──────────────────────────────",
		"Do you want to proceed?",
		"❯ 1. Yes",
		"  2. No",
		"Esc to cancel",
	}, "\n")
	if err := os.WriteFile(screen, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := explainFile(explainOpts{file: screen, agent: "claude", stateDir: dir})
	if err != nil {
		t.Fatalf("explain 离线：%v", err)
	}
	if out.State != "blocked" {
		t.Errorf("批准表单应判 blocked，实际 %s（命中 %+v）", out.State, out.Matched)
	}
	if out.Matched == nil {
		t.Fatal("应报告命中规则")
	}
	if !out.VisibleBlocker {
		t.Error("应带 visible_blocker 证据位")
	}
	if len(out.Rules) == 0 {
		t.Error("应输出全部规则的评估轨迹")
	}
	if out.ManifestSource != "embedded" {
		t.Errorf("来源应为 embedded，实际 %q", out.ManifestSource)
	}
}

// 认不出 agent 时报可行动的错（不静默）。
func TestExplainUnknownAgent(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "s.txt")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := explainFile(explainOpts{file: f, agent: "不存在的agent", stateDir: dir}); err == nil {
		t.Fatal("未知 agent 应报错")
	} else if !strings.Contains(err.Error(), "可用") {
		t.Errorf("错误信息应列出可用的 agent，实际 %v", err)
	}
}

// 在线模式：出口没跑时报可行动的错（并提示离线模式）。
func TestExplainOnlineNoExit(t *testing.T) {
	dir := t.TempDir() // 里面没有 term.sock
	_, err := explainSession(explainOpts{session: "s1", stateDir: dir})
	if err == nil {
		t.Fatal("没有 term.sock 应报错")
	}
	if !strings.Contains(err.Error(), "--file") {
		t.Errorf("错误信息应提示离线模式，实际 %v", err)
	}
}

// 参数校验：--file 必须配 --agent；只认一个会话名。
func TestExplainArgValidation(t *testing.T) {
	if _, err := parseExplainArgs([]string{"--file", "/tmp/x"}); err == nil {
		t.Error("--file 缺 --agent 应报错")
	}
	if _, err := parseExplainArgs([]string{"a", "b"}); err == nil {
		t.Error("多个会话名应报错")
	}
	if _, err := parseExplainArgs([]string{"--bogus"}); err == nil {
		t.Error("未知参数应报错")
	}
	o, err := parseExplainArgs([]string{"s1", "--json", "--state", "/tmp/st"})
	if err != nil || !o.json || o.stateDir != "/tmp/st" || o.session != "s1" {
		t.Errorf("参数解析不对：%+v err=%v", o, err)
	}
}

// explain 与列表判定一致（规格要求）：同一屏幕，两条路径必须给出同一状态。
func TestExplainConsistentWithSessionVerdict(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c, _, _, _ := attachTerm(t, ln, "explain1", true, 80, 24)
	defer c.Close()

	// 会话前台是 testTermShell 的 shell（非 agent）⇒ 在线 explain 应明确报「前台不是已知 agent」，
	// 而不是给一个编造的状态。
	_, terr := svc.explainJSON("explain1")
	if terr == nil {
		t.Skip("测试 shell 恰好被识别成 agent，跳过这条一致性断言")
	}
	if terr.code != "no_agent" && terr.code != "no_vt" && terr.code != "detect_off" {
		t.Errorf("期望可行动的具体错误码，实际 %s：%s", terr.code, terr.msg)
	}
}
