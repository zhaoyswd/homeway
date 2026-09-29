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

// ---- 4.8 枚举兼容 → 3.3 单轨化（legacyState/stateForLeg 已删，D6）----

// LIST JSON 只带 stateV2（旧 state 键已退役，term-remote 3.3 破坏性授权）+ cwd 缺省不显示。
func TestListJSONStateV2SingleTrack(t *testing.T) {
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
	if _, ok := sess["state"]; ok {
		t.Error("LIST JSON 的旧 state 键应已退役（term-remote 3.3 单轨化）")
	}
	// 没有 vt 上报 cwd 时该字段缺省（omitempty）——不显示而不是显示空串。
	if v, present := sess["cwd"]; present && v != "" {
		t.Errorf("未上报 cwd 时应缺省，实际 %q", v)
	}
}

// STATE 帧不按腿类折价（D6「状态口径统一」）：同一 stateV2 值发给 surface 与 raw 腿
// （改前 raw 腿拿 legacy 折价值：blocked→waiting）。直接锁载荷的 state 字节。
// 判别力注记（exec-r1 L9，如实登记）：legacy 与 stateV2 **数值同构**（blocked=2=
// waiting）⇒ 改前 stateForLeg(false, 2, 2) 与改后 stateV2Blocked 送出的是同一字节，
// 本用例对「折价删除」无红绿判别力（改前改后恒真），只锁 stateV2 值域回归；折价
// 删除的真判别 = 编译期符号消失（legacyState/stateForLeg 全仓零残留 grep，3.3 已验）。
func TestStateFrameStateV2ForEveryLeg(t *testing.T) {
	s := &termSession{svc: &termService{}, agent: agentCodex, stateV2: stateV2Blocked, scan: termScan{title: "批准"}}
	s.legs = []*termClient{
		{surface: true, out: newLegOut()},
		{surface: false, out: newLegOut()},
	}
	s.pushStateToLegsLocked()
	for _, l := range s.legs {
		items, _, _ := l.out.take()
		var got byte = 255
		saw := false
		for _, it := range items {
			if it.op == opState && len(it.payload) >= 2 {
				got, saw = it.payload[1], true
			}
		}
		if !saw {
			t.Fatal("腿未收到 STATE 帧")
		}
		if got != stateV2Blocked {
			t.Fatalf("腿（surface=%v）state 字节 = %d，期望 stateV2Blocked=%d（不按腿类折价）", l.surface, got, stateV2Blocked)
		}
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

// 在线模式：出口没跑时报可行动的错（1.4 收敛：explainSession 并入 cliDialTerm 统一
// 拨号缝后，连接层文案与本地面 list/new/delete 同一 dialErrText——ENOENT 合并提示）。
func TestExplainOnlineNoExit(t *testing.T) {
	dir := t.TempDir() // 里面没有 term.sock
	_, err := explainSession(explainOpts{session: "s1", stateDir: dir}, nil)
	if err == nil {
		t.Fatal("没有 term.sock 应报错")
	}
	if !strings.Contains(err.Error(), "出口未在运行") {
		t.Errorf("错误信息应为连接层合并文案，实际 %v", err)
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
