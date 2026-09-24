// realcli_test.go — 任务 4.5 的「用**我们实际 CLI 版本**的屏幕形态过 explain 复核」。
//
// 夹具是真实抓的：真 PTY 起 CLI（`codex` 0.155.1 / `opencode` v2.0.11，2026-09-23 本机版本），
// 输出喂进我们的 vt（pkg/term/vt），取纯文本落盘（testdata/*-startup.txt，仅把机器路径换成中性路径）。
// 这就是「explain 复核」要的证据链：**真 CLI 字节 → 我们的 vt → 我们的引擎**，全程没有手搓屏幕。
//
// 复核结论（2026-09-23）：
//
//   - opencode 首屏 = idle。opencode.toml **没有 idle 规则**（只有 blocked 的 permission_required
//     与两条 working），所以走「已知 agent 无命中 ⇒ 回落 idle + 标签」，与规格一致。
//   - codex 首屏（首次进入某目录的 **trust 确认框**）判为 idle —— **版本漂移的真发现**：
//     上游 codex.toml **有** trust_directory 规则（p=950, blocked），但它的第一条门是
//     `\A> You are in [^\r\n]+`，即要求 region（top_non_empty_lines(20)）**首行**就是
//     `> You are in …`；codex 0.155.1 在这行之上还画了 ASCII logo 与 `Welcome to Codex…`
//     ⇒ 锚点不成立 ⇒ 不命中。处置按 design 的既定机制：不动移植文件（保持逐字节上游原样），
//     用本地覆盖目录 `<state>/agent-detection/codex.toml` 放松锚点（见
//     TestTrustDialogFixedByOverride —— 它演示的正是这个**最小修法**）。
package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("读夹具 %s：%v", name, err)
	}
	if len(b) == 0 {
		t.Fatalf("夹具 %s 为空", name)
	}
	return string(b)
}

func TestRealCLIStartupScreens(t *testing.T) {
	l := NewLoader("")
	if warns := l.Warnings(); len(warns) > 0 {
		t.Fatalf("内嵌 manifest 不该有告警：%v", warns)
	}

	t.Run("opencode 首屏 = idle（无 idle 规则，走回落）", func(t *testing.T) {
		screen := readFixture(t, "opencode-startup.txt")
		if !strings.Contains(screen, "Ask anything") {
			t.Fatalf("夹具里应含 opencode 输入框占位文案，实际：%q", head(screen, 300))
		}
		c, ok := l.ForProcess("opencode")
		if !ok {
			t.Fatal("opencode 应能识别")
		}
		r := c.Evaluate(Input{Screen: screen})
		if r.State != StateIdle {
			t.Errorf("opencode 首屏应为 idle，实际 %s", r.State)
		}
		if r.MatchedRule != nil {
			t.Logf("（注：现在命中了规则 %s；上游 manifest 更新过？）", r.MatchedRule.ID)
		}
		if r.FallbackReason != DefaultKnownAgentIdleFallback {
			t.Errorf("应走「已知 agent 无命中」回落，实际标签 %q", r.FallbackReason)
		}
	})

	t.Run("codex 首屏信任确认框 = 版本漂移（上游规则锚点不成立）", func(t *testing.T) {
		screen := readFixture(t, "codex-startup.txt")
		if !strings.Contains(screen, "Do you trust the contents of this directory?") {
			t.Fatalf("夹具里应含 codex 的 trust 确认框，实际：%q", head(screen, 400))
		}
		c, ok := l.ForProcess("codex")
		if !ok {
			t.Fatal("codex 应能识别")
		}
		r := c.Evaluate(Input{Screen: screen})
		// 记录**现状**（characterization）：判为 idle 走回落。屏幕语义是「等用户选择」，
		// 但 trust_directory 规则因 \A 锚点（要求区域首行是 `> You are in …`）不成立而不命中——
		// 这是规则与 CLI 版本的漂移，不是引擎问题。处置见下一个用例（本地覆盖放松锚点）。
		if r.State != StateIdle {
			t.Errorf("现状应为 idle（上游规则不覆盖 trust 框），实际 %s；若上游已覆盖请更新本用例", r.State)
		}
		if r.FallbackReason != DefaultKnownAgentIdleFallback {
			t.Errorf("应走回落，实际标签 %q", r.FallbackReason)
		}
	})
}

// 处置路径的端到端证明：本地覆盖能把这个真实屏幕判成 blocked。
func TestTrustDialogFixedByOverride(t *testing.T) {
	dir := t.TempDir()
	// **最小修法**：照上游那条规则写，只把 `\A` 锚点换成 contains（版本漂移的根因就是锚点）。
	override := `id = "codex"
version = "local-trust-dialog"
min_engine_version = 3

[[rules]]
id = "trust_directory"
state = "blocked"
priority = 950
region = "top_non_empty_lines(20)"
visible_blocker = true
# 上游版本（manifest 原样）第一条门是 '\A> You are in [^\r\n]+'——要求区域首行就是它；
# codex 0.155.1 在这行之上画了 logo，锚点不成立。这里只放松这一点，其余保持上游写法。
all = [
  { contains = ["> you are in "] },
  { regex = ['(?s)Do\s+you\s+trust\s+the\s+contents\s+of\s+this\s+directory\?'] },
]
`
	if err := os.WriteFile(filepath.Join(dir, "codex.toml"), []byte(override), 0o644); err != nil {
		t.Fatal(err)
	}
	l := NewLoader(dir)
	if warns := l.Warnings(); len(warns) > 0 {
		t.Fatalf("合法覆盖不该有告警：%v", warns)
	}
	c, ok := l.ForProcess("codex")
	if !ok {
		t.Fatal("codex 应能识别")
	}
	if c.Manifest.Source != SourceOverride {
		t.Fatalf("应来自覆盖文件，实际 %s", c.Manifest.Source)
	}
	r := c.Evaluate(Input{Screen: readFixture(t, "codex-startup.txt")})
	if r.State != StateBlocked || !r.VisibleBlocker {
		t.Fatalf("覆盖规则应把 trust 框判成 blocked：state=%s blocker=%v matched=%v",
			r.State, r.VisibleBlocker, r.MatchedRule)
	}
	if r.MatchedRule == nil || r.MatchedRule.ID != "trust_directory" {
		t.Errorf("应命中 trust_directory，实际 %+v", r.MatchedRule)
	}
}

func head(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
