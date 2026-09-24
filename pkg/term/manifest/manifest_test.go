// manifest_test.go — 引擎单测（任务 4.1 解析/校验 + 4.2 region + 4.3 求值仲裁 + 4.4 加载）。
//
// 这批测试同时是任务 4.5 的**移植门**：TestEmbeddedManifestsLoad 会把 22 份携署名移植的
// TOML 全部过一遍解析 + 校验 + 编译，任何一份不合格都会红。
package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- 4.1 解析与校验 ----

func TestParseValid(t *testing.T) {
	src := `
id = "demo"
version = "1.0.0"
min_engine_version = 3
aliases = ["demo-cli"]

[[rules]]
id = "r1"
state = "working"
priority = 100
region = "bottom_non_empty_lines(5)"
visible_working = true
contains = ["building"]
any = [
  { line_regex = ['^\s*[⏵] '] },
  { regex = ['(?i)esc to interrupt'] },
]
not = [ { contains = ["esc to cancel"] } ]
`
	m, err := Parse([]byte(src), SourceEmbedded)
	if err != nil {
		t.Fatalf("合法 manifest 应解析成功：%v", err)
	}
	if m.ID != "demo" || len(m.Rules) != 1 {
		t.Fatalf("解析结果不对：%+v", m)
	}
	r := m.Rules[0]
	if r.State != StateWorking || r.Priority != 100 || !r.VisibleWorking {
		t.Errorf("规则字段不对：%+v", r)
	}
	if len(r.Gate.Any) != 2 || len(r.Gate.Not) != 1 || len(r.Gate.Contains) != 1 {
		t.Errorf("门结构不对：%+v", r.Gate)
	}
}

func TestParseRejects(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "未知字段",
			src:  "id = \"x\"\nfoo = 1\n[[rules]]\nid=\"r\"\nstate=\"idle\"\ncontains=[\"a\"]\n",
			want: "未知字段",
		},
		{
			name: "未知规则字段",
			src:  "id = \"x\"\n[[rules]]\nid=\"r\"\nstate=\"idle\"\nvisible_frog=true\ncontains=[\"a\"]\n",
			want: "未知字段",
		},
		{
			name: "缺 id",
			src:  "[[rules]]\nid=\"r\"\ncontains=[\"a\"]\n",
			want: "缺少 id",
		},
		{
			name: "没有规则",
			src:  "id = \"x\"\n",
			want: "至少要有一条规则",
		},
		{
			name: "规则缺 id",
			src:  "id = \"x\"\n[[rules]]\nstate=\"idle\"\ncontains=[\"a\"]\n",
			want: "缺 id",
		},
		{
			name: "region 非法",
			src:  "id = \"x\"\n[[rules]]\nid=\"r\"\nregion=\"bottom_lines\"\ncontains=[\"a\"]\n",
			want: "region 非法",
		},
		{
			name: "正则编不过",
			src:  "id = \"x\"\n[[rules]]\nid=\"r\"\nregex=['(?P<n>a']\n",
			want: "编译失败",
		},
		{
			name: "只有 not 不算正向匹配器",
			src:  "id = \"x\"\n[[rules]]\nid=\"r\"\nnot=[{contains=[\"a\"]}]\n",
			want: "必须含正向匹配器",
		},
		{
			name: "空 not 门",
			src:  "id = \"x\"\n[[rules]]\nid=\"r\"\ncontains=[\"a\"]\nnot=[{}]\n",
			want: "空的 not 门",
		},
		{
			name: "skip_state_update 必须配 unknown",
			src:  "id = \"x\"\n[[rules]]\nid=\"r\"\nstate=\"idle\"\nskip_state_update=true\ncontains=[\"a\"]\n",
			want: "state 不是 unknown",
		},
		{
			name: "skip_state_update 不得带可见证据",
			src:  "id = \"x\"\n[[rules]]\nid=\"r\"\nstate=\"unknown\"\nskip_state_update=true\nvisible_idle=true\ncontains=[\"a\"]\n",
			want: "可见状态证据",
		},
		{
			name: "top_non_empty_lines 要求引擎版本 ≥3",
			src:  "id = \"x\"\nmin_engine_version = 2\n[[rules]]\nid=\"r\"\nregion=\"top_non_empty_lines(3)\"\ncontains=[\"a\"]\n",
			want: "min_engine_version",
		},
		{
			name: "state 取值非法",
			src:  "id = \"x\"\n[[rules]]\nid=\"r\"\nstate=\"busy\"\ncontains=[\"a\"]\n",
			want: "未知 state",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(c.src), SourceEmbedded)
			if err == nil {
				t.Fatalf("应报错（期望含 %q）", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("错误信息应含 %q，实际 %v", c.want, err)
			}
		})
	}
}

func TestValidateComplexityLimits(t *testing.T) {
	// 规则数上限。
	var b strings.Builder
	b.WriteString("id = \"x\"\n")
	for i := 0; i <= MaxRulesPerManifest; i++ {
		b.WriteString("[[rules]]\nid=\"r")
		b.WriteString(itoa(i))
		b.WriteString("\"\ncontains=[\"a\"]\n")
	}
	if _, err := Parse([]byte(b.String()), SourceEmbedded); err == nil ||
		!strings.Contains(err.Error(), "规则数") {
		t.Errorf("超规则数应报错，实际 %v", err)
	}

	// 门嵌套深度上限（深度 9 的 all 链）。
	deep := "id=\"x\"\n[[rules]]\nid=\"r\"\nall=["
	for i := 0; i < MaxGateDepth+1; i++ {
		deep += "{ all = ["
	}
	deep += "{ contains = [\"a\"] }"
	for i := 0; i < MaxGateDepth+1; i++ {
		deep += "] }"
	}
	deep += "]\n"
	if _, err := Parse([]byte(deep), SourceEmbedded); err == nil {
		t.Error("超嵌套深度应报错")
	}

	// 单门匹配器数上限。
	var many strings.Builder
	many.WriteString("id=\"x\"\n[[rules]]\nid=\"r\"\ncontains=[")
	for i := 0; i <= MaxMatchersPerGate; i++ {
		if i > 0 {
			many.WriteString(",")
		}
		many.WriteString("\"a")
		many.WriteString(itoa(i))
		many.WriteString("\"")
	}
	many.WriteString("]\n")
	if _, err := Parse([]byte(many.String()), SourceEmbedded); err == nil ||
		!strings.Contains(err.Error(), "直接匹配器") {
		t.Errorf("超单门匹配器应报错，实际 %v", err)
	}

	// 单模式长度上限。
	long := strings.Repeat("x", MaxMatcherChars+1)
	tooLong := "id=\"x\"\n[[rules]]\nid=\"r\"\ncontains=[\"" + long + "\"]\n"
	if _, err := Parse([]byte(tooLong), SourceEmbedded); err == nil ||
		!strings.Contains(err.Error(), "长度上限") {
		t.Errorf("超模式长度应报错，实际 %v", err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// ---- 4.2 region 切片 ----

// promptBoxScreen 是一屏「带提示框的 agent UI」：提示框上下边框都是横线（与真实 TUI 同形——
// prompt_box_body 的判据是「从底部数第二条横线之后到再下一条横线之前」）。
const promptBoxScreen = `旧的一轮对话输出
• 已完成上一步
› 历史输入行
• 之后又有块标记

────────────────────────
│ 提示框正文第一行
│ 提示框正文第二行
────────────────────────
• 新一轮开始
› 当前输入
`

func TestRegionSlicing(t *testing.T) {
	in := Input{Screen: promptBoxScreen, OSCTitle: "codex 工作中", OSCProgress: "4;1;42"}

	cases := []struct {
		region string
		want   string
		// substr 为 true 时只断言包含。
		substr bool
	}{
		{region: "whole_recent", want: promptBoxScreen},
		{region: "osc_title", want: "codex 工作中"},
		{region: "osc_progress", want: "4;1;42"},
		{region: "bottom_lines(2)", want: "• 新一轮开始\n› 当前输入\n"},
		{region: "bottom_non_empty_lines(1)", want: "› 当前输入\n"},
		// 提示框正文：两条边框之间的内容（不含边框本身）。
		{region: "prompt_box_body", want: "│ 提示框正文第一行\n│ 提示框正文第二行\n"},
		// 框顶之前的一切（含空行，与 herdr 的字节偏移语义一致）。
		{region: "above_prompt_box", want: "旧的一轮对话输出\n• 已完成上一步\n› 历史输入行\n• 之后又有块标记\n\n"},
		{region: "last_non_empty_above_prompt_box", want: "• 之后又有块标记"},
		// 最后一条横线之后。
		{region: "after_last_horizontal_rule", want: "• 新一轮开始\n› 当前输入\n"},
		{region: "current_prompt_block_marker", want: "• 新一轮开始"},
		{region: "after_current_prompt_block_marker", want: "• 新一轮开始\n› 当前输入\n"},
		{region: "unknown_region_name", want: ""},
	}
	for _, c := range cases {
		t.Run(c.region, func(t *testing.T) {
			got := region(in, c.region)
			if c.substr {
				if !strings.Contains(got, c.want) {
					t.Errorf("region %s = %q，期望包含 %q", c.region, got, c.want)
				}
				return
			}
			if got != c.want {
				t.Errorf("region %s = %q，期望 %q", c.region, got, c.want)
			}
		})
	}
}

// 提示标记类 region：语义是「最后一条提示行**之后**的文本」。
func TestRegionPromptMarkers(t *testing.T) {
	// 提示行之后还有内容（真实形态：标记行 + 输入区）。
	withInput := Input{Screen: "输出\n› \n当前输入内容"}
	if got := region(withInput, "after_last_prompt_marker"); got != "当前输入内容" {
		t.Errorf("after_last_prompt_marker = %q，期望 %q", got, "当前输入内容")
	}
	// 提示行之后又出现块标记 ⇒ 那条提示是历史，「当前提示行」不存在。
	history := Input{Screen: "输出\n› 历史输入\n• 之后又有块标记\n新输出"}
	if got := region(history, "whole_recent_without_current_prompt_marker"); got != history.Screen {
		t.Errorf("提示行是历史时应返回整屏，实际 %q", got)
	}
	if got := region(history, "before_current_prompt_marker"); got != history.Screen {
		t.Errorf("无当前提示行时 before_current_prompt_marker 应返回整屏，实际 %q", got)
	}
	// 有当前提示行 ⇒ whole_recent_without_current_prompt_marker 为空、before_ 取提示行之前。
	current := Input{Screen: "输出一\n输出二\n› 当前输入"}
	if got := region(current, "whole_recent_without_current_prompt_marker"); got != "" {
		t.Errorf("有当前提示行时应为空，实际 %q", got)
	}
	if got := region(current, "before_current_prompt_marker"); got != "输出一\n输出二\n" {
		t.Errorf("before_current_prompt_marker = %q", got)
	}
}

// 空屏/全空行/重复文本取底部等边界（任务 4.2 点名）+ herdr 自己的用例（对齐证据）。
func TestRegionEdges(t *testing.T) {
	cases := []struct {
		name   string
		screen string
		region string
		want   string
	}{
		{name: "空屏 bottom_lines", screen: "", region: "bottom_lines(3)", want: ""},
		{name: "空屏 bottom_non_empty_lines", screen: "", region: "bottom_non_empty_lines(3)", want: ""},
		{name: "全空行 bottom_non_empty_lines", screen: "\n\n\n", region: "bottom_non_empty_lines(2)", want: ""},
		{name: "全空行 top_non_empty_lines", screen: "\n\n\n", region: "top_non_empty_lines(2)", want: ""},
		// 重复文本取**底部**那一次（herdr 用例逐字对齐）。
		{
			name:   "重复文本取底部",
			screen: "marker\nold\n\nmiddle\nmarker\nnew\n",
			region: "bottom_non_empty_lines(2)",
			want:   "marker\nnew\n",
		},
		// 重复文本取**顶部**那一次（herdr 用例逐字对齐）。
		{
			name:   "重复文本取顶部",
			screen: "\nmarker\nold\n\nmiddle\nmarker\nnew\n",
			region: "top_non_empty_lines(2)",
			want:   "\nmarker\nold\n",
		},
		{name: "行数多于内容", screen: "a\nb\n", region: "bottom_lines(10)", want: "a\nb\n"},
		{name: "无横线时 after_last_horizontal_rule 为整屏", screen: "a\nb\n", region: "after_last_horizontal_rule", want: "a\nb\n"},
		{name: "无提示框时 above_prompt_box 为整屏", screen: "a\nb\n", region: "above_prompt_box", want: "a\nb\n"},
		{name: "无提示框时 prompt_box_body 为空", screen: "a\nb\n", region: "prompt_box_body", want: ""},
		{name: "无提示标记时 after_last_prompt_marker 为整屏", screen: "a\nb\n", region: "after_last_prompt_marker", want: "a\nb\n"},
		// is_horizontal_rule：整行都是横线（哪怕一条）算分隔线；横线后还跟着别的字符则要求 ≥3 条。
		{name: "单条横线整行也算分隔线", screen: "─\nbody\n", region: "after_last_horizontal_rule", want: "body\n"},
		{name: "两条横线后跟内容不算分隔线", screen: "──abc\nbody\n", region: "after_last_horizontal_rule", want: "──abc\nbody\n"},
		{name: "三条横线后跟内容算分隔线", screen: "───abc\nbody\n", region: "after_last_horizontal_rule", want: "body\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := region(Input{Screen: c.screen}, c.region); got != c.want {
				t.Errorf("region %s(%q) = %q，期望 %q", c.region, c.screen, got, c.want)
			}
		})
	}
}

// 计数形态校验（对齐 herdr：拒绝 0/01/+1/超 u16 上限）。
func TestRegionCountValidation(t *testing.T) {
	// 注意 bottom_lines(0) 是**合法**的（herdr 只对 top_non_empty_lines 卡计数形态；
	// 0 行的语义就是空串，无副作用）。
	for _, bad := range []string{"top_non_empty_lines(01)", "top_non_empty_lines(+1)",
		"top_non_empty_lines(65536)", "top_non_empty_lines()", "bottom_lines(x)", "bottom_non_empty_lines(-1)"} {
		if err := validateRegionName(bad); err == nil {
			t.Errorf("%q 应被判为非法 region", bad)
		}
	}
	for _, ok := range []string{"bottom_lines(1)", "bottom_lines(0)", "bottom_non_empty_lines(12)",
		"top_non_empty_lines(1)", "top_non_empty_lines(65535)", "whole_recent", "osc_title"} {
		if err := validateRegionName(ok); err != nil {
			t.Errorf("%q 应合法，实际 %v", ok, err)
		}
	}
}

// ---- 4.3 求值与仲裁 ----

func mustCompile(t *testing.T, src string) *Compiled {
	t.Helper()
	m, err := Parse([]byte(src), SourceEmbedded)
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	c, err := Compile(m)
	if err != nil {
		t.Fatalf("编译失败：%v", err)
	}
	return c
}

func TestPriorityArbitration(t *testing.T) {
	// 两条都命中：priority 高的胜。
	c := mustCompile(t, `
id = "x"
[[rules]]
id = "low"
state = "idle"
priority = 100
contains = ["共同"]
[[rules]]
id = "high"
state = "blocked"
priority = 900
visible_blocker = true
contains = ["共同"]
`)
	r := c.Evaluate(Input{Screen: "共同"})
	if r.MatchedRule == nil || r.MatchedRule.ID != "high" || r.State != StateBlocked {
		t.Fatalf("高优先级应胜：%+v", r)
	}
	if !r.VisibleBlocker {
		t.Error("visible_blocker 应随 blocked 生效")
	}
	if r.VisibleIdle || r.VisibleWorking {
		t.Error("未声明或状态不符的可见位不该置位")
	}
}

func TestPriorityTieKeepsFileOrder(t *testing.T) {
	c := mustCompile(t, `
id = "x"
[[rules]]
id = "first"
state = "idle"
priority = 500
contains = ["共同"]
[[rules]]
id = "second"
state = "blocked"
priority = 500
contains = ["共同"]
`)
	r := c.Evaluate(Input{Screen: "共同"})
	if r.MatchedRule == nil || r.MatchedRule.ID != "first" {
		t.Fatalf("同分应取文件序靠前者：%+v", r.MatchedRule)
	}
}

func TestFallbackWhenNothingMatches(t *testing.T) {
	c := mustCompile(t, `
id = "x"
[[rules]]
id = "r"
state = "blocked"
contains = ["批准"]
`)
	r := c.Evaluate(Input{Screen: "完全无关的屏幕"})
	if r.State != StateIdle {
		t.Errorf("无命中应回落 idle，实际 %v", r.State)
	}
	if r.FallbackReason != DefaultKnownAgentIdleFallback {
		t.Errorf("回落标签不对：%q", r.FallbackReason)
	}
	if r.MatchedRule != nil {
		t.Error("回落时不该有命中规则")
	}
	if len(r.Rules) != 1 || r.Rules[0].Matched {
		t.Errorf("评估轨迹应记录未命中：%+v", r.Rules)
	}
}

func TestGateSemantics(t *testing.T) {
	c := mustCompile(t, `
id = "x"
[[rules]]
id = "contains_all_case_insensitive"
state = "blocked"
priority = 100
contains = ["do you want to proceed?", "esc to cancel"]
[[rules]]
id = "line_regex_any_line"
state = "working"
priority = 200
line_regex = ['^\s*[⏵] ', '(?i)esc to interrupt']
[[rules]]
id = "nested_not"
state = "working"
priority = 300
contains = ["running"]
not = [ { contains = ["do you want"] } ]
`)
	// contains 全部出现 + 大小写不敏感。
	r := c.Evaluate(Input{Screen: "Do You Want To Proceed? ... ESC TO CANCEL"})
	if r.MatchedRule == nil || r.MatchedRule.ID != "contains_all_case_insensitive" {
		t.Fatalf("contains 应大小写不敏感且要求全部出现：%+v", r)
	}
	// 只出现一个 needle ⇒ 不命中。
	r = c.Evaluate(Input{Screen: "do you want to proceed?"})
	if r.MatchedRule != nil {
		t.Errorf("只出现一个 needle 不该命中：%+v", r.MatchedRule)
	}
	// line_regex 要求每条模式都在**某一行**命中。
	r = c.Evaluate(Input{Screen: "⏵ 干活中\nESC TO INTERRUPT"})
	if r.MatchedRule == nil || r.MatchedRule.ID != "line_regex_any_line" {
		t.Fatalf("line_regex 应逐模式在任意行命中：%+v", r)
	}
	// not 命中 ⇒ 该规则不命中（掉到 contains 那条）。
	r = c.Evaluate(Input{Screen: "running\nDo you want to proceed? esc to cancel"})
	if r.MatchedRule == nil || r.MatchedRule.ID != "contains_all_case_insensitive" {
		t.Fatalf("not 命中应否决该规则：%+v", r)
	}
}

func TestNestedAnyAll(t *testing.T) {
	c := mustCompile(t, `
id = "x"
[[rules]]
id = "r"
state = "blocked"
any = [
  { contains = ["accept"], any = [ { contains = ["enter"] }, { contains = ["tab"] } ] },
  { contains = ["decline"] },
]
`)
	if r := c.Evaluate(Input{Screen: "accept 然后 tab"}); r.MatchedRule == nil {
		t.Error("any 的嵌套 any 命中应成立")
	}
	if r := c.Evaluate(Input{Screen: "decline 这个"}); r.MatchedRule == nil {
		t.Error("第二个 any 分支命中应成立")
	}
	if r := c.Evaluate(Input{Screen: "accept 但没别的"}); r.MatchedRule != nil {
		t.Error("内层 any 都不命中时不该命中")
	}
}

func TestSkipStateUpdate(t *testing.T) {
	c := mustCompile(t, `
id = "x"
[[rules]]
id = "viewer"
state = "unknown"
priority = 1000
skip_state_update = true
contains = ["showing detailed transcript"]
[[rules]]
id = "idle"
state = "idle"
priority = 100
contains = ["❯"]
`)
	r := c.Evaluate(Input{Screen: "showing detailed transcript\n❯"})
	if !r.SkipStateUpdate {
		t.Error("命中 skip_state_update 规则时应置位")
	}
	if !c.ShouldSkipStateUpdate(Input{Screen: "showing detailed transcript"}) {
		t.Error("ShouldSkipStateUpdate 应报告 true")
	}
	if c.ShouldSkipStateUpdate(Input{Screen: "❯ 空闲"}) {
		t.Error("未命中时不该报 true")
	}
}

// ---- 4.4 加载 ----

// 22 份携署名移植的 manifest 必须全部能解析、校验、编译（任务 4.5 的移植门）。
func TestEmbeddedManifestsLoad(t *testing.T) {
	l := NewLoader("")
	if warns := l.Warnings(); len(warns) > 0 {
		t.Fatalf("内嵌 manifest 不该有告警：%v", warns)
	}
	ids := l.IDs()
	if len(ids) != 22 {
		t.Fatalf("应加载 22 份 manifest，实际 %d 份：%v", len(ids), ids)
	}
	for _, id := range ids {
		c, ok := l.ForID(id)
		if !ok {
			t.Errorf("%s 取不到", id)
			continue
		}
		if len(c.rules) == 0 {
			t.Errorf("%s 没有编译出规则", id)
		}
	}
}

func TestProcessMapping(t *testing.T) {
	l := NewLoader("")
	cases := map[string]string{
		"codex":                "codex",
		"/usr/local/bin/codex": "codex",
		"claude":               "claude",
		"claude-code":          "claude",
		"opencode":             "opencode",
		"open-code":            "opencode",
		"cursor-agent":         "cursor",
		"github-copilot":       "copilot",
	}
	for proc, wantID := range cases {
		c, ok := l.ForProcess(proc)
		if !ok {
			t.Errorf("进程 %q 应能识别", proc)
			continue
		}
		if c.Manifest.ID != wantID {
			t.Errorf("进程 %q 应映射到 %s，实际 %s", proc, wantID, c.Manifest.ID)
		}
	}
	// 认不出就老实说不认识（不猜）。
	if _, ok := l.ForProcess("vim"); ok {
		t.Error("vim 不该被识别为 agent")
	}
	if _, ok := l.ForProcess(""); ok {
		t.Error("空进程名不该被识别")
	}
}

func TestOverrideWinsAndFallback(t *testing.T) {
	dir := t.TempDir()
	l := NewLoader(dir)
	if warns := l.Warnings(); len(warns) > 0 {
		t.Fatalf("空覆盖目录不该有告警：%v", warns)
	}
	// 合法覆盖：生效且来源标 override。
	good := `id = "codex"
version = "9.9.9"
[[rules]]
id = "custom"
state = "blocked"
priority = 5000
visible_blocker = true
contains = ["我的自定义批准提示"]
`
	if err := os.WriteFile(filepath.Join(dir, "codex.toml"), []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}
	l.Reload()
	c, ok := l.ForID("codex")
	if !ok {
		t.Fatal("codex 应仍可取到")
	}
	if c.Manifest.Source != SourceOverride {
		t.Errorf("应来自覆盖文件，实际 %s", c.Manifest.Source)
	}
	if r := c.Evaluate(Input{Screen: "我的自定义批准提示"}); r.State != StateBlocked {
		t.Errorf("覆盖规则应生效：%+v", r)
	}

	// 坏覆盖（TOML 坏）：整份忽略 + 告警 + 回落内嵌。
	if err := os.WriteFile(filepath.Join(dir, "codex.toml"), []byte("这不是 toml = ="), 0o644); err != nil {
		t.Fatal(err)
	}
	l.Reload()
	if warns := l.Warnings(); len(warns) == 0 || !strings.Contains(warns[0], "被忽略") {
		t.Errorf("坏覆盖应告警，实际 %v", l.Warnings())
	}
	c, _ = l.ForID("codex")
	if c.Manifest.Source != SourceEmbedded {
		t.Errorf("坏覆盖应回落内嵌，实际来源 %s", c.Manifest.Source)
	}

	// min_engine_version 过高：同样忽略 + 回落内嵌。
	tooNew := "id = \"codex\"\nmin_engine_version = 999\n[[rules]]\nid=\"r\"\ncontains=[\"a\"]\n"
	if err := os.WriteFile(filepath.Join(dir, "codex.toml"), []byte(tooNew), 0o644); err != nil {
		t.Fatal(err)
	}
	l.Reload()
	if warns := l.Warnings(); len(warns) == 0 || !strings.Contains(warns[0], "min_engine_version") {
		t.Errorf("引擎版本过老应告警，实际 %v", l.Warnings())
	}
	c, _ = l.ForID("codex")
	if c.Manifest.Source != SourceEmbedded {
		t.Errorf("引擎版本过老应回落内嵌，实际来源 %s", c.Manifest.Source)
	}

	// 删掉覆盖 ⇒ 恢复干净。
	if err := os.Remove(filepath.Join(dir, "codex.toml")); err != nil {
		t.Fatal(err)
	}
	l.Reload()
	if warns := l.Warnings(); len(warns) > 0 {
		t.Errorf("删掉覆盖后不该有告警：%v", warns)
	}
}

// 覆盖目录不存在（出口没配）也不能报错——默认路径就是「只用内嵌」。
func TestLoaderMissingOverrideDir(t *testing.T) {
	l := NewLoader(filepath.Join(t.TempDir(), "不存在的目录"))
	if warns := l.Warnings(); len(warns) > 0 {
		t.Fatalf("目录不存在不该告警：%v", warns)
	}
	if _, ok := l.ForID("codex"); !ok {
		t.Error("内嵌版本应照常可用")
	}
}
