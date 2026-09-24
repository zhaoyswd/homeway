// Package manifest 是 agent 状态识别规则的**数据驱动引擎**（openspec term-vt-backend 任务 4.1）。
//
// 规则以 TOML 承载（携署名移植自 herdr 的 screen manifest，Apache-2.0；见 manifests/ 目录与
// 任务 4.5）。引擎只做三件事：**解析 + 校验**（本文件）、**region 切片**（region.go）、
// **谓词求值与 priority 仲裁**（eval.go）。
//
// 为什么做成数据而不是 Go 代码（term-agent-state 规格）：新 agent 的支持只需增改 TOML，
// 不需要改 Go 代码，也不需要为每次 CLI 改版重发 App——规则时效性由本地覆盖目录兜住
// （`<state>/agent-detection/`，本地永远优先，任务 4.4）。
//
// 校验上限照 herdr 的 manifest 复杂度门（防病态/恶意覆盖文件把出口 CPU 拖死）：
// 规则数 ≤128、门嵌套深度 ≤8、门总数 ≤512、单门匹配器 ≤32、匹配器总数 ≤1024、
// 单模式 ≤512 字符、正则必须可编译。任一失败 ⇒ **整份忽略 + 告警**，绝不因此退出进程。
package manifest

import (
	"errors"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
)

// EngineVersion 是引擎能力版本。manifest 声明更高的 `min_engine_version` 时拒载
// （规格「manifest 数据驱动与版本兼容」）。
//
// 3 = 支持 `top_non_empty_lines(N)`（与 herdr 的 TOP_NON_EMPTY_LINES_ENGINE_VERSION 对齐；
// 低版本引擎遇到该 region 会当作非法）。
const EngineVersion = 3

// 复杂度上限（与 herdr 同值，见包注释）。
const (
	MaxRulesPerManifest = 128
	MaxGateDepth        = 8
	MaxTotalGates       = 512
	MaxMatchersPerGate  = 32
	MaxTotalMatchers    = 1024
	MaxMatcherChars     = 512
)

// DefaultKnownAgentIdleFallback 是无命中且 agent 已知时的回落标签（规格要求可解释）。
const DefaultKnownAgentIdleFallback = "default_known_agent_idle_fallback"

// State 规则声明的状态（与 herdr 的 ManifestState 同名同义）。
type State uint8

const (
	StateUnknown State = iota
	StateIdle
	StateWorking
	StateBlocked
)

// String 给日志/explain 用（与 TOML 里的取值同名）。
func (s State) String() string {
	switch s {
	case StateIdle:
		return "idle"
	case StateWorking:
		return "working"
	case StateBlocked:
		return "blocked"
	default:
		return "unknown"
	}
}

// ParseState 解析 TOML 里的 state 取值。
func ParseState(v string) (State, error) {
	switch v {
	case "idle":
		return StateIdle, nil
	case "working":
		return StateWorking, nil
	case "blocked":
		return StateBlocked, nil
	case "unknown":
		return StateUnknown, nil
	}
	return StateUnknown, fmt.Errorf("未知 state %q", v)
}

// Manifest 一份 agent 规则集。
type Manifest struct {
	ID               string
	Version          string
	MinEngineVersion uint32
	Aliases          []string
	Rules            []Rule

	// Source 记录这份 manifest 从哪来（内嵌 / 本地覆盖），供日志与 explain。
	Source Source
}

// Source manifest 的来源（规格要求日志标注来源）。
type Source string

const (
	SourceEmbedded Source = "embedded"
	SourceOverride Source = "override"
)

// Rule 一条规则。
type Rule struct {
	ID              string
	State           State
	Priority        int
	Region          string
	VisibleIdle     bool
	VisibleBlocker  bool
	VisibleWorking  bool
	SkipStateUpdate bool
	Gate            Gate
}

// Gate 一个谓词门。求值语义（照 herdr，见 eval.go）：
//   - contains：**全部**子串都要出现（大小写不敏感）
//   - regex：**全部**模式都要命中整段 region 文本
//   - line_regex：**全部**模式都要命中**至少一行**
//   - all：全部子门命中
//   - any：非空时至少一个子门命中
//   - not：任一子门命中即整体不命中
type Gate struct {
	All       []Gate
	Any       []Gate
	Not       []Gate
	Contains  []string
	Regex     []string
	LineRegex []string
}

// HasPositiveMatcher：本门是否有「正向」匹配器（规格：规则必须有正向匹配器，只有 not 不算）。
func (g Gate) HasPositiveMatcher() bool {
	return len(g.Contains) > 0 || len(g.Regex) > 0 || len(g.LineRegex) > 0 ||
		len(g.All) > 0 || len(g.Any) > 0
}

// HasAnyMatcher：本门（含 not）是否有任何匹配器。
func (g Gate) HasAnyMatcher() bool { return g.HasPositiveMatcher() || len(g.Not) > 0 }

// ErrInvalid 表示 manifest 不合法（加载方应整份忽略 + 告警，不退出）。
var ErrInvalid = errors.New("manifest: 非法")

// Parse 解析 TOML 并校验（含复杂度上限与正则编译）。
//
// 未知字段一律拒绝（与 herdr 的 deny_unknown_fields 同款）：拼错的键如果被静默忽略，
// 规则会「看起来生效但永远不命中」——这类静默失败比加载失败难查得多。
func Parse(data []byte, src Source) (*Manifest, error) {
	var raw rawManifest
	md, err := toml.Decode(string(data), &raw)
	if err != nil {
		return nil, fmt.Errorf("%w: TOML 解析失败：%v", ErrInvalid, err)
	}
	if undec := md.Undecoded(); len(undec) > 0 {
		return nil, fmt.Errorf("%w: 未知字段 %v", ErrInvalid, keyNames(undec))
	}
	m, err := raw.toManifest(src)
	if err != nil {
		return nil, err
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return m, nil
}

func keyNames(keys []toml.Key) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.String())
	}
	return out
}

// Validate 校验整份 manifest（规则数、region 名、门复杂度、正则可编译）。
func (m *Manifest) Validate() error {
	if m.ID == "" {
		return fmt.Errorf("%w: 缺少 id", ErrInvalid)
	}
	if len(m.Rules) == 0 {
		return fmt.Errorf("%w: 至少要有一条规则", ErrInvalid)
	}
	if len(m.Rules) > MaxRulesPerManifest {
		return fmt.Errorf("%w: 规则数 %d 超过上限 %d", ErrInvalid, len(m.Rules), MaxRulesPerManifest)
	}
	c := &complexity{}
	for i := range m.Rules {
		r := &m.Rules[i]
		if strings.TrimSpace(r.ID) == "" {
			return fmt.Errorf("%w: 第 %d 条规则缺 id", ErrInvalid, i+1)
		}
		if r.SkipStateUpdate {
			// 历史查看器类覆盖屏：命中时冻结状态不更新。只允许配 unknown + 不带可见证据，
			// 否则「冻结状态」和「宣称可见状态」互相矛盾。
			if r.State != StateUnknown {
				return fmt.Errorf("%w: 规则 %s 用了 skip_state_update 但 state 不是 unknown", ErrInvalid, r.ID)
			}
			if r.VisibleIdle || r.VisibleBlocker || r.VisibleWorking {
				return fmt.Errorf("%w: 规则 %s 同时用了 skip_state_update 与可见状态证据", ErrInvalid, r.ID)
			}
		}
		if err := validateRegionName(r.Region); err != nil {
			return fmt.Errorf("%w: 规则 %s 的 region 非法：%v", ErrInvalid, r.ID, err)
		}
		if strings.HasPrefix(strings.TrimSpace(r.Region), "top_non_empty_lines(") &&
			m.MinEngineVersion != 0 && m.MinEngineVersion < topNonEmptyLinesEngineVersion {
			return fmt.Errorf("%w: 规则 %s 用了 top_non_empty_lines 但 min_engine_version < %d",
				ErrInvalid, r.ID, topNonEmptyLinesEngineVersion)
		}
		if err := validateGate(r.Gate, "rule", 0, c, true); err != nil {
			return fmt.Errorf("%w: 规则 %s 的门非法：%v", ErrInvalid, r.ID, err)
		}
	}
	return nil
}

// complexity 累计复杂度（跨规则共享上限）。
type complexity struct {
	gates    int
	matchers int
}

func validateGate(g Gate, ctx string, depth int, c *complexity, positiveRequired bool) error {
	if depth > MaxGateDepth {
		return fmt.Errorf("%s 嵌套超过上限 %d", ctx, MaxGateDepth)
	}
	c.gates++
	if c.gates > MaxTotalGates {
		return fmt.Errorf("门总数超过上限 %d", MaxTotalGates)
	}
	if err := validateMatcherLimits(g, ctx, c); err != nil {
		return err
	}
	if positiveRequired && !g.HasPositiveMatcher() {
		return fmt.Errorf("%s 必须含正向匹配器（只有 not 不算）", ctx)
	}
	if err := validateRegexes(g.Regex, ctx, "regex"); err != nil {
		return err
	}
	if err := validateRegexes(g.LineRegex, ctx, "line_regex"); err != nil {
		return err
	}
	for _, n := range g.All {
		if err := validateGate(n, "all 门", depth+1, c, true); err != nil {
			return err
		}
	}
	for _, n := range g.Any {
		if err := validateGate(n, "any 门", depth+1, c, true); err != nil {
			return err
		}
	}
	for _, n := range g.Not {
		if !n.HasAnyMatcher() {
			return fmt.Errorf("%s 含空的 not 门", ctx)
		}
		// not 门内部不要求正向匹配器（它的语义就是「不得命中」）。
		if err := validateGate(n, "not 门", depth+1, c, false); err != nil {
			return err
		}
	}
	return nil
}

func validateMatcherLimits(g Gate, ctx string, c *complexity) error {
	n := len(g.Contains) + len(g.Regex) + len(g.LineRegex)
	if n > MaxMatchersPerGate {
		return fmt.Errorf("%s 直接匹配器 %d 个，超过上限 %d", ctx, n, MaxMatchersPerGate)
	}
	c.matchers += n
	if c.matchers > MaxTotalMatchers {
		return fmt.Errorf("匹配器总数超过上限 %d", MaxTotalMatchers)
	}
	for _, v := range append(append(append([]string{}, g.Contains...), g.Regex...), g.LineRegex...) {
		if len([]rune(v)) > MaxMatcherChars {
			return fmt.Errorf("%s 有匹配器超过长度上限 %d", ctx, MaxMatcherChars)
		}
	}
	return nil
}

func validateRegexes(patterns []string, ctx, field string) error {
	for _, p := range patterns {
		// 走方言垫片（Rust regex → Go RE2），见 dialect.go。
		if _, err := compilePattern(p); err != nil {
			return fmt.Errorf("%s 的 %s 模式 %q 编译失败：%v", ctx, field, p, err)
		}
	}
	return nil
}

// ---- TOML 形状（与 herdr 的 serde 结构一一对应）----

type rawManifest struct {
	ID               string    `toml:"id"`
	Version          string    `toml:"version"`
	MinEngineVersion uint32    `toml:"min_engine_version"`
	UpdatedAt        string    `toml:"updated_at"`
	Aliases          []string  `toml:"aliases"`
	Rules            []rawRule `toml:"rules"`
}

type rawRule struct {
	ID              string    `toml:"id"`
	State           string    `toml:"state"`
	Priority        int       `toml:"priority"`
	Region          string    `toml:"region"`
	VisibleIdle     bool      `toml:"visible_idle"`
	VisibleBlocker  bool      `toml:"visible_blocker"`
	VisibleWorking  bool      `toml:"visible_working"`
	SkipStateUpdate bool      `toml:"skip_state_update"`
	All             []rawGate `toml:"all"`
	Any             []rawGate `toml:"any"`
	Not             []rawGate `toml:"not"`
	Contains        []string  `toml:"contains"`
	Regex           []string  `toml:"regex"`
	LineRegex       []string  `toml:"line_regex"`
}

type rawGate struct {
	All       []rawGate `toml:"all"`
	Any       []rawGate `toml:"any"`
	Not       []rawGate `toml:"not"`
	Contains  []string  `toml:"contains"`
	Regex     []string  `toml:"regex"`
	LineRegex []string  `toml:"line_regex"`
}

func (r rawManifest) toManifest(src Source) (*Manifest, error) {
	m := &Manifest{
		ID:               r.ID,
		Version:          r.Version,
		MinEngineVersion: r.MinEngineVersion,
		Aliases:          r.Aliases,
		Source:           src,
		Rules:            make([]Rule, 0, len(r.Rules)),
	}
	for _, rr := range r.Rules {
		state := StateUnknown
		if rr.State != "" {
			s, err := ParseState(rr.State)
			if err != nil {
				return nil, fmt.Errorf("%w: 规则 %s：%v", ErrInvalid, rr.ID, err)
			}
			state = s
		}
		region := rr.Region
		if strings.TrimSpace(region) == "" {
			region = DefaultRegion
		}
		m.Rules = append(m.Rules, Rule{
			ID:              rr.ID,
			State:           state,
			Priority:        rr.Priority,
			Region:          region,
			VisibleIdle:     rr.VisibleIdle,
			VisibleBlocker:  rr.VisibleBlocker,
			VisibleWorking:  rr.VisibleWorking,
			SkipStateUpdate: rr.SkipStateUpdate,
			Gate: Gate{
				All:       toGates(rr.All),
				Any:       toGates(rr.Any),
				Not:       toGates(rr.Not),
				Contains:  rr.Contains,
				Regex:     rr.Regex,
				LineRegex: rr.LineRegex,
			},
		})
	}
	return m, nil
}

func toGates(in []rawGate) []Gate {
	if len(in) == 0 {
		return nil
	}
	out := make([]Gate, 0, len(in))
	for _, g := range in {
		out = append(out, Gate{
			All:       toGates(g.All),
			Any:       toGates(g.Any),
			Not:       toGates(g.Not),
			Contains:  g.Contains,
			Regex:     g.Regex,
			LineRegex: g.LineRegex,
		})
	}
	return out
}
