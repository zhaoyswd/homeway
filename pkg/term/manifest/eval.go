// eval.go — 谓词求值与 priority 仲裁（任务 4.3）。
//
// 求值语义逐条照 herdr（compiled_gate_matches）：
//
//	contains   全部子串都出现（**大小写不敏感**：整段 region 文本预先小写）
//	regex      全部模式都命中整段 region 文本
//	line_regex 全部模式都命中**至少一行**
//	all        全部子门命中
//	any        非空时至少一个子门命中
//	not        任一子门命中 ⇒ 本门不命中
//
// 仲裁：按**文件序**遍历规则，只有 priority **严格大于**当前命中者才替换
// ⇒ 最高 priority 胜、同分取文件序靠前的那条（规格「最高命中胜、文件序破平」）。
package manifest

import (
	"regexp"
	"strings"
)

// compiledRule 预编译后的规则（正则只编一次；manifest 是长期驻留的）。
type compiledRule struct {
	rule  Rule
	gate  compiledGate
	order int
}

type compiledGate struct {
	all       []compiledGate
	any       []compiledGate
	not       []compiledGate
	contains  []string // 已小写
	regex     []*regexp.Regexp
	lineRegex []*regexp.Regexp
}

// Compiled 一份编译好的 manifest（求值入口）。
type Compiled struct {
	Manifest *Manifest
	rules    []compiledRule
}

// Compile 编译规则里的正则（解析阶段已校验过可编译；这里失败只会来自极端环境，返回错误）。
func Compile(m *Manifest) (*Compiled, error) {
	c := &Compiled{Manifest: m, rules: make([]compiledRule, 0, len(m.Rules))}
	for i := range m.Rules {
		g, err := compileGate(m.Rules[i].Gate)
		if err != nil {
			return nil, err
		}
		c.rules = append(c.rules, compiledRule{rule: m.Rules[i], gate: g, order: i})
	}
	return c, nil
}

func compileGate(g Gate) (compiledGate, error) {
	out := compiledGate{}
	for _, s := range g.Contains {
		out.contains = append(out.contains, strings.ToLower(s))
	}
	for _, p := range g.Regex {
		re, err := compilePattern(p)
		if err != nil {
			return compiledGate{}, err
		}
		out.regex = append(out.regex, re)
	}
	for _, p := range g.LineRegex {
		re, err := compilePattern(p)
		if err != nil {
			return compiledGate{}, err
		}
		out.lineRegex = append(out.lineRegex, re)
	}
	for _, n := range g.All {
		cg, err := compileGate(n)
		if err != nil {
			return compiledGate{}, err
		}
		out.all = append(out.all, cg)
	}
	for _, n := range g.Any {
		cg, err := compileGate(n)
		if err != nil {
			return compiledGate{}, err
		}
		out.any = append(out.any, cg)
	}
	for _, n := range g.Not {
		cg, err := compileGate(n)
		if err != nil {
			return compiledGate{}, err
		}
		out.not = append(out.not, cg)
	}
	return out, nil
}

// EvaluatedRule 一条规则的评估轨迹（explain 用：规格要求输出全部规则的评估轨迹）。
type EvaluatedRule struct {
	ID       string
	Priority int
	Region   string
	State    State
	Matched  bool
	// RegionBytes 是本次判定的 region 文本长度（诊断「region 切空了」这类问题）。
	RegionBytes int
}

// Result 一次判定的结果。
type Result struct {
	// State 是最终状态。无命中且 agent 已知时回落 idle（FallbackReason 非空）。
	State State
	// MatchedRule 命中的规则（无命中时为 nil）。
	MatchedRule *Rule
	// VisibleIdle/VisibleBlocker/VisibleWorking 是命中规则声明的「可见证据位」。
	VisibleIdle    bool
	VisibleBlocker bool
	VisibleWorking bool
	// SkipStateUpdate 命中规则要求冻结状态不更新（历史查看器类覆盖屏）。
	SkipStateUpdate bool
	// FallbackReason 回落标签（非空 = 走了回落）。
	FallbackReason string
	// Rules 全部规则的评估轨迹。
	Rules []EvaluatedRule
}

// Evaluate 对一份编译好的 manifest 求值。
func (c *Compiled) Evaluate(in Input) Result {
	var (
		best       *compiledRule
		bestState  State
		bestRegion string
	)
	trace := make([]EvaluatedRule, 0, len(c.rules))
	for i := range c.rules {
		cr := &c.rules[i]
		regionText := region(in, cr.rule.Region)
		matched := gateMatches(cr.gate, regionText)
		trace = append(trace, EvaluatedRule{
			ID:          cr.rule.ID,
			Priority:    cr.rule.Priority,
			Region:      cr.rule.Region,
			State:       cr.rule.State,
			Matched:     matched,
			RegionBytes: len(regionText),
		})
		if !matched {
			continue
		}
		// 严格大于才替换 ⇒ 同分保持文件序靠前者。
		if best != nil && best.rule.Priority >= cr.rule.Priority {
			continue
		}
		best, bestState, bestRegion = cr, cr.rule.State, cr.rule.Region
	}
	_ = bestRegion
	if best == nil {
		return Result{
			State:          StateIdle,
			FallbackReason: DefaultKnownAgentIdleFallback,
			Rules:          trace,
		}
	}
	r := best.rule
	return Result{
		State:           bestState,
		MatchedRule:     &r,
		VisibleIdle:     r.VisibleIdle && bestState == StateIdle,
		VisibleBlocker:  r.VisibleBlocker && bestState == StateBlocked,
		VisibleWorking:  r.VisibleWorking && bestState == StateWorking,
		SkipStateUpdate: r.SkipStateUpdate,
		Rules:           trace,
	}
}

// ShouldSkipStateUpdate 只回答「有没有命中 skip_state_update 规则」（不跑完整 explain）。
func (c *Compiled) ShouldSkipStateUpdate(in Input) bool {
	return c.Evaluate(in).SkipStateUpdate
}

func gateMatches(g compiledGate, text string) bool {
	lower := strings.ToLower(text)
	return gateMatchesLower(g, text, lower)
}

func gateMatchesLower(g compiledGate, text, lower string) bool {
	for _, needle := range g.contains {
		if !strings.Contains(lower, needle) {
			return false
		}
	}
	for _, re := range g.regex {
		if !re.MatchString(text) {
			return false
		}
	}
	for _, re := range g.lineRegex {
		hit := false
		for _, line := range strings.Split(text, "\n") {
			if re.MatchString(line) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	for _, n := range g.all {
		if !gateMatchesLower(n, text, lower) {
			return false
		}
	}
	if len(g.any) > 0 {
		ok := false
		for _, n := range g.any {
			if gateMatchesLower(n, text, lower) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	for _, n := range g.not {
		if gateMatchesLower(n, text, lower) {
			return false
		}
	}
	return true
}
