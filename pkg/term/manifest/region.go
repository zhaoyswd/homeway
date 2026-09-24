// region.go — region 切片全集（任务 4.2）。
//
// 逐条照 herdr 的 `region()` 与其切片助手移植（语义、边界与「取不到就退回整屏/空」的选择都一致），
// 差别只在语言：Rust 的 `str::lines()` 与 Go 的 `strings.Split(s, "\n")` 对**结尾换行**的处理不同，
// 这里用 lines() 助手对齐（否则所有按行计数的 region 会差一行）。
//
// 为什么 region 是这套规则的关键：屏幕证据最容易误判的形态是「旧提示还留在上方、新输出已经出现」
// ——region 负责把判定范围锚到「最近一屏 / 最后一条分隔线之后 / 提示框内部」等位置，
// 让旧内容不参与判定（规格的「旧提示残留不误判」场景）。
package manifest

import "strings"

// DefaultRegion 是规则不写 region 时的默认值（与 herdr 一致）。
const DefaultRegion = "whole_recent"

// topNonEmptyLinesEngineVersion 是 top_non_empty_lines 需要的最低引擎版本。
const topNonEmptyLinesEngineVersion = 3

// Input 是检测输入（规格「检测输入契约」的四路证据）。
type Input struct {
	// Screen 是屏幕尾部文本（当前活动屏方向最近约一屏的纯文本，滚动位置不影响）。
	Screen string
	// OSCTitle 是终端标题（OSC 0/2，由 termScan 维护——标题的单一来源）。
	OSCTitle string
	// OSCProgress 是 OSC 9;4 progress 的原始载荷（如 "4;1;50"）；空 = 无。
	OSCProgress string
}

// region 取一条规则要判定的文本。取不到（无提示框/无标记）时按 herdr 的选择返回整屏或空串。
func region(in Input, spec string) string {
	trimmed := strings.TrimSpace(spec)
	// OSC 类 region 走专用字段，不碰屏幕文本。
	switch trimmed {
	case "osc_title":
		return in.OSCTitle
	case "osc_progress":
		return in.OSCProgress
	}
	content := in.Screen
	switch trimmed {
	case "whole_recent":
		return content
	case "after_last_prompt_marker":
		return afterLastPromptMarker(content)
	case "before_current_prompt_marker":
		return beforeCurrentPromptMarker(content)
	case "whole_recent_without_current_prompt_marker":
		return wholeRecentWithoutCurrentPromptMarker(content)
	case "current_prompt_block_marker":
		return currentPromptBlockMarker(content)
	case "after_current_prompt_block_marker":
		return afterCurrentPromptBlockMarker(content)
	case "prompt_box_body":
		return promptBoxBody(content)
	case "above_prompt_box":
		return abovePromptBox(content)
	case "last_non_empty_above_prompt_box":
		return lastNonEmptyLine(abovePromptBox(content))
	case "after_last_horizontal_rule":
		return afterLastHorizontalRule(content)
	}
	if n, ok := regionCount(trimmed, "bottom_lines"); ok {
		return bottomLines(content, n)
	}
	if n, ok := regionCount(trimmed, "bottom_non_empty_lines"); ok {
		return bottomNonEmptyLines(content, n)
	}
	if n, ok := topRegionCount(trimmed); ok {
		return topNonEmptyLines(content, n)
	}
	return ""
}

// validateRegionName 校验 region 名合法（任务 4.1 的加载校验）。
func validateRegionName(spec string) error {
	trimmed := strings.TrimSpace(spec)
	switch trimmed {
	case "whole_recent", "after_last_prompt_marker", "before_current_prompt_marker",
		"whole_recent_without_current_prompt_marker", "current_prompt_block_marker",
		"after_current_prompt_block_marker", "prompt_box_body", "above_prompt_box",
		"last_non_empty_above_prompt_box", "after_last_horizontal_rule",
		"osc_title", "osc_progress":
		return nil
	}
	if _, ok := regionCount(trimmed, "bottom_lines"); ok {
		return nil
	}
	if _, ok := regionCount(trimmed, "bottom_non_empty_lines"); ok {
		return nil
	}
	if _, ok := topRegionCount(trimmed); ok {
		return nil
	}
	return errUnknownRegion(trimmed)
}

type errUnknownRegion string

func (e errUnknownRegion) Error() string { return "未知 region " + string(e) }

// regionCount 解析 `name(N)` 形态。
func regionCount(spec, name string) (int, bool) {
	rest, ok := strings.CutPrefix(spec, name)
	if !ok {
		return 0, false
	}
	rest, ok = strings.CutPrefix(rest, "(")
	if !ok {
		return 0, false
	}
	rest, ok = strings.CutSuffix(rest, ")")
	if !ok {
		return 0, false
	}
	n, err := parseCount(rest)
	if err != nil {
		return 0, false
	}
	return n, true
}

// topRegionCount 解析 `top_non_empty_lines(N)`：拒绝前导 0（herdr 同款，避免 "01" 这类歧义写法）。
func topRegionCount(spec string) (int, bool) {
	rest, ok := strings.CutPrefix(spec, "top_non_empty_lines")
	if !ok {
		return 0, false
	}
	rest, ok = strings.CutPrefix(rest, "(")
	if !ok {
		return 0, false
	}
	rest, ok = strings.CutSuffix(rest, ")")
	if !ok {
		return 0, false
	}
	if strings.HasPrefix(rest, "0") {
		return 0, false
	}
	n, err := parseCount(rest)
	if err != nil {
		return 0, false
	}
	// 上限对齐 herdr（u16::MAX）：再大没有语义，且是病态输入的入口。
	if n > 65535 {
		return 0, false
	}
	return n, true
}

func parseCount(s string) (int, error) {
	if s == "" {
		return 0, errUnknownRegion(s)
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errUnknownRegion(s)
		}
		n = n*10 + int(s[i]-'0')
		if n > 1<<20 { // 防病态大数
			return 0, errUnknownRegion(s)
		}
	}
	return n, nil
}

// lines 与 Rust 的 str::lines() 对齐：按 '\n' 切、丢掉结尾换行产生的空元素。
func lines(s string) []string {
	if s == "" {
		return nil
	}
	out := strings.Split(s, "\n")
	if out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	return out
}

func lineStartOffset(content string, ls []string, index int) int {
	if index > len(ls) {
		index = len(ls)
	}
	off := 0
	for _, l := range ls[:index] {
		off += len(l) + 1
	}
	if off > len(content) {
		return len(content)
	}
	return off
}

func sliceFromLineIndex(content string, ls []string, index int) string {
	return content[lineStartOffset(content, ls, index):]
}

func bottomLines(content string, count int) string {
	ls := lines(content)
	start := len(ls) - count
	if start < 0 {
		start = 0
	}
	return sliceFromLineIndex(content, ls, start)
}

func bottomNonEmptyLines(content string, count int) string {
	ls := lines(content)
	startIndex := -1
	seen := 0
	for i := len(ls) - 1; i >= 0; i-- {
		if strings.TrimSpace(ls[i]) == "" {
			continue
		}
		seen++
		startIndex = i
		if seen == count {
			break
		}
	}
	if startIndex < 0 {
		return ""
	}
	return sliceFromLineIndex(content, ls, startIndex)
}

func topNonEmptyLines(content string, count int) string {
	ls := lines(content)
	endIndex := -1
	seen := 0
	for i, l := range ls {
		if strings.TrimSpace(l) == "" {
			continue
		}
		seen++
		endIndex = i
		if seen == count {
			break
		}
	}
	if endIndex < 0 {
		return ""
	}
	return content[:lineStartOffset(content, ls, endIndex+1)]
}

// afterLastPromptMarker 取最后一条 codex 提示行**之后**的文本；没有标记则退回整屏。
func afterLastPromptMarker(content string) string {
	ls := lines(content)
	index := -1
	for i := len(ls) - 1; i >= 0; i-- {
		if codexPromptLine(ls[i]) {
			index = i
			break
		}
	}
	if index < 0 {
		return content
	}
	return sliceFromLineIndex(content, ls, index+1)
}

func beforeCurrentPromptMarker(content string) string {
	ls := lines(content)
	index, ok := currentCodexPromptIndex(ls)
	if !ok {
		return content
	}
	return content[:lineStartOffset(content, ls, index)]
}

// wholeRecentWithoutCurrentPromptMarker：有「当前提示行」时返回空（这类屏是提示输入态，
// 不该被当成整屏证据），否则整屏。
func wholeRecentWithoutCurrentPromptMarker(content string) string {
	ls := lines(content)
	if _, ok := currentCodexPromptIndex(ls); ok {
		return ""
	}
	return content
}

func currentPromptBlockMarker(content string) string {
	ls := lines(content)
	idx, ok := currentCodexPromptIndex(ls)
	if !ok {
		return ""
	}
	for i := idx - 1; i >= 0; i-- {
		if codexBlockMarkerLine(ls[i]) {
			return ls[i]
		}
	}
	return ""
}

func afterCurrentPromptBlockMarker(content string) string {
	ls := lines(content)
	idx, ok := currentCodexPromptIndex(ls)
	if !ok {
		return ""
	}
	block := -1
	for i := idx - 1; i >= 0; i-- {
		if codexBlockMarkerLine(ls[i]) {
			block = i
			break
		}
	}
	if block < 0 {
		return ""
	}
	return sliceFromLineIndex(content, ls, block)
}

// currentCodexPromptIndex：最后一条提示行，且其后**不得**再出现块标记
// （否则那条提示是历史，不是「当前输入态」）。
func currentCodexPromptIndex(ls []string) (int, bool) {
	idx := -1
	for i := len(ls) - 1; i >= 0; i-- {
		if codexPromptLine(ls[i]) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return 0, false
	}
	for _, l := range ls[idx+1:] {
		if codexBlockMarkerLine(l) {
			return 0, false
		}
	}
	return idx, true
}

func codexPromptLine(line string) bool { return line == "›" || strings.HasPrefix(line, "› ") }

func codexBlockMarkerLine(line string) bool {
	for _, p := range []string{"•", "■", "✗", "✓"} {
		if strings.HasPrefix(line, p) {
			return true
		}
	}
	return false
}

// promptBoxBody：提示框**顶边框之后到框内下一条分隔线之前**（框内正文）。
func promptBoxBody(content string) string {
	ls := lines(content)
	top, ok := promptBoxTopBorderIndex(ls)
	if !ok {
		return ""
	}
	start := lineStartOffset(content, ls, top+1)
	endIndex := len(ls)
	for i := top + 1; i < len(ls); i++ {
		if isHorizontalRule(ls[i]) {
			endIndex = i
			break
		}
	}
	end := lineStartOffset(content, ls, endIndex)
	if start > len(content) {
		start = len(content)
	}
	if end > len(content) {
		end = len(content)
	}
	if end < start {
		return ""
	}
	return content[start:end]
}

func abovePromptBox(content string) string {
	ls := lines(content)
	top, ok := promptBoxTopBorderIndex(ls)
	if !ok {
		return content
	}
	return content[:lineStartOffset(content, ls, top)]
}

func afterLastHorizontalRule(content string) string {
	lastRuleEnd := 0
	offset := 0
	for _, l := range lines(content) {
		next := offset + len(l) + 1
		if isHorizontalRule(l) {
			lastRuleEnd = next
			if lastRuleEnd > len(content) {
				lastRuleEnd = len(content)
			}
		}
		offset = next
	}
	if lastRuleEnd > len(content) {
		lastRuleEnd = len(content)
	}
	return content[lastRuleEnd:]
}

func lastNonEmptyLine(content string) string {
	ls := lines(content)
	for i := len(ls) - 1; i >= 0; i-- {
		if strings.TrimSpace(ls[i]) != "" {
			return ls[i]
		}
	}
	return ""
}

// promptBoxTopBorderIndex：从底部数**第二条**水平分隔线（框顶；最后一条是框底）。
func promptBoxTopBorderIndex(ls []string) (int, bool) {
	count := 0
	for i := len(ls) - 1; i >= 0; i-- {
		if isHorizontalRule(ls[i]) {
			count++
			if count == 2 {
				return i, true
			}
		}
	}
	return 0, false
}

// isHorizontalRule：以 '─' 开头且「只有横线」或「横线 ≥3 条」（照 herdr；短的横线不算分隔线，
// 避免把内容里的装饰符号当框线）。
func isHorizontalRule(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	ruleChars := 0
	ruleBytes := 0
	for _, r := range trimmed {
		if r != '─' {
			break
		}
		ruleChars++
		ruleBytes += len(string(r))
	}
	if ruleChars == 0 {
		return false
	}
	suffix := strings.TrimLeft(trimmed[ruleBytes:], " \t")
	return suffix == "" || ruleChars >= 3
}
