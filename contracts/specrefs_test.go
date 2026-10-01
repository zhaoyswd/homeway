// specrefs_test.go — FIX-101 第一半：台账 spec 列的可校验化。
//
// spec 列是自由文本（能力域名 + 备注），此前「不可校验」——typo 与已改名能力域
// 无人抓。本门把**可识别的能力域 token**（全小写 kebab 形态）与 tier 仓
// openspec/specs/ 的真实目录对账：
//   - token ∈ 目录集 → 过；
//   - token ∈ 显式备注词表（specNoteTokens：fixtures/golden/goodbye/v1…）→ 过
//     （新增备注词必须登记——逼迫「要么真域名、要么显式登记」）；
//   - 其余 → 红（typo 或能力域已改名/退役）。
//
// 跨仓：tier 路径取 TIER_SPECS_DIR，缺省 ../tier/openspec/specs；找不到则 SKIP
// （homeway 单独 checkout / CI 上无 tier 仓时的正常形态）。
package contracts

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// specNoteTokens：spec 列里合法的**非目录**备注词（已核；新增需在此登记）。
// 校验目标集 = openspec/specs/（已落位能力域）∪ openspec/changes/（未归档 change——
// 能力域还在 change 阶段时引用它合法；archive/ 不算：历史 change 应已合入 specs）。
var specNoteTokens = map[string]bool{
	"fixtures": true, // 「daemon-control-plane fixtures v1」等：讲的是 fixtures 版本，不是能力域
	"golden":   true, // 「term-surface-protocol golden」：讲的是跨仓 golden 夹具
	"goodbye":  true, // 「（reload/goodbye 关帧原因）」：讲的是关帧
	"v1":       true, // 「fixtures v1」：版本后缀
}

var specTokenRe = regexp.MustCompile(`^[a-z][a-z0-9-]+$`)

func TestLedgerSpecRefs(t *testing.T) {
	root := testRoot(t)
	specsDir := os.Getenv("TIER_SPECS_DIR")
	if specsDir == "" {
		specsDir = filepath.Join(filepath.Dir(root), "tier", "openspec", "specs")
	}
	entries, err := os.ReadDir(specsDir)
	if err != nil {
		t.Skipf("SKIP：找不到 tier specs 目录（%s）——设 TIER_SPECS_DIR 或检出 tier 仓后重跑", specsDir)
	}
	dirs := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			dirs[e.Name()] = true
		}
	}
	// 未归档 change 也接受（能力域还在 change 阶段）。
	if changes, cerr := os.ReadDir(filepath.Join(filepath.Dir(specsDir), "changes")); cerr == nil {
		for _, e := range changes {
			if e.IsDir() && e.Name() != "archive" {
				dirs[e.Name()] = true
			}
		}
	}
	if len(dirs) == 0 {
		t.Fatalf("tier specs/changes 目录为空（%s）——先例「空集假绿」同款，拒绝", specsDir)
	}

	led, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	bad := 0
	check := func(where, spec string) {
		// 分隔符：+ / 空白 / 顿号 / 逗号；括号内容整体剥离（「（FIX-76）」这类注记）。
		s := spec
		for {
			l := strings.Index(s, "（")
			if l < 0 {
				break
			}
			r := strings.Index(s[l:], "）")
			if r < 0 {
				break
			}
			s = s[:l] + " " + s[l+r+len("）"):]
		}
		for _, tok := range strings.FieldsFunc(s, func(r rune) bool {
			return r == '+' || r == '/' || r == '、' || r == ',' || r == '，' || r == ' '
		}) {
			if !specTokenRe.MatchString(tok) || specNoteTokens[tok] {
				continue // 中文备注 / 已登记的备注词：不判
			}
			if !dirs[tok] {
				t.Errorf("%s: spec token %q 不在 tier openspec/specs/ 目录（typo 或能力域已改名/退役？若为备注词请在 specNoteTokens 登记）", where, tok)
				bad++
			}
		}
	}
	for _, r := range led.Rows {
		check("行 "+r.Family+"/"+r.Unit+"/"+r.Value, r.Spec)
	}
	for _, f := range led.Fixtures {
		check("fixtures 行 "+f.Unit+"/"+f.Name, f.Spec)
	}
	if bad > 0 {
		t.Fatalf("spec 引用不一致 %d 处（FIX-101：spec 值必须指向真实能力域目录）", bad)
	}
}
