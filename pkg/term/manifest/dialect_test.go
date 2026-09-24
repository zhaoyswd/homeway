// dialect_test.go — 方言垫片的单测（任务 4.1/4.5）。
//
// 垫片是「TOML 逐字节保持上游原样」的前提：它翻译错了，规则会**静默不命中**（比加载失败更难查），
// 所以这里把每条差异都钉住。
package manifest

import "testing"

func TestTranslateRustRegex(t *testing.T) {
	cases := []struct{ in, want string }{
		// \uXXXX（无花括号）
		{`^[\u2800-\u28FF]`, `^[\x{2800}-\x{28FF}]`},
		{`\u2800`, `\x{2800}`},
		// \u{XXXX}（有花括号）
		{`^⚠[\u{fe0e}\u{fe0f}]?`, `^⚠[\x{fe0e}\x{fe0f}]?`},
		// 派生属性 → 类别近似
		{`\p{Alphabetic}`, `\p{L}`},
		{`\P{Alphabetic}`, `\P{L}`},
		// 其它属性原样保留（Go RE2 自己能认）
		{`\p{Greek}\p{Han}`, `\p{Greek}\p{Han}`},
		// 其它转义一律不动
		{`\s\S\d\w\b\A\z\n\r\t\x41`, `\s\S\d\w\b\A\z\n\r\t\x41`},
		{`(?i)(?m)^foo$`, `(?i)(?m)^foo$`},
		// 字面反斜杠 + u 不翻译（`\\u2800` 是「反斜杠 + u2800」两个语义单位）
		{`\\u2800`, `\\u2800`},
		// 已经翻过的再翻不变（幂等）
		{`[\x{2800}-\x{28FF}]`, `[\x{2800}-\x{28FF}]`},
		// 畸形转义原样留给编译器报错（不静默吞掉）
		{`\uZZZZ`, `\uZZZZ`},
		{`\u{zz}`, `\u{zz}`},
	}
	for _, c := range cases {
		if got := TranslateRustRegex(c.in); got != c.want {
			t.Errorf("TranslateRustRegex(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}
}

// 翻译后必须真的能编译（这是垫片存在的唯一理由）。
func TestTranslateMakesPatternsCompilable(t *testing.T) {
	for _, p := range []string{
		`^\s*[\u2800-\u28FF]+\s+\p{Alphabetic}+\w*ing\b`,
		`^\s*(⬡|⬢|[\u2800-\u28FF]+)\s+\p{Alphabetic}+\w*ing\b`,
		`^⚠[\u{fe0e}\u{fe0f}]?(?:\s|$)`,
	} {
		if _, err := compilePattern(p); err != nil {
			t.Errorf("模式 %q 翻译后仍编不过：%v", p, err)
		}
	}
}

// 近似映射的方向性：\p{L} 是 Alphabetic 的子集 ⇒ 只会漏判，不会把非字母误判成字母。
func TestAlphabeticApproximationIsConservative(t *testing.T) {
	re, err := compilePattern(`^\p{Alphabetic}+$`)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"abc", "ABC", "汉字", "Ω"} {
		if !re.MatchString(s) {
			t.Errorf("%q 应命中（字母）", s)
		}
	}
	for _, s := range []string{"123", " ", "•", ""} {
		if re.MatchString(s) {
			t.Errorf("%q 不该命中（非字母）", s)
		}
	}
}
