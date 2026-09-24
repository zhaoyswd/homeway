// dialect.go — Rust regex → Go RE2 的**方言垫片**（任务 4.1/4.5）。
//
// 为什么需要它：移植的 manifest 是 herdr 用 Rust `regex` crate 写的，两者方言有**三处**差别，
// 而我们要让 TOML 文件**逐字节保持上游原样**（否则每次上游更新 manifest 都要人工重写一遍，
// 「携署名移植」的注释与 issue 引用也会被改脏）。差别集中在这里翻译，一处可查、一处可测。
//
// 实测差异（22 份 manifest 全量扫描，2026-09-23）：
//
//	\uXXXX        Rust 支持 `\u2800` 形态的码点转义；Go RE2 只认 `\x{2800}` / `\xNN`
//	\u{XXXX}      同上（带花括号）
//	\p{Alphabetic} Rust 支持 Unicode **派生属性** Alphabetic；Go RE2 只支持**类别与脚本**
//	              （\p{L} / \p{Greek} / \p{Han} …）⇒ 近似映射到 \p{L}
//
// 其余构造（\s \S \d \w \b \A \z \n \r \t \x、非贪婪、{m,n}、(?i)(?m)(?s)、字符类、
// 反向引用以外的分组）两者语义一致，无需翻译。
//
// ⚠️ 近似映射的**影响面**：`\p{Alphabetic}` → `\p{L}` 少了 Nl（罗马数字等）与 Other_Alphabetic
// （部分组合记号），只用在「spinner 后面跟着单词」这类模式上；漏掉的是极冷门字符，
// 不会把非字母误判成字母（\p{L} 是 Alphabetic 的子集）。如将来发现漏判，再单独放宽。
package manifest

import (
	"fmt"
	"regexp"
	"strings"
)

// propertyAliases 是派生属性 → Go RE2 可用类别的近似映射。
var propertyAliases = map[string]string{
	"Alphabetic": "L", // 见包注释的近似说明
}

// compilePattern 翻译方言后编译（引擎里**所有**正则编译都走这里，包括加载期校验）。
func compilePattern(p string) (*regexp.Regexp, error) {
	t := TranslateRustRegex(p)
	re, err := regexp.Compile(t)
	if err != nil {
		if t != p {
			return nil, fmt.Errorf("%v（方言翻译后：%q）", err, t)
		}
		return nil, err
	}
	return re, nil
}

// TranslateRustRegex 把 Rust regex 方言翻成 Go RE2 可编译的形式（幂等：已翻译过的再跑不变）。
//
// 只动「反斜杠引导的转义」，不碰字符串字面量语义——所以 `contains` 里的文本**不要**过这个函数
// （那边 `\u` 就是两个普通字符）。
func TranslateRustRegex(p string) string {
	var b strings.Builder
	b.Grow(len(p))
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c != '\\' || i+1 >= len(p) {
			b.WriteByte(c)
			continue
		}
		next := p[i+1]
		// `\\` 是字面反斜杠：原样吐出两个字符，避免把 `\\u2800` 误翻。
		if next == '\\' {
			b.WriteString(`\\`)
			i++ // 再吃掉第二个反斜杠（循环体末尾还会 +1，故这里只加 1）
			continue
		}
		if next == 'u' {
			if hex, n, ok := parseUnicodeEscape(p[i+2:]); ok {
				b.WriteString(`\x{`)
				b.WriteString(hex)
				b.WriteByte('}')
				// 吃掉 `\` + `u` + 载荷；循环体末尾还会 i++，所以这里加 1+n。
				i += 1 + n
				continue
			}
			b.WriteString(`\u`) // 不是可识别的转义：原样留给编译器报错
			i++
			continue
		}
		if next == 'p' || next == 'P' {
			if name, n, ok := parseProperty(p[i+2:]); ok {
				if alias, found := propertyAliases[name]; found {
					b.WriteByte('\\')
					b.WriteByte(next)
					b.WriteByte('{')
					b.WriteString(alias)
					b.WriteByte('}')
				} else {
					b.WriteByte('\\')
					b.WriteByte(next)
					b.WriteByte('{')
					b.WriteString(name)
					b.WriteByte('}')
				}
				i += 1 + n // 同上：`\` + p/P + {name}，末尾还会 i++
				continue
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

// parseUnicodeEscape 解析 `uXXXX` 或 `u{XXXX}` 的**后半段**（u 已消费），返回十六进制串与消费的字节数。
func parseUnicodeEscape(rest string) (hex string, consumed int, ok bool) {
	if strings.HasPrefix(rest, "{") {
		end := strings.IndexByte(rest, '}')
		if end < 0 {
			return "", 0, false
		}
		body := rest[1:end]
		if !isHex(body) || body == "" {
			return "", 0, false
		}
		return body, end + 1, true
	}
	if len(rest) < 4 || !isHex(rest[:4]) {
		return "", 0, false
	}
	return rest[:4], 4, true
}

// parseProperty 解析 `{Name}`（p/P 已消费）。
func parseProperty(rest string) (name string, consumed int, ok bool) {
	if !strings.HasPrefix(rest, "{") {
		return "", 0, false
	}
	end := strings.IndexByte(rest, '}')
	if end < 0 {
		return "", 0, false
	}
	return rest[1:end], end + 1, true
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return len(s) > 0
}
