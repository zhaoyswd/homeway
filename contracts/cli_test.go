// cli_test.go — CLI 面值集对账（tasks 2.4；files-cli r1 低-10 前向登记的兑现）：
// pkg/files/files_cli.go 与 internal/daemon 的 files/speedtest CLI 消费的稳定码
// （同包常量标识符 / 跨包选择子 / case 子句字符串字面量）必须 ⊆ 台账——CLI 文案
// 不进台账（冻结的是码不是文案）。
package contracts

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestLedgerCLIFace CLI 稳定码消费面：提取三处 CLI 文件里的词表常量引用与 case
// 字面量，值集 ⊆ 台账（按值全域查；未登记即红）。
func TestLedgerCLIFace(t *testing.T) {
	root := testRoot(t)
	led, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	// 全域已登记值（不分族——CLI 是消费面，值落在哪个族由台账行自带）。
	registered := map[string]string{}
	for _, r := range led.Rows {
		if r.Family == "fixtures" || r.Family == "napi-face" {
			continue
		}
		registered[r.Value] = r.Family + "/" + r.Unit
	}
	// 已知词表常量名 → 值（从提取结果反查；同包裸标识符与跨包选择子都靠它解析）。
	ex, err := ExtractAll(root)
	if err != nil {
		t.Fatal(err)
	}
	nameValue := map[string]string{} // 常量名（包内唯一性足够：files/term/streamend/speedtest/facade 的词表名互不重复）
	for _, units := range ex {
		for _, vals := range units {
			for v, n := range vals {
				if !strings.HasPrefix(n, "ctor:") {
					nameValue[n] = v
				}
			}
		}
	}
	// CLI 消费面选择子的限定名集合（导入别名 → 属于哪个已提取包的关键词表前缀不必要：
	// 值域名判断按选择子的 Sel 是否词表常量名）。
	cliFiles := []string{
		filepath.Join(root, "pkg/files/files_cli.go"),
		filepath.Join(root, "internal/daemon/files_remote.go"),
		filepath.Join(root, "internal/daemon/speedtest_cli.go"),
	}
	// case 字面量只查**码→文案映射函数**（tasks 2.4 的「files CLI Go 映射表与 speedtest
	// CLI 文案」）：CLI 参数子命令/flag/Phase 展示等本地 case 不属稳定码面（files 动词
	// 与 speedtest Phase 为 11 族之外的表外词面，进台账属后续 delta——exec-report 登记）。
	mapFuncs := map[string]bool{"codeMessage": true, "streamEndMessage": true, "speedShortReason": true}
	var unknown []string
	for _, path := range cliFiles {
		fset := token.NewFileSet()
		f, err := parseFileComments(fset, path)
		if err != nil {
			t.Fatalf("解析 %s 失败：%v", path, err)
		}
		inMapFunc := false
		ast.Inspect(f, func(n ast.Node) bool {
			if fd, ok := n.(*ast.FuncDecl); ok {
				inMapFunc = mapFuncs[fd.Name.Name]
				return true
			}
			switch x := n.(type) {
			case *ast.SelectorExpr: // speedtest.ReasonBusy / streamend.Gone / facade.CodeBadRequest
				if v, ok := nameValue[x.Sel.Name]; ok {
					if _, hit := registered[v]; !hit {
						unknown = append(unknown, path+": "+x.Sel.Name+" = "+v)
					}
				}
			case *ast.Ident: // 同包常量（files_cli.go 的 CodeInvalidArg 等）
				if v, ok := nameValue[x.Name]; ok && x.Obj == nil {
					// Obj==nil 粗滤局部变量；词表常量是包级声明。值未登记才红。
					if _, hit := registered[v]; !hit {
						unknown = append(unknown, path+": "+x.Name+" = "+v)
					}
				}
			case *ast.CaseClause: // 映射函数内 case "xxx": 的字符串字面量（提常量后应为零）
				if !inMapFunc {
					return true
				}
				for _, e := range x.List {
					if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if s, err := unquote(lit.Value); err == nil && s != "" {
							if _, hit := registered[s]; !hit {
								unknown = append(unknown, path+": case "+s)
							}
						}
					}
				}
			}
			return true
		})
	}
	if len(unknown) > 0 {
		t.Errorf("CLI 面出现台账外稳定码（值集 ⊆ 台账族不成立）：%v", unknown)
	}
}
