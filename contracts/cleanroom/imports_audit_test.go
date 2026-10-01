// imports_audit_test.go — 净室纪律的机器钉（contract-ledger tasks 4.1，design D4）：
// AST 扫本包全部 .go 文件的 import 清单 == 标准库白名单——净室一旦引用生产包即红
// （否则「净室从零解出」退回「生产包自解」，证明力归零）。白名单外的新 import
// 必须显式改这里（diff 可见），防标准库面无声膨胀。
package cleanroom

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// stdlibWhitelist 净室允许的标准库 import 面（设计 D4：标准库 only）=
// 当下实际使用的全集；新增须显式改这里（diff 可见）。
var stdlibWhitelist = map[string]bool{
	"bytes": true, "compress/gzip": true, "encoding/binary": true,
	"encoding/hex": true, "encoding/json": true, "errors": true, "fmt": true,
	"go/ast": true, "go/parser": true, "go/token": true, "hash/fnv": true,
	"io": true, "os": true, "path/filepath": true, "reflect": true,
	"sort": true, "strconv": true, "strings": true, "testing": true,
}

// TestCleanroomImportsAudited 扫包内全部 .go（含测试）的 import 声明：
// 非白名单（= 生产包或未审标准库）即红。
func TestCleanroomImportsAudited(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	nonTest := 0
	var badImports []string
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			t.Fatalf("解析 %s 失败：%v", e.Name(), err)
		}
		if !strings.HasSuffix(e.Name(), "_test.go") {
			nonTest++
		}
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("%s：import 路径非法：%v", e.Name(), err)
			}
			if !stdlibWhitelist[path] {
				badImports = append(badImports, e.Name()+" → "+path)
			}
		}
	}
	if nonTest == 0 {
		t.Fatal("包内无非测试 .go 文件（CI 形态构建门会「no non-test Go files」红——中-5）")
	}
	if len(badImports) > 0 {
		sort.Strings(badImports)
		t.Errorf("净室 import 面越界（只允许标准库白名单；引用生产包即红）：\n  %s",
			strings.Join(badImports, "\n  "))
	}
}
