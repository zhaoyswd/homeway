// frozen_test.go — 净室冻结线（FIX-103）：导出解码面**冻结**。
//
// 净室是「为未立项 4c（web 客户端）投的保」——证明三族 fixtures + 上行字节表 +
// spec 口径自足（未来 TS 消费者同路径可行），**不是**生产解码器的平行演进路径。
// 冻结期纪律：只解码、不加族。新增族（新 op / 新 category / 新解码入口）必须等
// 4c 立项后**按 spec 重写净室**，不允许顺手扩面。
//
// 本测试 AST 扫非测试 .go 的导出函数名集 == 冻结清单——改动即红（diff 可见，
// 形态与 imports_audit_test 同款）。
package cleanroom

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// frozenExports 净室导出面冻结清单（FIX-103 快照，2026-10-02）。新增/改名须显式改
// 这里并说明理由——冻结期内「加族」的正确路径是等 4c 立项按 spec 重写。
var frozenExports = []string{
	// cleanroom.go：控制面帧 / term 帧 / 上行字节表 / 压缩
	"DecodeControlFrame",
	"DecodeControlBody",
	"BuildTermFrame",
	"DecodeTermFrame",
	"DecodeTermPayload",
	"DecodeUplink",
	"Gunzip",
	"RepoRoot",
	// surface.go：跨仓 golden（manifest / 分片 / 应用 / 摘要 / 网格）
	"LoadGoldenManifest",
	"ReadGoldenFrames",
	"Deframe",
	"ApplyFrames",
	"DigestHex",
	"DecodeGridLines",
	"DecodeRows",
}

func TestCleanroomFrozenSurface(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if perr != nil {
			t.Fatalf("解析 %s 失败：%v", e.Name(), perr)
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || !fd.Name.IsExported() {
				continue
			}
			got = append(got, fd.Name.Name)
		}
	}
	sort.Strings(got)
	want := append([]string(nil), frozenExports...)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("净室导出面越出冻结线（FIX-103：只解码、不加族——新增族须等 4c 立项按 spec 重写）：\n  now  = %v\n  want = %v\n（若确为有意的冻结线修订，请显式更新 frozenExports 并说明）", got, want)
	}
}
