//go:build !windows && (darwin || linux) && (amd64 || arm64) && cgo

// （tag 与 term_surface_golden_test.go 一致——本文件共用其 decodedGridRows/goldenStyleText，
// 且 import vt（cgo）；FIX-98 顺带修复：原 tag 只有 !windows，linux+CGO_ENABLED=0 下编译必断。）

package term

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zhaoyswd/homeway/pkg/term/vt"
)

func TestStyleProbeDump(t *testing.T) {
	blob := buildStylesGridBlob(t)
	rows := decodedGridRows(t, blob)
	cols, _, _, _ := vt.DecodeGrid(blob)
	os.WriteFile("/tmp/styleprobe/go.txt", []byte(goldenStyleText(rows, cols)), 0o644)
}

func buildStylesGridBlob(t *testing.T) []byte {
	term, err := vtNew(100, 32, 5000)
	if err != nil {
		t.Fatal(err)
	}
	defer term.Close()
	term.Write(goldenStylesSession())
	cols, rows := term.Size()
	return vtEncodeGrid(cols, rows, term.Rows())
}

var _ = filepath.Join
