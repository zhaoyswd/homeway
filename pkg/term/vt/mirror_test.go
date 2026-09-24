//go:build (darwin || linux) && (amd64 || arm64) && cgo

// mirror_test.go — 回滚镜像窗口读取的判据（任务 2.3 依赖的底层能力）。
//
// 这条路径用的是上游「滚上去读、再滚回来」的 API 用法，两条纪律必须被测试钉住：
// ① 读完必须还原视口（否则 surface 的快照会拍到滚上去的那一帧）；
// ② 在底部时要还原成 BOTTOM（否则终端被摘出「跟随输出」模式，用户看到会话卡住不动）。
package vt

import (
	"fmt"
	"strings"
	"testing"
)

func fillLines(t *testing.T, term *Terminal, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		term.Write([]byte(fmt.Sprintf("line-%03d\r\n", i)))
	}
}

func TestMirrorRowsReadsScrollback(t *testing.T) {
	term, err := New(40, 10, 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer term.Close()
	fillLines(t, term, 100)

	above := term.RowsAboveViewport()
	if above == 0 {
		t.Fatal("写了 100 行后视口上方应有回滚行")
	}
	mirror := term.MirrorRows(20)
	if len(mirror) != 20 {
		t.Fatalf("镜像窗口应 20 行，实际 %d", len(mirror))
	}
	// 语义断言（不写死行号）：窗口最后一行必须**紧邻**视口首行，窗口首行比它早 19 行。
	// 行号从视口首行推出来，所以这条断言不依赖「写多少行会滚几次」的算术。
	vpTop := lineNo(t, rowText(term.Rows()[0]))
	if vpTop < 0 {
		t.Fatalf("视口首行不是 line-NNN：%q", rowText(term.Rows()[0]))
	}
	gotLast := lineNo(t, rowText(mirror[len(mirror)-1]))
	gotFirst := lineNo(t, rowText(mirror[0]))
	if gotLast != vpTop-1 {
		t.Errorf("镜像末行应是视口首行的上一行（期望 %d），实际 %d", vpTop-1, gotLast)
	}
	if gotFirst != vpTop-20 {
		t.Errorf("镜像首行应比视口首行早 20 行（期望 %d），实际 %d", vpTop-20, gotFirst)
	}
}

// lineNo 从 "line-NNN" 里取出行号（取不到返回 -1）。
func lineNo(t *testing.T, text string) int {
	t.Helper()
	i := strings.Index(text, "line-")
	if i < 0 {
		return -1
	}
	n := 0
	for _, c := range text[i+5:] {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// 纪律 ①：读完必须还原视口。
func TestMirrorRowsRestoresViewport(t *testing.T) {
	term, err := New(40, 10, 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer term.Close()
	fillLines(t, term, 60)

	before := term.Scrollbar()
	beforeText := rowsText(term.Rows())
	_ = term.MirrorRows(30)
	after := term.Scrollbar()
	afterText := rowsText(term.Rows())

	if before != after {
		t.Errorf("滚动条状态应还原：before=%+v after=%+v", before, after)
	}
	if beforeText != afterText {
		t.Errorf("视口内容应还原：\nbefore=%q\nafter=%q", beforeText, afterText)
	}
}

// 纪律 ②：在底部时还原成 BOTTOM（跟随输出不被摘掉）。
func TestMirrorRowsKeepsFollowMode(t *testing.T) {
	term, err := New(40, 10, 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer term.Close()
	fillLines(t, term, 60)
	if !term.Scrollbar().AtBottom() {
		t.Fatal("写完内容应贴着底部")
	}
	_ = term.MirrorRows(25)
	if !term.Scrollbar().AtBottom() {
		t.Fatal("读镜像后应仍在底部（否则跟随输出被摘掉）")
	}
	// 再写内容：视口应跟着滚（内容出现在可见区）。
	term.Write([]byte("FOLLOW-ME\r\n"))
	if !strings.Contains(rowsText(term.Rows()), "FOLLOW-ME") {
		t.Error("新输出应出现在视口里（跟随输出模式保持）")
	}
}

// 无回滚 / 备用屏：返回 nil（备用屏抑制回滚，design D3）。
func TestMirrorRowsEmptyCases(t *testing.T) {
	term, err := New(40, 10, 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer term.Close()
	term.Write([]byte("short\r\n"))
	if got := term.MirrorRows(20); len(got) != 0 {
		t.Errorf("无回滚时应返回空，实际 %d 行", len(got))
	}
	if got := term.MirrorRows(0); got != nil {
		t.Errorf("above<=0 应返回 nil，实际 %d 行", len(got))
	}
	fillLines(t, term, 60)
	term.Write([]byte("\x1b[?1049h")) // 进备用屏
	if got := term.MirrorRows(20); got != nil {
		t.Errorf("备用屏应抑制回滚窗口，实际 %d 行", len(got))
	}
	term.Write([]byte("\x1b[?1049l"))
	if got := term.MirrorRows(20); len(got) == 0 {
		t.Error("回主屏后应重新可取回滚窗口")
	}
}
