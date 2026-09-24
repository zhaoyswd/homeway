//go:build (darwin || linux) && (amd64 || arm64) && cgo

// vt_test.go — cgo 绑定层单测（任务 1.2）。
//
// 夹具（testdata/*.bin）是**真实会话字节**：用 PTY/管道跑真实程序抓的原始输出（含 CRLF 与
// 真实 ANSI 序列），不是手搓的合成串——
//   - session-git-log.bin：`git log --graph --color=always`（真彩色/调色板索引 + 图线 + CJK 提交信息）
//   - session-hexdump.bin：`hexdump -C`（低压缩比内容，任务 1.4 体积对照要用）
//   - session-cjk.bin：CJK + 制表框线 + 高样式密度（宽字符占位格判据）
package vt

import (
	"os"
	"strings"
	"sync"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("读夹具 %s：%v", name, err)
	}
	if len(b) == 0 {
		t.Fatalf("夹具 %s 是空的", name)
	}
	return b
}

// newFrom 建终端并喂入夹具（100x32，与 spike 口径一致）。
func newFrom(t *testing.T, name string) *Terminal {
	t.Helper()
	term, err := New(100, 32, DefaultScrollbackLines)
	if err != nil {
		t.Fatalf("New：%v", err)
	}
	t.Cleanup(term.Close)
	term.Write(fixture(t, name))
	return term
}

// TestPlainTextRealBytes：喂真实会话字节后纯文本导出可用（检测输入腿的基础）。
func TestPlainTextRealBytes(t *testing.T) {
	term := newFrom(t, "session-git-log.bin")
	text := term.PlainText()
	if !strings.Contains(text, "term-vt-backend") {
		t.Fatalf("纯文本里没有提交信息，前 300 字节：%q", head(text, 300))
	}
	if strings.Contains(text, "\x1b") {
		t.Fatalf("纯文本里残留转义序列（formatter PLAIN 应剥掉）：%q", head(text, 200))
	}
	// 折行展开后，图线行的内容也应完整出现。
	if !strings.Contains(text, "文件管理进页空态闪烁修复") {
		t.Errorf("CJK 提交信息没出现：%q", head(text, 400))
	}
}

// TestCJKWideCells：宽字符在网格里是「宽格 + 占位格」——客户端据此跳过占位格不画（D2 的 skip）。
func TestCJKWideCells(t *testing.T) {
	term := newFrom(t, "session-cjk.bin")
	rows := term.Rows()
	if len(rows) == 0 {
		t.Fatal("没有视口行")
	}
	// 找「构建产物」这一行（第一行，粗体）。
	var row *Row
	for i := range rows {
		if strings.Contains(rowText(rows[i]), "构建产物") {
			row = &rows[i]
			break
		}
	}
	if row == nil {
		t.Fatalf("没找到含「构建产物」的行；视口文本：%q", head(rowsText(rows), 200))
	}
	// 定位「构」所在的列，断言它是宽格、后一格是占位格。
	col := -1
	for i, c := range row.Cells {
		if strings.HasPrefix(c.Symbol, "构") {
			col = i
			break
		}
	}
	if col < 0 {
		t.Fatalf("这一行里没有「构」这个格：%q", rowText(*row))
	}
	if got := row.Cells[col].Width; got != 2 {
		t.Errorf("「构」应为宽格（Width=2），实际 %d", got)
	}
	if col+1 < len(row.Cells) {
		next := row.Cells[col+1]
		if !next.Skip || next.Width != 0 {
			t.Errorf("宽字符后一格应为占位格（Skip=true, Width=0），实际 Skip=%v Width=%d Symbol=%q",
				next.Skip, next.Width, next.Symbol)
		}
	}
	if row.Cells[col].Attr&AttrBold == 0 {
		t.Errorf("「构建产物」这行是 \\033[1m 粗体，Attr 里没有 AttrBold：%#x", row.Cells[col].Attr)
	}
}

// TestCellColorsAreRaw：cell 颜色保留**原始形态**（调色板索引或 RGB），不预先解成 RGB
// ——默认 16 色的取值随主题走，解早了主题切换就错（D2 的「主题客户端解析」）。
func TestCellColorsAreRaw(t *testing.T) {
	term := newFrom(t, "session-git-log.bin")
	sawPalette := false
	for _, row := range term.Rows() {
		for _, c := range row.Cells {
			if c.FG.Kind == ColorPalette {
				sawPalette = true
			}
			if c.FG.Kind == ColorNone && c.BG.Kind == ColorNone {
				continue
			}
		}
	}
	if !sawPalette {
		t.Error("git --color=always 的输出应有调色板索引前景色，一个都没读到")
	}
}

// TestModesFromRealBytes：模式位来自 vt 权威值（不是旁路扫描器）。
func TestModesFromRealBytes(t *testing.T) {
	term, err := New(80, 24, DefaultScrollbackLines)
	if err != nil {
		t.Fatalf("New：%v", err)
	}
	defer term.Close()

	if m := term.Modes(); m.Screen != ScreenPrimary || m.MouseTracking() || m.BracketedPaste {
		t.Fatalf("初始模式不对：%+v", m)
	}
	term.Write([]byte("\x1b[?1049h"))
	if m := term.Modes(); m.Screen != ScreenAlternate {
		t.Errorf("?1049h 后应为备用屏，实际 %v", m.Screen)
	}
	term.Write([]byte("\x1b[?1049l"))
	if m := term.Modes(); m.Screen != ScreenPrimary {
		t.Errorf("?1049l 后应回主屏，实际 %v", m.Screen)
	}
	term.Write([]byte("\x1b[?1h\x1b[?1000h\x1b[?1006h\x1b[?2004h\x1b[?1004h\x1b[?25l"))
	m := term.Modes()
	if !m.CursorKeysApp {
		t.Error("?1h 后 CursorKeysApp 应为真")
	}
	if !m.MouseNormal || !m.MouseSGR {
		t.Errorf("鼠标模式不对：%+v", m)
	}
	if !m.MouseTracking() {
		t.Error("MouseTracking() 应为真")
	}
	if !m.BracketedPaste {
		t.Error("?2004h 后 BracketedPaste 应为真")
	}
	if !m.FocusEvents {
		t.Error("?1004h 后 FocusEvents 应为真")
	}
	if m.CursorVisible {
		t.Error("?25l 后 CursorVisible 应为假")
	}
	// 精确复位。
	term.Write([]byte("\x1b[?1l\x1b[?1000l\x1b[?1006l\x1b[?2004l\x1b[?1004l\x1b[?25h"))
	m = term.Modes()
	if m.CursorKeysApp || m.MouseTracking() || m.BracketedPaste || m.FocusEvents || !m.CursorVisible {
		t.Errorf("复位后模式不对：%+v", m)
	}
}

// TestModifyOtherKeysQuery：vendor 补丁 0002 暴露的标量查询（D4 的输入编码依赖它）。
func TestModifyOtherKeysQuery(t *testing.T) {
	term, err := New(80, 24, DefaultScrollbackLines)
	if err != nil {
		t.Fatalf("New：%v", err)
	}
	defer term.Close()
	if term.Modes().ModifyOtherKeys {
		t.Fatal("初始 modifyOtherKeys 应为假")
	}
	term.Write([]byte("\x1b[>4;2m"))
	if !term.Modes().ModifyOtherKeys {
		t.Error("CSI > 4;2m 之后 modifyOtherKeys 应为真（补丁 0002 的查询没生效？）")
	}
	term.Write([]byte("\x1b[>4;0m"))
	if term.Modes().ModifyOtherKeys {
		t.Error("CSI > 4;0m 之后 modifyOtherKeys 应为假")
	}
}

// TestKeyEncodeFollowsModes：转义序列由**服务端按 vt 真实模式**产出——这是 vt 后端化的核心收益。
func TestKeyEncodeFollowsModes(t *testing.T) {
	term, err := New(80, 24, DefaultScrollbackLines)
	if err != nil {
		t.Fatalf("New：%v", err)
	}
	defer term.Close()

	// 普通模式：方向键上 = CSI A。
	up := term.EncodeKey(KeyEvent{Key: KeyArrowUp, Action: KeyPress})
	if string(up) != "\x1b[A" {
		t.Errorf("普通模式 ↑ 应为 \\x1b[A，实际 %q", up)
	}
	// 应用光标键模式（DECCKM）下变成 SS3 A——同一个抽象事件、不同字节。
	term.Write([]byte("\x1b[?1h"))
	up = term.EncodeKey(KeyEvent{Key: KeyArrowUp, Action: KeyPress})
	if string(up) != "\x1bOA" {
		t.Errorf("DECCKM 下 ↑ 应为 \\x1bOA，实际 %q", up)
	}

	// Ctrl+C：抽象修饰符 → 控制字节。
	ctrlC := term.EncodeKey(KeyEvent{Key: KeyC, Action: KeyPress, Mods: ModCtrl, Text: "c"})
	if string(ctrlC) != "\x03" {
		t.Errorf("Ctrl+C 应为 \\x03，实际 %q", ctrlC)
	}
	// 可打印字符按平台给的文本走。
	a := term.EncodeKey(KeyEvent{Key: KeyA, Action: KeyPress, Text: "a"})
	if string(a) != "a" {
		t.Errorf("按 a 应产出 \"a\"，实际 %q", a)
	}
}

// TestMouseEncodeSGR：鼠标按当前上报格式编码（网格坐标 1:1 映射）。
func TestMouseEncodeSGR(t *testing.T) {
	term, err := New(80, 24, DefaultScrollbackLines)
	if err != nil {
		t.Fatalf("New：%v", err)
	}
	defer term.Close()

	// 没开鼠标上报时不该产出任何字节（否则会把垃圾写进 PTY）。
	if got := term.EncodeMouse(MouseEvent{Action: MousePress, Button: MouseLeft, X: 5, Y: 3}); len(got) != 0 {
		t.Fatalf("未开鼠标上报时不该有输出，实际 %q", got)
	}
	term.Write([]byte("\x1b[?1000h\x1b[?1006h"))
	press := term.EncodeMouse(MouseEvent{Action: MousePress, Button: MouseLeft, X: 5, Y: 3})
	if string(press) != "\x1b[<0;6;4M" {
		t.Errorf("SGR 左键按下 (5,3) 应为 \\x1b[<0;6;4M（1 基），实际 %q", press)
	}
	release := term.EncodeMouse(MouseEvent{Action: MouseRelease, Button: MouseLeft, X: 5, Y: 3})
	if string(release) != "\x1b[<0;6;4m" {
		t.Errorf("SGR 左键释放应为小写 m 结尾，实际 %q", release)
	}
	// 滚轮：Button 4/5 在上报里是 press 语义的滚轮码。
	wheel := term.EncodeMouse(MouseEvent{Action: MousePress, Button: MouseFour, X: 1, Y: 1})
	if len(wheel) == 0 {
		t.Error("滚轮事件应产出字节")
	}
}

// TestFocusEncode：焦点事件编码（调用方负责先看 FocusEvents 模式）。
func TestFocusEncode(t *testing.T) {
	if got := EncodeFocus(true); string(got) != "\x1b[I" {
		t.Errorf("focus-in 应为 \\x1b[I，实际 %q", got)
	}
	if got := EncodeFocus(false); string(got) != "\x1b[O" {
		t.Errorf("focus-out 应为 \\x1b[O，实际 %q", got)
	}
}

// TestPasteWrapping：文本事件的括号粘贴包装（按模式）。
func TestPasteWrapping(t *testing.T) {
	if got := EncodePaste("hello", false); string(got) != "hello" {
		t.Errorf("非括号粘贴应原样，实际 %q", got)
	}
	got := EncodePaste("hello", true)
	if string(got) != "\x1b[200~hello\x1b[201~" {
		t.Errorf("括号粘贴包装不对：%q", got)
	}
}

// TestResizeAndScrollback：resize 走 vt（含重排），回滚行数可读。
func TestResizeAndScrollback(t *testing.T) {
	term, err := New(80, 24, 200)
	if err != nil {
		t.Fatalf("New：%v", err)
	}
	defer term.Close()
	if c, r := term.Size(); c != 80 || r != 24 {
		t.Fatalf("初始尺寸应为 80x24，实际 %dx%d", c, r)
	}
	if err := term.Resize(100, 30); err != nil {
		t.Fatalf("Resize：%v", err)
	}
	if c, r := term.Size(); c != 100 || r != 30 {
		t.Errorf("resize 后应为 100x30，实际 %dx%d", c, r)
	}
	for i := 0; i < 200; i++ {
		term.Write([]byte("line\n"))
	}
	if n := term.ScrollbackRows(); n == 0 {
		t.Error("写了 200 行后回滚行数应 > 0")
	}
}

// TestDirtyRowsLifecycle：Update → DirtyRows → Clean 的增量语义（surface 差分的基础）。
func TestDirtyRowsLifecycle(t *testing.T) {
	term, err := New(40, 10, DefaultScrollbackLines)
	if err != nil {
		t.Fatalf("New：%v", err)
	}
	defer term.Close()

	term.Write([]byte("hello\r\nworld\r\n"))
	if d := term.Update(); d == DirtyNone {
		t.Error("首次写入后应有脏行")
	}
	rows := term.DirtyRows()
	if len(rows) == 0 {
		t.Fatal("应至少有一行脏行")
	}
	term.Clean()

	// Clean 之后没有新输入 ⇒ 不再有脏行。
	if d := term.Update(); d != DirtyNone {
		t.Errorf("Clean 后无输入应为 DirtyNone，实际 %d", d)
	}
	if rows := term.DirtyRows(); len(rows) != 0 {
		t.Errorf("Clean 后不该有脏行，实际 %d 行", len(rows))
	}

	// 只改一行 ⇒ 脏行应少于整屏。
	term.Write([]byte("\x1b[1;1HX"))
	if d := term.Update(); d == DirtyNone {
		t.Fatal("写入后应有脏行")
	}
	if rows := term.DirtyRows(); len(rows) == 0 || len(rows) >= 10 {
		t.Errorf("单行改动的脏行数应介于 1 与整屏之间，实际 %d", len(rows))
	}
	// 快照路径：Rows() 恒为整屏。
	if rows := term.Rows(); len(rows) != 10 {
		t.Errorf("Rows() 应返回整屏 10 行，实际 %d", len(rows))
	}
}

// TestSnapshotRoundTrip：snapshot 编码/解码往返一致（口径与 spike 相同：
// **纯文本逐字节相等 + 尺寸保持**，不是全状态字节断言）。
func TestSnapshotRoundTrip(t *testing.T) {
	for _, name := range []string{"session-git-log.bin", "session-hexdump.bin", "session-cjk.bin"} {
		t.Run(name, func(t *testing.T) {
			term := newFrom(t, name)
			snap, err := term.Snapshot()
			if err != nil {
				t.Fatalf("Snapshot：%v", err)
			}
			if len(snap) == 0 {
				t.Fatal("快照为空")
			}
			restored, err := RestoreSnapshot(snap)
			if err != nil {
				t.Fatalf("RestoreSnapshot：%v", err)
			}
			defer restored.Close()
			if a, b := term.PlainText(), restored.PlainText(); a != b {
				t.Errorf("往返后纯文本不一致：\n原 %q\n还原 %q", head(a, 200), head(b, 200))
			}
			c1, r1 := term.Size()
			if c2, r2 := restored.Size(); c1 != c2 || r1 != r2 {
				t.Errorf("往返后尺寸不一致：%dx%d vs %dx%d", c1, r1, c2, r2)
			}
		})
	}
}

// TestConcurrentUse：每实例互斥 ⇒ 多 goroutine 并发调用不炸（配合 -race 才有意义）。
func TestConcurrentUse(t *testing.T) {
	term := newFrom(t, "session-git-log.bin")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				switch i % 4 {
				case 0:
					term.Write([]byte("\x1b[32mok\x1b[0m\r\n"))
				case 1:
					_ = term.Modes()
				case 2:
					term.Update()
					term.DirtyRows()
					term.Clean()
				case 3:
					_ = term.PlainText()
					term.EncodeKey(KeyEvent{Key: KeyA, Action: KeyPress, Text: "a"})
				}
			}
		}(i)
	}
	wg.Wait()
}

// TestClosedTerminalIsSafe：Close 之后所有入口都不 panic（会话收尾与 pump 有竞态）。
func TestClosedTerminalIsSafe(t *testing.T) {
	term, err := New(20, 5, 100)
	if err != nil {
		t.Fatalf("New：%v", err)
	}
	term.Close()
	term.Close() // 幂等
	term.Write([]byte("x"))
	if c, r := term.Size(); c != 0 || r != 0 {
		t.Errorf("关闭后尺寸应为 0,0，实际 %d,%d", c, r)
	}
	if err := term.Resize(30, 10); err == nil {
		t.Error("关闭后 Resize 应报错")
	}
	if got := term.PlainText(); got != "" {
		t.Errorf("关闭后纯文本应为空，实际 %q", got)
	}
	if got := term.EncodeKey(KeyEvent{Key: KeyA, Action: KeyPress, Text: "a"}); got != nil {
		t.Errorf("关闭后不该编码出字节，实际 %q", got)
	}
	term.Update()
	term.Clean()
}

// TestTitleAndPwd：标题与 OSC 7 工作目录（检测证据与 LIST JSON 的 cwd 字段来源）。
func TestTitleAndPwd(t *testing.T) {
	term, err := New(80, 24, DefaultScrollbackLines)
	if err != nil {
		t.Fatalf("New：%v", err)
	}
	defer term.Close()
	term.Write([]byte("\x1b]2;构建中\x07"))
	if got := term.Title(); got != "构建中" {
		t.Errorf("标题应为「构建中」，实际 %q", got)
	}
	// ⚠️ vt 给的是 OSC 7 的**原始值**（URI 形态，含 scheme 与 host），路径要自己剥。
	term.Write([]byte("\x1b]7;file://localhost/Users/zhaozhe/proj\x07"))
	if got := term.Pwd(); got != "file://localhost/Users/zhaozhe/proj" {
		t.Errorf("pwd 应为 OSC 7 原始 URI，实际 %q", got)
	}
	if got := PwdPath(term.Pwd()); got != "/Users/zhaozhe/proj" {
		t.Errorf("PwdPath 应剥出 /Users/zhaozhe/proj，实际 %q", got)
	}
}

// TestNewRejectsBadSize：非法尺寸要明确报错，不能建出一个坏终端。
func TestNewRejectsBadSize(t *testing.T) {
	if _, err := New(0, 24, 100); err == nil {
		t.Error("0 列应报错")
	}
	if _, err := New(80, 0, 100); err == nil {
		t.Error("0 行应报错")
	}
	if _, err := RestoreSnapshot(nil); err == nil {
		t.Error("空快照应报错")
	}
}

// ---- 小工具 ----

// rowText 拼一行的可读文本：占位格（宽字符尾格）跳过——它们 Symbol 为空，补空格会把 CJK 拆开。
func rowText(r Row) string {
	var b strings.Builder
	for _, c := range r.Cells {
		if c.Skip {
			continue
		}
		if c.Symbol == "" {
			b.WriteByte(' ')
			continue
		}
		b.WriteString(c.Symbol)
	}
	return b.String()
}

func rowsText(rows []Row) string {
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(rowText(r))
		b.WriteByte('\n')
	}
	return b.String()
}

func head(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// TestStructABI：Go 侧结构尺寸必须与 C 侧 sizeof 逐字节一致。
//
// sized struct（调用方填 size 字段的那些）一旦不一致，库会按自己的 sizeof 写内存、踩坏相邻的
// Go 变量——症状是偶发 GC 崩溃，极难定位。换 vendor 基线后这个测试是第一个该跑的门。
func TestStructABI(t *testing.T) {
	for name, pair := range structSizes() {
		if pair[0] != pair[1] {
			t.Errorf("%s 尺寸不一致：go=%d c=%d（sized-struct ABI 漂移，会踩坏内存）", name, pair[0], pair[1])
		}
	}
}
