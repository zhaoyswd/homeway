//go:build !windows && (darwin || linux) && (amd64 || arm64) && cgo

// term_surface_test.go — surface 协议的服务端判据（任务 2.1–2.7、2.10）。
//
// 测试是**端到端**的：真起 PTY 会话、真走帧协议，客户端侧用 Go 复刻（攒分片 → 解压 → 解体 →
// 应用 patch），断言客户端最终网格与服务端视口一致。这正是任务 2.10 要的那些判据：
// 编解码 roundtrip、分片重组、revision 断档自愈、差分自适应降级、背压降级、备用屏抑制、
// 单腿顶替语义。
package term

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/term/vt"
)

// ---- 2.1 能力协商 ----

// 新客户端（带 capability）走 surface：拿快照而不是原始字节回放。
func TestSurfaceNegotiationNewClient(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c, snap := attachSurface(t, ln, "sf1", 80, 24)
	defer c.Close()

	if snap.Geometry.Cols != 80 || snap.Geometry.Rows != 24 {
		t.Errorf("快照几何应为 80x24，实际 %dx%d", snap.Geometry.Cols, snap.Geometry.Rows)
	}
	if len(snap.Grid) == 0 {
		t.Error("快照应带网格")
	}
	// 关键：surface 腿**不该**收到 legacy 的 DATA 回放（那正是要消灭的路径）。
	// 会话在持续输出（testTermShell 的 ticker），所以这里能看到的是差分而非 DATA。
	_ = c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	f, err := readTermFrame(c)
	if err == nil {
		if f.op == opData {
			t.Fatal("surface 腿不该收到 legacy DATA 帧")
		}
		if f.op == opReplayDone {
			t.Fatal("surface 腿不该收到 legacy REPLAY-DONE")
		}
	}
}

// 旧客户端（不发 capability）走 legacy：照旧拿到回放。
func TestSurfaceNegotiationLegacyClient(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c, _, replay, _ := attachTerm(t, ln, "sf2", true, 80, 24)
	defer c.Close()
	if len(replay) == 0 {
		t.Error("legacy 腿应收到回放数据（旧客户端路径零变化）")
	}
}

// 畸形 capability 块 ⇒ **独立错误码**（不得复用版本不匹配路径）。
func TestSurfaceNegotiationBadCapability(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c := dialTerm(t, ln)
	defer c.Close()
	if f := readTermFrameT(t, c); f.op != opGreeting {
		t.Fatal("首帧应为 GREETING")
	}
	// capLen 声明 9 字节但只给 1 字节。
	hello := append(encHello(80, 24, true, "sf3"), 9, capsSurface)
	writeTermFrame(t, c, opHello, hello)
	f := readTermFrameT(t, c)
	if f.op != opError {
		t.Fatalf("畸形 capability 应报错，收到 0x%02x", f.op)
	}
	code, msg, err := decError(f.payload)
	if err != nil {
		t.Fatal(err)
	}
	if code != "bad_capability" {
		t.Errorf("错误码应为 bad_capability（与版本不匹配可区分），实际 %q（%s）", code, msg)
	}
}

// HOMEWAY_TERM_VT=off ⇒ surface 协商失败得**明确错误码**（客户端据此回落 legacy，不静默降级）。
func TestSurfaceNegotiationUnavailable(t *testing.T) {
	t.Setenv("HOMEWAY_TERM_VT", "off")
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c := dialTerm(t, ln)
	defer c.Close()
	if f := readTermFrameT(t, c); f.op != opGreeting {
		t.Fatal("首帧应为 GREETING")
	}
	hello := append(encHello(80, 24, true, "sf4"), encCapability(capsSurface)...)
	writeTermFrame(t, c, opHello, hello)
	f := readTermFrameT(t, c)
	if f.op != opError {
		t.Fatalf("应报错，收到 0x%02x", f.op)
	}
	if code, _, _ := decError(f.payload); code != "surface_unavailable" {
		t.Errorf("错误码应为 surface_unavailable，实际 %q", code)
	}
}

// ---- 2.2 分片与帧长契约 ----

func TestFragmentRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 100, fragChunk - 1, fragChunk, fragChunk + 1, 5 * fragChunk} {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i * 7)
		}
		frags := fragmentPayload(data)
		// 每帧都必须在硬上限内（u16 帧长）。
		for _, f := range frags {
			if len(f) > surfaceMaxFrame {
				t.Fatalf("n=%d 时出现超限帧：%d > %d", n, len(f), surfaceMaxFrame)
			}
		}
		// 片数应为 ceil(n/chunk)（空数据也发一片）。
		want := (n + fragChunk - 1) / fragChunk
		if want == 0 {
			want = 1
		}
		if len(frags) != want {
			t.Fatalf("n=%d 片数应为 %d，实际 %d", n, want, len(frags))
		}
		var asm fragAssembler
		var got []byte
		for i, f := range frags {
			done, out, err := asm.push(f)
			if err != nil {
				t.Fatalf("push: %v", err)
			}
			if done != (i == len(frags)-1) {
				t.Fatalf("n=%d 第 %d 片 done=%v 不符", n, i, done)
			}
			if done {
				got = out
			}
		}
		if len(got) != n {
			t.Fatalf("n=%d 重组长度 %d", n, len(got))
		}
		for i := range got {
			if got[i] != data[i] {
				t.Fatalf("n=%d 第 %d 字节不符", n, i)
			}
		}
	}
}

func TestFragmentRejectsOverlongGroup(t *testing.T) {
	var asm fragAssembler
	for i := 0; i < maxFragParts; i++ {
		if _, _, err := asm.push(encFragment(fragMoreBit, []byte("x"))); err != nil {
			t.Fatalf("第 %d 片不该报错：%v", i, err)
		}
	}
	if _, _, err := asm.push(encFragment(fragMoreBit, []byte("x"))); err == nil {
		t.Error("超过片数上限应报错（防病态对端拖死内存）")
	}
}

func TestGzipRoundTrip(t *testing.T) {
	for _, s := range []string{"", "hello", strings.Repeat("构建产物 中文 ", 500)} {
		gz, err := gzipBytes([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		back, err := gunzipBytes(gz)
		if err != nil {
			t.Fatal(err)
		}
		if string(back) != s {
			t.Errorf("gzip 往返不一致（len %d）", len(s))
		}
	}
}

// ---- 2.3 SNAPSHOT ----

func TestSurfaceSnapshotCarriesGridAndMirror(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c, snap := attachSurface(t, ln, "sf5", 80, 24)
	defer c.Close()

	// 网格能解出来，且行数 = 视口行数。
	cols, rows, gridRows, err := decodeGridOf(t, snap.Grid)
	if err != nil {
		t.Fatalf("解网格：%v", err)
	}
	if cols != 80 || rows != 24 {
		t.Errorf("网格几何应为 80x24，实际 %dx%d", cols, rows)
	}
	if len(gridRows) != 24 {
		t.Errorf("网格应有 24 行，实际 %d", len(gridRows))
	}
	// 标题（单一来源是 termScan）与模式位字段在位。
	if snap.Title != "" && len(snap.Title) > 512 {
		t.Error("标题应被限制在合理长度")
	}
	_ = svc
}

// 备用屏会话：快照含精确当前屏，**不带**镜像窗口（design D3 抑制回滚）。
//
// 用专门的 shell：读一行输入就进备用屏并输出标记——比让被测会话去解释 shell 语法确定得多
// （测试默认 shell 是 `cat`，敲进去的文本只会被回显，不会被执行）。
func TestSurfaceSnapshotAltScreenNoMirror(t *testing.T) {
	svc, ln := startTestTermServiceShell(t, "read -r _l; printf '\\033[?1049h'; echo ALT-MARK; sleep 2")
	defer svc.Close()
	defer ln.Close()
	c, _ := attachSurface(t, ln, "sf6", 80, 24)
	defer c.Close()

	writeTermFrame(t, c, opInput, encInputEvent(inputEvent{Kind: inputKindText, Text: "go\r"}))
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		f, err := readTermFrame(c)
		if err != nil {
			break
		}
		if f.op != opSnapshot {
			continue // 中间可能有差分/状态帧
		}
		body := surfaceReaderFrom(t, c, f)
		snap, derr := decSnapshotBody(body)
		if derr != nil {
			t.Fatal(derr)
		}
		if f2 := readTermFrameT(t, c); f2.op != opSnapshotDone {
			t.Fatalf("期望 SNAPSHOT-DONE，收到 0x%02x", f2.op)
		}
		if snap.Modes&termModeAltScreen == 0 {
			// 还没进备用屏：继续请求全量。
			writeTermFrame(t, c, opFetchSnapshot, nil)
			continue
		}
		if len(snap.Mirror) != 0 {
			t.Error("备用屏快照不该带镜像窗口（回滚在备用屏无意义）")
		}
		return
	}
	t.Fatal("没拿到备用屏的全量快照")
}

// ---- 2.4 差分与 revision ----

// 3.10：差分帧带光标，而且这个光标必须是**本拍的**（不是快照那份旧值）。
//
// 判据形状（对着「唯一的失效形态」设计）：测试 shell 是 `while :; do echo tick; sleep 0.2; done & cat`
// ⇒ 屏幕每 200ms 追加一行，光标一路下沉到屏底。所以对每个差分断言：
//   - 光标在几何内（客户端拒收口径）；
//   - **光标行 ≥ 客户端网格里最后一行有内容的行**——冻结在 attach 时刻的实现会给一个靠上的旧行号
//     （attach 时屏幕几乎是空的），这条会当场红；而「恒发 (0,0)」这种坏编码也过不了第二半……
//     因此额外要求光标行随输出推进过（见过不止一个不同的行号）。
func TestSurfaceDiffCarriesCursor(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c, snap := attachSurface(t, ln, "sf9", 80, 24)
	defer c.Close()

	grid := newClientGrid(t, snap) // 客户端网格（用来算「最后一行有内容的行」）

	writeTermFrame(t, c, opInput, encInputEvent(inputEvent{
		Kind: inputKindText, Text: "echo CURSOR-MARK-7\r",
	}))

	sawDiff := false
	rowsSeen := map[uint16]bool{}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		f, err := readTermFrame(c)
		if err != nil {
			break
		}
		switch f.op {
		case opSurfaceDiff:
			d := applyDiff(t, c, f, grid)
			sawDiff = true
			if d.Cursor.X > d.Geometry.Cols || d.Cursor.Y >= d.Geometry.Rows {
				t.Fatalf("差分光标越界：(%d,%d) 网格 %dx%d", d.Cursor.X, d.Cursor.Y,
					d.Geometry.Cols, d.Geometry.Rows)
			}
			last := lastContentRow(grid)
			if int(d.Cursor.Y) < last {
				t.Fatalf("差分光标在旧位置：光标行 %d < 最后有内容的行 %d（快照光标 %d,%d）"+
					"——说明发的是快照那份旧值，不是本拍",
					d.Cursor.Y, last, snap.Cursor.Y, snap.Cursor.X)
			}
			rowsSeen[d.Cursor.Y] = true
		case opSnapshot, opSnapshotDone, opState, opClipboard, opNotify:
			// 忽略（必要时快照会刷新基准）
		}
		if len(rowsSeen) >= 2 {
			break // 光标确实在推进（不是恒定值）
		}
	}
	if !sawDiff {
		t.Fatal("没收到差分帧")
	}
	if len(rowsSeen) < 2 {
		t.Fatalf("差分光标始终停在同一行（见过 %v）——3.10 要消灭的就是这个", rowsSeen)
	}
}

// lastContentRow 返回客户端网格里最后一行非空的行号（没有内容时返回 0）。
func lastContentRow(g *clientGrid) int {
	last := 0
	for i, l := range g.lines {
		if strings.TrimSpace(l) != "" {
			last = i
		}
	}
	return last
}

// 差分体编解码 roundtrip：光标块逐字段一致（wire 布局变更的最低门槛，跨仓 golden 是第二道）。
func TestSurfaceDiffBodyRoundtrip(t *testing.T) {
	in := diffBody{
		Geometry: surfaceGeometry{Cols: 80, Rows: 24, Revision: 42},
		Cursor: surfaceCursor{X: 7, Y: 3, Flags: cursorFlagVisible | cursorFlagWideTail,
			Shape: uint8(vt.CursorUnderline)},
		Rows:     []byte{0x01, 0x02, 0x03},
		RowCount: 1,
	}
	out, err := decDiffBody(encDiffBody(in))
	if err != nil {
		t.Fatalf("解差分体：%v", err)
	}
	if out.Geometry != in.Geometry || out.Cursor != in.Cursor || out.RowCount != in.RowCount ||
		string(out.Rows) != string(in.Rows) {
		t.Fatalf("差分体往返不一致：%+v vs %+v", out, in)
	}
}

// ---- 3.3 回滚：快照带回滚条 + 裁剪即强制全量 ----

// 快照必须带回滚条（total/offset/len）——客户端全靠它把镜像窗口与按需拉取锚到绝对行号空间。
//
// 两段：① 刚 attach（还没有回滚）时回滚条自洽；② 输出几拍后重取全量，镜像窗口应非空，
// 且行数不超过 offset（客户端按「镜像基址 = offset - 镜像行数」编号的前提）。
func TestSurfaceSnapshotCarriesScrollbar(t *testing.T) {
	// 用会立刻灌出回滚的 shell（tick 循环 200ms 一行，等它攒满一屏太久）。
	svc, ln := startTestTermServiceShell(t, "seq 1 200; sleep 2")
	defer svc.Close()
	defer ln.Close()
	c, snap := attachSurface(t, ln, "sf11", 80, 24)
	defer c.Close()

	checkScroll := func(tag string, s snapshotBody) {
		t.Helper()
		if s.Scroll.Total == 0 || s.Scroll.Len != 24 {
			t.Fatalf("%s：回滚条不对 total=%d offset=%d len=%d（期望 len=24）",
				tag, s.Scroll.Total, s.Scroll.Offset, s.Scroll.Len)
		}
		if s.Scroll.Offset+uint64(s.Scroll.Len) > s.Scroll.Total {
			t.Fatalf("%s：回滚条自相矛盾 offset=%d len=%d total=%d",
				tag, s.Scroll.Offset, s.Scroll.Len, s.Scroll.Total)
		}
	}
	checkScroll("attach", snap)

	// 让 shell 把 200 行灌进 vt（回滚远大于一屏），再要一次全量（此时镜像窗口应非空）。
	time.Sleep(1200 * time.Millisecond)
	writeTermFrame(t, c, opFetchSnapshot, nil)
	s2 := waitSnapshot(t, c, 5*time.Second)
	checkScroll("重取", s2)
	if s2.Scroll.Offset == 0 {
		t.Fatal("输出几拍后 offset 应 > 0（有回滚了）")
	}
	if len(s2.Mirror) == 0 {
		t.Fatal("有回滚时镜像窗口不该为空")
	}
	mcols, mrows, _, err := decodeGridLines(s2.Mirror)
	if err != nil {
		t.Fatalf("解镜像：%v", err)
	}
	if mcols != 80 {
		t.Fatalf("镜像列数应为 80，实际 %d", mcols)
	}
	if uint64(mrows) > s2.Scroll.Offset {
		t.Fatalf("镜像 %d 行 > offset %d ⇒ 基址会算成负数", mrows, s2.Scroll.Offset)
	}
	// 该会话始终贴底 ⇒ offset+len == total（客户端据此判定「跟随输出」）。
	if s2.Scroll.Offset+uint64(s2.Scroll.Len) != s2.Scroll.Total {
		t.Fatalf("贴底会话应满足 offset+len==total，实际 %d+%d vs %d",
			s2.Scroll.Offset, s2.Scroll.Len, s2.Scroll.Total)
	}
}

// 回滚裁剪检测的**规则**单测（纯函数）：total 变小 ⇒ 置 needSnapshot 并计数。
//
// 为什么只测规则、不测端到端：page 粒度裁剪在容量稳态下 total 会**持平**（探针实测：洪泛 4000 行
// 后 total 停在 455 不再下降），「total 变小」只是增长期释放整页时的瞬态，端到端要靠时序碰运气。
// 稳态下的行号滑动由**客户端的锚点探测**兜住（见客户端 surface_scroll 的单测与 design D3）。
func TestSurfaceLegNoteScrollbarTrimRule(t *testing.T) {
	leg := newSurfaceLeg()
	if leg.noteScrollbar(100) {
		t.Fatal("还没有基线时不该判定裁剪")
	}
	leg.lastSnapTotal, leg.hasSnapTotal = 100, true // 模拟「刚发过全量，基线 total=100」
	if leg.noteScrollbar(100) {
		t.Fatal("total 持平不该判定裁剪")
	}
	if leg.noteScrollbar(120) {
		t.Fatal("total 增长不该判定裁剪")
	}
	if !leg.noteScrollbar(80) {
		t.Fatal("total 变小必须判定裁剪")
	}
	if !leg.takeSnapshotFlag() {
		t.Fatal("裁剪必须置 needSnapshot（本拍就该走全量）")
	}
	if leg.statsSnapshot().trims != 1 {
		t.Fatalf("trims 计数应为 1，实际 %d", leg.statsSnapshot().trims)
	}
}

func TestSurfaceDiffAppliesToGrid(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c, snap := attachSurface(t, ln, "sf7", 80, 24)
	defer c.Close()

	// 客户端侧网格（从快照建立）。
	grid := newClientGrid(t, snap)

	// 让会话输出一行可辨认内容。
	writeTermFrame(t, c, opInput, encInputEvent(inputEvent{
		Kind: inputKindText, Text: "echo DIFF-MARK-42\r",
	}))

	// 等一个差分（期间可能有多个；逐个应用）。
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		f, err := readTermFrame(c)
		if err != nil {
			break
		}
		switch f.op {
		case opSurfaceDiff:
			d := applyDiff(t, c, f, grid)
			if d.Geometry.Revision != snap.Geometry.Revision {
				t.Errorf("差分 revision 应与快照同代（%d），实际 %d",
					snap.Geometry.Revision, d.Geometry.Revision)
			}
			if gridContains(grid, "DIFF-MARK-42") {
				return // 差分真的把新内容带过来了
			}
		case opSnapshot:
			// 服务端可能降级为全量：重建网格。
			body := surfaceReaderFrom(t, c, f)
			s, err := decSnapshotBody(body)
			if err != nil {
				t.Fatal(err)
			}
			f2 := readTermFrameT(t, c)
			if f2.op != opSnapshotDone {
				t.Fatalf("期望 SNAPSHOT-DONE，收到 0x%02x", f2.op)
			}
			grid = newClientGrid(t, s)
			snap = s
		case opState, opSnapshotDone, opClipboard, opNotify:
			// 忽略
		}
	}
	if !gridContains(grid, "DIFF-MARK-42") {
		t.Fatalf("客户端网格里没出现 DIFF-MARK-42；网格内容：%q", gridText(grid))
	}
}

// revision 断档自愈：客户端请求全量 ⇒ 服务端发新快照且 revision 推进。
func TestSurfaceFetchSnapshotAdvancesRevision(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c, snap := attachSurface(t, ln, "sf8", 80, 24)
	defer c.Close()

	writeTermFrame(t, c, opFetchSnapshot, nil)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		f, err := readTermFrame(c)
		if err != nil {
			break
		}
		switch f.op {
		case opSnapshot:
			body := surfaceReaderFrom(t, c, f)
			s, err := decSnapshotBody(body)
			if err != nil {
				t.Fatal(err)
			}
			if f2 := readTermFrameT(t, c); f2.op != opSnapshotDone {
				t.Fatalf("期望 SNAPSHOT-DONE，收到 0x%02x", f2.op)
			}
			if s.Geometry.Revision <= snap.Geometry.Revision {
				t.Errorf("请求全量后 revision 应推进：%d → %d", snap.Geometry.Revision, s.Geometry.Revision)
			}
			return
		case opSurfaceDiff, opState, opNotify:
			// 忽略中间帧
		}
	}
	t.Fatal("没收到新的全量快照")
}

// 整屏变化（滚动/清屏 + 满屏输出）**不再**降级为全量——它走「全视口行差分」。
//
// 2026-09-24 评审整改（P0）：旧实现把 `Update()==DirtyFull` 直接判为「发全量」，而滚动
// （最常见的输出形态）正是 DirtyFull ⇒ 每行输出都发带 10 视口镜像的全量快照（实测
// ≈1.4KB/行 vs ANSI ≈20B/行）。全量只留给「语义上真的需要重建」的场合。
func TestSurfaceFullScreenChangeSendsDiff(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c, _ := attachSurface(t, ln, "sf9", 80, 24)
	defer c.Close()

	// 用一条清屏 + 满屏输出的命令制造整屏变化（必然滚动 ⇒ DirtyFull）。
	writeTermFrame(t, c, opInput, encInputEvent(inputEvent{
		Kind: inputKindText, Text: "clear; for i in $(seq 1 30); do echo FILL-$i; done\r",
	}))
	deadline := time.Now().Add(5 * time.Second)
	sawDiff := false
	for time.Now().Before(deadline) && !sawDiff {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		f, err := readTermFrame(c)
		if err != nil {
			break
		}
		switch f.op {
		case opSnapshot:
			t.Fatal("整屏变化不该降级为全量（滚动走全视口行差分）——这条正是 P0 整改的判据")
		case opSurfaceDiff:
			body := surfaceReaderFrom(t, c, f)
			d, err := decDiffBody(body)
			if err != nil {
				t.Fatal(err)
			}
			if d.RowCount == 0 {
				t.Fatal("整屏变化的差分不该是空行集（rowCount=0）")
			}
			// v4：差分必须带模式位与回滚条（客户端据此更新触摸路由与绝对行号）。
			if d.Scroll.Total == 0 {
				t.Error("差分体应带回滚条（v4）")
			}
			sawDiff = true
		case opState, opNotify:
		}
	}
	if !sawDiff {
		t.Fatal("整屏变化后没收到差分")
	}
}

// 光标移动/模式位变化（无脏行）必须发帧——差分判定的**单测**（P0-1）。
//
// 为什么是单测而不是端到端：端到端要经 shell 回显，命令行的回显本身会产生脏行，
// 「空行集差分」会被行变化掩盖（实测：回显与 printf 的输出落在同一合并窗里）。
// 判定逻辑全在 SurfaceUpdate 里，这里直接钉死它。
func TestSurfaceUpdateSendsCursorAndModeChanges(t *testing.T) {
	sv, err := newSessionVT(termConfig{scrollbackLines: 1000}, 20, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer sv.Close()
	// 多腿化（2.2a）后基线在**腿**上：这里用一条真腿对账（flushSurface 的同款判定）。
	leg := newSurfaceLeg()
	sv.Write([]byte("hello"))

	// 建立基线（等价于一次全量成功入队）：消费脏状态再把屏态 commit 到腿上。
	sv.SurfaceTick()
	sv.SurfaceClean()
	leg.commitBaseline(sv.SurfaceStateNow())

	// ① 无变化 ⇒ 整拍跳过（不能空转刷帧）：会话级无脏行 + 腿基线无差异。
	enc, count, st, changed := sv.SurfaceTick()
	if changed {
		t.Fatalf("无变化不应有脏行（changed=%v）", changed)
	}
	if count != 0 || len(enc) != 0 {
		t.Fatalf("无变化不应有载荷（count=%d）", count)
	}
	if !leg.stateUnchanged(st) {
		t.Fatal("无变化时腿基线比对应判定整拍跳过")
	}

	// ② 只移动光标 ⇒ 无脏行但腿基线感知差异 ⇒ 发「空行集」差分（count=0 是合法更新）。
	sv.Write([]byte("\x1b[2D"))
	enc, count, st2, changed := sv.SurfaceTick()
	if changed {
		t.Fatal("只移光标不产生脏行（脏行由滚动/内容变化产生）")
	}
	if count != 0 || len(enc) != 0 {
		t.Fatalf("只移光标应是空行集（count=%d enc=%d）", count, len(enc))
	}
	if leg.stateUnchanged(st2) {
		t.Error("腿基线应感知光标变化（否则判据没生效）")
	}
	if st2.Cursor == st.Cursor {
		t.Error("本拍光标应与基线不同")
	}
	leg.commitBaseline(st2)

	// ③ 只开鼠标上报 ⇒ 模式位带 mouse1000（触摸路由靠它；同样不产生脏行）。
	sv.Write([]byte("\x1b[?1000h"))
	_, _, st3, _ := sv.SurfaceTick()
	if st3.Modes&termModeMouse1000 == 0 {
		t.Errorf("模式位应带 mouse1000，实际 %#x", st3.Modes)
	}
	if leg.stateUnchanged(st3) {
		t.Error("腿基线应感知模式位变化")
	}
	leg.commitBaseline(st3)

	// ④ 滚动输出（DirtyFull）⇒ 走差分（不降级），且带脏行。
	sv.Write([]byte("a\r\nb\r\nc\r\n"))
	enc4, count4, _, changed4 := sv.SurfaceTick()
	if !changed4 {
		t.Fatal("滚动输出应产生脏行——P0 整改的核心判据（DirtyFull 也走行差分）")
	}
	if count4 == 0 || len(enc4) == 0 {
		t.Fatal("滚动输出应有脏行（全视口行差分）")
	}

	// ⑤ 备用屏进出 ⇒ 腿判 Alt 与基线不符 ⇒ 该腿全量（离开时要重建主屏镜像）。
	sv.Write([]byte("\x1b[?1049h"))
	_, _, st5, _ := sv.SurfaceTick()
	if st5.Alt == leg.base.Alt {
		t.Error("进备用屏后腿的 Alt 基线判定应要求全量")
	}
}

// 备用屏进出**自己**触发全量（不是靠客户端 FETCH-SNAPSHOT 去要）。
//
// 与 TestSurfaceSnapshotAltScreenNoMirror 的分工：那条验「备用屏快照不带镜像」，
// 这条验「模式位变化（进备用屏）本身就是全量触发条件」——离开备用屏时要靠这次全量
// 重建主屏镜像（design D3 的 M4）。
//
// 用专门的 shell（读一行输入就进备用屏）：测试默认 shell 是 `cat`，敲进去的文本只会被回显、
// 不会被解释成转义序列。
func TestSurfaceAltScreenSwitchSendsSnapshot(t *testing.T) {
	svc, ln := startTestTermServiceShell(t, "read -r _l; printf '\\033[?1049h'; sleep 3")
	defer svc.Close()
	defer ln.Close()
	c, _ := attachSurface(t, ln, "sf15", 80, 24)
	defer c.Close()

	writeTermFrame(t, c, opInput, encInputEvent(inputEvent{Kind: inputKindText, Text: "go\r"}))
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		f, err := readTermFrame(c)
		if err != nil {
			break
		}
		if f.op != opSnapshot {
			continue // 回显产生的差分等中间帧
		}
		body := surfaceReaderFrom(t, c, f)
		s, err := decSnapshotBody(body)
		if err != nil {
			t.Fatal(err)
		}
		if f2 := readTermFrameT(t, c); f2.op != opSnapshotDone {
			t.Fatalf("期望 SNAPSHOT-DONE，收到 0x%02x", f2.op)
		}
		if s.Modes&termModeAltScreen == 0 {
			t.Fatalf("这次快照还没进备用屏（模式位 %#x）——进备用屏应自己触发全量", s.Modes)
		}
		return
	}
	t.Fatal("进备用屏没有自动触发全量快照")
}

// 空闲期不该出现**空行集**差分（guard 住「空转刷帧」）。
//
// 注意：测试 shell 自带 200ms ticker（有真实输出 ⇒ 合法差分），所以这里不判「完全没帧」，
// 只判「没有 count=0 的差分」——空行集差分只该由光标/模式位/回滚条变化触发。
func TestSurfaceIdleSendsNoEmptyDiff(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c, _ := attachSurface(t, ln, "sf16", 80, 24)
	defer c.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		f, err := readTermFrame(c)
		if err != nil {
			continue // 读超时/瞬时错误：还没帧
		}
		if f.op == opSurfaceDiff {
			body := surfaceReaderFrom(t, c, f)
			d, derr := decDiffBody(body)
			if derr != nil {
				t.Fatal(derr)
			}
			if d.RowCount == 0 {
				t.Fatal("空闲期出现了空行集差分（应整拍跳过）")
			}
		}
	}
}

// 分片组不被打断（P1-5 的多腿版，任务 4.3）：并发生产者入队时，一个帧组必须连续到达——
// 帧组原子性由「每腿唯一写者 + FIFO 队列」继承（旧 sendMu 的职责，design D5/B'）。
func TestSurfaceFragmentsNotInterleaved(t *testing.T) {
	conn := newSlowFirstWriteConn()
	cl := &termClient{conn: conn, out: newLegOut()}

	var wg sync.WaitGroup
	wg.Add(2)
	// A：一个「多片」快照组（第一片写出时让出，模拟慢链路）。
	go func() {
		defer wg.Done()
		cl.out.enqueueGroup([]writeItem{
			{op: opSnapshot, payload: []byte{1, 'a'}},
			{op: opSnapshot, payload: []byte{1, 'b'}},
			{op: opSnapshot, payload: []byte{0, 'c'}},
		}, perLegQueueBytes)
	}()
	// B：另一路的帧（FETCH 应答/通知/状态都走同一条队列）。
	go func() {
		defer wg.Done()
		cl.out.enqueueGroup([]writeItem{{op: opFetchRows, payload: []byte{0, 'f'}}}, perLegQueueBytes)
	}()
	wg.Wait()
	// 终止标记：写者见到它就收工（排在两组之后 ⇒ 同时验证 FIFO 不丢帧）。
	cl.out.enqueue(writeItem{op: opOK}, 0)

	done := make(chan struct{})
	go func() {
		for {
			items, _, _ := cl.out.take()
			sawEnd := false
			for _, it := range items {
				if it.op == opOK {
					sawEnd = true
					continue
				}
				if err := cl.writeFrameOnce(it.op, it.payload, termWriteTimeout); err != nil {
					t.Errorf("写帧失败：%v", err)
					return
				}
			}
			if sawEnd {
				_ = cl.conn.Close()
				close(done)
				return
			}
			if len(items) == 0 {
				<-cl.out.wake
			}
		}
	}()
	<-done

	ops := conn.ops(t)
	// A 的三片必须连续（0d 0d 0d），B 只有一片 ⇒ 合法形态只有两种：0d0d0d10 或 100d0d0d。
	joined := string(ops)
	if joined != "\x0d\x0d\x0d\x10" && joined != "\x10\x0d\x0d\x0d" {
		t.Fatalf("分片组被其它帧打断：ops=%x（应为一组连续）", ops)
	}
}

// slowFirstWriteConn 第一次写时阻塞 20ms（把「写慢」的窗口撑开），并把每帧的 op 记下来。
type slowFirstWriteConn struct {
	mu     sync.Mutex
	buf    []byte
	writes int
}

func newSlowFirstWriteConn() *slowFirstWriteConn { return &slowFirstWriteConn{} }

func (c *slowFirstWriteConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes++
	first := c.writes == 1
	c.mu.Unlock()
	if first {
		time.Sleep(20 * time.Millisecond)
	}
	c.mu.Lock()
	c.buf = append(c.buf, p...)
	c.mu.Unlock()
	return len(p), nil
}

// ops 把写下的字节流解成帧 op 序列（只读 op，跳过载荷）。
func (c *slowFirstWriteConn) ops(t *testing.T) []byte {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []byte
	for off := 0; off+3 <= len(c.buf); {
		out = append(out, c.buf[off])
		n := int(c.buf[off+1]) | int(c.buf[off+2])<<8
		off += 3 + n
	}
	return out
}

func (c *slowFirstWriteConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *slowFirstWriteConn) Close() error                     { return nil }
func (c *slowFirstWriteConn) LocalAddr() net.Addr              { return nil }
func (c *slowFirstWriteConn) RemoteAddr() net.Addr             { return nil }
func (c *slowFirstWriteConn) SetDeadline(time.Time) error      { return nil }
func (c *slowFirstWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (c *slowFirstWriteConn) SetWriteDeadline(time.Time) error { return nil }

// 大文本粘贴分帧（P0-3）：括号粘贴的 200~/201~ **只能在整个序列首尾各一次**。
//
// 客户端把 >64KiB 的粘贴拆成多帧（u16 帧长上限），若每帧都自己包一对 200~/201~，程序会把
// 一次粘贴当成多次（每次都可能触发自动提交）。所以首片带 more、末片带 cont，服务端据此
// 把开/闭各只发一次。
func TestSurfacePasteFragmentsWrapOnce(t *testing.T) {
	sv, err := newSessionVT(termConfig{scrollbackLines: 1000}, 20, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer sv.Close()
	sv.Write([]byte("\x1b[?2004h")) // 开括号粘贴模式

	var out []byte
	out = append(out, sv.EncodeInput(inputEvent{
		Kind: inputKindText, Text: "AAA", Paste: true, PasteMore: true})...)
	out = append(out, sv.EncodeInput(inputEvent{
		Kind: inputKindText, Text: "BBB", Paste: true, PasteMore: true, PasteCont: true})...)
	out = append(out, sv.EncodeInput(inputEvent{
		Kind: inputKindText, Text: "CCC", Paste: true, PasteCont: true})...)
	if want := "\x1b[200~AAABBBCCC\x1b[201~"; string(out) != want {
		t.Fatalf("分帧粘贴的包装应只在首尾各一次：\n得到 %q\n期望 %q", out, want)
	}

	// 单帧粘贴（未拆）行为不变：开+文+闭。
	if got := sv.EncodeInput(inputEvent{Kind: inputKindText, Text: "X", Paste: true}); string(got) != "\x1b[200~X\x1b[201~" {
		t.Fatalf("单帧粘贴包装变了：%q", got)
	}
	// 非粘贴文本原样。
	if got := sv.EncodeInput(inputEvent{Kind: inputKindText, Text: "Y"}); string(got) != "Y" {
		t.Fatalf("非粘贴文本不该被包装：%q", got)
	}
	// 未开括号粘贴模式：粘贴文本也原样（不包装）。
	sv2, err := newSessionVT(termConfig{scrollbackLines: 1000}, 20, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer sv2.Close()
	sv2.Write([]byte("hi"))
	if got := sv2.EncodeInput(inputEvent{Kind: inputKindText, Text: "Z", Paste: true}); string(got) != "Z" {
		t.Fatalf("未开括号粘贴模式时不该包装：%q", got)
	}
}

// 会话结束后 surfaceLoop 必须退出（P1-12：否则每建删一个会话漏一个 goroutine）。
func TestSurfaceLoopExitsOnSessionFinish(t *testing.T) {
	stop := make(chan struct{})
	sessionStop := make(chan struct{})
	ended := make(chan struct{})
	s := &termSession{
		svc:         &termService{stopCh: stop, cfg: termConfigFromEnv()},
		surfaceWake: make(chan struct{}, 1),
		clipChan:    make(chan string, 8),
		surfaceStop: sessionStop,
	}
	go func() { s.surfaceLoop(); close(ended) }()
	close(sessionStop) // finish() 的收工动作
	select {
	case <-ended:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("会话收工后 surfaceLoop 仍在跑（goroutine 泄漏）")
	}
	close(stop)
}

// ---- 2.6 RESIZE 与 FETCH-ROWS ----

func TestSurfaceResizeTriggersSnapshot(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c, snap := attachSurface(t, ln, "sf10", 80, 24)
	defer c.Close()

	writeTermFrame(t, c, opResize, encResize(100, 30))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		f, err := readTermFrame(c)
		if err != nil {
			break
		}
		switch f.op {
		case opSnapshot:
			body := surfaceReaderFrom(t, c, f)
			s, err := decSnapshotBody(body)
			if err != nil {
				t.Fatal(err)
			}
			if f2 := readTermFrameT(t, c); f2.op != opSnapshotDone {
				t.Fatalf("期望 SNAPSHOT-DONE，收到 0x%02x", f2.op)
			}
			if s.Geometry.Cols != 100 || s.Geometry.Rows != 30 {
				t.Errorf("resize 后快照几何应为 100x30，实际 %dx%d", s.Geometry.Cols, s.Geometry.Rows)
			}
			if s.Geometry.Revision <= snap.Geometry.Revision {
				t.Error("resize 触发的全量应推进 revision（隐含重置镜像基线）")
			}
			return
		case opSurfaceDiff, opState, opNotify:
		}
	}
	t.Fatal("resize 后没收到全量快照")
}

// FETCH-ROWS：先滚出足够历史，再按绝对行号拉更早的行，应答带几何与 revision。
func TestSurfaceFetchRows(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c, snap := attachSurface(t, ln, "sf11", 80, 24)
	defer c.Close()

	// 造出足够回滚。
	writeTermFrame(t, c, opInput, encInputEvent(inputEvent{
		Kind: inputKindText, Text: "for i in $(seq 1 80); do echo HIST-$i; done\r",
	}))
	time.Sleep(600 * time.Millisecond)

	writeTermFrame(t, c, opFetchRows, encFetchRowsReq(fetchRowsReq{From: 0, Count: 10}))
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		f, err := readTermFrame(c)
		if err != nil {
			break
		}
		if f.op != opFetchRows {
			continue
		}
		body := surfaceReaderFrom(t, c, f)
		reply, err := decFetchRowsReply(body)
		if err != nil {
			t.Fatalf("解 FETCH-ROWS 应答：%v", err)
		}
		if reply.Geometry.Cols != 80 || reply.Geometry.Rows != 24 {
			t.Errorf("应答应带几何，实际 %dx%d", reply.Geometry.Cols, reply.Geometry.Rows)
		}
		if reply.Geometry.Revision == 0 {
			t.Error("应答应带 revision（客户端据此丢弃过期应答）")
		}
		if reply.From != 0 || reply.Count != 10 {
			t.Errorf("应答应回显请求区间，实际 from=%d count=%d", reply.From, reply.Count)
		}
		rows, err := decodeRowsOf(t, reply.Rows, int(reply.Count), 80)
		if err != nil {
			t.Fatalf("解行：%v", err)
		}
		if len(rows) == 0 {
			t.Error("应取到行")
		}
		if snap.Geometry.Revision == 0 {
			t.Error("快照 revision 不该为 0")
		}
		return
	}
	t.Fatal("没收到 FETCH-ROWS 应答")
}

// ---- 2.7 INPUT / NOTIFY ----

// INPUT：键/文本上行被服务端按真实模式编码后写进 PTY（用回显验证）。
func TestSurfaceInputReachesPTY(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c, snap := attachSurface(t, ln, "sf12", 80, 24)
	defer c.Close()
	grid := newClientGrid(t, snap)

	writeTermFrame(t, c, opInput, encInputEvent(inputEvent{
		Kind: inputKindText, Text: "echo INPUT-OK-7\r",
	}))
	// 回显经差分/全量回来；用**解码后的网格**判据（分片里的 gzip 字节当然搜不到明文）。
	if waitGridText(t, c, grid, "INPUT-OK-7") {
		return
	}
	t.Fatalf("INPUT 上行没有在 PTY 里生效；网格内容：%q", gridText(grid))
}

// 没开鼠标上报时，鼠标事件不该往 PTY 写垃圾字节。
func TestSurfaceInputMouseIgnoredWithoutMode(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c, snap := attachSurface(t, ln, "sf13", 80, 24)
	defer c.Close()
	grid := newClientGrid(t, snap)

	// 会话没开鼠标上报：先发鼠标事件（应被编码器判为「无输出」），再发可辨认文本。
	writeTermFrame(t, c, opInput, encInputEvent(inputEvent{
		Kind: inputKindMouse, Action: 0, Button: 1, X: 5, Y: 3,
	}))
	writeTermFrame(t, c, opInput, encInputEvent(inputEvent{Kind: inputKindText, Text: "echo MOUSE-SAFE\r"}))
	if waitGridText(t, c, grid, "MOUSE-SAFE") {
		return
	}
	t.Fatalf("鼠标事件干扰了后续输入；网格内容：%q", gridText(grid))
}

// 裸 OSC 9 通知经 NOTIFY 帧转发到客户端。
func TestSurfaceNotifyForwarded(t *testing.T) {
	svc, ln := startTestTermServiceShell(t, "read -r _l; printf '\\033]9;NOTIFY-ME\\007'; sleep 2")
	defer svc.Close()
	defer ln.Close()
	c, _ := attachSurface(t, ln, "sf14", 80, 24)
	defer c.Close()

	writeTermFrame(t, c, opInput, encInputEvent(inputEvent{Kind: inputKindText, Text: "go\r"}))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		f, err := readTermFrame(c)
		if err != nil {
			break
		}
		if f.op != opNotify {
			continue
		}
		text, derr := decNotify(f.payload)
		if derr != nil {
			t.Fatalf("解 NOTIFY：%v", derr)
		}
		if text != "NOTIFY-ME" {
			t.Errorf("通知文本应为 NOTIFY-ME，实际 %q", text)
		}
		return
	}
	t.Fatal("没收到 NOTIFY 帧")
}

// OSC 9;4（progress）**不该**被当成通知转发（双语义判别）。
func TestSurfaceProgressNotForwardedAsNotify(t *testing.T) {
	svc, ln := startTestTermServiceShell(t, "read -r _l; printf '\\033]9;4;1;50\\007'; sleep 2")
	defer svc.Close()
	defer ln.Close()
	c, _ := attachSurface(t, ln, "sf15", 80, 24)
	defer c.Close()

	writeTermFrame(t, c, opInput, encInputEvent(inputEvent{Kind: inputKindText, Text: "go\r"}))
	// 给足时间让 progress 到达并被扫描器判别；这期间**不该**出现 NOTIFY 帧。
	deadline := time.Now().Add(2500 * time.Millisecond)
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
		f, err := readTermFrame(c)
		if err != nil {
			continue
		}
		if f.op == opNotify {
			text, _ := decNotify(f.payload)
			t.Fatalf("9;4 progress 不该走通知通道，收到 NOTIFY %q", text)
		}
	}
}

// ---- 多腿语义（term-host-cli 任务 2.1a/2.3；单腿顶替已退役）----

// 正常接入**不**顶掉旧腿：两条 surface 腿同时在场、各自收快照，旧腿不收 ENDED。
func TestSurfaceMultiLegCoexist(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c1, _ := attachSurface(t, ln, "sf16", 80, 24)
	defer c1.Close()

	c2, snap2 := attachSurface(t, ln, "sf16", 80, 24)
	defer c2.Close()
	if snap2.Geometry.Cols != 80 {
		t.Errorf("第二条腿应正常拿到快照（%dx%d）", snap2.Geometry.Cols, snap2.Geometry.Rows)
	}

	// 旧腿在窗口期内**不该**收到 ENDED（正常接入不顶腿）；也不该断流。
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		_ = c1.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
		f, err := readTermFrame(c1)
		if err != nil {
			break // 窗口内无帧（会话安静）：合法——重点是没收到 ENDED
		}
		if f.op == opEnded {
			t.Fatal("正常接入不该顶掉旧腿（收到 ENDED）")
		}
	}

	// LIST：attached 为真 + clients 记两条腿（kind=app）。
	list := listTerm(t, ln)
	sess, ok := listSession(list, "sf16")
	if !ok {
		t.Fatal("会话不在列表里")
	}
	clients, _ := sess["clients"].([]any)
	if len(clients) != 2 {
		t.Fatalf("clients 应记 2 条腿，实际 %d（%v）", len(clients), sess["clients"])
	}
	for _, it := range clients {
		m, _ := it.(map[string]any)
		if m["kind"] != "app" {
			t.Errorf("surface 腿 kind 应为 app，实际 %v", m["kind"])
		}
		if _, ok := m["sinceMs"]; !ok {
			t.Error("clients 条目应有 sinceMs 字段")
		}
	}
}

// 显式接管（HELLO flags bit2 = `attach -d`）：其它腿收 ENDED(code=-1, reason=replaced)。
func TestSurfaceTakeoverReplaces(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c1, _ := attachSurface(t, ln, "sf17", 80, 24)
	defer c1.Close()

	c2 := dialTerm(t, ln)
	defer c2.Close()
	if f := readTermFrameT(t, c2); f.op != opGreeting {
		t.Fatal("首帧应为 GREETING")
	}
	// HELLO flags = create|takeover（bit0|bit2）+ capability（surface）。
	hello := encHello(80, 24, true, "sf17")
	hello[4] = helloFlagCreate | helloFlagTakeover
	hello = append(hello, encCapability(capsSurface)...)
	writeTermFrame(t, c2, opHello, hello)
	if f := readTermFrameT(t, c2); f.op != opAttached {
		t.Fatalf("接管腿应收到 ATTACHED，收到 0x%02x", f.op)
	}

	f := readTermFrameT(t, c1)
	for f.op == opSnapshot || f.op == opSurfaceDiff || f.op == opState || f.op == opNotify {
		f = readTermFrameT(t, c1) // 跳过在飞帧
	}
	if f.op != opEnded {
		t.Fatalf("被接管的腿应收 ENDED，收到 0x%02x", f.op)
	}
	code := int32(binary.LittleEndian.Uint32(f.payload[0:4]))
	if code != termEndReplaced {
		t.Errorf("ENDED code = %d，期望 %d", code, termEndReplaced)
	}
	if reason := string(f.payload[5:]); reason != "replaced" {
		t.Errorf("ENDED reason = %q，期望 replaced（D8 词表）", reason)
	}
}

// 同实例标识重连替换自身旧腿（任务 2.3）：旧腿收 ENDED(self_reconnect)，其它腿不受影响。
func TestSurfaceSelfReconnectReplaces(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	// 腿 A：带标识 id-1。
	c1 := dialTerm(t, ln)
	defer c1.Close()
	readTermFrameT(t, c1)
	hello := append(encHello(80, 24, true, "sf18"), encHelloTail(capsSurface, true, "id-1")...)
	writeTermFrame(t, c1, opHello, hello)
	if f := readTermFrameT(t, c1); f.op != opAttached {
		t.Fatalf("腿 A 应收到 ATTACHED，收到 0x%02x", f.op)
	}
	// 腿 B：无标识（别的客户端），应不受影响。
	c2 := dialTerm(t, ln)
	defer c2.Close()
	readTermFrameT(t, c2)
	writeTermFrame(t, c2, opHello, append(encHello(80, 24, true, "sf18"), encCapability(capsSurface)...))
	if f := readTermFrameT(t, c2); f.op != opAttached {
		t.Fatalf("腿 B 应收到 ATTACHED，收到 0x%02x", f.op)
	}

	// 腿 A'：同标识 id-1 重连 ⇒ 旧腿 A 收 ENDED(self_reconnect)、腿 B 不收。
	c3 := dialTerm(t, ln)
	defer c3.Close()
	readTermFrameT(t, c3)
	writeTermFrame(t, c3, opHello, append(encHello(80, 24, true, "sf18"), encHelloTail(capsSurface, true, "id-1")...))
	if f := readTermFrameT(t, c3); f.op != opAttached {
		t.Fatalf("重连腿应收到 ATTACHED，收到 0x%02x", f.op)
	}

	f := readTermFrameT(t, c1)
	for f.op == opSnapshot || f.op == opSurfaceDiff || f.op == opState || f.op == opNotify {
		f = readTermFrameT(t, c1)
	}
	if f.op != opEnded {
		t.Fatalf("被替换的旧腿应收 ENDED，收到 0x%02x", f.op)
	}
	code := int32(binary.LittleEndian.Uint32(f.payload[0:4]))
	reason := string(f.payload[5:])
	if code != termEndReplaced || reason != "self_reconnect" {
		t.Errorf("ENDED = (%d, %q)，期望 (%d, self_reconnect)", code, reason, termEndReplaced)
	}
	// 腿 B 不受影响：窗口期内不收 ENDED。
	_ = c2.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))
	for {
		f, err := readTermFrame(c2)
		if err != nil {
			break
		}
		if f.op == opEnded {
			t.Fatal("其它腿不该受同实例替换影响（收到 ENDED）")
		}
	}
}

// ---- 2.5 背压的单元判据 ----

func TestSurfaceLegBackpressureFlags(t *testing.T) {
	leg := newSurfaceLeg()
	if !leg.takeSnapshotFlag() {
		t.Fatal("新腿应标记需要全量（首次 attach 必须发快照）")
	}
	if leg.takeSnapshotFlag() {
		t.Fatal("takeSnapshotFlag 应清除标记")
	}
	leg.markNeedSnapshot("backpressure")
	if !leg.takeSnapshotFlag() {
		t.Fatal("背压应标记需要全量")
	}
	if got := leg.statsSnapshot(); got.backpressure != 1 {
		t.Errorf("背压事件应计数，实际 %d", got.backpressure)
	}
	// 写耗时超合并窗 ⇒ 视为有压力（下一拍走全量）。
	leg.noteWriteCost(surfaceMergeWindowMax + time.Millisecond)
	if !leg.underPressure() {
		t.Error("写耗时超合并窗应判定有压力")
	}
	leg.noteWriteCost(time.Millisecond)
	if leg.underPressure() {
		t.Error("写很快时不该判定有压力")
	}
	// revision 单调推进。
	r1 := leg.nextRevision()
	r2 := leg.nextRevision()
	if r2 != r1+1 {
		t.Errorf("revision 应单调 +1：%d → %d", r1, r2)
	}
	if leg.currentRevision() != r2 {
		t.Error("currentRevision 应等于最后一次推进的值")
	}
}

// TestSurfaceWriterReportsWriteCost FIX-28 接线：surface 写者把每帧写耗时上报给腿
// （此前 noteWriteCost 无生产调用 ⇒ underPressure 恒 false，背压安全网空转）。
// 变异红路：删 runSurfaceWriter 里的 noteWriteCost 调用 ⇒ 本用例超时红。
func TestSurfaceWriterReportsWriteCost(t *testing.T) {
	leg := newSurfaceLeg()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	c := &termClient{conn: server, leg: leg, surface: true, out: newLegOut()}
	s := &termSession{}
	go s.runSurfaceWriter(c)
	// pipe 无缓冲：读端故意延迟超过合并窗，让写阻塞出「链路有压力」的耗时。
	go func() {
		time.Sleep(surfaceMergeWindowMax + 30*time.Millisecond)
		buf := make([]byte, 4096)
		for i := 0; i < 8; i++ {
			if _, err := client.Read(buf); err != nil {
				return
			}
		}
	}()
	if !c.out.enqueue(writeItem{op: opSnapshot, payload: []byte("frame")}, 0) {
		t.Fatal("入队失败")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if leg.underPressure() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("写耗时未上报：noteWriteCost 未接线（underPressure 恒 false）")
}

// ---- 上行帧编解码的纯函数 roundtrip（2.10）----
//
// 这一组是「便宜但关键」的：上面那些端到端判据一旦因为编解码错位失败，症状会是
// 「输入没生效」这种离根因很远的现象（实测踩过：encInputEvent 少写一个种类字节，
// 解码侧报的却是「载荷截断」）。
func TestSurfacePayloadRoundTrip(t *testing.T) {
	events := []inputEvent{
		{Kind: inputKindKey, Key: 0x1234, Mods: 0x0005, Action: 2, Text: "a"},
		{Kind: inputKindKey, Key: 1, Action: 0},
		{Kind: inputKindText, Text: "中文输入", Paste: true},
		{Kind: inputKindText, Text: ""},
		{Kind: inputKindMouse, Action: 1, Button: 3, Mods: 0x0002, X: 40, Y: 12},
		{Kind: inputKindFocus, Gained: true},
		{Kind: inputKindFocus},
	}
	for i, ev := range events {
		enc := encInputEvent(ev)
		if len(enc) == 0 {
			t.Fatalf("第 %d 个事件编码为空", i)
		}
		if enc[0] != ev.Kind {
			t.Fatalf("第 %d 个事件首字节应是种类 %d，实际 %d", i, ev.Kind, enc[0])
		}
		back, err := decInputEvent(enc)
		if err != nil {
			t.Fatalf("第 %d 个事件解码失败：%v", i, err)
		}
		if back != ev {
			t.Errorf("第 %d 个事件往返不一致：\n原 %+v\n解 %+v", i, ev, back)
		}
	}

	fg, bg := [3]uint8{1, 2, 3}, [3]uint8{4, 5, 6}
	encT := encTheme(fg, bg, true)
	dfg, dbg, dark, err := decTheme(encT)
	if err != nil || dfg != fg || dbg != bg || !dark {
		t.Errorf("THEME 往返不一致：%v %v %v %v", dfg, dbg, dark, err)
	}

	for _, text := range []string{"", "hello", strings.Repeat("x", 300)} {
		kind, got, err := decClipboard(encClipboard(clipKindReadAnswer, text))
		if err != nil || kind != clipKindReadAnswer || got != text {
			t.Errorf("CLIPBOARD 往返不一致（len %d）：%v %v", len(text), err, len(got))
		}
		if back, err := decClipboardAnswer(encClipboard(clipKindReadAnswer, text)); err != nil || back != text {
			t.Errorf("读应答往返不一致：%v", err)
		}
	}

	for _, text := range []string{"", "通知内容"} {
		back, err := decNotify(encNotify(text))
		if err != nil || back != text {
			t.Errorf("NOTIFY 往返不一致：%v %q", err, back)
		}
	}

	for _, req := range []fetchRowsReq{{From: 0, Count: 1}, {From: 1 << 40, Count: 512}} {
		back, err := decFetchRowsReq(encFetchRowsReq(req))
		if err != nil || back != req {
			t.Errorf("FETCH-ROWS 请求往返不一致：%+v %v", back, err)
		}
	}

	// 经 encHelloTail 组整段尾随（0xff 含 capsProtoVer 声明位 ⇒ 版本字节必须一起产出；
	// 单块 encCapability 不带版本字节，是「声明位在而字节缺」的畸形形态——见 TestHelloTailShape）。
	for _, caps := range []byte{0, capsSurface, 0xff} {
		c, present, _, ver, verPresent, err := decHelloTail(encHelloTail(caps, true, ""))
		if err != nil || !present || c != caps {
			t.Errorf("capability 往返不一致：%d %v %v", c, present, err)
		}
		if wantVer := caps&capsProtoVer != 0; verPresent != wantVer || (wantVer && ver != termProtoVer) {
			t.Errorf("caps=0x%02x 版本字节形态不对：present=%v ver=%d", caps, verPresent, ver)
		}
	}
	// encCapability 单独一块（不带版本字节）语义不变：不带声明位时照常解析。
	if c, present, _, _, verPresent, err := decHelloTail(encCapability(capsSurface)); err != nil || !present || c != capsSurface || verPresent {
		t.Errorf("capsSurface 单块应照常解析：%v %v %#x present=%v", err, present, c, verPresent)
	}
	if _, present, _, _, _, err := decHelloTail(nil); err != nil || present {
		t.Errorf("无尾随字节应是「不携带」而不是错误：%v %v", present, err)
	}
}

// OSC 52 剪贴板写：程序写剪贴板的动作经 CLIPBOARD 帧转给客户端（任务 2.7）。
func TestSurfaceClipboardWriteForwarded(t *testing.T) {
	// 程序用 OSC 52 写剪贴板（base64 的 "hello" = aGVsbG8=）。
	svc, ln := startTestTermServiceShell(t,
		"read -r _l; printf '\\033]52;c;aGVsbG8=\\007'; sleep 2")
	defer svc.Close()
	defer ln.Close()
	c, _ := attachSurface(t, ln, "sf17", 80, 24)
	defer c.Close()

	writeTermFrame(t, c, opInput, encInputEvent(inputEvent{Kind: inputKindText, Text: "go\r"}))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		f, err := readTermFrame(c)
		if err != nil {
			break
		}
		if f.op != opClipboard {
			continue
		}
		kind, text, derr := decClipboard(f.payload)
		if derr != nil {
			t.Fatalf("解 CLIPBOARD：%v", derr)
		}
		if kind != clipKindWrite {
			t.Errorf("S→C 剪贴板帧应是写请求，实际 kind=%d", kind)
		}
		if text != "hello" {
			t.Errorf("内容应为 aGVsbG8= 解出的 hello，实际 %q", text)
		}
		return
	}
	t.Fatal("没收到 CLIPBOARD 帧（OSC 52 没被转发）")
}

// TestEncClipboardLargeTextLengthExact FIX-27：剪贴板内容上限取 termMaxPayload-3，
// 长度字段（u16）恒精确。旧上限 256KiB 时 uint16(65536)=0 会回绕，且帧编码器按
// termMaxPayload 截 payload 把文本尾巴切掉 ⇒ 64KiB–256KiB 区间静默写坏。
// 变异红路：把 clipMaxBytes 改回 256<<10 ⇒ 本用例红（长度回绕 + 载荷超上限）。
func TestEncClipboardLargeTextLengthExact(t *testing.T) {
	big := strings.Repeat("x", 100<<10) // 100KiB：旧上限下长度字段回绕
	p := encClipboard(clipKindWrite, big)
	if len(p) > termMaxPayload {
		t.Fatalf("载荷超帧上限：%d > %d", len(p), termMaxPayload)
	}
	if got := int(binary.LittleEndian.Uint16(p[1:3])); got != len(p)-3 {
		t.Fatalf("长度字段应等于文本字节数：字段=%d 实际=%d（回绕即红）", got, len(p)-3)
	}
	if len(p)-3 != clipMaxBytes {
		t.Fatalf("超长文本应截到 clipMaxBytes=%d，实得 %d", clipMaxBytes, len(p)-3)
	}
	small := strings.Repeat("y", 1024)
	if ps := encClipboard(clipKindWrite, small); int(binary.LittleEndian.Uint16(ps[1:3])) != len(small) {
		t.Fatal("未超限文本不应被截")
	}
}
