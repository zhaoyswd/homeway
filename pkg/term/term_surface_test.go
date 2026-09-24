//go:build !windows

// term_surface_test.go — surface 协议的服务端判据（任务 2.1–2.7、2.10）。
//
// 测试是**端到端**的：真起 PTY 会话、真走帧协议，客户端侧用 Go 复刻（攒分片 → 解压 → 解体 →
// 应用 patch），断言客户端最终网格与服务端视口一致。这正是任务 2.10 要的那些判据：
// 编解码 roundtrip、分片重组、revision 断档自愈、差分自适应降级、背压降级、备用屏抑制、
// 单腿顶替语义。
package term

import (
	"encoding/binary"
	"strings"
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

// 整屏变化 ⇒ 自动降级为全量（差分自限）。
func TestSurfaceDiffDegradesOnFullScreenChange(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c, _ := attachSurface(t, ln, "sf9", 80, 24)
	defer c.Close()

	// 用一条清屏 + 满屏输出的命令制造整屏变化。
	writeTermFrame(t, c, opInput, encInputEvent(inputEvent{
		Kind: inputKindText, Text: "clear; for i in $(seq 1 30); do echo FILL-$i; done\r",
	}))
	deadline := time.Now().Add(5 * time.Second)
	sawSnapshot := false
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		f, err := readTermFrame(c)
		if err != nil {
			break
		}
		switch f.op {
		case opSnapshot:
			body := surfaceReaderFrom(t, c, f)
			if _, err := decSnapshotBody(body); err != nil {
				t.Fatal(err)
			}
			if f2 := readTermFrameT(t, c); f2.op != opSnapshotDone {
				t.Fatalf("期望 SNAPSHOT-DONE，收到 0x%02x", f2.op)
			}
			sawSnapshot = true
		case opSurfaceDiff, opState, opNotify:
		}
		if sawSnapshot {
			break
		}
	}
	if !sawSnapshot {
		t.Error("整屏变化应触发全量降级（差分自限）")
	}
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

// ---- 2.10 单腿顶替语义 ----

func TestSurfaceSingleLegReplacement(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c1, _ := attachSurface(t, ln, "sf16", 80, 24)
	defer c1.Close()

	// 第二条 surface 腿 attach 同一会话 ⇒ 旧腿收 ENDED(replaced)。
	c2, _ := attachSurface(t, ln, "sf16", 80, 24)
	defer c2.Close()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_ = c1.SetReadDeadline(time.Now().Add(2 * time.Second))
		f, err := readTermFrame(c1)
		if err != nil {
			break
		}
		if f.op == opEnded {
			code := int32(binary.LittleEndian.Uint32(f.payload[0:4]))
			if code != termEndReplaced {
				t.Errorf("旧腿应收到 ENDED(replaced)=%d，实际 %d", termEndReplaced, code)
			}
			return
		}
	}
	t.Fatal("旧腿没收到 ENDED(replaced)")
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

	for _, caps := range []byte{0, capsSurface, 0xff} {
		c, present, err := decCapability(encCapability(caps))
		if err != nil || !present || c != caps {
			t.Errorf("capability 往返不一致：%d %v %v", c, present, err)
		}
	}
	if _, present, err := decCapability(nil); err != nil || present {
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
