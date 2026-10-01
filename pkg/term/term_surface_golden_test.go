//go:build !windows && (darwin || linux) && (amd64 || arm64) && cgo

// term_surface_golden_test.go — 任务 2.8 的**跨仓 golden fixture**（生成半边）。
//
// 目的：surface 的字节布局在**多处**各有一份实现（出口 Go 的 term_surface.go + cellcodec.go、
// 客户端的 surface_codec.cpp、App 核的帧子集）——新增 op 会放大漂移风险。这里生成一组**共享样例**
// （每个 op 一例），两端各自解码并断言同一份结果。
//
// 产物（提交在本仓 surface/test/golden；宿主测试 surface/test/host 读它）：
//
//	surface/test/golden/manifest.tsv   name<TAB>op<TAB>cols<TAB>rows<TAB>revision<TAB>digest<TAB>title
//	surface/test/golden/<name>.bin     分片序列：[u32 片数]{[u32 长度][字节]}…
//
// 生成：go test ./pkg/term/ -run TestSurfaceGolden -update
// 校验：同命令（不带 -update）——服务端先自解一遍；客户端在宿主上再解一遍（两边同一份文件）。
//
// 摘要口径（两端必须逐字节一致）：FNV-1a 64 of「行以 \n 连接、占位格跳过、空符号补空格、行尾裁空白」。
package term

import (
	"encoding/binary"
	"flag"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zhaoyswd/homeway/pkg/term/vt"
)

// updateGolden 由 `go test ./pkg/term/ -update` 置位（go test 只接受注册过的自定义 flag）。
var updateGolden = flag.Bool("update", false, "重新生成 golden 样例（跨仓共享）")

// goldenDir 样例目录（surface 迁入本仓后不再跨仓取 tier 检出）：go test 的工作目录是包目录
// pkg/term，同仓相对路径在任何机器上都成立（原先按 TIER_REPO 指私有仓 + 硬编码本机默认，
// 换机器会静默 SKIP——迁移收掉）。注意要退两级：pkg/term → pkg → 仓库根。
func goldenDir(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "surface", "test", "golden")
}

// goldenDigest 与客户端 C++ 的 digestText 同一算法（改一处必须同步改另一处——这正是被钉住的东西）。
func goldenDigest(text string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(text))
	return fmt.Sprintf("%016x", h.Sum64())
}

// goldenStyleText 样式向量的规范文本（FIX-30）：逐行逐格，每格固定 26 个十六进制字符
// （fg 5B · bg 5B · attr 2B · flags 1B），行尾 \n。客户端 C++ 侧逐字段实现同一口径
// （surface_golden_test.cpp 的 styleDigest）。
//
// 为什么要有它：原摘要只吃**文本**，cell 的颜色/属性/模式位布局两端各写一遍却谁都没断言——
// 位序漂移（如 attr bit5 语义错位、palette/RGB kind 值错位）在两端各自的自测里都看不出来。
// 样式向量与 modes 列把「同一份字节、两端解出的样式」也钉住。
//
// flags = skip(bit0) | width<<1——宽度也要钉（宽字符占位格语义错位会直接画错）。
func goldenStyleText(rows []vt.Row, cols uint16) string {
	var b strings.Builder
	for _, r := range rows {
		for x := uint16(0); x < cols; x++ {
			c := vt.Cell{Width: 1} // 缺格按空白格（与服务端编码的 blankRun 语义一致）
			if int(x) < len(r.Cells) {
				c = r.Cells[x]
			}
			var flags byte
			if c.Skip {
				flags |= 1
			}
			flags |= c.Width << 1
			fmt.Fprintf(&b, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%04x%02x",
				c.FG.Kind, c.FG.Index, c.FG.R, c.FG.G, c.FG.B,
				c.BG.Kind, c.BG.Index, c.BG.R, c.BG.G, c.BG.B,
				c.Attr, flags)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// gridTextLines 从网格块取出「toText 口径」的文本（客户端 CellGrid::toText 的等价实现）。
func gridTextLines(t *testing.T, blob []byte) (uint16, uint16, string) {
	t.Helper()
	cols, rows, lines, err := decodeGridLines(blob)
	if err != nil {
		t.Fatalf("解网格：%v", err)
	}
	return cols, rows, strings.Join(lines, "\n")
}

// goldenFrame 一帧样例：op + 该帧的分片序列。
type goldenFrame struct {
	op     byte
	chunks [][]byte
}

// writeGoldenSample 写「帧序列」样例文件：一个样例可以含多帧（如 快照 + 差分），
// 客户端按序喂给状态机，比对**最终**网格与光标——这样 DIFF/FETCH-ROWS 这些「作用于前序状态」的
// 帧才有可验证的落点（单帧差分没法独立断言）。光标（任务 3.10）单列，是为了让「差分带的光标」
// 也被跨仓钉住：样例文本相同而光标错位，是这类实现最容易漂的一种。
func writeGoldenSample(t *testing.T, dir, name string, frames []goldenFrame, cols, rows uint16,
	rev uint32, digest, title string, cursor surfaceCursor, sb vt.Scrollbar,
	styleDigest string, modes uint32) {
	t.Helper()
	if len(frames) == 0 {
		t.Fatal("样例至少要有一帧")
	}
	var blob []byte
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(len(frames)))
	blob = append(blob, hdr[:]...)
	for _, fr := range frames {
		blob = append(blob, fr.op)
		binary.LittleEndian.PutUint32(hdr[:], uint32(len(fr.chunks)))
		blob = append(blob, hdr[:]...)
		for _, ch := range fr.chunks {
			binary.LittleEndian.PutUint32(hdr[:], uint32(len(ch)))
			blob = append(blob, hdr[:]...)
			blob = append(blob, ch...)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, name+".bin"), blob, 0o644); err != nil {
		t.Fatal(err)
	}
	// 列序：…回滚条 3 列（任务 3.3）→ 样式向量摘要 + 模式位（FIX-30 追加在**末两列**，
	// 既有列位不动——台账/对拍脚本按位置读）。
	line := fmt.Sprintf("%s\t0x%02x\t%d\t%d\t%d\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%d\n",
		name, frames[0].op, cols, rows, rev, digest, title, len(frames),
		cursor.X, cursor.Y, cursor.Flags, cursor.Shape,
		sb.Total, sb.Offset, sb.Len,
		styleDigest, modes)
	f, err := os.OpenFile(filepath.Join(dir, "manifest.tsv"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		t.Fatal(err)
	}
}

// readGoldenManifest 读 manifest（name → 各列）。
func readGoldenManifest(t *testing.T, dir string) map[string][]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "manifest.tsv"))
	if err != nil {
		t.Skipf("还没有 golden 样例（先带 -update 生成一次）：%v", err)
	}
	out := map[string][]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 6 {
			t.Fatalf("manifest 行格式不对：%q", line)
		}
		out[f[0]] = f
	}
	return out
}

// TestSurfaceGolden：生成（-update）或校验（默认）共享样例。
//
// 样例**离线**从真实会话字节夹具生成（`pkg/term/vt/testdata/session-*.bin`，见任务 1.2）：
// 走我们的 vt（真仿真器）拿到网格，再用服务端同一套编码器封成 SNAPSHOT——**不依赖 PTY 会话**，
// 所以生成/校验都是确定性的、没有收尾时序问题。真实内容覆盖了漂移最爱死的地方
// （宽字符占位格、调色板索引、gzip 分片边界）。
func TestSurfaceGolden(t *testing.T) {
	update := *updateGolden
	dir := goldenDir(t)
	if update {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		_ = os.Remove(filepath.Join(dir, "manifest.tsv"))
	}
	var manifest map[string][]string
	if !update {
		// 生成模式下**不能**读 manifest：还没有它（读会 Skip 掉整个测试）。
		manifest = readGoldenManifest(t, dir)
	}

	fixtures := []goldenSource{
		{key: "session-cjk", file: "session-cjk.bin"},
		{key: "session-git-log", file: "session-git-log.bin"},
		{key: "session-hexdump", file: "session-hexdump.bin"},
		// 样式专项夹具（FIX-30）：录制夹具没人保证覆盖到颜色/属性/模式位，这份内联序列把它们
		// 全点亮（SGR 属性、256 色、真彩、鼠标上报模式、括号粘贴），样式向量与 modes 列一并钉。
		{key: "session-styles", data: goldenStylesSession()},
	}
	for _, src := range fixtures {
		key := src.key
		var data []byte
		if src.file != "" {
			var err error
			data, err = os.ReadFile(filepath.Join("vt", "testdata", src.file))
			if err != nil {
				t.Skipf("没有夹具 %s：%v", src.file, err)
			}
		} else {
			data = src.data
		}
		snapFrames, diffFrames, sample := buildGoldenSamples(t, key, data)
		if update {
			writeGoldenSample(t, dir, key, snapFrames,
				sample.cols, sample.rows, sample.rev, sample.snapDigest, sample.title, sample.snapCursor,
				sample.snapScroll, sample.snapStyle, sample.snapModes)
			writeGoldenSample(t, dir, key+"-diff", diffFrames,
				sample.cols, sample.rows, sample.rev, sample.diffDigest, sample.title, sample.diffCursor,
				sample.diffScroll, sample.diffStyle, sample.diffModes)
			t.Logf("%s：快照 %s/%s 差分后 %s/%s（%dx%d rev=%d 光标 %d,%d → %d,%d modes=%#x→%#x）",
				key, sample.snapDigest, sample.snapStyle, sample.diffDigest, sample.diffStyle,
				sample.cols, sample.rows, sample.rev,
				sample.snapCursor.X, sample.snapCursor.Y, sample.diffCursor.X, sample.diffCursor.Y,
				sample.snapModes, sample.diffModes)
			continue
		}
		for _, c := range []struct {
			key, want, style string
			modes            uint32
			cursor           surfaceCursor
			scroll           vt.Scrollbar
		}{
			{key, sample.snapDigest, sample.snapStyle, sample.snapModes, sample.snapCursor, sample.snapScroll},
			{key + "-diff", sample.diffDigest, sample.diffStyle, sample.diffModes, sample.diffCursor, sample.diffScroll},
		} {
			row, ok := manifest[c.key]
			if !ok {
				t.Fatalf("manifest 里没有 %s 样例（先 -update 生成）", c.key)
			}
			if row[5] != c.want {
				t.Errorf("%s：出口侧解码与 golden 不一致：got %s want %s（两端实现漂移了？）",
					c.key, c.want, row[5])
			}
			// 光标列（任务 3.10）：样例里的光标必须与出口侧同拍一致——这是「差分带的光标
			// 到底对不对」的跨仓判据（客户端那侧再对同一份文件断言一次）。
			if len(row) >= 12 {
				got := row[8] + "," + row[9] + "," + row[10] + "," + row[11]
				want := fmt.Sprintf("%d,%d,%d,%d", c.cursor.X, c.cursor.Y, c.cursor.Flags, c.cursor.Shape)
				if got != want {
					t.Errorf("%s：golden 光标列与出口侧不一致：got %s want %s", c.key, got, want)
				}
			}
			if len(row) >= 15 {
				got := row[12] + "," + row[13] + "," + row[14]
				want := fmt.Sprintf("%d,%d,%d", c.scroll.Total, c.scroll.Offset, c.scroll.Len)
				if got != want {
					t.Errorf("%s：golden 回滚条列与出口侧不一致：got %s want %s", c.key, got, want)
				}
			}
			// 样式向量 + 模式位列（FIX-30）：客户端解同一份字节后的每格 fg/bg/attr/宽度与
			// 模式位必须与出口侧同拍一致——颜色/属性/模式位布局漂移自此有跨仓判据。
			if len(row) >= 17 {
				if row[15] != c.style {
					t.Errorf("%s：golden 样式向量列与出口侧不一致：got %s want %s", c.key, row[15], c.style)
				}
				if want := fmt.Sprintf("%d", c.modes); row[16] != want {
					t.Errorf("%s：golden 模式位列与出口侧不一致：got %s want %s", c.key, row[16], want)
				}
			} else {
				t.Fatalf("%s：manifest 缺样式向量/模式位列（先 -update 重生成）", c.key)
			}
		}
	}
}

type goldenSample struct {
	cols, rows uint16
	rev        uint32
	title      string
	snapDigest string
	diffDigest string
	// 样式向量摘要与模式位（FIX-30）：文本摘要之外，颜色/属性/宽度与模式位也跨仓钉住。
	snapStyle, diffStyle string
	snapModes, diffModes uint32
	// 样例光标（快照后 / 差分后各一份，任务 3.10）：客户端解同一份样例后必须落到同一个光标。
	snapCursor surfaceCursor
	diffCursor surfaceCursor
	// 样例回滚条（任务 3.3）：客户端解出来的 total/offset/len 必须与出口侧一致。
	snapScroll vt.Scrollbar
	diffScroll vt.Scrollbar
}

// buildGoldenSamples 生成两套样例：
//
//	① 仅快照（帧序列 1 帧）——覆盖 SNAPSHOT 体 + 分片 + gzip；
//	② 快照 + 差分（帧序列 2 帧）——覆盖 DIFF 体与**客户端按序应用**的语义（最终网格可比对）；
//	   revision 故意保持不变（差分的语义就是「同一代内的增量」）。
func buildGoldenSamples(t *testing.T, key string, data []byte) (snapFrames, diffFrames []goldenFrame, out goldenSample) {
	t.Helper()
	term, err := vtNew(100, 32, 5000)
	if err != nil {
		t.Fatal(err)
	}
	defer term.Close()
	term.Write(data)
	cols, rows := term.Size()
	out.cols, out.rows, out.rev = cols, rows, 1

	grid := vtEncodeGrid(cols, rows, term.Rows())
	_, _, snapText := gridTextLines(t, grid)
	out.snapDigest = goldenDigest(snapText)
	out.snapStyle = goldenDigest(goldenStyleText(decodedGridRows(t, grid), cols))
	out.snapCursor = surfaceCursorOf(term.Cursor())
	out.snapScroll = term.Scrollbar()
	// 模式位（FIX-30）：快照体此前不写 Modes（恒 0），跨仓无从钉「备用屏/鼠标上报」这类位；
	// 现在随快照一起发并进 manifest 列（diff 帧本就带 Modes，v4 起）。
	snapModes, _, _ := surfaceModesOf(term.Modes())
	out.snapModes = snapModes
	// 覆盖自检（FIX-30）：样式夹具必须真的点亮属性/颜色/宽字符与鼠标上报模式位——否则这份
	// 样例退化成「全默认样式」，跨仓样式向量等于白钉（序列失效或被 vt 忽略时在这里红）。
	if key == "session-styles" {
		var attrCells, colorCells, wideCells int
		for _, r := range term.Rows() {
			for _, c := range r.Cells {
				if c.Attr != 0 {
					attrCells++
				}
				if c.FG.Kind != vt.ColorNone || c.BG.Kind != vt.ColorNone {
					colorCells++
				}
				if c.Width == 2 || c.Skip {
					wideCells++
				}
			}
		}
		if attrCells == 0 || colorCells == 0 || wideCells == 0 {
			t.Fatalf("样式夹具覆盖不足：attr=%d color=%d wide=%d（SGR/宽字符序列没被 vt 生效？）",
				attrCells, colorCells, wideCells)
		}
		if snapModes&termModeMouse1000 == 0 || snapModes&termModeBracketed == 0 {
			t.Fatalf("样式夹具的模式位不齐：modes=%#x（鼠标上报/括号粘贴没进去？）", snapModes)
		}
	}
	snapBody := encSnapshotBody(snapshotBody{
		Geometry: surfaceGeometry{Cols: cols, Rows: rows, Revision: out.rev},
		Cursor:   out.snapCursor,
		Modes:    snapModes,
		Scroll: scrollbar{Total: out.snapScroll.Total, Offset: out.snapScroll.Offset,
			Len: uint16(out.snapScroll.Len)},
		Grid: grid,
	})
	snapFrames = []goldenFrame{{op: opSnapshot, chunks: mustFrag(t, snapBody)}}
	diffFrames = append(diffFrames, snapFrames...)

	// 再写一批内容 → 取脏行差分（与服务端 flushSurface 的路径同一套编码）。
	//
	// 追加的是**不带换行的文本**（光标在同一行上右移）：这样无论夹具把屏幕填没填满，光标位置都会
	// 变化——屏满时追加一整行会滚动、光标可能原地不动（(0,31) 恒等），就钉不住新鲜度了。
	// 差分的期望光标 = **追加之后**的光标（与 flushSurface「同一拍取光标」的口径一致）。
	var dirtyNow []vt.Row
	for attempt := 0; attempt < 4; attempt++ {
		term.Write([]byte("GOLDEN-DIFF-追加"))
		term.Update()
		dirtyNow = vtDirtyRows(term)
		out.diffCursor = surfaceCursorOf(term.Cursor())
		if len(dirtyNow) > 0 && out.diffCursor != out.snapCursor {
			break
		}
		out.diffCursor = surfaceCursor{}
	}
	if len(dirtyNow) == 0 {
		t.Skipf("夹具 %s 没有产生脏行，跳过差分样例", key)
	}
	if out.diffCursor == (surfaceCursor{}) {
		t.Fatalf("夹具 %s：追加 4 次后光标与快照仍相同（%d,%d）——这份样例钉不住光标新鲜度",
			key, out.snapCursor.X, out.snapCursor.Y)
	}
	enc := vtEncodeRows(dirtyNow)
	out.diffScroll = term.Scrollbar()
	diffModes, _, _ := surfaceModesOf(term.Modes())
	diffBody := encDiffBody(diffBody{
		Geometry: surfaceGeometry{Cols: cols, Rows: rows, Revision: out.rev},
		Cursor:   out.diffCursor,
		Modes:    diffModes,
		Scroll: scrollbar{Total: out.diffScroll.Total, Offset: out.diffScroll.Offset,
			Len: uint16(out.diffScroll.Len)},
		Rows:     enc,
		RowCount: uint16(len(dirtyNow)),
	})
	diffFrames = append(diffFrames, goldenFrame{op: opSurfaceDiff, chunks: mustFrag(t, diffBody)})

	// 期望值 = 「快照 + 差分」应用后的整屏文本。
	post := vtEncodeGrid(cols, rows, term.Rows())
	_, _, postText := gridTextLines(t, post)
	out.diffDigest = goldenDigest(postText)
	out.diffStyle = goldenDigest(goldenStyleText(decodedGridRows(t, post), cols))
	out.diffModes = diffModes
	return snapFrames, diffFrames, out
}

// decodedGridRows 解回网格行：样式向量按**解码后**的格值算（width 这类派生字段只在解码侧
// 存在——源行的 width=2 不上线；两端都对同一份字节解码，向量才有可比性）。
func decodedGridRows(t *testing.T, blob []byte) []vt.Row {
	t.Helper()
	_, _, rows, err := vt.DecodeGrid(blob)
	if err != nil {
		t.Fatalf("解网格：%v", err)
	}
	return rows
}

// goldenSource 一个样例来源：文件夹具（vt/testdata）或内联构造的序列。
type goldenSource struct {
	key  string
	file string
	data []byte
}

// goldenStylesSession 样式专项夹具（FIX-30）：一段覆盖颜色/属性/模式位的确定字节序列——
// SGR 组合属性、256 色前景、真彩背景、宽字符（占位格/宽度位）、鼠标上报与括号粘贴模式、
// 光标形状/隐藏。录制夹具（git log/hexdump）碰不齐这些；两端解同一份快照后样式向量必须一致。
func goldenStylesSession() []byte {
	return []byte(
		"\x1b[2J\x1b[H" + // 清屏 + 归位
			"\x1b[1;3;4;7mBOLD\x1b[0m" + // 粗体/斜体/下划线/反显
			"\x1b[2;9mDIM-STRIKE\x1b[0m" + // 暗淡/删除线
			"\x1b[38;5;196mPAL256\x1b[0m " + // 256 色前景
			"\x1b[48;2;10;20;30mRGBBG\x1b[0m " + // 真彩背景
			"\x1b[31;44mRED-BLUE\x1b[0m " + // 基础 16 色
			"宽字" + // 宽字符 + 占位格（width/skip 位）
			"\r\n" +
			"\x1b[?1000h\x1b[?1002h\x1b[?1006h" + // 鼠标上报（X10/按键/SGR）
			"\x1b[?2004h" + // 括号粘贴
			"\x1b[?1049l" + // 确保主屏（备用屏位由 diff 段另行验证）
			"STYLES-OK")
}

func mustFrag(t *testing.T, body []byte) [][]byte {
	t.Helper()
	gz, err := gzipBytes(body)
	if err != nil {
		t.Fatal(err)
	}
	return fragmentPayload(gz)
}
