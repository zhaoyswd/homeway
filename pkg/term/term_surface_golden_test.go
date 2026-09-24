//go:build !windows

// term_surface_golden_test.go — 任务 2.8 的**跨仓 golden fixture**（生成半边）。
//
// 目的：surface 的字节布局在**多处**各有一份实现（出口 Go 的 term_surface.go + cellcodec.go、
// 客户端的 surface_codec.cpp、App 核的帧子集）——新增 op 会放大漂移风险。这里生成一组**共享样例**
// （每个 op 一例），两端各自解码并断言同一份结果。
//
// 产物（提交在 tier 仓；客户端宿主测试读它）：
//
//	terminal/src/test/golden/manifest.tsv   name<TAB>op<TAB>cols<TAB>rows<TAB>revision<TAB>digest<TAB>title
//	terminal/src/test/golden/<name>.bin     分片序列：[u32 片数]{[u32 长度][字节]}…
//
// 生成：TIER_REPO=<tier 仓路径> go test ./pkg/term/ -run TestSurfaceGolden -update
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

const goldenDirEnv = "TIER_REPO"

func goldenDir(t *testing.T) string {
	t.Helper()
	repo := os.Getenv(goldenDirEnv)
	if repo == "" {
		repo = "/Users/zhaozhe/Documents/projects/tier" // 本机默认（跨仓路径；别处用环境变量）
	}
	return filepath.Join(repo, "terminal", "src", "test", "golden")
}

// goldenDigest 与客户端 C++ 的 digestText 同一算法（改一处必须同步改另一处——这正是被钉住的东西）。
func goldenDigest(text string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(text))
	return fmt.Sprintf("%016x", h.Sum64())
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
	rev uint32, digest, title string, cursor surfaceCursor, sb vt.Scrollbar) {
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
	// 末尾 3 列 = 回滚条（任务 3.3）：客户端解同一份样例后 total/offset/len 必须一致。
	line := fmt.Sprintf("%s\t0x%02x\t%d\t%d\t%d\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n",
		name, frames[0].op, cols, rows, rev, digest, title, len(frames),
		cursor.X, cursor.Y, cursor.Flags, cursor.Shape,
		sb.Total, sb.Offset, sb.Len)
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

	fixtures := []string{"session-cjk.bin", "session-git-log.bin", "session-hexdump.bin"}
	for _, name := range fixtures {
		key := strings.TrimSuffix(name, ".bin")
		snapFrames, diffFrames, sample := buildGoldenSamples(t, name)
		if update {
			writeGoldenSample(t, dir, key, snapFrames,
				sample.cols, sample.rows, sample.rev, sample.snapDigest, sample.title, sample.snapCursor,
				sample.snapScroll)
			writeGoldenSample(t, dir, key+"-diff", diffFrames,
				sample.cols, sample.rows, sample.rev, sample.diffDigest, sample.title, sample.diffCursor,
				sample.diffScroll)
			t.Logf("%s：快照 %s / 差分后 %s（%dx%d rev=%d 光标 %d,%d → %d,%d）",
				key, sample.snapDigest, sample.diffDigest, sample.cols, sample.rows, sample.rev,
				sample.snapCursor.X, sample.snapCursor.Y, sample.diffCursor.X, sample.diffCursor.Y)
			continue
		}
		for _, c := range []struct {
			key, want string
			cursor    surfaceCursor
			scroll    vt.Scrollbar
		}{
			{key, sample.snapDigest, sample.snapCursor, sample.snapScroll},
			{key + "-diff", sample.diffDigest, sample.diffCursor, sample.diffScroll},
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
		}
	}
}

type goldenSample struct {
	cols, rows uint16
	rev        uint32
	title      string
	snapDigest string
	diffDigest string
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
func buildGoldenSamples(t *testing.T, fixture string) (snapFrames, diffFrames []goldenFrame, out goldenSample) {
	t.Helper()
	term, err := vtNew(100, 32, 5000)
	if err != nil {
		t.Fatal(err)
	}
	defer term.Close()
	data, err := os.ReadFile(filepath.Join("vt", "testdata", fixture))
	if err != nil {
		t.Skipf("没有夹具 %s：%v", fixture, err)
	}
	term.Write(data)
	cols, rows := term.Size()
	out.cols, out.rows, out.rev = cols, rows, 1

	grid := vtEncodeGrid(cols, rows, term.Rows())
	_, _, snapText := gridTextLines(t, grid)
	out.snapDigest = goldenDigest(snapText)
	out.snapCursor = surfaceCursorOf(term.Cursor())
	out.snapScroll = term.Scrollbar()
	snapBody := encSnapshotBody(snapshotBody{
		Geometry: surfaceGeometry{Cols: cols, Rows: rows, Revision: out.rev},
		Cursor:   out.snapCursor,
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
		t.Skipf("夹具 %s 没有产生脏行，跳过差分样例", fixture)
	}
	if out.diffCursor == (surfaceCursor{}) {
		t.Fatalf("夹具 %s：追加 4 次后光标与快照仍相同（%d,%d）——这份样例钉不住光标新鲜度",
			fixture, out.snapCursor.X, out.snapCursor.Y)
	}
	enc := vtEncodeRows(dirtyNow)
	out.diffScroll = term.Scrollbar()
	diffBody := encDiffBody(diffBody{
		Geometry: surfaceGeometry{Cols: cols, Rows: rows, Revision: out.rev},
		Cursor:   out.diffCursor,
		Rows:     enc,
		RowCount: uint16(len(dirtyNow)),
	})
	diffFrames = append(diffFrames, goldenFrame{op: opSurfaceDiff, chunks: mustFrag(t, diffBody)})

	// 期望值 = 「快照 + 差分」应用后的整屏文本。
	post := vtEncodeGrid(cols, rows, term.Rows())
	_, _, postText := gridTextLines(t, post)
	out.diffDigest = goldenDigest(postText)
	return snapFrames, diffFrames, out
}

func mustFrag(t *testing.T, body []byte) [][]byte {
	t.Helper()
	gz, err := gzipBytes(body)
	if err != nil {
		t.Fatal(err)
	}
	return fragmentPayload(gz)
}
