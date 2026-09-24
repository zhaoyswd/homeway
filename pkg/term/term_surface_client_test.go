//go:build !windows

// term_surface_client_test.go — surface 协议的**客户端侧参考解码器**（任务 2.10 的测试基建）。
//
// 刻意不复用服务端的编码函数：客户端解码器是**独立实现**（就像手机端会用自己的语言写一遍），
// 这样 roundtrip 测试才真的在验证「两端对同一串字节的理解一致」，而不是自己跟自己比。
// 任务 2.8 的跨仓 golden fixture 是同一个思路，只是那份要跨仓对照。
package term

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// ---- 连接读取 ----

func surfaceReader(t *testing.T, c net.Conn, wantOp byte) []byte {
	t.Helper()
	var asm fragAssembler
	for i := 0; i < maxFragParts+8; i++ {
		f := readTermFrameT(t, c)
		if f.op != wantOp {
			t.Fatalf("期望 op 0x%02x，收到 0x%02x%s", wantOp, f.op, describeFrame(f))
		}
		done, data, err := asm.push(f.payload)
		if err != nil {
			t.Fatalf("攒分片：%v", err)
		}
		if !done {
			continue
		}
		body, err := gunzipBytes(data)
		if err != nil {
			t.Fatalf("解压：%v", err)
		}
		return body
	}
	t.Fatalf("等 op 0x%02x 的分片组超时", wantOp)
	return nil
}

// surfaceReaderFrom 从**已经读到的那一帧**开始攒（调用方在 switch 里已经消费了首片）。
func surfaceReaderFrom(t *testing.T, c net.Conn, first termFrame) []byte {
	t.Helper()
	var asm fragAssembler
	done, data, err := asm.push(first.payload)
	if err != nil {
		t.Fatalf("攒分片：%v", err)
	}
	for !done {
		f := readTermFrameT(t, c)
		if f.op != first.op {
			t.Fatalf("同组分片 op 应一致（0x%02x），收到 0x%02x", first.op, f.op)
		}
		done, data, err = asm.push(f.payload)
		if err != nil {
			t.Fatalf("攒分片：%v", err)
		}
	}
	body, err := gunzipBytes(data)
	if err != nil {
		t.Fatalf("解压：%v", err)
	}
	return body
}

func readSnapshot(t *testing.T, c net.Conn) snapshotBody {
	t.Helper()
	body := surfaceReader(t, c, opSnapshot)
	snap, err := decSnapshotBody(body)
	if err != nil {
		t.Fatalf("解 SNAPSHOT 体：%v", err)
	}
	f := readTermFrameT(t, c)
	if f.op != opSnapshotDone {
		t.Fatalf("快照后应跟 SNAPSHOT-DONE，收到 0x%02x", f.op)
	}
	return snap
}

// waitSnapshot 读到下一个 SNAPSHOT 为止（跳过差分/状态/通知等在飞帧），返回它。
//
// 需要它是因为「请求全量」的应答可能排在若干已经在路上的差分后面。每次读都设短超时：
// 测试里的连接在 attach 之后已清掉读超时（阻塞读），不设就会在「服务端没有新帧」时挂死。
func waitSnapshot(t *testing.T, c net.Conn, timeout time.Duration) snapshotBody {
	t.Helper()
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		f, err := readTermFrame(c)
		if err != nil {
			continue // 读超时/瞬时错误：还没帧，继续等到总 deadline
		}
		if f.op != opSnapshot {
			continue
		}
		body := surfaceReaderFrom(t, c, f)
		snap, err := decSnapshotBody(body)
		if err != nil {
			t.Fatalf("解 SNAPSHOT 体：%v", err)
		}
		if f2 := readTermFrameT(t, c); f2.op != opSnapshotDone {
			t.Fatalf("快照后应跟 SNAPSHOT-DONE，收到 0x%02x", f2.op)
		}
		return snap
	}
	t.Fatalf("等全量快照超时（%v）", timeout)
	return snapshotBody{}
}

// describeFrame 把 ERROR 帧的错误码/文案带进失败信息（否则只看到 op 号，很难查）。
func describeFrame(f termFrame) string {
	if f.op != opError {
		return fmt.Sprintf("（payload %d 字节）", len(f.payload))
	}
	code, msg, err := decError(f.payload)
	if err != nil {
		return fmt.Sprintf("（ERROR 解不开：%v）", err)
	}
	return fmt.Sprintf(" = ERROR %s：%s", code, msg)
}

func attachSurface(t *testing.T, ln net.Listener, name string, cols, rows uint16) (net.Conn, snapshotBody) {
	t.Helper()
	c := dialTerm(t, ln)
	if f := readTermFrameT(t, c); f.op != opGreeting {
		t.Fatalf("首帧应为 GREETING，收到 0x%02x", f.op)
	}
	hello := append(encHello(cols, rows, true, name), encCapability(capsSurface)...)
	writeTermFrame(t, c, opHello, hello)
	f := readTermFrameT(t, c)
	if f.op != opAttached {
		t.Fatalf("期望 ATTACHED，收到 0x%02x（%q）", f.op, f.payload)
	}
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	snap := readSnapshot(t, c)
	_ = c.SetDeadline(time.Time{})
	return c, snap
}

// ---- 客户端侧网格 ----

// clientGrid 客户端持有的网格（行 → 文本）。真实客户端持 cell，这里只要文本就够判据用。
type clientGrid struct {
	cols, rows uint16
	lines      []string
	// cursor 是最近一帧带来的光标（快照或差分；surfaceVer 2 起差分也带）——测试用它断言
	// 「光标每拍都在动」，这正是 3.10 把它加进差分的原因。
	cursor surfaceCursor
}

func newClientGrid(t *testing.T, snap snapshotBody) *clientGrid {
	t.Helper()
	cols, rows, lines, err := decodeGridLines(snap.Grid)
	if err != nil {
		t.Fatalf("解快照网格：%v", err)
	}
	g := &clientGrid{cols: cols, rows: rows, lines: make([]string, rows), cursor: snap.Cursor}
	copy(g.lines, lines)
	return g
}

// applyDiff 解一组差分并把脏行覆盖到网格上（revision 与光标由调用方对账）。
func applyDiff(t *testing.T, c net.Conn, first termFrame, g *clientGrid) diffBody {
	t.Helper()
	body := surfaceReaderFrom(t, c, first)
	d, err := decDiffBody(body)
	if err != nil {
		t.Fatalf("解差分体：%v", err)
	}
	rows, err := decodeRowLines(d.Rows, int(d.RowCount), int(d.Geometry.Cols))
	if err != nil {
		t.Fatalf("解差分行：%v", err)
	}
	if g != nil {
		if int(d.Geometry.Cols) != int(g.cols) {
			t.Fatalf("差分几何与网格不符：%d vs %d", d.Geometry.Cols, g.cols)
		}
		for _, r := range rows {
			if int(r.y) < len(g.lines) {
				g.lines[r.y] = r.text
			}
		}
		g.cursor = d.Cursor // 差分带的光标就是客户端要落的那一份
	}
	return d
}

func gridContains(g *clientGrid, want string) bool { return strings.Contains(gridText(g), want) }

func gridText(g *clientGrid) string { return strings.Join(g.lines, "\n") }

func decodeGridOf(t *testing.T, blob []byte) (uint16, uint16, []string, error) {
	t.Helper()
	return decodeGridLines(blob)
}

func decodeRowsOf(t *testing.T, blob []byte, count, cols int) ([]rowLine, error) {
	t.Helper()
	return decodeRowLines(blob, count, cols)
}

// ---- cell 行编码的独立解码器（与服务端编码器分开实现）----

type rowLine struct {
	y    uint16
	text string
}

// decodeGridLines 解 [ver][cols:2][rows:2] + 行序列。
func decodeGridLines(b []byte) (uint16, uint16, []string, error) {
	if len(b) < 5 {
		return 0, 0, nil, fmt.Errorf("网格头太短")
	}
	if b[0] != 1 {
		return 0, 0, nil, fmt.Errorf("网格版本 %d 不认识", b[0])
	}
	cols := binary.LittleEndian.Uint16(b[1:3])
	rows := binary.LittleEndian.Uint16(b[3:5])
	rl, err := decodeRowLines(b[5:], int(rows), int(cols))
	if err != nil {
		return 0, 0, nil, err
	}
	out := make([]string, len(rl))
	for i, r := range rl {
		out[i] = r.text
	}
	return cols, rows, out, nil
}

// decodeRowLines 解「每行 [y:2][格流…]」的序列（count 行）。
//
// 格流：0x00 = 空白游程（后跟 varint）、0x01 = 完整格、0x02 = 重复上一格（后跟 varint）。
func decodeRowLines(b []byte, count, cols int) ([]rowLine, error) {
	out := make([]rowLine, 0, count)
	off := 0
	for i := 0; i < count; i++ {
		if off+2 > len(b) {
			return nil, fmt.Errorf("行头截断")
		}
		y := binary.LittleEndian.Uint16(b[off:])
		off += 2
		var sb strings.Builder
		prev := ""
		havePrev := false
		// ⚠️ 必须按**格数**判断行是否解完，不能用 sb.Len()（字节数）：CJK 一格占 3 字节，
		// 用字节数会在 ~1/3 处就以为行结束，把后面的格当成下一行解——实测症状是
		// 「未知格标记」这类看着像编码坏了、其实是解码器计数口径错的报错。
		cells := 0
		prevSkip := false
		for cells < cols && off < len(b) {
			switch b[off] {
			case 0x00: // 空白游程
				off++
				n, adv, err := clientVarint(b[off:])
				if err != nil {
					return nil, err
				}
				off += adv
				for k := uint64(0); k < n && cells < cols; k++ {
					sb.WriteByte(' ')
					cells++
				}
			case 0x02: // 重复上一格
				off++
				n, adv, err := clientVarint(b[off:])
				if err != nil {
					return nil, err
				}
				off += adv
				if !havePrev {
					return nil, fmt.Errorf("重复格前没有上一格")
				}
				for k := uint64(0); k < n && cells < cols; k++ {
					// 重放「上一格」的输出效果：占位格不画、空符号补空格（与非重复路径同口径）。
					if !prevSkip {
						if prev == "" {
							sb.WriteByte(' ')
						} else {
							sb.WriteString(prev)
						}
					}
					cells++
				}
			case 0x01: // 完整格
				off++
				if off >= len(b) {
					return nil, fmt.Errorf("格头截断")
				}
				hdr := b[off]
				off++
				symLen := int(hdr & 0x7f)
				skip := hdr&0x80 != 0
				if off+symLen > len(b) {
					return nil, fmt.Errorf("符号截断")
				}
				sym := string(b[off : off+symLen])
				off += symLen
				for c := 0; c < 2; c++ { // 前景/背景色
					if off >= len(b) {
						return nil, fmt.Errorf("颜色截断")
					}
					switch b[off] {
					case 0:
						off++
					case 1:
						off += 2
					case 2:
						off += 4
					default:
						return nil, fmt.Errorf("未知颜色标记 0x%02x", b[off])
					}
				}
				if off+2 > len(b) {
					return nil, fmt.Errorf("属性截断")
				}
				off += 2
				cells++ // 占位格也占一格
				// prev 必须记**包括占位格在内**的上一格：服务端的游程判据是「整个 Cell 相同」，
				// 所以重复游程可能以占位格为基准（相邻宽字符的尾格就是这种）。
				prev, prevSkip, havePrev = sym, skip, true
				if skip {
					continue // 占位格：客户端跳过不画
				}
				if sym == "" {
					sb.WriteByte(' ')
				} else {
					sb.WriteString(sym)
				}
			default:
				return nil, fmt.Errorf("未知格标记 0x%02x", b[off])
			}
		}
		out = append(out, rowLine{y: y, text: strings.TrimRight(sb.String(), " ")})
	}
	return out, nil
}

func clientVarint(b []byte) (uint64, int, error) {
	var v uint64
	for i := 0; i < len(b) && i < 10; i++ {
		v |= uint64(b[i]&0x7f) << (7 * uint(i))
		if b[i]&0x80 == 0 {
			return v, i + 1, nil
		}
	}
	return 0, 0, fmt.Errorf("varint 截断")
}

// waitGridText 在若干秒内不断应用差分/全量，直到网格里出现目标文本。
func waitGridText(t *testing.T, c net.Conn, grid *clientGrid, want string) bool {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		f, err := readTermFrame(c)
		if err != nil {
			continue
		}
		switch f.op {
		case opSurfaceDiff:
			applyDiff(t, c, f, grid)
		case opSnapshot:
			body := surfaceReaderFrom(t, c, f)
			s, derr := decSnapshotBody(body)
			if derr != nil {
				t.Fatal(derr)
			}
			if f2 := readTermFrameT(t, c); f2.op != opSnapshotDone {
				t.Fatalf("期望 SNAPSHOT-DONE，收到 0x%02x", f2.op)
			}
			*grid = *newClientGrid(t, s)
		case opError:
			// ERROR 帧是**判据**，不能当噪声跳过（否则输入没生效会被误读成超时）。
			code, msg, _ := decError(f.payload)
			t.Fatalf("服务端报错 %s：%s", code, msg)
		case opState, opNotify, opClipboard, opSnapshotDone:
		}
		if gridContains(grid, want) {
			return true
		}
	}
	return false
}
