//go:build (darwin || linux) && (amd64 || arm64) && cgo

// cellcodec.go — 网格的**自定义 cell 行编码**（任务 1.4 的候选方案 B）。
//
// 任务 1.4 要在两条路里选一条做 surface 的快照/差分载荷：
//
//	A) 上游 snapshot API（ghostty_snapshot_encode_alloc）—— 整个终端状态的不透明字节流；
//	B) 本文件的 cell 行编码 —— 按 design D2 的 cell 契约自己编码网格。
//
// **结论（2026-09-23，真实会话字节实测见 vt_test.go 的 TestSerializationChoice）**：选 B。
// 决定性理由不是体积而是**契约归属**：A 的字节格式是 libghostty 内部格式（无版本承诺、只有
// 它自己能解），而客户端已经不再链接 vt（design D5 明确「客户端零 vt」）——用 A 就等于要求
// 手机端复刻一份上游内部格式解析器，正好把本 change 要消灭的「双实现漂移」换个地方重新引入。
// B 的格式是我们自己的 wire 契约，能写进 delta spec、能跨仓 golden fixture 钉住（任务 2.8），
// 且 cell 契约（字素簇/调色板索引或 RGB/修饰位/占位跳过）本来就必须逐字段定义给客户端。
//
// 体积/耗时（100×32 视口，三个真实夹具；gzip 后 = 可比的量级口径，**7.4 的基线就是这张表**）：
//
//	夹具                   snapshot API（原始/gzip/耗时）      cell 行编码（原始/gzip/耗时）
//	git log --color        28102 B / 4564 B / 287µs           18687 B / 3248 B /  98µs
//	hexdump -C（低压缩比）  2979 B / 1016 B /  28µs             8514 B /  755 B /  62µs
//	CJK + 框线             1650 B /  779 B /  16µs              546 B /  264 B /  27µs
//
// 三份的 gzip 后都是 cell 编码更小，最大的那份还快 3×；原始字节在 hexdump 上更大（它每格都
// 带样式，snapshot 的内部编码更紧凑但压不动）。**口径提示**：snapshot API 编的是整个终端状态
// （含全部回滚），cell 行编码只编视口网格——所以只比 gzip 后的量级，不比原始字节。
//
// ⚠️ 留给任务 2.3 的依赖：视口网格来自 render state（本层已封装），但 SNAPSHOT 要的**镜像窗口**
// 是回滚区的行，render state 不覆盖——2.3 需要走上游的滚动视口 / grid_ref 一类 API 取回滚行，
// 取到后仍用本文件的编码（同一套 cell 契约，不为镜像另立格式）。
//
// 差分（SURFACE-DIFF，任务 2.4）复用同一套 cell 编码，只是只发脏行。
package vt

import (
	"errors"
	"fmt"
)

// 行/格流里的标记字节。
const (
	codecBlankRun byte = 0x00 // 后跟 varint：连续 n 个空白格
	codecCell     byte = 0x01 // 后跟一个完整格
	codecRepeat   byte = 0x02 // 后跟 varint：把上一格重复 n 次（框线/重复图案）
)

// 格头的 symLen 字节用高位存「占位格」标志（字素簇长度远小于 128，高位白给）。
const (
	symLenMask  byte = 0x7f
	cellSkipBit byte = 0x80
)

// 颜色编码：kind 字节（复用 ColorKind），palette 跟 1 字节，rgb 跟 3 字节。
const (
	codecColorNone    byte = 0
	codecColorPalette byte = 1
	codecColorRGB     byte = 2
)

// ErrBadGrid 解码失败（越界/截断/版本不符）。
var ErrBadGrid = errors.New("vt: 网格编码非法")

// cellCodecVersion 是编码版本，进载荷头（跨仓 golden fixture 与将来演进都靠它）。
const cellCodecVersion byte = 1

// EncodeGrid 把视口行编成字节（不含 gzip；压缩由调用方按分片契约做，见 design D2）。
//
// 布局：[ver:1][cols:2][rows:2] 然后逐行 [y:2][格流…]。
func EncodeGrid(cols, rows uint16, rs []Row) []byte {
	out := make([]byte, 0, 5+len(rs)*8)
	out = append(out, cellCodecVersion)
	out = appendU16(out, cols)
	out = appendU16(out, rows)
	for _, r := range rs {
		out = appendU16(out, r.Y)
		out = appendRowCells(out, r.Cells)
	}
	return out
}

// EncodeRows 只编「行序列」：每行 [y:2][格流…]（不含头）。
// 差分帧与 FETCH-ROWS 应答都用它——同一套 cell 契约，不为它们另立格式。
func EncodeRows(rows []Row) []byte {
	out := make([]byte, 0, len(rows)*8)
	for _, r := range rows {
		out = appendU16(out, r.Y)
		out = appendRowCells(out, r.Cells)
	}
	return out
}

// DecodeRows 解「行序列」（count = 行数）。
func DecodeRows(b []byte, count, cols int) ([]Row, error) {
	out := make([]Row, 0, count)
	off := 0
	for i := 0; i < count; i++ {
		if off+2 > len(b) {
			return nil, ErrBadGrid
		}
		y := le16(b[off : off+2])
		off += 2
		cells, n, err := decodeRowCells(b[off:], cols)
		if err != nil {
			return nil, err
		}
		off += n
		out = append(out, Row{Y: y, Cells: cells})
	}
	return out, nil
}

func appendRowCells(out []byte, cells []Cell) []byte {
	blankRun := 0
	repeatRun := 0
	var prev Cell
	havePrev := false
	flushBlank := func() {
		if blankRun > 0 {
			out = append(out, codecBlankRun)
			out = appendVarint(out, uint64(blankRun))
			blankRun = 0
		}
	}
	flushRepeat := func() {
		if repeatRun > 0 {
			out = append(out, codecRepeat)
			out = appendVarint(out, uint64(repeatRun))
			repeatRun = 0
		}
	}
	for _, c := range cells {
		if isBlank(c) {
			flushRepeat()
			blankRun++
			prev, havePrev = c, true
			continue
		}
		if havePrev && c == prev {
			flushBlank()
			repeatRun++
			continue
		}
		flushBlank()
		flushRepeat()
		out = append(out, codecCell)
		out = appendCell(out, c)
		prev, havePrev = c, true
	}
	flushBlank()
	flushRepeat()
	return out
}

// isBlank 判定「空白格」：没有字素、没有背景色、没有修饰（最常见的一类，值得游程编码）。
func isBlank(c Cell) bool {
	return c.Symbol == "" && !c.Skip && c.BG.Kind == ColorNone && c.Attr == 0 && c.FG.Kind == ColorNone
}

func appendCell(out []byte, c Cell) []byte {
	hdr := byte(len(c.Symbol))
	if c.Skip {
		hdr |= cellSkipBit
	}
	out = append(out, hdr)
	out = append(out, c.Symbol...)
	out = appendColor(out, c.FG)
	out = appendColor(out, c.BG)
	out = append(out, byte(c.Attr), byte(c.Attr>>8))
	return out
}

func appendColor(out []byte, c Color) []byte {
	switch c.Kind {
	case ColorPalette:
		out = append(out, codecColorPalette, c.Index)
	case ColorRGB:
		out = append(out, codecColorRGB, c.R, c.G, c.B)
	default:
		out = append(out, codecColorNone)
	}
	return out
}

// DecodeGrid 解回行（与 EncodeGrid 严格互逆；测试里断言往返一致）。
func DecodeGrid(b []byte) (uint16, uint16, []Row, error) {
	if len(b) < 5 || b[0] != cellCodecVersion {
		return 0, 0, nil, ErrBadGrid
	}
	cols := le16(b[1:3])
	rows := le16(b[3:5])
	off := 5
	out := make([]Row, 0, rows)
	for i := 0; i < int(rows); i++ {
		if off+2 > len(b) {
			return 0, 0, nil, ErrBadGrid
		}
		y := le16(b[off : off+2])
		off += 2
		cells, n, err := decodeRowCells(b[off:], int(cols))
		if err != nil {
			return 0, 0, nil, err
		}
		off += n
		out = append(out, Row{Y: y, Cells: cells})
	}
	return cols, rows, out, nil
}

func decodeRowCells(b []byte, cols int) ([]Cell, int, error) {
	cells := make([]Cell, 0, cols)
	off := 0
	for len(cells) < cols {
		if off >= len(b) {
			return nil, 0, ErrBadGrid
		}
		switch b[off] {
		case codecBlankRun:
			off++
			n, adv, err := readVarint(b[off:])
			if err != nil {
				return nil, 0, err
			}
			off += adv
			for i := uint64(0); i < n && len(cells) < cols; i++ {
				cells = append(cells, Cell{Width: 1})
			}
		case codecRepeat:
			off++
			n, adv, err := readVarint(b[off:])
			if err != nil {
				return nil, 0, err
			}
			off += adv
			if len(cells) == 0 {
				return nil, 0, ErrBadGrid
			}
			last := cells[len(cells)-1]
			for i := uint64(0); i < n && len(cells) < cols; i++ {
				cells = append(cells, last)
			}
		case codecCell:
			off++
			c, adv, err := decodeCell(b[off:])
			if err != nil {
				return nil, 0, err
			}
			off += adv
			cells = append(cells, c)
		default:
			return nil, 0, ErrBadGrid
		}
	}
	return cells, off, nil
}

func decodeCell(b []byte) (Cell, int, error) {
	if len(b) < 1 {
		return Cell{}, 0, ErrBadGrid
	}
	n := int(b[0] & symLenMask)
	skip := b[0]&cellSkipBit != 0
	off := 1
	if off+n > len(b) {
		return Cell{}, 0, ErrBadGrid
	}
	c := Cell{Symbol: string(b[off : off+n]), Width: 1, Skip: skip}
	off += n
	fg, adv, err := decodeColor(b[off:])
	if err != nil {
		return Cell{}, 0, err
	}
	off += adv
	bg, adv, err := decodeColor(b[off:])
	if err != nil {
		return Cell{}, 0, err
	}
	off += adv
	if off+2 > len(b) {
		return Cell{}, 0, ErrBadGrid
	}
	c.Attr = uint16(b[off]) | uint16(b[off+1])<<8
	off += 2
	c.FG, c.BG = fg, bg
	if c.Symbol == "" {
		c.Width = 0 // 无字素的格（占位格/空格）宽度记 0：客户端据此不画字形
	}
	return c, off, nil
}

func decodeColor(b []byte) (Color, int, error) {
	if len(b) < 1 {
		return Color{}, 0, ErrBadGrid
	}
	switch b[0] {
	case codecColorPalette:
		if len(b) < 2 {
			return Color{}, 0, ErrBadGrid
		}
		return Color{Kind: ColorPalette, Index: b[1]}, 2, nil
	case codecColorRGB:
		if len(b) < 4 {
			return Color{}, 0, ErrBadGrid
		}
		return Color{Kind: ColorRGB, R: b[1], G: b[2], B: b[3]}, 4, nil
	case codecColorNone:
		return Color{}, 1, nil
	default:
		return Color{}, 0, fmt.Errorf("%w: 颜色标记 0x%02x", ErrBadGrid, b[0])
	}
}

// ---- 小工具 ----

func appendU16(b []byte, v uint16) []byte { return append(b, byte(v), byte(v>>8)) }

func le16(b []byte) uint16 { return uint16(b[0]) | uint16(b[1])<<8 }

func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func readVarint(b []byte) (uint64, int, error) {
	var v uint64
	for i := 0; i < len(b) && i < 10; i++ {
		v |= uint64(b[i]&0x7f) << (7 * uint(i))
		if b[i]&0x80 == 0 {
			return v, i + 1, nil
		}
	}
	return 0, 0, ErrBadGrid
}
