//go:build (darwin || linux) && (amd64 || arm64) && cgo

// render.go — 视口网格读取（render API 脏行读取，任务 1.2 的「脏行网格读取」一项）。
//
// 用法（surface 差分路径，design D2/D5）：
//
//	d := t.Update()                 // 消费终端脏状态，把 render state 拉到最新
//	rows := t.DirtyRows()           // 本拍需要重绘的视口行（含全部 cell）
//	...编码下发...
//	t.Clean()                       // **完整帧成功下发后**才消费脏标记
//
// Clean 的时机很重要：中途失败不 Clean，下一拍会重新给出同样的脏行（宁可重复下发，
// 不能半新半旧——D2 的背压规则同理）。
package vt

import (
	"strings"
	"unsafe"
)

/*
#cgo CFLAGS: -I${SRCDIR} -I${SRCDIR}/../../../third_party/libghostty-vt/include
#include <stdlib.h>
#include "helpers.h"
*/
import "C"

// Dirty 是 render state 的全局脏度（GHOSTTY_RENDER_STATE_DIRTY_*）。
type Dirty uint8

const (
	DirtyNone    Dirty = 0 // 无变化，可跳过本帧
	DirtyPartial Dirty = 1 // 部分行变化，可增量重绘
	DirtyFull    Dirty = 2 // 全局变化，应整屏重绘
)

// ColorKind 颜色来源。cell 契约（design D2）要求「调色板索引或 RGB」，由**客户端**解析配色
// ⇒ 这里保留原始形态，不预先解成 RGB（默认 16 色的取值随主题走，解早了主题切换就错）。
type ColorKind uint8

const (
	ColorNone    ColorKind = 0 // 未设置（用终端默认前景/背景）
	ColorPalette ColorKind = 1 // Index 有效
	ColorRGB     ColorKind = 2 // R/G/B 有效
)

// Color 一个 cell 的前景或背景色。
type Color struct {
	Kind  ColorKind
	Index uint8
	R     uint8
	G     uint8
	B     uint8
}

// 属性位（cell 的 modifier 掩码，u16）。
const (
	AttrBold          uint16 = 1 << 0
	AttrItalic        uint16 = 1 << 1
	AttrFaint         uint16 = 1 << 2
	AttrBlink         uint16 = 1 << 3
	AttrInverse       uint16 = 1 << 4
	AttrInvisible     uint16 = 1 << 5
	AttrStrikethrough uint16 = 1 << 6
	AttrOverline      uint16 = 1 << 7
	// 下划线样式占 bit 8..11（0 = 无；1..5 = single/double/curly/dotted/dashed）。
	attrUnderlineShift = 8
	attrUnderlineMask  = 0xf << attrUnderlineShift
)

// UnderlineAttr 把 vt 的下划线样式值（GHOSTTY_SGR_UNDERLINE_*）编进属性位。
func UnderlineAttr(style uint8) uint16 { return uint16(style&0xf) << attrUnderlineShift }

// Underline 取属性位里的下划线样式值。
func Underline(attr uint16) uint8 { return uint8((attr & attrUnderlineMask) >> attrUnderlineShift) }

// Cell 一个网格单元（cell 契约见 design D2）。
type Cell struct {
	// Symbol 是**字素簇**的 UTF-8（客户端免二次聚类，D2 明确要求）。空格/无文本时为空串。
	Symbol string
	// Width 是显示宽度：1 = 窄，2 = 宽，0 = 宽字符的占位格（不渲染）。
	Width uint8
	// Skip 是差分跳过位：占位格（宽字符尾/软折行头的占位）为 true，客户端跳过不画。
	Skip bool
	FG   Color
	BG   Color
	Attr uint16
}

// Row 一行（视口坐标 Y）。
type Row struct {
	Y     uint16
	Dirty bool
	Cells []Cell
}

// Update 把 render state 更新到终端最新状态并返回全局脏度。
//
// 上游提供两阶段（begin/end）以便调用方只在前半段持终端锁；本层已用 Terminal 自己的锁
// 串行化，所以直接用合并形式（ghostty_render_state_update）。
func (t *Terminal) Update() Dirty {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.rs == nil || t.h == nil {
		return DirtyNone
	}
	if rc := C.ghostty_render_state_update(t.rs, t.h); rc != C.GHOSTTY_SUCCESS {
		return DirtyFull // 更新失败按「整屏」处理：调用方会走全量兜底，不会带病增量
	}
	// ⚠️ 枚举输出用 C 枚举类型接（4 字节；用 uint8_t 会写坏相邻内存，见 Modes 的同类注释）。
	var d C.GhosttyRenderStateDirty
	if C.ghostty_render_state_get(t.rs, C.GHOSTTY_RENDER_STATE_DATA_DIRTY, unsafe.Pointer(&d)) != C.GHOSTTY_SUCCESS {
		return DirtyFull
	}
	return Dirty(d)
}

// DirtyRows 返回本拍需要重绘的视口行（含全部 cell）。**必须先 Update()**（增量路径：
// render state 的脏度由 Update 消费终端脏状态得到）。
//
// 全局脏度为 DirtyFull 时返回**全部**视口行（上游 next_dirty 的语义）。
func (t *Terminal) DirtyRows() []Row {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.rowsLocked(true)
}

// Rows 返回**全部**视口行（快照路径）。内部会把 render state 拉到最新——也就是**隐含消费
// 脏状态**（调用方随后要发全量帧，本来也要 Clean，语义一致）。
func (t *Terminal) Rows() []Row {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.rs == nil || t.h == nil {
		return nil
	}
	if rc := C.ghostty_render_state_update(t.rs, t.h); rc != C.GHOSTTY_SUCCESS {
		return nil
	}
	return t.rowsLocked(false)
}

// Clean 在**完整帧成功下发后**调用，消费脏标记（ghostty_render_state_clean）。
// 部分消费（只发了几行就失败）不要调用它。
func (t *Terminal) Clean() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.rs == nil {
		return
	}
	C.ghostty_render_state_clean(t.rs)
}

// initRenderContainers 建行迭代器、行 cell 容器与字素缓冲（New / RestoreSnapshot 共用）。
// 前两者可复用：每行/每格只换内容，不重新分配。
func (t *Terminal) initRenderContainers() error {
	if rc := C.ghostty_render_state_row_iterator_new(nil, &t.rowIt); rc != C.GHOSTTY_SUCCESS {
		return errf("render_state_row_iterator_new", rc)
	}
	if rc := C.ghostty_render_state_row_cells_new(nil, &t.cells); rc != C.GHOSTTY_SUCCESS {
		C.ghostty_render_state_row_iterator_free(t.rowIt)
		t.rowIt = nil
		return errf("render_state_row_cells_new", rc)
	}
	// 读字素簇的复用缓冲（C 内存，见 graphemeLocked 的指针约束）。
	if !t.growCBuf(64) {
		C.ghostty_render_state_row_cells_free(t.cells)
		t.cells = nil
		C.ghostty_render_state_row_iterator_free(t.rowIt)
		t.rowIt = nil
		return errOutOfMemory
	}
	return nil
}

// rowsLocked 走一遍行迭代器（**调用方必须持 t.mu**）。dirtyOnly = 只取需要重绘的行。
//
// ⚠️ 行迭代器建出来时除 allocator 外**所有字段都是未定义的**（上游文档明写），必须先经
// ghostty_render_state_get(DATA_ROW_ITERATOR) 绑定到当前 render state 才能迭代——漏了这一步
// 会在 next_dirty 里空指针崩（实测 SIGSEGV）。
func (t *Terminal) rowsLocked(dirtyOnly bool) []Row {
	if t.closed || t.rs == nil || t.rowIt == nil || t.cells == nil {
		return nil
	}
	if C.ghostty_render_state_get(t.rs, C.GHOSTTY_RENDER_STATE_DATA_ROW_ITERATOR,
		unsafe.Pointer(&t.rowIt)) != C.GHOSTTY_SUCCESS {
		return nil
	}
	var out []Row
	for {
		var y C.uint16_t
		if dirtyOnly {
			if !bool(C.ghostty_render_state_row_iterator_next_dirty(t.rowIt, &y)) {
				break
			}
		} else {
			if !bool(C.ghostty_render_state_row_iterator_next(t.rowIt)) {
				break
			}
			// 上游语义：非脏迭代从 y=0 起**连续**访问视口行 ⇒ Y 就是序号。
			y = C.uint16_t(len(out))
		}
		row := Row{Y: uint16(y)}
		var dirty C.bool
		if C.ghostty_render_state_row_get(t.rowIt, C.GHOSTTY_RENDER_STATE_ROW_DATA_DIRTY,
			unsafe.Pointer(&dirty)) == C.GHOSTTY_SUCCESS {
			row.Dirty = bool(dirty)
		}
		if C.ghostty_render_state_row_get(t.rowIt, C.GHOSTTY_RENDER_STATE_ROW_DATA_CELLS,
			unsafe.Pointer(&t.cells)) == C.GHOSTTY_SUCCESS {
			row.Cells = t.cellsLocked()
		}
		out = append(out, row)
	}
	return out
}

// cellsLocked 读当前行的全部 cell（必须已 row_get(ROW_DATA_CELLS)）。
func (t *Terminal) cellsLocked() []Cell {
	var out []Cell
	for bool(C.ghostty_render_state_row_cells_next(t.cells)) {
		out = append(out, t.cellLocked())
	}
	return out
}

// cellLocked 读当前 cell：符号（字素簇）+ 宽属性 + 样式（颜色与装饰）。
//
// ⚠️ 三类输出类型必须严格照上游文档：**枚举是 4 字节 int**（GhosttyCellWide /
// GhosttyTerminalScreen / GhosttyRenderStateDirty），用 uint8_t 之类的窄类型接会让库往小变量里
// 写 4 字节、静默踩坏相邻内存——实测症状是 -race 下 GC 扫描崩（SIGBUS/SIGSEGV）。
func (t *Terminal) cellLocked() Cell {
	var c Cell

	// 宽属性来自原始 cell 值。
	var raw C.GhosttyCell
	if C.ghostty_render_state_row_cells_get(t.cells, C.GHOSTTY_RENDER_STATE_ROW_CELLS_DATA_RAW,
		unsafe.Pointer(&raw)) == C.GHOSTTY_SUCCESS {
		var wide C.GhosttyCellWide
		if C.ghostty_cell_get(raw, C.GHOSTTY_CELL_DATA_WIDE, unsafe.Pointer(&wide)) == C.GHOSTTY_SUCCESS {
			switch uint8(wide) {
			case 1: // GHOSTTY_CELL_WIDE_WIDE
				c.Width = 2
			case 2, 3: // SPACER_TAIL / SPACER_HEAD：占位格，不渲染
				c.Width, c.Skip = 0, true
			default: // NARROW
				c.Width = 1
			}
		} else {
			c.Width = 1
		}
	}

	c.Symbol = t.graphemeLocked()

	// 样式：tagged 颜色（调色板索引 / RGB）+ 装饰位。
	var st C.GhosttyStyle
	C.tier_vt_style_init(&st)
	if C.ghostty_render_state_row_cells_get(t.cells, C.GHOSTTY_RENDER_STATE_ROW_CELLS_DATA_STYLE,
		unsafe.Pointer(&st)) == C.GHOSTTY_SUCCESS {
		c.FG = styleColor(st.fg_color)
		c.BG = styleColor(st.bg_color)
		// 逐位拼装（这里是逐格热路径：不要用 map/切片之类的分配式写法）。
		var attr uint16
		if bool(st.bold) {
			attr |= AttrBold
		}
		if bool(st.italic) {
			attr |= AttrItalic
		}
		if bool(st.faint) {
			attr |= AttrFaint
		}
		if bool(st.blink) {
			attr |= AttrBlink
		}
		if bool(st.inverse) {
			attr |= AttrInverse
		}
		if bool(st.invisible) {
			attr |= AttrInvisible
		}
		if bool(st.strikethrough) {
			attr |= AttrStrikethrough
		}
		if bool(st.overline) {
			attr |= AttrOverline
		}
		attr |= UnderlineAttr(uint8(int32(st.underline)))
		c.Attr = attr
	}
	return c
}

// graphemeLocked 把当前 cell 的字素簇编码成 UTF-8（缓冲不够就按所需容量扩容重试）。
//
// ⚠️ 缓冲必须是 **C 内存**：GhosttyBuffer 要作为结构体整体传给 C，而 cgo 禁止「指向 Go 指针的
// Go 指针」（Go 的切片指针存在结构体里就撞这条，实测 panic: cgo argument has Go pointer to
// unpinned Go pointer）。用 C.malloc 的裸缓冲就没有 Go 指针参与。
func (t *Terminal) graphemeLocked() string {
	for attempt := 0; attempt < 2; attempt++ {
		var buf C.GhosttyBuffer
		buf.ptr = t.cbuf
		buf.cap = C.size_t(t.cbufLen)
		buf.len = 0
		rc := C.ghostty_render_state_row_cells_get(t.cells,
			C.GHOSTTY_RENDER_STATE_ROW_CELLS_DATA_GRAPHEMES_UTF8, unsafe.Pointer(&buf))
		switch rc {
		case C.GHOSTTY_SUCCESS:
			if buf.len == 0 {
				return ""
			}
			return C.GoStringN((*C.char)(unsafe.Pointer(t.cbuf)), C.int(buf.len))
		case C.GHOSTTY_OUT_OF_SPACE:
			// buf.len 是所需容量；字素簇上限很小，给一次扩容机会即可。
			need := int(buf.len)
			if need <= t.cbufLen || need > 1<<12 {
				return ""
			}
			if !t.growCBuf(need) {
				return ""
			}
		default:
			return ""
		}
	}
	return ""
}

// growCBuf 把 C 侧复用缓冲扩到至少 n 字节。
func (t *Terminal) growCBuf(n int) bool {
	p := C.malloc(C.size_t(n))
	if p == nil {
		return false
	}
	if t.cbuf != nil {
		C.free(unsafe.Pointer(t.cbuf))
	}
	t.cbuf = (*C.uint8_t)(p)
	t.cbufLen = n
	return true
}

// styleColor 把 C 侧的 tagged union 转成 Go 值。
func styleColor(c C.GhosttyStyleColor) Color {
	switch uint8(C.tier_vt_style_color_tag(c)) {
	case 1: // GHOSTTY_STYLE_COLOR_PALETTE
		return Color{Kind: ColorPalette, Index: uint8(C.tier_vt_style_color_palette(c))}
	case 2: // GHOSTTY_STYLE_COLOR_RGB
		var r, g, b C.uint8_t
		C.tier_vt_style_color_rgb(c, &r, &g, &b)
		return Color{Kind: ColorRGB, R: uint8(r), G: uint8(g), B: uint8(b)}
	default:
		return Color{}
	}
}

// ScreenText 取**当前视口**的纯文本（每行由 cell 的字素簇拼成，行尾空白裁掉）。
//
// 这是检测引擎「屏幕尾部文本」腿的正确输入口径（term-agent-state 的检测输入契约：
// 「当前活动屏方向最近约一屏的纯文本行，滚动位置不影响」）：
//   - **只取一屏**：不要把整条回滚灌给引擎——回滚里可能有几万行旧内容，既让 anchored 规则
//     （\A 锚定的那些）失准，也让每拍扫描的成本随历史长度增长。
//   - 视口坐标天然与滚动位置无关（render state 给的就是当前视口），所以不需要额外折算。
//   - 占位格（宽字符尾格）跳过：它们 Symbol 为空，补进去会把 CJK 行拼错。
func (t *Terminal) ScreenText() string {
	rows := t.Rows()
	var b strings.Builder
	for i, r := range rows {
		if i > 0 {
			b.WriteByte('\n')
		}
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
	}
	out := b.String()
	lines := strings.Split(out, "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], " \t\u00a0")
	}
	return strings.Join(lines, "\n")
}
