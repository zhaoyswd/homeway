//go:build (darwin || linux) && (amd64 || arm64) && cgo

// mirror.go — 回滚镜像窗口的读取（任务 2.3 依赖）。
//
// render state 只暴露**当前视口**，而 surface 的 SNAPSHOT 要带「最近约 10 个视口的回滚行」
// （design D2/D3 的镜像窗口）。取回滚行的正路是上游的滚动视口 API：
// `ghostty_terminal_scroll_viewport(ROW)` 用的是**与滚动条 offset 同一套行号空间**（文档明写可往返），
// 所以流程是「读滚动条 → 滚到目标行 → 读视口 → 滚回原位」。
//
// 两条必须守住的纪律：
//
//  1. **滚回原位要区分「在底部」**：在底部时要用 BOTTOM 而不是 ROW(offset) 恢复——绝对行号会把
//     终端从「跟随输出」模式里摘出来，之后新输出不再自动滚动（对用户表现为会话卡住不动）。
//  2. **整个过程在会话锁内**（调用方持锁）：中间态不会被任何客户端看到（我们只经 render state
//     读，不直接投递），但也不能让并发的 surface 投递读到滚上去的那一帧。
package vt

import "unsafe"

/*
#cgo CFLAGS: -I${SRCDIR} -I${SRCDIR}/../../../third_party/libghostty-vt/include
#include <stdlib.h>
#include "helpers.h"
*/
import "C"

// Scrollbar 是终端的可滚动区域状态（滚动条口径：total/offset/len 单位都是行）。
type Scrollbar struct {
	Total  uint64
	Offset uint64
	Len    uint64
}

// AtBottom 报告视口是否贴着底部（= 跟随输出）。
func (s Scrollbar) AtBottom() bool { return s.Offset+s.Len >= s.Total }

// Scrollbar 读当前滚动条状态（诊断与镜像窗口都用它）。
func (t *Terminal) Scrollbar() Scrollbar {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.scrollbarLocked()
}

func (t *Terminal) scrollbarLocked() Scrollbar {
	if t.closed || t.h == nil {
		return Scrollbar{}
	}
	var sb C.GhosttyTerminalScrollbar
	if C.ghostty_terminal_get(t.h, C.GHOSTTY_TERMINAL_DATA_SCROLLBAR, unsafe.Pointer(&sb)) != C.GHOSTTY_SUCCESS {
		return Scrollbar{}
	}
	return Scrollbar{Total: uint64(sb.total), Offset: uint64(sb.offset), Len: uint64(sb.len)}
}

// MirrorRows 取当前视口**上方**最多 above 行的回滚窗口（返回的行按屏幕顺序：最旧的在前）。
//
// 无回滚（视口已在顶部）或备用屏时返回 nil——备用屏没有回滚语义，且 design D3 要求备用屏
// 激活时抑制回滚预取。
//
// 返回的是**快照副本**（Cell 已拷成 Go 值），调用方可以放心在锁外编码/发送。
func (t *Terminal) MirrorRows(above int) []Row {
	if above <= 0 {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.rs == nil || t.h == nil {
		return nil
	}
	if t.screenLocked() == ScreenAlternate {
		return nil
	}
	sb := t.scrollbarLocked()
	if sb.Offset == 0 {
		return nil
	}
	start := uint64(0)
	if sb.Offset > uint64(above) {
		start = sb.Offset - uint64(above)
	}
	// 视口一次只显示一屏，所以窗口要**分块**读：每次滚到块的起点、读当前视口、
	// 只取属于窗口的那几行，直到覆盖 [start, sb.Offset)。
	out := make([]Row, 0, int(sb.Offset-start))
	for cur := start; cur < sb.Offset; {
		t.scrollToRowLocked(cur)
		if rc := C.ghostty_render_state_update(t.rs, t.h); rc != C.GHOSTTY_SUCCESS {
			t.restoreViewportLocked(sb)
			return nil
		}
		vp := t.rowsLocked(false)
		if len(vp) == 0 {
			break
		}
		take := len(vp)
		if remain := int(sb.Offset - cur); take > remain {
			take = remain
		}
		out = append(out, vp[:take]...)
		cur += uint64(take)
	}
	t.restoreViewportLocked(sb)
	return out
}

// RowsAt 取绝对行号区间 [from, from+count) 的行（与滚动条 offset 同一套行号空间）。
//
// 供 surface 的 FETCH-ROWS 应答用：客户端滚出镜像窗口边缘时按需拉更早的行。越界部分
// （行号超出可滚动区）自动截断——客户端按返回的实际行数处理。
func (t *Terminal) RowsAt(from uint64, count int) []Row {
	if count <= 0 {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.rs == nil || t.h == nil {
		return nil
	}
	if t.screenLocked() == ScreenAlternate {
		return nil // 备用屏没有回滚语义（design D3 要求抑制回滚拉取）
	}
	sb := t.scrollbarLocked()
	// 可滚动区总行数 = total（含可见区）；行号必须落在 [0, total) 内。
	if from >= sb.Total {
		return nil
	}
	end := from + uint64(count)
	if end > sb.Total {
		end = sb.Total
	}

	out := make([]Row, 0, int(end-from))
	for cur := from; cur < end; {
		t.scrollToRowLocked(cur)
		if rc := C.ghostty_render_state_update(t.rs, t.h); rc != C.GHOSTTY_SUCCESS {
			t.restoreViewportLocked(sb)
			return nil
		}
		vp := t.rowsLocked(false)
		if len(vp) == 0 {
			break
		}
		take := len(vp)
		if remain := int(end - cur); take > remain {
			take = remain
		}
		out = append(out, vp[:take]...)
		cur += uint64(take)
	}
	t.restoreViewportLocked(sb)
	return out
}

// RowsAboveViewport 视口**上方**还有多少行（= 镜像窗口可达的深度；0 = 视口贴着顶部）。
func (t *Terminal) RowsAboveViewport() int { return int(t.Scrollbar().Offset) }

func (t *Terminal) screenLocked() Screen {
	var screen C.GhosttyTerminalScreen
	if C.ghostty_terminal_get(t.h, C.GHOSTTY_TERMINAL_DATA_ACTIVE_SCREEN, unsafe.Pointer(&screen)) != C.GHOSTTY_SUCCESS {
		return ScreenPrimary
	}
	return Screen(screen)
}

func (t *Terminal) scrollToRowLocked(row uint64) {
	C.tier_vt_scroll_to_row(t.h, C.size_t(row))
}

func (t *Terminal) scrollToBottomLocked() {
	C.tier_vt_scroll_bottom(t.h)
}

// restoreViewportLocked 把视口还原到读窗口之前的位置（见文件头纪律 ①）。
func (t *Terminal) restoreViewportLocked(before Scrollbar) {
	if before.AtBottom() {
		t.scrollToBottomLocked()
		return
	}
	t.scrollToRowLocked(before.Offset)
}
