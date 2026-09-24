//go:build (darwin || linux) && (amd64 || arm64) && cgo

// Package vt 是 libghostty-vt 的 cgo 绑定层（openspec term-vt-backend 任务 1.2）。
//
// 出口侧 term 服务用它把 vt 提升为**会话屏态的唯一持有者**：surface 帧下发、回滚拉取、
// agent 检测读取都从同一份状态派生（design D1），消灭「服务端旁路扫描器 vs 手机端 vt」
// 双实现对同一字节流的理解漂移。
//
// 绑定面刻意收窄（design D1 列的清单）：new/free、vt_write、render API 脏行网格、formatter
// 纯文本、snapshot 编码/解码、key/mouse/focus 编码、terminal_get（尺寸/模式位）。
// 上游头文件在 third_party/libghostty-vt/include/ghostty/vt/，每个方法的对应 API 写在注释里。
//
// **并发**：每个 Terminal 自带互斥锁，所有方法可安全并发调用。会话锁与它的关系见 design D1
// （锁内只取脏行快照、锁外编码/发送）——本层不做额外的锁外延展，调用方负责在「取快照」与
// 「编码发送」之间释放会话锁。
package vt

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"unsafe"
)

/*
#cgo CFLAGS: -I${SRCDIR} -I${SRCDIR}/../../../third_party/libghostty-vt/include
#include <stdlib.h>
#include "helpers.h"
*/
import "C"

// releaseTerminal 注销回调注册表条目（幂等；Close 与构造失败路径都走它）。
func (t *Terminal) releaseTerminal() {
	if t.regID != 0 {
		unregisterTerminal(t.regID)
		t.regID = 0
	}
}

// errClosed：终端已 Close，调用方不该把它当成「会话失败」（会话收尾路径会照常调到）。
var errClosed = errors.New("vt: 终端已关闭")

// errOutOfMemory：建终端时的分配失败（字素缓冲等）。
var errOutOfMemory = errors.New("vt: 分配失败")

// errf 把上游的 GhosttyResult 包成带上下文的错误。
func errf(what string, rc C.GhosttyResult) error {
	return fmt.Errorf("vt: %s rc=%d", what, int32(rc))
}

// DefaultScrollbackLines 是每会话回滚行数上限的默认值（env HOMEWAY_TERM_SCROLLBACK_LINES 可调，
// 见 design D1 的内存预算口径：会话上限 × (1MiB ring + vt 峰值)）。
const DefaultScrollbackLines = 10000

// nominalCellPx 是喂给 resize 的**名义**单元格像素尺寸。
//
// 它只影响两类我们不用出口像素几何的东西：图片协议（kitty graphics）与 CSI 14/16 t 尺寸上报。
// 我们的网格协议全按 cell 走，客户端自己按真实字号排版，所以这里给一个常规值即可——
// 给 0 会让「程序问终端多大」拿到 0，给真实值又没人能提供（出口不知道手机的字号）。
const nominalCellPx = 8

// Screen 是当前活动屏（ghostty_terminal_get 的 GHOSTTY_TERMINAL_DATA_ACTIVE_SCREEN）。
type Screen uint8

const (
	ScreenPrimary   Screen = 0
	ScreenAlternate Screen = 1
)

// CursorShape 是光标形状（render state 的 CURSOR_VISUAL_STYLE）。
type CursorShape uint8

const (
	CursorBar         CursorShape = 0 // DECSCUSR 5/6
	CursorBlock       CursorShape = 1 // DECSCUSR 1/2
	CursorUnderline   CursorShape = 2 // DECSCUSR 3/4
	CursorBlockHollow CursorShape = 3
)

// Modes 是一次模式位快照。字段命名对齐 vt 的 DEC/ANSI 模式号（注释里给出）。
//
// 为什么不用 legacy 的 termMode* 位掩码：那是 legacy 协议的下行编码格式，属另一层的事；
// 这里给结构化字段，由 term 包按需映射（legacy 位掩码 / surface 帧字段）。
type Modes struct {
	Screen Screen

	CursorKeysApp  bool // DEC 1   应用光标键
	KeypadApp      bool // DEC 66  应用小键盘
	BracketedPaste bool // DEC 2004
	FocusEvents    bool // DEC 1004

	MouseX10    bool // DEC 9
	MouseNormal bool // DEC 1000
	MouseButton bool // DEC 1002
	MouseAny    bool // DEC 1003
	MouseSGR    bool // DEC 1006
	MouseUTF8   bool // DEC 1005
	MouseURXVT  bool // DEC 1015
	AltScroll   bool // DEC 1007

	CursorVisible bool // DEC 25
	CursorBlink   bool // DEC 12

	Insert     bool // ANSI 4
	Origin     bool // DEC 6
	Wraparound bool // DEC 7

	// KittyFlags 是 kitty 键盘协议标志（uint8 位掩码）；ModifyOtherKeys 是 xterm
	// modifyOtherKeys mode 2——后者正是 vendor 补丁 0002 暴露的查询（design D4 的输入编码依赖它）。
	KittyFlags      uint8
	ModifyOtherKeys bool
}

// Cursor 是光标快照。X/Y 是**视口**坐标（render state 口径，回滚偏移已折算）。
type Cursor struct {
	X, Y     uint16
	Visible  bool
	Blinking bool
	Password bool
	WideTail bool
	Shape    CursorShape
}

// Terminal 是一个会话的服务端仿真器。
type Terminal struct {
	mu       sync.Mutex
	h        C.GhosttyTerminal
	rs       C.GhosttyRenderState // 视口网格（脏行读取用），随 Terminal 一起建/销
	rowIt    C.GhosttyRenderStateRowIterator
	cells    C.GhosttyRenderStateRowCells
	keyEnc   C.GhosttyKeyEncoder   // 懒建（输入编码用）
	mouseEnc C.GhosttyMouseEncoder // 懒建
	cbuf     *C.uint8_t            // C 侧复用缓冲（读字素簇；见 render.go 的 cgo 指针约束）
	cbufLen  int
	// responseSink 是 vt 写回 PTY 的接收方（DA1/DSR/OSC 查询应答；见 response.go）。
	responseSink func([]byte)
	// regID 是本终端在回调注册表里的 id（0 = 没注册）。
	regID  uintptr
	cols   uint16
	rows   uint16
	closed bool
}

// New 建一个 cols×rows 的终端，回滚行数上限 scrollbackLines（≤0 用 DefaultScrollbackLines）。
func New(cols, rows uint16, scrollbackLines int) (*Terminal, error) {
	if cols == 0 || rows == 0 {
		return nil, fmt.Errorf("vt: 尺寸非法 %dx%d", cols, rows)
	}
	if scrollbackLines <= 0 {
		scrollbackLines = DefaultScrollbackLines
	}
	var h C.GhosttyTerminal
	if rc := C.ghostty_terminal_new(nil, &h, C.uint16_t(cols), C.uint16_t(rows)); rc != C.GHOSTTY_SUCCESS {
		return nil, fmt.Errorf("vt: terminal_new rc=%d", int32(rc))
	}
	// 回滚行数上限（输入类型 size_t*，见 GHOSTTY_TERMINAL_OPT_SCROLLBACK_MAX_LINES 文档）。
	maxLines := C.size_t(scrollbackLines)
	if rc := C.ghostty_terminal_set(h, C.GHOSTTY_TERMINAL_OPT_SCROLLBACK_MAX_LINES,
		unsafe.Pointer(&maxLines)); rc != C.GHOSTTY_SUCCESS {
		C.ghostty_terminal_free(h)
		return nil, fmt.Errorf("vt: 设置回滚上限 %d 行失败 rc=%d", scrollbackLines, int32(rc))
	}
	var rs C.GhosttyRenderState
	if rc := C.ghostty_render_state_new(nil, &rs); rc != C.GHOSTTY_SUCCESS {
		C.ghostty_terminal_free(h)
		return nil, fmt.Errorf("vt: render_state_new rc=%d", int32(rc))
	}
	t := &Terminal{h: h, rs: rs, cols: cols, rows: rows}
	t.regID = registerTerminal(t)
	// 装「写回 PTY」回调：不装的话 vt **静默丢弃**所有查询应答（DA1/DSR/OSC 10-11），
	// 会话里的程序会卡在终端探测上（见 response.go）。
	C.tier_vt_set_write_pty(t.h, C.uintptr_t(t.regID))
	if err := t.initRenderContainers(); err != nil {
		C.ghostty_render_state_free(rs)
		C.ghostty_terminal_free(h)
		return nil, err
	}
	return t, nil
}

// Close 释放终端与 render state（幂等）。关闭后所有方法都返回错误/零值。
func (t *Terminal) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.closed = true
	t.releaseTerminal()
	if t.cbuf != nil {
		C.free(unsafe.Pointer(t.cbuf))
		t.cbuf = nil
		t.cbufLen = 0
	}
	if t.mouseEnc != nil {
		C.ghostty_mouse_encoder_free(t.mouseEnc)
		t.mouseEnc = nil
	}
	if t.keyEnc != nil {
		C.ghostty_key_encoder_free(t.keyEnc)
		t.keyEnc = nil
	}
	if t.cells != nil {
		C.ghostty_render_state_row_cells_free(t.cells)
		t.cells = nil
	}
	if t.rowIt != nil {
		C.ghostty_render_state_row_iterator_free(t.rowIt)
		t.rowIt = nil
	}
	if t.rs != nil {
		C.ghostty_render_state_free(t.rs)
		t.rs = nil
	}
	if t.h != nil {
		C.ghostty_terminal_free(t.h)
		t.h = nil
	}
}

// Write 把 PTY 输出喂进 vt（ghostty_terminal_vt_write）。这是屏态的唯一入口。
func (t *Terminal) Write(p []byte) {
	if len(p) == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.h == nil {
		return
	}
	C.ghostty_terminal_vt_write(t.h, (*C.uint8_t)(unsafe.Pointer(&p[0])), C.size_t(len(p)))
}

// Resize 改尺寸（ghostty_terminal_resize，含回滚重排）。尺寸未变时是空操作。
func (t *Terminal) Resize(cols, rows uint16) error {
	if cols == 0 || rows == 0 {
		return fmt.Errorf("vt: 尺寸非法 %dx%d", cols, rows)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.h == nil {
		return errClosed
	}
	if t.cols == cols && t.rows == rows {
		return nil
	}
	if rc := C.ghostty_terminal_resize(t.h, C.uint16_t(cols), C.uint16_t(rows),
		C.uint32_t(nominalCellPx), C.uint32_t(nominalCellPx*2)); rc != C.GHOSTTY_SUCCESS {
		return fmt.Errorf("vt: resize %dx%d rc=%d", cols, rows, int32(rc))
	}
	t.cols, t.rows = cols, rows
	return nil
}

// Size 返回当前网格尺寸（vt 权威值，非调用方记账）。
func (t *Terminal) Size() (cols, rows uint16) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.h == nil {
		return 0, 0
	}
	var c, r C.uint16_t
	if C.ghostty_terminal_get(t.h, C.GHOSTTY_TERMINAL_DATA_COLS, unsafe.Pointer(&c)) != C.GHOSTTY_SUCCESS {
		return t.cols, t.rows
	}
	if C.ghostty_terminal_get(t.h, C.GHOSTTY_TERMINAL_DATA_ROWS, unsafe.Pointer(&r)) != C.GHOSTTY_SUCCESS {
		return t.cols, t.rows
	}
	return uint16(c), uint16(r)
}

// Modes 取模式位快照（逐项 ghostty_terminal_get + GhosttyTerminalModeConfig）。
// 拿不到的模式留 false——模式位只用于编码/显示，取不到不该让会话失败。
func (t *Terminal) Modes() Modes {
	t.mu.Lock()
	defer t.mu.Unlock()
	var m Modes
	if t.closed || t.h == nil {
		return m
	}
	// ⚠️ 枚举输出必须用 C 的枚举类型接：C 枚举是 int（4 字节），用 uint8_t 接会让库往
	// 1 字节的 Go 变量里写 4 字节，**静默踩坏相邻内存**（实测表现为 -race 下 GC 扫描崩）。
	var screen C.GhosttyTerminalScreen
	if C.ghostty_terminal_get(t.h, C.GHOSTTY_TERMINAL_DATA_ACTIVE_SCREEN, unsafe.Pointer(&screen)) == C.GHOSTTY_SUCCESS {
		m.Screen = Screen(screen)
	}
	var kitty C.uint8_t
	if C.ghostty_terminal_get(t.h, C.GHOSTTY_TERMINAL_DATA_KITTY_KEYBOARD_FLAGS, unsafe.Pointer(&kitty)) == C.GHOSTTY_SUCCESS {
		m.KittyFlags = uint8(kitty)
	}
	// modifyOtherKeys mode 2 是 vendor 补丁 0002 新增的**数据查询**（bool），不是 GHOSTTY_MODE_*。
	var mok C.bool
	if C.ghostty_terminal_get(t.h, C.GHOSTTY_TERMINAL_DATA_MODIFY_OTHER_KEYS, unsafe.Pointer(&mok)) == C.GHOSTTY_SUCCESS {
		m.ModifyOtherKeys = bool(mok)
	}
	m.CursorKeysApp = t.modeLocked(C.GHOSTTY_MODE_DECCKM)
	m.KeypadApp = t.modeLocked(C.GHOSTTY_MODE_KEYPAD_KEYS)
	m.BracketedPaste = t.modeLocked(C.GHOSTTY_MODE_BRACKETED_PASTE)
	m.FocusEvents = t.modeLocked(C.GHOSTTY_MODE_FOCUS_EVENT)
	m.MouseX10 = t.modeLocked(C.GHOSTTY_MODE_X10_MOUSE)
	m.MouseNormal = t.modeLocked(C.GHOSTTY_MODE_NORMAL_MOUSE)
	m.MouseButton = t.modeLocked(C.GHOSTTY_MODE_BUTTON_MOUSE)
	m.MouseAny = t.modeLocked(C.GHOSTTY_MODE_ANY_MOUSE)
	m.MouseSGR = t.modeLocked(C.GHOSTTY_MODE_SGR_MOUSE)
	m.MouseUTF8 = t.modeLocked(C.GHOSTTY_MODE_UTF8_MOUSE)
	m.MouseURXVT = t.modeLocked(C.GHOSTTY_MODE_URXVT_MOUSE)
	m.AltScroll = t.modeLocked(C.GHOSTTY_MODE_ALT_SCROLL)
	m.CursorVisible = t.modeLocked(C.GHOSTTY_MODE_CURSOR_VISIBLE)
	m.CursorBlink = t.modeLocked(C.GHOSTTY_MODE_CURSOR_BLINKING)
	m.Insert = t.modeLocked(C.GHOSTTY_MODE_INSERT)
	m.Origin = t.modeLocked(C.GHOSTTY_MODE_ORIGIN)
	m.Wraparound = t.modeLocked(C.GHOSTTY_MODE_WRAPAROUND)
	return m
}

// MouseTracking 报告是否有任何鼠标上报模式激活（含 X10）。
func (m Modes) MouseTracking() bool {
	return m.MouseX10 || m.MouseNormal || m.MouseButton || m.MouseAny
}

func (t *Terminal) modeLocked(mode C.GhosttyMode) bool {
	var v C.bool
	if !bool(C.tier_vt_mode_get(t.h, C.uint16_t(mode), &v)) {
		return false
	}
	return bool(v)
}

// Cursor 取光标快照（render state 的 CURSOR 聚合查询）。
func (t *Terminal) Cursor() Cursor {
	t.mu.Lock()
	defer t.mu.Unlock()
	var c Cursor
	if t.closed || t.rs == nil {
		return c
	}
	if rc := C.ghostty_render_state_update(t.rs, t.h); rc != C.GHOSTTY_SUCCESS {
		return c
	}
	var cur C.GhosttyRenderStateCursor
	C.tier_vt_cursor_init(&cur)
	if C.ghostty_render_state_get(t.rs, C.GHOSTTY_RENDER_STATE_DATA_CURSOR, unsafe.Pointer(&cur)) != C.GHOSTTY_SUCCESS {
		return c
	}
	if bool(cur.viewport_has_value) {
		c.X, c.Y = uint16(cur.viewport_x), uint16(cur.viewport_y)
		c.WideTail = bool(cur.wide_tail)
	}
	c.Visible = bool(cur.visible)
	c.Blinking = bool(cur.blinking)
	c.Password = bool(cur.password_input)
	c.Shape = CursorShape(cur.visual_style)
	return c
}

// Title 取终端标题（vt 从 OSC 0/2 解析）。未设置时返回空串。
//
// ⚠️ 检测与 surface 快照的标题**单一来源是 termScan**（design D1：跨 read 安全、已实战），
// 本方法只用于对照与诊断——不要把它接成第二条权威。
func (t *Terminal) Title() string {
	return t.stringData(C.GHOSTTY_TERMINAL_DATA_TITLE)
}

// Pwd 取当前工作目录（vt 从 OSC 7 解析）。未上报时返回空串（LIST JSON 的 cwd 字段来源）。
func (t *Terminal) Pwd() string {
	return t.stringData(C.GHOSTTY_TERMINAL_DATA_PWD)
}

func (t *Terminal) stringData(kind C.GhosttyTerminalData) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.h == nil {
		return ""
	}
	var s C.GhosttyString
	if C.ghostty_terminal_get(t.h, kind, unsafe.Pointer(&s)) != C.GHOSTTY_SUCCESS {
		return ""
	}
	if s.ptr == nil || s.len == 0 {
		return ""
	}
	return C.GoStringN((*C.char)(unsafe.Pointer(s.ptr)), C.int(s.len))
}

// PlainText 导出**整屏 + 回滚**的纯文本（软折行展开、行尾空白裁掉）。
// 这是检测引擎「屏幕尾部文本」腿的输入（term-agent-state 的检测输入契约）。
func (t *Terminal) PlainText() string { return t.format(true, true) }

// ViewportText 导出**不展开折行**的纯文本行（物理行，含回滚区），供按行切片的场景使用。
func (t *Terminal) ViewportText() string { return t.format(false, true) }

func (t *Terminal) format(unwrap, trim bool) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.h == nil {
		return ""
	}
	var opts C.GhosttyFormatterTerminalOptions
	C.tier_vt_formatter_plain(&opts, C.bool(unwrap), C.bool(trim))
	var f C.GhosttyFormatter
	if rc := C.ghostty_formatter_terminal_new(nil, &f, t.h, opts); rc != C.GHOSTTY_SUCCESS {
		return ""
	}
	defer C.ghostty_formatter_free(f)
	var buf *C.uint8_t
	var n C.size_t
	if rc := C.ghostty_formatter_format_alloc(f, nil, &buf, &n); rc != C.GHOSTTY_SUCCESS {
		return ""
	}
	defer C.ghostty_free(nil, buf, n)
	if buf == nil || n == 0 {
		return ""
	}
	return string(C.GoBytes(unsafe.Pointer(buf), C.int(n)))
}

// Snapshot 编码当前完整状态（ghostty_snapshot_encode_alloc）。
//
// 用途：任务 1.4 的序列化选型对照（snapshot API vs 自定义 cell 行编码），以及把屏态
// 整体搬运（例如测试里做往返一致性断言）。surface 的 SNAPSHOT 帧**不一定**用它——
// 选型结论见 1.4。
func (t *Terminal) Snapshot() ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.h == nil {
		return nil, errClosed
	}
	var buf *C.uint8_t
	var n C.size_t
	if rc := C.ghostty_snapshot_encode_alloc(t.h, nil, &buf, &n); rc != C.GHOSTTY_SUCCESS {
		return nil, fmt.Errorf("vt: snapshot_encode rc=%d", int32(rc))
	}
	defer C.ghostty_free(nil, buf, n)
	if buf == nil || n == 0 {
		return nil, nil
	}
	return C.GoBytes(unsafe.Pointer(buf), C.int(n)), nil
}

// RestoreSnapshot 从快照字节还原一个新终端（解码往返测试与诊断用）。
func RestoreSnapshot(data []byte) (*Terminal, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("vt: 空快照")
	}
	var dec C.GhosttySnapshotDecoder
	if rc := C.ghostty_snapshot_decoder_new_buf(nil, &dec,
		(*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data))); rc != C.GHOSTTY_SUCCESS {
		return nil, fmt.Errorf("vt: snapshot_decoder_new rc=%d", int32(rc))
	}
	defer C.ghostty_snapshot_decoder_free(dec)
	var h C.GhosttyTerminal
	if rc := C.ghostty_snapshot_decoder_decode(dec, &h); rc != C.GHOSTTY_SUCCESS {
		return nil, fmt.Errorf("vt: snapshot_decoder_decode rc=%d", int32(rc))
	}
	var rs C.GhosttyRenderState
	if rc := C.ghostty_render_state_new(nil, &rs); rc != C.GHOSTTY_SUCCESS {
		C.ghostty_terminal_free(h)
		return nil, fmt.Errorf("vt: render_state_new rc=%d", int32(rc))
	}
	cols, rows := terminalSize(h)
	t := &Terminal{h: h, rs: rs, cols: cols, rows: rows}
	t.regID = registerTerminal(t)
	C.tier_vt_set_write_pty(t.h, C.uintptr_t(t.regID))
	if err := t.initRenderContainers(); err != nil {
		C.ghostty_render_state_free(rs)
		C.ghostty_terminal_free(h)
		return nil, err
	}
	return t, nil
}

func terminalSize(h C.GhosttyTerminal) (uint16, uint16) {
	var c, r C.uint16_t
	C.ghostty_terminal_get(h, C.GHOSTTY_TERMINAL_DATA_COLS, unsafe.Pointer(&c))
	C.ghostty_terminal_get(h, C.GHOSTTY_TERMINAL_DATA_ROWS, unsafe.Pointer(&r))
	return uint16(c), uint16(r)
}

// ScrollbackRows 当前保留的回滚行数（诊断/观测用；内存预算口径见 design D1）。
func (t *Terminal) ScrollbackRows() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.h == nil {
		return 0
	}
	var n C.size_t
	if C.ghostty_terminal_get(t.h, C.GHOSTTY_TERMINAL_DATA_SCROLLBACK_ROWS, unsafe.Pointer(&n)) != C.GHOSTTY_SUCCESS {
		return 0
	}
	return int(n)
}

// PwdPath 把 OSC 7 的原始值（URI 形态，如 file://host/Users/x/proj）剥成文件系统路径。
//
// 为什么单独一个函数：vt 的 PWD 查询给的是**原始 OSC 7 值**（含 scheme 与 host，实测如此），
// 而 LIST JSON 的 cwd 字段与 App 列表要显示的是路径（任务 4.8 的消费方）。
// 剥不出路径（空值/非 file scheme/畸形）时返回空串——缺省不显示，而不是显示一段 URI。
func PwdPath(raw string) string {
	if raw == "" {
		return ""
	}
	if !strings.HasPrefix(raw, "file://") {
		return ""
	}
	rest := strings.TrimPrefix(raw, "file://")
	// file://<host>/<path>：host 之后第一个 '/' 起才是路径；file:///path 时 host 为空。
	i := strings.IndexByte(rest, '/')
	if i < 0 {
		return ""
	}
	path := rest[i:]
	if path == "" {
		return ""
	}
	// 百分号转义（OSC 7 规范要求路径按 URI 转义）。
	if strings.ContainsRune(path, '%') {
		if unescaped, err := url.PathUnescape(path); err == nil {
			return unescaped
		}
	}
	return path
}
