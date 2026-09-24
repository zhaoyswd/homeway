//go:build !windows && (darwin || linux) && (amd64 || arm64) && cgo

// term_vt.go — 会话屏态的服务端 vt（任务 1.3；本文件只在带 vt 的构建里编）。
//
// 会话屏态 vt 化（design D1）：PTY 输出在 pump 里**同时**喂 ring（legacy 回放源 + 诊断）与
// 这里的 vt（surface/检测的唯一真源）。vt 失败或 `HOMEWAY_TERM_VT=off` ⇒ 该会话 legacy-only，
// 终端功能照常（MUST NOT 影响既有 legacy 会话）。
//
// 锁的纪律（design D1）：本文件的方法都在**会话锁内**被调用；surface 投递要求「锁内只取脏行
// 快照、锁外编码/发送」——那一步在任务 2.x 的投递路径上做，不在这里。
package term

import (
	"errors"
	"os"
	"strings"

	"github.com/zhaoyswd/homeway/pkg/term/vt"
)

// errVTUnavailable：本会话没有可用的服务端 vt（环境变量关闭 / 创建失败）。
var errVTUnavailable = errors.New("term: 服务端 vt 不可用")

// sessionVT 一个会话的服务端 vt（薄包装：让 service.go 不依赖构建标签）。
type sessionVT struct {
	t *vt.Terminal
}

// vtGloballyDisabled 报告 `HOMEWAY_TERM_VT=off`（全局逃生口：整服务退化为 legacy）。
func vtGloballyDisabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("HOMEWAY_TERM_VT")), "off")
}

// newSessionVT 建一个会话的 vt；失败返回 error（调用方降级为 legacy-only + 告警）。
func newSessionVT(cfg termConfig, cols, rows uint16) (*sessionVT, error) {
	if vtGloballyDisabled() {
		return nil, errVTUnavailable
	}
	t, err := vt.New(cols, rows, cfg.scrollbackLines)
	if err != nil {
		return nil, err
	}
	return &sessionVT{t: t}, nil
}

// Write 把一批 PTY 输出喂进 vt（与 ring 的写入同在会话锁内）。
func (s *sessionVT) Write(p []byte) {
	if s == nil || s.t == nil {
		return
	}
	s.t.Write(p)
}

// Resize 让 vt 跟着尺寸变化重排（回滚重排；surface 的 Replace 语义依赖它）。
func (s *sessionVT) Resize(cols, rows uint16) {
	if s == nil || s.t == nil {
		return
	}
	_ = s.t.Resize(cols, rows)
}

// Close 释放 vt（会话收尾；幂等）。
func (s *sessionVT) Close() {
	if s == nil || s.t == nil {
		return
	}
	s.t.Close()
}

// SetResponseSink 装「vt 写回 PTY」的接收方（DA1/DSR/OSC 10-11 的应答都走它）。
//
// 线程纪律：回调在 vt 的锁内**同步**触发 ⇒ 接收方只做「写 ptmx」这类无依赖动作，
// 绝不能再调回本 Terminal（自锁）。
func (s *sessionVT) SetResponseSink(fn func([]byte)) {
	if s == nil || s.t == nil {
		return
	}
	s.t.SetResponseSink(fn)
}

// RegistryID 本会话 vt 的回调注册表 id（0 = 无 vt）。
func (s *sessionVT) RegistryID() uintptr {
	if !s.Available() {
		return 0
	}
	return s.t.RegistryID()
}

// EnableClipboardWrite 装「程序写剪贴板」的转发（OSC 52 → CLIPBOARD 帧）。
//
// 转发器是**进程级**的（上游回调不带 per-terminal 上下文，只有 userdata id），
// 所以注册一次、按 id 分派到具体会话（见 pkg/term 的 clipboardRouter）。
func (s *sessionVT) EnableClipboardWrite() {
	if !s.Available() {
		return
	}
	s.t.EnableClipboardWrite()
}

// EnableClipboardRead 装「程序读剪贴板」的转发（OSC 52 "?" → 从会话缓存应答，2.7 的读方向）。
func (s *sessionVT) EnableClipboardRead() {
	if !s.Available() {
		return
	}
	s.t.EnableClipboardRead()
}

// SetTheme 把客户端上报的默认前景/背景交给 vt（OSC 10/11 查询按它应答，design D4）。
func (s *sessionVT) SetTheme(fg, bg [3]uint8) {
	if s == nil || s.t == nil {
		return
	}
	s.t.SetDefaultColors(fg, bg)
}

// Terminal 暴露底层 vt 给 surface/检测路径（任务 2.x/4.x 用）；无 vt 时返回 nil。
func (s *sessionVT) Terminal() *vt.Terminal {
	if s == nil {
		return nil
	}
	return s.t
}

// vtPwdPath 把 vt 的 OSC 7 原始值剥成文件系统路径（无 vt 的构建里恒为空）。
func vtPwdPath(raw string) string { return vt.PwdPath(raw) }

// surfaceCapable 报告本构建/本服务能否提供 surface（有服务端 vt 才可能）。
func surfaceCapable() bool { return !vtGloballyDisabled() }

// ---- surface 载荷的读取面（任务 2.3–2.7）----
//
// 这一层是 term 包与 vt 包的**唯一接缝**：surface 的投递/背压/线格式全在 term 包，
// vt 只负责「给我当前屏态」。这样 surface 代码不必带构建标签——无 vt 的构建里这些方法
// 返回 nil/零值 + Available()=false，surface 腿在协商阶段就被挡掉（明确错误码，不静默降级）。

// Available 报告本会话有没有服务端 vt。
func (s *sessionVT) Available() bool { return s != nil && s.t != nil }

// SurfaceGrid 当前视口的网格（cell 行编码）。
func (s *sessionVT) SurfaceGrid(cols, rows uint16) []byte {
	if !s.Available() {
		return nil
	}
	rs := s.t.Rows()
	if len(rs) == 0 {
		return nil
	}
	return vt.EncodeGrid(cols, rows, rs)
}

// SurfaceMirror 回滚镜像窗口（最多 viewports 个视口的行；备用屏/无回滚时为空）。
func (s *sessionVT) SurfaceMirror(cols, rows uint16, viewports int) []byte {
	if !s.Available() {
		return nil
	}
	above := int(rows) * viewports
	rs := s.t.MirrorRows(above)
	if len(rs) == 0 {
		return nil
	}
	return vt.EncodeGrid(cols, uint16(len(rs)), rs)
}

// surfaceCursorOf 把 vt 的光标快照打成 wire 形态。
//
// 单独抽出来是为了**单一映射**：会话下发（SurfaceCursor）与 golden 样例生成都用它，
// 否则「样例里的光标」与「线上发出去的光标」可能各按一套 flag 位映射，golden 就白做了。
func surfaceCursorOf(c vt.Cursor) surfaceCursor {
	out := surfaceCursor{X: c.X, Y: c.Y, Shape: uint8(c.Shape)}
	if c.Visible {
		out.Flags |= cursorFlagVisible
	}
	if c.Blinking {
		out.Flags |= cursorFlagBlinking
	}
	if c.WideTail {
		out.Flags |= cursorFlagWideTail
	}
	if c.Password {
		out.Flags |= cursorFlagPassword
	}
	return out
}

// SurfaceCursor 光标快照（含形状与可见性）。差分帧（任务 3.10）与快照帧共用它。
func (s *sessionVT) SurfaceCursor() surfaceCursor {
	if !s.Available() {
		return surfaceCursor{}
	}
	return surfaceCursorOf(s.t.Cursor())
}

// SurfaceModes 模式位（legacy termMode* 布局，客户端已有这套位）+ kitty/modifyOtherKeys 扩展位。
func (s *sessionVT) SurfaceModes() (modes uint32, kitty, misc uint8) {
	if !s.Available() {
		return 0, 0, 0
	}
	m := s.t.Modes()
	if m.CursorKeysApp {
		modes |= termModeDECCKM
	}
	if m.MouseX10 || m.MouseNormal {
		modes |= termModeMouse1000
	}
	if m.MouseButton {
		modes |= termModeMouse1002
	}
	if m.MouseAny {
		modes |= termModeMouse1003
	}
	if m.MouseSGR {
		modes |= termModeMouse1006
	}
	if m.FocusEvents {
		modes |= termModeFocus
	}
	if m.BracketedPaste {
		modes |= termModeBracketed
	}
	if m.Screen == vt.ScreenAlternate {
		modes |= termModeAltScreen
	}
	if m.ModifyOtherKeys {
		misc |= miscModifyOtherKeys
	}
	return modes, m.KittyFlags, misc
}

// SurfaceAltScreen 报告当前是否备用屏（差分降级与 FETCH-ROWS 抑制都要它）。
func (s *sessionVT) SurfaceAltScreen() bool {
	if !s.Available() {
		return false
	}
	return s.t.Modes().Screen == vt.ScreenAlternate
}

// SurfaceDiff 取本拍的脏行 patch。full=true 表示「别发差分，发全量」（全局脏/降级）。
//
// **不消费脏状态**：调用方在差分成功下发后才调 SurfaceClean（锁内取快照、锁外编码发送，
// 中途失败则下一拍重来——宁可重复下发，不能半新半旧，design D2 的背压规则同理）。
func (s *sessionVT) SurfaceDiff(cols, rows uint16) (encoded []byte, count uint16, full bool) {
	if !s.Available() {
		return nil, 0, true
	}
	if d := s.t.Update(); d == vt.DirtyFull {
		return nil, 0, true
	}
	dirty := s.t.DirtyRows()
	if len(dirty) == 0 {
		return nil, 0, false
	}
	// 差分自限：条数超过整屏、或编码体积不小于整屏 ⇒ 直接降级全量（协议自己兜底）。
	if len(dirty) >= int(rows) {
		return nil, 0, true
	}
	enc := vt.EncodeRows(dirty)
	grid := s.t.Rows()
	if len(grid) > 0 && len(enc) >= len(vt.EncodeGrid(cols, rows, grid)) {
		return nil, 0, true
	}
	return enc, uint16(len(dirty)), false
}

// SurfaceClean 在差分/快照**成功下发后**消费脏标记。
func (s *sessionVT) SurfaceClean() {
	if !s.Available() {
		return
	}
	s.t.Clean()
}

// SurfaceRowsAt 取绝对行号区间 [from, from+count) 的行（FETCH-ROWS 应答）。
//
// 行号空间 = 滚动条的 offset 空间（与镜像窗口边界天然对齐）。取不到返回 nil。
func (s *sessionVT) SurfaceRowsAt(from uint64, count int) []byte {
	if !s.Available() || count <= 0 {
		return nil
	}
	rs := s.t.RowsAt(from, count)
	if len(rs) == 0 {
		return nil
	}
	return vt.EncodeRows(rs)
}

// SurfaceScrollbar 回滚条状态（任务 3.3）：客户端用它把镜像窗口/按需拉取锚到绝对行号空间，
// 也用它算「距缓存顶还有多远」来触发预取。行号空间 = [0, Total)，视口占 [Offset, Offset+Len)。
func (s *sessionVT) SurfaceScrollbar() vt.Scrollbar {
	if !s.Available() {
		return vt.Scrollbar{}
	}
	return s.t.Scrollbar()
}

// SurfaceTitle 标题（单一来源是 termScan，见 design D1——这里只是把快照要的字段接出来）。
func (s *sessionVT) SurfaceTitle(fallback string) string { return fallback }

// EncodeInput 把抽象输入按 vt 的**真实模式**编码成转义序列（任务 2.7 的核心）。
//
// 返回 nil 表示「本事件在当前模式下无输出」（例如没开鼠标上报时的鼠标事件）——这是正常情况，
// 不是错误：上游编码器自己会判模式。
func (s *sessionVT) EncodeInput(ev inputEvent) []byte {
	if !s.Available() {
		return nil
	}
	switch ev.Kind {
	case inputKindKey:
		return s.t.EncodeKey(vt.KeyEvent{
			Key:    vt.Key(ev.Key),
			Action: vt.KeyAction(ev.Action),
			Mods:   vt.Mods(ev.Mods),
			Text:   ev.Text,
		})
	case inputKindText:
		return vt.EncodePaste(ev.Text, ev.Paste && s.bracketedPaste())
	case inputKindMouse:
		return s.t.EncodeMouse(vt.MouseEvent{
			Action: vt.MouseAction(ev.Action),
			Button: vt.MouseButton(ev.Button),
			Mods:   vt.Mods(ev.Mods),
			X:      ev.X,
			Y:      ev.Y,
		})
	case inputKindFocus:
		if !s.t.Modes().FocusEvents {
			return nil // 程序没开焦点上报：写进去就是垃圾字节
		}
		return vt.EncodeFocus(ev.Gained)
	}
	return nil
}

// bracketedPaste 当前是否开了括号粘贴（粘贴包装按模式走）。
func (s *sessionVT) bracketedPaste() bool { return s.t.Modes().BracketedPaste }

// installClipboardForwarder 进程级装一次剪贴板转发器（写方向经通道投递，读方向同步查缓存）。
func installClipboardForwarder() {
	vt.SetClipboardWriteForwarder(clipboardRouter)
	vt.SetClipboardReadForwarder(clipboardReadRouter)
}

// ---- 给 golden 生成器用的薄包装（测试文件不能直接用 cgo 包，见 *_golden_test.go）----

// vtNew 建一个仿真终端（golden 生成/宿主对照用）。
func vtNew(cols, rows uint16, scrollback int) (*vt.Terminal, error) {
	return vt.New(cols, rows, scrollback)
}

// vtEncodeGrid 按 cell 行编码封网格（与服务端下发同一套编码）。
func vtEncodeGrid(cols, rows uint16, rs []vt.Row) []byte { return vt.EncodeGrid(cols, rows, rs) }

// vtDirtyRows 取本拍的脏行（golden 生成差分样例用；与 flushSurface 同一条路径）。
func vtDirtyRows(t *vt.Terminal) []vt.Row {
	t.Update()
	return t.DirtyRows()
}

// vtEncodeRows 只编行序列（差分帧的载荷）。
func vtEncodeRows(rs []vt.Row) []byte { return vt.EncodeRows(rs) }
