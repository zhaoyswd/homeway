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
	// base/hasBase 是**上一次成功下发**（快照或差分）的屏态基线。
	//
	// 为什么需要它（2026-09-24 评审整改，P0）：光标移动、鼠标上报模式开关（?1000h）、
	// DECTCEM 光标显隐、DECCKM、括号粘贴这些**都不产生脏行**——只看「有没有脏行」会
	// 一个字节都不发（真机后果：方向键/行内编辑光标不动；触摸路由按旧模式位判，
	// TUI 开鼠标上报后手势一直错到下一次行变化）。有了基线，本拍与上一拍比光标/模式位/
	// 回滚条，任一变化就发帧（差分体已带这三样）。
	base    SurfaceState
	hasBase bool
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

// Terminal 暴露底层 vt；无 vt 时返回 nil。
//
// 只允许 **cgo 侧**代码（测试）用：off 变体里 pkg/term/vt 没有 Terminal 类型，共享代码
// 点名它就编不过——生产路径一律走下面的 facade（ScreenText/Pwd/PlainText/…）。
func (s *sessionVT) Terminal() *vt.Terminal {
	if s == nil {
		return nil
	}
	return s.t
}

// ScreenText 当前视口纯文本（检测引擎的一屏输入；无 vt 返回空串）。
func (s *sessionVT) ScreenText() string {
	if !s.Available() {
		return ""
	}
	return s.t.ScreenText()
}

// Pwd vt 侧解析到的 shell 工作目录原始值（OSC 7；配 vtPwdPath 剥成路径）。
func (s *sessionVT) Pwd() string {
	if !s.Available() {
		return ""
	}
	return s.t.Pwd()
}

// PlainText 整屏纯文本（explain 的屏幕证据；无 vt 返回空串）。
func (s *sessionVT) PlainText() string {
	if !s.Available() {
		return ""
	}
	return s.t.PlainText()
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

// SurfaceCursor 光标快照（含形状与可见性）。差分帧（任务 3.10）与快照帧共用它。
func (s *sessionVT) SurfaceCursor() surfaceCursor {
	if !s.Available() {
		return surfaceCursor{}
	}
	return surfaceCursorOf(s.t.Cursor())
}

// surfaceModesOf 把 vt 的模式位打成 wire 形态（**单一映射**：会话下发与 golden 样例共用，
// 与 surfaceCursorOf 同款理由——两处各按一套位映射的话 golden 就白做了）。
func surfaceModesOf(m vt.Modes) (modes uint32, kitty, misc uint8) {
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

// SurfaceModes 模式位（legacy termMode* 布局，客户端已有这套位）+ kitty/modifyOtherKeys 扩展位。
func (s *sessionVT) SurfaceModes() (modes uint32, kitty, misc uint8) {
	if !s.Available() {
		return 0, 0, 0
	}
	return surfaceModesOf(s.t.Modes())
}

// SurfaceAltScreen 报告当前是否备用屏（差分降级与 FETCH-ROWS 抑制都要它）。
func (s *sessionVT) SurfaceAltScreen() bool {
	if !s.Available() {
		return false
	}
	return s.t.Modes().Screen == vt.ScreenAlternate
}

// SurfaceStateNow 读当前屏态（锁内调用；不消费脏状态）。
func (s *sessionVT) SurfaceStateNow() SurfaceState {
	if !s.Available() {
		return SurfaceState{}
	}
	modes, _, _ := s.SurfaceModes()
	sb := s.t.Scrollbar()
	return SurfaceState{
		Cursor: s.t.Cursor(),
		Modes:  modes,
		Total:  sb.Total,
		Offset: sb.Offset,
		Len:    uint16(sb.Len),
		Alt:    modes&termModeAltScreen != 0,
	}
}

// CommitSurfaceBaseline 在一次快照/差分**成功下发后**记基线（调用方锁内调用）。
func (s *sessionVT) CommitSurfaceBaseline(st SurfaceState) {
	s.base, s.hasBase = st, true
}

// ResetSurfaceBaseline 清基线（换腿/新 attach 时用：新腿从全量快照开始）。
func (s *sessionVT) ResetSurfaceBaseline() {
	s.base, s.hasBase = SurfaceState{}, false
}

// SurfaceUpdate 取本拍要发的差分（锁内调用）。
//
// 返回：
//   - enc/count：脏行 patch（**count 可以为 0**：只有光标/模式位/回滚条变了——差分体里
//     这三样都带，所以「空行 patch」是一帧合法且有意义的更新）；
//   - st：本拍屏态（发送成功后调 CommitSurfaceBaseline(st)）；
//   - needFull：必须走全量（首次基线缺失 / 备用屏进出——离开备用屏要重建主屏镜像）；
//   - changed：本拍有没有要发的东西（false = 整拍跳过）。
//
// **不消费脏状态**：调用方在帧成功下发后才调 SurfaceClean（锁内取快照、锁外编码发送，
// 中途失败则下一拍重来——宁可重复下发，不能半新半旧，design D2 的背压规则同理）。
//
// ⚠️ 2026-09-24 整改（评审 P0）：旧实现把 `Update()==DirtyFull` 直接判为「发全量」，而
// **滚动（最常见的输出形态）正是 DirtyFull**（整屏行都移动了）⇒ 每行输出都发带 10 视口
// 镜像的全量快照（实测 ≈1.4KB/行 vs ANSI ≈20B/行）。现在 DirtyFull 也走行差分（全视口行，
// 不带镜像）——全量只留给「语义上真的需要重建」的场合（首次/备用屏进出/裁剪/背压/客户端请求）。
// 同理删掉了「差分体积 ≥ 整屏编码 ⇒ 降级」的旧自限：那条判据拿**不含镜像的视口编码**当基准，
// 而实际全量还要加镜像 ⇒ 视口稀疏时把几乎所有更新都误判成「差分更贵」。
func (s *sessionVT) SurfaceUpdate() (encoded []byte, count uint16, st SurfaceState, needFull, changed bool) {
	if !s.Available() {
		return nil, 0, SurfaceState{}, true, true
	}
	s.t.Update() // 把 render state 拉到最新；DirtyFull 时 DirtyRows 会给出全部视口行
	dirty := s.t.DirtyRows()
	st = s.SurfaceStateNow()
	if !s.hasBase {
		return nil, 0, st, true, true
	}
	if st.Alt != s.base.Alt {
		// 备用屏进出：整屏语义变了（且「离开备用屏」要求重建主屏镜像）⇒ 全量。
		return nil, 0, st, true, true
	}
	cursorChanged := st.Cursor != s.base.Cursor
	modesChanged := st.Modes != s.base.Modes
	scrollChanged := st.Total != s.base.Total || st.Offset != s.base.Offset || st.Len != s.base.Len
	if len(dirty) == 0 && !cursorChanged && !modesChanged && !scrollChanged {
		return nil, 0, st, false, false
	}
	return vt.EncodeRows(dirty), uint16(len(dirty)), st, false, true
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
		if !ev.Paste || !s.bracketedPaste() {
			return []byte(ev.Text)
		}
		// 括号粘贴：开/闭标记只在整段粘贴的首/末片各一次（跨帧分片见 textPaste*Bit 的注释）。
		return vt.EncodePastePart(ev.Text, true, !ev.PasteCont, !ev.PasteMore)
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
