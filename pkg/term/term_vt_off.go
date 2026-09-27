//go:build !windows && !((darwin || linux) && (amd64 || arm64) && cgo)

// term_vt_off.go — 不带服务端 vt 的构建变体（design D7：armv7 / CGO_ENABLED=0 等）。
//
// 与 pkg/term/vt 的 vt_unsupported.go 同款约定：不提供「假装能用」的实现，而是让「没有 vt」
// 这件事显式可查——会话照常起（legacy 原始字节模式），只是没有 surface 与屏幕证据。
//
// 方法集必须与带 vt 的 term_vt.go **一一对应**：surface 的共享代码（term_surface*.go）不带
// 构建标签，靠这层 facade 在两种变体下都可编。这里全部返回「没有」值；surface 腿在协商
// 阶段就被 surfaceCapable() 挡掉，这些零值不会被真正消费。注意这里**没有** Terminal()：
// off 变体里 pkg/term/vt 没有 Terminal 类型，点名它的代码都该待在 cgo 侧或走 facade。
package term

import (
	"errors"

	"github.com/zhaoyswd/homeway/pkg/term/vt"
)

// errVTUnavailable：本构建不带服务端 vt。
var errVTUnavailable = errors.New("term: 本构建不带服务端 vt（需要 darwin/linux + amd64/arm64 + cgo）")

// sessionVT 空实现：所有操作都是无操作。
type sessionVT struct{}

// vtGloballyDisabled 在无 vt 的构建里恒为真（等价于全局关闭）。
func vtGloballyDisabled() bool { return true }

func newSessionVT(cfg termConfig, cols, rows uint16) (*sessionVT, error) {
	_, _, _ = cfg, cols, rows
	return nil, errVTUnavailable
}

func (s *sessionVT) Write(p []byte)           {}
func (s *sessionVT) Resize(cols, rows uint16) {}
func (s *sessionVT) Close()                   {}

// vtPwdPath 在无 vt 的构建里恒为空（没有屏态就没有 OSC 7 解析）。
func vtPwdPath(raw string) string { _ = raw; return "" }

// surfaceCapable 在无 vt 的构建里恒为 false（surface 的全部载荷都从 vt 派生）。
func surfaceCapable() bool { return false }

// ---- 会话/检测/输入面（无 vt 的构建：全部不可用）----

func (s *sessionVT) Available() bool { return false }

// RegistryID 回调注册表 id 恒为 0（注册表里不会有本会话，回调永远不会被分派到）。
func (s *sessionVT) RegistryID() uintptr { return 0 }

// SetResponseSink 无 vt：没有 DA1/DSR/OSC 查询应答源。
func (s *sessionVT) SetResponseSink(fn func([]byte)) { _ = fn }

// EnableClipboardWrite/EnableClipboardRead 无 vt：没有 OSC 52 转发可装。
func (s *sessionVT) EnableClipboardWrite() {}
func (s *sessionVT) EnableClipboardRead()  {}

// SetTheme 无 vt：没有 OSC 10/11 应答源。
func (s *sessionVT) SetTheme(fg, bg [3]uint8) { _, _ = fg, bg }

// ScreenText/Pwd/PlainText 无 vt：没有屏幕与工作目录可取（检测与 cwd 都按「没有」处理）。
func (s *sessionVT) ScreenText() string { return "" }
func (s *sessionVT) Pwd() string        { return "" }
func (s *sessionVT) PlainText() string  { return "" }

// EncodeInput 无 vt：没有「真实模式」可依，任何事件都无输出。
func (s *sessionVT) EncodeInput(ev inputEvent) []byte { _ = ev; return nil }

// ---- surface 载荷的读取面（无 vt 的构建：全部不可用）----
//
// 与带 vt 的版本同签名，值全部是「没有」。

func (s *sessionVT) SurfaceGrid(cols, rows uint16) []byte           { return nil }
func (s *sessionVT) SurfaceMirror(cols, rows uint16, vp int) []byte { return nil }
func (s *sessionVT) SurfaceCursor() surfaceCursor                   { return surfaceCursor{} }
func (s *sessionVT) SurfaceModes() (uint32, uint8, uint8)           { return 0, 0, 0 }
func (s *sessionVT) SurfaceAltScreen() bool                         { return false }
func (s *sessionVT) SurfaceStateNow() SurfaceState                  { return SurfaceState{} }
func (s *sessionVT) CommitSurfaceBaseline(st SurfaceState)          { _ = st }
func (s *sessionVT) ResetSurfaceBaseline()                          {}
func (s *sessionVT) SurfaceUpdate() ([]byte, uint16, SurfaceState, bool, bool) {
	return nil, 0, SurfaceState{}, true, true
}
func (s *sessionVT) SurfaceScrollbar() vt.Scrollbar              { return vt.Scrollbar{} }
func (s *sessionVT) SurfaceClean()                               {}
func (s *sessionVT) SurfaceRowsAt(from uint64, count int) []byte { return nil }
func (s *sessionVT) SurfaceTitle(fallback string) string         { return fallback }

// installClipboardForwarder 在无 vt 的构建里是空操作（注册表不存在 ⇒ 剪贴板回调不会触发）。
func installClipboardForwarder() {}
