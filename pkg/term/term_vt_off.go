//go:build !windows && !((darwin || linux) && (amd64 || arm64) && cgo)

// term_vt_off.go — 不带服务端 vt 的构建变体（design D7：armv7 / CGO_ENABLED=0 等）。
//
// 与 pkg/term/vt 的 vt_unsupported.go 同款约定：不提供「假装能用」的实现，而是让「没有 vt」
// 这件事显式可查——会话照常起（legacy 原始字节模式），只是没有 surface 与屏幕证据。
package term

import (
	"errors"

	"github.com/zhaoyswd/homeway/pkg/term/vt"
)

// errVTUnavailable：本构建不带服务端 vt。
var errVTUnavailable = errors.New("term: 本构建不带服务端 vt（需要 darwin/linux + amd64/arm64 + cgo）")

// sessionVT 空实现：所有操作都是无操作，Terminal() 恒返回 nil。
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

// ---- surface 载荷的读取面（无 vt 的构建：全部不可用）----
//
// 与带 vt 的版本同签名，值全部是「没有」。surface 腿在协商阶段就被 surfaceCapable() 挡掉，
// 所以这些零值不会被真正消费——保留它们只是让 surface 代码不必带构建标签。

func (s *sessionVT) Available() bool                                { return false }
func (s *sessionVT) SurfaceGrid(cols, rows uint16) []byte           { return nil }
func (s *sessionVT) SurfaceMirror(cols, rows uint16, vp int) []byte { return nil }
func (s *sessionVT) SurfaceCursor() surfaceCursor                   { return surfaceCursor{} }
func (s *sessionVT) SurfaceModes() (uint32, uint8, uint8)           { return 0, 0, 0 }
func (s *sessionVT) SurfaceAltScreen() bool                         { return false }
func (s *sessionVT) SurfaceDiff(cols, rows uint16) ([]byte, uint16, bool) {
	return nil, 0, true
}
func (s *sessionVT) SurfaceClean()                               {}
func (s *sessionVT) SurfaceRowsAt(from uint64, count int) []byte { return nil }
func (s *sessionVT) SurfaceTitle(fallback string) string         { return fallback }

// clipboardReadRouter 在无 vt 的构建里恒无内容（不会有回调）。
func clipboardReadRouter(id uintptr, location int) (string, bool) { return "", false }

// installClipboardForwarder 在无 vt 的构建里是空操作。
func installClipboardForwarder() {}
