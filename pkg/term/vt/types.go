// types.go — vt 的**纯数据形状**（无行为、无 cgo，故意不带构建标签）。
//
// surface 的共享面（term 包的 !windows 文件：term_surface*.go、term_vt_off.go）在
// cgo 与非 cgo 两个构建变体里都要引用这些类型（SurfaceState 的字段、facade 方法的
// 参数/返回值），所以它们必须两种变体都能编。行为（Terminal 及其方法）仍在 cgo 侧
// 文件（vt.go/render.go/mirror.go）。
package vt

// CursorShape 是光标形状（render state 的 CURSOR_VISUAL_STYLE）。
type CursorShape uint8

const (
	CursorBar         CursorShape = 0 // DECSCUSR 5/6
	CursorBlock       CursorShape = 1 // DECSCUSR 1/2
	CursorUnderline   CursorShape = 2 // DECSCUSR 3/4
	CursorBlockHollow CursorShape = 3
)

// Cursor 是光标快照。X/Y 是**视口**坐标（render state 口径，回滚偏移已折算）。
type Cursor struct {
	X, Y     uint16
	Visible  bool
	Blinking bool
	Password bool
	WideTail bool
	Shape    CursorShape
}

// Scrollbar 是终端的可滚动区域状态（滚动条口径：total/offset/len 单位都是行）。
type Scrollbar struct {
	Total  uint64
	Offset uint64
	Len    uint64
}

// AtBottom 报告视口是否贴着底部（= 跟随输出）。
func (s Scrollbar) AtBottom() bool { return s.Offset+s.Len >= s.Total }
