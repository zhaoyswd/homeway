//go:build (darwin || linux) && (amd64 || arm64) && cgo

// input.go — 输入编码（任务 1.2 的「key/mouse/focus 编码」一项）。
//
// 核心价值（design D4）：**转义序列由服务端按 vt 当前真实模式产出**，客户端只上行抽象事件
// （键/文本/滚轮/焦点）。客户端 vt 退役后，kitty 键盘协议、modifyOtherKeys、鼠标上报格式、
// 括号粘贴这些模式全都只存在于出口这一份 vt 里——编码不再有两份实现可以漂移。
//
// 键码表口径 = vt 的 W3C UI Events code 枚举（GHOSTTY_KEY_*）；两仓共用的 u16 wire 键码表
// （任务 2.7/3.4）映射到这里的 Key 值。
package vt

import "unsafe"

/*
#cgo CFLAGS: -I${SRCDIR} -I${SRCDIR}/../../../third_party/libghostty-vt/include
#include <stdlib.h>
#include "helpers.h"
*/
import "C"

// Key 是键码（vt 的 W3C UI Events code 口径，GHOSTTY_KEY_* 的值）。
type Key uint16

// KeyAction 按键动作（GHOSTTY_KEY_ACTION_*）。
type KeyAction uint8

const (
	KeyRelease KeyAction = 0
	KeyPress   KeyAction = 1
	KeyRepeat  KeyAction = 2
)

// Mods 修饰符位掩码（与 GHOSTTY_MODS_* 同值，便于直接对照上游头文件）。
type Mods uint16

const (
	ModShift  Mods = 1 << 0
	ModCtrl   Mods = 1 << 1
	ModAlt    Mods = 1 << 2
	ModSuper  Mods = 1 << 3
	ModCapsLk Mods = 1 << 4
	ModNumLk  Mods = 1 << 5
	ModShiftL Mods = 1 << 6 // 仅当 ModShift 置位时有意义
	ModCtrlL  Mods = 1 << 7
	ModAltL   Mods = 1 << 8
	ModSuperL Mods = 1 << 9
)

// KeyEvent 一次抽象按键上行。
type KeyEvent struct {
	Key    Key
	Action KeyAction
	Mods   Mods
	// Text 是平台产出的 UTF-8 文本（软键盘/IME 上屏的字符；可空）。
	Text string
	// UnshiftedCodepoint 是该键在未按 Shift 时的码点（kitty 协议要用）。
	UnshiftedCodepoint uint32
	// Composing 表示该事件来自 IME 组段过程中（组段中的键不该被当成提交文本）。
	Composing bool
}

// MouseAction 鼠标动作（GHOSTTY_MOUSE_ACTION_*）。
type MouseAction uint8

const (
	MousePress   MouseAction = 0
	MouseRelease MouseAction = 1
	MouseMotion  MouseAction = 2
)

// MouseButton 鼠标按钮（GHOSTTY_MOUSE_BUTTON_*）。
type MouseButton uint8

const (
	MouseButtonUnknown MouseButton = 0
	MouseLeft          MouseButton = 1
	MouseRight         MouseButton = 2
	MouseMiddle        MouseButton = 3
	MouseFour          MouseButton = 4
	MouseFive          MouseButton = 5
)

// MouseEvent 一次鼠标/触摸上行。X/Y 是**网格坐标**（wire 口径，见 design D4）。
type MouseEvent struct {
	Action MouseAction
	Button MouseButton
	Mods   Mods
	X, Y   uint16
}

// encodeBuf 是编码输出缓冲。转义序列都很短；不够时按上游给的长度重试一次。
const encodeBuf = 256

// EncodeKey 把抽象按键编码成转义序列（无输出时返回 nil，例如按键被模式抑制）。
//
// 每次调用都 setopt_from_terminal：模式随时在变（TUI 进/出、kitty 协议开关），缓存一份
// 编码器选项会漏掉变化。
func (t *Terminal) EncodeKey(ev KeyEvent) []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.h == nil {
		return nil
	}
	enc, err := t.keyEncoderLocked()
	if err != nil {
		return nil
	}
	C.ghostty_key_encoder_setopt_from_terminal(enc, t.h)

	var ke C.GhosttyKeyEvent
	if rc := C.ghostty_key_event_new(nil, &ke); rc != C.GHOSTTY_SUCCESS {
		return nil
	}
	defer C.ghostty_key_event_free(ke)
	C.ghostty_key_event_set_key(ke, C.GhosttyKey(ev.Key))
	C.ghostty_key_event_set_action(ke, C.GhosttyKeyAction(ev.Action))
	C.ghostty_key_event_set_mods(ke, C.GhosttyMods(ev.Mods))
	C.ghostty_key_event_set_composing(ke, C.bool(ev.Composing))
	if ev.UnshiftedCodepoint != 0 {
		C.ghostty_key_event_set_unshifted_codepoint(ke, C.uint32_t(ev.UnshiftedCodepoint))
	}
	if ev.Text != "" {
		p := []byte(ev.Text)
		C.ghostty_key_event_set_utf8(ke, (*C.char)(unsafe.Pointer(&p[0])), C.size_t(len(p)))
	}
	return encodeWith(enc, ke)
}

func (t *Terminal) keyEncoderLocked() (C.GhosttyKeyEncoder, error) {
	if t.keyEnc != nil {
		return t.keyEnc, nil
	}
	var enc C.GhosttyKeyEncoder
	if rc := C.ghostty_key_encoder_new(nil, &enc); rc != C.GHOSTTY_SUCCESS {
		return nil, errf("key_encoder_new", rc)
	}
	t.keyEnc = enc
	return enc, nil
}

// EncodeMouse 把鼠标事件编码成转义序列（按 vt 当前鼠标模式与格式）。
//
// 几何用 1×1 px 的虚拟网格（helpers.c 的 tier_vt_mouse_size_grid）⇒ 传进来的网格坐标
// 直接就是编码器眼里的坐标，客户端不必知道像素几何。
func (t *Terminal) EncodeMouse(ev MouseEvent) []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.h == nil {
		return nil
	}
	enc, err := t.mouseEncoderLocked()
	if err != nil {
		return nil
	}
	C.ghostty_mouse_encoder_setopt_from_terminal(enc, t.h)
	var size C.GhosttyMouseEncoderSize
	C.tier_vt_mouse_size_grid(&size, C.uint32_t(t.cols), C.uint32_t(t.rows))
	C.ghostty_mouse_encoder_setopt(enc, C.GHOSTTY_MOUSE_ENCODER_OPT_SIZE, unsafe.Pointer(&size))

	var me C.GhosttyMouseEvent
	if rc := C.ghostty_mouse_event_new(nil, &me); rc != C.GHOSTTY_SUCCESS {
		return nil
	}
	defer C.ghostty_mouse_event_free(me)
	C.ghostty_mouse_event_set_action(me, C.GhosttyMouseAction(ev.Action))
	if ev.Button != MouseButtonUnknown {
		C.ghostty_mouse_event_set_button(me, C.GhosttyMouseButton(ev.Button))
	} else {
		C.ghostty_mouse_event_clear_button(me)
	}
	C.ghostty_mouse_event_set_mods(me, C.GhosttyMods(ev.Mods))
	var pos C.GhosttyMousePosition
	pos.x = C.float(ev.X)
	pos.y = C.float(ev.Y)
	C.ghostty_mouse_event_set_position(me, pos)

	var buf [encodeBuf]C.char
	var n C.size_t
	rc := C.ghostty_mouse_encoder_encode(enc, me, &buf[0], C.size_t(len(buf)), &n)
	if rc == C.GHOSTTY_OUT_OF_SPACE && int(n) > len(buf) && int(n) <= 4096 {
		big := make([]C.char, int(n))
		rc = C.ghostty_mouse_encoder_encode(enc, me, &big[0], C.size_t(len(big)), &n)
		if rc == C.GHOSTTY_SUCCESS && n > 0 {
			return C.GoBytes(unsafe.Pointer(&big[0]), C.int(n))
		}
		return nil
	}
	if rc != C.GHOSTTY_SUCCESS || n == 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(&buf[0]), C.int(n))
}

func (t *Terminal) mouseEncoderLocked() (C.GhosttyMouseEncoder, error) {
	if t.mouseEnc != nil {
		return t.mouseEnc, nil
	}
	var enc C.GhosttyMouseEncoder
	if rc := C.ghostty_mouse_encoder_new(nil, &enc); rc != C.GHOSTTY_SUCCESS {
		return nil, errf("mouse_encoder_new", rc)
	}
	t.mouseEnc = enc
	return enc, nil
}

// EncodeFocus 编码焦点事件（CSI I / CSI O）。
//
// ⚠️ 上游只做编码、不看模式：调用方**必须**先确认 vt 开了焦点上报（Modes().FocusEvents），
// 否则会把 TUI 不认识的字节写进 PTY（legacy 的 focusNudgeLocked 有同样的约束）。
func EncodeFocus(gained bool) []byte {
	ev := C.GhosttyFocusEvent(C.GHOSTTY_FOCUS_LOST)
	if gained {
		ev = C.GhosttyFocusEvent(C.GHOSTTY_FOCUS_GAINED)
	}
	var buf [8]C.char
	var n C.size_t
	if rc := C.ghostty_focus_encode(ev, &buf[0], C.size_t(len(buf)), &n); rc != C.GHOSTTY_SUCCESS || n == 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(&buf[0]), C.int(n))
}

// EncodePaste 把一段文本按**当前括号粘贴模式**包装（文本事件带粘贴语义，design D4）。
// bracketed = true 时包 \x1b[200~…\x1b[201~（粘贴内容里的 ESC 原样保留，与终端惯例一致）。
func EncodePaste(text string, bracketed bool) []byte {
	if text == "" {
		return nil
	}
	if !bracketed {
		return []byte(text)
	}
	out := make([]byte, 0, len(text)+12)
	out = append(out, "\x1b[200~"...)
	out = append(out, text...)
	out = append(out, "\x1b[201~"...)
	return out
}

// encodeWith 用键编码器编码一个事件（共用缓冲 + 超限重试）。
func encodeWith(enc C.GhosttyKeyEncoder, ev C.GhosttyKeyEvent) []byte {
	var buf [encodeBuf]C.char
	var n C.size_t
	rc := C.ghostty_key_encoder_encode(enc, ev, &buf[0], C.size_t(len(buf)), &n)
	if rc == C.GHOSTTY_OUT_OF_SPACE && int(n) > len(buf) && int(n) <= 4096 {
		big := make([]C.char, int(n))
		rc = C.ghostty_key_encoder_encode(enc, ev, &big[0], C.size_t(len(big)), &n)
		if rc == C.GHOSTTY_SUCCESS && n > 0 {
			return C.GoBytes(unsafe.Pointer(&big[0]), C.int(n))
		}
		return nil
	}
	if rc != C.GHOSTTY_SUCCESS || n == 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(&buf[0]), C.int(n))
}
