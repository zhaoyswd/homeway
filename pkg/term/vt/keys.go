//go:build (darwin || linux) && (amd64 || arm64) && cgo

// keys.go — vt 键码常量（GHOSTTY_KEY_* 的 W3C UI Events code 口径）。
//
// 为什么要在这里铺一层：`_test.go` 里**不能用 cgo**（Go 不支持），而两仓共用的 u16 wire
// 键码表（任务 2.7/3.4）最终要映射到这些值上。这里先给出「函数键栏 + 常用字符键 + 修饰键」
// 这一批，够本 change 的输入路径与单测用；剩余键在 2.7/3.4 补表时按需追加。
package vt

/*
#cgo CFLAGS: -I${SRCDIR} -I${SRCDIR}/../../../third_party/libghostty-vt/include
#include <ghostty/vt.h>
*/
import "C"

// 字符键（数字/字母/常用符号）。
const (
	KeyDigit0 Key = C.GHOSTTY_KEY_DIGIT_0
	KeyDigit1 Key = C.GHOSTTY_KEY_DIGIT_1
	KeyDigit2 Key = C.GHOSTTY_KEY_DIGIT_2
	KeyDigit3 Key = C.GHOSTTY_KEY_DIGIT_3
	KeyDigit4 Key = C.GHOSTTY_KEY_DIGIT_4
	KeyDigit5 Key = C.GHOSTTY_KEY_DIGIT_5
	KeyDigit6 Key = C.GHOSTTY_KEY_DIGIT_6
	KeyDigit7 Key = C.GHOSTTY_KEY_DIGIT_7
	KeyDigit8 Key = C.GHOSTTY_KEY_DIGIT_8
	KeyDigit9 Key = C.GHOSTTY_KEY_DIGIT_9

	KeyA Key = C.GHOSTTY_KEY_A
	KeyB Key = C.GHOSTTY_KEY_B
	KeyC Key = C.GHOSTTY_KEY_C
	KeyD Key = C.GHOSTTY_KEY_D
	KeyE Key = C.GHOSTTY_KEY_E
	KeyF Key = C.GHOSTTY_KEY_F
	KeyG Key = C.GHOSTTY_KEY_G
	KeyH Key = C.GHOSTTY_KEY_H
	KeyI Key = C.GHOSTTY_KEY_I
	KeyJ Key = C.GHOSTTY_KEY_J
	KeyK Key = C.GHOSTTY_KEY_K
	KeyL Key = C.GHOSTTY_KEY_L
	KeyM Key = C.GHOSTTY_KEY_M
	KeyN Key = C.GHOSTTY_KEY_N
	KeyO Key = C.GHOSTTY_KEY_O
	KeyP Key = C.GHOSTTY_KEY_P
	KeyQ Key = C.GHOSTTY_KEY_Q
	KeyR Key = C.GHOSTTY_KEY_R
	KeyS Key = C.GHOSTTY_KEY_S
	KeyT Key = C.GHOSTTY_KEY_T
	KeyU Key = C.GHOSTTY_KEY_U
	KeyV Key = C.GHOSTTY_KEY_V
	KeyW Key = C.GHOSTTY_KEY_W
	KeyX Key = C.GHOSTTY_KEY_X
	KeyY Key = C.GHOSTTY_KEY_Y
	KeyZ Key = C.GHOSTTY_KEY_Z

	KeyBackquote    Key = C.GHOSTTY_KEY_BACKQUOTE
	KeyMinus        Key = C.GHOSTTY_KEY_MINUS
	KeyEqual        Key = C.GHOSTTY_KEY_EQUAL
	KeyBracketLeft  Key = C.GHOSTTY_KEY_BRACKET_LEFT
	KeyBracketRight Key = C.GHOSTTY_KEY_BRACKET_RIGHT
	KeyBackslash    Key = C.GHOSTTY_KEY_BACKSLASH
	KeySemicolon    Key = C.GHOSTTY_KEY_SEMICOLON
	KeyQuote        Key = C.GHOSTTY_KEY_QUOTE
	KeyComma        Key = C.GHOSTTY_KEY_COMMA
	KeyPeriod       Key = C.GHOSTTY_KEY_PERIOD
	KeySlash        Key = C.GHOSTTY_KEY_SLASH
)

// 编辑/导航键。
const (
	KeyEscape    Key = C.GHOSTTY_KEY_ESCAPE
	KeyEnter     Key = C.GHOSTTY_KEY_ENTER
	KeyTab       Key = C.GHOSTTY_KEY_TAB
	KeySpace     Key = C.GHOSTTY_KEY_SPACE
	KeyBackspace Key = C.GHOSTTY_KEY_BACKSPACE
	KeyDelete    Key = C.GHOSTTY_KEY_DELETE
	KeyInsert    Key = C.GHOSTTY_KEY_INSERT
	KeyHome      Key = C.GHOSTTY_KEY_HOME
	KeyEnd       Key = C.GHOSTTY_KEY_END
	KeyPageUp    Key = C.GHOSTTY_KEY_PAGE_UP
	KeyPageDown  Key = C.GHOSTTY_KEY_PAGE_DOWN

	KeyArrowUp    Key = C.GHOSTTY_KEY_ARROW_UP
	KeyArrowDown  Key = C.GHOSTTY_KEY_ARROW_DOWN
	KeyArrowLeft  Key = C.GHOSTTY_KEY_ARROW_LEFT
	KeyArrowRight Key = C.GHOSTTY_KEY_ARROW_RIGHT
)

// 功能键（函数键栏用）。
const (
	KeyF1  Key = C.GHOSTTY_KEY_F1
	KeyF2  Key = C.GHOSTTY_KEY_F2
	KeyF3  Key = C.GHOSTTY_KEY_F3
	KeyF4  Key = C.GHOSTTY_KEY_F4
	KeyF5  Key = C.GHOSTTY_KEY_F5
	KeyF6  Key = C.GHOSTTY_KEY_F6
	KeyF7  Key = C.GHOSTTY_KEY_F7
	KeyF8  Key = C.GHOSTTY_KEY_F8
	KeyF9  Key = C.GHOSTTY_KEY_F9
	KeyF10 Key = C.GHOSTTY_KEY_F10
	KeyF11 Key = C.GHOSTTY_KEY_F11
	KeyF12 Key = C.GHOSTTY_KEY_F12
)
