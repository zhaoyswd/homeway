//go:build (darwin || linux) && (amd64 || arm64) && cgo

// response.go — vt 写回 PTY 的通道（任务 2.7 的前置）。
//
// 为什么必须有它：libghostty-vt **默认静默丢弃**所有需要输出的序列——DA1（设备属性）、
// DSR（光标位置报告）、DECRQM（模式查询）、OSC 10/11（颜色查询）的**应答**都走这条回调。
// 不装回调 = 会话里的程序问「你在哪」「终端什么颜色」永远等不到答案（vim/htop/tmux 这类
// 会卡在启动探测上），而这正是 legacy 模式下客户端 vt 替我们做的事——vt 搬到服务端后
// 这条腿也得跟着搬。
//
// 线程纪律：回调是**同步**触发的（在 ghostty_terminal_vt_write 内部，此时 Terminal 的锁
// 已被持有）⇒ 接收方 MUST NOT 回调进同一个 Terminal（会自锁），只做「把字节写到 PTY」这类
// 无依赖动作。pkg/term 侧的接收方就是 ptmx.Write。
package vt

/*
#cgo CFLAGS: -I${SRCDIR} -I${SRCDIR}/../../../third_party/libghostty-vt/include
#include <stdlib.h>
#include "helpers.h"
*/
import "C"

import (
	"sync"
	"sync/atomic"
	"unsafe"
)

// vtRegistry 把整数 id 映射到 Terminal：userdata 用整数而不是 Go 指针，
// 这样 C 侧存它不触发 cgo 的「Go 指针不得被 C 保留」规则。
var (
	vtRegistryMu sync.RWMutex
	vtRegistry   = map[uintptr]*Terminal{}
	vtNextID     atomic.Uintptr
)

func registerTerminal(t *Terminal) uintptr {
	id := vtNextID.Add(1)
	vtRegistryMu.Lock()
	vtRegistry[id] = t
	vtRegistryMu.Unlock()
	return id
}

func unregisterTerminal(id uintptr) {
	vtRegistryMu.Lock()
	delete(vtRegistry, id)
	vtRegistryMu.Unlock()
}

//export tierVtWritePty
func tierVtWritePty(userdata unsafe.Pointer, data *C.uint8_t, length C.size_t) {
	if data == nil || length == 0 {
		return
	}
	vtRegistryMu.RLock()
	t := vtRegistry[uintptr(userdata)]
	vtRegistryMu.RUnlock()
	if t == nil {
		return
	}
	buf := C.GoBytes(unsafe.Pointer(data), C.int(length))
	t.deliverResponse(buf)
}

// RegistryID 返回本终端在回调注册表里的整数 id（pkg/term 用它做剪贴板回调的分派）。
func (t *Terminal) RegistryID() uintptr {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.regID
}

// SetResponseSink 装「写回 PTY」的接收方（nil = 丢弃应答）。
//
// 必须在**任何写入之前**调用一次；装配时机见 pkg/term 的会话创建路径。
func (t *Terminal) SetResponseSink(fn func([]byte)) {
	t.mu.Lock()
	t.responseSink = fn
	t.mu.Unlock()
}

// deliverResponse 由 C 回调进入（此时 t.mu 已被调用方持有，**不要再加锁**）。
func (t *Terminal) deliverResponse(p []byte) {
	fn := t.responseSink
	if fn == nil {
		return
	}
	fn(p)
}

// SetDefaultColors 设置终端默认前景/背景（客户端上报的主题）。
//
// 设了之后 vt 自己就会用这两个值应答 OSC 10/11 颜色查询——这正是「主题客户端解析」的
// 唯一例外（design D4：渲染配色不回传，查询应答值回传）。
func (t *Terminal) SetDefaultColors(fg, bg [3]uint8) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.h == nil {
		return
	}
	C.tier_vt_set_default_colors(t.h,
		C.uint8_t(fg[0]), C.uint8_t(fg[1]), C.uint8_t(fg[2]),
		C.uint8_t(bg[0]), C.uint8_t(bg[1]), C.uint8_t(bg[2]))
}

// ---- 剪贴板写回调（OSC 52，任务 2.7）----

// clipboardWriteFn 由 pkg/term 装（把内容转成 CLIPBOARD 帧发给客户端）。
// 返回 true = 已受理（回调会因此应答 SUCCESS）。
var clipboardWriteFn atomic.Pointer[func(id uintptr, text string) bool]

// SetClipboardWriteForwarder 装「程序写剪贴板」的转发器（nil = 拒绝，回调应答 UNSUPPORTED）。
func SetClipboardWriteForwarder(fn func(id uintptr, text string) bool) {
	if fn == nil {
		clipboardWriteFn.Store(nil)
		return
	}
	clipboardWriteFn.Store(&fn)
}

// clipboardReadFn 由 pkg/term 装（从会话缓存里取客户端最近上报的剪贴板内容）。
var clipboardReadFn atomic.Pointer[func(id uintptr, location int) (string, bool)]

// SetClipboardReadForwarder 装「程序读剪贴板」的转发器（进程级，注册一次）。
func SetClipboardReadForwarder(fn func(id uintptr, location int) (string, bool)) {
	if fn == nil {
		clipboardReadFn.Store(nil)
		return
	}
	clipboardReadFn.Store(&fn)
}

// tierVtClipboardRead 是 C 回调（同步）进 Go 的桥：把内容写进调用方给的缓冲并返回字节数。
// 返回 0 = 没有内容（调用方会明确拒绝这次读）。
//
// noescape 未用：buf 指向 C 侧栈缓冲，只在本次调用内有效（回调返回前已拷贝完）。
//
//export tierVtClipboardRead
func tierVtClipboardRead(userdata unsafe.Pointer, location C.int, buf unsafe.Pointer, cap C.int) C.int {
	fn := clipboardReadFn.Load()
	if fn == nil || buf == nil || cap <= 0 {
		return 0
	}
	text, ok := (*fn)(uintptr(userdata), int(location))
	if !ok || text == "" {
		return 0
	}
	dst := unsafe.Slice((*byte)(buf), int(cap))
	n := copy(dst, text)
	return C.int(n)
}

//export tierVtClipboardWrite
func tierVtClipboardWrite(userdata unsafe.Pointer, w unsafe.Pointer) C.int {
	fn := clipboardWriteFn.Load()
	if fn == nil {
		return 0
	}
	// 取内容：先问长度，再按长度取文本（helper 侧按 text/* MIME 挑选并截断）。
	n := int(C.tier_vt_clipboard_content_len((*C.GhosttyClipboardWrite)(w)))
	if n <= 0 {
		// contents_len == 0 表示「清空剪贴板」——照旧转发（空文本）让客户端清空。
		if (*fn)(uintptr(userdata), "") {
			return 1
		}
		return 0
	}
	buf := make([]byte, clipTextMax)
	got := C.tier_vt_clipboard_content_text((*C.GhosttyClipboardWrite)(w), 0,
		(*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	if got == 0 {
		return 0
	}
	text := string(buf[:int(got)])
	if (*fn)(uintptr(userdata), text) {
		return 1
	}
	return 0
}

// clipTextMax 是单次转发内容的上限（与 wire 侧的 clipMaxBytes 同量级）。
const clipTextMax = 256 << 10

// EnableClipboardRead 给这个终端装剪贴板读回调（内容从「客户端最近上报」的缓存里取）。
func (t *Terminal) EnableClipboardRead() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.h == nil {
		return
	}
	C.tier_vt_set_clipboard_read(t.h, C.uintptr_t(t.regID))
}

// EnableClipboardWrite 给这个终端装剪贴板写回调（内容经转发器交给客户端）。
func (t *Terminal) EnableClipboardWrite() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.h == nil {
		return
	}
	C.tier_vt_set_clipboard_write(t.h, C.uintptr_t(t.regID))
}
