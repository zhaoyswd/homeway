// helpers.h — libghostty-vt 的 C 侧小助手（cgo 读不了 union / 写不了复合字面量）。
//
// 为什么单独一个 .c/.h：cgo 每个 Go 文件的 preamble 是**独立编译单元**，一个文件里定义的
// static 函数另一个文件看不见。放在包目录的 .c 文件里由 cgo 一起编译进包，各 Go 文件的
// preamble 只要 `#include "helpers.h"` + `-I${SRCDIR}` 即可共用（实测该组合可用）。
#ifndef TIER_TERM_VT_HELPERS_H
#define TIER_TERM_VT_HELPERS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <ghostty/vt.h>

// 查询一个终端模式（ghostty_terminal_get + GhosttyTerminalModeConfig）。
// mode 用 GHOSTTY_MODE_* 宏的打包值（ghostty_mode_new(number, ansi)）。
// 返回 false 表示查询失败（未知模式 / 句柄无效），此时 *out 不变。
bool tier_vt_mode_get(GhosttyTerminal t, uint16_t mode, bool *out);

// sized-struct 初始化（Go 里写不了 C 复合字面量 GHOSTTY_INIT_SIZED）。
void tier_vt_formatter_plain(GhosttyFormatterTerminalOptions *o, bool unwrap, bool trim);
void tier_vt_cursor_init(GhosttyRenderStateCursor *c);
void tier_vt_style_init(GhosttyStyle *s);

// GhosttyStyleColor 是 tagged union，Go 侧不能直接取 union 成员。
uint8_t tier_vt_style_color_tag(GhosttyStyleColor c);
uint8_t tier_vt_style_color_palette(GhosttyStyleColor c);
void tier_vt_style_color_rgb(GhosttyStyleColor c, uint8_t *r, uint8_t *g, uint8_t *b);

// VT 的「写回 PTY」回调（cgo 侧桥接）。
//
// libghostty-vt 默认**静默丢弃**所有需要输出的序列（DECRQM/DSR/DA1/OSC 10-11 查询应答…），
// 必须装 GHOSTTY_TERMINAL_OPT_WRITE_PTY 才会交回来（头文件明写）。这里用一层 C 转发函数
// 把 userdata（= 我们注册的终端 id，**不是 Go 指针**）与数据交给 Go 侧实现。
//
// 为什么要有这层：cgo 的 //export 要求「同一文件的 preamble 只能有声明」，
// 所以回调的**定义**落在 helpers.c 里，而它对 Go 侧函数的声明来自 cgo 生成的
// `_cgo_export.h`（**不要**在这里手写声明：cgo 生成的签名用的是 Go 的整型 typedef，
// 手写会撞 "conflicting types"，实测踩过）。
void tier_vt_set_write_pty(GhosttyTerminal t, uintptr_t id);

// 剪贴板读请求（OSC 52 "?"）：回调在 vt 里**同步**触发（请求句柄只在这期间有效），
// 所以 Go 侧必须当场给出内容（s.clipCache = 客户端最近上报的值）或明确拒绝。
// location：0 = clipboard、1 = selection（见 ghostty GhosttyClipboardLocation）。
void tier_vt_set_clipboard_read(GhosttyTerminal t, uintptr_t id);
int tier_vt_clipboard_read_location(const GhosttyClipboardRead* r);

// 剪贴板写请求（OSC 52）：把「程序要写剪贴板」的内容取出来交给 Go 侧转发给客户端，
// 并在回调期间**立即应答成功**（客户端真正写系统剪贴板是异步的，这里不能等）。
// 返回：0 = 已处理（含应答），非 0 = 无内容可转发（此时也要应答，否则请求悬着）。
void tier_vt_set_clipboard_write(GhosttyTerminal t, uintptr_t id);
int tier_vt_clipboard_content_len(const GhosttyClipboardWrite* w);
// 把第 idx 条内容（MIME + 数据）取成 UTF-8 文本；返回实际写入的字节数（0 = 取不到）。
size_t tier_vt_clipboard_content_text(const GhosttyClipboardWrite* w, int idx,
                                      uint8_t* out, size_t cap);

// 主题色（客户端上报的默认前景/背景）：设置后 vt 自己按它应答 OSC 10/11 查询。
void tier_vt_set_default_colors(GhosttyTerminal t, uint8_t fr, uint8_t fg, uint8_t fb,
                                uint8_t br, uint8_t bg, uint8_t bb);

// 滚动视口（Go 侧读不了 GhosttyTerminalScrollViewport 的 union 字段，必须走 C）。
void tier_vt_scroll_to_row(GhosttyTerminal t, size_t row);
void tier_vt_scroll_bottom(GhosttyTerminal t);

// 鼠标编码器的几何上下文：cell 固定 1×1 px、无内边距、屏幕 = 网格尺寸
// ⇒ 编码器看到的「surface 像素坐标」就是**网格坐标**（wire 上的鼠标事件按网格走，见 design D4）。
void tier_vt_mouse_size_grid(GhosttyMouseEncoderSize *s, uint32_t cols, uint32_t rows);

#endif // TIER_TERM_VT_HELPERS_H
