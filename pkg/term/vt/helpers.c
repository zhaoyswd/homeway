// helpers.c — 见 helpers.h。
#include "helpers.h"

// cgo 生成的导出头：Go 侧 //export 的函数在这里有权威声明（签名由 cgo 生成，手写会撞类型）。
#include "_cgo_export.h"

#include <string.h>

bool tier_vt_mode_get(GhosttyTerminal t, uint16_t mode, bool *out) {
  if (t == NULL || out == NULL) {
    return false;
  }
  GhosttyTerminalModeConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.mode = (GhosttyMode)mode;
  cfg.value = false;
  if (ghostty_terminal_get(t, GHOSTTY_TERMINAL_DATA_MODE, &cfg) != GHOSTTY_SUCCESS) {
    return false;
  }
  *out = cfg.value;
  return true;
}

void tier_vt_formatter_plain(GhosttyFormatterTerminalOptions *o, bool unwrap, bool trim) {
  *o = GHOSTTY_INIT_SIZED(GhosttyFormatterTerminalOptions);
  o->emit = GHOSTTY_FORMATTER_FORMAT_PLAIN;
  o->unwrap = unwrap;
  o->trim = trim;
}

void tier_vt_cursor_init(GhosttyRenderStateCursor *c) {
  *c = GHOSTTY_INIT_SIZED(GhosttyRenderStateCursor);
}

void tier_vt_style_init(GhosttyStyle *s) {
  *s = GHOSTTY_INIT_SIZED(GhosttyStyle);
}

uint8_t tier_vt_style_color_tag(GhosttyStyleColor c) { return (uint8_t)c.tag; }

uint8_t tier_vt_style_color_palette(GhosttyStyleColor c) { return (uint8_t)c.value.palette; }

void tier_vt_style_color_rgb(GhosttyStyleColor c, uint8_t *r, uint8_t *g, uint8_t *b) {
  *r = c.value.rgb.r;
  *g = c.value.rgb.g;
  *b = c.value.rgb.b;
}

static void tier_vt_write_pty_trampoline(GhosttyTerminal t, void* userdata,
                                       const uint8_t* data, size_t len) {
  (void)t;
  // 签名以 _cgo_export.h 为准（Go 侧的 *C.uint8_t 在 C 侧是非 const 的 uint8_t*）。
  tierVtWritePty(userdata, (uint8_t*)data, len);
}

void tier_vt_set_write_pty(GhosttyTerminal t, uintptr_t id) {
  if (t == NULL) return;
  /* ⚠️ 这两个选项的 ABI 与标量选项**相反**：回调/userdata 类选项的 `value` 就是值本身
   * （上游 InType 是 `?WritePtyFn` / `?*const anyopaque`，C 侧只做 @ptrCast），
   * 而 bool / size_t 那类「指针型」选项才是「指向值的指针」。传 &fn 会让库把栈地址当函数指针调用
   * 实测直接 SIGSEGV（PC == 跳转地址）。头文件的措辞是线索：
   *   "Input type: GhosttyTerminalWritePtyFn"（无星号） vs "Input type: bool*"（有星号）。 */
  ghostty_terminal_set(t, GHOSTTY_TERMINAL_OPT_USERDATA, (const void*)id);
  ghostty_terminal_set(t, GHOSTTY_TERMINAL_OPT_WRITE_PTY,
                       (const void*)tier_vt_write_pty_trampoline);
}

void tier_vt_set_default_colors(GhosttyTerminal t, uint8_t fr, uint8_t fg, uint8_t fb,
                                uint8_t br, uint8_t bg, uint8_t bb) {
  if (t == NULL) return;
  GhosttyColorRgb f = {.r = fr, .g = fg, .b = fb};
  GhosttyColorRgb b = {.r = br, .g = bg, .b = bb};
  ghostty_terminal_set(t, GHOSTTY_TERMINAL_OPT_COLOR_FOREGROUND, &f);
  ghostty_terminal_set(t, GHOSTTY_TERMINAL_OPT_COLOR_BACKGROUND, &b);
}

// ---- 剪贴板读（OSC 52 "?"）----

static void tier_vt_clipboard_read_trampoline(GhosttyTerminal t, void* userdata,
                                             const GhosttyClipboardRead* r);

int tier_vt_clipboard_read_location(const GhosttyClipboardRead* r) {
  if (r == NULL) return 0;
  return (int)r->location;
}

void tier_vt_set_clipboard_read(GhosttyTerminal t, uintptr_t id) {
  if (t == NULL) return;
  ghostty_terminal_set(t, GHOSTTY_TERMINAL_OPT_USERDATA, (const void*)id);
  ghostty_terminal_set(t, GHOSTTY_TERMINAL_OPT_CLIPBOARD_READ,
                       (const void*)tier_vt_clipboard_read_trampoline);
}

static void tier_vt_clipboard_read_trampoline(GhosttyTerminal t, void* userdata,
                                             const GhosttyClipboardRead* r) {
  (void)t;
  if (r == NULL || r->reply == NULL) return;
  /* 内容缓冲在栈上：reply 只在本次调用内有效（文档：应答必须发生在回调返回前）。 */
  static char buf[64 * 1024];
  size_t n = (size_t)tierVtClipboardRead(userdata, tier_vt_clipboard_read_location(r),
                                         buf, sizeof(buf));
  GhosttyClipboardReadReply reply;
  memset(&reply, 0, sizeof(reply));
  reply.size = sizeof(reply);
  if (n == 0) {
    /* 没有内容（或没有 surface 腿）：明确拒绝——程序会得到空剪贴板而不是悬着的请求。 */
    reply.result = GHOSTTY_CLIPBOARD_READ_RESULT_DENIED;
    r->reply(r, &reply);
    return;
  }
  static const char kTextPlain[] = "text/plain";
  GhosttyClipboardContent content;
  memset(&content, 0, sizeof(content));
  content.mime.ptr = (const uint8_t*)kTextPlain;
  content.mime.len = sizeof(kTextPlain) - 1;
  content.data.ptr = (const uint8_t*)buf;
  content.data.len = n;
  reply.result = GHOSTTY_CLIPBOARD_READ_RESULT_SUCCESS;
  reply.contents = &content;
  reply.contents_len = 1;
  r->reply(r, &reply);
}

// ---- 剪贴板写（OSC 52）----

static void tier_vt_clipboard_write_trampoline(GhosttyTerminal t, void* userdata,
                                              const GhosttyClipboardWrite* w);
static void tier_vt_clipboard_reply(const GhosttyClipboardWrite* w, GhosttyClipboardWriteResult res);

void tier_vt_set_clipboard_write(GhosttyTerminal t, uintptr_t id) {
  if (t == NULL) return;
  ghostty_terminal_set(t, GHOSTTY_TERMINAL_OPT_USERDATA, (const void*)id);
  ghostty_terminal_set(t, GHOSTTY_TERMINAL_OPT_CLIPBOARD_WRITE,
                       (const void*)tier_vt_clipboard_write_trampoline);
}

int tier_vt_clipboard_content_len(const GhosttyClipboardWrite* w) {
  if (w == NULL) return 0;
  return (int)w->contents_len;
}

size_t tier_vt_clipboard_content_text(const GhosttyClipboardWrite* w, int idx,
                                      uint8_t* out, size_t cap) {
  if (w == NULL || out == NULL || idx < 0 || (size_t)idx >= w->contents_len) return 0;
  const GhosttyClipboardContent* c = &w->contents[idx];
  /* 优先 text/plain（终端剪贴板的常规形态）；取不到就退回第一条。 */
  const uint8_t* data = NULL;
  size_t len = 0;
  for (size_t i = 0; i < 2; i++) {
    const GhosttyClipboardContent* pick = (i == 0) ? c : &w->contents[0];
    if (pick->mime.len == 0) continue;
    /* mime 以 "text/" 开头即认（含 text/plain、text/plain;charset=utf-8 等）。 */
    if (pick->mime.len >= 5 && memcmp(pick->mime.ptr, "text/", 5) == 0) {
      data = pick->data.ptr;
      len = pick->data.len;
      break;
    }
  }
  if (data == NULL) return 0;
  if (len > cap) len = cap;
  memcpy(out, data, len);
  return len;
}

static void tier_vt_clipboard_reply(const GhosttyClipboardWrite* w, GhosttyClipboardWriteResult res) {
  if (w == NULL || w->reply == NULL) return;
  GhosttyClipboardWriteReply reply;
  memset(&reply, 0, sizeof(reply));
  reply.size = sizeof(reply);
  reply.result = res;
  reply.remember = false;
  w->reply(w, &reply);
}

static void tier_vt_clipboard_write_trampoline(GhosttyTerminal t, void* userdata,
                                              const GhosttyClipboardWrite* w) {
  (void)t;
  /* Go 侧负责转发给客户端；**无论成功与否都要在回调期间应答**，否则请求悬着
     （文档：返回而不 reply = 拒绝，OSC 52 会丢弃回复，但我们要明确给出成功/失败语义）。 */
  int accepted = tierVtClipboardWrite(userdata, (void*)w);
  tier_vt_clipboard_reply(w, accepted ? GHOSTTY_CLIPBOARD_WRITE_RESULT_SUCCESS
                                      : GHOSTTY_CLIPBOARD_WRITE_RESULT_UNSUPPORTED);
}

void tier_vt_scroll_to_row(GhosttyTerminal t, size_t row) {
  if (t == NULL) return;
  GhosttyTerminalScrollViewport v;
  memset(&v, 0, sizeof(v));
  v.tag = GHOSTTY_SCROLL_VIEWPORT_ROW;
  v.value.row = row;
  ghostty_terminal_scroll_viewport(t, v);
}

void tier_vt_scroll_bottom(GhosttyTerminal t) {
  if (t == NULL) return;
  GhosttyTerminalScrollViewport v;
  memset(&v, 0, sizeof(v));
  v.tag = GHOSTTY_SCROLL_VIEWPORT_BOTTOM;
  ghostty_terminal_scroll_viewport(t, v);
}

void tier_vt_mouse_size_grid(GhosttyMouseEncoderSize *s, uint32_t cols, uint32_t rows) {
  *s = GHOSTTY_INIT_SIZED(GhosttyMouseEncoderSize);
  s->screen_width = cols;
  s->screen_height = rows;
  s->cell_width = 1;
  s->cell_height = 1;
  s->padding_top = 0;
  s->padding_bottom = 0;
  s->padding_left = 0;
  s->padding_right = 0;
}
