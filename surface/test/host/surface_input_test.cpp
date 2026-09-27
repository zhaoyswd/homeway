// surface/test/host/surface_input_test.cpp — 上行帧（客户端 → 出口）的**字节级判据**（任务 3.4）。
//
// 为什么要有它：上行帧的布局在两端各有一份手写实现（客户端 surface_codec.cpp 的 encode*、出口
// term_surface.go 的 decInputEvent/decTheme/decClipboardAnswer）。下行有跨仓 golden fixture 钉着，
// 上行此前只有出口侧自己的 roundtrip（Go 编→Go 解，自证清白）。这里把**布局本身**钉死：
// 每个事件编出来必须逐字节等于文档里的形状——客户端改坏了这里红，出口改坏了它那边的
// decInputEvent 测试红。两边的期望值同源（都是 design D4 的 wire 形态）。
#include <cassert>
#include <iostream>
#include <string>
#include <vector>

#include "surface/surface_codec.h"

using namespace tierterm;

namespace {

int failures = 0;

void check(bool ok, const std::string& what) {
    if (!ok) {
        failures++;
        std::cerr << "[FAIL] " << what << "\n";
    }
}

std::string hex(const std::vector<uint8_t>& v) {
    static const char* d = "0123456789abcdef";
    std::string out;
    for (uint8_t b : v) {
        out.push_back(d[b >> 4]);
        out.push_back(d[b & 0xf]);
    }
    return out;
}

void checkBytes(const std::vector<uint8_t>& got, const std::string& wantHex, const std::string& what) {
    if (hex(got) != wantHex) {
        failures++;
        std::cerr << "[FAIL] " << what << "：got " << hex(got) << " want " << wantHex << "\n";
    }
}

}  // namespace

int main() {
    // ① 键事件：[kind=0][key:2 LE][mods:2 LE][action:1][textLen:1][text]
    //    key = ghostty 键码、mods = ghostty 位（SHIFT=1/CTRL=2/ALT=4）、action 1=press。
    {
        const auto ev = encodeKeyEvent(0x0041 /* A */, 0x0002 /* CTRL */, 1, "");
        checkBytes(ev, "00410002000100", "键事件（Ctrl+A）");
        const auto ev2 = encodeKeyEvent(0x0041, 0, 1, "a");
        checkBytes(ev2, "0041000000010161", "键事件（带文本的 a）");
        check(ev2.size() == 8, "键事件长度 = 1+2+2+1+1+文本");
    }

    // ② 文本事件：[kind=1][flags:1][len:2 LE][text]
    //    flags：bit0 = 粘贴语义、bit1 = 后面还有后续片（more）、bit2 = 本片是续片（cont）。
    //    大文本分帧时 200~/201~ 只能在整个序列首尾各一次 ⇒ 用 more/cont 让出口推迟闭合
    //    （2026-09-24 评审整改，P0-3）。
    {
        const auto ev = encodeTextEvent("hi", false);
        checkBytes(ev, "010002006869", "文本事件");
        const auto paste = encodeTextEvent("hi", true);
        checkBytes(paste, "010102006869", "文本事件（粘贴位）");
        const auto first = encodeTextEvent("hi", true, /*more=*/true, /*cont=*/false);
        checkBytes(first, "010302006869", "文本事件（粘贴首片：more）");
        const auto mid = encodeTextEvent("hi", true, /*more=*/true, /*cont=*/true);
        checkBytes(mid, "010702006869", "文本事件（粘贴续片：more+cont）");
        const auto last = encodeTextEvent("hi", true, /*more=*/false, /*cont=*/true);
        checkBytes(last, "010502006869", "文本事件（粘贴末片：cont）");
    }

    // ③ 鼠标事件：[kind=2][action:1][button:1][mods:2 LE][x:2 LE][y:2 LE]（x/y = 网格坐标）
    {
        const auto ev = encodeMouseEvent(0 /*press*/, 1 /*left*/, 0x0004 /*ALT*/, 12, 34);
        checkBytes(ev, "02000104000c002200", "鼠标事件（press left @12,34）");
    }

    // ④ 焦点事件：[kind=3][gained:1]
    {
        checkBytes(encodeFocusEvent(true), "0301", "焦点事件（获得）");
        checkBytes(encodeFocusEvent(false), "0300", "焦点事件（失去）");
    }

    // ⑤ 主题上报：[dark:1][fg:3][bg:3]（**深浅在前**，与服务端 decTheme 的读法一致）
    {
        const uint8_t fg[3] = {0x1a, 0x1a, 0x1a};
        const uint8_t bg[3] = {0xff, 0xff, 0xff};
        checkBytes(encodeTheme(fg, bg, false), "001a1a1affffff", "主题上报（浅色）");
        checkBytes(encodeTheme(fg, bg, true), "011a1a1affffff", "主题上报（深色）");
    }

    // ⑥ 剪贴板读应答：[kind=2 (readAnswer)][len:2 LE][text]
    {
        const auto ev = encodeClipboardAnswer("abc");
        checkBytes(ev, "020300616263", "剪贴板读应答");
        checkBytes(encodeClipboardAnswer(""), "020000", "剪贴板读应答（空）");
    }

    // ⑦ 能力块：[capLen:1][flags:capLen]（capLen 是 flags 的字节数，不是整块长度）
    {
        const auto ev = encodeCapabilityBlock(kCapsSurface);
        checkBytes(ev, "0101", "能力块（surface）");
    }

    // ⑧ 入站 OSC 帧的解码（出口 → 客户端）：NOTIFY / CLIPBOARD 两种。
    //    NOTIFY = [len:2 LE][text]；CLIPBOARD = [kind:1][len:2 LE][text]（kind 0=写 1=读 2=读应答）。
    {
        const uint8_t notify[] = {0x02, 0x00, 'h', 'i'};
        std::string text, err;
        check(decodeNotify(notify, sizeof(notify), text, err) && text == "hi", "NOTIFY 解码");
        // CLIPBOARD 写：[kind=0][len:2][text]；读请求：[kind=1][len=2]（无文本）
        const uint8_t clipWrite[] = {0x00, 0x02, 0x00, 'o', 'k'};
        uint8_t kind = 9;
        check(decodeClipboard(clipWrite, sizeof(clipWrite), kind, text, err) && kind == 0 &&
                  text == "ok",
              "CLIPBOARD 写帧解码");
        const uint8_t clipRead[] = {0x01, 0x00, 0x00};  // kind=1 读请求（len=0）
        check(decodeClipboard(clipRead, sizeof(clipRead), kind, text, err) && kind == 1,
              "CLIPBOARD 读请求解码");
    }

    if (failures > 0) {
        std::cerr << failures << " 项不一致\n";
        return 1;
    }
    std::cout << "surface 上行帧：全部通过（键/文本/鼠标/焦点/主题/剪贴板/能力块/OSC 解码）\n";
    return 0;
}
