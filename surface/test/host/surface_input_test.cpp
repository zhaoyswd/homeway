// surface/test/host/surface_input_test.cpp — 上行帧（客户端 → 出口）的**字节级判据**（任务 3.4）。
//
// 为什么要有它：上行帧的布局在两端各有一份手写实现（客户端 surface_codec.cpp 的 encode*、出口
// term_surface.go 的 decInputEvent/decTheme/decClipboardAnswer）。下行有跨仓 golden fixture 钉着，
// 上行此前只有出口侧自己的 roundtrip（Go 编→Go 解，自证清白）。这里把**布局本身**钉死。
//
// contract-ledger 3.2 起期望字节表语言无关化：判据数据 = 同目录 surface_input_cases.tsv
// （name/category/args/hex 四列，golden manifest.tsv 同款自解析 TSV——C++ 仓无 JSON 库，零新依赖）。
// C++ 这侧「按 args 重新编码、与 hex 对拍」；Go 净室（contracts/cleanroom）那侧「按 hex 解码、
// 与 args 对拍」——上行布局自此两端共源，改任何一端期望都同批改这一份文件（内嵌表已删，不留双轨）。
//
// 用法：surface_input_test [surface_input_cases.tsv 路径]（缺省 = 仓根相对路径）。
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "surface/surface_codec.h"

using namespace tierterm;

namespace {

int failures = 0;
int cases = 0;

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

// split 按逗号拆 args（TSV 内 args 用逗号做子分隔；语料里的文本不含逗号——扩语料时留意）。
std::vector<std::string> split(const std::string& s) {
    std::vector<std::string> out;
    std::stringstream ss(s);
    std::string part;
    while (std::getline(ss, part, ',')) {
        out.push_back(part);
    }
    if (!s.empty() && s.back() == ',') {
        out.push_back("");  // 尾随逗号 = 末字段为空（如 key 的 text）
    }
    return out;
}

long parseNum(const std::string& s) { return std::strtoul(s.c_str(), nullptr, 0); }

// runCase 按 category 把 args 重新编码，与期望 hex 对拍。
void runCase(const std::string& name, const std::string& category, const std::string& args,
             const std::string& wantHex) {
    const auto parts = split(args);
    bool ok = true;
    if (category == "key") {
        // [kind=0][key:2 LE][mods:2 LE][action:1][textLen:1][text]（key = ghostty 键码、
        // mods = ghostty 位 SHIFT=1/CTRL=2/ALT=4、action 1=press）。
        ok = parts.size() == 4;
        if (ok) {
            checkBytes(encodeKeyEvent(static_cast<uint16_t>(parseNum(parts[0])),
                                      static_cast<uint16_t>(parseNum(parts[1])),
                                      static_cast<uint8_t>(parseNum(parts[2])), parts[3]),
                       wantHex, name);
        }
    } else if (category == "text") {
        // [kind=1][flags:1][len:2 LE][text]；flags bit0=paste、bit1=more、bit2=cont
        // （大文本分帧时 200~/201~ 只能在整个序列首尾各一次 ⇒ 用 more/cont 让出口推迟闭合）。
        ok = parts.size() == 4;
        if (ok) {
            checkBytes(encodeTextEvent(parts[0], parts[1] == "1", parts[2] == "1", parts[3] == "1"),
                       wantHex, name);
        }
    } else if (category == "mouse") {
        // [kind=2][action:1][button:1][mods:2 LE][x:2 LE][y:2 LE]（x/y = 网格坐标）。
        ok = parts.size() == 5;
        if (ok) {
            checkBytes(encodeMouseEvent(static_cast<uint8_t>(parseNum(parts[0])),
                                        static_cast<uint8_t>(parseNum(parts[1])),
                                        static_cast<uint16_t>(parseNum(parts[2])),
                                        static_cast<uint16_t>(parseNum(parts[3])),
                                        static_cast<uint16_t>(parseNum(parts[4]))),
                       wantHex, name);
        }
    } else if (category == "focus") {
        // [kind=3][gained:1]
        ok = parts.size() == 1;
        if (ok) {
            checkBytes(encodeFocusEvent(parts[0] == "1"), wantHex, name);
        }
    } else if (category == "theme") {
        // [dark:1][fg:3][bg:3]（**深浅在前**，与服务端 decTheme 的读法一致）
        ok = parts.size() == 3 && parts[1].size() == 6 && parts[2].size() == 6;
        if (ok) {
            uint8_t fg[3], bg[3];
            for (int i = 0; i < 3; i++) {
                fg[i] = static_cast<uint8_t>(strtoul(parts[1].substr(i * 2, 2).c_str(), nullptr, 16));
                bg[i] = static_cast<uint8_t>(strtoul(parts[2].substr(i * 2, 2).c_str(), nullptr, 16));
            }
            checkBytes(encodeTheme(fg, bg, parts[0] == "1"), wantHex, name);
        }
    } else if (category == "clipboard") {
        // 读应答：[kind=2 (readAnswer)][len:2 LE][text]（args = 文本原样，可为空）
        ok = parts.size() <= 1;
        if (ok) {
            checkBytes(encodeClipboardAnswer(args), wantHex, name);
        }
    } else if (category == "caps") {
        // 能力块：[capLen:1][flags:capLen]（capLen 是 flags 的字节数，不是整块长度）
        uint8_t caps = 0;
        if (args == "surface") {
            caps = kCapsSurface;
        } else {
            ok = false;
        }
        if (ok) {
            checkBytes(encodeCapabilityBlock(caps), wantHex, name);
        }
    } else if (category == "hello-tail") {
        // HELLO 尾随块（FIX-29 版本门）：args = caps,ver,id（ver/id 空 = 不出现）。
        // caps 带 kCapsProtoVer（0x80）时 encodeHelloTail 在 caps 块后写 1 字节 kProtoVer；
        // 期望 hex 钉死整段布局（与服务端 pkg/term encHelloTail 逐字节一致）。
        ok = parts.size() == 3;
        if (ok) {
            const uint8_t caps = static_cast<uint8_t>(parseNum(parts[0]));
            checkBytes(encodeHelloTail(caps, parts[2]), wantHex, name);
        }
    } else {
        ok = false;
    }
    if (!ok) {
        failures++;
        std::cerr << "[FAIL] " << name << "：category=" << category << " args 与其形态不符（" << args
                  << "）\n";
        return;
    }
    cases++;
}

}  // namespace

int main(int argc, char** argv) {
    const std::string path = (argc > 1) ? argv[1] : "surface/test/host/surface_input_cases.tsv";
    std::ifstream in(path);
    if (!in) {
        std::cerr << "读不到 " << path << "（上行字节表 manifest；与测试同批维护）\n";
        return 2;
    }
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        std::istringstream ss(line);
        std::string name, category, args, wantHex;
        std::getline(ss, name, '\t');
        std::getline(ss, category, '\t');
        std::getline(ss, args, '\t');
        std::getline(ss, wantHex, '\t');
        if (name.empty() || category.empty() || wantHex.empty()) {
            failures++;
            std::cerr << "[FAIL] manifest 行缺列：" << line << "\n";
            continue;
        }
        runCase(name, category, args, wantHex);
    }
    if (cases == 0) {
        std::cerr << "manifest 是空的（空集假绿——期望表必须有行）\n";
        return 2;
    }

    // ⑧ 入站 OSC 帧的解码（出口 → 客户端）：NOTIFY / CLIPBOARD 两种。
    //    NOTIFY = [len:2 LE][text]；CLIPBOARD = [kind:1][len:2 LE][text]（kind 0=写 1=读 2=读应答）。
    //    （这是解码向行为判据、非 checkBytes 期望表——留在内嵌。）
    {
        const uint8_t notify[] = {0x02, 0x00, 'h', 'i'};
        std::string text, err;
        check(decodeNotify(notify, sizeof(notify), text, err) && text == "hi", "NOTIFY 解码");
        // CLIPBOARD 写：[kind=0][len:2][text]；读请求：[kind=1][len:2]（无文本）
        const uint8_t clipWrite[] = {0x00, 0x02, 0x00, 'o', 'k'};
        uint8_t kind = 9;
        check(decodeClipboard(clipWrite, sizeof(clipWrite), kind, text, err) && kind == 0 &&
                  text == "ok",
              "CLIPBOARD 写帧解码");
        const uint8_t clipRead[] = {0x01, 0x00, 0x00};  // kind=1 读请求（len=0）
        check(decodeClipboard(clipRead, sizeof(clipRead), kind, text, err) && kind == 1,
              "CLIPBOARD 读请求解码");
        // FIX-27：读应答的长度字段是 u16——超 65532 的文本必须被截到帧上限内，否则
        // appendU16 回绕（65536 → 0）写出「声明长度与实际字节不符」的坏帧。
        {
            const std::string huge(100 * 1024, 'x');
            const std::vector<uint8_t> ans = encodeClipboardAnswer(huge);
            const size_t declared =
                static_cast<size_t>(ans[1]) | (static_cast<size_t>(ans[2]) << 8);
            check(ans.size() <= 65535 && declared == ans.size() - 3,
                  "剪贴板读应答超长文本：长度字段精确且不超帧上限（FIX-27）");
        }
    }

    if (failures > 0) {
        std::cerr << failures << " 项不一致\n";
        return 1;
    }
    std::cout << "surface 上行帧：全部通过（" << cases
              << " 例，键/文本/鼠标/焦点/主题/剪贴板/能力块 + OSC 解码）\n";
    return 0;
}
