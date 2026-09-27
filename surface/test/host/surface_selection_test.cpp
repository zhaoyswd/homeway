// surface/test/host/surface_selection_test.cpp — surface 网格上的文本选择（任务 3.7 配套）的宿主判据。
//
// 为什么要它：选择/复制是**用户在用的功能**（长按选词、键栏 Copy），退役本地 vt 后它整块换实现。
// 这几条恰恰是最容易悄悄坏的地方：占位尾格漏跳过会拆开 CJK、行尾不裁会带一堆空格、跨行拼接
// 少一个换行就粘出一行。
#include <cassert>
#include <iostream>
#include <string>
#include <vector>

#include "surface/surface_selection.h"

using namespace tierterm;

namespace {

int failures = 0;

void check(bool ok, const std::string& what) {
    if (!ok) {
        failures++;
        std::cerr << "[FAIL] " << what << "\n";
    }
}

// mkRow：把 ASCII 文本铺成一行（按列宽补齐）。
Row mkRow(const std::string& text, int cols) {
    Row r;
    for (int i = 0; i < cols; i++) {
        Cell c;
        c.width = 1;
        if (i < static_cast<int>(text.size())) {
            c.symbol = std::string(1, text[static_cast<size_t>(i)]);
        }
        r.cells.push_back(c);
    }
    return r;
}

// mkCjkRow：一行「宽字符 + 占位尾格 + 空白」（真机白块那个坑的同一形态）。
Row mkCjkRow(const std::string& word, int cols) {
    Row r;
    for (int i = 0; i < cols; i++) {
        Cell c;
        c.width = 1;
        r.cells.push_back(c);
    }
    size_t col = 0;
    for (size_t i = 0; i < word.size();) {
        const size_t n = (static_cast<unsigned char>(word[i]) >= 0xE0) ? 3 : 1;
        r.cells[col].symbol = word.substr(i, n);
        r.cells[col].width = (n == 3) ? 2 : 1;
        if (n == 3 && col + 1 < static_cast<size_t>(cols)) {
            r.cells[col + 1].skip = true;
            r.cells[col + 1].width = 0;
        }
        col += (n == 3) ? 2 : 1;
        i += n;
    }
    return r;
}

}  // namespace

int main() {
    const int cols = 20;

    // ① 长按选词：按词类扩到边界（空白不算同类）。
    {
        std::vector<Row> rows = {mkRow("run tests --verbose", cols), mkRow("second line", cols)};
        SelectionModel sel;
        sel.press(0, 2 /* 'n' in run */, rows, cols);
        check(sel.active(), "press 后应有选择");
        check(sel.covers(0, 0) && sel.covers(0, 2) && !sel.covers(0, 3), "选词应扩到词边界（run）");
        std::string t = sel.text(rows, cols);
        check(t == "run", "长按选词文本应为 run，实际 " + t);
    }

    // ② 拖动扩选 + 跨行拼接（行间一个 \n，行尾裁空白）。
    {
        std::vector<Row> rows = {mkRow("hello world", cols), mkRow("second line", cols)};
        SelectionModel sel;
        sel.press(0, 0, rows, cols);  // 词 = hello
        sel.drag(1, 5);               // 拖到第二行第 5 列（含）
        const std::string t = sel.text(rows, cols);
        check(t == "hello world\nsecond", "跨行选择文本应拼接正确，实际 [" + t + "]");
        check(sel.covers(0, 19) && sel.covers(1, 3) && !sel.covers(1, 6), "范围判断应与拖动一致");
    }

    // ③ 反向拖动（从下往上）与整行覆盖。
    {
        std::vector<Row> rows = {mkRow("aaa bbb", cols), mkRow("ccc ddd", cols)};
        SelectionModel sel;
        sel.press(1, 3, rows, cols);
        sel.drag(0, 0);
        const std::string t = sel.text(rows, cols);
        // 反向选择 = 「从 (0,0) 到 (1,3)」：首行取到行尾、末行取到指定列（标准语义）。
        check(t == "aaa bbb\nccc", "反向拖动应取到从上行开头到本行的内容，实际 [" + t + "]");
    }

    // ④ CJK 占位尾格不产出字符（否则「构」会被拆成两半）。
    {
        std::vector<Row> rows = {mkCjkRow("构建产物", cols), mkRow("tail", cols)};
        SelectionModel sel;
        sel.press(0, 0, rows, cols);
        sel.drag(0, 7);  // 拖到「物」的占位尾格（宽字符跨两列）
        const std::string t = sel.text(rows, cols);
        check(t == "构建产物", "CJK 选择不应被占位尾格污染，实际 [" + t + "]");
    }

    // ⑤ 空白处按下：只选那一格；没选择时 text 为空、covers 恒 false。
    {
        std::vector<Row> rows = {mkRow("a   b", cols)};
        SelectionModel sel;
        sel.press(0, 2, rows, cols);  // 空格
        check(sel.text(rows, cols).empty(), "空白处按下不应选出文本");
        sel.reset();
        check(!sel.active() && !sel.covers(0, 0) && sel.text(rows, cols).empty(),
              "reset 后应无选择");
    }

    // ⑥ 抬手保留范围（Copy 在抬手之后取），再按下则重新开始。
    {
        std::vector<Row> rows = {mkRow("copy me", cols)};
        SelectionModel sel;
        sel.press(0, 0, rows, cols);
        sel.drag(0, 6);
        sel.release();
        check(sel.text(rows, cols) == "copy me", "抬手后应保留选择（键栏 Copy 依赖它）");
        sel.press(0, 6, rows, cols);  // 在 'm' 上重新按下：词 = me
        check(sel.text(rows, cols) == "me", "重新按下应替换旧选择，实际 [" + sel.text(rows, cols) + "]");
    }

    if (failures > 0) {
        std::cerr << failures << " 项不一致\n";
        return 1;
    }
    std::cout << "surface 选择：全部通过（选词 / 跨行拼接 / 反向 / CJK 占位格 / 空选择 / 抬手保留）\n";
    return 0;
}
