// surface/surface_selection.cpp — 见 surface_selection.h。
#include "surface/surface_selection.h"

#include <algorithm>

namespace tierterm {
namespace {

// WordClass：近似的词类（只区分「同类才扩选」）——字母数字一类（含 _ - . / : @ 这类常见于
// URL/路径的符号），CJK 与其它符号各成一类，空白自成一类。不做 ghostty 的完整 Unicode 词边界。
enum class WordClass { None, Word, Cjk, Space };

bool isAsciiWord(uint32_t cp) {
    return (cp >= '0' && cp <= '9') || (cp >= 'A' && cp <= 'Z') || (cp >= 'a' && cp <= 'z') ||
           cp == '_' || cp == '-' || cp == '.' || cp == '/' || cp == ':' || cp == '@' ||
           cp == '~' || cp == '?' || cp == '=' || cp == '&' || cp == '%' || cp == '+';
}

bool isCjk(uint32_t cp) {
    return (cp >= 0x2E80 && cp <= 0x9FFF) || (cp >= 0xF900 && cp <= 0xFAFF) ||
           (cp >= 0xFF00 && cp <= 0xFFEF) || (cp >= 0x20000 && cp <= 0x3FFFF);
}

// firstCodepoint：取 cell 字素簇的首个码点（词类判定够用）。
uint32_t firstCodepoint(const Cell& c) {
    if (c.symbol.empty()) return ' ';
    const uint8_t* s = reinterpret_cast<const uint8_t*>(c.symbol.data());
    const size_t n = c.symbol.size();
    uint32_t cp = s[0];
    size_t extra = 0;
    if ((cp & 0xE0) == 0xC0) {
        cp &= 0x1F;
        extra = 1;
    } else if ((cp & 0xF0) == 0xE0) {
        cp &= 0x0F;
        extra = 2;
    } else if ((cp & 0xF8) == 0xF0) {
        cp &= 0x07;
        extra = 3;
    }
    for (size_t i = 1; i <= extra && i < n; i++) {
        cp = (cp << 6) | (s[i] & 0x3F);
    }
    return cp;
}

WordClass classOf(const std::vector<Row>& rows, int row, int col) {
    if (row < 0 || row >= static_cast<int>(rows.size())) return WordClass::None;
    const Row& r = rows[row];
    if (col < 0 || col >= static_cast<int>(r.cells.size())) return WordClass::Space;
    const Cell& c = r.cells[col];
    if (c.skip) return WordClass::None;  // 占位尾格：不参与词类
    if (c.symbol.empty()) return WordClass::Space;
    const uint32_t cp = firstCodepoint(c);
    if (isAsciiWord(cp)) return WordClass::Word;
    if (isCjk(cp)) return WordClass::Cjk;
    if (cp == ' ' || cp == '\t') return WordClass::Space;
    return WordClass::None;
}

}  // namespace

void SelectionModel::press(int row, int col, const std::vector<Row>& rows, int cols) {
    m_dragging = true;
    const WordClass want = classOf(rows, row, col);
    m_anchorRow = row;
    m_focusRow = row;
    m_anchorCol = col;
    m_focusCol = col;
    if (want != WordClass::Word && want != WordClass::Cjk) {
        return;  // 空白/其它符号：只选这一格（拖动可扩）
    }
    // 长按选词：向两侧扩到同类边界（宽度有限，避免整屏扫描）。
    // 右边界用调用方给的 cols（= 渲染层的列数）：rows 可能是 overscan 窗口，
    // 拿 rows[0].cells.size() 会在窗口行数不足时把边界算错（2026-09-24 评审整改）。
    const int width = cols > 0 ? cols : (rows.empty() ? 0 : static_cast<int>(rows[0].cells.size()));
    int lo = col;
    while (lo - 1 >= 0 && classOf(rows, row, lo - 1) == want) lo--;
    int hi = col;
    while (hi + 1 < width && classOf(rows, row, hi + 1) == want) hi++;
    m_anchorCol = lo;
    m_focusCol = hi;
}

void SelectionModel::drag(int row, int col) {
    if (!m_dragging && m_anchorRow < 0) {
        return;  // 没有按下的拖动不算选择
    }
    m_focusRow = row;
    m_focusCol = col;
}

void SelectionModel::release() { m_dragging = false; }

void SelectionModel::reset() {
    m_anchorRow = -1;
    m_focusRow = -1;
    m_anchorCol = 0;
    m_focusCol = 0;
    m_dragging = false;
}

void SelectionModel::range(int& row0, int& col0, int& row1, int& col1) const {
    if (m_anchorRow < 0) {
        row0 = col0 = row1 = col1 = -1;
        return;
    }
    const bool forward = m_anchorRow < m_focusRow ||
                         (m_anchorRow == m_focusRow && m_anchorCol <= m_focusCol);
    row0 = forward ? m_anchorRow : m_focusRow;
    col0 = forward ? m_anchorCol : m_focusCol;
    row1 = forward ? m_focusRow : m_anchorRow;
    col1 = forward ? m_focusCol : m_anchorCol;
}

bool SelectionModel::covers(int row, int col) const {
    int r0 = 0, c0 = 0, r1 = 0, c1 = 0;
    range(r0, c0, r1, c1);
    if (r0 < 0 || row < r0 || row > r1) return false;
    if (r0 == r1) return col >= c0 && col <= c1;
    if (row == r0) return col >= c0;
    if (row == r1) return col <= c1;
    return true;  // 中间整行
}

std::string SelectionModel::text(const std::vector<Row>& rows, int cols) const {
    if (!hasCells() || rows.empty()) return {};
    int r0 = 0, c0 = 0, r1 = 0, c1 = 0;
    range(r0, c0, r1, c1);
    if (r0 < 0) return {};
    std::string out;
    for (int r = r0; r <= r1; r++) {
        if (r < 0 || r >= static_cast<int>(rows.size())) continue;
        const Row& row = rows[r];
        const int from = (r == r0) ? c0 : 0;
        const int to = (r == r1) ? c1 : cols - 1;
        std::string line;
        for (int c = from; c <= to; c++) {
            if (c < 0 || c >= static_cast<int>(row.cells.size())) continue;
            const Cell& cell = row.cells[c];
            if (cell.skip) continue;  // 占位尾格：不产出字符（否则 CJK 会被拆开）
            if (cell.symbol.empty()) {
                line.push_back(' ');
                continue;
            }
            line += cell.symbol;
        }
        while (!line.empty() && line.back() == ' ') line.pop_back();  // 行尾裁空白
        if (r > r0) out.push_back('\n');
        out += line;
    }
    return out;
}

}  // namespace tierterm
