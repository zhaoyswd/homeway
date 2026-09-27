// surface/surface_selection.h — surface 网格上的**文本选择**（openspec term-vt-backend 任务 3.7 的配套）。
//
// 为什么要自己实现：退役本地 vt 之后，长按选词 / 拖动选择 / 键栏 Copy 原来靠 `vt->selection*()`，
// 而 surface 腿的「屏」在客户端只是 cell 缓冲 ⇒ 选择必须在 cell 上做。语义与 legacy 对齐：
//   * 长按 → 选「词」（近似词边界，不做 ghostty 那套完整 Unicode 表）；
//   * 长按后拖动 → 按（行, 列）扩选；
//   * 抬手 → 取文本（行尾裁空白、占位尾格不产出字符、行间 \n）；
//   * 渲染层按 `covers()` 给 cell 打 `selected`（与 legacy 同一套渲染约定）。
//
// 坐标口径：**窗口内的行/列**（窗口 = 渲染层此刻画的那一份，含滚动状态）⇒ 选中的就是「看得见的」，
// 与 legacy 在滚回历史时的表现一致。滑动/换帧不改已建立的选择（选择期不滚屏是常态）。
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "surface/surface_types.h"

namespace tierterm {

class SelectionModel {
public:
    // press：按下并**清掉旧选择**（新选择的起点）。row/col 是窗口内坐标。
    void press(int row, int col, const std::vector<Row>& rows, int cols);
    // drag：拖动扩选（按下之后才有意义）。
    void drag(int row, int col);
    // release：结束本次拖选（**选择范围保留**，等 Copy 取文本；legacy 也是这个语义）。
    void release();
    // reset：放弃选择（例：普通点击切换通道时清掉高亮）。
    void reset();

    bool active() const { return m_anchorRow >= 0; }
    // covers：该格是否被选中（渲染层逐格问）。
    bool covers(int row, int col) const;
    // text：从窗口行提取纯文本（越界行忽略；空选择返回空串）。
    std::string text(const std::vector<Row>& rows, int cols) const;
    // 选中的行列范围（观测/测试用）。
    void range(int& row0, int& col0, int& row1, int& col1) const;

private:
    bool hasCells() const { return m_anchorRow >= 0 && m_focusRow >= 0; }

    int m_anchorRow = -1, m_anchorCol = 0;
    int m_focusRow = -1, m_focusCol = 0;
    bool m_dragging = false;
};

}  // namespace tierterm
