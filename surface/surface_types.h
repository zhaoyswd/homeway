// surface/surface_types.h — surface 线格式的**共享类型**（cell / 行 / 几何 / 回滚条）。
//
// 为什么单独一份：数据层（surface_codec）与回滚视图模型（surface_scroll）都要这些类型，
// 而两者互相 include 会成环。这里只放**纯数据**（无编解码逻辑），两边各自 include 它。
// 编解码器、状态机仍在 surface_codec.h；回滚配方在 surface_scroll.h。
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tierterm {

// 颜色来源（与服务端 ColorKind 一致）：客户端按它决定用调色板还是直接 RGB。
enum class ColorKind : uint8_t { None = 0, Palette = 1, Rgb = 2 };

struct Color {
    ColorKind kind = ColorKind::None;
    uint8_t index = 0;  // Palette 时有效
    uint8_t r = 0, g = 0, b = 0;  // Rgb 时有效
};

struct Cell {
    std::string symbol;  // 字素簇（UTF-8）；空 = 空白格
    uint8_t width = 1;   // 1 = 窄，2 = 宽，0 = 占位格
    bool skip = false;   // 占位格：客户端跳过不画
    Color fg, bg;
    uint16_t attr = 0;
};

struct Row {
    uint16_t y = 0;
    std::vector<Cell> cells;
};

struct Geometry {
    uint16_t cols = 0;
    uint16_t rows = 0;
    uint32_t revision = 0;
};

// Scrollbar：回滚条状态（任务 3.3；与服务端同一口径）。行号空间 = [0, total)，
// 视口占 [offset, offset+len)——FETCH-ROWS 的 from 用的就是这套绝对行号。
// ⚠️ 这套行号**会滑动**：回滚裁剪（page 粒度，探针实测）之后同一个行号指向别的内容，
// 所以客户端缓存的行只在「锚点未漂移」时可信（见 surface_scroll.h 的锚点探测）。
struct Scrollbar {
    uint64_t total = 0;
    uint64_t offset = 0;
    uint16_t len = 0;
};

}  // namespace tierterm
