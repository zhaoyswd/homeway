// surface/surface_scroll.cpp — 见 surface_scroll.h。
#include "surface/surface_scroll.h"

#include <algorithm>

namespace tierterm {

bool rowEqual(const Row& a, const Row& b) {
    if (a.cells.size() != b.cells.size()) return false;
    for (size_t i = 0; i < a.cells.size(); i++) {
        const Cell& x = a.cells[i];
        const Cell& y = b.cells[i];
        if (x.symbol != y.symbol || x.width != y.width || x.skip != y.skip || x.attr != y.attr) {
            return false;
        }
        if (x.fg.kind != y.fg.kind || x.fg.index != y.fg.index || x.fg.r != y.fg.r ||
            x.fg.g != y.fg.g || x.fg.b != y.fg.b) {
            return false;
        }
        if (x.bg.kind != y.bg.kind || x.bg.index != y.bg.index || x.bg.r != y.bg.r ||
            x.bg.g != y.bg.g || x.bg.b != y.bg.b) {
            return false;
        }
    }
    return true;
}

// shiftRows 把缓存行号键整体 -shift（负键丢弃 = 行号空间平移后被裁掉的最旧行）。
// 平移语义见 onSnapshot/onDiffScroll 的注释：内容不变、行号滑动，缓存按平移量跟住。
static std::map<uint64_t, Row> shiftedRows(const std::map<uint64_t, Row>& rows, uint64_t shift) {
    std::map<uint64_t, Row> out;
    for (const auto& kv : rows) {
        if (kv.first >= shift) {
            out.emplace(kv.first - shift, kv.second);
        }
    }
    return out;
}

// isPureShift 判「这拍回滚条是不是行号空间纯平移」（差分路径用，CellGrid::applyDiff 同判据
// 放行的帧才会到 onDiffScroll）：len 不变、距底（total-offset）不变、且 offset 与 total
// 同步减同一正量（D>0）。
static bool isPureShift(const Scrollbar& oldSb, const Scrollbar& newSb) {
    if (newSb.offset >= oldSb.offset || newSb.total >= oldSb.total) {
        return false;  // 只处理回落（增长是输出推进，不是平移）
    }
    if (oldSb.len != newSb.len) {
        return false;
    }
    return (oldSb.total - oldSb.offset) == (newSb.total - newSb.offset);
}

// isLenShift 判「全量快照是否可按近似平移保缓存」（onSnapshot 用，比 isPureShift 宽）：
// 只要求 **len 不变**（非 resize/reflow）且 offset 下滑。zsh 重绘的 IL/DL 行重排是
// 非平移回落（total 与 offset 变化量不等、距底变）——出口对它发全量快照——但行号空间
// 整体下滑、内容基本没动，按键 -D 平移后仍有近似效度（错位几行由锚点探测就地纠偏）。
// clear 大清屏（D 巨大）也走这条：平移后负键大面积丢弃、镜像重填，行为等价清空。
static bool isLenShift(const Scrollbar& oldSb, const Scrollbar& newSb) {
    return oldSb.len == newSb.len && newSb.offset < oldSb.offset;
}

void ScrollModel::onSnapshot(const Geometry& geom, const std::vector<Row>& viewport,
                             const std::vector<Row>& mirror, const Scrollbar& sb) {
    // 锚定所需的前态（重建会覆盖它们）。
    const bool hadCache = m_haveCache;
    const uint64_t oldOffset = m_offset;
    const float prevScroll = m_scrollRows;
    const uint16_t oldViewportRows = m_viewportRows;
    const Scrollbar oldSb = m_sb;

    // 近似平移快照：深层缓存平移保留，不清空——清空会让滚出镜像窗口的视图在快照风暴期
    // 永远补不回来（FETCH 应答被 revision 推进判过期）。len 变化（resize/reflow）才清空重建。
    const bool nearShift = hadCache && isLenShift(oldSb, sb);
    if (nearShift) {
        m_rows = shiftedRows(m_rows, oldOffset - sb.offset);
        m_haveCache = !m_rows.empty();
    } else {
        m_rows.clear();
        m_haveCache = false;
    }
    m_sb = sb;
    m_offset = sb.offset;
    m_viewportRows = geom.rows;
    m_fetchPending = false;  // 在飞应答的行号/revision 都是旧空间的，弃了让它重发
    m_probeActive = false;
    m_probeRow = 0;
    m_lastProbeMs = 0;

    // 镜像按**位置**编号：最后一行紧邻视口上方 ⇒ 基址 = offset - 行数。
    // （服务端给的 y 是视口相对值、分块还会重复，不能直接用——3.3 探针实测。）
    // 平移保留的缓存与新镜像自然衔接：同键覆盖 = 新内容就地刷新。
    if (!mirror.empty() && sb.offset >= mirror.size()) {
        const uint64_t base = sb.offset - mirror.size();
        for (size_t i = 0; i < mirror.size(); i++) {
            m_rows[base + i] = mirror[i];
        }
        m_haveCache = true;
    }
    // 滚动位置（见头文件 onSnapshot 的分支）：
    //   * 近似平移：滚动量**原样保留**——viewTop 与 offset 同步平移，距底关系近似不变；
    //     锚定公式保持的是旧行号空间的 viewTop，平移场景下反而引入 D 行错位。
    //   * 首次/在底部/resize ⇒ 回到底部；其余按绝对行号锚定（viewTop 不变）、不 clamp。
    //   * **resize**（行数变了，reflow 后行号语义全变）⇒ 回到底部。
    const bool resized = oldViewportRows != 0 && oldViewportRows != geom.rows;
    if (nearShift) {
        // 保留 prevScroll；平移后行号空间变小，超出新缓存顶的部分由下面的钳制兜底。
    } else if (hadCache && prevScroll > 0.0f && !resized && sb.offset > 0) {
        const float viewTop = static_cast<float>(oldOffset) - prevScroll;
        float next = static_cast<float>(sb.offset) - viewTop;
        if (next < 0.0f) next = 0.0f;
        m_scrollRows = next;
    } else {
        m_scrollRows = 0.0f;
    }
    if (m_scrollRows < 0.0f) m_scrollRows = 0.0f;
    (void)viewport;  // 视口不进缓存：它由调用方每帧从实时网格给（差分不必动缓存）
}

void ScrollModel::onDiffScroll(const Scrollbar& sb) {
    if (sb.offset > m_offset) {
        const uint64_t delta = sb.offset - m_offset;
        // 滚回历史：offset 增长表示「实时底部下移」，把增量加进本地滚动量 ⇒ viewTop 不变
        // （用户看的内容不动，新输出只把「距底距离」推大）。在底部（滚动量 0）自然跟随。
        if (m_scrollRows > 0.0f) m_scrollRows += static_cast<float>(delta);
    } else if (sb.offset < m_offset) {
        // offset 变小 = 行号空间平移（出口对平移型回落直接发差分：total/offset 同步减 D、
        // 距底不变）。缓存键 -D 平移、滚动量不动（viewTop 与 offset 同步平移）。旧实现把
        // 它当「视口被上移」往回缩滚动量——语义错了：服务端 vt 视口恒在底部，offset 减小
        // 只能是行号空间滑动。非平移回落到不了这里（applyDiff 拒收 ⇒ 全量 ⇒ onSnapshot 判定）。
        if (isPureShift(m_sb, sb)) {
            m_rows = shiftedRows(m_rows, m_offset - sb.offset);
            m_haveCache = m_haveCache && !m_rows.empty();
        }
    }
    m_offset = sb.offset;
    m_sb = sb;
    // 钳制：缓存顶之上没有内容可看（maxRows 随 offset 增大而增大，正常不会越界）。
    const float maxRows = static_cast<float>(m_offset - std::min<uint64_t>(cachedTop(), m_offset));
    if (m_scrollRows > maxRows) m_scrollRows = maxRows;
    if (m_scrollRows < 0.0f) m_scrollRows = 0.0f;
}

void ScrollModel::onFetchReply(uint64_t from, const std::vector<Row>& rows, bool& drift) {
    drift = false;
    m_fetchPending = false;
    if (rows.empty()) {
        return;  // 空应答（越界/备用屏）：清单飞，允许再请求
    }
    // ① 先判锚点（**在写入缓存之前**：先写后比等于自证清白）。
    if (m_probeActive && from == m_probeRow) {
        auto it = m_rows.find(from);
        if (it != m_rows.end() && !rowEqual(it->second, rows[0])) {
            m_stats.drifts++;
            drift = true;  // 只作观测（计数）：调用方**不再**升级为全量快照
        }
        m_probeActive = false;
    }
    // ② 并入缓存（键 = 绝对行号）。**漂移也照样并入**——那正是「就地刷新」：
    //    内容变了（TUI 重写回滚行 / 行号滑动）就用服务端的新内容覆盖这一行，
    //    比「请求全量、把用户瞬移到镜像顶」便宜且无感。
    uint64_t y = from;
    for (const auto& r : rows) {
        m_rows[y] = r;
        y++;
    }
    m_stats.fetchApplied += rows.size();
    m_haveCache = true;
}

void ScrollModel::onFetchFailed() { m_fetchPending = false; }

bool ScrollModel::scrollByPixels(float dyPx, float cellH) {
    if (cellH <= 0.0f) return false;
    const float before = m_scrollRows;
    // 向更早 = 滚动量增加（dyPx 负 = 手指上滑，与 legacy 同约定）。
    float next = m_scrollRows - dyPx / cellH;
    if (next < 0.0f) next = 0.0f;
    // 上界：缓存顶之上没有内容可看。预取在飞时**冻结在边缘**（design D3：宁可停在边缘，
    // 也不渲染空白）。
    //
    // 2026-09-24 二轮修正：视图**已在缓存之上**时（快照锚定到镜像之外、补缺口在飞）
    // 不能 clamp 到 maxRows —— 那会在用户反向起手的第一下把他瞬移回镜像顶（真机现象：
    // 「卡一下 → 跳到中间位置 → 才跟手」）。此时保持原位、只冻结「继续往更早」的方向；
    // 预取把缺口补上后 maxRows 自然放开。
    const float maxRows = static_cast<float>(m_offset - std::min<uint64_t>(cachedTop(), m_offset));
    if (next > maxRows) {
        if (m_scrollRows > maxRows) {
            // 已在缓存之上：只冻结「继续往更早」的方向；往更新方向（next 变小）放行。
            if (next > m_scrollRows) {
                next = m_scrollRows;
                if (m_fetchPending) m_stats.frozenHits++;
            }
        } else {
            next = maxRows;
            if (m_fetchPending) m_stats.frozenHits++;
        }
    }
    m_scrollRows = next;
    return m_scrollRows != before;
}

void ScrollModel::scrollToBottom() { m_scrollRows = 0.0f; }

ScrollModel::Window ScrollModel::window(const std::vector<Row>& viewport, int cols,
                                        int viewportRows) const {
    Window w;
    w.cols = cols;
    w.viewportRows = viewportRows;
    w.scrolled = scrolled();
    if (viewportRows <= 0) {
        return w;
    }

    if (!w.scrolled) {
        // 贴底：直接给实时视口（无亚行偏移 ⇒ 不需要 overscan）。
        w.absTop = m_offset;
        w.rows = viewport;
        w.valid = !viewport.empty();
        return w;
    }

    // 视图顶（绝对行，小数）= 视口顶 - 滚动量。网格起点取它的**整数下界**、绘制偏移取
    // 它的小数部分 ⇒ 屏幕顶边恰好落在 viewTop（内容跟手、跨行连续、顶部无空白带）。
    // （2026-09-24 修正：旧实现起点取 ceil(viewTop)、偏移取滚动量的小数 ⇒ 亚行期间内容反向漂。）
    const float viewTopF = static_cast<float>(m_offset) - m_scrollRows;
    const uint64_t topRow = static_cast<uint64_t>(viewTopF < 0.0f ? 0.0f : viewTopF);
    w.absTop = topRow;
    w.viewTop = viewTopF;
    w.gridOffsetCells = viewTopF - static_cast<float>(topRow);  // ∈ [0,1)
    // 窗口 = [topRow, topRow + viewportRows]（偏移 > 0 时多带 1 行 overscan：屏幕底边落在
    // viewTop + viewportRows 之内，没有这一行底部会露空白）。偏移为 0（正好整数行）时
    // 不需要 overscan——那一行本来也在实时视口之外（缓存里没有，硬要会判 invalid）。
    const int need = viewportRows + (w.gridOffsetCells > 0.0f ? 1 : 0);
    for (int i = 0; i < need; i++) {
        const uint64_t idx = topRow + static_cast<uint64_t>(i);
        auto it = m_rows.find(idx);
        if (it != m_rows.end()) {
            w.rows.push_back(it->second);
            continue;
        }
        if (idx >= m_offset) {
            // 落在实时视口里：用视口行补齐（滚到接近底部时常见）。
            const size_t vi = static_cast<size_t>(idx - m_offset);
            if (vi < viewport.size()) {
                w.rows.push_back(viewport[vi]);
                continue;
            }
        }
        // 缓存缺口（预取还没到）：**不补空白**，标记无效让调用方保持上一帧。
        w.valid = false;
        w.rows.clear();
        return w;
    }
    w.valid = true;
    return w;
}

bool ScrollModel::takeFetchRequest(uint64_t& from, uint16_t& count) {
    // 取数闸门（2026-09-24 修「新建会话上下滑不生效、退出重进才行」）：
    //   旧写法是 `!m_haveCache`，而 m_haveCache 只在**快照带非空镜像**时才为真 —— 新会话的
    //   快照镜像本来就是空的（刚创建、视口顶在第 0 行）⇒ 历史长起来之后永远规划不出预取
    //   ⇒ 缓存填不上 ⇒ scrollMaxRows() 恒 0 ⇒ 上滑被夹回原地（唯一自愈是重新 attach 拿到带
    //   镜像的快照，正是用户观察到的「退出重进才行」）。
    //   两条判据各归其位：**有没有基线**看 m_viewportRows（首份快照建立），**有没有东西可拉**
    //   看 m_offset（视口顶之上还有几行）。两者都不再假手 m_haveCache（它继续只表示「手上有没有
    //   镜像/缓存行」，供锚定分支与锚点探测用）。
    if (m_fetchPending || m_viewportRows == 0 || m_offset == 0) {
        return false;  // 没基线 / 视口顶之上没有行（无历史可拉）⇒ 不预取（否则每帧空转刷流量）
    }
    const uint64_t topRow = m_offset - static_cast<uint64_t>(m_scrollRows);
    // 空缓存也要安全：cachedTop() 在空缓存时返回 m_offset（= 视口顶），下面 gap 算出来正好是
    // 「视口上方这一屏」，正是要补的那一段。**不能**直接解引用 m_rows.begin()（空容器是 UB）。
    const uint64_t cacheTop = cachedTop();
    const uint64_t want = static_cast<uint64_t>(kPrefetchWindowViewports) * m_viewportRows;

    // ① 视图窗口**没被缓存覆盖**（快照锚定到镜像窗口之外 / 缓存有洞）⇒ 先补这个缺口，
    //    否则 window() 永远 invalid（冻结在上一帧）。这是「滚回历史 + 降级全量」组合下
    //    的必经路径（2026-09-24 评审整改）。
    //    覆盖判据 = [topRow, topRow+viewportRows]（含 1 行 overscan）都可画：缓存里有，
    //    或落在实时视口里（视口由调用方每帧给进来，不算缺口）。
    auto available = [&](uint64_t idx) {
        if (m_rows.find(idx) != m_rows.end()) {
            return true;
        }
        return idx >= m_offset && idx < m_offset + m_viewportRows;
    };
    // 覆盖判据（2026-09-24 修取数风暴）：可画窗口 = [topRow, topRow+viewportRows)。
    //   ⚠️ 旧写法把上界写成 `i <= m_viewportRows`（多要一行 overscan），而 available() 里
    //   实时视口的右端是**开区间** ⇒ 贴底时那一行（topRow+viewportRows == m_offset+viewportRows）
    //   既不在缓存（缓存只存视口**上方**的行）也不在视口 ⇒ 恒判"不覆盖" ⇒ 每帧都规划补缺口预取，
    //   应答又经 onSurfaceUpdate 触发重绘 ⇒ **拉满帧率的取数风暴**（实测 fps 56 / 预取 490 /
    //   下行 188KB）。旧代码靠"空镜像时闸门不放行"掩盖了它。
    //   现在：窗口行必须可画；overscan 那一行只在**滚离底部**时才要求（那时它是缓存行；
    //   贴底时它在实时视口之下，本来就没有内容可画）。
    bool covered = true;
    for (uint16_t i = 0; i < m_viewportRows; i++) {
        if (!available(topRow + i)) {
            covered = false;
            break;
        }
    }
    if (covered && topRow < m_offset) {
        covered = available(topRow + m_viewportRows);
    }
    if (!covered) {
        // 补缺口：从视图上方 1 视口起、**尽量拉到与已有缓存接上**（count 覆盖到 cacheTop）
        // ——这样视图立刻可画，后续滚动也不会再撞缺口；上限仍是 kMaxFetchRows（大缺口多轮补）。
        from = topRow > m_viewportRows ? topRow - m_viewportRows : 0;
        const uint64_t gap = cacheTop > from ? cacheTop - from : 0;
        const uint64_t need = std::max<uint64_t>(gap, want);
        count = static_cast<uint16_t>(std::min<uint64_t>(need, kMaxFetchRows));
        if (count == 0) {
            return false;
        }
        m_fetchPending = true;
        m_stats.fetchSent++;
        return true;
    }

    // ② 正常预取：触发条件 = 可见窗口顶行距缓存顶不足 1 视口（design D3）。
    const uint64_t trigger = static_cast<uint64_t>(kPrefetchTriggerViewports) * m_viewportRows;
    if (topRow > cacheTop + trigger) {
        return false;
    }
    if (cacheTop == 0) {
        return false;  // 已经拉到回滚最开头
    }
    // 一次拉 3 视口（在缓存顶之上），钳到 0。
    from = cacheTop > want ? cacheTop - want : 0;
    const uint64_t n = cacheTop - from;
    count = static_cast<uint16_t>(std::min<uint64_t>(n, kMaxFetchRows));
    m_fetchPending = true;
    m_stats.fetchSent++;
    return count > 0;
}

bool ScrollModel::takeAnchorProbe(uint64_t nowMs, uint64_t& row) {
    if (!scrolled() || !m_haveCache || m_rows.empty()) {
        return false;
    }
    if (m_probeActive) {
        return false;  // 单飞
    }
    if (m_lastProbeMs != 0 && nowMs - m_lastProbeMs < kProbeIntervalMs) {
        return false;
    }
    row = m_rows.begin()->first;  // 最旧缓存行：裁剪最先吃掉的就是它
    m_probeRow = row;
    m_probeActive = true;
    m_lastProbeMs = nowMs;
    m_stats.probes++;
    return true;
}

}  // namespace tierterm
