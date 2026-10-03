// surface/surface_scroll.h — surface 腿的**回滚视图模型**（openspec term-vt-backend 任务 3.3）。
//
// 职责边界：渲染层的像素物理（惯性衰减、亚行偏移、单元格量化）**一行不改**——本文件只回答
// 「此刻该画哪些行」与「要不要去拉更早的行」。所以它刻意做成纯逻辑（不碰 GL/NAPI/OHOS），
// 宿主测试能把配方钉死（design D3：镜像 10 视口 / 距顶 1 视口触发 / 3 视口窗 / 单飞 / 冻结在边缘）。
//
// 行号空间（与服务端 FETCH-ROWS 同一套绝对行号）：
//   [0, total) 里视口占 [offset, offset+len)。快照给的镜像窗口就是紧邻视口上方的那些行
//   ⇒ 镜像基址 = offset - 镜像行数（服务端发的镜像行 y 是视口相对值、分块还会重复，**不能**当
//   绝对行号用，见 3.3 的探针记录）。
//
// ⚠️ 这套行号**会滑动**：回滚裁剪（page 粒度）后同一个行号指向别的内容。所以：
//   * 缓存只在「锚点未漂移」时可信 —— 滚回历史期间周期性核对最旧的那一行（takeAnchorProbe）；
//     内容变了 ⇒ 调用方请求 FETCH-SNAPSHOT 全量重建（design D3 的「快照隐含重建镜像」）。
//   * 稳态下 total 会持平（探针实测），所以服务端的「total 变小」只能抓增长期瞬态，
//     稳态滑动**必须**由这里的锚点探测兜住。
#pragma once

#include <cstdint>
#include <map>
#include <vector>

#include "surface/surface_types.h"

namespace tierterm {

// rowEqual 两行内容是否逐格一致（锚点探测用；符号/宽度/颜色/属性/跳过位全比）。
bool rowEqual(const Row& a, const Row& b);

class ScrollModel {
public:
    // 预取配方（design D3 钉死的数字；宿主测试按它断言）。
    static constexpr int kPrefetchTriggerViewports = 1;  // 距缓存顶 1 视口 ⇒ 触发
    static constexpr int kPrefetchWindowViewports = 3;   // 一次拉 3 视口
    static constexpr uint64_t kProbeIntervalMs = 1000;   // 滚回期间的锚点核对间隔
    static constexpr uint64_t kMaxFetchRows = 512;       // 与服务端 surfaceFetchRowsMax 同档

    // Window 是渲染层要的那一份。**几何不变量（2026-09-24 修正，见下）**：
    //   absTop = floor(viewTop)（视图顶的整数下界）
    //   gridOffsetCells = viewTop - absTop ∈ [0, 1)
    //   rows 覆盖 [absTop, absTop + viewportRows]（偏移 > 0 时多带 1 行 overscan，
    //   因为屏幕底边落在 viewTop + viewportRows 之内 ⇒ 需要那一行补齐）
    // 渲染层把整块网格**上移** gridOffsetCells 格 ⇒ 屏幕顶边恰好落在 viewTop：
    // 内容与手指同向、跨整行提交处连续、顶部不出现空白带。
    //
    // ⚠️ 为什么之前是反的：旧实现 absTop 取「视口顶 - 整行数」（= ceil(viewTop)）而偏移取
    // 滚动量的小数部分 ⇒ 屏幕顶边落在 ceil(viewTop) + f 而不是 viewTop，亚行期间内容朝
    // **反方向**漂、每次整行提交再跳回来（用户 2026-09-24 报「内容方向对、滚动方向反」）。
    struct Window {
        std::vector<Row> rows;      // rows[0] 的绝对行号 = absTop
        uint64_t absTop = 0;
        float viewTop = 0.0f;       // 视图顶（绝对行，小数）= offset - 滚动量
        // 整块网格的绘制偏移（格；渲染层换算成 setGridYOffset 像素）。语义 = 「网格要上移多少」
        // ——与 gles_renderer 的实现一致（`y0 - yOffCells`，着色器里 y 向下增大 ⇒ 正 = 上移）。
        float gridOffsetCells = 0.0f;
        int cols = 0;
        int viewportRows = 0;
        bool scrolled = false;      // 不在底部（渲染层据此抑制光标）
        bool valid = false;         // 缓存不足以铺满窗口时为 false（调用方保持上一帧，绝不画空白）
    };

    // onSnapshot：**重建镜像窗口 + 重置 revision 基线**。viewport 与 mirror 都按位置编号，
    // 忽略它们自带的 y。
    //
    // 平移型快照保深层缓存（2026-10-03 修「执行命令后滚不动历史」）：出口侧曾把 vt total 的
    // 正常回落（shell 重绘/清屏的 erase、真裁剪）一律当「回滚裁剪 ⇒ 强制全量」，长历史会话每条
    // 命令都来一记全量快照。这类回落的共同特征是**行号空间纯平移**（len 不变、距底 total-offset
    // 不变、offset 与 total 同步减 D）——深层缓存按键 -D 平移后仍有效（内容没变，行号滑了）；
    // 清空重拉会让滚出镜像窗口的视图永远补不回来（快照风暴期 FETCH 应答又因 revision 推进全被
    // 判过期丢弃）。
    //   * 平移型：m_rows 键 -D（负键丢弃 = 被裁掉的最旧行）、滚动量**原样保留**（viewTop 与
    //     offset 同步平移 ⇒ 距底关系不变；不走锚定公式——公式保持的是旧行号空间的 viewTop）、
    //     新镜像照常并入（同键覆盖 = 就地刷新）。
    //   * 非平移（距底/len 变化）：旧行为——清空缓存按镜像重建。
    //
    // 滚动位置（2026-09-24 评审整改 + 二轮修正）：
    //   - 首次基线（还没有缓存）/ 用户在底部 / **resize**（reflow 后行号语义全变）⇒ 回到底部；
    //   - 其余（含**非平移裁剪**）⇒ 按**绝对行号**锚定（viewTop 不变），**且不 clamp 到新镜像**：
    //     视图可能落在新镜像之外（用户滚得比 10 视口镜像更深），此时保留绝对位置、由
    //     「补缺口预取」（takeFetchRequest 的覆盖判据）把窗口填回来。
    //     旧写法 clamp 到 maxRows 会把用户**瞬移到镜像顶**（真机现象：滚到最头部后
    //     反向一滚，「卡一下 → 跳到中间位置」——镜像只有 10 视口，对 600 行的历史就是中间）；
    //     裁剪时回到底部同样是大跳（保持同一绝对行号 ≈ 原地，内容最多滑一个裁剪粒度）。
    void onSnapshot(const Geometry& geom, const std::vector<Row>& viewport, const std::vector<Row>& mirror,
                    const Scrollbar& sb);

    // onDiffScroll：差分带回滚条（v4）时更新本模型。滚回历史时把 offset 增量加进本地滚动量
    // ⇒ 绝对视图位置不动（新输出只把「距底距离」推大）；视口在底部时滚动量为 0，自然跟随。
    // offset **减小** = 行号空间平移（出口对平移型回落直接发差分：total/offset 同步减 D、距底
    // 不变）。旧实现当「视口被服务端上移」把滚动量往回缩——真实成因不是上移（服务端 vt 视口
    // 恒在底部），正确动作是**缓存键 -D 平移、滚动量不动**。非平移回落到不了这里
    // （CellGrid::applyDiff 先拒收、升级全量快照后走 onSnapshot 的平移判定）。
    void onDiffScroll(const Scrollbar& sb);

    // onFetchReply：并入一次 FETCH-ROWS 应答。drift=true 表示这次应答**正好是锚点探测**且内容
    // 变了——**只是观测**（计数 + 就地刷新该行），调用方不要再升级成全量快照：
    //   行号整体滑动由「差分带回滚条（total 变小）+ 出口侧裁剪快照」兜住；
    //   而 TUI 重写一行也会让锚点内容变（不是滑动）——旧实现把它当漂移 ⇒ 每秒一次全量 ⇒
    //   用户被瞬移到镜像顶（真机现象：「卡一下 → 跳到中间位置」）。
    // 顺序由这里保证：先比对锚点、再并入缓存（并入会覆盖旧内容，先比后写才不会自证清白）。
    void onFetchReply(uint64_t from, const std::vector<Row>& rows, bool& drift);

    // onFetchFailed：清单飞标记（应答被拒/超时/空），允许再次请求。
    void onFetchFailed();

    // scrollByPixels：本地像素滚动。dyPx 约定与既有手势一致（负 = 向更早 = 手指上滑）。
    // 行量 = -dyPx/cellH，**小数部分留着**（渲染层按 setGridYOffset 做亚行偏移），
    // 与 legacy/历史文档路径同一套手感。返回 true = 视图变了（调用方应请求重绘）。
    bool scrollByPixels(float dyPx, float cellH);
    void scrollToBottom();
    bool scrolled() const { return m_scrollRows > 0.0f; }

    // window：组装当前渲染窗口（viewport 由调用方从**实时网格**取，永远是新鲜的）。
    Window window(const std::vector<Row>& viewport, int cols, int viewportRows) const;

    // takeFetchRequest：预取计划（单飞）。返回 true = 需要发 FETCH-ROWS（from/count 已填）。
    bool takeFetchRequest(uint64_t& from, uint16_t& count);
    bool fetchPending() const { return m_fetchPending; }

    // takeAnchorProbe：滚回历史期间周期性核对最旧缓存行（漂移探测）。返回 true = 发一次
    // FETCH-ROWS(row, 1)；应答走 onFetchReply（drift 由它报）。
    //
    // ⚠️ 2026-09-24 评审整改（P1-9）：旧实现用 `m_probeInFlight == 0` 当「没有在飞」的哨兵，
    // 而探测**第 0 行**（滚到回滚开头）时哨兵恒为 0 ⇒ 应答回来判不中 ⇒ 漂移检测静默失效。
    // 现在用独立的 bool + row（0 是合法行号）。
    bool takeAnchorProbe(uint64_t nowMs, uint64_t& row);

    // 观测/诊断（对称 3.8 的计数）。
    struct Stats {
        uint64_t fetchSent = 0;     // 预取请求数
        uint64_t fetchApplied = 0;  // 落地的历史行数
        uint64_t probes = 0;        // 锚点核对次数
        uint64_t drifts = 0;        // 探测到漂移（请求全量重建）次数
        uint64_t frozenHits = 0;    // 预取在飞时滚到边缘被冻结的次数（手感判据）
    };
    const Stats& stats() const { return m_stats; }
    uint64_t cachedTop() const { return m_rows.empty() ? m_offset : m_rows.begin()->first; }
    uint64_t cachedBottom() const { return m_rows.empty() ? m_offset : m_rows.rbegin()->first; }
    size_t cachedRows() const { return m_rows.size(); }
    uint64_t viewportTop() const { return m_offset; }
    const Scrollbar& scrollbar() const { return m_sb; }
    float scrollRows() const { return m_scrollRows; }
    // 滚动上限（行）：视口顶到缓存顶的距离。pill 位置 = scrollRows()/scrollMaxRows()。
    float scrollMaxRows() const {
        return static_cast<float>(m_offset - std::min<uint64_t>(cachedTop(), m_offset));
    }

private:
    // 历史缓存（绝对行号 → 行）。含镜像窗口与按需拉取的行；**不含实时视口**
    // （视口由调用方每帧从网格给进来，所以差分不需要动缓存）。
    std::map<uint64_t, Row> m_rows;
    Scrollbar m_sb;             // 快照带回滚条（诊断/golden 断言用）
    uint64_t m_offset = 0;      // 快照时的视口顶行（绝对行号）
    uint16_t m_viewportRows = 0;
    float m_scrollRows = 0.0f;  // 本地滚动量（行；>0 = 滚离底部，小数 = 亚行偏移）
    bool m_fetchPending = false;
    uint64_t m_lastProbeMs = 0;
    // 锚点探测的单飞状态（哨兵必须与行号解耦：第 0 行是合法行号，不能拿 0 当「没有在飞」）。
    bool m_probeActive = false;
    uint64_t m_probeRow = 0;
    bool m_haveCache = false;
    Stats m_stats;
};

}  // namespace tierterm
