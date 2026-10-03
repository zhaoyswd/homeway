// surface/test/host/surface_scroll_test.cpp — 回滚视图模型的宿主判据（任务 3.3）。
//
// 为什么值得单独钉：滚动是「手感」唯一的量化入口，而配方（镜像 10 视口 / 距顶 1 视口触发 /
// 3 视口窗 / 单飞 / 冻结在边缘）在 design D3 里是**钉死的数字**——真机只能看「卡不卡」，
// 数字错了照样"能滚"，只是会多打几倍流量或停在空白上。这里把数字与失效路径一次钉死。
#include <cassert>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include <atomic>

#include "surface/surface_scroll.h"
#include "surface/surface_codec.h"  // 回归：经 SurfaceSession::onFrame 喂 FETCH-ROWS（自死锁）
#include <zlib.h>  // 回归用例自备 gzip 体（wire 体 = [flags][gzip(…)]）

using namespace tierterm;

namespace {

int failures = 0;

void check(bool ok, const std::string& what) {
    if (!ok) {
        failures++;
        std::cerr << "[FAIL] " << what << "\n";
    }
}

// mkRow 造一行可辨认内容（内容 = 绝对行号），用于断言「拿到的是哪一行」。
Row mkRow(uint64_t y, int cols) {
    Row r;
    r.y = static_cast<uint16_t>(y & 0xffff);
    for (int i = 0; i < cols; i++) {
        Cell c;
        c.width = 1;
        r.cells.push_back(c);
    }
    r.cells[0].symbol = std::to_string(y);
    return r;
}

std::vector<Row> mkRows(uint64_t from, int n, int cols) {
    std::vector<Row> out;
    for (int i = 0; i < n; i++) out.push_back(mkRow(from + static_cast<uint64_t>(i), cols));
    return out;
}

// firstSymbol 取窗口首行的符号（= 它的绝对行号，便于判据可读）。
std::string firstSymbol(const ScrollModel::Window& w) {
    if (w.rows.empty() || w.rows[0].cells.empty()) return "";
    return w.rows[0].cells[0].symbol;
}

constexpr int kCols = 80;
constexpr int kViewRows = 30;

// setup 造一个「有 300 行镜像（10 视口）、视口顶在 700」的模型。
ScrollModel setup() {
    ScrollModel m;
    Geometry g;
    g.cols = kCols;
    g.rows = kViewRows;
    g.revision = 1;
    Scrollbar sb;
    sb.total = 1000;
    sb.offset = 700;
    sb.len = kViewRows;
    std::vector<Row> viewport = mkRows(700, kViewRows, kCols);
    std::vector<Row> mirror = mkRows(400, 300, kCols);
    m.onSnapshot(g, viewport, mirror, sb);
    return m;
}

}  // namespace

int main() {
    // ① 贴底：窗口 = 实时视口本身，无亚行偏移、不 scrolled。
    {
        ScrollModel m = setup();
        std::vector<Row> vp = mkRows(700, kViewRows, kCols);
        auto w = m.window(vp, kCols, kViewRows);
        check(w.valid && !w.scrolled && w.gridOffsetCells == 0.0f && w.absTop == 700,
              "贴底窗口应直接用视口（无偏移）");
        check(w.rows.size() == static_cast<size_t>(kViewRows), "贴底窗口行数 = 视口行数");
        check(firstSymbol(w) == "700", "贴底首行应是视口顶行");
    }

    // ② 镜像基址：镜像按位置编号（offset - 行数），与服务端给的 y 无关。
    {
        ScrollModel m = setup();
        check(m.cachedTop() == 400 && m.cachedRows() == 300, "镜像应编号成 [400,700)");
        std::vector<Row> vp = mkRows(700, kViewRows, kCols);
        m.scrollByPixels(-5.5f * 40.0f, 40.0f);  // 上滑 5.5 行
        auto w = m.window(vp, kCols, kViewRows);
        check(w.scrolled && w.valid, "滚起来后窗口应有效");
        // 几何不变量（2026-09-24 修正方向后钉死）：
        //   viewTop = offset - 滚动量 = 694.5；absTop = floor(viewTop) = 694；
        //   gridOffsetCells = viewTop - absTop = 0.5 ∈ [0,1)
        // 渲染层按「上移 gridOffsetCells 格」画 ⇒ 屏幕顶边正好落在 viewTop（内容跟手、
        // 跨整行提交连续、顶部无空白带）。旧实现起点取 ceil(viewTop)=695、偏移取 0.5，
        // 屏幕顶边落在 695.5 ⇒ 亚行期间内容反向漂、每行提交再跳回（用户报的「方向反」）。
        check(w.absTop == 694, "窗口整数顶 = floor(viewTop) = floor(700-5.5) = 694");
        check(firstSymbol(w) == "694", "窗口首行应取自镜像缓存（绝对行号 694）");
        check(w.gridOffsetCells > 0.49f && w.gridOffsetCells < 0.51f, "亚行偏移 = 0.5（∈[0,1)）");
        check(w.viewTop > 694.4f && w.viewTop < 694.6f, "视图顶应保留小数（694.5）");
        check(w.rows.size() == static_cast<size_t>(kViewRows + 1),
              "偏移 > 0 时多带 1 行 overscan（屏幕底边落在 viewTop+viewportRows 之内）");
        check(static_cast<float>(w.absTop) + static_cast<float>(w.rows.size()) >=
                  w.viewTop + static_cast<float>(kViewRows),
              "窗口必须覆盖 [viewTop, viewTop+viewportRows]（否则底部露空白）");
    }

    // ②b 连续性/无空白带：任意小数滚动量下，屏幕顶边恒等于 viewTop，且 absTop 与偏移自洽。
    {
        ScrollModel m = setup();
        std::vector<Row> vp = mkRows(700, kViewRows, kCols);
        const float fracs[] = {0.001f, 0.25f, 0.5f, 0.75f, 0.999f};
        bool ok = true;
        for (float f : fracs) {
            ScrollModel mm = setup();
            mm.scrollByPixels(-(5.0f + f) * 40.0f, 40.0f);  // 上滑 5+f 行
            auto ww = mm.window(vp, kCols, kViewRows);
            const float expectTop = 700.0f - (5.0f + f);
            if (!ww.valid) ok = false;
            if (ww.absTop != static_cast<uint64_t>(expectTop)) ok = false;      // floor
            if (!(ww.gridOffsetCells >= 0.0f && ww.gridOffsetCells < 1.0f)) ok = false;
            if (std::abs((static_cast<float>(ww.absTop) + ww.gridOffsetCells) - ww.viewTop) > 1e-3f)
                ok = false;                                                     // 自洽
            if (std::abs(ww.viewTop - expectTop) > 1e-3f) ok = false;           // 顶边 = viewTop
        }
        check(ok, "任意小数滚动量：absTop=floor(viewTop)、偏移∈[0,1)、顶边=viewTop（连续无跳变）");
    }

    // ③ 预取配方：距缓存顶 < 1 视口才触发；一次 3 视口；单飞。
    {
        ScrollModel m = setup();
        uint64_t from = 0;
        uint16_t count = 0;
        // 刚滚 5 行：距缓存顶 290 行 ≫ 1 视口 ⇒ 不请求。
        m.scrollByPixels(-5.0f * 40.0f, 40.0f);
        check(!m.takeFetchRequest(from, count), "远离缓存顶时不该预取");
        // 滚到距缓存顶 20 行（< 30）⇒ 触发，一次拉 3 视口（90 行）。
        m.scrollByPixels(-(280.0f - 5.0f) * 40.0f, 40.0f);
        check(m.takeFetchRequest(from, count), "距缓存顶不足 1 视口应触发预取");
        check(from == 310 && count == 90, "预取应是 [cacheTop-90, cacheTop) = [310,400)");
        check(m.fetchPending(), "请求后应处于单飞");
        check(!m.takeFetchRequest(from, count), "单飞期间不该再发请求");
    }

    // ④ 冻结在边缘：预取在飞时滚到缓存顶就停住（绝不越过缓存去画空白），并计数。
    {
        ScrollModel m = setup();
        uint64_t from = 0;
        uint16_t count = 0;
        m.scrollByPixels(-400.0f * 40.0f, 40.0f);  // 想滚 400 行，但缓存只有 300 行
        (void)m.takeFetchRequest(from, count);
        m.scrollByPixels(-10.0f * 40.0f, 40.0f);  // 再顶一次：应被冻结
        check(m.scrollRows() == 300.0f, "滚动量应冻结在缓存顶（300 行）");
        check(m.stats().frozenHits >= 1, "冻结应计数（手感判据）");
        std::vector<Row> vp = mkRows(700, kViewRows, kCols);
        auto w = m.window(vp, kCols, kViewRows);
        check(w.valid && firstSymbol(w) == "400", "冻结边缘时应正好画出缓存最旧的一行");
    }

    // ⑤ 应答并入后可以继续往上拉；空应答清单飞（可重试）。
    {
        ScrollModel m = setup();
        uint64_t from = 0;
        uint16_t count = 0;
        m.scrollByPixels(-280.0f * 40.0f, 40.0f);
        check(m.takeFetchRequest(from, count) && from == 310 && count == 90, "先触发一次预取");
        bool drift = false;
        m.onFetchReply(from, mkRows(310, 90, kCols), drift);
        check(!drift && m.cachedTop() == 310, "应答应并入缓存（顶行降到 310）");
        check(!m.fetchPending(), "应答到达应清单飞");
        m.scrollByPixels(-(280.0f - 0.0f) * 40.0f, 40.0f);  // 再往上滚 280 行 → 顶行 ≈ 420-280=140
        check(m.takeFetchRequest(from, count) && from == 220 && count == 90,
              "并集后继续上滚应触发下一窗 [220,310)（每窗 3 视口）");
        m.onFetchReply(from, {}, drift);  // 空应答
        check(!m.fetchPending() && !drift, "空应答应清单飞且不算漂移");
    }

    // ⑥ 锚点漂移探测：滚回历史时核对最旧缓存行；内容变了 ⇒ drift（行号已滑动）。
    {
        ScrollModel m = setup();
        m.scrollByPixels(-10.0f * 40.0f, 40.0f);
        uint64_t row = 0;
        check(m.takeAnchorProbe(10000, row) && row == 400, "首次探测应指向最旧缓存行 400");
        check(!m.takeAnchorProbe(10100, row), "探测单飞：在飞期间不再发");
        bool drift = false;
        m.onFetchReply(400, mkRows(400, 1, kCols), drift);
        check(!drift, "内容一致 ⇒ 不算漂移");
        check(m.stats().probes == 1, "探测计数");
        check(!m.takeAnchorProbe(10500, row), "间隔未到（<1s）不该再探");
        check(m.takeAnchorProbe(11500, row) && row == 400, "间隔到了应再探一次");
        Row drifted = mkRow(999, kCols);  // 同一行号、不同内容
        m.onFetchReply(400, {drifted}, drift);
        check(drift, "锚点内容变了 ⇒ 应报漂移（调用方据此请求全量重建）");
        check(m.stats().drifts == 1, "漂移计数");
    }

    // ⑦ 快照重建：缓存作废（design D3 的隐含语义）+ **滚动位置按绝对行号锚定**。
    //
    // 2026-09-24 评审整改（P0-2 第二半）：旧实现无条件 `m_scrollRows = 0`（回到底部）——
    // 配合「每行输出都降级全量」的旧行为，用户回看历史时会被新输出反复拽回底部。
    // 现在：无裁剪 ⇒ 锚定（viewTop 不变）；裁剪（total 变小，行号滑动）⇒ 回到底部。
    {
        ScrollModel m = setup();  // 缓存 [400,700)，offset=700
        m.scrollByPixels(-50.0f * 40.0f, 40.0f);  // 滚 50 行 ⇒ viewTop = 650
        check(m.scrolled(), "先滚起来");
        Geometry g;
        g.cols = kCols;
        g.rows = kViewRows;
        g.revision = 2;
        Scrollbar sb;
        sb.total = 1200;
        sb.offset = 900;
        sb.len = kViewRows;
        m.onSnapshot(g, mkRows(900, kViewRows, kCols), mkRows(600, 300, kCols), sb);
        // 锚定：新滚动量 = 新 offset - 旧 viewTop = 900 - 650 = 250。
        check(m.scrollRows() > 249.0f && m.scrollRows() < 251.0f,
              "无裁剪的快照应锚定滚动位置（viewTop 不变）而不是回到底部");
        check(m.cachedTop() == 600 && m.cachedRows() == 300, "快照后缓存应是新镜像 [600,900)");
        // 贴底时仍回到底部（滚动量本来就是 0）。
        ScrollModel m2 = setup();
        m2.onSnapshot(g, mkRows(900, kViewRows, kCols), mkRows(600, 300, kCols), sb);
        check(!m2.scrolled() && m2.scrollRows() == 0.0f, "在底部时快照后仍在底部");
    }

    // ⑦b 裁剪（total 变小）：行号整体滑动，但**保持同一绝对行号 ≈ 原地**（距底距离不变），
    //     不再回到底部（回到底部是大跳；内容最多滑动一个裁剪粒度）。
    {
        ScrollModel m = setup();  // total=1000
        m.scrollByPixels(-50.0f * 40.0f, 40.0f);
        Geometry g;
        g.cols = kCols;
        g.rows = kViewRows;
        g.revision = 3;
        Scrollbar sb;
        sb.total = 800;  // < 1000：裁剪发生
        sb.offset = 600;
        sb.len = kViewRows;
        m.onSnapshot(g, mkRows(600, kViewRows, kCols), mkRows(300, 300, kCols), sb);
        // 旧 offset 700、旧位置 50 ⇒ viewTop = 650；新 offset 600 ⇒ 新位置 = 600 - 650 < 0
        // ⇒ 钳到 0（视图顶已在新回滚区之外——被裁掉的就是它上面的内容）。
        check(m.scrollRows() >= 0.0f && m.scrollRows() < 1.0f,
              "裁剪后视图顶被裁掉时应落在回滚区顶部（不弹到别处）");
    }

    // ⑦c 差分带回滚条（v4）：滚回历史时 offset 增长 ⇒ 绝对视图位置不动；在底部时跟随。
    {
        ScrollModel m = setup();  // offset=700
        m.scrollByPixels(-50.0f * 40.0f, 40.0f);  // viewTop = 650
        Scrollbar sb;
        sb.total = 1030;
        sb.offset = 730;  // 输出追加：实时底部下移 30 行
        sb.len = kViewRows;
        m.onDiffScroll(sb);
        check(m.scrollRows() > 79.0f && m.scrollRows() < 81.0f,
              "滚回历史时 offset 增量应加进本地滚动量（视图锚定在 650）");
        std::vector<Row> vp = mkRows(730, kViewRows, kCols);
        auto w = m.window(vp, kCols, kViewRows);
        check(w.valid && w.absTop == 650, "视图顶应仍是 650（新输出只把距底距离推大）");
        // 在底部：滚动量保持 0 ⇒ 自然跟随实时底部。
        ScrollModel m2 = setup();
        m2.onDiffScroll(sb);
        check(!m2.scrolled() && m2.scrollRows() == 0.0f, "在底部时差分应保持跟随");
    }

    // ⑦d 锚点探测在第 0 行也必须有效（P1-9：旧实现拿 0 当「没有在飞」的哨兵）。
    {
        ScrollModel m;
        Geometry g;
        g.cols = kCols;
        g.rows = kViewRows;
        g.revision = 1;
        Scrollbar sb;
        sb.total = 100;
        sb.offset = 50;
        sb.len = kViewRows;
        // 镜像 50 行 ⇒ 基址 = 50-50 = 0（最旧缓存行就是 0）。
        m.onSnapshot(g, mkRows(50, kViewRows, kCols), mkRows(0, 50, kCols), sb);
        m.scrollByPixels(-10.0f * 40.0f, 40.0f);
        uint64_t row = 999;
        check(m.takeAnchorProbe(10000, row) && row == 0, "探测应指向最旧缓存行 0");
        bool drift = false;
        m.onFetchReply(0, {mkRow(777, kCols)}, drift);  // 同一行号、不同内容
        check(drift, "第 0 行的锚点漂移必须能检出（哨兵与行号解耦）");
    }

    // ⑦e 视图落在缓存顶之上（快照锚定到镜像窗口之外）⇒ 预取补缺口，而不是干等冻结。
    {
        ScrollModel m = setup();  // 缓存 [400,700)
        // 锚定到 200：模拟「滚回历史深处时来了一次全量、镜像只覆盖近处」。
        Geometry g;
        g.cols = kCols;
        g.rows = kViewRows;
        g.revision = 2;
        Scrollbar sb;
        sb.total = 1000;
        sb.offset = 700;
        sb.len = kViewRows;
        m.onSnapshot(g, mkRows(700, kViewRows, kCols), mkRows(400, 300, kCols), sb);
        // 直接滚到 200（缓存顶 400 之上）：
        m.scrollByPixels(-500.0f * 40.0f, 40.0f);  // 被钳到 300（缓存顶）
        // 手工制造「视图在缓存顶之上」的形态：并入一段远处缓存后把滚动量顶到 500 之外。
        bool drift = false;
        m.onFetchReply(150, mkRows(150, 10, kCols), drift);
        m.scrollByPixels(-(700.0f - 160.0f) * 40.0f, 40.0f);  // viewTop ≈ 160
        uint64_t from = 0;
        uint16_t count = 0;
        check(m.takeFetchRequest(from, count), "视图在缓存顶之上应触发补缺口预取");
        check(from <= 160 && from + count >= 160, "补缺口应覆盖当前视图（from..from+count 含 160）");
    }

    // ⑧ 缓存缺口不画空白：应答只覆盖一段、与镜像之间有**洞**时，滚到洞上必须报 invalid
    //（调用方保持上一帧，绝不补空白——design D3 的「宁可冻结」）。
    {
        ScrollModel m = setup();  // 缓存 [400,700)
        // 手工并入一段与镜像不相邻的应答：缓存变成 {310..319} ∪ {400..699}，洞 = [320,400)
        bool drift = false;
        m.onFetchReply(310, mkRows(310, 10, kCols), drift);
        check(m.cachedTop() == 310, "并集后缓存顶应是 310（中间留洞）");
        // 滚到洞上：窗口顶 360 ⇒ 需要 [360,391)，其中 360..399 不在缓存里
        m.scrollByPixels(-(700.0f - 360.0f) * 40.0f, 40.0f);
        std::vector<Row> vp = mkRows(700, kViewRows, kCols);
        auto w = m.window(vp, kCols, kViewRows);
        check(!w.valid && w.rows.empty(), "缓存洞应报 invalid（绝不补空白）");
    }

    // ⑦f 深滚时来快照：**保留绝对位置、不 clamp 到新镜像**（否则瞬移到镜像顶 = 用户报的
    //    「跳到中间位置」），并由补缺口预取把视图窗口填回来。
    {
        ScrollModel m = setup();  // 缓存 [400,700)，视口顶 700
        // 先深滚到 200（缓存之外）：直接设置滚动量（模拟「快照前用户就在深处」）。
        m.scrollByPixels(-500.0f * 40.0f, 40.0f);  // 被钳到 300（缓存顶）
        // 关键：手工把位置放到缓存之上（等价于「快照后锚定到镜像之外」的前态）。
        Geometry g;
        g.cols = kCols;
        g.rows = kViewRows;
        g.revision = 2;
        Scrollbar sb;
        sb.total = 1000;
        sb.offset = 700;
        sb.len = kViewRows;
        // 快照前的「旧 offset」= 700、位置在 500 ⇒ viewTop = 200；新快照 offset 仍 700 ⇒
        // 期望位置保持 500（而不是被 clamp 到镜像的 300）。
        // 先造出「位置 500」的前态：把缓存顶抬到 200 再滚到顶。
        bool drift = false;
        m.onFetchReply(200, mkRows(200, 200, kCols), drift);  // 缓存顶 → 200
        m.scrollByPixels(-500.0f * 40.0f, 40.0f);             // 滚到缓存顶 ⇒ 位置 = 500
        check(m.scrollRows() > 499.0f && m.scrollRows() < 501.0f, "先滚到缓存顶（位置 500）");
        m.onSnapshot(g, mkRows(700, kViewRows, kCols), mkRows(400, 300, kCols), sb);
        check(m.scrollRows() > 499.0f && m.scrollRows() < 501.0f,
              "快照必须保留绝对位置（500），不得 clamp 到镜像顶（300）");
        // 反向起手的第一下也不许被 clamp 弹回镜像顶。
        m.scrollByPixels(5.0f * 40.0f, 40.0f);  // 手指上滑 5 行 = 往更新走
        check(m.scrollRows() > 494.0f && m.scrollRows() < 496.0f,
              "视图在缓存之上时反向起手应立刻跟手（不弹回镜像顶）");
        // 补缺口预取应覆盖当前视图（视图顶的绝对行号 = 700 - 495 = 205）。
        uint64_t from = 0;
        uint16_t count = 0;
        check(m.takeFetchRequest(from, count), "视图在缓存之外 ⇒ 应触发补缺口预取");
        check(from <= 205 && static_cast<uint64_t>(from) + count >= 205 + kViewRows,
              "补缺口应覆盖当前视图（[205, 235]）");
    }

    // ⑦g 锚点内容变化 = 就地刷新（不再请求全量）：缓存里那一行换成服务端的新内容。
    {
        ScrollModel m = setup();
        m.scrollByPixels(-10.0f * 40.0f, 40.0f);
        uint64_t row = 0;
        check(m.takeAnchorProbe(10000, row) && row == 400, "探测指向最旧缓存行 400");
        Row drifted = mkRow(999, kCols);  // 同一行号、不同内容
        bool drift = false;
        m.onFetchReply(400, {drifted}, drift);
        check(drift, "锚点内容变了应报 drift（观测）");
        // 关键：**内容已就地刷新**（旧实现 drift 时不并入缓存）。
        check(m.cachedRows() >= 300, "drift 不应丢缓存");
        // 再探一次：这次服务端内容与缓存一致（说明上次确实并入了）。
        uint64_t row2 = 0;
        check(m.takeAnchorProbe(12000, row2) && row2 == 400, "间隔到了再探一次");
        bool drift2 = false;
        m.onFetchReply(400, {drifted}, drift2);
        check(!drift2, "同一内容再探不应再报 drift（证明上次已就地刷新）");
    }


    // ⑪ 新会话冷启动（用户报的「新建会话上下滑不生效，退出重进才行」的根因判据）：
    //    刚创建时没有历史 ⇒ 快照的**镜像窗口是空的**（合法形态），视口顶就在第 0 行。
    //    之后输出长起来（差分把 offset 前移）——此时**必须**能规划预取把历史填进缓存，
    //    否则滚动上限恒 0（滑不动），而唯一的自愈路径是重新 attach（退出重进）拿到带镜像的快照。
    {
        ScrollModel m;
        Geometry g;
        g.cols = kCols;
        g.rows = kViewRows;
        g.revision = 1;
        Scrollbar sb0;                 // 刚创建：没有历史
        sb0.total = kViewRows;
        sb0.offset = 0;
        sb0.len = kViewRows;
        m.onSnapshot(g, mkRows(0, kViewRows, kCols), {}, sb0);
        check(m.cachedRows() == 0, "新会话的快照可以没有镜像（正常形态）");
        uint64_t f0 = 0;
        uint16_t c0 = 0;
        check(!m.takeFetchRequest(f0, c0), "视口顶之上没有行时不得预取（否则每帧空转刷流量）");

        // 输出长起来：offset 前移到 40（total=70、仍然贴底：len=30 ⇒ 视口占 [40,70)）
        Scrollbar sb1;
        sb1.total = 70;
        sb1.offset = 40;
        sb1.len = kViewRows;
        m.onDiffScroll(sb1);
        check(m.scrollMaxRows() == 0.0f, "还没拉到历史时滚动上限确实是 0（滑不动）");
        uint64_t from = 0;
        uint16_t count = 0;
        check(m.takeFetchRequest(from, count), "历史出现后必须能规划预取（这是修「滑不动」的关键）");
        check(m.fetchPending(), "预取应进入单飞");

        // 应答到达：历史填进缓存 ⇒ 滚动上限放开、上滑真的滚得动
        // （应答范围按模型给的 from 造——补缺口路径的起点是「视口上方 1 视口」，不是 0）
        std::vector<Row> rows = mkRows(from, 40, kCols);
        bool drift = false;
        m.onFetchReply(from, rows, drift);
        check(m.cachedTop() == from && m.cachedRows() == 40, "预取应答应并入缓存（新会话也能填上）");
        check(m.scrollMaxRows() > 0.0f, "有历史 ⇒ 滚动上限必须 > 0");
        std::vector<Row> vp = mkRows(40, kViewRows, kCols);
        check(m.scrollByPixels(-5.0f * 40.0f, 40.0f) && m.scrolled(), "新会话里上滑应真的滚起来");
        auto w2 = m.window(vp, kCols, kViewRows);
        check(w2.valid && firstSymbol(w2) == "35", "窗口首行应取自新填的历史（40-5=35）");
    }


    // ⑫ 取数风暴与"按需深潜"（2026-09-24 真机实测到 fps 56 / 预取 490 / 下行 188KB 后加的判据）：
    //    贴底时按设计只拉**一个 3 视口窗口**，之后必须停手（旧代码的覆盖判据无条件多要一行
    //    overscan，而实时视口的可用判据右端是开区间 ⇒ 贴底恒判"不覆盖" ⇒ 每帧一次取数，
    //    应答又经 onSurfaceUpdate 触发重绘 ⇒ 自持风暴）；只有滚到窗口边缘才继续拉下一窗。
    {
        ScrollModel m;
        Geometry g;
        g.cols = kCols;
        g.rows = kViewRows;
        g.revision = 1;
        Scrollbar sb0;                       // 新会话：空镜像（合法形态）
        sb0.total = kViewRows;
        sb0.offset = 0;
        sb0.len = kViewRows;
        m.onSnapshot(g, mkRows(0, kViewRows, kCols), {}, sb0);
        Scrollbar sb1;                       // 输出长到 400 行、视口顶在 370
        sb1.total = 400;
        sb1.offset = 370;
        sb1.len = kViewRows;
        m.onDiffScroll(sb1);
        check(m.scrollMaxRows() == 0.0f, "还没有历史缓存时滑不动（这就是用户报的形态）");

        uint64_t from = 0;
        uint16_t count = 0;
        check(m.takeFetchRequest(from, count) && from == 280 && count == 90,
              "首次应按设计拉 3 视口窗口 [280,370)");
        bool d = false;
        m.onFetchReply(from, mkRows(from, count, kCols), d);
        check(m.scrollMaxRows() > 89.0f && m.scrollMaxRows() < 91.0f, "应答落地后可滚 90 行");
        std::vector<Row> vp = mkRows(370, kViewRows, kCols);
        check(m.scrollByPixels(-5.0f * 40.0f, 40.0f) && m.scrolled(), "上滑必须真的滚得动");
        auto w3 = m.window(vp, kCols, kViewRows);
        check(w3.valid && firstSymbol(w3) == "365", "窗口首行 = 370-5（取自刚拉到的历史）");

        from = 0;
        count = 0;
        bool storm = false;                  // 贴底连泵 60 次 = 模拟 60 帧
        for (int i = 0; i < 60; i++) {
            if (m.takeFetchRequest(from, count)) storm = true;
        }
        check(!storm, "窗口够用时贴底必须停手（旧代码在这里每帧一次 = 取数风暴）");

        // 滚到窗口边缘才继续拉（按需深潜，不是一次拉光）。
        m.scrollByPixels(-85.0f * 40.0f, 40.0f);
        check(m.takeFetchRequest(from, count) && count > 0, "滚到窗口边缘才继续拉下一窗");
    }

    // ---- 回归（2026-10-03 自死锁）：经 onFrame 喂 FETCH-ROWS 应答 ----
    // 修复前：onFrame 全程持 statsMu，kOpFetchRows 分支调 applyFetchRows（公开壳再取
    // 同一把非递归锁）⇒ reader 线程当场死锁——真机 THREAD_BLOCK_3S/6S 连环杀进程的
    // 直接根因（此前无任何用例经 onFrame 喂 FETCH-ROWS——golden 的短尾用例直接调
    // decodeFetchRowsReply，零覆盖）。死锁与应答内容无关（锁获取在逻辑之前）；注意
    // wire 体 = [flags][gzip(ver+…)]——裸字节会在攒片器的 gunzip 就失败早退、根本到
    // 不了 switch（首版回归就因此空转通过）。线程+超时判：修复后 2s 内必须返回；再
    // 死锁 = 本用例红（detached 线程残留不阻塞进程退出）。
    {
        SurfaceSession s;
        std::vector<uint8_t> inner;  // 解压后的体：ver/revision/cols/rows/from/count
        auto u8v = [&](uint8_t v) { inner.push_back(v); };
        auto u16v = [&](uint16_t v) { u8v(v & 0xff); u8v((v >> 8) & 0xff); };
        auto u32v = [&](uint32_t v) { for (int i = 0; i < 4; i++) u8v((v >> (8 * i)) & 0xff); };
        auto u64v = [&](uint64_t v) { for (int i = 0; i < 8; i++) u8v((v >> (8 * i)) & 0xff); };
        u8v(4 /*kSurfaceVer*/);
        u32v(1 /*revision*/);
        u16v(80 /*cols*/);
        u16v(24 /*rows*/);
        u64v(0 /*from*/);
        u16v(0 /*count：0 行（短尾合法）*/);
        uLongf bound = compressBound(inner.size()) + 64;
        std::vector<uint8_t> gz(bound);
        uLongf gzLen = bound;
        // gzip 容器（windowBits 15+16）——攒片器按 gzip 魔数解压（zlib 容器会被拒）。
        z_stream zs{};
        deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
        zs.next_in = inner.data();
        zs.avail_in = static_cast<uInt>(inner.size());
        zs.next_out = gz.data();
        zs.avail_out = static_cast<uInt>(gzLen);
        const int zrc = deflate(&zs, Z_FINISH);
        gzLen = zs.total_out;
        deflateEnd(&zs);
        check(zrc == Z_STREAM_END, "回归用例自备 gzip 体失败（测试自身问题）");
        gz.resize(gzLen);
        std::vector<uint8_t> wire;  // flags=0（无后续片）+ gzip 体
        wire.push_back(0);
        wire.insert(wire.end(), gz.begin(), gz.end());
        std::atomic<bool> fin{false};
        std::thread th([&]() {
            s.onFrame(kOpFetchRows, wire.data(), wire.size(), 0);
            fin = true;
        });
        th.detach();
        for (int waited = 0; waited < 200 && !fin.load(); waited++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        check(fin.load(), "onFrame(kOpFetchRows) 不得自死锁（statsMu 重入；2s 内必须返回）");
    }

    // ⑫ 平移型全量快照保深层缓存（2026-10-03 修「执行命令后滚不动历史」）：出口旧版对
    //     total 回落（shell 重绘/erase）强制全量快照，长历史会话每条命令一记；这些回落的
    //     特征是行号空间纯平移（len/距底不变、offset 与 total 同步减 D）——深层缓存按键
    //     -D 平移后仍有效，清空重拉会让滚出镜像窗口的视图在快照风暴期永远补不回来。
    {
        ScrollModel m = setup();                       // 缓存 [400,700)，offset=700，total=1000
        m.scrollByPixels(-50.0f * 40.0f, 40.0f);       // viewTop = 650，滚 50 行
        bool drift = false;
        m.onFetchReply(310, mkRows(310, 90, kCols), drift);  // 预取并入 [310,400)——深层历史
        check(m.cachedTop() == 310, "前置：预取后缓存顶应到 310");
        Geometry g;
        g.cols = kCols;
        g.rows = kViewRows;
        g.revision = 9;
        Scrollbar sb;
        // 平移型回落：total 1000→900、offset 700→600（D=100）、len 不变、距底 300→300 不变。
        sb.total = 900;
        sb.offset = 600;
        sb.len = kViewRows;
        m.onSnapshot(g, mkRows(600, kViewRows, kCols), mkRows(300, 300, kCols), sb);
        check(m.cachedTop() == 210, "平移型快照应保留深层缓存（预取行 310 平移到 210）");
        check(m.scrollRows() > 49.0f && m.scrollRows() < 51.0f,
              "平移型快照滚动量应原样保留（viewTop 与 offset 同步平移）");
        // 内容连续性分两层：视口上方 10 视口内以**新镜像**为准（新数据就地刷新同键）；
        // 更深处（新镜像之外、原预取区）是平移过来的旧内容——滚到 250（预取区 [210,300)）
        // 画出的应是原预取行 350 的内容（行号平移、内容不动）。
        std::vector<Row> vp = mkRows(600, kViewRows, kCols);
        auto w = m.window(vp, kCols, kViewRows);
        check(w.valid && w.absTop == 550, "平移后视图顶 = 新 offset - 滚动量 = 550");
        m.scrollByPixels(-(350.0f - 50.0f) * 40.0f, 40.0f);  // 滚动量 50 → 350
        auto wDeep = m.window(vp, kCols, kViewRows);
        check(wDeep.valid && wDeep.absTop == 250 && firstSymbol(wDeep) == "350",
              "平移后深层窗口内容应是原预取行（absTop=250 → 原 350 行内容）");
    }

    // ⑬ 差分平移（出口对平移型回落直接发差分）：onDiffScroll 收到 offset/total 同步回落
    //     ⇒ 缓存键平移、滚动量不动。旧实现把 offset 减小当「视口被上移」把滚动量往回缩——
    //     语义错了（服务端 vt 视口恒在底部，offset 减小只能是行号空间滑动）。
    {
        ScrollModel m = setup();                       // [400,700)，offset=700
        m.scrollByPixels(-50.0f * 40.0f, 40.0f);       // 滚 50 行
        Scrollbar sb;
        sb.total = 900;                                // total/offset 同步 -100：平移
        sb.offset = 600;
        sb.len = kViewRows;
        m.onDiffScroll(sb);
        check(m.cachedTop() == 300, "差分平移应把缓存顶 400 平移到 300");
        check(m.scrollRows() > 49.0f && m.scrollRows() < 51.0f,
              "差分平移滚动量应不动（旧实现错误地往回缩 100）");
        std::vector<Row> vp = mkRows(600, kViewRows, kCols);
        auto w = m.window(vp, kCols, kViewRows);
        check(w.valid && firstSymbol(w) == "650", "差分平移后首行内容应是原 650 行");
    }

    // ⑭ CellGrid::applyDiff 对平移型回落放行、非平移拒收：这是差分路径的闸门——平移型
    //     （len/距底不变）接受，让 ScrollModel 平移缓存；非平移（距底变化）整帧拒收走全量。
    {
        CellGrid grid;
        Snapshot snap;
        snap.geom.cols = kCols;
        snap.geom.rows = kViewRows;
        snap.geom.revision = 1;
        snap.scroll.total = 1000;
        snap.scroll.offset = 970;  // 贴底：offset = total - len
        snap.scroll.len = kViewRows;
        snap.grid = mkRows(970, kViewRows, kCols);
        grid.reset(snap);
        Diff d;
        d.geom = snap.geom;
        d.scroll.len = kViewRows;
        // 平移型回落：total/offset 同步 -11（zsh 重绘锯齿的典型幅度）。
        d.scroll.total = 989;
        d.scroll.offset = 959;
        check(grid.applyDiff(d), "平移型回落的差分应放行（客户端自己平移缓存）");
        check(grid.scrollbar().total == 989, "放行后回滚条应随差分更新");
        // 非平移回落：距底变化（total-offset 从 30 变 25）⇒ 拒收走全量自愈。
        Diff d2;
        d2.geom = snap.geom;
        d2.scroll.len = kViewRows;
        d2.scroll.total = 960;
        d2.scroll.offset = 935;  // 距底 960-935=25 ≠ 30
        check(!grid.applyDiff(d2), "非平移回落的差分必须拒收（行号语义已变，走全量重锚）");
    }

    if (failures > 0) {
        std::cerr << failures << " 项不一致\n";
        return 1;
    }
    std::cout << "surface 回滚模型：全部通过（镜像基址 / 亚行偏移 / 预取配方 / 冻结 / 锚点漂移 / 锚定重建 / 补缺口 / 新会话冷启动 / FETCH-ROWS 自死锁回归 / 平移保缓存）\n";
    return 0;
}
