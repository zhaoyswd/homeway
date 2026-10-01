// surface/surface_codec.h — surface 线格式的**客户端解码层**（openspec term-vt-backend 任务 3.1 的解码半边）。
//
// 与出口侧 pkg/term/term_surface.go 是同一份契约的两端实现：帧常量、分片契约、SNAPSHOT/DIFF 体
// 布局、cell 行编码都必须逐字段一致。**跨仓 golden fixture（任务 2.8）就是防止这两份实现漂移的**：
// 出口侧生成样例（surface/test/golden/*.bin + manifest.tsv），本文件在**宿主上**解码并断言
// ——所以本文件刻意不依赖 OHOS/NAPI/GLES，只用标准库 + zlib，能被 `tools/surface-host-test.sh`
// 直接编起来跑（宿主测试见 surface/test/host/surface_golden_test.cpp）。
//
// 纪律（对应 design D2/D3/D5）：
//   - **攒齐全部分片才解压**；分片组不完整不应用（宁可重取，不能带病渲染）。
//   - 解码失败一律**拒收**（越界/尺寸不符/revision 断档/光标冲突 ⇒ 请求全量），绝不部分应用。
//   - cell 契约：symbol = 字素簇（客户端免二次聚类）、fg/bg = 调色板索引或 RGB（**主题客户端解析**）、
//     attr = u16 修饰位、skip = 占位格跳过（宽字符尾格）。
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "surface/surface_scroll.h"
#include "surface/surface_selection.h"

namespace tierterm {

// ---- 帧 op（与出口 pkg/term/frames.go 逐值一致）----
constexpr uint8_t kOpSnapshot = 0x0D;      // S→C 全量快照（可分片）
constexpr uint8_t kOpSnapshotDone = 0x0E;  // S→C 快照完成标志
constexpr uint8_t kOpSurfaceDiff = 0x0F;   // S→C 脏行差分（可分片）
constexpr uint8_t kOpFetchRows = 0x10;     // C→S 请求 / S→C 应答（可分片）
constexpr uint8_t kOpInput = 0x11;         // C→S 抽象输入
constexpr uint8_t kOpTheme = 0x12;         // C→S 主题上报
constexpr uint8_t kOpClipboard = 0x13;     // S↔C OSC 52 转发
constexpr uint8_t kOpNotify = 0x14;        // S→C OSC 9 通知
constexpr uint8_t kOpFetchSnapshot = 0x15; // C→S 请求全量

// 帧协议版本（GREETING ver 字节；与服务端 pkg/term termProtoVer 同值）。
constexpr uint8_t kProtoVer = 1;

// GREETING features 的 surface 能力位（客户端见位才在 HELLO 尾随 capability 块）。
constexpr uint32_t kFeatSurface = 1u << 5;
// GREETING features 的「HELLO 版本声明可协商」位（FIX-29 服务端版本门；与服务端
// pkg/term featProtoVerBit 同值）：出口置位 ⇒ 客户端在 HELLO 尾随声明协议版本
// （kCapsProtoVer + 1 字节 kProtoVer），出口据此比对、错配回 ERROR(term_version) 拒腿。
// 旧出口不置位 ⇒ 不声明，尾随字节与旧版逐字节一致（旧出口的严格耗尽解析不被打断）。
constexpr uint32_t kFeatProtoVer = 1u << 6;
// capability 块里的 surface 标志位。
constexpr uint8_t kCapsSurface = 1u << 0;
// capability 块里的「后随 1 字节协议版本」声明位（与服务端 pkg/term capsProtoVer 同值）。
constexpr uint8_t kCapsProtoVer = 1u << 7;

// 双传输开关（任务 3.5）：**模块级**设置（进程内所有页面共用），对之后新建的腿生效。
//   Auto          = 出口声明了 featSurface 位才走 surface（M3 起的默认值）；
//   ForceSurface  = 只要有位就协商（出口没有位时静默退 legacy，日志记一行）；
//   ForceLegacy   = 永不声明能力位（逃生口；M2 阶段的默认值，见 tasks 3.5 的发布阶段口径）。
// 无论哪个模式，**协商失败都会自动回落 legacy 重试一次**（surface_unavailable / bad_capability）。
enum class SurfaceMode : uint8_t { Auto = 0, ForceSurface = 1, ForceLegacy = 2 };

constexpr size_t kFragChunk = 60u << 10;   // 单片 gzip 数据上限（与服务端同值）
constexpr uint8_t kFragMoreBit = 1u << 0;  // 分片头 flags bit0 = 还有后续片
// surface 载荷版本（**帧体头**：SNAPSHOT / SURFACE-DIFF / FETCH-ROWS 应答；与服务端 surfaceVer
// 同值）。
//   v2 = 差分帧带光标（任务 3.10）：光标只在快照里出现会让 surface 腿「打字时光标停在 attach
//        那一刻」，所以在差分体里补了 6 字节光标块；
//   v3 = 快照带回滚条（任务 3.3）：total/offset/len 18 字节，客户端靠它锚定镜像窗口与预取；
//   v4 = **差分帧也带模式位与回滚条**（2026-09-24 评审整改）：模式位变化（鼠标上报/备用屏/
//        括号粘贴/DECCKM）不产生脏行，回滚条每拍都在变（输出追加）——只挂快照会让这两类
//        状态长期滞后（真机后果：TUI 开鼠标上报后触摸路由按旧模式判）。**RowCount 可为 0**：
//        那是「只有状态变了、没有行变」的合法更新（旧实现把它整拍丢掉）。
// 版本不匹配 ⇒ 本腿按协商失败处理（两端必须同升，别指望混搭）。**布局一变就升版本**：
// 真机踩过「字段改了但版本没升 ⇒ 新旧二进制错位、静默错解」的坑，版本门正是为它设的。
constexpr uint8_t kSurfaceVer = 4;
// cell 行/grid 块的**编码版本**（网格块的第一字节；与服务端 vt.cellCodecVersion 同值）。
// 与 kSurfaceVer 是**两个独立的版本空间**：一个管帧体布局，一个管 cell 编码。
// （2026-09-23 的教训：解码器原先拿 kSurfaceVer 校验网格块，两个常量恰好都是 1 所以看不出来；
// 把 surfaceVer 升到 2 时立刻被跨仓 golden fixture 抓住——"网格版本不符"。别再合并它们。）
constexpr uint8_t kCellCodecVer = 1;

// cell 属性位（与服务端 vt.Cell 的 Attr 位布局一致）。
constexpr uint16_t kAttrBold = 1u << 0;
constexpr uint16_t kAttrItalic = 1u << 1;
constexpr uint16_t kAttrFaint = 1u << 2;
constexpr uint16_t kAttrBlink = 1u << 3;
constexpr uint16_t kAttrInverse = 1u << 4;
constexpr uint16_t kAttrInvisible = 1u << 5;
constexpr uint16_t kAttrStrikethrough = 1u << 6;
constexpr uint16_t kAttrOverline = 1u << 7;

// 光标标志位。
constexpr uint8_t kCursorVisible = 1u << 0;
constexpr uint8_t kCursorBlinking = 1u << 1;
constexpr uint8_t kCursorWideTail = 1u << 2;
constexpr uint8_t kCursorPassword = 1u << 3;

// 模式位（与服务端 legacy termMode* 布局一致；客户端这套位本来就在用）。
constexpr uint32_t kModeDECCKM = 1u << 0;
constexpr uint32_t kModeMouse1000 = 1u << 1;
constexpr uint32_t kModeMouse1002 = 1u << 2;
constexpr uint32_t kModeMouse1003 = 1u << 3;
constexpr uint32_t kModeMouse1006 = 1u << 4;
constexpr uint32_t kModeFocus = 1u << 5;
constexpr uint32_t kModeBracketed = 1u << 6;
constexpr uint32_t kModeAltScreen = 1u << 7;

struct Cursor {
    uint16_t x = 0, y = 0;
    uint8_t flags = 0;
    uint8_t shape = 0;
};

struct Snapshot {
    Geometry geom;
    Cursor cursor;
    Scrollbar scroll;   // 回滚条（任务 3.3）：镜像窗口/按需拉取/预取都靠它锚定
    uint32_t modes = 0;
    uint8_t kitty = 0;
    uint8_t misc = 0;
    std::string title;
    std::vector<Row> grid;    // 当前视口
    std::vector<Row> mirror;  // 回滚镜像窗口（备用屏时为空）
};

struct Diff {
    Geometry geom;
    uint16_t rowCount = 0;
    // 本拍光标（v2 起差分也带，任务 3.10）：行内容不一定变，光标却随时在动（打字/方向键/TUI
    // 输入框），所以它不能只挂在快照上——否则 surface 腿的光标永远停在 attach 那一刻。
    Cursor cursor;
    // 本拍模式位（v4，2026-09-24 评审整改）：鼠标上报/备用屏/括号粘贴/DECCKM 不产生脏行，
    // 只挂快照会让触摸路由按旧模式判。
    uint32_t modes = 0;
    // 本拍回滚条（v4）：输出追加时 total/offset 每拍都在变，客户端靠它跟住绝对行号、
    // 算预取触发、检测裁剪（total 变小 ⇒ 行号滑动 ⇒ 请求全量）。
    Scrollbar scroll;
    std::vector<Row> rows;
};

struct FetchRowsReply {
    Geometry geom;
    uint64_t from = 0;
    uint16_t count = 0;
    std::vector<Row> rows;
};

// CellGrid：客户端持有的网格（渲染层的数据源，任务 3.2 从这里读）。
//
// 只存视口 + 镜像窗口；差分按 Y 覆盖。revision 用于对账（断档 ⇒ 请求全量，绝不带病渲染）。
class CellGrid {
public:
    void reset(const Snapshot& snap);
    // 应用差分；几何/revision 不符或光标越界返回 false（调用方应拒收并请求全量）。
    bool applyDiff(const Diff& diff);
    // 镜像窗口（供任务 3.3 的滚动本地使用）。
    const std::vector<Row>& mirror() const { return m_mirror; }
    const std::vector<Row>& rows() const { return m_rows; }
    Geometry geometry() const { return m_geom; }
    // 光标：快照与差分都更新（v2 起差分带光标，任务 3.10——光标每拍都可能动，所以它和
    // 行内容一样属于「差分状态」；早先只随快照更新会让 surface 腿的光标冻在 attach 那一刻）。
    const Cursor& cursor() const { return m_cursor; }
    // 模式位（kMode* 掩码）：快照与差分都更新（v4 起差分带模式位）。
    // 渲染层用它替掉本地 vt 的答案（任务 3.2：surface 腿本地没有 vt，备用屏判定只能来自这里）；
    // 触摸路由（鼠标上报）也读它。
    uint32_t modes() const { return m_modes; }
    bool altScreen() const { return (m_modes & kModeAltScreen) != 0; }
    // 回滚条（v4 起差分也更新）：镜像窗口/预取/裁剪检测都靠它。
    const Scrollbar& scrollbar() const { return m_scroll; }

    // 纯文本（诊断与判据用：导出当前视口，占位格跳过、行尾空白裁掉）。
    std::string toText() const;

private:
    Geometry m_geom;
    Cursor m_cursor;
    uint32_t m_modes = 0;
    Scrollbar m_scroll;
    std::vector<Row> m_rows;
    std::vector<Row> m_mirror;
};

// 分片攒片器：**攒齐才解压**。每组开始的 op 变了就丢弃上一组（服务端不会交错发两组大帧）。
class FragmentAssembler {
public:
    // 喂一片；返回 true 表示本组集齐，body 是解压后的整块载荷。
    // 失败（分片头坏/超片数/解压失败）返回 false 并置 error。
    bool push(uint8_t op, const uint8_t* payload, size_t len, std::vector<uint8_t>& body, std::string& error);
    void reset();

private:
    uint8_t m_op = 0;
    std::vector<uint8_t> m_buf;
    int m_parts = 0;
};

// gzip 解压（zlib；失败返回 false）。
bool gunzip(const uint8_t* data, size_t len, std::vector<uint8_t>& out, std::string& error);

// 体解码（失败返回 false 并置 error；**任何**越界/版本不符都算失败）。
bool decodeSnapshot(const std::vector<uint8_t>& body, Snapshot& out, std::string& error);
bool decodeDiff(const std::vector<uint8_t>& body, Diff& out, std::string& error);
bool decodeFetchRowsReply(const std::vector<uint8_t>& body, FetchRowsReply& out, std::string& error);

// cell 行编码：解 count 行（每行 [y:2][格流…]）。cols 用于判「一行解到多少格为止」。
bool decodeRows(const uint8_t* p, size_t len, int count, int cols, std::vector<Row>& out,
                size_t& consumed, std::string& error);
// 同 decodeRows，但允许少于 count 行（FETCH-ROWS 的短尾；见实现注释）。
bool decodeRowsAtMost(const uint8_t* p, size_t len, int count, int cols, std::vector<Row>& out,
                      size_t& consumed, std::string& error);
// 网格块（[ver][cols:2][rows:2] + 行序列）。
bool decodeGrid(const std::vector<uint8_t>& blob, uint16_t& cols, uint16_t& rows, std::vector<Row>& out,
                std::string& error);

// SurfaceSession：surface 腿的**客户端状态机**（任务 3.1）。
//
// 它把「字节 → 可渲染的网格」这段路走全，并且**只在确信画面一致时才前进**：
//   - 攒分片（不完整不应用）→ 解压 → 解体 → 更新网格；
//   - 差分先做三项校验（行越界 / 几何不符 / revision 断档），任一不过 ⇒ **整帧拒收** +
//     请求全量（绝不部分应用：半新半旧的网格比慢一拍更难查）；
//   - 分片组超时（服务端半路断了/链路丢包）⇒ 丢弃该组 + 请求全量；
//   - SNAPSHOT 到达即重置基线（隐含重建镜像窗口 + revision 重置，对应服务端每次全量 revision+1）。
//
// 为什么状态机放在这一层而不是渲染层：拒收/自愈的判据要能被**宿主测试**覆盖（跨仓 golden
// 与 3.8 的计数都读它），塞进渲染层就只能上设备才能验。
//
// **线程契约（任务 3.2 接线上渲染层后新增，别绕过）**：写侧只有一个线程（transport 的 reader /
// 握手线程：onFrame / applyFetchRows / pollTimeout），读侧是**另一个线程**（渲染线程）。所以
// 网格数据必须经 `copyGridForRender` / `altScreenNow` 读——它们持内部锁把当前网格拷成一份
// 独立的快照；`grid()` 这类直读访问器**只给单线程场景**（宿主测试、3.3 的滚动管理在同一线程里
// 用）。理由：帧间隔 16–33ms 而一次换源重建只要几百微秒，流式输出时两者必然重叠，
// 裸读 std::vector<Row> 会撞上 onFrame 的 `m_rows = snap.grid`（重分配 ⇒ 读到半截指针）。
class SurfaceSession {
public:
    struct Stats {
        uint64_t framesIn = 0;        // 收到的 surface 帧数（含分片；7.4 的流量/频率对照）
        uint64_t snapshots = 0;
        uint64_t diffs = 0;
        uint64_t patchRejects = 0;    // 被拒的差分帧（越界/几何/revision）
        uint64_t fragTimeouts = 0;    // 分片组超时丢弃
        uint64_t fetchSnapshotSent = 0;
        // FETCH-ROWS 应答的失败面（2026-09-24 加：这三类原本静默，导致「预取永久卡死」查不出来）
        uint64_t fetchReplyBad = 0;    // 解不开（版本/头截断/行坏）
        uint64_t fetchReplyStale = 0;  // 几何或 revision 不符（过期应答）
        uint64_t remoteErrors = 0;     // 出口 opError（稳态；原来被静默吞掉）
        uint64_t fetchRowsApplied = 0;
        uint64_t bytesIn = 0;         // 收到的帧载荷净字节（7.4 两端对照用）
        uint64_t lastRejectReason = 0;  // 见 RejectReason
        // 诊断（真机「滚动跳变」类问题的一手数据）：最近一次快照落地前后的滚动位置与
        // 回滚条 total。位置被重锚/裁剪时这里能直接看出跳了多少行。
        float lastSnapScrollBefore = 0.0f;
        float lastSnapScrollAfter = 0.0f;
        uint64_t lastSnapTotalBefore = 0;
        uint64_t lastSnapTotalAfter = 0;
    };

    // onFrame 处理一帧。返回 true 表示**需要向服务端请求全量**（调用方发 FETCH-SNAPSHOT）。
    bool onFrame(uint8_t op, const uint8_t* payload, size_t len, uint64_t nowMs);

    // pollTimeout：分片组超过 fragTimeoutMs 还没集齐 ⇒ 丢弃 + 请求全量。
    //
    // ⚠️ 2026-09-24 评审整改（P1）：本方法原先**没有调用点**（只有宿主测试直接调）⇒
    // 运行期这条自愈路径不可达。现在由 StreamTransport 的 reader 循环在**读空闲一拍**
    // 调用（见 stream_transport.cpp：SO_RCVTIMEO 1s + 分片活跃时判超时）。
    bool pollTimeout(uint64_t nowMs);

    // 应用一次 FETCH-ROWS 应答（按绝对行号并入镜像/历史缓存；几何或 revision 不符则丢弃）。
    bool applyFetchRows(const FetchRowsReply& reply);

    // noteTitle：喂一个标题（快照或 STATE 帧都走它）——**变化才**发 OSC 标题事件。
    // 两处来源共用这一个去重点，避免同一标题发两次/漏发。
    void noteTitle(const std::string& title);
    // 稳态收到出口 opError：计数 + 清预取单飞（否则一次失败会把预取永久卡死）。
    void noteRemoteError();
    // 出口报来的会话状态（STATE 帧的 [agent][state]；5.1 的列表/副标题会用）。
    void noteAgentState(uint8_t agent, uint8_t state);
    uint8_t agentState() const { return m_agentState.load(std::memory_order_relaxed); }
    uint8_t agentKind() const { return m_agentKind.load(std::memory_order_relaxed); }

    // OSC 事件出口（任务 3.4）：type 0 = 标题（来自快照的 title，变化时才发）。
    // 页面既有的 OSC 消费路径（写剪贴板/发通知/改标题）对两条腿一视同仁。
    std::function<void(int type, const std::string& text)> onOscEvent;

    // 载荷版本不符（出口与 App 没同升）：**不是可自愈的拒收**——继续「拒收 → 请求全量 → 还是
    // 解不开」只会变成空转的取全量风暴，而且遮罩撤下时画面是空的。所以单独成一位：传输层据此
    // 把这条腿按协商失败处理（本版客户端没有 legacy 回落，直接失败并提示升级出口），别让它
    // 当普通坏帧重试。
    bool versionMismatch() const { return m_versionMismatch.load(std::memory_order_relaxed); }
    // 新一轮协商开始时清位（状态机被同一条腿的重试/重连复用，别把上一轮的结论带过来）。
    void resetVersionMismatch() { m_versionMismatch.store(false, std::memory_order_relaxed); }

    // ---- 回滚视图（任务 3.3；滚动由触摸线程驱动、渲染线程读，锁与网格同一把）----
    //
    // 本地滚动（像素；负 = 向更早 = 手指上滑，与 legacy 同约定）。返回 true = 视图变了。
    bool scrollByPixels(float dyPx, float cellH);
    void scrollToBottom();
    bool scrolled() const;
    // 渲染窗口（含 1 行 overscan；实时视口取网格）。锁内组装一份拷贝。
    ScrollModel::Window viewWindow() const;
    // 本拍光标（锁内读；渲染层不能裸读 grid()——网格由 transport reader 改写）。
    Cursor cursorForRender() const;
    // 预取计划 / 锚点漂移探测（由 transport 在帧后泵，或宿主在滚动后泵）。
    bool takeFetchRequest(uint64_t& from, uint16_t& count);
    bool takeAnchorProbe(uint64_t nowMs, uint64_t& row);
    void noteFetchFailed();
    ScrollModel::Stats scrollStats() const;
    Scrollbar scrollbar() const;
    float scrollRows() const;
    float scrollMaxRows() const;
    // viewTopAbs：当前**视图顶**的绝对行号（= 实时视口顶 - 本地滚动量）。
    // 回滚条的滑块位置用它除以 total（不能用「滚动量 / 已缓存行数」：缓存是随预取长大的，
    // 拿它当分母会让滑块在惯性滚动中跳变——用户 2026-09-24 报「滚动条不跟惯性、某一刻直接
    // 跳到最终位置」）。
    uint64_t viewTopAbs() const;
    // 回滚缓存的行数（诊断用；与 cachedTop/cachedBottom 同源）。
    size_t cachedRowsForStats() const;
    // ---- 文本选择（任务 3.7 配套；退役本地 vt 后选择在 cell 上做）----
    // 坐标是**窗口内**的行/列（窗口 = 渲染层此刻画的那一份）。press 会按词扩选（长按选词）。
    void selectionPress(int row, int col);
    void selectionDrag(int row, int col);
    void selectionRelease();
    void selectionReset();
    // 当前是否有选择（宿主用它决定「新手势要不要清高亮」——没选择时不必标脏重画）。
    bool selectionActive() const;
    // 取选中文本（从当前窗口提取；无选择返回 false）。
    bool selectionText(std::string& out) const;
    // 该格是否被选中（渲染层逐格问；无选择恒 false）。
    bool selectionCovers(int row, int col) const;

    // 程序是否开了鼠标上报（按快照模式位判）——**触摸路由必须问它**：
    // 本地 vt 在 surface 腿没有模式，而「发了字节就是开了鼠标」是错的判据
    // （3.4 的接线曾据此把 plain shell 的每一次触摸都当鼠标事件吞掉，滚动因此失效）。
    bool mouseReporting() const;

    // ---- 跨线程读面（渲染路径只走这两个）----
    // 锁内把当前网格整份拷进 out（调用方持有副本，之后随便读）；返回是否有过快照。
    bool copyGridForRender(CellGrid& out) const;
    // 当前是否备用屏（渲染层替掉本地 vt 的答案；锁内读，等价于 copyGridForRender 的轻量版）。
    bool altScreenNow() const;
    // 是否有过基线快照（原子，渲染层的光标门与换腿判定用）。
    bool hasSnapshot() const { return m_haveSnapshot.load(std::memory_order_relaxed); }
    // 最近一次**完整快照组**是否成功解码并应用（SNAPSHOT-DONE 的配对判据）。
    //
    // 2026-09-24 评审整改（P1-7）：SNAPSHOT-DONE 原先只看「版本不符」就置 replayDone ⇒
    // 快照解码失败（自洽性校验/体截断）时页面照样撤遮罩、而网格是空的 ⇒ 白屏（首帧永远
    // 不产生，只能等 5s 兜底）。现在 DONE 只在 snapshotOk() 为真时才置 replayDone，
    // 否则请求全量（自愈）——「画面就绪」必须真的有一份能画的网格。
    bool snapshotOk() const { return m_snapshotOk.load(std::memory_order_relaxed); }

    const CellGrid& grid() const { return m_grid; }
    CellGrid& mutableGrid() { return m_grid; }
    const Stats& stats() const { return m_stats; }
    // 已落地的快照数（**跨线程读专用**，2026-09-24 评审整改 L3）：`stats()` 里的
    // `snapshots` 是普通 uint64（Stats 要可拷贝，不能塞 atomic），而它由 transport reader
    // 线程写在 `m_gridMu` 之外——NAPI 侧（回前台探活的判据）读它属数据竞争。这里单独用
    // atomic 记一份，写点与 `m_stats.snapshots++` 相邻（同一处，不会漂移）。
    // FIX-31：跨线程读统计的唯一入口——**锁内拷一份**。stats() 返回的是 m_stats 的
    // 引用（普通 uint64，由 transport reader 线程写），跨线程裸读属数据竞争；此前只给
    // snapshots 一个 atomic 特例（m_snapCount），其余字段照旧竞争，特例本身也已无消费者。
    Stats statsSnapshot() const {
        std::lock_guard<std::mutex> lk(m_statsMu);
        return m_stats;
    }
    // 最近一次拒收原因（观测/诊断）。
    const std::string& lastError() const { return m_lastError; }
    static constexpr uint64_t kFragTimeoutMs = 3000;

private:
    FragmentAssembler m_asm;
    CellGrid m_grid;
    std::atomic<bool> m_haveSnapshot{false};
    std::atomic<bool> m_snapshotOk{false};
    uint64_t m_fragStartMs = 0;
    bool m_fragActive = false;
    Stats m_stats;
    // m_statsMu 保护 m_stats（reader 线程写 / 任意线程经 statsSnapshot() 读）。
    // 写侧只在 onFrame/noteRemoteError/pollTimeout/applyFetchRows 内持锁自增，
    // 锁序 = statsMu → gridMu（无反向路径，见 FIX-31 注释）。
    mutable std::mutex m_statsMu;
    std::string m_lastError;
    std::string m_lastTitle;  // 上一次转发过的标题（变化才发 OSC 事件）
    std::atomic<uint8_t> m_agentKind{0};
    // 255 = 还没有任何状态来源（ATTACHED/STATE 帧都没到）——ITransport::agentState 的
    // 「无 STATE 帧」口径（页面据此不显示副标题）；0=unknown 是合法值，不能当「还没有」。
    std::atomic<uint8_t> m_agentState{255};
    std::atomic<bool> m_versionMismatch{false};
    // 回滚视图模型（缓存 + 本地滚动量 + 预取/探测状态）。与网格同锁：写侧是 transport reader
    // （快照/应答）与触摸线程（滚动），读侧是渲染线程（换源重建）。
    ScrollModel m_scroll;
    SelectionModel m_selection;
    // 只在网格/滚动缓存上锁（写侧 = transport reader + 触摸线程，读侧 = 渲染线程）。
    mutable std::mutex m_gridMu;
};

// ---- 上行编码（任务 3.4；与服务端 decInputEvent/decTheme 对应）----
enum class InputKind : uint8_t { Key = 0, Text = 1, Mouse = 2, Focus = 3 };
// 文本事件的语义位（与服务端 textPaste*Bit 同值）。
//   paste = 本片是粘贴内容（按括号粘贴模式包装）；
//   more  = 后面还有同一段粘贴的后续片（闭合标记推迟到末片）；
//   cont  = 本片是同一段粘贴的后续片（开标记已在首片发过）。
// 大文本（>64KiB 帧长上限）必须分帧，而 200~/201~ 只能在整个序列首尾各一次
// （拆成多个完整块会让程序把一次粘贴当成多次）——2026-09-24 评审整改（P0-3）。
constexpr uint8_t kTextPasteBit = 1u << 0;
constexpr uint8_t kTextPasteMoreBit = 1u << 1;
constexpr uint8_t kTextPasteContBit = 1u << 2;

std::vector<uint8_t> encodeKeyEvent(uint16_t key, uint16_t mods, uint8_t action, const std::string& utf8);
std::vector<uint8_t> encodeTextEvent(const std::string& text, bool paste, bool more = false,
                                     bool cont = false);
std::vector<uint8_t> encodeMouseEvent(uint8_t action, uint8_t button, uint16_t mods, uint16_t x, uint16_t y);
std::vector<uint8_t> encodeFocusEvent(bool gained);
std::vector<uint8_t> encodeTheme(const uint8_t fg[3], const uint8_t bg[3], bool dark);
std::vector<uint8_t> encodeClipboardAnswer(const std::string& text);
std::vector<uint8_t> encodeCapabilityBlock(uint8_t caps);
// encodeHelloTail 组 HELLO 尾随块 [capLen][caps][ver?][idLen][id]（与服务端 pkg/term
// encHelloTail 同布局）：caps 带 kCapsProtoVer 时在 caps 块后插入 1 字节 kProtoVer；
// id 为空则不出 ID 块（与服务端「无 caps 不产 ID」的编码约束同族）。
std::vector<uint8_t> encodeHelloTail(uint8_t caps, const std::string& clientID);

// NOTIFY / CLIPBOARD 的入站解码（任务 3.4 的消费侧）。
bool decodeNotify(const uint8_t* p, size_t len, std::string& out, std::string& error);
bool decodeClipboard(const uint8_t* p, size_t len, uint8_t& kind, std::string& out, std::string& error);

}  // namespace tierterm
