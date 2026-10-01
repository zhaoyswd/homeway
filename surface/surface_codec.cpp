// surface/surface_codec.cpp — 见 surface_codec.h。
//
// 刻意不依赖 OHOS/NAPI/GLES：本文件要能在**宿主**上编起来跑跨仓 golden fixture
// （tools/surface-host-test.sh），否则「两仓各自解码断言一致」就没有落点。
#include "surface/surface_codec.h"

#include <zlib.h>

#include <cstring>

namespace tierterm {
namespace {

// 小端读取器（带边界检查；越界一律失败，不做「尽量解」）。
class Reader {
public:
    Reader(const uint8_t* p, size_t len) : m_p(p), m_len(len) {}
    bool u8(uint8_t& v) { return take(1, [&](const uint8_t* q) { v = q[0]; }); }
    bool u16(uint16_t& v) {
        return take(2, [&](const uint8_t* q) { v = static_cast<uint16_t>(q[0] | (q[1] << 8)); });
    }
    bool u32(uint32_t& v) {
        return take(4, [&](const uint8_t* q) {
            v = static_cast<uint32_t>(q[0] | (q[1] << 8) | (q[2] << 16) | (q[3] << 24));
        });
    }
    bool u64(uint64_t& v) {
        return take(8, [&](const uint8_t* q) {
            uint64_t out = 0;
            for (int i = 7; i >= 0; --i) out = (out << 8) | q[i];
            v = out;
        });
    }
    bool bytes(size_t n, const uint8_t*& out) {
        if (m_off + n > m_len) return false;
        out = m_p + m_off;
        m_off += n;
        return true;
    }
    bool str(size_t n, std::string& out) {
        const uint8_t* p = nullptr;
        if (!bytes(n, p)) return false;
        out.assign(reinterpret_cast<const char*>(p), n);
        return true;
    }
    size_t remaining() const { return m_len - m_off; }
    const uint8_t* rest() const { return m_p + m_off; }

private:
    template <typename F>
    bool take(size_t n, F&& fn) {
        if (m_off + n > m_len) return false;
        fn(m_p + m_off);
        m_off += n;
        return true;
    }
    const uint8_t* m_p;
    size_t m_len;
    size_t m_off = 0;
};

bool readVarint(Reader& r, uint64_t& v) {
    v = 0;
    for (int i = 0; i < 10; i++) {
        uint8_t b = 0;
        if (!r.u8(b)) return false;
        v |= static_cast<uint64_t>(b & 0x7f) << (7 * i);
        if ((b & 0x80) == 0) return true;
    }
    return false;
}

// 颜色（与服务端 appendColor 对应）。
bool readColor(Reader& r, Color& out) {
    uint8_t tag = 0;
    if (!r.u8(tag)) return false;
    switch (tag) {
        case 0:
            out.kind = ColorKind::None;
            return true;
        case 1: {
            uint8_t idx = 0;
            if (!r.u8(idx)) return false;
            out.kind = ColorKind::Palette;
            out.index = idx;
            return true;
        }
        case 2: {
            const uint8_t* p = nullptr;
            if (!r.bytes(3, p)) return false;
            out.kind = ColorKind::Rgb;
            out.r = p[0];
            out.g = p[1];
            out.b = p[2];
            return true;
        }
        default:
            return false;
    }
}

// 一行格流：[y:2] + （0x00 空白游程 / 0x01 完整格 / 0x02 重复上一格）。
bool readRow(Reader& r, int cols, Row& out, std::string& error) {
    uint16_t y = 0;
    if (!r.u16(y)) {
        error = "行头截断";
        return false;
    }
    out.y = y;
    out.cells.clear();
    out.cells.reserve(static_cast<size_t>(cols));

    Cell prev;
    bool havePrev = false;
    while (static_cast<int>(out.cells.size()) < cols) {
        if (r.remaining() == 0) {
            error = "格流截断";
            return false;
        }
        const uint8_t mark = *r.rest();
        if (mark == 0x00) {  // 空白游程
            uint8_t ignored = 0;
            r.u8(ignored);
            uint64_t n = 0;
            if (!readVarint(r, n)) {
                error = "空白游程 varint 截断";
                return false;
            }
            for (uint64_t i = 0; i < n && static_cast<int>(out.cells.size()) < cols; i++) {
                Cell c;
                c.width = 1;
                out.cells.push_back(c);
            }
        } else if (mark == 0x02) {  // 重复上一格
            uint8_t ignored = 0;
            r.u8(ignored);
            uint64_t n = 0;
            if (!readVarint(r, n)) {
                error = "重复游程 varint 截断";
                return false;
            }
            if (!havePrev) {
                error = "重复格前没有上一格";
                return false;
            }
            for (uint64_t i = 0; i < n && static_cast<int>(out.cells.size()) < cols; i++) {
                out.cells.push_back(prev);
            }
        } else if (mark == 0x01) {  // 完整格
            uint8_t ignored = 0;
            r.u8(ignored);
            uint8_t hdr = 0;
            if (!r.u8(hdr)) {
                error = "格头截断";
                return false;
            }
            const size_t symLen = static_cast<size_t>(hdr & 0x7f);
            Cell c;
            c.skip = (hdr & 0x80) != 0;
            if (!r.str(symLen, c.symbol)) {
                error = "符号截断";
                return false;
            }
            if (!readColor(r, c.fg)) {
                error = "前景色截断";
                return false;
            }
            if (!readColor(r, c.bg)) {
                error = "背景色截断";
                return false;
            }
            uint8_t lo = 0, hi = 0;
            if (!r.u8(lo) || !r.u8(hi)) {
                error = "属性截断";
                return false;
            }
            c.attr = static_cast<uint16_t>(lo | (hi << 8));
            c.width = (c.symbol.empty() && c.skip) ? 0 : (c.skip ? 0 : 1);
            out.cells.push_back(c);
            prev = c;
            havePrev = true;
        } else {
            error = "未知格标记";
            return false;
        }
    }
    return true;
}

void appendU16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
}

}  // namespace

bool gunzip(const uint8_t* data, size_t len, std::vector<uint8_t>& out, std::string& error) {
    out.clear();
    if (len == 0) {
        error = "空 gzip 载荷";
        return false;
    }
    z_stream zs;
    std::memset(&zs, 0, sizeof(zs));
    // 16 + MAX_WBITS = 只接受 gzip 头（服务端一律 gzip，不接 zlib/裸 deflate）。
    if (inflateInit2(&zs, 16 + MAX_WBITS) != Z_OK) {
        error = "inflateInit2 失败";
        return false;
    }
    zs.next_in = const_cast<Bytef*>(data);
    zs.avail_in = static_cast<uInt>(len);
    std::vector<uint8_t> buf(64 * 1024);
    int rc = Z_OK;
    while (rc != Z_STREAM_END) {
        zs.next_out = buf.data();
        zs.avail_out = static_cast<uInt>(buf.size());
        rc = inflate(&zs, Z_NO_FLUSH);
        if (rc != Z_OK && rc != Z_STREAM_END) {
            inflateEnd(&zs);
            error = "inflate 失败";
            return false;
        }
        const size_t produced = buf.size() - zs.avail_out;
        out.insert(out.end(), buf.data(), buf.data() + produced);
        if (out.size() > (32u << 20)) {  // 32MiB 上限：防病态载荷把内存打满
            inflateEnd(&zs);
            error = "解压结果超过上限";
            out.clear();
            return false;
        }
    }
    inflateEnd(&zs);
    return true;
}

bool FragmentAssembler::push(uint8_t op, const uint8_t* payload, size_t len, std::vector<uint8_t>& body,
                             std::string& error) {
    body.clear();
    if (len < 1) {
        error = "分片头缺失";
        return false;
    }
    if (m_parts > 0 && op != m_op) {
        // 上一组没集齐就来了别的 op：丢弃上一组（客户端会因超时重取全量，不能混着拼）。
        reset();
        error = "分片组被其它 op 打断";
        return false;
    }
    m_op = op;
    const uint8_t flags = payload[0];
    if (m_parts++ == 0) m_buf.clear();
    if (m_parts > 512) {
        reset();
        error = "分片数超过上限";
        return false;
    }
    m_buf.insert(m_buf.end(), payload + 1, payload + len);
    if ((flags & kFragMoreBit) != 0) return false;  // 还没集齐

    const bool ok = gunzip(m_buf.data(), m_buf.size(), body, error);
    reset();
    return ok;
}

void FragmentAssembler::reset() {
    m_op = 0;
    m_buf.clear();
    m_parts = 0;
}

// decodeRowsAtMost：最多解 count 行，**允许提前结束**（缓冲耗尽即停）。
// 用途 = FETCH-ROWS 应答：出口在「请求范围越过历史末尾」时只回它有的行，而帧头 Count 是
// **请求数**（2026-09-24 实测：请求 [134,+102) 只有 68 行存在）——严格按 count 解码必然失败，
// 而那条失败路径在传输层是静默的（不计数、不请求全量），且 ScrollModel 的单飞不会清 ⇒
// 预取永久卡死、缓存填不上、新会话滑不动。分片组装 + gunzip 已保证完整性，
// 所以"比 count 少"只可能是服务端没有那么多行（真截断会先在解压那步失败）。
bool decodeRowsAtMost(const uint8_t* p, size_t len, int count, int cols, std::vector<Row>& out,
                      size_t& consumed, std::string& error) {
    Reader r(p, len);
    out.clear();
    out.reserve(static_cast<size_t>(count));
    for (int i = 0; i < count; i++) {
        if (r.remaining() == 0) break;  // 短尾：服务端的历史到此为止
        Row row;
        if (!readRow(r, cols, row, error)) return false;
        out.push_back(std::move(row));
    }
    consumed = len - r.remaining();
    return true;
}

bool decodeRows(const uint8_t* p, size_t len, int count, int cols, std::vector<Row>& out,
                size_t& consumed, std::string& error) {
    Reader r(p, len);
    out.clear();
    out.reserve(static_cast<size_t>(count));
    for (int i = 0; i < count; i++) {
        Row row;
        if (!readRow(r, cols, row, error)) return false;
        out.push_back(std::move(row));
    }
    consumed = len - r.remaining();
    return true;
}

bool decodeGrid(const std::vector<uint8_t>& blob, uint16_t& cols, uint16_t& rows, std::vector<Row>& out,
                std::string& error) {
    Reader r(blob.data(), blob.size());
    uint8_t ver = 0;
    // cell 编码版本，不是帧体版本（两者独立，见 kCellCodecVer 的注释——这里曾经混淆过）。
    if (!r.u8(ver) || ver != kCellCodecVer) {
        error = "网格版本不符";
        return false;
    }
    if (!r.u16(cols) || !r.u16(rows)) {
        error = "网格头截断";
        return false;
    }
    size_t consumed = 0;
    if (!decodeRows(r.rest(), r.remaining(), rows, cols, out, consumed, error)) return false;
    return true;
}

bool decodeSnapshot(const std::vector<uint8_t>& body, Snapshot& out, std::string& error) {
    Reader r(body.data(), body.size());
    uint8_t ver = 0;
    if (!r.u8(ver) || ver != kSurfaceVer) {
        error = "快照版本不符";
        return false;
    }
    if (!r.u32(out.geom.revision) || !r.u16(out.geom.cols) || !r.u16(out.geom.rows)) {
        error = "快照几何截断";
        return false;
    }
    if (!r.u16(out.cursor.x) || !r.u16(out.cursor.y) || !r.u8(out.cursor.flags) ||
        !r.u8(out.cursor.shape)) {
        error = "快照光标截断";
        return false;
    }
    if (!r.u32(out.modes) || !r.u8(out.kitty) || !r.u8(out.misc)) {
        error = "快照模式截断";
        return false;
    }
    // 回滚条（任务 3.3）：服务端位序在 misc 之后、标题之前（与 encSnapshotBody 逐字节对齐）。
    if (!r.u64(out.scroll.total) || !r.u64(out.scroll.offset) || !r.u16(out.scroll.len)) {
        error = "快照回滚条截断";
        return false;
    }
    uint16_t titleLen = 0;
    if (!r.u16(titleLen) || !r.str(titleLen, out.title)) {
        error = "快照标题截断";
        return false;
    }
    uint32_t gridLen = 0;
    const uint8_t* gridPtr = nullptr;
    if (!r.u32(gridLen) || !r.bytes(gridLen, gridPtr)) {
        error = "快照网格截断";
        return false;
    }
    std::vector<uint8_t> gridBlob(gridPtr, gridPtr + gridLen);
    uint16_t gcols = 0, grows = 0;
    if (!decodeGrid(gridBlob, gcols, grows, out.grid, error)) return false;

    uint32_t mirrorLen = 0;
    const uint8_t* mirrorPtr = nullptr;
    if (!r.u32(mirrorLen) || !r.bytes(mirrorLen, mirrorPtr)) {
        error = "快照镜像截断";
        return false;
    }
    out.mirror.clear();
    if (mirrorLen > 0) {
        std::vector<uint8_t> mirrorBlob(mirrorPtr, mirrorPtr + mirrorLen);
        uint16_t mcols = 0, mrows = 0;
        if (!decodeGrid(mirrorBlob, mcols, mrows, out.mirror, error)) return false;
    }
    // 光标绘制冲突（快照侧同款校验；x == cols 合法 = 末列待折行）。
    if (out.cursor.x > out.geom.cols || out.cursor.y >= out.geom.rows) {
        error = "快照光标越界";
        return false;
    }
    // 回滚条自洽：视口必须落在 [0,total) 内，且 len 就是视口行数（不一致说明两端口径漂了）。
    if (out.scroll.len != out.geom.rows ||
        out.scroll.offset + uint64_t(out.scroll.len) > out.scroll.total) {
        error = "快照回滚条不自洽";
        return false;
    }
    return true;
}

bool decodeDiff(const std::vector<uint8_t>& body, Diff& out, std::string& error) {
    Reader r(body.data(), body.size());
    uint8_t ver = 0;
    if (!r.u8(ver) || ver != kSurfaceVer) {
        error = "差分版本不符";
        return false;
    }
    if (!r.u32(out.geom.revision) || !r.u16(out.geom.cols) || !r.u16(out.geom.rows) ||
        !r.u16(out.rowCount)) {
        error = "差分头截断";
        return false;
    }
    // 光标块（v2，任务 3.10）：与快照同位序（x,y,flags,shape）。
    if (!r.u16(out.cursor.x) || !r.u16(out.cursor.y) || !r.u8(out.cursor.flags) ||
        !r.u8(out.cursor.shape)) {
        error = "差分光标截断";
        return false;
    }
    // 模式位 + 回滚条（v4，2026-09-24 评审整改）：与快照同位序（modes → total/offset/len）。
    if (!r.u32(out.modes) || !r.u64(out.scroll.total) || !r.u64(out.scroll.offset) ||
        !r.u16(out.scroll.len)) {
        error = "差分模式/回滚条截断";
        return false;
    }
    size_t consumed = 0;
    return decodeRows(r.rest(), r.remaining(), out.rowCount, out.geom.cols, out.rows, consumed, error);
}

bool decodeFetchRowsReply(const std::vector<uint8_t>& body, FetchRowsReply& out, std::string& error) {
    Reader r(body.data(), body.size());
    uint8_t ver = 0;
    if (!r.u8(ver) || ver != kSurfaceVer) {
        error = "FETCH-ROWS 版本不符";
        return false;
    }
    if (!r.u32(out.geom.revision) || !r.u16(out.geom.cols) || !r.u16(out.geom.rows) || !r.u64(out.from) ||
        !r.u16(out.count)) {
        error = "FETCH-ROWS 头截断";
        return false;
    }
    size_t consumed = 0;
    // 短尾容忍：见 decodeRowsAtMost 的注释（出口的 Count 是请求数而非实际行数）。
    return decodeRowsAtMost(r.rest(), r.remaining(), out.count, out.geom.cols, out.rows, consumed, error);
}

void CellGrid::reset(const Snapshot& snap) {
    m_geom = snap.geom;
    m_cursor = snap.cursor;
    m_modes = snap.modes;
    m_scroll = snap.scroll;
    m_rows = snap.grid;
    m_mirror = snap.mirror;
    // 视口行数补齐（服务端只发有内容的行时也不能让渲染层读到越界）。
    if (m_rows.size() < snap.geom.rows) m_rows.resize(snap.geom.rows);
}

bool CellGrid::applyDiff(const Diff& diff) {
    if (diff.geom.cols != m_geom.cols || diff.geom.rows != m_geom.rows) return false;
    if (diff.geom.revision != m_geom.revision) return false;  // revision 断档：拒收并请求全量
    // 光标绘制冲突（规格里那条校验，v2 起才有落点）：光标必须落在本帧几何内，否则整帧拒收。
    // x == cols 是合法的（宽字符/末列待折行的「待决定位置」），所以上界取 <=。
    if (diff.cursor.x > diff.geom.cols || diff.cursor.y >= diff.geom.rows) return false;
    // 回滚裁剪（total 变小）⇒ 绝对行号整体滑动，镜像/拉取行全部失锚 ⇒ 整帧拒收并请求全量。
    // （v4 起差分带回滚条，客户端自己就能判；服务端的 noteScrollbar 只是同一判据的提前量。）
    if (diff.scroll.total < m_scroll.total) return false;
    for (const auto& row : diff.rows) {
        if (row.y >= m_geom.rows) return false;  // 行越界：拒收
        m_rows[row.y] = row;
    }
    m_cursor = diff.cursor;  // 光标随差分走（任务 3.10）——行没变但它动了是常态
    m_modes = diff.modes;    // 模式位随差分走（v4）——触摸路由/备用屏判定靠它
    m_scroll = diff.scroll;  // 回滚条随差分走（v4）——绝对行号跟住/裁剪检测靠它
    return true;
}

std::string CellGrid::toText() const {
    std::string out;
    for (size_t i = 0; i < m_rows.size(); i++) {
        if (i > 0) out.push_back('\n');
        for (const auto& c : m_rows[i].cells) {
            if (c.skip) continue;  // 占位格跳过（补空格会把 CJK 拆开）
            out += c.symbol.empty() ? " " : c.symbol;
        }
        // 行尾空白裁掉（与 formatter trim 口径一致）。
        while (!out.empty() && (out.back() == ' ' || out.back() == '\t')) out.pop_back();
    }
    return out;
}

// ---- SurfaceSession（客户端状态机，任务 3.1）----

bool SurfaceSession::onFrame(uint8_t op, const uint8_t* payload, size_t len, uint64_t nowMs) {
    // FIX-31：本方法内所有 m_stats 自增都在 m_statsMu 下（跨线程读者走 statsSnapshot()）。
    std::lock_guard<std::mutex> slk(m_statsMu);
    m_stats.framesIn++;
    m_stats.bytesIn += len;
    if (len >= 1 && (payload[0] & kFragMoreBit) != 0 && !m_fragActive) {
        m_fragActive = true;
        m_fragStartMs = nowMs;
    }
    std::vector<uint8_t> body;
    std::string err;
    const bool complete = m_asm.push(op, payload, len, body, err);
    if (!complete) {
        if (!err.empty()) {
            // 分片头坏/解压失败：这一组废了，请求全量（不猜、不部分应用）。
            m_lastError = err;
            m_fragActive = false;
            m_stats.patchRejects++;
            m_stats.fetchSnapshotSent++;
            return true;
        }
        return false;  // 还在攒
    }
    m_fragActive = false;

    // 载荷版本先看第一字节（体头就是版本）：不符时**不当普通坏帧处理**（见 versionMismatch 的
    // 注释——重试解不开，只会空转取全量）。标位后照常返回「需全量」，由传输层决定升级为协商失败。
    if (!body.empty() && body[0] != kSurfaceVer) {
        m_versionMismatch.store(true, std::memory_order_relaxed);
        m_lastError = "surface 载荷版本不符（出口 " + std::to_string(static_cast<int>(body[0])) +
                      " vs App " + std::to_string(static_cast<int>(kSurfaceVer)) + "，两端需同升）";
        return true;
    }

    switch (op) {
        case kOpSnapshot: {
            Snapshot snap;
            if (!decodeSnapshot(body, snap, err)) {
                m_lastError = err;
                m_snapshotOk.store(false, std::memory_order_relaxed);  // 这一份解不开：DONE 不能当就绪
                m_stats.patchRejects++;
                m_stats.fetchSnapshotSent++;
                return true;
            }
            {
                // 网格写入对渲染线程可见（见头文件的线程契约）：锁只包住网格/滚动缓存，
                // 解码与分片攒片（耗时大头）都在锁外。
                std::lock_guard<std::mutex> lk(m_gridMu);
                m_stats.lastSnapScrollBefore = m_scroll.scrollRows();
                m_stats.lastSnapTotalBefore = m_scroll.scrollbar().total;
                m_grid.reset(snap);
                // 回滚视图重建（design D3：SNAPSHOT 到达即重建镜像 + 重置基线 ⇒ 历史缓存作废）。
                m_scroll.onSnapshot(snap.geom, snap.grid, snap.mirror, snap.scroll);
                m_stats.lastSnapScrollAfter = m_scroll.scrollRows();
                m_stats.lastSnapTotalAfter = m_scroll.scrollbar().total;
            }
            m_haveSnapshot.store(true, std::memory_order_relaxed);
            m_snapshotOk.store(true, std::memory_order_relaxed);
            m_stats.snapshots++;
            // 跨线程读的那一份（L3）：与上一行同处递增，保持两个计数一致。
            // 标题（任务 3.4）：surface 腿本地 vt 看不到 OSC，标题来自快照与 STATE 帧。
            noteTitle(snap.title);
            return false;
        }
        case kOpSurfaceDiff: {
            Diff diff;
            if (!decodeDiff(body, diff, err)) {
                m_lastError = err;
                m_stats.patchRejects++;
                m_stats.fetchSnapshotSent++;
                return true;
            }
            if (!m_haveSnapshot.load(std::memory_order_relaxed)) {
                // 还没有基线就来了差分：不能应用（否则网格是半截的）。
                m_lastError = "差分早于快照";
                m_stats.patchRejects++;
                m_stats.fetchSnapshotSent++;
                return true;
            }
            {
                std::lock_guard<std::mutex> lk(m_gridMu);
                if (!m_grid.applyDiff(diff)) {
                    // 越界/几何不符/revision 断档/回滚裁剪——**整帧拒收**并请求全量（自愈路径）。
                    m_lastError = (diff.geom.cols != m_grid.geometry().cols ||
                                   diff.geom.rows != m_grid.geometry().rows)
                                      ? "差分几何不符"
                                      : (diff.scroll.total < m_grid.scrollbar().total
                                             ? "回滚裁剪（行号已滑动）"
                                             : "revision 断档");
                    m_stats.patchRejects++;
                    m_stats.fetchSnapshotSent++;
                    return true;
                }
                // 回滚视图跟住本拍回滚条（v4）：滚回历史时按 offset 增量平移本地滚动量
                // ⇒ 绝对视图位置不动（新输出只把「距底距离」推大，不再把人拽回底部）。
                m_scroll.onDiffScroll(diff.scroll);
            }
            m_stats.diffs++;
            return false;
        }
        case kOpFetchRows: {
            FetchRowsReply reply;
            if (!decodeFetchRowsReply(body, reply, err)) {
                m_lastError = err;
                m_stats.fetchReplyBad++;
                return false;  // 不进 patchRejects（不触发取全量），但必须留痕：原来这里全静默
            }
            // 漂移（锚点内容变了 ⇒ 绝对行号已滑动）⇒ 当「需要全量」返回，走既有自愈路径。
            return !applyFetchRows(reply);
        }
        case kOpSnapshotDone:
            // 完成标志本身不带数据；reveal 由调用方在收到它时解除渲染抑制（3.9）。
            return false;
        default:
            // 其它 op（STATE/CLIPBOARD/NOTIFY/…）由传输层分派，不走这里。
            return false;
    }
}

void SurfaceSession::noteTitle(const std::string& title) {
    if (title.empty() || title == m_lastTitle) {
        return;
    }
    m_lastTitle = title;
    if (onOscEvent) {
        onOscEvent(0, title);
    }
}

void SurfaceSession::noteRemoteError() {
    std::lock_guard<std::mutex> slk(m_statsMu);

    // 稳态的出口 opError（原来被传输层的 default 静默吞掉）：计数 + **清预取单飞**——
    // 否则一次 FETCH 失败就把 m_fetchPending 永久钉住，回滚预取死掉、缓存填不上（真机症状：
    // 新会话上下滑不生效，且预取计数停在 1 不动）。
    m_stats.remoteErrors++;
    m_scroll.onFetchFailed();
}

void SurfaceSession::noteAgentState(uint8_t agent, uint8_t state) {
    m_agentKind.store(agent, std::memory_order_relaxed);
    m_agentState.store(state, std::memory_order_relaxed);
}

bool SurfaceSession::pollTimeout(uint64_t nowMs) {
    std::lock_guard<std::mutex> slk(m_statsMu);

    if (!m_fragActive) return false;
    if (nowMs - m_fragStartMs < kFragTimeoutMs) return false;
    m_asm.reset();
    m_fragActive = false;
    m_stats.fragTimeouts++;
    m_stats.fetchSnapshotSent++;
    m_lastError = "分片组超时";
    return true;
}

bool SurfaceSession::applyFetchRows(const FetchRowsReply& reply) {
    std::lock_guard<std::mutex> slk(m_statsMu);

    std::lock_guard<std::mutex> lk(m_gridMu);
    const Geometry g = m_grid.geometry();
    if (reply.geom.cols != g.cols || reply.geom.rows != g.rows) {
        m_stats.fetchReplyStale++;  // 几何不符：丢弃并清单飞（可重试）
        m_scroll.onFetchFailed();
        return true;
    }
    if (reply.geom.revision != g.revision) {
        m_stats.fetchReplyStale++;  // revision 不符（过期应答）：丢弃（可重试）
        m_scroll.onFetchFailed();
        return true;
    }
    bool drift = false;
    m_scroll.onFetchReply(reply.from, reply.rows, drift);
    m_stats.fetchRowsApplied += reply.rows.size();
    // 锚点内容变了（TUI 重写回滚行 / 行号滑动）：onFetchReply 已**就地刷新**该行，
    // 这里不再升级为全量快照（旧行为会让用户被瞬移到镜像顶，真机「跳到中间位置」）。
    // 行号整体滑动由「差分带回滚条 total 变小」+ 出口侧裁剪快照兜住（见 ScrollModel 的注释）。
    (void)drift;
    return true;  // 已处理：不需要全量
}

// ---- 回滚视图（任务 3.3）----

bool SurfaceSession::scrollByPixels(float dyPx, float cellH) {
    std::lock_guard<std::mutex> lk(m_gridMu);
    return m_scroll.scrollByPixels(dyPx, cellH);
}

void SurfaceSession::scrollToBottom() {
    std::lock_guard<std::mutex> lk(m_gridMu);
    m_scroll.scrollToBottom();
}

bool SurfaceSession::scrolled() const {
    std::lock_guard<std::mutex> lk(m_gridMu);
    return m_scroll.scrolled();
}

Cursor SurfaceSession::cursorForRender() const {
    std::lock_guard<std::mutex> lk(m_gridMu);
    return m_grid.cursor();
}

ScrollModel::Window SurfaceSession::viewWindow() const {
    std::lock_guard<std::mutex> lk(m_gridMu);
    return m_scroll.window(m_grid.rows(), static_cast<int>(m_grid.geometry().cols),
                           static_cast<int>(m_grid.geometry().rows));
}

bool SurfaceSession::takeFetchRequest(uint64_t& from, uint16_t& count) {
    std::lock_guard<std::mutex> lk(m_gridMu);
    return m_scroll.takeFetchRequest(from, count);
}

bool SurfaceSession::takeAnchorProbe(uint64_t nowMs, uint64_t& row) {
    std::lock_guard<std::mutex> lk(m_gridMu);
    return m_scroll.takeAnchorProbe(nowMs, row);
}

void SurfaceSession::noteFetchFailed() {
    std::lock_guard<std::mutex> lk(m_gridMu);
    m_scroll.onFetchFailed();
}

ScrollModel::Stats SurfaceSession::scrollStats() const {
    std::lock_guard<std::mutex> lk(m_gridMu);
    return m_scroll.stats();
}

Scrollbar SurfaceSession::scrollbar() const {
    std::lock_guard<std::mutex> lk(m_gridMu);
    return m_scroll.scrollbar();
}

float SurfaceSession::scrollRows() const {
    std::lock_guard<std::mutex> lk(m_gridMu);
    return m_scroll.scrollRows();
}

float SurfaceSession::scrollMaxRows() const {
    std::lock_guard<std::mutex> lk(m_gridMu);
    return m_scroll.scrollMaxRows();
}

uint64_t SurfaceSession::viewTopAbs() const {
    std::lock_guard<std::mutex> lk(m_gridMu);
    const uint64_t off = m_scroll.viewportTop();
    const float s = m_scroll.scrollRows();
    if (s <= 0.0f) {
        return off;
    }
    const uint64_t back = static_cast<uint64_t>(s);
    return off > back ? off - back : 0;
}

void SurfaceSession::selectionPress(int row, int col) {
    std::lock_guard<std::mutex> lk(m_gridMu);
    // 坐标系必须与 selectionText()/selectionCovers() 一致：**窗口行**。
    // （滚回历史时窗口 ≠ 实时视口；旧实现拿实时视口做按词扩选，长按选词/复制会选到
    // 完全不同的行——2026-09-24 评审整改，P1-8。真机/宿主实测：滚回历史时选中 "h" 而不是
    // 用户看到的那一行词。）
    const int cols = static_cast<int>(m_grid.geometry().cols);
    const ScrollModel::Window win =
        m_scroll.window(m_grid.rows(), cols, static_cast<int>(m_grid.geometry().rows));
    const std::vector<Row>& src = win.valid ? win.rows : m_grid.rows();
    m_selection.press(row, col, src, cols);
}

void SurfaceSession::selectionDrag(int row, int col) {
    std::lock_guard<std::mutex> lk(m_gridMu);
    m_selection.drag(row, col);
}

void SurfaceSession::selectionRelease() {
    std::lock_guard<std::mutex> lk(m_gridMu);
    m_selection.release();
}

void SurfaceSession::selectionReset() {
    std::lock_guard<std::mutex> lk(m_gridMu);
    m_selection.reset();
}

bool SurfaceSession::selectionActive() const {
    std::lock_guard<std::mutex> lk(m_gridMu);
    return m_selection.active();
}

bool SurfaceSession::selectionText(std::string& out) const {
    std::lock_guard<std::mutex> lk(m_gridMu);
    if (!m_selection.active()) {
        return false;
    }
    // 从**当前窗口**提取：滚回历史时选到的就是看到的那几行（与 legacy 语义一致）。
    const ScrollModel::Window win = m_scroll.window(m_grid.rows(),
                                                    static_cast<int>(m_grid.geometry().cols),
                                                    static_cast<int>(m_grid.geometry().rows));
    out = m_selection.text(win.rows, static_cast<int>(m_grid.geometry().cols));
    return !out.empty();
}

bool SurfaceSession::selectionCovers(int row, int col) const {
    std::lock_guard<std::mutex> lk(m_gridMu);
    return m_selection.covers(row, col);
}

bool SurfaceSession::mouseReporting() const {
    std::lock_guard<std::mutex> lk(m_gridMu);
    const uint32_t m = m_grid.modes();
    return (m & (kModeMouse1000 | kModeMouse1002 | kModeMouse1003)) != 0;
}

size_t SurfaceSession::cachedRowsForStats() const {
    std::lock_guard<std::mutex> lk(m_gridMu);
    return m_scroll.cachedRows();
}

// ---- 跨线程读面（渲染路径）----

bool SurfaceSession::copyGridForRender(CellGrid& out) const {
    std::lock_guard<std::mutex> lk(m_gridMu);
    if (!m_haveSnapshot.load(std::memory_order_relaxed)) {
        return false;
    }
    out = m_grid;
    return true;
}

bool SurfaceSession::altScreenNow() const {
    std::lock_guard<std::mutex> lk(m_gridMu);
    return m_grid.altScreen();
}

// ---- 上行编码 ----

std::vector<uint8_t> encodeKeyEvent(uint16_t key, uint16_t mods, uint8_t action, const std::string& utf8) {
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>(InputKind::Key));
    appendU16(out, key);
    appendU16(out, mods);
    out.push_back(action);
    out.push_back(static_cast<uint8_t>(utf8.size() & 0xff));
    out.insert(out.end(), utf8.begin(), utf8.end());
    return out;
}

std::vector<uint8_t> encodeTextEvent(const std::string& text, bool paste, bool more, bool cont) {
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>(InputKind::Text));
    uint8_t flags = 0;
    if (paste) flags |= kTextPasteBit;
    if (more) flags |= kTextPasteMoreBit;
    if (cont) flags |= kTextPasteContBit;
    out.push_back(flags);
    appendU16(out, static_cast<uint16_t>(text.size()));
    out.insert(out.end(), text.begin(), text.end());
    return out;
}

std::vector<uint8_t> encodeMouseEvent(uint8_t action, uint8_t button, uint16_t mods, uint16_t x, uint16_t y) {
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>(InputKind::Mouse));
    out.push_back(action);
    out.push_back(button);
    appendU16(out, mods);
    appendU16(out, x);
    appendU16(out, y);
    return out;
}

std::vector<uint8_t> encodeFocusEvent(bool gained) {
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>(InputKind::Focus));
    out.push_back(gained ? 1 : 0);
    return out;
}

std::vector<uint8_t> encodeTheme(const uint8_t fg[3], const uint8_t bg[3], bool dark) {
    std::vector<uint8_t> out;
    out.push_back(dark ? 1 : 0);
    out.insert(out.end(), fg, fg + 3);
    out.insert(out.end(), bg, bg + 3);
    return out;
}

std::vector<uint8_t> encodeClipboardAnswer(const std::string& text) {
    // FIX-27：长度字段是 u16，文本超 65532 会让 appendU16 回绕（65536 → 0），而外层帧
    // 编码按 kMaxPayload(65535) 截断 ⇒ 服务端读到「声明长度与实际字节不符」的坏帧
    // （64KiB–256KiB 区间静默写坏）。这里先截到帧上限减去 3 字节头，长度字段恒精确；
    // 与 Go 侧 clipMaxBytes = termMaxPayload-3 同口径（两端必须同时改）。
    static constexpr size_t kMaxClipText = 65535u - 3u;
    const size_t n = text.size() > kMaxClipText ? kMaxClipText : text.size();
    std::vector<uint8_t> out;
    out.push_back(2);  // kClipKindReadAnswer
    appendU16(out, static_cast<uint16_t>(n));
    out.insert(out.end(), text.begin(), text.begin() + static_cast<std::ptrdiff_t>(n));
    return out;
}

std::vector<uint8_t> encodeCapabilityBlock(uint8_t caps) {
    return std::vector<uint8_t>{1, caps};
}

std::vector<uint8_t> encodeHelloTail(uint8_t caps, const std::string& clientID) {
    // 布局与服务端 pkg/term encHelloTail 逐字节一致：[capLen][caps][ver?][idLen][id]。
    std::vector<uint8_t> out = encodeCapabilityBlock(caps);
    if ((caps & kCapsProtoVer) != 0) {
        out.push_back(kProtoVer);
    }
    if (!clientID.empty()) {
        out.push_back(static_cast<uint8_t>(clientID.size()));
        out.insert(out.end(), clientID.begin(), clientID.end());
    }
    return out;
}

bool decodeNotify(const uint8_t* p, size_t len, std::string& out, std::string& error) {
    if (len < 2) {
        error = "NOTIFY 载荷过短";
        return false;
    }
    const uint16_t n = static_cast<uint16_t>(p[0] | (p[1] << 8));
    if (len < 2u + n) {
        error = "NOTIFY 载荷截断";
        return false;
    }
    out.assign(reinterpret_cast<const char*>(p + 2), n);
    return true;
}

bool decodeClipboard(const uint8_t* p, size_t len, uint8_t& kind, std::string& out, std::string& error) {
    if (len < 3) {
        error = "CLIPBOARD 载荷过短";
        return false;
    }
    kind = p[0];
    const uint16_t n = static_cast<uint16_t>(p[1] | (p[2] << 8));
    if (len < 3u + n) {
        error = "CLIPBOARD 载荷截断";
        return false;
    }
    out.assign(reinterpret_cast<const char*>(p + 3), n);
    return true;
}

}  // namespace tierterm
