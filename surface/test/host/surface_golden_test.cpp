// surface/test/host/surface_golden_test.cpp — 跨仓 golden fixture 的**客户端侧断言**（任务 2.8）。
//
// 读出口侧生成的共享样例（surface/test/golden/manifest.tsv + <name>.bin），用**客户端的解码实现**
// （surface/surface_codec.cpp）解一遍，断言几何与文本摘要与 manifest 记录一致。
//
// 为什么值得这么绕：surface 的字节布局在出口 Go 与客户端 C++ 各有一份手写实现，**新增 op 必然
// 要改两处**——这类漂移在两端各自的自测里都看不出来（各测各的自然都绿），只有拿同一份字节互相对
// 才能发现。跑法见 tools/surface-host-test.sh（宿主编译，不需要设备/DevEco）。
//
// 摘要口径与出口侧逐字节一致：FNV-1a 64 of「行以 \n 连接、占位格跳过、空符号补空格、行尾裁空白」。
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "surface/surface_codec.h"

namespace {

uint64_t fnv1a64(const std::string& s) {
    uint64_t h = 14695981039346656037ull; // FNV-1a 64 的 offset basis（少写一位数字就会全错——实测踩过）
    for (unsigned char c : s) {
        h ^= c;
        h *= 1099511628211ull;
    }
    return h;
}

std::string digestHex(uint64_t v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(v));
    return buf;
}

uint32_t readU32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
}

// styleDigest：样式向量的规范文本摘要（FIX-30），与服务端 goldenStyleText 逐字符一致——
// 逐行逐格固定 26 个十六进制字符（fg 5B · bg 5B · attr 2B · flags 1B），行尾 \n；
// 行不足 cols 的缺格按空白格（width=1）补，与服务端编码的 blankRun 语义对齐。
// flags = skip(bit0) | width<<1。
std::string styleDigest(const tierterm::CellGrid& grid) {
    const uint16_t cols = grid.geometry().cols;
    std::string text;
    char buf[16]; // 单个颜色块 = 10 字符 + NUL；8 字节会静默截断（首跑红过）
    for (const auto& r : grid.rows()) {
        for (uint16_t x = 0; x < cols; x++) {
            tierterm::Cell blank;
            blank.width = 1;
            const tierterm::Cell& c = x < r.cells.size() ? r.cells[x] : blank;
            const unsigned flags = (c.skip ? 1u : 0u) | (static_cast<unsigned>(c.width) << 1);
            std::snprintf(buf, sizeof(buf), "%02x%02x%02x%02x%02x",
                          static_cast<unsigned>(c.fg.kind), c.fg.index, c.fg.r, c.fg.g, c.fg.b);
            text += buf;
            std::snprintf(buf, sizeof(buf), "%02x%02x%02x%02x%02x",
                          static_cast<unsigned>(c.bg.kind), c.bg.index, c.bg.r, c.bg.g, c.bg.b);
            text += buf;
            std::snprintf(buf, sizeof(buf), "%04x", c.attr);
            text += buf;
            std::snprintf(buf, sizeof(buf), "%02x", flags);
            text += buf;
        }
        text += '\n';
    }
    return digestHex(fnv1a64(text));
}

struct Sample {
    std::string name;
    uint8_t op = 0;
    int cols = 0, rows = 0;
    uint32_t rev = 0;
    std::string digest;
    int frameCount = 0;
    // 样例光标（任务 3.10 新增的 manifest 列）：喂完全部帧后客户端网格的光标必须等于它。
    // 这是「差分带的光标」在跨仓层面的判据——文本摘要对了、光标错了也要红。
    int cx = -1, cy = -1, cflags = -1, cshape = -1;
    // 样例回滚条（任务 3.3 新增的 manifest 列）：total/offset/len 必须与出口侧一致。
    long long total = -1, offset = -1;
    int slen = -1;
    // 样式向量摘要 + 模式位（FIX-30 新增的末两列）：每格 fg/bg/attr/宽度与模式位也跨仓钉住。
    std::string style;
    long long modes = -1;
};

std::vector<Sample> readManifest(const std::string& path, bool& ok) {
    std::vector<Sample> out;
    std::ifstream in(path);
    if (!in) {
        ok = false;
        return out;
    }
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        std::istringstream ss(line);
        std::string name, opHex, cols, rows, rev, digest, title, frames;
        std::string cx, cy, cflags, cshape, total, offset, slen, style, modes;
        std::getline(ss, name, '\t');
        std::getline(ss, opHex, '\t');
        std::getline(ss, cols, '\t');
        std::getline(ss, rows, '\t');
        std::getline(ss, rev, '\t');
        std::getline(ss, digest, '\t');
        std::getline(ss, title, '\t');
        std::getline(ss, frames, '\t');
        std::getline(ss, cx, '\t');
        std::getline(ss, cy, '\t');
        std::getline(ss, cflags, '\t');
        std::getline(ss, cshape, '\t');
        std::getline(ss, total, '\t');
        std::getline(ss, offset, '\t');
        std::getline(ss, slen, '\t');
        std::getline(ss, style, '\t');
        std::getline(ss, modes, '\t');
        Sample s;
        s.name = name;
        s.op = static_cast<uint8_t>(std::strtoul(opHex.c_str(), nullptr, 16));
        s.cols = std::atoi(cols.c_str());
        s.rows = std::atoi(rows.c_str());
        s.rev = static_cast<uint32_t>(std::strtoul(rev.c_str(), nullptr, 10));
        s.digest = digest;
        s.frameCount = std::atoi(frames.c_str());
        if (!cx.empty()) s.cx = std::atoi(cx.c_str());
        if (!cy.empty()) s.cy = std::atoi(cy.c_str());
        if (!cflags.empty()) s.cflags = std::atoi(cflags.c_str());
        if (!cshape.empty()) s.cshape = std::atoi(cshape.c_str());
        if (!total.empty()) s.total = std::atoll(total.c_str());
        if (!offset.empty()) s.offset = std::atoll(offset.c_str());
        if (!slen.empty()) s.slen = std::atoi(slen.c_str());
        s.style = style;
        if (!modes.empty()) s.modes = std::atoll(modes.c_str());
        out.push_back(std::move(s));
    }
    ok = true;
    return out;
}

struct GoldenFrame {
    uint8_t op = 0;
    std::vector<std::vector<uint8_t>> chunks;
};

// readFrames 读帧序列：[u32 帧数]{[u8 op][u32 片数]{[u32 长度][字节]}…}…
//
// 为什么是**多帧**：差分/回滚应答这类帧作用于前序状态（没有基线就没法独立断言），
// 所以样例是「快照 + 差分…」的序列，客户端按序喂给状态机、比对**最终**网格。
bool readFrames(const std::string& path, std::vector<GoldenFrame>& frames) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    std::vector<uint8_t> blob((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (blob.size() < 4) return false;
    const uint32_t frameCount = readU32(blob.data());
    size_t off = 4;
    for (uint32_t f = 0; f < frameCount; f++) {
        if (off + 5 > blob.size()) return false;
        GoldenFrame fr;
        fr.op = blob[off];
        off += 1;
        const uint32_t chunkCount = readU32(blob.data() + off);
        off += 4;
        for (uint32_t c = 0; c < chunkCount; c++) {
            if (off + 4 > blob.size()) return false;
            const uint32_t len = readU32(blob.data() + off);
            off += 4;
            if (off + len > blob.size()) return false;
            fr.chunks.emplace_back(blob.begin() + off, blob.begin() + off + len);
            off += len;
        }
        frames.push_back(std::move(fr));
    }
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    const std::string dir = (argc > 1) ? argv[1] : "surface/test/golden";
    bool ok = false;
    auto samples = readManifest(dir + "/manifest.tsv", ok);
    if (!ok) {
        std::cerr << "读不到 " << dir << "/manifest.tsv（先在出口侧跑 "
                  << "go test ./pkg/term/ -run TestSurfaceGolden -update 生成）\n";
        return 2;
    }
    if (samples.empty()) {
        std::cerr << "manifest 是空的\n";
        return 2;
    }
    int failures = 0;
    for (const auto& s : samples) {
        std::vector<GoldenFrame> frames;
        if (!readFrames(dir + "/" + s.name + ".bin", frames)) {
            std::cerr << "[FAIL] " << s.name << "：读不到样例文件\n";
            failures++;
            continue;
        }
        if (static_cast<int>(frames.size()) != s.frameCount) {
            std::cerr << "[FAIL] " << s.name << "：帧数不符（文件 " << frames.size() << "，manifest "
                      << s.frameCount << "）\n";
            failures++;
            continue;
        }
        // 用**客户端状态机**按序吃帧（攒分片 → 解压 → 校验 → 应用）。
        tierterm::SurfaceSession sess;
        uint64_t now = 1000;
        bool needFetch = false;
        for (const auto& fr : frames) {
            for (const auto& ch : fr.chunks) {
                needFetch = sess.onFrame(fr.op, ch.data(), ch.size(), now);
                now += 1;
            }
        }
        // FIX-31：跨线程安全读入口（锁内拷一份）。宿主测试是单线程，用它与用
        // stats() 等价——这里刻意用新入口，保证它被真实编译/执行到。
        const auto st = sess.statsSnapshot();
        if (st.framesIn == 0) {
            failures++;
            std::cerr << "[FAIL] " << s.name << "：statsSnapshot 未反映收到的帧（framesIn=0）\n";
            continue;
        }
        if (needFetch || st.patchRejects > 0 || st.fragTimeouts > 0) {
            failures++;
            std::cerr << "[FAIL] " << s.name << "：状态机拒收/请求全量了（rejects=" << st.patchRejects
                      << " timeouts=" << st.fragTimeouts << " lastError=" << sess.lastError() << "）\n";
            continue;
        }
        if (!sess.hasSnapshot()) {
            failures++;
            std::cerr << "[FAIL] " << s.name << "：没有建立基线快照\n";
            continue;
        }
        // 跨线程读面（任务 3.2 接线上渲染层后新增）：渲染帧拿的是**锁内的整份副本**，
        // 副本必须与状态机内的网格逐字一致（否则渲染层画的是另一份画面）。
        {
            tierterm::CellGrid copy;
            if (!sess.copyGridForRender(copy) || copy.toText() != sess.grid().toText() ||
                copy.modes() != sess.grid().modes() || copy.altScreen() != sess.altScreenNow()) {
                failures++;
                std::cerr << "[FAIL] " << s.name << "：渲染副本与状态机网格不一致\n";
                continue;
            }
        }
        const std::string text = sess.grid().toText();
        const std::string digest = digestHex(fnv1a64(text));
        const bool geomOk = sess.grid().geometry().cols == s.cols && sess.grid().geometry().rows == s.rows;
        const bool revOk = sess.grid().geometry().revision == s.rev;
        const bool digestOk = digest == s.digest;
        // 光标（任务 3.10）：manifest 里的期望值来自出口侧同一拍；差分样本必须落在**追加之后**
        // 的位置（与快照样本的光标不同），否则说明「光标随差分来」这条链路没通。
        const tierterm::Cursor cur = sess.grid().cursor();
        const bool cursorOk = s.cx < 0 ||
                              (static_cast<int>(cur.x) == s.cx && static_cast<int>(cur.y) == s.cy &&
                               static_cast<int>(cur.flags) == s.cflags && static_cast<int>(cur.shape) == s.cshape);
        // 回滚条（任务 3.3）：客户端解出的 total/offset/len 必须与出口侧同一份样例一致。
        const tierterm::Scrollbar sb = sess.scrollbar();
        const bool scrollOk = s.total < 0 ||
                              (static_cast<long long>(sb.total) == s.total &&
                               static_cast<long long>(sb.offset) == s.offset &&
                               static_cast<int>(sb.len) == s.slen);
        // 样式向量 + 模式位（FIX-30）：颜色/属性/宽度与模式位布局漂移的自证面——此前只有文本
        // 摘要，两端把 attr 位序/颜色 kind 值改错（只有一端改）也照样双绿。
        const std::string style = styleDigest(sess.grid());
        const bool styleOk = s.style.empty() || style == s.style;
        const bool modesOk = s.modes < 0 || static_cast<long long>(sess.grid().modes()) == s.modes;
        if (!geomOk || !revOk || !digestOk || !cursorOk || !scrollOk || !styleOk || !modesOk) {
            failures++;
            std::cerr << "[FAIL] " << s.name << "：" << (geomOk ? "" : "几何不符 ")
                      << (revOk ? "" : "revision 不符 ") << (digestOk ? "" : "摘要不符 ")
                      << (cursorOk ? "" : "光标不符 ") << (scrollOk ? "" : "回滚条不符 ")
                      << (styleOk ? "" : "样式向量不符 ") << (modesOk ? "" : "模式位不符 ") << "\n"
                      << "       几何 " << sess.grid().geometry().cols << "x" << sess.grid().geometry().rows
                      << "（期望 " << s.cols << "x" << s.rows << "）rev=" << sess.grid().geometry().revision
                      << "（期望 " << s.rev << "）\n"
                      << "       摘要 " << digest << "（期望 " << s.digest << "）\n"
                      << "       光标 (" << cur.x << "," << cur.y << "," << static_cast<int>(cur.flags)
                      << "," << static_cast<int>(cur.shape) << ")（期望 " << s.cx << "," << s.cy << ","
                      << s.cflags << "," << s.cshape << "）\n"
                      << "       回滚条 (" << sb.total << "," << sb.offset << "," << static_cast<int>(sb.len)
                      << ")（期望 " << s.total << "," << s.offset << "," << s.slen << "）\n"
                      << "       样式向量 " << style << "（期望 " << s.style << "）模式位 "
                      << sess.grid().modes() << "（期望 " << s.modes << "）\n"
                      << "       文本前 120 字节：" << text.substr(0, 120) << "\n";
            {
                std::ofstream dump("/tmp/surface-" + s.name + ".cpp.txt", std::ios::binary);
                dump << text;
            }
            continue;
        }
        std::cout << "[ok] " << s.name << "：几何 " << sess.grid().geometry().cols << "x"
                  << sess.grid().geometry().rows << " rev=" << sess.grid().geometry().revision << " 摘要 "
                  << digest << "（帧 " << frames.size() << "：快照 " << st.snapshots << " 差分 " << st.diffs
                  << "，网格 " << sess.grid().rows().size() << " 行，镜像 " << sess.grid().mirror().size()
                  << " 行，光标 " << cur.x << "," << cur.y << "，回滚条 " << sb.total << "/" << sb.offset
                  << "/" << static_cast<int>(sb.len) << "）\n";
    }
    // ---- ⑤ FETCH-ROWS 短尾容忍（2026-09-24 修「新会话上下滑不生效」的第二半）----
    // 出口在「请求范围越过历史末尾」时只回它有的行，而帧头 Count 是**请求数**（实测：请求
    // [134,+102) 只有 68 行存在）。严格按 count 解码会失败，而那条失败路径在传输层静默、
    // 且不清 ScrollModel 的单飞 ⇒ 预取永久卡死、缓存填不上、滑不动。
    // 这里用「零行短尾」把语义钉死：帧头合法、一行都没有 ⇒ 必须解出 0 行而不是报错。
    {
        std::vector<uint8_t> body;
        body.push_back(tierterm::kSurfaceVer);              // 体头版本
        const uint32_t rev = 7;
        body.push_back(static_cast<uint8_t>(rev & 0xff));   // revision（LE u32）
        body.push_back(static_cast<uint8_t>((rev >> 8) & 0xff));
        body.push_back(static_cast<uint8_t>((rev >> 16) & 0xff));
        body.push_back(static_cast<uint8_t>((rev >> 24) & 0xff));
        body.push_back(80); body.push_back(0);              // cols（LE u16）
        body.push_back(24); body.push_back(0);              // rows
        for (int i = 0; i < 8; i++) body.push_back(0);      // from（LE u64）
        body.push_back(5);  body.push_back(0);              // count = 5（请求数）
        tierterm::FetchRowsReply rep;
        std::string err;
        const bool ok = tierterm::decodeFetchRowsReply(body, rep, err);
        if (!ok || !rep.rows.empty() || rep.count != 5) {
            failures++;
            std::cerr << "[FAIL] 短尾 FETCH-ROWS 应答应解出 0 行（ok=" << ok << " rows=" << rep.rows.size()
                      << " err=" << err << "）\n";
        } else {
            std::cout << "[ok] 短尾 FETCH-ROWS 应答：帧头 count=5、实际 0 行 ⇒ 容忍（不再静默卡死）\n";
        }
    }

    // ---- 负路径：拒收与自愈（任务 3.1 的「绝不带病渲染」）----
    //
    // 用真实样例构造两类病态输入，断言状态机**整帧拒收 + 请求全量**而不是部分应用：
    //   ① 差分早于快照（客户端还没有基线）
    //   ② 差分的 revision 与基线不符（模拟丢帧断档：服务端 revision 已推进）
    {
        std::vector<GoldenFrame> baseFrames, diffFrames;
        bool okLoad = readFrames(dir + "/session-cjk.bin", baseFrames) &&
                      readFrames(dir + "/session-cjk-diff.bin", diffFrames);
        if (okLoad && baseFrames.size() == 1 && diffFrames.size() == 2) {
            // ① 差分先到。
            tierterm::SurfaceSession early;
            const auto& d = diffFrames[1];
            bool fetch = false;
            for (const auto& ch : d.chunks) fetch = early.onFrame(d.op, ch.data(), ch.size(), 1000);
            if (!fetch || early.statsSnapshot().patchRejects == 0 || early.hasSnapshot()) {
                failures++;
                std::cerr << "[FAIL] 负路径①：差分早于快照时应拒收并请求全量\n";
            } else {
                std::cout << "[ok] 负路径①：差分早于快照 ⇒ 拒收 + 请求全量（" << early.lastError() << "）\n";
            }

            // ② revision 断档：把差分体里的 revision 改掉，断言**应用被拒**（不是解码失败——
            //    载荷仍然合法，只是与基线不是同一代；这正是「revision 对账」要拦的情况）。
            tierterm::SurfaceSession gap;
            for (const auto& ch : baseFrames[0].chunks) {
                gap.onFrame(baseFrames[0].op, ch.data(), ch.size(), 2000);
            }
            std::vector<uint8_t> body;
            std::string err;
            {
                tierterm::FragmentAssembler asm_;
                for (const auto& ch : diffFrames[1].chunks) {
                    if (asm_.push(diffFrames[1].op, ch.data(), ch.size(), body, err)) break;
                }
            }
            // 体头：ver(1) revision(4) cols(2) rows(2) rowCount(2) …
            if (body.size() < 5) {
                failures++;
                std::cerr << "[FAIL] 负路径②：样例载荷太短，无法构造断档\n";
            } else {
                body[1] = 99;  // revision 低字节 ⇒ 与基线的 1 不符
                tierterm::Diff dd;
                std::string derr;
                if (!tierterm::decodeDiff(body, dd, derr)) {
                    failures++;
                    std::cerr << "[FAIL] 负路径②：载荷本身该仍能解出（只是代次不符），却报 " << derr << "\n";
                } else if (gap.mutableGrid().applyDiff(dd)) {
                    failures++;
                    std::cerr << "[FAIL] 负路径②：revision 断档的差分竟被应用了（应当拒收）\n";
                } else {
                    std::cout << "[ok] 负路径②：revision 断档的差分被拒（applyDiff=false）\n";
                }
            }
        }
    }

    // ---- 负路径③：分片组超时（服务端半路断/链路丢包）⇒ 丢弃 + 请求全量 ----
    {
        std::vector<GoldenFrame> frames;
        if (readFrames(dir + "/session-cjk.bin", frames) && !frames.empty() && frames[0].chunks.size() == 1) {
            // 造一个「还有后续片」的分片头（more 位），永远不给后续 ⇒ 必须在超时后请求全量。
            std::vector<uint8_t> partial;
            partial.push_back(tierterm::kFragMoreBit);
            partial.insert(partial.end(), frames[0].chunks[0].begin() + 1, frames[0].chunks[0].end());
            tierterm::SurfaceSession s2;
            const bool early = s2.onFrame(frames[0].op, partial.data(), partial.size(), 1000);
            const bool beforeTimeout = s2.pollTimeout(1000 + tierterm::SurfaceSession::kFragTimeoutMs - 1);
            const bool afterTimeout = s2.pollTimeout(1000 + tierterm::SurfaceSession::kFragTimeoutMs + 1);
            if (early || beforeTimeout || !afterTimeout || s2.statsSnapshot().fragTimeouts != 1) {
                failures++;
                std::cerr << "[FAIL] 负路径③：不完整分片组该在超时后丢弃并请求全量\n";
            } else {
                std::cout << "[ok] 负路径③：不完整分片组超时 ⇒ 丢弃 + 请求全量\n";
            }
        }
    }

    // ---- 负路径④：载荷版本不符（出口与 App 没同升）⇒ 解码层明确拒绝 ----
    //
    // 这里只钉**解码器**那一半（体头版本字节）：整条腿怎么处置（升级成协商失败 + 回落 legacy，
    // 见 stream_transport 的 connectOnce/handleSurfaceFrame）依赖 OHOS socket，宿主测不了——
    // 那条在真机上用「出口故意发 ver 1」验（见 tasks 3.10 的验证记录）。
    {
        std::vector<uint8_t> wrongVer = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};  // 版本字节 = 1
        tierterm::Snapshot snap;
        tierterm::Diff diff;
        std::string errS, errD;
        const bool snapRejected = !tierterm::decodeSnapshot(wrongVer, snap, errS);
        const bool diffRejected = !tierterm::decodeDiff(wrongVer, diff, errD);
        if (!snapRejected || !diffRejected) {
            failures++;
            std::cerr << "[FAIL] 负路径④：版本不符的载荷应被解码器拒绝\n";
        } else {
            std::cout << "[ok] 负路径④：版本不符 ⇒ 解码拒绝（快照：" << errS << " / 差分：" << errD << "）\n";
        }
    }

    if (failures > 0) {
        std::cerr << failures << " 个样例不一致——**两端实现漂移了**（这正是这个测试存在的理由）\n";
        return 1;
    }
    std::cout << "跨仓 golden fixture：全部一致（" << samples.size() << " 例，" << failures << " 失败）\n";
    return 0;
}
