//go:build !windows

// term_surface_leg.go — surface 腿的投递（任务 2.3/2.4/2.5）。
//
// 一条会话只有**一条腿**（单腿顶替语义：新 attach 顶掉旧腿，旧腿收 ENDED(replaced)），
// 所以这里的状态就挂在 termClient 上。
//
// # 锁纪律（design D2）
//
// **锁内只取快照、锁外压缩与发送**：取脏行/网格/光标/模式要持会话锁（与 PTY pump 串行），
// 但 gzip、分片、socket 写全在锁外——那才是耗时大头，占着会话锁会把子进程一起拖住。
// （cell 行编码本身在锁内做：实测 100×32 全网格 ~100µs，与取快照同一把锁更简单也更安全。）
//
// # 背压（2.5）
//
// 合并窗（16–33ms）把窗内的多次脏标记并成一帧；单帧体积超过 perLegPendingCap（4MiB）或
// 上一次写超时/耗时过长（链路慢）⇒ **丢弃待发差分、标记该腿需要全量快照**——
// 状态宁可全量重建，不可让客户端停在半新半旧。socket 写超时 ⇒ 断该腿（会话存续，
// 客户端按断线重连路径恢复）。
package term

import (
	"sync"
	"time"
)

const (
	// surfaceMergeWindowMin/Max 是差分合并窗（design D2 的 16–33ms）。
	// 窗内再来脏标记就往后延到 Max，把高频小输出并成一帧。
	surfaceMergeWindowMin = 16 * time.Millisecond
	surfaceMergeWindowMax = 33 * time.Millisecond

	// perLegPendingCap 是单腿单帧的体积上限（design D2 的 4MiB）。
	// 超过它就不发差分/快照，而是标记「需要全量」并等下一拍（那时体积会小下来）。
	perLegPendingCap = 4 << 20

	// surfaceFetchRowsMax 是单次 FETCH-ROWS 的行数上限（防对端一次要几万行把内存打满）。
	surfaceFetchRowsMax = 512
)

// surfaceStats 是服务端观测计数器（任务 2.9；对称客户端 3.8，7.4 两端对照的数据源）。
type surfaceStats struct {
	snapshots    uint64 // 下发的全量快照数
	diffs        uint64 // 下发的差分帧数
	degrades     uint64 // 差分降级为全量的次数
	backpressure uint64 // 背压事件（弃差分标记需快照）
	fragments    uint64 // 分片总数
	bytesOut     uint64 // 下发字节（分片后的净字节）
	fetchHits    uint64 // FETCH-ROWS 命中（取到行）
	fetchMiss    uint64 // FETCH-ROWS 落空（越界/备用屏）
	writeTimeout uint64 // 写超时断腿次数
	sentDiffs    uint64 // 差分成功下发（用于 7.4 的差分 vs 原始 ANSI 对照）
	trims        uint64 // 回滚裁剪触发的强制全量重建（任务 3.3；观测用）
}

// surfaceLeg 一条 surface 腿的投递状态。
type surfaceLeg struct {
	mu sync.Mutex

	// revision 是差分对账的世代号：每发一次全量 +1；差分沿用当前值。
	// 客户端发现断档就 FETCH-SNAPSHOT（服务端不重传旧差分）。
	revision uint32
	// needSnapshot 标记该腿需要全量重建（首次 attach / 背压 / 降级 / resize / 回滚裁剪）。
	needSnapshot bool
	// lastWriteCost 上次写耗时（> 合并窗 ⇒ 链路有压力，下一拍走全量）。
	lastWriteCost time.Duration
	// lastSnapTotal / hasSnapTotal：上次全量快照时的回滚条 total（任务 3.3）。
	// total **变小**只可能是回滚裁剪（写入时只增或持平）⇒ 绝对行号滑动 ⇒ 该腿的镜像/拉取行
	// 全部失锚，必须重发全量让客户端重建（判据见 noteScrollbar）。
	lastSnapTotal uint64
	hasSnapTotal  bool

	stats surfaceStats
}

func newSurfaceLeg() *surfaceLeg { return &surfaceLeg{needSnapshot: true} }

// markNeedSnapshot 标记该腿需要全量（下次 flush 发快照）。
func (l *surfaceLeg) markNeedSnapshot(reason string) {
	l.mu.Lock()
	l.needSnapshot = true
	if reason == "backpressure" {
		l.stats.backpressure++
	}
	l.mu.Unlock()
}

// takeSnapshotFlag 读并清除 needSnapshot。
func (l *surfaceLeg) takeSnapshotFlag() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	v := l.needSnapshot
	l.needSnapshot = false
	return v
}

// nextRevision 发全量时推进世代号。
func (l *surfaceLeg) nextRevision() uint32 {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.revision++
	return l.revision
}

// currentRevision 当前世代号（差分与 FETCH 应答都带它）。
func (l *surfaceLeg) currentRevision() uint32 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.revision
}

// noteWriteCost 记一次写的耗时；超过合并窗视为链路有压力（下一拍走全量）。
func (l *surfaceLeg) noteWriteCost(d time.Duration) {
	l.mu.Lock()
	l.lastWriteCost = d
	l.mu.Unlock()
}

// underPressure 报告链路是否有压力。
func (l *surfaceLeg) underPressure() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastWriteCost > surfaceMergeWindowMax
}

// noteScrollbar 记下本拍的回滚条 total，并在**检测到裁剪**时要求全量重建（任务 3.3）。
//
// 判据：total 比上次快照时小 ⇒ 回滚被裁剪（page 粒度；探针实测：写 4000 行时 total 从 2001
// 掉到 1719）。此时 [0,total) 的绝对行号整体滑动，客户端缓存的镜像行与拉取行都指向别的内容，
// 只有一次新的全量（含新镜像 + 新 total）能让它重新锚定。返回 true = 已置 needSnapshot。
func (l *surfaceLeg) noteScrollbar(total uint64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	trimmed := l.hasSnapTotal && total < l.lastSnapTotal
	if trimmed {
		l.needSnapshot = true
		l.stats.trims++
	}
	return trimmed
}

// statsSnapshot 读计数器（观测/诊断用）。
func (l *surfaceLeg) statsSnapshot() surfaceStats {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.stats
}

// sendFrames 把一串帧按顺序写出（调用方保证锁外）。
//
// 写失败（含超时）⇒ 返回 false，调用方负责断腿。分片计数与字节数在这里累加。
func (l *surfaceLeg) sendFrames(c *termClient, op byte, payloads [][]byte) bool {
	start := time.Now()
	for i, p := range payloads {
		if len(p) > surfaceMaxFrame {
			// 服务端**硬保证**单帧 ≤ 64KiB：真出现说明分片逻辑坏了，宁可断腿也不发截断帧
			// （截断对 surface 是非法化语义，评审 H2）。
			l.mu.Lock()
			l.stats.writeTimeout++
			l.mu.Unlock()
			return false
		}
		if err := c.frame(op, p); err != nil {
			l.mu.Lock()
			l.stats.writeTimeout++
			l.mu.Unlock()
			return false
		}
		_ = i
	}
	cost := time.Since(start)
	l.mu.Lock()
	l.stats.fragments += uint64(len(payloads))
	for _, p := range payloads {
		l.stats.bytesOut += uint64(len(p))
	}
	l.mu.Unlock()
	l.noteWriteCost(cost)
	return true
}

// sendSnapshot 下发一次全量快照（锁外调用）：压缩 → 分片 → 逐帧写 → SNAPSHOT-DONE。
//
// body 是**未压缩**的 SNAPSHOT 体；体积超上限时返回 false（调用方断腿/重试）。
func (l *surfaceLeg) sendSnapshot(c *termClient, body []byte) bool {
	if len(body) > perLegPendingCap {
		// 单帧超上限：标记需要全量并在下一拍重试（此时屏幕内容通常已变小）。
		l.markNeedSnapshot("backpressure")
		return true
	}
	gz, err := gzipBytes(body)
	if err != nil {
		return false
	}
	frags := fragmentPayload(gz)
	if !l.sendFrames(c, opSnapshot, frags) {
		return false
	}
	// 完成标志：客户端据此解除渲染抑制（surface 版 REPLAY-DONE）。
	if err := c.frame(opSnapshotDone, encReplayDone(uint32(len(body)), 0)); err != nil {
		l.mu.Lock()
		l.stats.writeTimeout++
		l.mu.Unlock()
		return false
	}
	l.mu.Lock()
	l.stats.snapshots++
	l.mu.Unlock()
	return true
}

// sendDiff 下发一次差分（锁外调用）。
func (l *surfaceLeg) sendDiff(c *termClient, body []byte) bool {
	if len(body) > perLegPendingCap {
		l.markNeedSnapshot("backpressure")
		return true
	}
	gz, err := gzipBytes(body)
	if err != nil {
		return false
	}
	if !l.sendFrames(c, opSurfaceDiff, fragmentPayload(gz)) {
		return false
	}
	l.mu.Lock()
	l.stats.diffs++
	l.stats.sentDiffs++
	l.mu.Unlock()
	return true
}

// sendFetchRows 下发 FETCH-ROWS 应答（锁外调用）。
func (l *surfaceLeg) sendFetchRows(c *termClient, reply fetchRowsReply, hit bool) bool {
	body := encFetchRowsReply(reply)
	gz, err := gzipBytes(body)
	if err != nil {
		return false
	}
	if !l.sendFrames(c, opFetchRows, fragmentPayload(gz)) {
		return false
	}
	l.mu.Lock()
	if hit {
		l.stats.fetchHits++
	} else {
		l.stats.fetchMiss++
	}
	l.mu.Unlock()
	return true
}

// sendClipboard 下发 OSC 52 写请求（S→C）。
func (l *surfaceLeg) sendClipboard(c *termClient, payload []byte) bool {
	return l.sendFrames(c, opClipboard, [][]byte{payload})
}

// sendNotify 下发裸 OSC 9 通知（S→C）。
func (l *surfaceLeg) sendNotify(c *termClient, payload []byte) bool {
	return l.sendFrames(c, opNotify, [][]byte{payload})
}
