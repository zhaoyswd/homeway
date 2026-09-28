//go:build !windows

// term_surface_leg.go — surface 腿的投递（任务 2.3/2.4/2.5；多腿化 = term-host-cli 2.2a）。
//
// 一条会话可以有多条 surface 腿同时在场（每腿一份本结构）：**基线（base/hasBase）、
// needSnapshot、revision、背压都在腿上**——掉队腿全量重建、健康腿继续差分、互不影响。
//
// # 锁纪律（design D2）
//
// **锁内只取快照、锁外压缩与入队**：取脏行/网格/光标/模式要持会话锁（与 PTY pump 串行），
// 但 gzip、分片、socket 写全在锁外（socket 写由每腿唯一的写者 goroutine 执行，design D5/B'，
// 见 term_leg.go——sendMu 的帧组原子性职责由「单队列 + 单写者」继承）。
//
// # 背压（2.5 + 任务 4.3 的两种失败模式）
//
// 合并窗（16–33ms）把窗内的多次脏标记并成一帧。两种失败模式**分开**：
//   - 单帧体积超 perLegPendingCap（4MiB）⇒ 标记该腿需要全量、下一拍重试（既有语义）；
//   - 队列积压超 perLegQueueBytes（8MiB/腿，**队列**上限——perLegPendingCap 是单帧上限、
//     不是队列长度）⇒ 丢弃待发 + 标记需全量。
//
// 状态宁可全量重建，不可让客户端停在半新半旧。socket 写失败（含超时）⇒ 断该腿（会话存续，
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

	// perLegPendingCap 是单腿**单帧**的体积上限（design D2 的 4MiB）。
	// 超过它就不发差分/快照，而是标记「需要全量」并等下一拍（那时体积会小下来）。
	perLegPendingCap = 4 << 20

	// perLegQueueBytes 是单腿**队列**的体积上限（任务 4.3，默认 8MiB/腿）。
	// 与 perLegPendingCap 是两个维度：前者拦病态单帧，后者拦持续积压（慢腿吃满队列 ⇒
	// 丢弃待发 + 标记需全量，写者继续排空已有帧）。
	perLegQueueBytes = 8 << 20

	// surfaceFetchRowsMax 是单次 FETCH-ROWS 的行数上限（防对端一次要几万行把内存打满）。
	surfaceFetchRowsMax = 512
)

// surfaceStats 是服务端观测计数器（任务 2.9；对称客户端 3.8，7.4 两端对照的数据源）。
type surfaceStats struct {
	snapshots     uint64 // 下发的全量快照数
	diffs         uint64 // 下发的差分帧数
	degrades      uint64 // 差分降级为全量的次数
	backpressure  uint64 // 背压事件（弃差分标记需快照）
	queueOverflow uint64 // 队列积压超 perLegQueueBytes 的丢弃事件（任务 4.3 失败模式二）
	fragments     uint64 // 分片总数
	bytesOut      uint64 // 下发字节（分片后的净字节）
	fetchHits     uint64 // FETCH-ROWS 命中（取到行）
	fetchMiss     uint64 // FETCH-ROWS 落空（越界/备用屏）
	writeTimeout  uint64 // 写失败/超时断腿次数
	sentDiffs     uint64 // 差分成功下发（用于 7.4 的差分 vs 原始 ANSI 对照）
	trims         uint64 // 回滚裁剪触发的强制全量重建（任务 3.3；观测用）
}

// surfaceLeg 一条 surface 腿的投递状态。
type surfaceLeg struct {
	mu sync.Mutex

	// revision 是差分对账的世代号：每发一次全量 +1；差分沿用当前值。
	// 客户端发现断档就 FETCH-SNAPSHOT（服务端不重传旧差分）。
	revision uint32
	// needSnapshot 标记该腿需要全量重建（首次 attach / 背压 / 降级 / resize / 回滚裁剪）。
	needSnapshot bool
	// base/hasBase 是**该腿**上一次成功下发（快照或差分）的屏态基线（任务 2.2a：
	// 从 sessionVT 搬到腿上——多腿各自对账）。
	//
	// 为什么需要它（2026-09-24 评审整改，P0）：光标移动、鼠标上报模式开关（?1000h）、
	// DECTCEM 光标显隐、DECCKM、括号粘贴这些**都不产生脏行**——只看「有没有脏行」会
	// 一个字节都不发。有了基线，本拍与上一拍比光标/模式位/回滚条，任一变化就发帧
	//（差分体已带这三样）。
	base    SurfaceState
	hasBase bool
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
	switch reason {
	case "backpressure":
		l.stats.backpressure++
	case "queue_overflow":
		l.stats.queueOverflow++
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

// stateUnchanged 报告本拍屏态与该腿基线相比是否完全没动（光标/模式位/回滚条；
// 脏行由会话级 SurfaceTick 判，这里只补「不产生脏行」的那部分）。
func (l *surfaceLeg) stateUnchanged(st SurfaceState) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.hasBase && st.Cursor == l.base.Cursor && st.Modes == l.base.Modes &&
		st.Total == l.base.Total && st.Offset == l.base.Offset && st.Len == l.base.Len
}

// commitBaseline 在一次快照/差分**成功入队后**记该腿的基线（2.2a：基线在腿上）。
func (l *surfaceLeg) commitBaseline(st SurfaceState) {
	l.mu.Lock()
	l.base, l.hasBase = st, true
	l.mu.Unlock()
}

// noteSent 记一次成功入队的载荷（快照/差分）的观测计数。
func (l *surfaceLeg) noteSent(op byte, items []writeItem) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if op == opSnapshot {
		l.stats.snapshots++
	} else {
		l.stats.diffs++
		l.stats.sentDiffs++
	}
	l.stats.fragments += uint64(len(items))
	for _, it := range items {
		l.stats.bytesOut += uint64(len(it.payload))
	}
}

// noteFetchRows 记一次 FETCH-ROWS 应答的命中/落空。
func (l *surfaceLeg) noteFetchRows(hit bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if hit {
		l.stats.fetchHits++
	} else {
		l.stats.fetchMiss++
	}
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

// noteWriteFailure 记一次写失败（写者断腿路径调用；观测用）。
func (l *surfaceLeg) noteWriteFailure() {
	l.mu.Lock()
	l.stats.writeTimeout++
	l.mu.Unlock()
}
