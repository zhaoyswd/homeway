package control

// stream.go — 流式通道（§3.5，spec「流式通道」）：term 字节流的**纯透传**多路
// 复用。守护进程 MUST NOT 解析/改写/重定义 term 协议语义（腿模式/caps/ENDED 词表
// 全归 term 协议——控制面词表不含它们）。
//
// 写者模型（borrow term-host-cli D5，design B5 拍板）：每流有界队列 + 独立泵，
// 生产者只入队、慢流自治——
//
//	backendPump:   读后端 → dataC（有界 16 条 × 16KiB；满则阻塞 = 暂停读后端 =
//	               背压传导到后端 TCP，绝不阻塞控制帧/事件/其它流）
//	upstreamPump:  upC → 写后端（前端上行）
//	upWorker:      upBuf → upC（**每流**上行工位，4a §5.3：读循环非阻塞转投进
//	               upBuf〔32 帧/512KiB 双界〕，工位内有界等待 upC 空位——超时
//	               才收流；停滞只收该流不扩散）
//	conn.writer:   唯一写前端 socket（优先级见 server.go 文件头）
//
// 终结次序：finish(reason) 先停后端读、end 标记尾入 dataC——积压数据先送达、
// end 之后绝无该流数据（spec「流关闭先给结束信号」）。reason ∈ {closed, gone}：
// closed = 对端（后端 EOF/写失败）或前端主动 stream.close；gone = 目标主机不可达/
// 会话收工（控制面层的本地原因）。连接级断开不发 end（三者可区分）。

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/zhaoyswd/homeway/clientcore/facade"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// 流参数（design D5；不改契约形状）。
const (
	streamChunkSize  = 16 << 10 // backendPump 单次读块
	streamQueueItems = 16       // 下行队列条数（≈256KiB/流有界缓冲）
	streamUpItems    = 8        // 上行队列条数（前端→后端；term 键盘量级）
	streamUpTimeout  = 30 * time.Second
)

// 上行收流宽容化（4a §5.3，D4：每流工位 + 双界 + 全连接总量上限——wire 零改动，
// 16KiB 分片〔3b 客户端 Send〕与 L4 双向显式化〔3c〕已落地不重复认领）。
const (
	// upWorkerItems 每流上行工位队列条数界（32 帧）。
	upWorkerItems = 32
	// upWorkerBytes 每流上行工位字节界（512KiB = 按 16KiB 分片假设的 32 帧——
	// 只按条数设界会让第三方/异常前端把内存放大 16 倍，双界取先到）。
	upWorkerBytes = 512 << 10
	// DefaultUpStallTimeout 每流工位等待 upC 空位的上限（默认 30s）。独立于
	// streamUpTimeout 论证：那是 SetWriteDeadline 的单次写上限、这是等队列空位
	//（「后端在读但慢」场景的可容忍上界——期间前端 Send 已返回成功、数据压在
	// 服务端）；发版前可按实测调小。
	DefaultUpStallTimeout = 30 * time.Second
	// DefaultMaxUpWorkers 全连接（server 汇总）上行工位总量上限（防「每流一
	// 工位」的资源放大——超总量拒开新流，复用既有 stream_refused）。
	DefaultMaxUpWorkers = 64
)

// streamItem 下行队列元素（data 或 end 标记——end 必经同队列保序）。
type streamItem struct {
	data []byte
	end  string // 非"" = 终结帧（reason）
}

// stream 一条在册流。
type stream struct {
	id      uint32
	c       *conn
	backend net.Conn

	dataC chan streamItem // 后端→前端（conn.writer 消费）
	upC   chan []byte     // 前端→后端（upstreamPump 消费）

	// 上行工位（4a §5.3）：读循环非阻塞转投进 upBuf（32 帧/512KiB 双界——
	// upBytes 记账），工位 goroutine（upWorker）搬运营收到 upC，有界等待
	// DefaultUpStallTimeout，超时才收流。有效缓冲 = upC 8 帧 + 工位 32 帧 =
	// 40 帧（16KiB 分片形态 ≈ 640KiB）：背靠背大块上行从「>8 帧即秒杀」放宽到
	// 「40 帧内排队排空、>40 帧仍收流」——如实边界，非无限缓速排空。
	upBuf   chan []byte
	upBytes atomic.Int64

	done      chan struct{} // 流终结（pumps 退出）
	finishOne sync.Once
}

// wake 唤醒 writer 轮询流数据（非阻塞——writer 本就在循环轮询，wake 只兜底）。
func (c *conn) wake() {
	select {
	case c.wakeC <- struct{}{}:
	default:
	}
}

// opStreamOpen stream.open{kind, host}：kind 初始集仅 term；拨号经 Backend.DialTerm
// （hostsession 的 DialPort 过隧道，term 端口为核内约定、不进控制面词表）。本函数
// 运行在独立拨号执行体（runStreamOpen，4a §5.1 r2 新-6）——30s 级拨号不占请求
// 工位串行位。工位配额（4a §5.3）：全连接上行工位总量超上限 → 拒开（复用既有
// stream_refused）。
func (c *conn) opStreamOpen(corr uint64, args json.RawMessage) {
	var a StreamOpenArgs
	if err := parseArgs(args, &a); err != nil {
		c.reply(corr, nil, err)
		return
	}
	if a.Kind != facade.StreamKindTerm {
		c.reply(corr, nil, errCode(facade.CodeBadRequest)) // kind 值域外（初始集仅 term）
		return
	}
	if a.Host == "" {
		c.reply(corr, nil, errCode(facade.CodeBadRequest))
		return
	}
	if c.s.cfg.Backend.NotReady() {
		c.reply(corr, nil, errCode(facade.CodeNotReady))
		return
	}
	c.streamsMu.Lock()
	if len(c.streams) >= c.s.cfg.MaxStreams {
		c.streamsMu.Unlock()
		c.reply(corr, nil, errCode(facade.CodeStreamRefused)) // 在册流超上限
		return
	}
	c.streamsMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	backend, err := c.s.cfg.Backend.DialTerm(ctx, a.Host)
	if err != nil {
		switch {
		case errors.Is(err, ErrBackendNoHost):
			c.reply(corr, nil, errCode(facade.CodeNoHost))
		case errors.Is(err, ErrBackendNoSession):
			c.reply(corr, nil, errCode(facade.CodeStreamRefused))
		default:
			c.s.cfg.Logf("control: stream.open(%s) 拨号失败：%v", a.Host, err)
			c.reply(corr, nil, errCode(facade.CodeStreamRefused)) // 主机不可达等 = 被拒
		}
		return
	}

	c.streamsMu.Lock()
	if len(c.streams) >= c.s.cfg.MaxStreams { // 并发 open 竞争上限
		c.streamsMu.Unlock()
		_ = backend.Close()
		c.reply(corr, nil, errCode(facade.CodeStreamRefused))
		return
	}
	// 上行工位总量（4a §5.3）：全连接汇总超上限 = 拒开新流（防「每流一工位」的
	// 资源放大；释放点在 finishOne——finish/teardown 都经它，恰一次）。
	if c.s.upWorkers.Add(1) > int64(c.s.cfg.MaxUpWorkers) {
		c.s.upWorkers.Add(-1)
		c.streamsMu.Unlock()
		_ = backend.Close()
		c.reply(corr, nil, errCode(facade.CodeStreamRefused))
		return
	}
	c.nextStream++
	id := c.nextStream
	st := &stream{
		id:      id,
		c:       c,
		backend: backend,
		dataC:   make(chan streamItem, streamQueueItems),
		upC:     make(chan []byte, streamUpItems),
		upBuf:   make(chan []byte, upWorkerItems),
		done:    make(chan struct{}),
	}
	c.streams[id] = st
	c.streamsMu.Unlock()

	c.reply(corr, StreamOpenResult{StreamID: id}, nil)
	go st.backendPump()
	go st.upstreamPump()
	go st.upWorker()
}

// opStreamClose 前端主动关（reason=closed；确认 rsp 与 end 帧都送达——前端可依
// end 帧确认次序，未知流只回 no_stream 不断连）。
func (c *conn) opStreamClose(corr uint64, args json.RawMessage) {
	var a StreamCloseArgs
	if err := parseArgs(args, &a); err != nil {
		c.reply(corr, nil, err)
		return
	}
	st := c.lookupStream(a.StreamID)
	if st == nil {
		c.reply(corr, nil, errCode(facade.CodeNoStream))
		return
	}
	st.finish(facade.StreamEndClosed)
	c.reply(corr, map[string]bool{"closed": true}, nil)
}

// lookupStream 查在册流（已终结/未知 = nil）。
func (c *conn) lookupStream(id uint32) *stream {
	c.streamsMu.Lock()
	defer c.streamsMu.Unlock()
	return c.streams[id]
}

// handleStreamData 上行数据帧（前端→后端透传）。未知/已关闭流：回执 no_stream
// （corr=0 保留值 = 服务端主动通知，result 标注来源——流数据帧无 corr 关联位，
// spec 场景「未知流引用只回错误不断连」的「回错误码」载体）；连接不断连、其它流
// 不受影响。在册流：**非阻塞**转投进每流上行工位队列（4a §5.3：读循环永不阻塞
// ——「慢流 MUST NOT 阻塞控制帧/事件推送/其它流」在上行方向同样成立）；双界
// （32 帧 / 512KiB）取先到，超界 = 每流有效缓冲（upC 8 + 工位 32 = 40 帧）已尽
// → 收流（gone——如实边界，非无限缓速排空；发送端仍义务分片节流）。
func (c *conn) handleStreamData(body []byte) {
	id, payload, err := DecodeStreamBody(body)
	if err != nil {
		c.fatal(facade.CodeBadFrame)
		return
	}
	st := c.lookupStream(id)
	if st == nil {
		c.reply(0, map[string]any{"op": OpStreamData, "streamId": id, "error": facade.CodeNoStream}, nil)
		c.s.cfg.Logf("control: 流 %d 不在册（已关？），上行 %d 字节被拒", id, len(payload))
		return
	}
	select {
	case st.upBuf <- payload:
		st.upBytes.Add(int64(len(payload)))
	default:
		// 工位队列条数界满：每流缓冲已尽 → 收流（只收该流，不扩散）。
		st.finish(facade.StreamEndGone)
		return
	}
	// 字节界（双界取先到）：入队后核对（记账原子；超界收流——已入队部分由收流
	// 机器统一兜底，不再逐条回捞）。
	if st.upBytes.Load() > upWorkerBytes {
		st.finish(facade.StreamEndGone)
	}
}

// upWorker 每流上行工位（4a §5.3）：upBuf → upC 的搬运 goroutine。upC 满（后端
// 消费慢）时有界等待（cfg.UpStallTimeout，默认 30s——「后端在读但慢」的可容忍
// 上界，独立于 streamUpTimeout 的单次写上限论证）；超时 = 后端持续不读（远超
// 正常形态）→ 收流（gone）。停滞等待次数与超时收流计数进观测（server 级计数，
// 超时日志行携带累计值）。
func (st *stream) upWorker() {
	for {
		select {
		case p := <-st.upBuf:
			st.upBytes.Add(-int64(len(p)))
			select {
			case st.upC <- p:
			default:
				// 需要等空位 = 一次停滞等待（观测计数；不逐次刷日志——超时行带累计）。
				st.c.s.upStallWaits.Add(1)
				select {
				case st.upC <- p:
				case <-st.done:
					return
				case <-time.After(st.c.s.cfg.UpStallTimeout):
					st.c.s.upStallKills.Add(1)
					st.c.s.cfg.Logf("control: 流 %d 上行停滞 %v（后端不读）——收流（gone）；累计停滞等待 %d 次 / 超时收流 %d 次",
						st.id, st.c.s.cfg.UpStallTimeout, st.c.s.upStallWaits.Load(), st.c.s.upStallKills.Load())
					st.finish(facade.StreamEndGone)
					return
				}
			}
		case <-st.done:
			return
		}
	}
}

// backendPump 后端→前端：读后端 → dataC（满则暂停读后端 = 慢流背压，不影响
// 他人）；EOF → closed（对端主动关）；读错 → gone；done → 流已终结。
func (st *stream) backendPump() {
	buf := make([]byte, streamChunkSize)
	for {
		n, err := st.backend.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			item := streamItem{data: chunk}
			select {
			case st.dataC <- item:
				st.c.wake()
			case <-st.done:
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				st.finish(facade.StreamEndClosed)
			} else {
				st.finish(facade.StreamEndGone) // 后端连接错误（会话收工会体现为这里）
			}
			return
		}
		select {
		case <-st.done:
			return
		default:
		}
	}
}

// upstreamPump 前端→后端：upC → 写后端（写停滞/错误 = 对端不消费 → 收流）。
func (st *stream) upstreamPump() {
	for {
		select {
		case b := <-st.upC:
			_ = st.backend.SetWriteDeadline(time.Now().Add(streamUpTimeout))
			if _, err := st.backend.Write(b); err != nil {
				st.finish(facade.StreamEndGone)
				return
			}
		case <-st.done:
			// 收工前把上行余量刷完（有限条目；写失败按收流处理）。
			for {
				select {
				case b := <-st.upC:
					_ = st.backend.SetWriteDeadline(time.Now().Add(streamUpTimeout))
					if _, err := st.backend.Write(b); err != nil {
						return
					}
				default:
					return
				}
			}
		}
	}
}

// finish 流终结（幂等）：停泵（done + 关后端连接）→ end 标记尾入 dataC（阻塞
// 等积压排空——「先送数据后送 end」）。上行工位配额在此释放（finishOne 保证
// 恰一次——finish 与 teardown 都经它）。
func (st *stream) finish(reason string) {
	st.finishOne.Do(func() {
		st.c.s.upWorkers.Add(-1) // 上行工位总量释放（4a §5.3；未配额成功的流不构造，必配对）
		close(st.done)
		_ = st.backend.Close()
		select {
		case st.dataC <- streamItem{end: reason}:
			st.c.wake()
		case <-st.c.closed:
			// 连接已断（end 发不出）：无意义等待，直接弃。
		}
	})
}

// teardown 连接级收口：只停泵关后端，**不发 end**（连接没了；spec：连接级断开
// 与流级 end 可区分）。
func (st *stream) teardown() {
	st.finishOne.Do(func() {
		st.c.s.upWorkers.Add(-1)
		close(st.done)
		_ = st.backend.Close()
	})
}
