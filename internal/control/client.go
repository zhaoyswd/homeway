package control

// client.go — 控制面 Go 客户端（§3.8）：握手/请求/订阅/流的客户端 API，
// `homeway daemon status`（4.1）与控制面全部服务器单测共用（真实消费者路径——
// 每个服务器测试都经本客户端走完整 UDS + 帧 + JSON 协议）。不抽 facade（4a 的活，
// 届时以「第二个真实消费者」资格定型）。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zhaoyswd/homeway/clientcore/facade"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// CodeError 稳定错误码（服务端 rsp 的 error 值原样返回——CLI 侧映射人类可读
// 文案，文案 MUST NOT 进入契约）。
type CodeError string

func (e CodeError) Error() string { return string(e) }

// OpError 控制面错误：稳定码 + 服务端可行动归因（FIX-50 只增面）。errors.Is 对
// CodeError 仍成立（既有映射零改）。
type OpError struct {
	Code   CodeError
	Detail string
}

func (e *OpError) Error() string {
	if e.Detail != "" {
		return string(e.Code) + ": " + e.Detail
	}
	return string(e.Code)
}

// As 让 errors.As(err, &code)（code 为 CodeError）成立——既有「按码分支」的调用面
// （host_cli/files_remote/term_remote/socks_cli…）零改。
func (e *OpError) As(target any) bool {
	if p, ok := target.(*CodeError); ok {
		*p = e.Code
		return true
	}
	return false
}

// Is 让 errors.Is(err, CodeError(x)) 成立（码比较与既有语义一致）。
func (e *OpError) Is(target error) bool {
	switch t := target.(type) {
	case CodeError:
		return e.Code == t
	case *OpError:
		return e.Code == t.Code
	}
	return false
}

// errFromRsp 响应错误 → 错误值：有 detail 用 OpError（可行动归因随行），无则原样
// CodeError（零 detail 的旧服务端/断连路径回落既有类型）。
func errFromRsp(rsp ResponseBody) error {
	if rsp.Detail == "" {
		return CodeError(rsp.Error)
	}
	return &OpError{Code: CodeError(rsp.Error), Detail: rsp.Detail}
}

// CodeDetailOf 取错误里的稳定码与可行动归因（非控制面错误返回 ok=false）。
func CodeDetailOf(err error) (CodeError, string, bool) {
	var oe *OpError
	if errors.As(err, &oe) {
		return oe.Code, oe.Detail, true
	}
	var ce CodeError
	if errors.As(err, &ce) {
		return ce, "", true
	}
	return "", "", false
}

// ErrConnClosed 客户端连接已断（等待响应期间对端关闭/告别）。
var ErrConnClosed = errors.New("控制面连接已关闭")

// ErrStreamEnded 流已终结（stream.end 已收 / 连接已断）后 Send 的错误
// （term-remote 2.2 上行显式化：不再静默成功把数据写进死流；errors.Is 可判，
// 原因见包装文案——closed/gone/连接断三态）。
var ErrStreamEnded = errors.New("流已终结")

// endReasonConn 连接级断开的终结原因（区别于 stream.end 的 closed/gone——
// endReason 值只进本地错误文案，不上 wire）。
const endReasonConn = "conn"

// Client 控制面客户端（一连接一客户端）。
type Client struct {
	nc      net.Conn
	writeMu sync.Mutex

	corr     atomic.Uint64
	pending  sync.Map // corr(uint64) -> chan ResponseBody
	pendingW sync.WaitGroup

	eventsC  chan EventBody
	goodbyeC chan GoodbyeBody
	reloadC  chan ReloadBody
	welcomeC chan *WelcomeBody
	notifyC  chan ResponseBody // corr=0 服务端通知（如 no_stream 流数据回执）

	streams        sync.Map // streamID(uint32) -> *ClientStream
	pendingStreams sync.Map // corr(uint64) -> *ClientStream（open 响应到达时由
	// reader 同步注册进 streams——消除「rsp 处理与调用方注册流之间」的首帧竞态：
	// 紧随 rsp 的第一帧流数据必须在流已在册时才到达 reader）

	closed chan struct{}
	once   sync.Once
}

// ClientStream 前端侧的一条流。
type ClientStream struct {
	c    *Client
	ID   uint32
	recv chan []byte
	end  chan string

	// 终结状态（2.2）：收到 stream.end（closed|gone）或连接级断开（conn）置位，
	// 此后 Send 恒报 ErrStreamEnded。end 通道语义不变（只对流级 end 触发——
	// 连接级断开与流级 end 三者可区分的既有契约）。
	mu        sync.RWMutex
	ended     bool
	endReason string
}

// markEnded 流终结状态化（幂等，首个原因生效）。
func (s *ClientStream) markEnded(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return
	}
	s.ended = true
	s.endReason = reason
}

// EndedErr 流已终结时的错误（含原因文案）；nil = 流还活着。Send 的前置检查。
func (s *ClientStream) EndedErr() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.ended {
		return nil
	}
	return fmt.Errorf("%w（%s）", ErrStreamEnded, endReasonText(s.endReason))
}

// EndReason 终结原因的**类型化导出**（files-cli 2.1 计划外最小扩展，r2 新-2）：
// 流已终结时返回 reason 值（closed|gone|conn——conn 为连接级断开的本地值，见
// endReasonConn）；未终结返回空串。写路径消费者（daemon 的 streamConn.Write 翻译
// streamend.Error）经它取原因——此前原因只进 EndedErr 的中文文案，换文案即静默
// 失效。markEnded 幂等且首因生效 ⇒ 非 nil 终结错误 ⇒ 原因已定，读此值无竞态
// （加锁读取）。
func (s *ClientStream) EndReason() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.endReason
}

// endReasonText 终结原因 → 中文描述（EndReason/EndedErr 的文案面；EndReason 给
// 调用方的是裸原因值，不进这里）。
func endReasonText(r string) string {
	switch r {
	case facade.StreamEndClosed:
		return "对端已关闭（stream.end=closed）"
	case facade.StreamEndGone:
		return "主机不可达或上行过快（stream.end=gone）"
	case endReasonConn:
		return "控制面连接已断开"
	}
	return r
}

// Dial 连接 control.sock 并完成握手；返回客户端与 welcome（服务端版本/代际/序号）。
func Dial(ctx context.Context, sockPath string, frontend FrontendInfo) (*Client, *WelcomeBody, error) {
	d := &net.Dialer{}
	nc, err := d.DialContext(ctx, "unix", sockPath)
	if err != nil {
		return nil, nil, err
	}
	c := &Client{
		nc:       nc,
		eventsC:  make(chan EventBody, 1024),
		goodbyeC: make(chan GoodbyeBody, 1),
		reloadC:  make(chan ReloadBody, 1),
		notifyC:  make(chan ResponseBody, 16),
		welcomeC: make(chan *WelcomeBody, 1),
		closed:   make(chan struct{}),
	}
	go c.reader()
	if err := c.writeFrame(encodeJSONFrame(OpHello, HelloBody{ProtoVersion: ProtoVersion, Frontend: frontend})); err != nil {
		c.Close()
		return nil, nil, err
	}
	// 等 welcome（或 reload——版本不匹配时服务端回 reload 后关闭连接）。
	select {
	case w := <-c.welcomeC:
		return c, w, nil
	case r := <-c.reloadC:
		c.Close()
		return nil, nil, fmt.Errorf("服务端要求 reload（%s）", r.Reason)
	case <-ctx.Done():
		c.Close()
		return nil, nil, ctx.Err()
	case <-c.closed:
		return nil, nil, ErrConnClosed
	}
}

// writeFrame 帧写（互斥——请求/流数据共用连接）。
func (c *Client) writeFrame(f []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.nc.SetWriteDeadline(time.Now().Add(writeStallTimeout))
	if _, err := c.nc.Write(f); err != nil {
		return err
	}
	return nil
}

// Request 发请求等响应。args 为 nil 时不带载荷；错误码响应返回 CodeError。
func (c *Client) Request(ctx context.Context, op string, args any) (json.RawMessage, error) {
	corr := c.corr.Add(1)
	var raw json.RawMessage
	if args != nil {
		b, err := json.Marshal(args)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	ch := make(chan ResponseBody, 1)
	c.pending.Store(corr, ch)
	defer c.pending.Delete(corr)
	if err := c.writeFrame(encodeJSONFrame(OpReq, RequestBody{Corr: corr, Op: op, Args: raw})); err != nil {
		return nil, err
	}
	select {
	case rsp := <-ch:
		if !rsp.Ok {
			return nil, errFromRsp(rsp)
		}
		return rsp.Result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, ErrConnClosed
	}
}

// Subscribe 订阅事件（游标续播；view 声明**参与服务端需求合成**并在确认/快照里回显，
// FIX-53：此前注释写「只回显」与 spec（facade 期起 view 参与需求合成）相反；
// generation = 游标所属代际——
// 非空且失配时服务端回 cursor_stale）。订阅确认后回放事件先于在线事件进入
// Events()（服务端写出次序保证）。
func (c *Client) Subscribe(ctx context.Context, domains []string, cursor *uint64, view, generation string) (SubscribeResult, error) {
	raw, err := c.Request(ctx, facade.OpEventsSubscribe, SubscribeArgs{Domains: domains, Cursor: cursor, View: view, Generation: generation})
	if err != nil {
		return SubscribeResult{}, err
	}
	var r SubscribeResult
	if err := json.Unmarshal(raw, &r); err != nil {
		return SubscribeResult{}, err
	}
	return r, nil
}

// Unsubscribe 退订。
func (c *Client) Unsubscribe(ctx context.Context, domains []string) error {
	_, err := c.Request(ctx, facade.OpEventsUnsubscribe, UnsubscribeArgs{Domains: domains})
	return err
}

// Events 事件流（含订阅回放）。
func (c *Client) Events() <-chan EventBody { return c.eventsC }

// Goodbye 服务端告别（overrun/bad_frame/bad_json/shutting_down…）。
func (c *Client) Goodbye() <-chan GoodbyeBody { return c.goodbyeC }

// Notify corr=0 服务端通知（如对未知流 stream.data 的 no_stream 回执）。
func (c *Client) Notify() <-chan ResponseBody { return c.notifyC }

// Closed 连接关闭信号。
func (c *Client) Closed() <-chan struct{} { return c.closed }

// OpenStream stream.open{kind, host} → 流句柄。kind ∈ term|files（daemon-control-plane
// 值域只增；files 自 files-cli 期起）——载荷由调用方携带，本客户端不设值域闸（服务端
// 是值域真源）。流对象在请求发出前经 pendingStreams 预登记、由 reader 在响应帧上同步
// 注册（见 pendingStreams 注释）。
func (c *Client) OpenStream(ctx context.Context, kind, host string) (*ClientStream, error) {
	corr := c.corr.Add(1)
	st := &ClientStream{c: c, recv: make(chan []byte, 64), end: make(chan string, 1)}
	c.pendingStreams.Store(corr, st)
	defer c.pendingStreams.Delete(corr)
	var raw json.RawMessage
	ch := make(chan ResponseBody, 1)
	c.pending.Store(corr, ch)
	defer c.pending.Delete(corr)
	if err := c.writeFrame(encodeJSONFrame(OpReq, RequestBody{Corr: corr, Op: facade.OpStreamOpen, Args: mustMarshal(StreamOpenArgs{Kind: kind, Host: host})})); err != nil {
		return nil, err
	}
	select {
	case rsp := <-ch:
		if !rsp.Ok {
			return nil, errFromRsp(rsp)
		}
		raw = rsp.Result
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, ErrConnClosed
	}
	var r StreamOpenResult
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	if st.ID == 0 {
		// 防御：reader 未及注册（不应发生——rsp 帧路径同步注册）。
		st.ID = r.StreamID
		c.streams.Store(r.StreamID, st)
	}
	return st, nil
}

func mustMarshal(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// Send 上行数据（stream.data 帧；透传原始字节）。按 streamChunkSize（16KiB，与
// 服务端下行 backendPump 读块同款常量）自动分片——单帧 body 超 256KiB-4 会被
// 服务端按帧长上限拒（bad_frame 断连），大块上行必须分片（host-cli 3b，exec-r2 ①）。
// 流 = 字节流语义，不承诺帧边界（对端按序重组即可）。
// L4 上行显式化（term-remote 2.2）：Send 先查终结状态——stream.end 已收或连接已断
// 即报 ErrStreamEnded（含原因），不再静默成功把数据写进死流（现状 = 数据丢失无从
// 感知）。分片循环逐帧经 EndedErr 复查，流中途死即停发（粘贴突发不推进死流）。
// 注记：分片无流控（真流控 = 4a 的 credit 设计——无 wire 反馈信号，任何客户端侧
// 窗口都只是猜测）；超突发仍会被服务端按背压收流（finish(gone)，design D7）。
// 空载荷显式不发（字节流语义下无实害；历史口径见 host-cli 3b 注记）。
func (s *ClientStream) Send(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if err := s.EndedErr(); err != nil {
		return err
	}
	for off := 0; off < len(b); off += streamChunkSize {
		end := off + streamChunkSize
		if end > len(b) {
			end = len(b)
		}
		if err := s.c.writeFrame(EncodeFrame(OpStreamData, EncodeStreamBody(s.ID, b[off:end]))); err != nil {
			return err
		}
		if err := s.EndedErr(); err != nil {
			return err
		}
	}
	return nil
}

// Recv 下行数据流。
func (s *ClientStream) Recv() <-chan []byte { return s.recv }

// End 流终结信号（reason ∈ closed|gone；连接级断开不触发本信号——三者可区分）。
func (s *ClientStream) End() <-chan string { return s.end }

// Close 前端主动关（stream.close 操作，reason=closed）。成功即置终结位
// （markEnded(facade.StreamEndClosed)，exec-r1 L4）：终结状态化原只覆盖「收到 stream.end /
// 连接级断开」，本端主动关流后 Send 同样不再静默成功写进死流（与 2.2 的 proposal
// 意图对齐；服务端对已关流的 data 另有 no_stream 回执兜底，此处是本端第一道闸）。
// 归因复用 closed 的近似（exec-r2 N4 登记）：此后 Send 的 EndedErr 文案为「对端已
// 关闭」，实情是本端主动 stream.close（对端 end 帧可能永不到达）；仓内唯一消费者
// streamConn.Close 在 Client.Close() 后不再写、无命中路径，不值得为此新开原因枚举。
func (s *ClientStream) Close(ctx context.Context) error {
	_, err := s.c.Request(ctx, facade.OpStreamClose, StreamCloseArgs{StreamID: s.ID})
	if err == nil {
		s.markEnded(facade.StreamEndClosed)
	}
	return err
}

// Close 关闭客户端连接（幂等）。
func (c *Client) Close() {
	c.once.Do(func() {
		// 顺序契约（FIX-114 实测窗口）：先标在册流 ended，再关 closed——反序时
		// 「Closed 已关、流还没标」的窗口里 Send 会返回写错误而非 ErrStreamEnded
		//（测试在 -race 整包负载下 0.00s 偶发红暴露；reader 退出的 readerDone 幂等，
		// 与本调用重复无害）。
		c.readerDone()
		close(c.closed)
		_ = c.nc.Close()
	})
}

// reader 客户端读循环（分发 rsp/evt/流帧/生命周期帧）。退出（IO 错误/EOF/goodbye/
// reload）= 连接级断开：在册流全部终结状态化（见 readerDone）。
func (c *Client) reader() {
	defer c.readerDone()
	for {
		head, err := ReadHeader(c.nc) // 按 op 选上限（流 DATA 256KiB / 控制类 1MiB）
		if err != nil {
			return
		}
		body, err := ReadBody(c.nc, head)
		if err != nil {
			return
		}
		op := head.Op
		switch op {
		case OpWelcome:
			var w WelcomeBody
			if err := json.Unmarshal(body, &w); err == nil {
				select {
				case c.welcomeC <- &w:
				default:
				}
			}
		case OpRsp:
			var rsp ResponseBody
			if err := json.Unmarshal(body, &rsp); err != nil {
				continue
			}
			if rsp.Corr == 0 {
				select {
				case c.notifyC <- rsp:
				default:
				}
				continue
			}
			// stream.open 响应：先于调用方注册流（首帧数据可能紧随本帧到达）。
			if pst, ok := c.pendingStreams.Load(rsp.Corr); ok && rsp.Ok {
				var r StreamOpenResult
				if err := json.Unmarshal(rsp.Result, &r); err == nil && r.StreamID != 0 {
					st := pst.(*ClientStream)
					st.ID = r.StreamID
					c.streams.Store(r.StreamID, st)
				}
			}
			if ch, ok := c.pending.Load(rsp.Corr); ok {
				ch.(chan ResponseBody) <- rsp
			}
		case OpEvt:
			var ev EventBody
			if err := json.Unmarshal(body, &ev); err == nil {
				select {
				case c.eventsC <- ev:
				default:
					// 客户端侧缓冲满（测试消费者太慢）：断开由使用方重启客户端；
					// 真实前端应有自己的有界缓冲与重订阅策略。
				}
			}
		case OpGoodbye:
			var g GoodbyeBody
			if err := json.Unmarshal(body, &g); err == nil {
				select {
				case c.goodbyeC <- g:
				default:
				}
			}
			c.Close()
			return
		case OpReload:
			var r ReloadBody
			if err := json.Unmarshal(body, &r); err == nil {
				select {
				case c.reloadC <- r:
				default:
				}
			}
			c.Close()
			return
		case OpStreamData:
			id, payload, derr := DecodeStreamBody(body)
			if derr != nil {
				continue
			}
			if st, ok := c.streams.Load(id); ok {
				s := st.(*ClientStream)
				if len(s.recv) == cap(s.recv) {
					noteSlowDeliveryForTest() // 测试判别力钩子（见 testhooks.go；探测零副作用）
				}
				// L4 下行背压显式化（term-remote 2.1）：满槽时阻塞投递而非 default 丢弃
				//——丢帧对 term 是无从感知的静默画面损坏（协议无重传/校验），阻塞是唯一
				// 不丢的选项。背压沿链传导（本条链路的设计意图）：本端停读 → 这里阻塞 →
				// 服务端 conn.writer 阻在 dataC（16 条）→ backendPump 停读后端 → 隧道 TCP
				// 背压 → 出口侧 raw 腿跳环/追赶截断策略收尾（term-host-cli D5「慢腿自治」
				// 本就是那一层的职责）。
				// 逃生口 = 连接关闭（<-c.closed）：Close 先关连接即解阻塞（CLI 分离键/
				// 信号路径，见 daemon streamConn 的 Close 定序——反序在 reader 阻塞时
				// 退化为等满 ≤2s 兜底 ctx 才返回，无界 ctx 才恒挂死）。
				// 单流前端语义（r1 P0-1 拍板 = 接受）：reader 阻塞期间同连接的其它帧
				//（应答/事件/别的流的 end）停摆是既定语义而非待修缺陷——CLI term attach
				// 一条连接唯一 term 流、host 命令面是一次性独立连接，「另一条连接上的
				// 请求照常应答」天然成立；同连接多流/混合前端的公平性与收流语义归
				// 4a 事件总线期。停读窗口内的可保证项：本流已接收数据零丢失、本流
				// data/end 顺序不乱。
				select {
				case s.recv <- payload:
				case <-c.closed:
				}
			}
		case OpStreamEnd:
			var e StreamEndBody
			if err := json.Unmarshal(body, &e); err == nil {
				if st, ok := c.streams.Load(e.StreamID); ok {
					// 先标记终结（Send 立即报错），再投递 end 信号（语义不变）。
					st.(*ClientStream).markEnded(e.Reason)
					select {
					case st.(*ClientStream).end <- e.Reason:
					default:
					}
				}
			}
		}
	}
}

// readerDone 连接级断开的终结状态化：在册流全部标记 ended（reason=conn）——此后
// Send 报错而非静默成功（连接断了发什么都是丢）；end 通道不触发（连接级断开与
// 流级 end 三者可区分的既有契约）。
func (c *Client) readerDone() {
	c.streams.Range(func(_, v any) bool {
		v.(*ClientStream).markEnded(endReasonConn)
		return true
	})
}
