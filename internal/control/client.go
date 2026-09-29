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
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// CodeError 稳定错误码（服务端 rsp 的 error 值原样返回——CLI 侧映射人类可读
// 文案，文案 MUST NOT 进入契约）。
type CodeError string

func (e CodeError) Error() string { return string(e) }

// ErrConnClosed 客户端连接已断（等待响应期间对端关闭/告别）。
var ErrConnClosed = errors.New("控制面连接已关闭")

// Client 控制面客户端（一连接一客户端）。
type Client struct {
	nc      net.Conn
	writeMu sync.Mutex

	corr     atomic.Uint64
	pending  sync.Map // corr(uint64) -> chan ResponseBody
	pendingW sync.WaitGroup

	eventsC  chan EventBody
	resyncC  chan ResyncBody
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
		resyncC:  make(chan ResyncBody, 4),
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
			return nil, CodeError(rsp.Error)
		}
		return rsp.Result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, ErrConnClosed
	}
}

// Subscribe 订阅事件（游标续播；view 只回显；generation = 游标所属代际——
// 非空且失配时服务端回 cursor_stale）。订阅确认后回放事件先于在线事件进入
// Events()（服务端写出次序保证）。
func (c *Client) Subscribe(ctx context.Context, domains []string, cursor *uint64, view, generation string) (SubscribeResult, error) {
	raw, err := c.Request(ctx, OpEventsSubscribe, SubscribeArgs{Domains: domains, Cursor: cursor, View: view, Generation: generation})
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
	_, err := c.Request(ctx, OpEventsUnsubscribe, UnsubscribeArgs{Domains: domains})
	return err
}

// Events 事件流（含订阅回放）。
func (c *Client) Events() <-chan EventBody { return c.eventsC }

// Resync 服务端主动重同步信号（v1 服务端无发射场景；客户端路径就绪）。
func (c *Client) Resync() <-chan ResyncBody { return c.resyncC }

// Goodbye 服务端告别（overrun/bad_frame/bad_json/shutting_down…）。
func (c *Client) Goodbye() <-chan GoodbyeBody { return c.goodbyeC }

// Notify corr=0 服务端通知（如对未知流 stream.data 的 no_stream 回执）。
func (c *Client) Notify() <-chan ResponseBody { return c.notifyC }

// Closed 连接关闭信号。
func (c *Client) Closed() <-chan struct{} { return c.closed }

// OpenStream stream.open{kind:"term", host} → 流句柄。流对象在请求发出前经
// pendingStreams 预登记、由 reader 在响应帧上同步注册（见 pendingStreams 注释）。
func (c *Client) OpenStream(ctx context.Context, host string) (*ClientStream, error) {
	corr := c.corr.Add(1)
	st := &ClientStream{c: c, recv: make(chan []byte, 64), end: make(chan string, 1)}
	c.pendingStreams.Store(corr, st)
	defer c.pendingStreams.Delete(corr)
	var raw json.RawMessage
	ch := make(chan ResponseBody, 1)
	c.pending.Store(corr, ch)
	defer c.pending.Delete(corr)
	if err := c.writeFrame(encodeJSONFrame(OpReq, RequestBody{Corr: corr, Op: OpStreamOpen, Args: mustMarshal(t_streamArgs(host))})); err != nil {
		return nil, err
	}
	select {
	case rsp := <-ch:
		if !rsp.Ok {
			return nil, CodeError(rsp.Error)
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

// t_streamArgs 仅收敛 OpenStream 的载荷构造（避免内联闭包）。
func t_streamArgs(host string) StreamOpenArgs {
	return StreamOpenArgs{Kind: StreamKindTerm, Host: host}
}

func mustMarshal(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// Send 上行数据（stream.data 帧；透传原始字节）。
func (s *ClientStream) Send(b []byte) error {
	return s.c.writeFrame(EncodeFrame(OpStreamData, EncodeStreamBody(s.ID, b)))
}

// Recv 下行数据流。
func (s *ClientStream) Recv() <-chan []byte { return s.recv }

// End 流终结信号（reason ∈ closed|gone；连接级断开不触发本信号——三者可区分）。
func (s *ClientStream) End() <-chan string { return s.end }

// Close 前端主动关（stream.close 操作，reason=closed）。
func (s *ClientStream) Close(ctx context.Context) error {
	_, err := s.c.Request(ctx, OpStreamClose, StreamCloseArgs{StreamID: s.ID})
	return err
}

// Close 关闭客户端连接（幂等）。
func (c *Client) Close() {
	c.once.Do(func() {
		close(c.closed)
		_ = c.nc.Close()
	})
}

// reader 客户端读循环（分发 rsp/evt/流帧/生命周期帧）。
func (c *Client) reader() {
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
		case OpResync:
			var r ResyncBody
			if err := json.Unmarshal(body, &r); err == nil {
				select {
				case c.resyncC <- r:
				default:
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
				select {
				case st.(*ClientStream).recv <- payload:
				default:
				}
			}
		case OpStreamEnd:
			var e StreamEndBody
			if err := json.Unmarshal(body, &e); err == nil {
				if st, ok := c.streams.Load(e.StreamID); ok {
					select {
					case st.(*ClientStream).end <- e.Reason:
					default:
					}
				}
			}
		}
	}
}
