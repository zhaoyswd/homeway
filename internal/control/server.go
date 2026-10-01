package control

// server.go — 控制面服务器（§3.2/§3.3）：握手与代际、请求/响应与错误码映射、
// 事件推送泵；流式通道见 stream.go；socket 监听与权限见 listen.go。
//
// 连接模型：一连接两 goroutine（reader 分发 / writer 唯一写 socket）+ **每连接
// 有界请求队列 + 固定请求工位**（L2，4a §5.1：在途〔含工位执行中〕≤ 32、超界
// goodbye(overrun) 断连；「有界在途 = 契约、串行不是契约」——30s 级 stream.open
// 拨号走独立但有界执行体〔同样计入在途〕，同连接其它请求照常应答）+ 每流上行
// 工位（见 stream.go）。writer 的输入按优先级排空：
//
//	highC（welcome/rsp/goodbye/reload 等控制类；订阅确认帧携带门闩标记——
//	写出后清位并按序补写回放）> 事件（bus 订阅者 channel；订阅确认在途门闩
//	置位期复检-暂存）> 各流 dataC（公平轮询）
//
// 这保证慢流积压、订阅回放大批都不阻塞控制帧（spec「慢流不拖垮控制面」/「三类
// 流量同连接交错」）。前端整体不读的病态由写停滞看门狗兜底（SetWriteDeadline
// 超时断连）——订阅了事件的前端通常更早触发 overrun 断连（goodbye(overrun)）。
//
// 协议次序错乱（握手前非 hello、握手后再 hello、前端方向出现 welcome/rsp/evt 等
// 服务端帧）= 无词表值的连接级硬错误：直接关闭连接、不发帧（词表纪律：不发明
// spec 外的 reason 值）。

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zhaoyswd/homeway/clientcore/facade"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// 默认连接参数（design D5；Open Questions：真机数据再调，不改契约形状）。
const (
	// DefaultMaxStreams 每连接在册流上限（超限 stream_refused）。
	DefaultMaxStreams = 8
	// writeStallTimeout 连接写停滞看门狗（前端整体不读的病态兜底）。
	writeStallTimeout = 30 * time.Second
	// highQueue 控制帧队列容量（在途请求 + 生命周期帧）。
	highQueue = 64
	// dialTimeout stream.open 的隧道拨号预算（healingDial 首段试探 + 剩余重试）。
	dialTimeout = 30 * time.Second
	// maxInflight 每连接在途请求上限（L2，4a §5.1）：在途（含工位执行中）≤ 32——
	// 判据只认该口径（队列 31 + 工位 1 或统一计数均可；实现 = 统一计数，容量
	// maxInflight 的队列 + 1 个分发工位 + stream.open 的拨号执行体各占一计）。
	// 超界 = 前端失控流水线（32 条慢 host.add 已是极端）→ goodbye(overrun) 断连
	//（复用既有原因词、零新错误码；前端自辨：断连时有未完成 corr = 请求面溢出
	// → 重连后按需重发；事件面 overrun〔订阅被总线终止〕则 resubscribe + 全量
	// 重快照，r1 中-9）。
	maxInflight = 32
)

// Server 控制面服务器。
type Server struct {
	cfg   ServerConfig
	ln    net.Listener
	mu    sync.Mutex
	conns map[*conn]struct{}
	clos  atomic.Bool
	wg    sync.WaitGroup

	// 上行工位总量（4a §5.3）：全连接（server 汇总）在役工位数（超总量拒开新流，
	// 复用 stream_refused）+ 停滞观测计数（停滞等待次数 / 超时收流次数——日志
	// 计数行携带，发版前可按实测调小 DefaultUpStallTimeout）。
	upWorkers    atomic.Int64
	upStallWaits atomic.Int64
	upStallKills atomic.Int64
}

// ServerConfig 服务器装配项。
type ServerConfig struct {
	ServerVersion string
	Bus           *facade.Bus
	Backend       Backend
	Logf          func(format string, args ...any) // nil = 丢弃
	MaxStreams    int                              // <=0 = DefaultMaxStreams
	// UpStallTimeout 每流上行工位等待 upC 空位的上限（<=0 = DefaultUpStallTimeout；
	// 测试注入缩短）。
	UpStallTimeout time.Duration
	// MaxUpWorkers 全连接（server 汇总）上行工位总量上限（<=0 = DefaultMaxUpWorkers）。
	MaxUpWorkers int
}

// NewServer 建服务器（代际 = facade.Bus 的 generation）。
func NewServer(cfg ServerConfig) *Server {
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.MaxStreams <= 0 {
		cfg.MaxStreams = DefaultMaxStreams
	}
	if cfg.UpStallTimeout <= 0 {
		cfg.UpStallTimeout = DefaultUpStallTimeout
	}
	if cfg.MaxUpWorkers <= 0 {
		cfg.MaxUpWorkers = DefaultMaxUpWorkers
	}
	return &Server{cfg: cfg, conns: make(map[*conn]struct{})}
}

// Generation 当前代际。
func (s *Server) Generation() string { return s.cfg.Bus.Generation() }

// Serve 接入循环（阻塞；listener 由 listen.go 提供，Close 后返回）。accept 错误
// 按瞬态/永久二分（L3，4a §5.2，对齐 net/http 的 Accept 错误处理）：瞬态（连接
// 中断类/fd 短缺类）→ 同一 listener 有界退避重试（不打断在途用户面、不触发角色
// 重建）；永久（listener 失效类）→ 返回错误，由 control 角色上抛走 supervisor
// 既有退避重建（重新 Listen+Serve）。正常 Close 路径零噪声（clos 先行检查）。
func (s *Server) Serve(ln net.Listener) error {
	// s.ln 与 Close 的读写同锁（race 修复：Close 与 Serve 并发时不再裸碰字段）。
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	if s.clos.Load() {
		return nil // Close 先于 Serve 接入（control 角色瞬收窗口）：listener 由调用方收口
	}
	var retryDelay time.Duration // 瞬态退避（5ms 起翻倍、上限 1s）
	for {
		nc, err := ln.Accept()
		if err != nil {
			if s.clos.Load() {
				return nil // 正常收工（Close 先置位再关 listener——零噪声）
			}
			if transientAcceptError(err) {
				if retryDelay == 0 {
					retryDelay = 5 * time.Millisecond
				} else {
					retryDelay *= 2
					if retryDelay > time.Second {
						retryDelay = time.Second
					}
				}
				s.cfg.Logf("control: accept 瞬态错误（%v）——退避 %v 后同 listener 重试（不重建）", err, retryDelay)
				time.Sleep(retryDelay)
				continue
			}
			return err // 永久错误：上抛 → control 角色失败 → supervisor 退避重建
		}
		retryDelay = 0
		c := newConn(s, nc)
		s.mu.Lock()
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			c.run()
			s.mu.Lock()
			delete(s.conns, c)
			s.mu.Unlock()
		}()
	}
}

// transientAcceptError accept 错误的瞬态/永久二分（对齐 net/http）：瞬态 = 连接
// 中断类（ECONNABORTED/ECONNRESET/EINTR）+ fd/内存短缺类（EMFILE/ENFILE/ENOMEM）
// + 超时类 net.Error；其余（listener 已关闭/失效类）= 永久。
func transientAcceptError(err error) bool {
	if errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EINTR) ||
		errors.Is(err, syscall.EMFILE) ||
		errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ENOMEM) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return false
}

// Close 收工：停接入、断开全部连接（在途请求由 shutting_down 错误码路径承接；
// goodbye(shutting_down) 对还写得出的连接尽力送达）。
func (s *Server) Close() {
	s.clos.Store(true)
	s.mu.Lock()
	ln := s.ln
	s.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	s.mu.Lock()
	conns := make([]*conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		c.close("shutting_down")
	}
	s.wg.Wait()
}

func (s *Server) shuttingDown() bool { return s.clos.Load() }

// ---------- 连接 ----------

// conn 一条控制面连接。
type conn struct {
	s  *Server
	nc net.Conn

	handshook atomic.Bool

	// highC 控制帧队列（已帧化字节 + 订阅确认的门闩标记）。元素结构见 highItem。
	highC chan highItem
	sub   *facade.Subscriber // 事件订阅（nil = 未订阅）
	subMu sync.Mutex
	// subConfirm 订阅确认在途门闩（B3，r2 新-1 复检暂存 + r3 低-2 按 corr 标记
	// 而非裸 bool——两次订阅在途互不误清，writer 只清 rsp 帧携带的 corr）。
	subConfirm map[uint64]bool
	// heldFrames 门闩置位期间从 evC 取出的事件帧（复检暂存——已武装的阻塞
	// receive 无法撤销，只能在取后复检；清位后按序补写）。
	heldFrames [][]byte

	streams    map[uint32]*stream
	streamsMu  sync.Mutex
	nextStream uint32
	// streamsClosed 连接收工置位（streamsMu 保护）：stream.open 拨号窗口内连接关闭时，
	// 注册前拦下——晚注册的流不在 close 的 teardown 清单里，会成孤儿（pump 永挂、
	// 工位配额不回落）。
	streamsClosed bool

	// reqC 每连接请求队列（L2，4a §5.1）+ inflight 在途计数（含工位执行中与
	// stream.open 拨号执行体——统一计数口径：队列 + 工位 + 拨号各占一计）。
	// dispatcher = 固定请求工位（1 个分发 goroutine，工位内串行只限无长阻塞
	// 操作——30s 级 stream.open 拨号经 runStreamOpen 走独立执行体，不占工位
	// 串行位）。在途超界（> maxInflight）→ goodbye(overrun) 断连。
	reqC     chan RequestBody
	inflight atomic.Int32

	wakeC  chan struct{} // 有流数据待写（唤醒 writer 轮询）
	closed chan struct{}
	once   sync.Once
}

// highItem highC 的元素：控制帧字节；subConfirm 非 0 = 该帧是订阅确认 rsp
// （成功或错误应答——corr 即门闩标记），writer **写出后**按 corr 清门闩（B3）。
type highItem struct {
	frame      []byte
	subConfirm uint64
}

func newConn(s *Server, nc net.Conn) *conn {
	return &conn{
		s:          s,
		nc:         nc,
		highC:      make(chan highItem, highQueue),
		subConfirm: make(map[uint64]bool),
		streams:    make(map[uint32]*stream),
		reqC:       make(chan RequestBody, maxInflight),
		wakeC:      make(chan struct{}, 1),
		closed:     make(chan struct{}),
	}
}

// run 连接主循环：writer 与请求工位（dispatcher）先起，reader 阻塞驱动（三者随
// close 退出）。
func (c *conn) run() {
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		c.writer()
	}()
	go c.dispatcher() // 请求工位（自终止：close 后经 closed 分支退出，不进 run 等待列）
	defer c.close("")
	c.reader()
	// reader 已退（EOF/IO 错误/对端直接关 socket——CLI 形态不发 goodbye）：立即收工
	// 唤醒 writer/dispatcher（close 关闭 closed + nc.Close），再等 writer 退出。若
	// 等到 `<-writerDone` 之后才走 defer 的 close，writer 会永远停在 step() 的
	// select 里等 closed——连接 goroutine 与 fd 全部泄漏（exec-r1 B1）。dispatcher
	// **不在等待列**：工位可能仍在执行在途请求（host.add 探测等有界慢操作），
	// close 后经 closed 分支自终止——不等它，免得 Server.Close 被一条慢请求绑架。
	c.close("")
	<-writerDone
}

// dispatcher 固定请求工位（L2，4a §5.1）：逐条从 reqC 取请求执行。工位内串行只
// 限无长阻塞操作——stream.open 的 30s 级拨号经 runStreamOpen 移交独立执行体
// （在途记账随工位原子转移，净恰 1 计——不因移交瞬时虚高导致边界假拒）。
func (c *conn) dispatcher() {
	for {
		select {
		case <-c.closed:
			return
		case req := <-c.reqC:
			c.dispatch(req)
		}
	}
}

// dispatch 工位执行一条请求。非 stream.open：在工位内联执行（完成后释放在途
// 计）；stream.open：整条移交拨号执行体（goroutine），工位立即空出——同连接的
// daemon.status/host.list/另一个 open 照常应答（r2 新-6：「有界在途 = 契约，
// 串行不是契约」）。
func (c *conn) dispatch(req RequestBody) {
	if req.Op == facade.OpStreamOpen {
		go c.runStreamOpen(req) // 在途计数随本调用原子转移（dispatch 不减、拨号收尾减）
		return
	}
	defer c.inflight.Add(-1)
	if c.s.shuttingDown() {
		c.reply(req.Corr, nil, errCode(facade.CodeShuttingDown))
		return
	}
	h := c.handlerFor(req.Op)
	if h == nil {
		// 未知操作名：稳定错误码、连接不中断（spec 场景「未知操作报稳定错误码」）。
		c.reply(req.Corr, nil, errCode(facade.CodeUnknownOp))
		return
	}
	h(req.Corr, req.Args)
}

// runStreamOpen stream.open 的独立但有界执行体（同样计入在途 32——「不无界
// spawn」的立目的不因拨号豁免而退化）：30s 级内联拨号（DialTerm）在这里发生，
// 不占工位串行位。
func (c *conn) runStreamOpen(req RequestBody) {
	defer c.inflight.Add(-1)
	if c.s.shuttingDown() {
		c.reply(req.Corr, nil, errCode(facade.CodeShuttingDown))
		return
	}
	c.opStreamOpen(req.Corr, req.Args)
}

// close 收工连接（幂等）。reason 非空时尽力先发 goodbye（服务端主动收工）：
// 入 highC 用**非阻塞**发送——队列满（前端不读的病态）时丢弃而非挂等（告别帧
// 本就是尽力语义，写停滞看门狗是对端不读的最终兜底）。此前这里走阻塞 sendHigh，
// 唯一逃生口 `<-c.closed` 又在本函数更后面才关：highC 满 + 一次帧级错误会让
// close 永久互等挂死、`Server.Close()`（daemon 收工路径）收不了尾（exec-r1 M1）。
func (c *conn) close(reason string) {
	c.once.Do(func() {
		if reason != "" {
			if f := encodeJSONFrame(OpGoodbye, GoodbyeBody{Reason: reason}); f != nil {
				select {
				case c.highC <- highItem{frame: f}:
				default: // 队列满：尽力语义，丢弃告别帧不挂等
				}
			}
		}
		waitHighDrained(c) // reload/goodbye 等在途告别帧的有界等待（空队列零等待）
		close(c.closed)
		_ = c.nc.Close()
		c.streamsMu.Lock()
		c.streamsClosed = true // 先置位再 teardown：拨号窗口内的并发注册在锁内被拦（FIX-02）
		for _, st := range c.streams {
			st.teardown() // 连接级断开：end 帧发不出，不发（与流级 gone 三者可区分）
		}
		c.streams = map[uint32]*stream{}
		c.streamsMu.Unlock()
		c.subMu.Lock()
		if c.sub != nil {
			c.s.cfg.Bus.Unsubscribe(c.sub)
			c.sub = nil
		}
		// 连接关闭兜底清位（B3）：rsp 写失败路径不单独清位（写失败必然走向连接
		// 收工，靠此处兜底）——门闩与暂存缓冲都是无消费面的纯状态，一并收尾。
		for corr := range c.subConfirm {
			delete(c.subConfirm, corr)
		}
		c.heldFrames = nil
		c.subMu.Unlock()
	})
}

// sendHigh 控制帧入 highC（阻塞有界：closed 退出——队列满且前端不读的病态由写
// 停滞看门狗兜底）。
func (c *conn) sendHigh(frame []byte) {
	if frame == nil {
		return
	}
	select {
	case c.highC <- highItem{frame: frame}:
	case <-c.closed:
	}
}

// sendConfirm 订阅确认 rsp 入 highC，携带门闩标记（B3：成功与错误应答一律经此
// ——错误 rsp 同样清位，否则订阅队列无人消费、灌满 512 后被总线
// terminateOverrun，一次 cursor_stale 被放大成 goodbye(overrun) 断连，r2 新-1）。
func (c *conn) sendConfirm(corr uint64, frame []byte) {
	if frame == nil {
		return // 序列化防御性失败（ResponseBody 为结构体，实际不可达）：连接收工兜底
	}
	select {
	case c.highC <- highItem{frame: frame, subConfirm: corr}:
	case <-c.closed:
	}
}

// encodeJSONFrame 帧化一个 JSON body 帧。body 为已序列化的 JSON 字节
// （json.RawMessage/[]byte）时**原样承载**——json.Marshal 对裸 []byte 会按
// base64 字符串编码，必须特判（帧内二次编码会让对端解出 base64 灰尘）。
func encodeJSONFrame(op byte, body any) []byte {
	switch b := body.(type) {
	case json.RawMessage:
		return EncodeFrame(op, b)
	case []byte:
		return EncodeFrame(op, b)
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil // 全部 body 为结构体字面量，序列化不会失败；防御性丢弃
	}
	return EncodeFrame(op, b)
}

// ---------- reader：读循环与分发 ----------

func (c *conn) reader() {
	for {
		head, err := ReadHeader(c.nc) // 按 op 选上限（流 DATA 256KiB / 控制类 1MiB）
		if err != nil {
			if errors.Is(err, ErrBadFrame) {
				c.fatal(facade.CodeBadFrame) // 长度超限（读 body 前拒绝）
			}
			return // IO 错误/EOF = 连接结束
		}
		body, err := ReadBody(c.nc, head)
		if err != nil {
			return // 半帧（声明了 body 却断流）= 连接结束
		}
		op := head.Op
		if !ValidOp(op) {
			c.fatal(facade.CodeBadFrame) // 非法 op（预留段/未知值）
			return
		}
		switch op {
		case OpHello:
			if c.handshook.Load() {
				return // 协议次序错乱：无词表值，裸断
			}
			if !c.handleHello(body) {
				return
			}
		case OpGoodbye:
			return // 前端礼貌告别：正常收工
		case OpReq:
			if !c.handshook.Load() {
				return
			}
			c.handleRequestFrame(body)
		case OpStreamData:
			if !c.handshook.Load() {
				return
			}
			c.handleStreamData(body)
		case OpWelcome, OpReload, OpRsp, OpEvt, OpResync, OpStreamEnd:
			return // 服务端方向的帧从前端来：次序错乱，裸断
		}
	}
}

// fatal 帧级/连接级协议错误：发 goodbye(<错误码>) 后断连（「回错误码」的载体 =
// goodbye 帧 reason 引用错误码表稳定字符串；spec「畸形帧被拒」场景）。
func (c *conn) fatal(code string) { c.close(code) }

// handleHello 握手：正常 → welcome；版本不匹配 → reload(proto_mismatch) 后关闭
// （锁步哲学：唯一协商位，无降级路径）。
func (c *conn) handleHello(body []byte) bool {
	var hello HelloBody
	if err := json.Unmarshal(body, &hello); err != nil {
		c.fatal(facade.CodeBadJSON)
		return false
	}
	if hello.Frontend.Kind == "" || hello.Frontend.Name == "" {
		c.fatal(facade.CodeBadRequest) // 前端标识缺失（握手无 rsp 通道）
		return false
	}
	if hello.ProtoVersion != ProtoVersion {
		c.s.cfg.Logf("control: 前端 %s/%s 协议版本 %d 不匹配（本端 %d）——reload",
			hello.Frontend.Kind, hello.Frontend.Name, hello.ProtoVersion, ProtoVersion)
		c.sendHigh(encodeJSONFrame(OpReload, ReloadBody{Reason: ReloadProtoMismatch}))
		c.close("")
		return false
	}
	c.sendHigh(encodeJSONFrame(OpWelcome, WelcomeBody{
		ServerVersion: c.s.cfg.ServerVersion,
		Generation:    c.s.Generation(),
		ServerSeq:     c.s.cfg.Bus.CurrentSeq(),
	}))
	c.handshook.Store(true)
	c.s.cfg.Logf("control: 前端已接入（%s/%s %s）", hello.Frontend.Kind, hello.Frontend.Name, hello.Frontend.Version)
	return true
}

// ---------- 请求/响应与错误码映射 ----------

// opError 操作错误（code = 错误码表稳定字符串）。
// opError 码 + 可行动归因（FIX-50：detail 随行走 wire，CLI 不必吞成 bad_request
// 或自己再猜一次原因）。
type opError struct {
	code   string
	detail string
}

func (e *opError) Error() string {
	if e.detail != "" {
		return e.code + ": " + e.detail
	}
	return e.code
}

func errCode(code string) error { return &opError{code: code} }

// opErrf 带归因的码错误（映射层用：把 facade 层的可行动文案带给 CLI）。
func opErrf(code, format string, args ...any) error {
	return &opError{code: code, detail: fmt.Sprintf(format, args...)}
}

// handleRequestFrame 解请求帧：控制类 body 非法 JSON → bad_json 断连；合法 →
// 入每连接有界请求队列（非阻塞；慢操作不阻塞读循环——spec「三类流量同连接
// 交错」）。在途（含工位执行中）超 maxInflight = 前端失控流水线 →
// goodbye(overrun) 断连（L2，4a §5.1）。
func (c *conn) handleRequestFrame(body []byte) {
	var req RequestBody
	if err := json.Unmarshal(body, &req); err != nil {
		c.fatal(facade.CodeBadJSON)
		return
	}
	if c.inflight.Add(1) > maxInflight {
		c.inflight.Add(-1)
		c.fatal(GoodbyeOverrun) // 请求面 overrun：告别帧经 highC 由 writer 串行写出（无并发写竞态）
		return
	}
	select {
	case c.reqC <- req:
	case <-c.closed:
		c.inflight.Add(-1)
		return
	default:
		// 防御性：计数已界 32、队列容量 32，不应触达（触达 = 计数/容量漂移，按
		// overrun 断连自保）。
		c.inflight.Add(-1)
		c.fatal(GoodbyeOverrun)
	}
}

// reply 帧化响应（corr 关联回送；err 非 nil 时为错误码）。
func (c *conn) reply(corr uint64, result any, err error) {
	rsp := ResponseBody{Corr: corr}
	if err != nil {
		var oe *opError
		if errors.As(err, &oe) {
			rsp.Error = oe.code
			rsp.Detail = oe.detail // FIX-50：可行动归因随行（码窄、detail 自由文本）
		} else {
			rsp.Error = facade.CodeBadRequest // 非映射错误统一落 bad_request（防御）
			rsp.Detail = errText(err)
		}
	} else {
		rsp.Ok = true
		if result != nil {
			b, merr := json.Marshal(result)
			if merr != nil {
				c.s.cfg.Logf("control: 序列化响应失败：%v", merr)
				rsp.Ok, rsp.Error = false, facade.CodeBadRequest
			} else {
				rsp.Result = b
			}
		}
	}
	c.sendHigh(encodeJSONFrame(OpRsp, rsp))
}

// replyConfirm 订阅确认应答（B3）：与 reply 同构，但帧经 sendConfirm 携带
// 门闩标记（corr）——writer 写出该 rsp 后按 corr 清位、按序补写回放与暂存
// （clearSubConfirm）。
func (c *conn) replyConfirm(corr uint64, result any, err error) {
	rsp := ResponseBody{Corr: corr}
	if err != nil {
		var oe *opError
		if errors.As(err, &oe) {
			rsp.Error = oe.code
			rsp.Detail = oe.detail
		} else {
			rsp.Error = facade.CodeBadRequest
			rsp.Detail = errText(err)
		}
	} else {
		rsp.Ok = true
		if result != nil {
			b, merr := json.Marshal(result)
			if merr != nil {
				c.s.cfg.Logf("control: 序列化响应失败：%v", merr)
				rsp.Ok, rsp.Error = false, facade.CodeBadRequest
			} else {
				rsp.Result = b
			}
		}
	}
	c.sendConfirm(corr, encodeJSONFrame(OpRsp, rsp))
}

// opHandler 操作处理函数（自带 corr 回复——订阅等需要自定义响应次序的操作）。
type opHandler func(corr uint64, args json.RawMessage)

// handlerFor 操作词表注册处（spec 初始集；后续各期新命令 MUST 先在归属表登记
// 再实现——「命令归属规则」）。归属：host.*/daemon.status/snapshot.get/events.*
// = 守护托管；stream.open(term) = 控制面转发；一次性直跑类命令不经过控制面。
func (c *conn) handlerFor(op string) opHandler {
	switch op {
	case facade.OpDaemonStatus:
		return c.opDaemonStatus
	case facade.OpHostAdd:
		return c.opHostAdd
	case facade.OpHostRemove:
		return c.opHostRemove
	case facade.OpHostList:
		return c.opHostList
	case facade.OpSnapshotGet:
		return c.opSnapshotGet
	case facade.OpEventsSubscribe:
		return c.opSubscribe
	case facade.OpEventsUnsubscribe:
		return c.opUnsubscribe
	case facade.OpStreamOpen:
		return c.opStreamOpen
	case facade.OpStreamClose:
		return c.opStreamClose
	// 承载面 9 op（3e，D6）：守护托管——语义全在宿主 Backend（facade.Carriers 镜像），
	// 本层只做载荷解析与错误码映射（值域外/冲突 = bad_request、无主机 = no_host——
	// 错误码零新增，spec 场景「三面新 op 复用既有错误码」锁死该映射）。
	case facade.OpForwardAdd:
		return c.opForwardAdd
	case facade.OpForwardRemove:
		return c.opForwardRemove
	case facade.OpForwardList:
		return c.opForwardList
	case facade.OpSocksOn:
		return c.opSocksOn
	case facade.OpSocksOff:
		return c.opSocksOff
	case facade.OpSocksStatus:
		return c.opSocksStatus
	case facade.OpSpeedtestStart:
		return c.opSpeedtestStart
	case facade.OpSpeedtestStatus:
		return c.opSpeedtestStatus
	case facade.OpSpeedtestCancel:
		return c.opSpeedtestCancel
	// serve/relay 角色管理 10 op（3f，role-management）：守护托管——语义在角色
	// 接口与 nodeconfig，本层只解析与回送；幂等语义在成功载荷呈现（错误码零新增，
	// spec 场景「serve/relay 启停幂等不借道错误码」）。
	case facade.OpServeStart:
		return c.opServeStart
	case facade.OpServeStop:
		return c.opServeStop
	case facade.OpServeRestart:
		return c.opServeRestart
	case facade.OpServeStatus:
		return c.opServeStatus
	case facade.OpServeToken:
		return c.opServeToken
	case facade.OpRelayStart:
		return c.opRelayStart
	case facade.OpRelayStop:
		return c.opRelayStop
	case facade.OpRelayRestart:
		return c.opRelayRestart
	case facade.OpRelayStatus:
		return c.opRelayStatus
	case facade.OpRelayToken:
		return c.opRelayToken
	}
	return nil
}

// parseArgs 载荷解析（字段缺失/类型不符/值域外 → bad_request，不断连）。
func parseArgs(args json.RawMessage, dst any) error {
	if len(args) == 0 {
		return nil // 无载荷操作（host.list / daemon.status / snapshot.get）
	}
	if err := json.Unmarshal(args, dst); err != nil {
		return errCode(facade.CodeBadRequest)
	}
	return nil
}

func (c *conn) opDaemonStatus(corr uint64, _ json.RawMessage) {
	// daemon.status 不受 not_ready 挡：版本/代际/角色面是骨架信息（注册表未挂
	// 时 hosts 面为空——CLI「守护进程未运行时报可行动错误」依赖骨架可应答）。
	c.reply(corr, DaemonStatusResult{
		ServerVersion: c.s.cfg.ServerVersion,
		Generation:    c.s.Generation(),
		Seq:           c.s.cfg.Bus.CurrentSeq(),
		Pid:           os.Getpid(),
		Roles:         c.s.cfg.Backend.RolesStatus(),
		Hosts:         c.s.cfg.Backend.HostStates(),
		Demand:        c.s.cfg.Backend.DemandStatus(),
	}, nil)
}

func (c *conn) opHostAdd(corr uint64, args json.RawMessage) {
	var a HostAddArgs
	if err := parseArgs(args, &a); err != nil {
		c.reply(corr, nil, err)
		return
	}
	if a.Token == "" {
		c.reply(corr, nil, errCode(facade.CodeBadRequest))
		return
	}
	if c.s.cfg.Backend.NotReady() {
		c.reply(corr, nil, errCode(facade.CodeNotReady))
		return
	}
	// 服务端验证路径（host-cli 3b，design D1/D3）：decode（bad_token）→ 探测
	//（≤3.5s，请求 goroutine 内——不阻塞同连接其它请求）→ 入表（host_exists）；
	// 全不可达且未带 force → host_unreachable（不入表、不断连）。
	res, err := c.s.cfg.Backend.AddHost(a.Name, a.Token, a.Force)
	switch {
	case errors.Is(err, ErrBackendHostExists):
		c.reply(corr, nil, errCode(facade.CodeHostExists))
	case errors.Is(err, ErrBackendBadToken):
		c.reply(corr, nil, errCode(facade.CodeBadToken))
	case errors.Is(err, ErrBackendHostUnreachable):
		c.reply(corr, nil, errCode(facade.CodeHostUnreachable))
	case err != nil:
		c.reply(corr, nil, errCode(facade.CodeBadRequest))
	default:
		c.reply(corr, res, nil)
	}
}

func (c *conn) opHostRemove(corr uint64, args json.RawMessage) {
	var a HostRemoveArgs
	if err := parseArgs(args, &a); err != nil {
		c.reply(corr, nil, err)
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
	if err := c.s.cfg.Backend.RemoveHost(a.Host); errors.Is(err, ErrBackendNoHost) {
		c.reply(corr, nil, errCode(facade.CodeNoHost))
	} else if err != nil {
		c.reply(corr, nil, errCode(facade.CodeBadRequest))
	} else {
		c.reply(corr, map[string]bool{"removed": true}, nil)
	}
}

func (c *conn) opHostList(corr uint64, _ json.RawMessage) {
	if c.s.cfg.Backend.NotReady() {
		c.reply(corr, nil, errCode(facade.CodeNotReady))
		return
	}
	c.reply(corr, HostListResult{Hosts: c.s.cfg.Backend.HostBriefs()}, nil)
}

// opSnapshotGet 快照（锁序三路径之②：**先读总线当前 seq、后读宿主快照**——FIX-03
// 修正实现次序。设计 A4 原文写「最后读 seq」，但其论证（「重放可能重复但无害」）恰好
// 只对 seq 先读成立：seq 后读的失败模式是「状态已迁、seq 未读」窗口内的事件 seq ≤
// 游标且不在快照里 ⇒ 既不回放也不含于快照 ⇒ 前端该行永久陈旧；seq 先读则该窗口内
// 事件 seq > 游标 ⇒ 必回放（可能重复，由同键幂等覆盖消化——at-least-once 口径）。）
func (c *conn) opSnapshotGet(corr uint64, _ json.RawMessage) {
	if c.s.cfg.Backend.NotReady() {
		c.reply(corr, nil, errCode(facade.CodeNotReady))
		return
	}
	seq := c.s.cfg.Bus.CurrentSeq() // 先取号（保「不漏」；重复允许，见上）
	hosts := c.s.cfg.Backend.HostStates()
	c.reply(corr, SnapshotResult{
		Seq:        seq,
		Generation: c.s.Generation(),
		Hosts:      hosts,
	}, nil)
}

// opSubscribe 订阅：游标检查（cursor_stale/bad_request）、幂等（同域重复订阅 =
// 成功，语义 = **替换**：该连接的订阅域集合整体换为新载荷的 domains——
// daemon-control-plane delta 3b 钉死，非并集；实现 = bus.Subscribe 的
// sub.domains = dm 整体赋值）、view 回显（**并且**自 facade 期起参与需求合成——
// 见 facade/demand.go ParseView；spec「门控信号词表」）。「确认 → 回放 → 在线」三段次序 =
// B3 订阅原子交付：回放拷入订阅者 pending 段在总线锁内原子完成（见
// facade.Bus.Subscribe），绑定侧以「订阅确认在途」门闩（复检暂存）保证——门闩
// 在 Bus.Subscribe **前**置位（注册后投递的在线事件被取到时门闩必已置位），
// 确认 rsp（成功或错误）写出且清位后，writer 先排空 pending 回放段、再补写
// 暂存缓冲、再恢复常规消费（clearSubConfirm）。
func (c *conn) opSubscribe(corr uint64, args json.RawMessage) {
	var a SubscribeArgs
	if err := parseArgs(args, &a); err != nil {
		c.reply(corr, nil, err)
		return
	}
	if a.Domains == nil {
		c.reply(corr, nil, errCode(facade.CodeBadRequest))
		return
	}
	c.subMu.Lock()
	defer c.subMu.Unlock()
	if c.sub == nil {
		c.sub = c.s.cfg.Bus.NewSubscriber()
	}
	// 门闩置位在 Bus.Subscribe 之前（B3 复检暂存的覆盖窗口从 Subscribe 前开始）。
	c.subConfirm[corr] = true
	if err := c.s.cfg.Bus.Subscribe(c.sub, a.Domains, a.Cursor, a.Generation, a.View); err != nil {
		// 错误应答同样清位（r2 新-1）——经 sendConfirm 携带 corr，writer 写出后清。
		switch {
		case errors.Is(err, facade.ErrCursorStale):
			c.replyConfirm(corr, nil, errCode(facade.CodeCursorStale))
		case errors.Is(err, facade.ErrCursorFuture):
			c.replyConfirm(corr, nil, errCode(facade.CodeBadRequest))
		default:
			c.replyConfirm(corr, nil, errCode(facade.CodeBadRequest)) // 词表外订阅域
		}
		return
	}
	c.replyConfirm(corr, SubscribeResult{
		Domains:    a.Domains, // 替换语义下生效集合恰 = 本次声明（回显即生效域集合，spec「重复订阅替换而非并集」）
		Cursor:     c.s.cfg.Bus.CurrentSeq(),
		View:       a.View, // 回显 + 参与需求合成（facade 期起；spec「门控信号词表」）
		Generation: c.s.Generation(),
	}, nil)
}

// opUnsubscribe 退订（未订阅域 = 幂等成功，无错误码——spec 错误码表）。
func (c *conn) opUnsubscribe(corr uint64, args json.RawMessage) {
	var a UnsubscribeArgs
	if err := parseArgs(args, &a); err != nil {
		c.reply(corr, nil, err)
		return
	}
	if a.Domains == nil {
		c.reply(corr, nil, errCode(facade.CodeBadRequest))
		return
	}
	c.subMu.Lock()
	defer c.subMu.Unlock()
	if c.sub != nil {
		// 域增删收敛在总线锁内（facade.Bus.UnsubscribeDomains）——订阅态的写半边不得
		// 留在 server 侧裸改（exec-r1 H1 的竞态源）。
		c.s.cfg.Bus.UnsubscribeDomains(c.sub, a.Domains)
	}
	c.reply(corr, UnsubscribeResult{Domains: a.Domains}, nil)
}

// ---------- 承载面 op（3e，D6）：forward / socks / speedtest ----------

// mapCarrierErr 承载面错误的统一映射：无主机 = no_host，其余（值域外/冲突/监听
// 失败/落盘失败）= bad_request——错误码零新增。
func mapCarrierErr(err error) error {
	if err == nil {
		return nil
	}
	code := facade.CodeBadRequest
	if errors.Is(err, ErrBackendNoHost) {
		code = facade.CodeNoHost
	}
	// FIX-50：底层可行动归因随行（「端口 1080 已被 xx 的 socks 监听占用」这类原文
	// 不再被吞成 bad_request 三个字——CLI 侧据此直接给结论，不必再自建「现场诊断」）。
	return &opError{code: code, detail: err.Error()}
}

func (c *conn) opForwardAdd(corr uint64, args json.RawMessage) {
	var a ForwardAddArgs
	if err := parseArgs(args, &a); err != nil {
		c.reply(corr, nil, err)
		return
	}
	if a.Host == "" || a.Listen == 0 {
		c.reply(corr, nil, errCode(facade.CodeBadRequest))
		return
	}
	if c.s.cfg.Backend.NotReady() {
		c.reply(corr, nil, errCode(facade.CodeNotReady))
		return
	}
	res, err := c.s.cfg.Backend.ForwardAdd(a)
	c.reply(corr, res, mapCarrierErr(err))
}

func (c *conn) opForwardRemove(corr uint64, args json.RawMessage) {
	var a ForwardRemoveArgs
	if err := parseArgs(args, &a); err != nil {
		c.reply(corr, nil, err)
		return
	}
	if a.Host == "" || a.Listen == 0 {
		c.reply(corr, nil, errCode(facade.CodeBadRequest))
		return
	}
	if c.s.cfg.Backend.NotReady() {
		c.reply(corr, nil, errCode(facade.CodeNotReady))
		return
	}
	err := c.s.cfg.Backend.ForwardRemove(a)
	if err != nil {
		c.reply(corr, nil, mapCarrierErr(err))
		return
	}
	c.reply(corr, ForwardRemoveResult{Removed: true}, nil)
}

func (c *conn) opForwardList(corr uint64, args json.RawMessage) {
	var a ForwardListArgs
	if err := parseArgs(args, &a); err != nil {
		c.reply(corr, nil, err)
		return
	}
	if c.s.cfg.Backend.NotReady() {
		c.reply(corr, nil, errCode(facade.CodeNotReady))
		return
	}
	c.reply(corr, c.s.cfg.Backend.ForwardList(a.Host), nil)
}

func (c *conn) opSocksOn(corr uint64, args json.RawMessage) {
	var a SocksOnArgs
	if err := parseArgs(args, &a); err != nil {
		c.reply(corr, nil, err)
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
	res, err := c.s.cfg.Backend.SocksOn(a.Host, a.Listen)
	c.reply(corr, res, mapCarrierErr(err))
}

func (c *conn) opSocksOff(corr uint64, args json.RawMessage) {
	var a SocksOffArgs
	if err := parseArgs(args, &a); err != nil {
		c.reply(corr, nil, err)
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
	res, err := c.s.cfg.Backend.SocksOff(a.Host)
	c.reply(corr, res, mapCarrierErr(err))
}

func (c *conn) opSocksStatus(corr uint64, _ json.RawMessage) {
	if c.s.cfg.Backend.NotReady() {
		c.reply(corr, nil, errCode(facade.CodeNotReady))
		return
	}
	c.reply(corr, c.s.cfg.Backend.SocksStatus(), nil)
}

func (c *conn) opSpeedtestStart(corr uint64, args json.RawMessage) {
	var a SpeedtestStartArgs
	if err := parseArgs(args, &a); err != nil {
		c.reply(corr, nil, err)
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
	// busy 是成功载荷里的 reason（同手机信封形态），不进错误码表。
	ack, err := c.s.cfg.Backend.SpeedtestStart(a)
	if err != nil {
		c.reply(corr, nil, mapCarrierErr(err))
		return
	}
	c.reply(corr, ack, nil)
}

func (c *conn) opSpeedtestStatus(corr uint64, args json.RawMessage) {
	var a SpeedtestStatusArgs
	if err := parseArgs(args, &a); err != nil {
		c.reply(corr, nil, err)
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
	res, err := c.s.cfg.Backend.SpeedtestStatus(a.Host)
	if err != nil {
		c.reply(corr, nil, mapCarrierErr(err))
		return
	}
	c.reply(corr, res, nil)
}

func (c *conn) opSpeedtestCancel(corr uint64, args json.RawMessage) {
	var a SpeedtestCancelArgs
	if err := parseArgs(args, &a); err != nil {
		c.reply(corr, nil, err)
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
	if err := c.s.cfg.Backend.SpeedtestCancel(a.Host); err != nil {
		c.reply(corr, nil, mapCarrierErr(err))
		return
	}
	c.reply(corr, SpeedtestCancelResult{Cancelled: true}, nil)
}

// ---------- serve/relay 角色管理 op（3f，role-management） ----------
//
// 全部无载荷（{}）；不受 not_ready 挡（角色管理是进程层面，与 client 注册表
// 就绪无关——同 daemon.status 口径）。restart 无重建对象 = 宿主哨兵
// ErrBackendRoleStopped → bad_request（CLI 预检兜住，wire 理论不可达——错误码
// 零新增，幂等语义不借道错误码）。

func mapRoleErr(err error) error {
	if err == nil {
		return nil
	}
	// ErrBackendRoleStopped（restart 无对象）与其余宿主错误统一落 bad_request——
	// 错误码零新增；幂等语义不借道错误码（在成功载荷呈现）。
	return errCode(facade.CodeBadRequest)
}

func (c *conn) opServeStart(corr uint64, _ json.RawMessage) {
	res, err := c.s.cfg.Backend.ServeStart()
	c.reply(corr, res, mapRoleErr(err))
}

func (c *conn) opServeStop(corr uint64, _ json.RawMessage) {
	res, err := c.s.cfg.Backend.ServeStop()
	c.reply(corr, res, mapRoleErr(err))
}

func (c *conn) opServeRestart(corr uint64, _ json.RawMessage) {
	res, err := c.s.cfg.Backend.ServeRestart()
	c.reply(corr, res, mapRoleErr(err))
}

func (c *conn) opServeStatus(corr uint64, _ json.RawMessage) {
	c.reply(corr, c.s.cfg.Backend.ServeStatus(), nil)
}

func (c *conn) opServeToken(corr uint64, _ json.RawMessage) {
	res, err := c.s.cfg.Backend.ServeToken()
	c.reply(corr, res, mapRoleErr(err))
}

func (c *conn) opRelayStart(corr uint64, _ json.RawMessage) {
	res, err := c.s.cfg.Backend.RelayStart()
	c.reply(corr, res, mapRoleErr(err))
}

func (c *conn) opRelayStop(corr uint64, _ json.RawMessage) {
	res, err := c.s.cfg.Backend.RelayStop()
	c.reply(corr, res, mapRoleErr(err))
}

func (c *conn) opRelayRestart(corr uint64, _ json.RawMessage) {
	res, err := c.s.cfg.Backend.RelayRestart()
	c.reply(corr, res, mapRoleErr(err))
}

func (c *conn) opRelayStatus(corr uint64, _ json.RawMessage) {
	c.reply(corr, c.s.cfg.Backend.RelayStatus(), nil)
}

func (c *conn) opRelayToken(corr uint64, _ json.RawMessage) {
	res, err := c.s.cfg.Backend.RelayToken()
	c.reply(corr, res, mapRoleErr(err))
}

// ---------- writer：唯一 socket 写者（优先级排空） ----------

func (c *conn) writer() {
	for {
		if !c.drainHigh() { // ① 控制（最高；订阅确认帧写出后清门闩+按序补写）
			return
		}
		if !c.step() { // ② 一条事件或一条流数据（交替防饿死）→ 回循环头
			return
		}
	}
}

// waitHighDrained 等 writer 把 highC 取尽（告别帧送出的有界等待）。
func waitHighDrained(c *conn) {
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(c.highC) == 0 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond) // 取走→写出的微窗口
}

func (c *conn) drainHigh() bool {
	for {
		select {
		case item := <-c.highC:
			if !c.writeHighItem(item) {
				return false
			}
		default:
			return true
		}
	}
}

// writeHighItem 写一条控制帧；订阅确认帧（subConfirm != 0）写出后按 corr 清门闩
// （B3）：最后一个门闩清位 = 先排空 pending 回放段、再补写暂存缓冲、再恢复常规
// 消费——「确认 → 回放 → 在线」三段次序的绑定侧落点（r3 低-1）。
func (c *conn) writeHighItem(item highItem) bool {
	if !c.writeFrame(item.frame) {
		return false
	}
	if item.subConfirm == 0 {
		return true
	}
	return c.clearSubConfirm(item.subConfirm)
}

// step 消费一条在线事件或一条流数据；无消费来源时阻塞等待（wakeC 唤醒后重扫
// 流集合）。false = 连接收工。
func (c *conn) step() bool {
	c.subMu.Lock()
	var evC <-chan facade.Event
	var doneC <-chan struct{}
	if c.sub != nil {
		evC, doneC = c.sub.Events(), c.sub.Done()
	}
	c.subMu.Unlock()

	// 事件非阻塞一条（在流轮询前——事件是慢流 MUST NOT 阻塞的另一类）。取到后
	// 复检门闩（B3 复检暂存——见 takeEvent）。
	if evC != nil {
		select {
		case ev := <-evC:
			return c.takeEvent(ev)
		default:
		}
	}
	// 流公平轮询一条。
	for _, st := range c.streamSnapshot() {
		select {
		case it := <-st.dataC:
			return c.writeStreamItem(st, it)
		default:
		}
	}
	// 阻塞等待任一来源（动态流集合经 wakeC 唤醒重扫）。
	if evC != nil {
		select {
		case ev := <-evC:
			return c.takeEvent(ev)
		case <-doneC:
			// 订阅 overrun（bus 停投）：goodbye(overrun) 断连（spec「慢消费者被
			// 断连重同步」——不静默丢事件）。
			c.fatalFromWriter(GoodbyeOverrun)
			return false
		case item := <-c.highC:
			return c.writeHighItem(item)
		case <-c.wakeC:
			return true
		case <-c.closed:
			return false
		}
	}
	select {
	case item := <-c.highC:
		return c.writeHighItem(item)
	case <-c.wakeC:
		return true
	case <-c.closed:
		return false
	}
}

// takeEvent B3 复检暂存（r2 新-1 / r3 低-1）：writer 从 evC 取到事件后**复检**
// 订阅确认门闩——置位期间 writer 唯一写出源 = highC，evC 事件仍会被取出（已武装
// 的阻塞 receive 无法撤销——标志位对「下一次进 select」生效，已停在 select 里的
// writer 只能靠取后复检覆盖），取出即复检-暂存、不写出；pending 回放段与流数据
// 在门闩期同样不写出（drainHigh 之外无写出路径）。清位后由 clearSubConfirm 按
// 「pending 回放段 → 暂存缓冲」次序补写。
func (c *conn) takeEvent(ev facade.Event) bool {
	f := encodeJSONFrame(OpEvt, EventBody{Seq: ev.Seq, Domain: ev.Domain, Kind: ev.Kind, Payload: ev.Payload})
	c.subMu.Lock()
	if len(c.subConfirm) > 0 {
		c.heldFrames = append(c.heldFrames, f)
		c.subMu.Unlock()
		return true // 门闩置位：暂存不写出，回循环头（highC 仍是唯一消费源）
	}
	c.subMu.Unlock()
	return c.writeFrame(f)
}

// clearSubConfirm 清订阅确认门闩（按 corr 匹配——r3 低-2：两次订阅在途互不
// 误清）。最后一个门闩清位后：锁内原子取走 pending 回放段与暂存缓冲，锁外按序
// 写出——先排空 pending 回放段、再补写暂存缓冲、再恢复常规消费。
func (c *conn) clearSubConfirm(corr uint64) bool {
	c.subMu.Lock()
	delete(c.subConfirm, corr)
	var out [][]byte
	if len(c.subConfirm) == 0 {
		if c.sub != nil {
			for _, ev := range c.sub.DrainPending() {
				out = append(out, encodeJSONFrame(OpEvt, EventBody{Seq: ev.Seq, Domain: ev.Domain, Kind: ev.Kind, Payload: ev.Payload}))
			}
		}
		out = append(out, c.heldFrames...)
		c.heldFrames = nil
	}
	c.subMu.Unlock()
	for _, f := range out {
		if !c.writeFrame(f) {
			return false
		}
	}
	return true
}

// streamSnapshot 流集合快照（轮询用）。
func (c *conn) streamSnapshot() []*stream {
	c.streamsMu.Lock()
	defer c.streamsMu.Unlock()
	out := make([]*stream, 0, len(c.streams))
	for _, st := range c.streams {
		out = append(out, st)
	}
	return out
}

// fatalFromWriter writer 侧致命路径（overrun 等：告别帧同步写出后断连——此时
// 走 highC 已无意义，直接写 socket）。
func (c *conn) fatalFromWriter(reason string) {
	_ = c.nc.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if f := encodeJSONFrame(OpGoodbye, GoodbyeBody{Reason: reason}); f != nil {
		_, _ = c.nc.Write(f)
	}
	c.close("")
}

// writeFrame 写一帧（写停滞看门狗：前端整体不读时最终断连，不无限积压）。
func (c *conn) writeFrame(f []byte) bool {
	_ = c.nc.SetWriteDeadline(time.Now().Add(writeStallTimeout))
	if _, err := c.nc.Write(f); err != nil {
		c.close("")
		return false
	}
	return true
}

// writeStreamItem 写一条流 item（data 或 end 标记——end 与该流数据同队列 FIFO：
// 「end 之前的数据先送达、end 之后绝无该流数据」，spec「流关闭先给结束信号」）。
func (c *conn) writeStreamItem(st *stream, it streamItem) bool {
	if it.end != "" {
		if !c.writeFrame(encodeJSONFrame(OpStreamEnd, StreamEndBody{StreamID: st.id, Reason: it.end})) {
			return false
		}
		c.streamsMu.Lock()
		delete(c.streams, st.id)
		c.streamsMu.Unlock()
		return true
	}
	return c.writeFrame(EncodeFrame(OpStreamData, EncodeStreamBody(st.id, it.data)))
}

// errText 错误原文（detail 字段用；nil 空串）。
func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
