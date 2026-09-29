package control

// server.go — 控制面服务器（§3.2/§3.3）：握手与代际、请求/响应与错误码映射、
// 事件推送泵；流式通道见 stream.go；socket 监听与权限见 listen.go。
//
// 连接模型：一连接两 goroutine（reader 分发 / writer 唯一写 socket）+ 每请求一个
// handler goroutine（慢操作如 stream.open 的隧道拨号不阻塞读循环）+ 每流两个泵
//（backend→前端 / 前端→backend，见 stream.go）。writer 的输入按优先级排空：
//
//	highC（welcome/rsp/goodbye/reload 等控制类）> replayC（订阅回放批）
//	> 事件（bus 订阅者 channel）> 各流 dataC（公平轮询）
//
// 这保证慢流积压、订阅回放大批都不阻塞控制帧（spec「慢流不拖垮控制面」/「三类
// 流量同连接交错」）。前端整体不读的病态由写停滞看门狗兜底（SetWriteDeadline
// 超时断连）——订阅了事件的前端通常更早触发 overrun 断连（goodbye(overrun)）。
//
// 协议次序错乱（握手前非 hello、握手后再 hello、前端方向出现 welcome/rsp/evt 等
// 服务端帧）= 无词表值的连接级硬错误：直接关闭连接、不发帧（词表纪律：不发明
// spec 外的 reason 值）。

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"sync/atomic"
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
)

// Server 控制面服务器。
type Server struct {
	cfg   ServerConfig
	ln    net.Listener
	mu    sync.Mutex
	conns map[*conn]struct{}
	clos  atomic.Bool
	wg    sync.WaitGroup
}

// ServerConfig 服务器装配项。
type ServerConfig struct {
	ServerVersion string
	Bus           *Bus
	Backend       Backend
	Logf          func(format string, args ...any) // nil = 丢弃
	MaxStreams    int                              // <=0 = DefaultMaxStreams
}

// NewServer 建服务器（代际 = Bus 的 generation）。
func NewServer(cfg ServerConfig) *Server {
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.MaxStreams <= 0 {
		cfg.MaxStreams = DefaultMaxStreams
	}
	return &Server{cfg: cfg, conns: make(map[*conn]struct{})}
}

// Generation 当前代际。
func (s *Server) Generation() string { return s.cfg.Bus.Generation() }

// NewGeneration 生成新代际（16 字节随机 hex——每次守护进程启动调用一次，
// Bus 与 Server 共用同一值）。
func NewGeneration() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand 在真实平台不会失败；退化用时间熵兜底（仅可测性路径）。
		now := time.Now().UnixNano()
		for i := range b {
			b[i] = byte(now >> (uint(i%8) * 8))
		}
	}
	return hex.EncodeToString(b[:])
}

// Serve 接入循环（阻塞；listener 由 listen.go 提供，Close 后返回）。
func (s *Server) Serve(ln net.Listener) error {
	s.ln = ln
	for {
		nc, err := ln.Accept()
		if err != nil {
			if s.clos.Load() {
				return nil
			}
			return err
		}
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

// Close 收工：停接入、断开全部连接（在途请求由 shutting_down 错误码路径承接；
// goodbye(shutting_down) 对还写得出的连接尽力送达）。
func (s *Server) Close() {
	s.clos.Store(true)
	if s.ln != nil {
		_ = s.ln.Close()
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

	highC   chan []byte   // 控制帧（已帧化字节）
	replayC chan [][]byte // 订阅回放批（已帧化字节，按序）
	sub     *Subscriber   // 事件订阅（nil = 未订阅）
	subMu   sync.Mutex

	streams    map[uint32]*stream
	streamsMu  sync.Mutex
	nextStream uint32

	wakeC  chan struct{} // 有流数据待写（唤醒 writer 轮询）
	closed chan struct{}
	once   sync.Once
}

func newConn(s *Server, nc net.Conn) *conn {
	return &conn{
		s:       s,
		nc:      nc,
		highC:   make(chan []byte, highQueue),
		replayC: make(chan [][]byte, 2),
		streams: make(map[uint32]*stream),
		wakeC:   make(chan struct{}, 1),
		closed:  make(chan struct{}),
	}
}

// run 连接主循环：writer 先起，reader 阻塞驱动（两者随 close 退出）。
func (c *conn) run() {
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		c.writer()
	}()
	defer c.close("")
	c.reader()
	// reader 已退（EOF/IO 错误/对端直接关 socket——CLI 形态不发 goodbye）：立即收工
	// 唤醒 writer（close 关闭 closed + nc.Close），再等 writer 退出。若等到
	// `<-writerDone` 之后才走 defer 的 close，writer 会永远停在 step() 的 select
	// 里等 closed——连接 goroutine 与 fd 全部泄漏（exec-r1 B1）。
	c.close("")
	<-writerDone
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
				case c.highC <- f:
				default: // 队列满：尽力语义，丢弃告别帧不挂等
				}
			}
		}
		waitHighDrained(c) // reload/goodbye 等在途告别帧的有界等待（空队列零等待）
		close(c.closed)
		_ = c.nc.Close()
		c.streamsMu.Lock()
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
	case c.highC <- frame:
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
				c.fatal(CodeBadFrame) // 长度超限（读 body 前拒绝）
			}
			return // IO 错误/EOF = 连接结束
		}
		body, err := ReadBody(c.nc, head)
		if err != nil {
			return // 半帧（声明了 body 却断流）= 连接结束
		}
		op := head.Op
		if !ValidOp(op) {
			c.fatal(CodeBadFrame) // 非法 op（预留段/未知值）
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
		c.fatal(CodeBadJSON)
		return false
	}
	if hello.Frontend.Kind == "" || hello.Frontend.Name == "" {
		c.fatal(CodeBadRequest) // 前端标识缺失（握手无 rsp 通道）
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
type opError struct{ code string }

func (e *opError) Error() string { return e.code }

func errCode(code string) error { return &opError{code: code} }

// handleRequestFrame 解请求帧：控制类 body 非法 JSON → bad_json 断连；合法 →
// 异步分发（慢操作不阻塞读循环——spec「三类流量同连接交错」）。
func (c *conn) handleRequestFrame(body []byte) {
	var req RequestBody
	if err := json.Unmarshal(body, &req); err != nil {
		c.fatal(CodeBadJSON)
		return
	}
	go func() {
		if c.s.shuttingDown() {
			c.reply(req.Corr, nil, errCode(CodeShuttingDown))
			return
		}
		h := c.handlerFor(req.Op)
		if h == nil {
			// 未知操作名：稳定错误码、连接不中断（spec 场景「未知操作报稳定错误码」）。
			c.reply(req.Corr, nil, errCode(CodeUnknownOp))
			return
		}
		h(req.Corr, req.Args)
	}()
}

// reply 帧化响应（corr 关联回送；err 非 nil 时为错误码）。
func (c *conn) reply(corr uint64, result any, err error) {
	rsp := ResponseBody{Corr: corr}
	if err != nil {
		var oe *opError
		if errors.As(err, &oe) {
			rsp.Error = oe.code
		} else {
			rsp.Error = CodeBadRequest // 非映射错误统一落 bad_request（防御）
		}
	} else {
		rsp.Ok = true
		if result != nil {
			b, merr := json.Marshal(result)
			if merr != nil {
				c.s.cfg.Logf("control: 序列化响应失败：%v", merr)
				rsp.Ok, rsp.Error = false, CodeBadRequest
			} else {
				rsp.Result = b
			}
		}
	}
	c.sendHigh(encodeJSONFrame(OpRsp, rsp))
}

// opHandler 操作处理函数（自带 corr 回复——订阅等需要自定义响应次序的操作）。
type opHandler func(corr uint64, args json.RawMessage)

// handlerFor 操作词表注册处（spec 初始集；后续各期新命令 MUST 先在归属表登记
// 再实现——「命令归属规则」）。归属：host.*/daemon.status/snapshot.get/events.*
// = 守护托管；stream.open(term) = 控制面转发；一次性直跑类命令不经过控制面。
func (c *conn) handlerFor(op string) opHandler {
	switch op {
	case OpDaemonStatus:
		return c.opDaemonStatus
	case OpHostAdd:
		return c.opHostAdd
	case OpHostRemove:
		return c.opHostRemove
	case OpHostList:
		return c.opHostList
	case OpSnapshotGet:
		return c.opSnapshotGet
	case OpEventsSubscribe:
		return c.opSubscribe
	case OpEventsUnsubscribe:
		return c.opUnsubscribe
	case OpStreamOpen:
		return c.opStreamOpen
	case OpStreamClose:
		return c.opStreamClose
	}
	return nil
}

// parseArgs 载荷解析（字段缺失/类型不符/值域外 → bad_request，不断连）。
func parseArgs(args json.RawMessage, dst any) error {
	if len(args) == 0 {
		return nil // 无载荷操作（host.list / daemon.status / snapshot.get）
	}
	if err := json.Unmarshal(args, dst); err != nil {
		return errCode(CodeBadRequest)
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
		Roles:         c.s.cfg.Backend.RolesStatus(),
		Hosts:         c.s.cfg.Backend.HostStates(),
	}, nil)
}

func (c *conn) opHostAdd(corr uint64, args json.RawMessage) {
	var a HostAddArgs
	if err := parseArgs(args, &a); err != nil {
		c.reply(corr, nil, err)
		return
	}
	if a.Token == "" {
		c.reply(corr, nil, errCode(CodeBadRequest))
		return
	}
	if c.s.cfg.Backend.NotReady() {
		c.reply(corr, nil, errCode(CodeNotReady))
		return
	}
	brief, err := c.s.cfg.Backend.AddHost(a.Name, a.Token)
	switch {
	case errors.Is(err, ErrBackendHostExists):
		c.reply(corr, nil, errCode(CodeHostExists))
	case errors.Is(err, ErrBackendBadToken):
		c.reply(corr, nil, errCode(CodeBadToken))
	case err != nil:
		c.reply(corr, nil, errCode(CodeBadRequest))
	default:
		c.reply(corr, brief, nil)
	}
}

func (c *conn) opHostRemove(corr uint64, args json.RawMessage) {
	var a HostRemoveArgs
	if err := parseArgs(args, &a); err != nil {
		c.reply(corr, nil, err)
		return
	}
	if a.Host == "" {
		c.reply(corr, nil, errCode(CodeBadRequest))
		return
	}
	if c.s.cfg.Backend.NotReady() {
		c.reply(corr, nil, errCode(CodeNotReady))
		return
	}
	if err := c.s.cfg.Backend.RemoveHost(a.Host); errors.Is(err, ErrBackendNoHost) {
		c.reply(corr, nil, errCode(CodeNoHost))
	} else if err != nil {
		c.reply(corr, nil, errCode(CodeBadRequest))
	} else {
		c.reply(corr, map[string]bool{"removed": true}, nil)
	}
}

func (c *conn) opHostList(corr uint64, _ json.RawMessage) {
	if c.s.cfg.Backend.NotReady() {
		c.reply(corr, nil, errCode(CodeNotReady))
		return
	}
	c.reply(corr, HostListResult{Hosts: c.s.cfg.Backend.HostBriefs()}, nil)
}

// opSnapshotGet 快照（锁序三路径之②：先宿主快照（Registry.mu 拷贝会话集合 →
// 各会话无锁快照），**最后**读总线当前 seq 作为快照序号——设计 A4）。
func (c *conn) opSnapshotGet(corr uint64, _ json.RawMessage) {
	if c.s.cfg.Backend.NotReady() {
		c.reply(corr, nil, errCode(CodeNotReady))
		return
	}
	hosts := c.s.cfg.Backend.HostStates()
	c.reply(corr, SnapshotResult{
		Seq:        c.s.cfg.Bus.CurrentSeq(),
		Generation: c.s.Generation(),
		Hosts:      hosts,
	}, nil)
}

// opSubscribe 订阅：游标检查（cursor_stale/bad_request）、幂等（同域重复订阅 =
// 成功并集）、view 回显；确认 rsp 先于回放批（writer 优先级），回放先于在线
// 事件（seq 次序——锁内原子拷贝+注册，见 bus.Subscribe）。
func (c *conn) opSubscribe(corr uint64, args json.RawMessage) {
	var a SubscribeArgs
	if err := parseArgs(args, &a); err != nil {
		c.reply(corr, nil, err)
		return
	}
	if a.Domains == nil {
		c.reply(corr, nil, errCode(CodeBadRequest))
		return
	}
	c.subMu.Lock()
	defer c.subMu.Unlock()
	if c.sub == nil {
		c.sub = c.s.cfg.Bus.NewSubscriber()
	}
	replay, err := c.s.cfg.Bus.Subscribe(c.sub, a.Domains, a.Cursor, a.Generation)
	if err != nil {
		switch {
		case errors.Is(err, ErrCursorStale):
			c.reply(corr, nil, errCode(CodeCursorStale))
		case errors.Is(err, ErrCursorFuture):
			c.reply(corr, nil, errCode(CodeBadRequest))
		default:
			c.reply(corr, nil, errCode(CodeBadRequest)) // 词表外订阅域
		}
		return
	}
	c.reply(corr, SubscribeResult{
		Domains:    a.Domains, // 幂等语义下回显本次声明（生效集合为其并集）
		Cursor:     c.s.cfg.Bus.CurrentSeq(),
		View:       a.View, // 只回显（spec：不参与需求判定——信号源归 facade 期）
		Generation: c.s.Generation(),
	}, nil)
	if len(replay) > 0 {
		batch := make([][]byte, 0, len(replay))
		for _, ev := range replay {
			batch = append(batch, encodeJSONFrame(OpEvt, EventBody{Seq: ev.Seq, Domain: ev.Domain, Kind: ev.Kind, Payload: ev.Payload}))
		}
		select {
		case c.replayC <- batch:
		case <-c.closed:
		}
	}
}

// opUnsubscribe 退订（未订阅域 = 幂等成功，无错误码——spec 错误码表）。
func (c *conn) opUnsubscribe(corr uint64, args json.RawMessage) {
	var a UnsubscribeArgs
	if err := parseArgs(args, &a); err != nil {
		c.reply(corr, nil, err)
		return
	}
	if a.Domains == nil {
		c.reply(corr, nil, errCode(CodeBadRequest))
		return
	}
	c.subMu.Lock()
	defer c.subMu.Unlock()
	if c.sub != nil {
		// 域增删收敛在总线锁内（Bus.UnsubscribeDomains）——订阅态的写半边不得
		// 留在 server 侧裸改（exec-r1 H1 的竞态源）。
		c.s.cfg.Bus.UnsubscribeDomains(c.sub, a.Domains)
	}
	c.reply(corr, UnsubscribeResult{Domains: a.Domains}, nil)
}

// ---------- writer：唯一 socket 写者（优先级排空） ----------

func (c *conn) writer() {
	for {
		if !c.drainHigh() { // ① 控制（最高）
			return
		}
		if !c.drainReplay() { // ② 订阅回放（先于在线事件）
			return
		}
		if !c.step() { // ③ 一条事件或一条流数据（交替防饿死）→ 回循环头
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
		case f := <-c.highC:
			if !c.writeFrame(f) {
				return false
			}
		default:
			return true
		}
	}
}

func (c *conn) drainReplay() bool {
	for {
		select {
		case batch := <-c.replayC:
			for _, f := range batch {
				if !c.writeFrame(f) {
					return false
				}
			}
		default:
			return true
		}
	}
}

// step 消费一条在线事件或一条流数据；无消费来源时阻塞等待（wakeC 唤醒后重扫
// 流集合）。false = 连接收工。
func (c *conn) step() bool {
	c.subMu.Lock()
	var evC <-chan Event
	var doneC <-chan struct{}
	if c.sub != nil {
		evC, doneC = c.sub.Events(), c.sub.Done()
	}
	c.subMu.Unlock()

	// 事件非阻塞一条（在流轮询前——事件是慢流 MUST NOT 阻塞的另一类）。
	if evC != nil {
		select {
		case ev := <-evC:
			return c.writeFrame(encodeJSONFrame(OpEvt, EventBody{Seq: ev.Seq, Domain: ev.Domain, Kind: ev.Kind, Payload: ev.Payload}))
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
			return c.writeFrame(encodeJSONFrame(OpEvt, EventBody{Seq: ev.Seq, Domain: ev.Domain, Kind: ev.Kind, Payload: ev.Payload}))
		case <-doneC:
			// 订阅 overrun（bus 停投）：goodbye(overrun) 断连（spec「慢消费者被
			// 断连重同步」——不静默丢事件）。
			c.fatalFromWriter(GoodbyeOverrun)
			return false
		case f := <-c.highC:
			return c.writeFrame(f)
		case batch := <-c.replayC:
			for _, f := range batch {
				if !c.writeFrame(f) {
					return false
				}
			}
			return true
		case <-c.wakeC:
			return true
		case <-c.closed:
			return false
		}
	}
	select {
	case f := <-c.highC:
		return c.writeFrame(f)
	case batch := <-c.replayC:
		for _, f := range batch {
			if !c.writeFrame(f) {
				return false
			}
		}
		return true
	case <-c.wakeC:
		return true
	case <-c.closed:
		return false
	}
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
