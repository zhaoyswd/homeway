// Package speedtest：隧道内测速服务（openspec tier/tunnel-speedtest）。
//
// 客户端（手机核）经隧道拨隧道IP:7803，拦截层按 LocalServices 映射转投到本服务
// （<state>/speedtest.sock，UDS 承载）。会话数据只在内存收发、不落盘；每连接一角色：
//   - role=recv（供下行）：服务端自驱——预热发 data → 窗口发 data → report 后关；
//   - role=send（收上行）：客户端泵 data，START 后服务端才计窗内字节，FINISH 触发 report。
//
// 线上一切消息 = 统一帧 [magic u32][type u8][seq u32][len u16][crc32 u32][payload]（LE）。
// goodput 只计 data 的 payload（零填充，帧头不计）；crc 盖 payload——data 帧载荷全零，
// crc 按长度恒定可缓存，截断/错位由 magic+len+crc 三重兜住（UDS 本机承载，无信道损坏面）。
// 速率读数永远由接收端报数（tunnel-speedtest design D3）。
package speedtest

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"sync"
	"time"
)

// magic "SPED"。
var frameMagic = [4]byte{'S', 'P', 'E', 'D'}

// maxHeader 帧头字节数（4 magic + 1 type + 4 seq + 2 len + 4 crc）。
const maxHeader = 15

// MaxHeader 导出的帧头字节数（客户端拼整帧 scratch 时用；与 maxHeader 同值）。
const MaxHeader = maxHeader

// FrameType 线上帧类型。
type FrameType uint8

const (
	TypeRequest FrameType = 1 // client→server：会话请求（恒第一帧）
	TypeStart   FrameType = 2 // client→server：role=send 的窗口起点（空载荷）
	TypeFinish  FrameType = 3 // client→server：role=send 收口，服务端回 report（空载荷）
	TypeData    FrameType = 4 // 双向：数据块（payload 全零，goodput 只计它）
	TypeReport  FrameType = 5 // server→client：收口报告（含 error 时为失败收场）
)

// Role 会话角色。
type Role string

const (
	RoleRecv Role = "recv" // 服务端发、客户端收（测下行）
	RoleSend Role = "send" // 客户端发、服务端收（测上行）
)

// requestJSON 会话请求的 JSON 形状。
type requestJSON struct {
	Role     Role  `json:"role"`
	WarmupMs int64 `json:"warmup_ms"`
	WindowMs int64 `json:"window_ms"`
}

// Report 一次测量的收口报告（接收端报数）。
type Report struct {
	Bytes       int64  `json:"bytes"`        // 窗口内收到的 payload 字节（role=send 为 START 后计数）
	WarmupBytes int64  `json:"warmup_bytes"` // 预热阶段字节（不计入读数）
	WallMs      int64  `json:"wall_ms"`      // 服务端实测的窗口墙钟
	Error       string `json:"error,omitempty"`
}

// maxPayload 载荷长度场的硬上限（u16）。
const maxPayload = 65535

// Limits 服务端限额（spec「出口测速服务边界」：并发会话数、单会话时长、帧大小上限）。
type Limits struct {
	MaxConns    int           // 并发测速连接上限（0 = 8）
	ConnTimeout time.Duration // 单连接硬超时（0 = 30s；覆盖 5s 预热 + 15s 窗口 + 余量）
	MaxWarmup   time.Duration // 预热时长上限（0 = 5s）
	MaxWindow   time.Duration // 窗口时长上限（0 = 15s）
	MaxBlock    int           // data 载荷上限（0 = maxPayload；u16 长度场决定 ≤65535）
	SendBlock   int           // 服务端发送块大小（0 = maxPayload）
}

func (l Limits) withDefaults() Limits {
	if l.MaxConns <= 0 {
		l.MaxConns = 12 // 客户端 4+4 条流，留出下行摘表时差的余量（评审 r2-D1）
	}
	if l.ConnTimeout <= 0 {
		l.ConnTimeout = 30 * time.Second
	}
	if l.MaxWarmup <= 0 {
		l.MaxWarmup = 5 * time.Second
	}
	if l.MaxWindow <= 0 {
		l.MaxWindow = 15 * time.Second
	}
	if l.MaxBlock <= 0 || l.MaxBlock > maxPayload {
		l.MaxBlock = maxPayload
	}
	if l.SendBlock <= 0 || l.SendBlock > l.MaxBlock {
		l.SendBlock = l.MaxBlock
	}
	return l
}

// Server：内存收发的测速服务。Serve 由调用方在 listener 上拉起（照 files/term 的形状），
// Close 主动断开仍在跑的会话（listener 由持有方关闭）。
type Server struct {
	logf func(format string, args ...any)
	lim  Limits

	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	total    int // 已受理会话数（判据行 #N 的来源）
	rejected int // 超限拒绝数
}

// NewServer 建服务（默认限额，可用 SetLimits 覆盖）。
func NewServer(logf func(format string, args ...any)) *Server {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Server{logf: logf, lim: Limits{}.withDefaults(), conns: map[net.Conn]struct{}{}}
}

// SetLimits 覆盖限额（Serve 之前调用）。
func (s *Server) SetLimits(l Limits) { s.lim = l.withDefaults() }

// Stats 会话计数（验收对账用）。
func (s *Server) Stats() (total, rejected int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.total, s.rejected
}

// Close 断开全部在跑会话并停止受理（listener 由持有方关）。
func (s *Server) Close() error {
	s.mu.Lock()
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.conns = map[net.Conn]struct{}{}
	s.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
	return nil
}

// Serve 在 listener 上受理（每连接一个 goroutine）。Accept 出错即返回。
func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.serveConn(conn)
	}
}

func (s *Server) serveConn(conn net.Conn) {
	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)
	s.mu.Lock()
	if len(s.conns) >= s.lim.MaxConns {
		s.rejected++
		s.mu.Unlock()
		s.logf("speedtest: 会话拒绝（并发上限 %d）", s.lim.MaxConns)
		// 先有界读掉请求帧再回帧（r1 中-1②）：去问候帧后客户端先写请求，回帧后立刻关
		// 会走 RST 路径、已发出的 report 可能被对端丢弃。
		ReplyThenClose(conn, br, Report{Error: "busy"})
		return
	}
	s.total++
	id := s.total
	s.conns[conn] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		conn.Close()
	}()

	// 单连接硬超时：覆盖最大预热 + 最大窗口 + 控制帧余量（spec：单会话时长上限）。
	conn.SetDeadline(time.Now().Add(s.lim.ConnTimeout))

	// 恒第一帧（去问候帧后首帧 = 会话请求，客户端先写、服务端后答）。
	t, _, payload, err := readFrame(br)
	if err != nil {
		s.logf("speedtest: 会话异常（读请求帧：%v）", err)
		return
	}
	if t != TypeRequest {
		s.logf("speedtest: 会话异常（首帧类型 %d 非 request）", t)
		return
	}
	var req requestJSON
	if err := json.Unmarshal(payload, &req); err != nil {
		s.logf("speedtest: 会话异常（请求解析：%v）", err)
		return
	}
	warmup := time.Duration(req.WarmupMs) * time.Millisecond
	window := time.Duration(req.WindowMs) * time.Millisecond
	if req.Role != RoleRecv && req.Role != RoleSend {
		finishWithError(bw, fmt.Sprintf("未知角色 %q", req.Role))
		return
	}
	if warmup < 0 || warmup > s.lim.MaxWarmup {
		finishWithError(bw, fmt.Sprintf("预热 %s 超上限 %s", warmup, s.lim.MaxWarmup))
		return
	}
	if window < 100*time.Millisecond || window > s.lim.MaxWindow {
		finishWithError(bw, fmt.Sprintf("窗口 %s 超出 [%s, %s]", window, 100*time.Millisecond, s.lim.MaxWindow))
		return
	}

	s.logf("speedtest: 会话 #%d role=%s warmup=%s window=%s", id, req.Role, warmup, window)

	if req.Role == RoleRecv {
		s.serveRecv(id, bw, warmup, window)
		return
	}
	s.serveSend(id, br, bw, s.lim.MaxBlock)
}

// serveRecv role=recv：预热发 → 窗口发 → report。发送侧按接收方 TCP 背压自然限速。
func (s *Server) serveRecv(id int, bw *bufio.Writer, warmup, window time.Duration) {
	block := make([]byte, s.lim.SendBlock)
	var seq uint32
	t0 := time.Now()
	warmupBytes := PumpData(bw, block, &seq, warmup)
	if err := bw.Flush(); err != nil {
		s.logf("speedtest: 会话 #%d 异常（下行发送：%v）", id, err)
		return
	}
	windowBytes := PumpData(bw, block, &seq, window)
	if err := bw.Flush(); err != nil {
		s.logf("speedtest: 会话 #%d 异常（下行发送：%v）", id, err)
		return
	}
	rep := Report{Bytes: windowBytes, WarmupBytes: warmupBytes, WallMs: time.Since(t0).Milliseconds()}
	if err := writeReport(bw, rep); err != nil {
		s.logf("speedtest: 会话 #%d 异常（回报告：%v）", id, err)
		return
	}
	s.logf("speedtest: 会话 #%d role=recv bytes=%d（含预热 %d）用时=%dms", id, rep.Bytes, rep.WarmupBytes, rep.WallMs)
}

// serveSend role=send：读帧计数——START 前 = 预热，START 后 = 窗口；FINISH 触发 report。
func (s *Server) serveSend(id int, br *bufio.Reader, bw *bufio.Writer, maxBlock int) {
	var (
		windowBytes int64
		warmupBytes int64
		started     bool
		startAt     time.Time
	)
	for {
		t, _, payloadLen, err := readFrameHeader(br)
		if err != nil {
			s.logf("speedtest: 会话 #%d 异常（读上行帧：%v）", id, err)
			return
		}
		if t != TypeData && payloadLen > 0 {
			// 控制帧按约定空载荷；非空按载荷丢弃（协议向前兼容）。
			if err := discardPayload(br, payloadLen); err != nil {
				s.logf("speedtest: 会话 #%d 异常（读控制载荷：%v）", id, err)
				return
			}
		}
		switch t {
		case TypeData:
			if payloadLen > maxBlock {
				finishWithError(bw, fmt.Sprintf("data 载荷 %d 超上限 %d", payloadLen, maxBlock))
				return
			}
			if err := discardPayload(br, payloadLen); err != nil {
				s.logf("speedtest: 会话 #%d 异常（读上行载荷：%v）", id, err)
				return
			}
			if started {
				windowBytes += int64(payloadLen)
			} else {
				warmupBytes += int64(payloadLen)
			}
		case TypeStart:
			if started {
				finishWithError(bw, "重复 START")
				return
			}
			started = true
			startAt = time.Now()
		case TypeFinish:
			if !started {
				finishWithError(bw, "FINISH 前无 START")
				return
			}
			rep := Report{Bytes: windowBytes, WarmupBytes: warmupBytes, WallMs: time.Since(startAt).Milliseconds()}
			if err := writeReport(bw, rep); err != nil {
				s.logf("speedtest: 会话 #%d 异常（回报告：%v）", id, err)
				return
			}
			s.logf("speedtest: 会话 #%d role=send bytes=%d（含预热 %d）用时=%dms", id, rep.Bytes, rep.WarmupBytes, rep.WallMs)
			return
		default:
			finishWithError(bw, fmt.Sprintf("窗口期收到类型 %d", t))
			return
		}
	}
}

func finishWithError(bw *bufio.Writer, msg string) {
	_ = writeReport(bw, Report{Error: msg})
	_ = bw.Flush()
}

// PumpData 在 dur 内持续写 data 帧（发送块全零、seq 递增），返回 payload 总字节。
// 导出给客户端（手机核的测速引擎）复用：上行方向的泵与服务端同一段代码，语义一致。
// 不 Flush——调用方控制冲刷时机（阶段级一次，压满 TCP 背压）。
// 整帧（头+载荷）拼进一块 scratch 一次写出：避免 bufio 大写直通把帧头/载荷拆成两次系统调用。
func PumpData(bw *bufio.Writer, block []byte, seq *uint32, dur time.Duration) int64 {
	scratch := make([]byte, maxHeader+len(block))
	copy(scratch[maxHeader:], block)
	deadline := time.Now().Add(dur)
	var total int64
	for !time.Now().After(deadline) {
		if err := writeData(scratch, *seq+1, len(block)); err != nil {
			return total
		}
		if _, err := bw.Write(scratch); err != nil {
			return total
		}
		*seq++
		total += int64(len(block))
	}
	return total
}

// PumpDataChunk 泵一个时间片（dur 内持续写 data 帧，整帧单次写出），返回本片写出的
// payload 字节数（评审 r2-N1：调用方的用量/实时计数必须用它——「一片一帧」的假设
// 在 2026-09-27 造成了 1~2 个数量级的少算）。
// 与 PumpData 的差别：调用方自带 scratch（跨片复用、零分配）且按片返回——
// 客户端用它做上行实时计数与取消检查点（每片一个节拍）。
func PumpDataChunk(bw *bufio.Writer, scratch []byte, seq *uint32, dur time.Duration) (int64, error) {
	deadline := time.Now().Add(dur)
	payloadLen := len(scratch) - maxHeader
	if payloadLen <= 0 {
		return 0, fmt.Errorf("scratch 太小（%d 字节，帧头 %d）", len(scratch), maxHeader)
	}
	var total int64
	for !time.Now().After(deadline) {
		if err := writeData(scratch, *seq+1, payloadLen); err != nil {
			return total, err
		}
		if _, err := bw.Write(scratch); err != nil {
			return total, err
		}
		*seq++
		total += int64(payloadLen)
	}
	return total, nil
}

// ---------- 帧编解码（客户端助手与服务端共用） ----------

// 零载荷的 crc 按长度缓存：crc32 只由长度决定，发送侧免重复计算。
var zeroCRCCache sync.Map // map[int]uint32

func zeroCRC(n int) uint32 {
	if v, ok := zeroCRCCache.Load(n); ok {
		return v.(uint32)
	}
	v := crc32.ChecksumIEEE(make([]byte, n))
	zeroCRCCache.Store(n, v)
	return v
}

// writeData 把 data 帧头填进 scratch 前 maxHeader 字节（载荷已就位）。
// scratch = 帧缓冲，载荷区必须是全零（crc 按长度缓存的前提）。
func writeData(scratch []byte, seq uint32, payloadLen int) error {
	if payloadLen > maxPayload {
		return fmt.Errorf("data 载荷 %d 超 u16 长度场上限 %d", payloadLen, maxPayload)
	}
	copy(scratch[0:4], frameMagic[:])
	scratch[4] = byte(TypeData)
	binary.LittleEndian.PutUint32(scratch[5:9], seq)
	binary.LittleEndian.PutUint16(scratch[9:11], uint16(payloadLen))
	// payload 全零 ⇒ crc 恒定可缓存；错位/截断由 magic+len+crc 三重兜住。
	binary.LittleEndian.PutUint32(scratch[11:15], zeroCRC(payloadLen))
	return nil
}

// WriteControl 写一个控制帧（request/start/finish）。
func WriteControl(bw *bufio.Writer, t FrameType, payload []byte) error {
	if len(payload) > maxPayload {
		return fmt.Errorf("控制帧载荷 %d 超上限 %d", len(payload), maxPayload)
	}
	var hdr [maxHeader]byte
	copy(hdr[0:4], frameMagic[:])
	hdr[4] = byte(t)
	binary.LittleEndian.PutUint32(hdr[5:9], 0)
	binary.LittleEndian.PutUint16(hdr[9:11], uint16(len(payload)))
	binary.LittleEndian.PutUint32(hdr[11:15], crc32.ChecksumIEEE(payload))
	if _, err := bw.Write(hdr[:]); err != nil {
		return err
	}
	_, err := bw.Write(payload)
	return err
}

// WriteRequest 写会话请求帧（恒第一帧）。
func WriteRequest(bw *bufio.Writer, role Role, warmup, window time.Duration) error {
	b, err := json.Marshal(requestJSON{Role: role, WarmupMs: warmup.Milliseconds(), WindowMs: window.Milliseconds()})
	if err != nil {
		return err
	}
	return WriteControl(bw, TypeRequest, b)
}

// WriteStart / WriteFinish：role=send 的窗口起止标记（空载荷）。
func WriteStart(bw *bufio.Writer)  { _ = WriteControl(bw, TypeStart, nil) }
func WriteFinish(bw *bufio.Writer) { _ = WriteControl(bw, TypeFinish, nil) }

func replyReport(conn net.Conn, rep Report) {
	bw := bufio.NewWriter(conn)
	_ = writeReport(bw, rep)
	_ = bw.Flush()
}

// ReplyThenClose busy/link_down 类拒绝回帧的有序收口（3e 去问候帧，r1 中-1②）：
// 客户端已先写请求，直接回帧后关连接会因「对端尚有未读数据」走 RST 路径、已发出的
// report 可能被对端丢弃。顺序：有界读掉一帧（请求）→ 回 report 并冲刷 → 半关写侧
// （FIN 先于任何复位）→ 短窗继续吞掉后续输入（role=send 的泵送数据）→ 关。
// 消费方：服务端 busy 路径与手机桥宿主的 link_down 回复（app_bridge.go speedLinkDownReply）。
func ReplyThenClose(conn net.Conn, br *bufio.Reader, rep Report) {
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, _, _ = readFrame(br) // 有界吞一帧；失败也继续回帧（连接本就异常，尽力而为）
	_ = conn.SetReadDeadline(time.Time{})
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	bw := bufio.NewWriter(conn)
	_ = writeReport(bw, rep)
	// 继续吞输入一小窗（send 角色在回帧抵达前还在泵）后整关；期限内对端先关则自然提前结束。
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	discard := make([]byte, 4096)
	for {
		if _, err := br.Read(discard); err != nil {
			break
		}
	}
	_ = conn.Close()
}

func writeReport(bw *bufio.Writer, rep Report) error {
	b, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	if err := WriteControl(bw, TypeReport, b); err != nil {
		return err
	}
	// 立刻冲：写完 report 的下一步就是关连接，不冲会把报告留在 bufio 缓冲里丢掉。
	return bw.Flush()
}

// ReadReport 读服务端报告（客户端收口用）。
func ReadReport(br *bufio.Reader) (Report, error) {
	t, _, payload, err := readFrame(br)
	if err != nil {
		return Report{}, err
	}
	if t != TypeReport {
		return Report{}, fmt.Errorf("期望 report 帧，收到类型 %d", t)
	}
	var rep Report
	if err := json.Unmarshal(payload, &rep); err != nil {
		return Report{}, err
	}
	if rep.Error != "" {
		return rep, errors.New(rep.Error)
	}
	return rep, nil
}

// ReadFrameLoose 读一帧（客户端下行读循环用）：
//   - data 帧：零分配——只解头返回长度，载荷留给调用方 DiscardPayload；
//   - 其它帧（report 等）：载荷读进 ctrlBuf（容量不足才分配）并做 crc 校验。
//
// 返回的 payload 只在非 data 帧有效。
func ReadFrameLoose(br *bufio.Reader, ctrlBuf []byte) (t FrameType, seq uint32, n int, payload []byte, err error) {
	var hdr [maxHeader]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return 0, 0, 0, nil, err
	}
	if string(hdr[0:4]) != string(frameMagic[:]) {
		return 0, 0, 0, nil, errors.New("帧魔数不符（流已错位或非 speedtest 服务）")
	}
	t = FrameType(hdr[4])
	seq = binary.LittleEndian.Uint32(hdr[5:9])
	n = int(binary.LittleEndian.Uint16(hdr[9:11]))
	got := binary.LittleEndian.Uint32(hdr[11:15])
	if t == TypeData {
		if got != zeroCRC(n) {
			return 0, 0, 0, nil, errors.New("data 帧 crc 不符")
		}
		return t, seq, n, nil, nil
	}
	buf := ctrlBuf
	if cap(buf) < n {
		buf = make([]byte, n)
	}
	payload = buf[:n]
	if _, err := io.ReadFull(br, payload); err != nil {
		return 0, 0, 0, nil, err
	}
	if got != crc32.ChecksumIEEE(payload) {
		return 0, 0, 0, nil, errors.New("帧 crc 不符")
	}
	return t, seq, n, payload, nil
}

// readFrame 读一帧（控制帧路径：载荷小，连同 crc 一起校验）。
func readFrame(br *bufio.Reader) (FrameType, uint32, []byte, error) {
	var hdr [maxHeader]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return 0, 0, nil, err
	}
	if string(hdr[0:4]) != string(frameMagic[:]) {
		return 0, 0, nil, errors.New("帧魔数不符（流已错位或非 speedtest 服务）")
	}
	t := FrameType(hdr[4])
	seq := binary.LittleEndian.Uint32(hdr[5:9])
	n := int(binary.LittleEndian.Uint16(hdr[9:11]))
	got := binary.LittleEndian.Uint32(hdr[11:15])
	payload := make([]byte, n)
	if _, err := io.ReadFull(br, payload); err != nil {
		return 0, 0, nil, err
	}
	var want uint32
	if t == TypeData {
		want = zeroCRC(n)
	} else {
		want = crc32.ChecksumIEEE(payload)
	}
	if got != want {
		return 0, 0, nil, errors.New("帧 crc 不符")
	}
	return t, seq, payload, nil
}

// readFrameHeader 只读帧头不进载荷（data 计数路径：payload 是零填充，只需长度）。
// 返回后 crc 只做了 data 的长度一致性比对（零载荷 crc 只由长度决定）；
// 控制帧的完整校验走 readFrame。
func readFrameHeader(br *bufio.Reader) (FrameType, uint32, int, error) {
	var hdr [maxHeader]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return 0, 0, 0, err
	}
	if string(hdr[0:4]) != string(frameMagic[:]) {
		return 0, 0, 0, errors.New("帧魔数不符（流已错位或非 speedtest 服务）")
	}
	t := FrameType(hdr[4])
	seq := binary.LittleEndian.Uint32(hdr[5:9])
	n := int(binary.LittleEndian.Uint16(hdr[9:11]))
	got := binary.LittleEndian.Uint32(hdr[11:15])
	if t == TypeData && got != zeroCRC(n) {
		return 0, 0, 0, errors.New("data 帧 crc 不符")
	}
	return t, seq, n, nil
}

// DiscardPayload 导出的载荷丢弃（客户端 data 计数路径：payload 是零填充，只需长度；
// 配 ReadFrameLoose 的 header 使用。有消费者：tier 核 readDownStream）。
func DiscardPayload(br *bufio.Reader, n int) error {
	return discardPayload(br, n)
}

// discardPool data 计数路径的丢弃缓冲（64KB）。io.CopyN(io.Discard, …) 受 io.Discard
// 内部 8KB 读粒度限制，64KB 载荷要 ~8 次 read 系统调用（tunnel-speedtest 下行读端是
// 管线最慢一环，2026-09-28 整改）；这里整块读（请求长度 ≥ bufio 缓冲 ⇒ 直读旁路、
// 零缓冲拷贝），热路径每 64KB 帧降到 ~2-3 次。出口收上行（serveSend）同路径受益。
var discardPool = sync.Pool{
	New: func() any {
		b := make([]byte, 64<<10)
		return &b
	},
}

func discardPayload(br *bufio.Reader, n int) error {
	bp := discardPool.Get().(*[]byte)
	buf := *bp
	defer discardPool.Put(bp)
	for n > 0 {
		c := n
		if c > len(buf) {
			c = len(buf)
		}
		if _, err := io.ReadFull(br, buf[:c]); err != nil {
			return err
		}
		n -= c
	}
	return nil
}
