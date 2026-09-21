package dns

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
)

// Server：出口侧 DNS 代答（openspec dns-host-resolver）。
//
// 监听仅回环；经隧道的 :53 查询由 intercept 的端口改写投到这里（见
// pkg/intercept 的 target）。上游 = 主机系统解析（Upstreams 跟随 resolv.conf），
// 按序尝试 + 末位公共 DNS 兜底（仅连接层失败触发，否定应答绝不兜底）；
// 单查询总预算内完成；v6 类 qtype 回空应答；应答 TTL 钳制 ≤60s；UDP 超限
// 截断置 TC。每查询 recover + 在途上限——出口单进程多手机共享，DNS 处理
// 不得拖死隧道转发。
type Server struct {
	cfg Config
	ups *Upstreams
	udp net.PacketConn
	tcp net.Listener

	closed    chan struct{}
	inFlight  atomic.Int32
	fbOnceLog atomic.Bool

	// TCP 客户端面（本机可达）：连接跟踪 + 上限（review M5——Close 能收线、
	// 挂连接的本地进程不能无限耗 goroutine/fd）。closeOnce 属实例（review F3）。
	closeOnce sync.Once
	connsMu   sync.Mutex
	conns     map[net.Conn]bool

	q, resp, filtered, trunc, fallback, fail, dropped, malformed, aaaaMixed atomic.Uint64
}

// Config 代答配置（零值用默认；Dial 上游不可注入——测试用 ResolvPath +
// FallbackDNS 指向本地 fake 上游）。
type Config struct {
	Addr        string               // 监听地址（默认 127.0.0.1:5300；:0 = 随机，测试用）
	ResolvPath  string               // 默认 /etc/resolv.conf
	FallbackDNS string               // 全部 nameserver 连接层失败时的末位兜底（默认 223.5.5.5）
	Budget      time.Duration        // 单查询总预算（默认 2.5s，主/兜共享）
	MaxInFlight int                  // 在途查询上限（默认 256，超限丢弃计数）
	MaxTCPConns int                  // TCP 客户端连接上限（默认 64；测试注入）
	Logf        func(string, ...any) // 摘要级：就绪/告警/兜底首次触发
	DLogf       func(string, ...any) // 细节级：周期统计行/兜底每次触发
}

const (
	defaultDNSPort  = 5300
	defaultFallback = "223.5.5.5"
	defaultBudget   = 2500 * time.Millisecond
	defaultInFlight = 256
	maxTTL          = 60
	statsInterval   = 60 * time.Second
	udpBufSize      = 64 << 10
	maxPerTry       = 800 * time.Millisecond // 单次上游尝试的预算上限（review F1：防静默上游吃干总预算）
	maxTCPConns     = 64                     // TCP 客户端面（本机可达）连接上限（review M5）
	tcpIdle         = 30 * time.Second       // TCP 客户端单消息空闲期限
)

// Listen 建 UDP+TCP 双 listener 并加载上游。自环防护：监听端口为 53 时剔除
// 回环上游（上游查询打回自身，查询风暴）。
func Listen(cfg Config) (*Server, error) {
	if cfg.Addr == "" {
		cfg.Addr = fmt.Sprintf("127.0.0.1:%d", defaultDNSPort)
	}
	if cfg.ResolvPath == "" {
		cfg.ResolvPath = "/etc/resolv.conf"
	}
	if cfg.FallbackDNS == "" {
		cfg.FallbackDNS = defaultFallback
	}
	if cfg.Budget <= 0 {
		cfg.Budget = defaultBudget
	}
	if cfg.MaxInFlight <= 0 {
		cfg.MaxInFlight = defaultInFlight
	}
	if cfg.MaxTCPConns <= 0 {
		cfg.MaxTCPConns = maxTCPConns
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.DLogf == nil {
		cfg.DLogf = func(string, ...any) {}
	}
	ups, err := NewUpstreams(cfg.ResolvPath)
	if err != nil {
		return nil, fmt.Errorf("dns: 无可用上游（%s：%v）", cfg.ResolvPath, err)
	}
	_, port, _ := net.SplitHostPort(cfg.Addr)
	if port == "53" { // 自环：上游按 <host>:53 拨，监听 53 时回环上游会打回自己
		filtered := ups.list[:0:0]
		for _, up := range ups.list {
			if ip := net.ParseIP(up); ip != nil && ip.IsLoopback() {
				cfg.Logf("⚠️ dns 上游 %s 指向回环且监听为 53（自环），已剔除", up)
				continue
			}
			filtered = append(filtered, up)
		}
		if len(filtered) == 0 {
			return nil, errors.New("dns: 全部上游为自环地址，代答不可用")
		}
		ups.list = filtered
	}
	udp, err := net.ListenPacket("udp", cfg.Addr)
	if err != nil {
		return nil, err
	}
	tcp, err := net.Listen("tcp", udp.LocalAddr().String())
	if err != nil {
		udp.Close()
		return nil, err
	}
	s := &Server{cfg: cfg, ups: ups, udp: udp, tcp: tcp, closed: make(chan struct{}), conns: make(map[net.Conn]bool)}
	go s.serveUDP()
	go s.serveTCP()
	go s.statsLoop()
	return s, nil
}

// Addr 实际监听地址（:0 时取内核分配值）。
func (s *Server) Addr() string { return s.udp.LocalAddr().String() }

// UpstreamsText 当前上游列表的逗连摘要（判据行用）。
func (s *Server) UpstreamsText() string { return strings.Join(s.ups.List(), ", ") }

// Close 收工（listener 双关 + 通知 TCP 连接收线；在途查询靠 budget 自行了断）。
// Once 防并发双 Close panic（review F3：select/default 只防顺序二次调用）。
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.tcp.Close()
		s.udp.Close()
		s.connsMu.Lock()
		for c := range s.conns {
			c.Close()
		}
		s.connsMu.Unlock()
	})
	return nil
}

// StatsLine 判据行（debug.log 周期输出）。
func (s *Server) StatsLine() string {
	return fmt.Sprintf("dns: q=%d resp=%d filter=%d trunc=%d fallback=%d fail=%d drop=%d malformed=%d aaaa-mixed=%d",
		s.q.Load(), s.resp.Load(), s.filtered.Load(), s.trunc.Load(), s.fallback.Load(),
		s.fail.Load(), s.dropped.Load(), s.malformed.Load(), s.aaaaMixed.Load())
}

// SelfCheck 启动自验证：**经监听器真发**一条 UDP 查询走完整链路（监听 →
// 转发 → 上游），校验拿到合法应答且非 SERVFAIL（review M2：直调 respond 的
// 老实现里失败分支不可达——上游全死时 respond 本地造 SERVFAIL 也返回非 nil，
// 恒过；NXDOMAIN 仍算「链路活着」）。
func (s *Server) SelfCheck() error {
	q := selfCheckQuery()
	// 期限 ≥ 代答预算 + 余量（review3 中1）：resolv.conf 前几位是静默死上游时，
	// F1 的均分让首个真实应答 ~1.6s 才到——1s 期限会在这种真实故障场景打假告警。
	dl := s.cfg.Budget + 500*time.Millisecond
	c, err := net.DialTimeout("udp", s.Addr(), dl)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(dl))
	if _, err := c.Write(q); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return fmt.Errorf("自验证无应答（监听/上游全不可达）：%w", err)
	}
	resp := buf[:n]
	if len(resp) < 12 || binary.BigEndian.Uint16(resp[0:2]) != binary.BigEndian.Uint16(q[0:2]) {
		return errors.New("自验证应答不合法")
	}
	if resp[3]&0x0F == 2 { // SERVFAIL = 上游全挂且兜底也失败
		return errors.New("自验证拿到 SERVFAIL（上游全挂且兜底失败）")
	}
	return nil
}

func (s *Server) statsLoop() {
	t := time.NewTicker(statsInterval)
	defer t.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-t.C:
			s.cfg.DLogf("%s", s.StatsLine())
		}
	}
}

func (s *Server) serveUDP() {
	buf := make([]byte, udpBufSize)
	for {
		n, addr, err := s.udp.ReadFrom(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				// 临时性错误（如上游不可达回灌的 ECONNREFUSED）不该杀死监听循环
				//（review F2：一次错误永久退出且无日志 = 静默失能）。
				s.cfg.DLogf("dns: UDP 读错误（继续）：%v", err)
				time.Sleep(50 * time.Millisecond)
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		s.q.Add(1)
		if int(s.inFlight.Add(1)) > s.cfg.MaxInFlight {
			s.inFlight.Add(-1)
			s.dropped.Add(1)
			continue // 超限丢弃：客户端按超时重试，不排长队放大延迟
		}
		go func(addr net.Addr, pkt []byte) {
			defer s.inFlight.Add(-1)
			defer func() {
				if r := recover(); r != nil {
					s.malformed.Add(1)
					s.cfg.DLogf("dns: 查询处理 panic（已兜住）：%v", r)
				}
			}()
			if resp := s.respond(pkt, false); resp != nil {
				s.udp.WriteTo(resp, addr) // best-effort
			}
		}(addr, pkt)
	}
}

func (s *Server) serveTCP() {
	for {
		conn, err := s.tcp.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.cfg.DLogf("dns: TCP accept 错误（继续）：%v", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		s.connsMu.Lock()
		// Close 已整段跑完的窗口（review3 低）：这条 conn 注册进已清扫的表只会
		// 等自己的 deadline——拿锁后复查，关了就别注册。
		select {
		case <-s.closed:
			s.connsMu.Unlock()
			conn.Close()
			continue
		default:
		}
		if len(s.conns) >= s.cfg.MaxTCPConns { // 本机可达面也要有闸（review M5；可注入）
			s.connsMu.Unlock()
			conn.Close()
			s.dropped.Add(1)
			continue
		}
		s.conns[conn] = true
		s.connsMu.Unlock()
		go func(conn net.Conn) {
			defer func() {
				conn.Close()
				s.connsMu.Lock()
				delete(s.conns, conn)
				s.connsMu.Unlock()
			}()
			for {
				// 每条消息一个空闲期限：挂住不发的本地进程不能无限占 goroutine/fd。
				_ = conn.SetDeadline(time.Now().Add(tcpIdle))
				q, err := readTCPMessage(conn)
				if err != nil {
					return
				}
				s.q.Add(1)
				if int(s.inFlight.Add(1)) > s.cfg.MaxInFlight {
					s.inFlight.Add(-1)
					s.dropped.Add(1)
					continue
				}
				var resp []byte
				func() {
					defer s.inFlight.Add(-1)
					defer func() {
						if r := recover(); r != nil {
							s.malformed.Add(1)
						}
					}()
					resp = s.respond(q, true)
				}()
				if resp == nil || writeTCPMessage(conn, resp) != nil {
					return
				}
			}
		}(conn)
	}
}

// respond 单查询处理（调用方已 recover）。nil = 不回包（畸形）。
// isTCP：TCP 客户端正是为「取全量」而来（UDP 截断后的重试），不受 1232 的
// TUN 单包约束（review H2：无条件截断 = 永远拿不到全量的死循环）。
func (s *Server) respond(query []byte, isTCP bool) []byte {
	qt, ok := QType(query)
	if !ok {
		s.malformed.Add(1)
		return nil
	}
	if FilteredQType(qt) {
		s.filtered.Add(1)
		return EmptyResponse(query)
	}
	resp := s.forward(query)
	if resp == nil {
		s.fail.Add(1)
		return servfailResponse(query)
	}
	if n := CountAAAA(resp); n > 0 {
		s.aaaaMixed.Add(uint64(n)) // 观测面：夹带 v6 记录只计数不剥离（已知限制）
	}
	ClampTTL(resp, maxTTL)
	if !isTCP && len(resp) > proto.MaxDNSPayload53 {
		resp = Truncate(resp, proto.MaxDNSPayload53)
		s.trunc.Add(1)
	}
	s.resp.Add(1)
	return resp
}

// forward 按序尝试 nameserver 列表 + 末位兜底，共享单查询总预算。
// exchange 区分「连接层失败（试下一个）」与「拿到应答（含否定，直接返回）」。
// 每次尝试的预算 = min(剩余, 800ms)：静默黑洞上游（收包不回，代理残留死指向的
// 典型形态）不能把总预算吃干——否则后续 nameserver 与兜底全被 budget<=0 跳过，
// 「上游全挂时兜底」就不成立了（review F1，测试锁定）。
func (s *Server) forward(query []byte) []byte {
	deadline := time.Now().Add(s.cfg.Budget)
	ups := s.ups.List()
	attempts := len(ups) + 1 // nameservers + 兜底
	try := func(addr string, i int) ([]byte, bool) {
		remain := time.Until(deadline)
		if remain <= 0 {
			return nil, false
		}
		perTry := remain / time.Duration(attempts-i)
		// 末次尝试不吃 800ms 上限（review3 低）：唯一/最后的上游是「慢但活着」
		// （800ms–2.5s）时让它用满剩余预算，而不是提前 SERVFAIL 白扔预算。
		if i < attempts-1 && perTry > maxPerTry {
			perTry = maxPerTry
		}
		return s.exchange(addr, query, perTry, deadline)
	}
	for i, up := range ups {
		if resp, ok := try(dialAddr(up), i); ok {
			return resp
		}
	}
	if resp, ok := try(dialAddr(s.cfg.FallbackDNS), len(ups)); ok {
		s.fallback.Add(1)
		s.cfg.DLogf("dns: 兜底触发（nameserver 全部连接层失败）→ %s", s.cfg.FallbackDNS)
		if s.fbOnceLog.CompareAndSwap(false, true) {
			s.cfg.Logf("⚠️ dns 上游全部不可达，已触发公共 DNS 兜底（%s）——fake-ip 主机上该应答为真实 IP，域名规则对这些流量失效", s.cfg.FallbackDNS)
		}
		return resp
	}
	return nil
}

// exchange 向单个上游转发一条查询（UDP，TC 切 TCP），返回 (应答, 是否拿到)。
// 应答回填原始 ID；只接受来自该 socket、ID 与 question 段匹配的应答（防投毒/
// 串答）。连接层失败（超时/不可达/被拒）= false；否定应答 = true 原样透传。
func (s *Server) exchange(addr string, query []byte, budget time.Duration, deadline time.Time) ([]byte, bool) {
	if budget <= 0 {
		return nil, false
	}
	origID := binary.BigEndian.Uint16(query[0:2])
	var fwd [2]byte
	if _, err := rand.Read(fwd[:]); err != nil {
		fwd[0], fwd[1] = query[0], query[1]
	}
	newID := binary.BigEndian.Uint16(fwd[:])
	q := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(q[0:2], newID) // 事务 ID 重写为密码学随机，防可预测 ID 的投毒面

	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, false
	}
	conn, err := net.DialUDP("udp", nil, raddr) // 每查询新 socket = 随机源端口
	if err != nil {
		return nil, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(budget))
	if _, err := conn.Write(q); err != nil {
		return nil, false
	}
	qend, qok := skipName(q, 12)
	if !qok {
		return nil, false
	}
	buf := make([]byte, udpBufSize)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			return nil, false // 超时/重置 = 连接层失败
		}
		if !from.(*net.UDPAddr).AddrPort().Addr().IsValid() || n < 12 {
			continue
		}
		resp := buf[:n]
		if binary.BigEndian.Uint16(resp[0:2]) != binary.BigEndian.Uint16(fwd[:]) {
			continue // 事务 ID 不匹配：丢弃（伪造/迟到应答）
		}
		if rend, ok := skipName(resp, 12); !ok || rend+4 > len(resp) || !equalQuestion(resp[12:rend+4], q[12:qend+4]) {
			continue // question 段不一致：丢弃
		}
		out := append([]byte(nil), resp...)
		binary.BigEndian.PutUint16(out[0:2], origID)
		if out[2]&0x02 != 0 { // 上游置 TC → 切 TCP 取全量（预算 = 查询剩余时间，非本腿新起算）
			if remain := time.Until(deadline); remain > 0 {
				if tcpResp, ok := s.exchangeTCP(addr, query, out, remain); ok {
					return tcpResp, true
				}
			}
			// TCP 腿失败（被拒/超时）：回 UDP 截断应答（TC 保持），客户端按
			// DNS 语义自行重试——UDP 腿已证明上游活着，按连接层失败试下一个
			// 反而丢掉了已拿到的（截断）应答。
		}
		return out, true
	}
}

// exchangeTCP 经 TCP 向上游重查：**发原始查询报文**（重新随机事务 ID），读单条
// 应答并校验 (ID, question)（review H1：老实现把 UDP 应答当查询发出——QR=1 的
// 报文上游要么丢要么回 FORMERR，整条 TC→TCP 链路不可用）。失败回退 = 入参的
// UDP 截断应答（TC 保持，客户端可自行重试），不算连接层成功。
func (s *Server) exchangeTCP(addr string, query, udpResp []byte, budget time.Duration) ([]byte, bool) {
	d := net.Dialer{Timeout: budget}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return udpResp, true
	}
	defer conn.Close()
	// 拨号与读共用同一绝对期限（review3 低：各自起算会让 tarpit 上游把单查询
	// 推到 ~2×perTry，突破 spec 的总预算上界）。
	absDL := time.Now().Add(budget)
	_ = conn.SetDeadline(absDL)
	origID := binary.BigEndian.Uint16(query[0:2])
	q := append([]byte(nil), query...)
	var id [2]byte
	newID := origID ^ 0xFFFF
	if _, err := rand.Read(id[:]); err == nil {
		newID = binary.BigEndian.Uint16(id[:])
	} else {
		binary.BigEndian.PutUint16(id[:], newID) // 同步本地 id（review3 低：不同步则校验期望 0x0000）
	}
	binary.BigEndian.PutUint16(q[0:2], newID)
	if err := writeTCPMessage(conn, q); err != nil {
		return udpResp, true
	}
	resp, err := readTCPMessage(conn)
	if err != nil || len(resp) < 12 {
		return udpResp, true
	}
	if binary.BigEndian.Uint16(resp[0:2]) != binary.BigEndian.Uint16(id[:]) {
		return udpResp, true // ID 不匹配：不认（垃圾回包/错位应答）
	}
	rend, ok := skipName(resp, 12)
	qend, ok2 := skipName(q, 12)
	if !ok || !ok2 || rend+4 > len(resp) || qend+4 > len(q) || !equalQuestion(resp[12:rend+4], q[12:qend+4]) {
		return udpResp, true // question 段不一致
	}
	binary.BigEndian.PutUint16(resp[0:2], origID)
	return resp, true
}

// readTCPMessage / writeTCPMessage：RFC 1035 TCP 分帧（2 字节长度前缀）。
func readTCPMessage(conn net.Conn) ([]byte, error) {
	var lb [2]byte
	if _, err := ioReadFull(conn, lb[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lb[:]))
	if n == 0 {
		return nil, errors.New("dns: 空 TCP 消息")
	}
	msg := make([]byte, n)
	if _, err := ioReadFull(conn, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func writeTCPMessage(conn net.Conn, msg []byte) error {
	if len(msg) > 0xFFFF {
		return errors.New("dns: TCP 消息超长")
	}
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(msg)))
	copy(out[2:], msg)
	_, err := conn.Write(out)
	return err
}

func ioReadFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// dialAddr 把 resolv.conf 的 nameserver 形态转成可拨地址：纯 IPv4 拼 :53；
// 裸 IPv6 加方括号；已带端口的形态原样（测试注入用，标准文件不会出现）。
func dialAddr(up string) string {
	if _, _, err := net.SplitHostPort(up); err == nil {
		return up
	}
	if strings.Contains(up, ":") {
		return "[" + up + "]:53"
	}
	return up + ":53"
}

// servfailResponse 预算耗尽/全失败的应答（RCODE=2），让客户端按 DNS 失败重试。
func servfailResponse(query []byte) []byte {
	out := EmptyResponse(query)
	if out == nil {
		return nil
	}
	out[3] |= 0x02
	return out
}

// selfCheckQuery 构造自验证查询（随机 ID + 一次性域名，避免命中任何缓存）。
func selfCheckQuery() []byte {
	var id [2]byte
	rand.Read(id[:])
	q := make([]byte, 0, 40)
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], binary.BigEndian.Uint16(id[:]))
	hdr[2] = 0x01
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	q = append(q, hdr...)
	for _, label := range []string{"selfcheck", "dns", "homeway", "invalid"} {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	return append(q, 0, 0x00, 0x01, 0x00, 0x01) // 根 + A/IN
}

// equalQuestion 比较两段 question 字节（含 QTYPE/QCLASS）。
func equalQuestion(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
