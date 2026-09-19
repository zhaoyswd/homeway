package flows

// UDP 中继（内部 UDP 流承载）。
//
// 线上格式（每条数据报一个包）：
//
//	[16B v6(4in6) 目标地址][2B BE 端口][payload]
//
// 语义（2026-09-19 起 = **按客户端来源固定会话**）：
//   - 客户端一条「会话」= 它到内部流端口的一条 netstack UDP socket；同一会话里所有数据报
//     都指向同一个目标（客户端核按目标建会话）。
//   - 服务端按「客户端来源地址」认会话：**只拨一次**真实 UDP socket，之后双向泵 —— 这是
//     QUIC / 游戏 / 长寿命多应答 UDP 能跑起来的关键（旧版是"一问一答"，多出来的应答被丢）。
//   - 会话空闲 `udpIdle`（默认 60s，与客户端空闲回收对齐）后关闭并回收。
//   - 计数口径（与 TCP 流一致）：`dialok` = 成功建立的真实 UDP socket 数（**每条会话一次**，
//     不是每条应答一次）；`flows` = 当前活着的会话数。

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// ErrDgramMalformed：数据报格式非法（短包/端口 0/地址非法）。
var ErrDgramMalformed = errors.New("flows/udp: 数据报格式非法")

// DefaultUDPIdle：服务端 UDP 会话空闲回收（客户端核默认也是 60s）。
const DefaultUDPIdle = 60 * time.Second

// EncodeDgram 组一条数据报。
func EncodeDgram(dst netip.AddrPort, payload []byte) []byte {
	out := make([]byte, 18+len(payload))
	a := dst.Addr()
	if a.Is4() {
		a = netip.AddrFrom16(a.As16()) // 4in6
	}
	a16 := a.As16()
	copy(out, a16[:])
	binary.BigEndian.PutUint16(out[16:], dst.Port())
	copy(out[18:], payload)
	return out
}

// DecodeDgram 解一条数据报。
func DecodeDgram(b []byte) (netip.AddrPort, []byte, error) {
	if len(b) < 18 {
		return netip.AddrPort{}, nil, ErrDgramMalformed
	}
	var a16 [16]byte
	copy(a16[:], b[:16])
	addr := netip.AddrFrom16(a16).Unmap()
	port := binary.BigEndian.Uint16(b[16:18])
	if port == 0 || !addr.IsValid() {
		return netip.AddrPort{}, nil, ErrDgramMalformed
	}
	return netip.AddrPortFrom(addr, port), b[18:], nil
}

// UDPOption：UDP 中继的可选项。
type UDPOption func(*udpRelay)

// UDPConn：中继里"到真实目标"的那条通道。直连 = *net.UDPConn（可绑物理网卡），
// 经代理 = SOCKS5 UDP 关联（pkg/proxy 的实现）。两者接口一致，中继本体不感知差别。
type UDPConn interface {
	WriteToUDPAddrPort(p []byte, dst netip.AddrPort) (int, error)
	ReadFromUDPAddrPort(p []byte) (int, netip.AddrPort, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

// sockNetworkFor：目标家族 → socket 网络（"udp4"/"udp6"）。
func sockNetworkFor(dst netip.AddrPort) string {
	if dst.IsValid() && dst.Addr().Unmap().Is6() {
		return "udp6"
	}
	return "udp4"
}

type udpRelay struct {
	// targetMap：目标地址映射（测试/特殊部署用；把逻辑目标换成本机可达地址）。
	targetMap func(netip.AddrPort) netip.AddrPort
	// newSock：给每个会话开一条到目标的通道（出口用 = 绑卡直连或经代理；nil = 系统默认直连）。
	// 入参是该会话的目标地址（工厂按家族建 udp4/udp6）。
	newSock func(netip.AddrPort) (UDPConn, error)
	idle      time.Duration
	st        *Stats
	pc        net.PacketConn
	logf      func(format string, args ...any)
	seq       atomic.Uint64

	mu       sync.Mutex
	sessions map[string]*udpSession
}

// WithUDPSocket 注入「按目标开一条通道」的工厂（出口 = 绑物理网卡 / 经 SOCKS5 代理）。
// 不注入时按目标家族用 net.ListenUDP("udp4"/"udp6", nil)（系统默认路由）。
func WithUDPSocket(f func(netip.AddrPort) (UDPConn, error)) UDPOption {
	return func(r *udpRelay) { r.newSock = f }
}

// WithTargetMap 注入目标地址映射（nil = 原样使用；embedding/测试用）。
func WithTargetMap(f func(netip.AddrPort) netip.AddrPort) UDPOption {
	return func(r *udpRelay) { r.targetMap = f }
}

// WithUDPIdle 覆盖会话空闲回收时间（0 = 默认 60s）。
func WithUDPIdle(d time.Duration) UDPOption {
	return func(r *udpRelay) {
		if d > 0 {
			r.idle = d
		}
	}
}

// WithUDPLog 注入日志（出口用；**只在会话建立/关闭各打一行**，逐包细节不在这里）。
// 判据：真机上看「UDP 会话 → :443」存活 + 双向包数增长 ⇒ QUIC 这类长会话真的在跑。
func WithUDPLog(f func(format string, args ...any)) UDPOption {
	return func(r *udpRelay) { r.logf = f }
}

// udpSession 一条已固定的中继会话：客户端来源地址 → 真实 UDP socket。
type udpSession struct {
	conn      UDPConn
	dst       netip.AddrPort
	backTo    net.Addr // 隧道内的客户端来源地址（回投用）
	last      atomic.Int64
	closed    atomic.Bool
	id        uint64
	started   time.Time
	upPkts    atomic.Uint64
	upBytes   atomic.Uint64
	downPkts  atomic.Uint64
	downBytes atomic.Uint64
}

// ServeUDP 在内部 UDP 流端口上做中继。返回停止函数（关闭全部会话）。
func ServeUDP(pc net.PacketConn, st *Stats, opts ...UDPOption) (stop func(), err error) {
	if st == nil {
		st = &Stats{}
	}
	r := &udpRelay{st: st, pc: pc, idle: DefaultUDPIdle, sessions: map[string]*udpSession{}}
	for _, o := range opts {
		o(r)
	}
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				select {
				case <-done:
					return
				default:
					continue
				}
			}
			dst, payload, err := DecodeDgram(buf[:n])
			if err != nil {
				continue
			}
			if r.targetMap != nil {
				dst = r.targetMap(dst)
			}
			r.handle(from, dst, payload)
		}
	}()
	go r.reapLoop(done)
	return func() {
		close(done)
		pc.Close()
		r.closeAll()
	}, nil
}

// handle：按来源取/建会话，然后把这条数据报写进真实 UDP socket。
func (r *udpRelay) handle(from net.Addr, dst netip.AddrPort, payload []byte) {
	key := from.String()
	r.mu.Lock()
	s := r.sessions[key]
	if s != nil && s.dst != dst {
		// 同一来源换了目标：客户端核按目标建会话，正常不该发生；真发生就重建（保守）。
		r.closeLocked(key, s)
		s = nil
	}
	if s == nil {
		// 家族按目标定（v4 → udp4，v6 → udp6）。
		var conn UDPConn
		var err error
		if r.newSock != nil {
			conn, err = r.newSock(dst)
		} else {
			conn, err = net.ListenUDP(sockNetworkFor(dst), nil)
		}
		if err != nil {
			r.mu.Unlock()
			r.st.IncrFail()
			if r.logf != nil {
				r.logf("udp relay: 开会话 socket 失败（→ %v）：%v", dst, err)
			}
			return
		}
		s = &udpSession{conn: conn, dst: dst, backTo: from}
		s.last.Store(time.Now().UnixNano())
		s.id = r.seq.Add(1)
		s.started = time.Now()
		r.sessions[key] = s
		r.st.IncrOK()   // 会话建立 = 一次 dial 成功
		r.st.IncrFlow() // 会话随建立/回收增减，与 TCP 的 flows 同义
		if r.logf != nil {
			r.logf("udp relay: 会话 #%d 建立 %v → %v", s.id, from, dst)
		}
		go r.pumpBack(key, s)
	}
	s.last.Store(time.Now().UnixNano())
	r.mu.Unlock()
	s.upPkts.Add(1)
	s.upBytes.Add(uint64(len(payload)))
	if _, err := s.conn.WriteToUDPAddrPort(payload, dst); err != nil {
		r.st.IncrFail()
		return
	}
}

// pumpBack：真实 UDP socket → 隧道（多条应答都回投；QUIC 依赖这一点）。
func (r *udpRelay) pumpBack(key string, s *udpSession) {
	buf := make([]byte, 65535)
	for {
		if s.closed.Load() {
			return
		}
		_ = s.conn.SetReadDeadline(time.Now().Add(r.idle + 5*time.Second))
		n, src, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue // 交给 reapLoop 决定是否回收
			}
			return
		}
		s.last.Store(time.Now().UnixNano())
		s.downPkts.Add(1)
		s.downBytes.Add(uint64(n))
		_ = r.pc.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, werr := r.pc.WriteTo(EncodeDgram(src, buf[:n]), s.backTo); werr != nil {
			r.st.IncrFail()
		}
	}
}

// reapLoop：定期回收空闲会话。
func (r *udpRelay) reapLoop(done <-chan struct{}) {
	// 节拍随 idle 缩放：idle 很短（测试/特殊部署）时不至于拖到 5s 才回收。
	tick := r.idle / 4
	if tick > 5*time.Second {
		tick = 5 * time.Second
	}
	if tick < 100*time.Millisecond {
		tick = 100 * time.Millisecond
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			now := time.Now()
			r.mu.Lock()
			for k, s := range r.sessions {
				if now.Sub(time.Unix(0, s.last.Load())) > r.idle {
					r.closeLocked(k, s)
				}
			}
			r.mu.Unlock()
		}
	}
}

func (r *udpRelay) closeLocked(key string, s *udpSession) {
	if s.closed.CompareAndSwap(false, true) {
		_ = s.conn.Close()
		r.st.DecrFlow()
		if r.logf != nil {
			r.logf("udp relay: 会话 #%d 关闭 %v → %v（上行 %d 包/%dB，下行 %d 包/%dB，存活 %v）",
				s.id, s.backTo, s.dst, s.upPkts.Load(), s.upBytes.Load(),
				s.downPkts.Load(), s.downBytes.Load(), time.Since(s.started).Round(time.Millisecond))
		}
	}
	delete(r.sessions, key)
}

func (r *udpRelay) closeAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, s := range r.sessions {
		r.closeLocked(k, s)
	}
}
