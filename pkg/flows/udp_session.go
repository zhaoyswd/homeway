package flows

// 客户端侧的**长活 UDP 会话**（net.Conn）。
//
// 一条会话 = 一个到后端流端口的 socket + 一个固定目标；所有 Write 复用同一条会话，
// 服务端按来源地址把它认成同一条真实 UDP socket（见 ServeUDP 的会话表）。
// 这是 QUIC / 游戏 / 长寿命多应答 UDP 能跑起来的关键：「一问一答」在客户端半边同样不行。
//
// 收工：调用方负责 Close（生产里由空闲回收器统一关，见 tunmode 的 udpIdle）。

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Session 客户端侧长活 UDP 会话。零值不可用，用 OpenSession 构造。
type Session struct {
	pc       net.PacketConn
	flowAddr netip.AddrPort
	dst      netip.AddrPort
	closed   chan struct{}
	once     sync.Once
	deadline atomic.Int64 // unix nano；0 = 无期限
}

// OpenSession 用一条已就绪的 socket 开会话。
// pc 由调用方提供（生产 = 隧道侧 netstack 的 ListenUDP；测试 = 标准库 UdpConn），
// flowAddr = 后端内部 UDP 流端口，dst = 应用要访问的真实目标。
func OpenSession(pc net.PacketConn, flowAddr, dst netip.AddrPort) (*Session, error) {
	if pc == nil {
		return nil, fmt.Errorf("flows: 会话需要一条 UDP socket")
	}
	if !flowAddr.IsValid() {
		return nil, fmt.Errorf("flows: 会话需要内部 UDP 流端口地址")
	}
	if !dst.IsValid() || dst.Port() == 0 {
		return nil, fmt.Errorf("flows: 会话目标 %v 非法", dst)
	}
	s := &Session{pc: pc, flowAddr: flowAddr, dst: dst, closed: make(chan struct{})}
	s.deadline.Store(time.Now().Add(DefaultSessionTimeout).UnixNano())
	return s, nil
}

// DefaultSessionTimeout：会话默认读写期限（调用方通常显式 SetDeadline 覆盖）。
const DefaultSessionTimeout = 10 * time.Second

func (s *Session) Write(p []byte) (int, error) {
	select {
	case <-s.closed:
		return 0, net.ErrClosed
	default:
	}
	_ = s.pc.SetWriteDeadline(s.deadlineTime())
	if _, err := s.pc.WriteTo(EncodeDgram(s.dst, p), net.UDPAddrFromAddrPort(s.flowAddr)); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *Session) Read(p []byte) (int, error) {
	_ = s.pc.SetReadDeadline(s.deadlineTime())
	buf := make([]byte, 65535)
	for {
		n, from, err := s.pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-s.closed:
				return 0, net.ErrClosed
			default:
			}
			return 0, err
		}
		// 只认来自内部流端口的包（同一条 socket 上不该有别的来源）
		if ua, ok := from.(*net.UDPAddr); ok && ua != nil {
			if got := ua.AddrPort(); got.IsValid() && got != s.flowAddr {
				continue
			}
		}
		_, payload, derr := DecodeDgram(buf[:n])
		if derr != nil {
			continue
		}
		return copy(p, payload), nil
	}
}

func (s *Session) Close() error {
	s.once.Do(func() {
		close(s.closed)
		_ = s.pc.Close()
	})
	return nil
}

func (s *Session) deadlineTime() time.Time {
	ns := s.deadline.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

func (s *Session) LocalAddr() net.Addr  { return s.pc.LocalAddr() }
func (s *Session) RemoteAddr() net.Addr { return net.UDPAddrFromAddrPort(s.dst) }

func (s *Session) SetDeadline(t time.Time) error {
	if t.IsZero() {
		s.deadline.Store(0) // 零值 = 无期限（不能存 UnixNano：那是 1754 年的负数）
		return nil
	}
	s.deadline.Store(t.UnixNano())
	return nil
}

func (s *Session) SetReadDeadline(t time.Time) error  { return s.SetDeadline(t) }
func (s *Session) SetWriteDeadline(t time.Time) error { return s.SetDeadline(t) }
