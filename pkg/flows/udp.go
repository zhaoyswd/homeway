package flows

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// UDP 数据报编解码（内部 UDP 流承载，DNS 先行）：
//
//	[16B v6(4in6) 地址][2B BE 端口][payload]
//
// v1 语义：每请求一报一 socket、等单个应答（10s）后关闭——面向 DNS 类查询；
// QUIC 类长寿命 UDP 会话需要 pin 池，记为后续项（对齐旧栈 S19 的同样取舍）。
var ErrDgramMalformed = errors.New("flows/udp: 数据报格式非法")

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

func DecodeDgram(b []byte) (netip.AddrPort, []byte, error) {
	if len(b) < 19 {
		return netip.AddrPort{}, nil, ErrDgramMalformed
	}
	var a16 [16]byte
	copy(a16[:], b[:16])
	addr := netip.AddrFrom16(a16).Unmap()
	port := binary.BigEndian.Uint16(b[16:18])
	if port == 0 || !addr.IsValid() {
		return netip.AddrPort{}, nil, fmt.Errorf("%w: 端口/地址非法", ErrDgramMalformed)
	}
	return netip.AddrPortFrom(addr, port), b[18:], nil
}

// UDPOption：UDP 中继的可选项。
type UDPOption func(*udpRelay)

type udpRelay struct {
	// targetMap：目标地址映射（测试/特殊部署用；把逻辑目标换成本机可达地址）。
	targetMap func(netip.AddrPort) netip.AddrPort
}

// WithTargetMap 注入目标地址映射（nil = 原样使用；embedding/测试用）。
func WithTargetMap(f func(netip.AddrPort) netip.AddrPort) UDPOption {
	return func(r *udpRelay) { r.targetMap = f }
}

// ServeUDP 在内部 UDP 流端口上做逐报中继（拨真实目标、等单应答、回投）。
// 返回停止函数。writeBack 超时 5s。
func ServeUDP(pc net.PacketConn, st *Stats, opts ...UDPOption) (stop func(), err error) {
	if st == nil {
		st = &Stats{}
	}
	relay := &udpRelay{}
	for _, o := range opts {
		o(relay)
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
			if relay.targetMap != nil {
				dst = relay.targetMap(dst)
			}
			go relayOne(pc, from, dst, payload, st)
		}
	}()
	return func() { close(done); pc.Close() }, nil
}

func relayOne(pc net.PacketConn, backTo net.Addr, dst netip.AddrPort, payload []byte, st *Stats) {
	c, err := net.ListenUDP("udp", nil)
	if err != nil {
		return
	}
	defer c.Close()
	if _, err := c.WriteToUDPAddrPort(payload, dst); err != nil {
		st.IncrFail()
		return
	}
	if err := c.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return
	}
	buf := make([]byte, 65535)
	n, src, err := c.ReadFromUDPAddrPort(buf)
	if err != nil {
		st.IncrFail()
		return
	}
	st.IncrOK()
	pc.SetWriteDeadline(time.Now().Add(5 * time.Second))
	pc.WriteTo(EncodeDgram(src, buf[:n]), backTo)
}
