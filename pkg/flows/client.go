// 内部流协议的客户端半边（wg-native-stack tasks 2.4）。
//
// 与 ServeTCP/ServeUDP 同包：协议两端在一起，改一处不会漂移。刻意**不依赖 gvisor/gonet**——
// 传输只是一个函数接口，手机核里传 wgnet 的适配器，单测里传标准库 net.Dialer。
//
// 语义：
//   - TCP：一条命令一条流。Connect 拨后端隧道内的流端口 → 写 CONNECT 行 → 等 OK/ERR；
//     OK 之后返回的 net.Conn 保留 bufio 里可能读到的多余字节（否则会吞掉首批载荷）。
//   - UDP：一问一答（DNS 语义）。每条请求开一个独立 socket（与服务端「一报一 socket」对称，
//     用源端口做天然的多路复用键），等一个应答后关闭。
package flows

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// ConnectTimeout：CONNECT 往返（不含之后的数据管道）的默认期限。
const ConnectTimeout = 10 * time.Second

// DatagramTimeout：一问一答的默认期限（DNS 场景）。
const DatagramTimeout = 10 * time.Second

// TCPDialFunc：拨隧道内 TCP（生产 = wgnet.DialTCPAddrPortCtx 适配）。
type TCPDialFunc func(ctx context.Context, addr netip.AddrPort) (net.Conn, error)

// UDPOpenFunc：开一个未连接的 UDP socket（生产 = wgnet.ListenUDPAddrPort(local)）。
// 返回的 PacketConn 的源地址即该 socket 的本地地址（客户端隧道地址）。
type UDPOpenFunc func() (net.PacketConn, error)

// Client 内部流协议客户端。FlowAddr / UDPFlowAddr 是后端隧道内的两个服务端口。
type Client struct {
	FlowAddr    netip.AddrPort
	UDPFlowAddr netip.AddrPort
	DialTCP     TCPDialFunc
	OpenUDP     UDPOpenFunc
}

// Connect 建一条内部流并把 CONNECT 目标送过去；成功返回可直接读写的管道。
// 远端以 ERR <code> 拒绝时返回 *RemoteError（code 供上层中文归因）。
func (c *Client) Connect(ctx context.Context, host string, port uint16) (net.Conn, error) {
	if c.DialTCP == nil {
		return nil, errors.New("flows: Client.DialTCP 未配置")
	}
	if _, has := ctx.Deadline(); !has {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, ConnectTimeout)
		defer cancel()
	}
	conn, err := c.DialTCP(ctx, c.FlowAddr)
	if err != nil {
		return nil, fmt.Errorf("flows: 拨流端口 %v 失败: %w", c.FlowAddr, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if err := WriteConnect(conn, host, port); err != nil {
		conn.Close()
		return nil, fmt.Errorf("flows: 写 CONNECT 失败: %w", err)
	}
	br := bufio.NewReader(conn)
	if err := ReadResponse(br); err != nil {
		conn.Close()
		return nil, err // 已是 *RemoteError 或读错误
	}
	_ = conn.SetDeadline(time.Time{}) // 之后的数据管道由调用方控制期限
	return &bufConn{Conn: conn, r: br}, nil
}

// Datagram 一问一答：把 [dst‖payload] 发往后端 UDP 流端口，返回应答来源与载荷。
func (c *Client) Datagram(ctx context.Context, dst netip.AddrPort, payload []byte) (netip.AddrPort, []byte, error) {
	if c.OpenUDP == nil {
		return netip.AddrPort{}, nil, errors.New("flows: Client.OpenUDP 未配置")
	}
	if !c.UDPFlowAddr.IsValid() {
		return netip.AddrPort{}, nil, errors.New("flows: Client.UDPFlowAddr 未配置")
	}
	pc, err := c.OpenUDP()
	if err != nil {
		return netip.AddrPort{}, nil, fmt.Errorf("flows: 开 UDP socket 失败: %w", err)
	}
	defer pc.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(DatagramTimeout)
	}
	_ = pc.SetDeadline(deadline)
	if _, err := pc.WriteTo(EncodeDgram(dst, payload), net.UDPAddrFromAddrPort(c.UDPFlowAddr)); err != nil {
		return netip.AddrPort{}, nil, fmt.Errorf("flows: 数据报发送失败: %w", err)
	}
	buf := make([]byte, 65535)
	n, from, err := pc.ReadFrom(buf)
	if err != nil {
		return netip.AddrPort{}, nil, fmt.Errorf("flows: 数据报应答未达: %w", err)
	}
	if ua, ok := from.(*net.UDPAddr); ok && ua != nil {
		if got := ua.AddrPort(); got.IsValid() && got != c.UDPFlowAddr {
			return netip.AddrPort{}, nil, fmt.Errorf("flows: 应答来源 %v 非流端口 %v", got, c.UDPFlowAddr)
		}
	}
	src, body, err := DecodeDgram(buf[:n])
	if err != nil {
		return netip.AddrPort{}, nil, err
	}
	return src, body, nil
}

// bufConn：把「读过一行的 bufio.Reader」接回 net.Conn，避免吞掉已读进缓冲的载荷。
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// CloseWrite / CloseRead：包装层必须转发可选接口，否则半关闭会在这一层静默失效
// （FINDINGS #21：flows 的空闲回收包装吞过同样的亏；表现是对端永远等不到 EOF，双方互等）。
func (b *bufConn) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (b *bufConn) CloseRead() error {
	if cr, ok := b.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}
