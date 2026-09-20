// Package wgnet：Homeway 自有的 netstack glue（wireguard-go tun/netstack 同构的精简版）。
//
// 为什么不用 wireguard-go 的 tun/netstack：它不暴露 *stack.Stack，而我们需要逐端点
// 关 Nagle（栈级 `TCPDelayEnabled(false)` 在 gVisor 此快照里是单向 no-op：只在 true 时
// SetDelayOption(true)，见 FINDINGS #10）。流协议是「几字节的行 + 小 JSON」这种
// 请求/响应步进式交互，Nagle 与对端延迟 ACK 叠加会给每一步加数十毫秒——
// **这是延迟优化，不是正确性前提**（2026-09-19 实测：Nagle 开/关两种状态集成测试都通过；
// 此前「小段死锁」的判读实为测试读长写错，见 FINDINGS #10 更正与 #11）。
package wgnet

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Net：兼具 tun.Device（交给 wireguard-go device）与拨号/监听面（gVisor gonet）。
type Net struct {
	ep       *channel.Endpoint
	stack    *stack.Stack
	events   chan tun.Event
	incoming chan *buffer.View
	notify   *channel.NotificationHandle
	mtu      int
}

// Opts：CreateOpts 的可选项。HandleLocal 见 gVisor stack.Options 同名项——
// **过境拦截侧必须关**：开了会把「混杂模式下临时端点覆盖源地址检查」变成
// 所有外来包都被判成 martian 丢弃（ipv4.HandlePacket 的 HandleLocal 分支）。
type Opts struct {
	HandleLocal bool
}

// Create 装配 netstack：SACK 开、Nagle 关（手机侧默认形态，HandleLocal 开）。
func Create(localAddresses []netip.Addr, mtu int) (tun.Device, *Net, error) {
	return CreateOpts(localAddresses, mtu, Opts{HandleLocal: true})
}

// CreateOpts：带选项装配（出口过境拦截侧用 HandleLocal:false）。
func CreateOpts(localAddresses []netip.Addr, mtu int, opts Opts) (tun.Device, *Net, error) {
	n := &Net{
		ep: channel.New(1024, uint32(mtu), ""),
		stack: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
			HandleLocal:        opts.HandleLocal,
		}),
		events:   make(chan tun.Event, 10),
		incoming: make(chan *buffer.View),
		mtu:      mtu,
	}
	sack := tcpip.TCPSACKEnabled(true)
	if err := n.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return nil, nil, fmt.Errorf("wgnet: SACK: %v", err)
	}
	// 关键差异：Nagle 关（对开 gVisor 栈的小段死锁，见包注释）。
	noDelay := tcpip.TCPDelayEnabled(false)
	if err := n.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &noDelay); err != nil {
		return nil, nil, fmt.Errorf("wgnet: TCPDelay: %v", err)
	}
	n.notify = n.ep.AddNotify(n)
	if err := n.stack.CreateNIC(1, n.ep); err != nil {
		return nil, nil, fmt.Errorf("wgnet: CreateNIC: %v", err)
	}
	hasV4, hasV6 := false, false
	for _, ip := range localAddresses {
		proto := ipv6.ProtocolNumber
		if ip.Is4() {
			proto = ipv4.ProtocolNumber
			hasV4 = true
		} else {
			hasV6 = true
		}
		addr := tcpip.ProtocolAddress{
			Protocol:          proto,
			AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix(),
		}
		if err := n.stack.AddProtocolAddress(1, addr, stack.AddressProperties{}); err != nil {
			return nil, nil, fmt.Errorf("wgnet: AddProtocolAddress(%v): %v", ip, err)
		}
	}
	if hasV4 {
		n.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	}
	if hasV6 {
		n.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})
	}
	n.events <- tun.EventUp
	return n, n, nil
}

// WriteNotify 实现 channel.Notification（协议栈有出站包时投递给 device 的 tun.Read）。
func (n *Net) WriteNotify() {
	pkt := n.ep.Read()
	if pkt == nil {
		return
	}
	view := pkt.ToView()
	pkt.DecRef()
	n.incoming <- view
}

// ---------- tun.Device（给 wireguard-go 的 NewDevice） ----------

func (n *Net) Name() (string, error)    { return "wgnet", nil }
func (n *Net) File() *os.File           { return nil }
func (n *Net) Events() <-chan tun.Event { return n.events }

func (n *Net) Read(buf [][]byte, sizes []int, offset int) (int, error) {
	view, ok := <-n.incoming
	if !ok {
		return 0, os.ErrClosed
	}
	sz, err := view.Read(buf[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = sz
	return 1, nil
}

func (n *Net) Write(buf [][]byte, offset int) (int, error) {
	for _, b := range buf {
		packet := b[offset:]
		if len(packet) == 0 {
			continue
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		switch packet[0] >> 4 {
		case 4:
			n.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		case 6:
			n.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
		default:
			return 0, syscall.EAFNOSUPPORT
		}
	}
	return len(buf), nil
}

func (n *Net) Close() error {
	n.stack.RemoveNIC(1)
	n.stack.Close()
	n.ep.RemoveNotify(n.notify)
	n.ep.Close()
	close(n.events)
	close(n.incoming)
	return nil
}

func (n *Net) MTU() (int, error) { return n.mtu, nil }

func (n *Net) BatchSize() int   { return 1 }

// Stack 暴露底层 gVisor 栈（过境拦截层挂 SetTransportProtocolHandler 用；
// 别处不要绕过 Net 的拨号/监听面直接操作栈）。
func (n *Net) Stack() *stack.Stack { return n.stack }

// ---------- 拨号/监听面（自管端点：每个 TCP 端点逐个关 Nagle） ----------
//
// gVisor 此快照的栈级 TCPDelayEnabled 是单向的（endpoint.go:910 只在 true 时
// SetDelayOption(true)，false 被无视）⇒ 必须逐端点关。

func (n *Net) DialTCPAddrPort(addr netip.AddrPort) (*gonet.TCPConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return n.DialTCPAddrPortCtx(ctx, addr)
}

// DialTCPAddrPortCtx：可取消的拨号（取消/超时即时关端点，不给上层留悬挂 socket）。
func (n *Net) DialTCPAddrPortCtx(ctx context.Context, addr netip.AddrPort) (*gonet.TCPConn, error) {
	fa, netProto := fullAddr(addr)
	var wq waiter.Queue
	ep, err := n.stack.NewEndpoint(tcp.ProtocolNumber, netProto, &wq)
	if err != nil {
		return nil, fmt.Errorf("wgnet: NewEndpoint: %v", err)
	}
	ep.SocketOptions().SetDelayOption(false)

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.WritableEvents)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	err = ep.Connect(fa)
	if _, ok := err.(*tcpip.ErrConnectStarted); ok {
		select {
		case <-notifyCh:
		case <-ctx.Done():
			ep.Close()
			return nil, fmt.Errorf("wgnet: connect 取消: %w", ctx.Err())
		}
		err = ep.LastError()
	}
	if err != nil {
		ep.Close()
		return nil, fmt.Errorf("wgnet: connect: %v", err)
	}
	return gonet.NewTCPConn(&wq, ep), nil
}

// Listener：net.Listener 实现，Accept 出的每个连接都关 Nagle。
type Listener struct {
	ep     tcpip.Endpoint
	wq     *waiter.Queue
	cancel chan struct{}
	once   sync.Once
}

func (n *Net) ListenTCPAddrPort(addr netip.AddrPort) (*Listener, error) {
	fa, netProto := fullAddr(addr)
	var wq waiter.Queue
	ep, err := n.stack.NewEndpoint(tcp.ProtocolNumber, netProto, &wq)
	if err != nil {
		return nil, fmt.Errorf("wgnet: NewEndpoint: %v", err)
	}
	if err := ep.Bind(fa); err != nil {
		ep.Close()
		return nil, fmt.Errorf("wgnet: bind: %v", err)
	}
	if err := ep.Listen(4096); err != nil {
		ep.Close()
		return nil, fmt.Errorf("wgnet: listen: %v", err)
	}
	return &Listener{ep: ep, wq: &wq, cancel: make(chan struct{})}, nil
}

func (l *Listener) Accept() (net.Conn, error) {
	n, wq, err := l.ep.Accept(nil)
	if _, ok := err.(*tcpip.ErrWouldBlock); ok {
		waitEntry, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
		l.wq.EventRegister(&waitEntry)
		defer l.wq.EventUnregister(&waitEntry)
		for {
			n, wq, err = l.ep.Accept(nil)
			if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
				break
			}
			select {
			case <-l.cancel:
				return nil, fmt.Errorf("wgnet: listener 已关闭")
			case <-notifyCh:
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("wgnet: accept: %v", err)
	}
	n.SocketOptions().SetDelayOption(false)
	return gonet.NewTCPConn(wq, n), nil
}

func (l *Listener) Close() error {
	l.ep.Close()
	l.once.Do(func() { close(l.cancel) })
	return nil
}

func (l *Listener) Addr() net.Addr {
	a, _ := l.ep.GetLocalAddress()
	return &net.TCPAddr{IP: net.IP(a.Addr.AsSlice()), Port: int(a.Port)}
}

// ListenUDPAddrPort：未连接（监听型）UDP socket —— 可以 ReadFrom/WriteTo 任意对端。
// ⚠️ raddr 必须传 nil：传 &FullAddress{} 会把 socket「连接」到 0.0.0.0:0，
// 之后 WriteTo 的目标被忽略 ⇒ 数据报无声消失（上游 netstack.ListenUDPAddrPort 就是传 nil）。
func (n *Net) ListenUDPAddrPort(addr netip.AddrPort) (*gonet.UDPConn, error) {
	fa, netProto := fullAddr(addr)
	return gonet.DialUDP(n.stack, &fa, nil, netProto)
}

// DialUDPAddrPort：已连接 UDP socket（固定对端，读写不需要地址；对称于 gonet.DialUDP）。
func (n *Net) DialUDPAddrPort(laddr, raddr netip.AddrPort) (*gonet.UDPConn, error) {
	fa, netProto := fullAddr(laddr)
	ra, _ := fullAddr(raddr)
	return gonet.DialUDP(n.stack, &fa, &ra, netProto)
}

func fullAddr(ap netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	proto := ipv6.ProtocolNumber
	if ap.Addr().Is4() {
		proto = ipv4.ProtocolNumber
	}
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(ap.Addr().AsSlice()), Port: ap.Port()}, proto
}
