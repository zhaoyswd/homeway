// Package intercept：出口过境流拦截（openspec l3-exit-intercept）。
//
// 挂在 wgnet 栈上，把「WG 解密后的明文 IP 包」按目的地址分流：
//
//	dst == 隧道IP → 豁免：转投本机 127.0.0.1:同端口（files/term/探测/端口转发 localhost）
//	dst == 其它   → 过境：终结（tcp/udp Forwarder）+ 用本机 socket 重拨
//
// 机制与 xjasonlyu/tun2socks 同款，两个前提（缺一不可，都源码核实过）：
//  1. SetPromiscuousMode(nic, true)：非本机 dst 的包否则在 IP 层被
//     handleValidatedPacket 当 InvalidDestinationAddressesReceived 丢掉；
//     混杂模式让 AcquireAssignedAddress 为外来 dst 建临时端点 → 本地投递。
//  2. 栈必须 HandleLocal:false（见 wgnet.Opts）：混杂模式的临时端点会命中
//     HandlePacket 的源地址自检，把所有外来包当「自己发出的」丢弃。
//
// 注册 SetTransportProtocolHandler 后，netstack 原生 listener 不再收到
// demux 失败的包——所以后端本机服务监听真实 127.0.0.1、靠豁免转投到达
// （历史上兼容期 flows 监听也是这个原因挪出 netstack 的，随 flows 退役已删）。
package intercept

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/zhaoyswd/homeway/pkg/wgnet"
)

const (
	nicID = 1 // wgnet.Create 固定的 NIC id

	defaultMaxConns = 4096
	defaultTCPIdle  = 6 * time.Minute
	defaultUDPIdle  = 60 * time.Second // 与手机侧空闲回收对齐
	defaultDNSIdle  = 10 * time.Second // :53 会话（改写进代答）：一问一答即闲，短回收防挤占会话表（review M4）
	dialTimeout     = 10 * time.Second
	// defaultMaxUDPSessions：与 TCP 的 defaultMaxConns 同量级（保险阀不是整形：
	// 正常使用远达不到，防失控应用把 goroutine/内存打满）。
	defaultMaxUDPSessions = 4096
	// 读粒度：短期限轮转 + 共享活跃时间戳（防「单方向静默误杀长轮询」）。
	readSlice = 30 * time.Second
	bufSize   = 64 << 10
)

// Config：拦截层配置。Dial/ListenUDP 可注入（测试）；nil 用系统默认直连。
type Config struct {
	TunnelIP netip.Addr // 出口隧道 IP（dst == 它 → 豁免转投 127.0.0.1:同端口）
	// DNSPort：DNS 代答监听端口。非 0 时任意目的 :53 改写到 127.0.0.1:DNSPort
	//（dns-host-resolver；0 = 禁用）。
	DNSPort uint16
	// DNSIdle：DNS 会话的空闲回收（默认 10s；测试注入缩短）。
	DNSIdle time.Duration
	// Dial 同时服务 TCP 与 UDP 重拨（udp = Dial("udp", target)，返回已连接 socket）。
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// LocalServices：豁免端口的本机服务承载映射（端口→Unix socket 路径；nil/未命中 =
	// 回环 TCP 同端口）。命中的端口（files/term，openspec exit-service-uds）经 UDS
	// 拨号——主机本地端口零占用、其它本地进程不可达；未命中的豁免端口照旧
	// （PathProbe 死端口拿内核 RST、端口转发的 localhost 目标都不受影响）。
	// 建后不改（dial 时并发读）：服务被摘除时不删条目——socket 文件不存在，
	// 拨号 ENOENT 快速失败回 RST，与「端口没人听」不可区分。
	LocalServices map[uint16]string
	MaxConns      int
	TCPIdle       time.Duration
	UDPIdle       time.Duration
	// MaxUDPSessions：UDP 会话上限（0 = 默认 4096）。TCP 有 MaxConns 保险阀，
	// UDP 每会话 3 goroutine + 端点 + 双向缓冲——失控应用按五元组洪水时同样
	// 需要闸（review 2026-09-21：原先 UDP 无闸，与 TCP 不对称）。超限返回
	// false = 未处理，netstack 按「无监听」回 ICMP 不可达（客户端快速失败）。
	MaxUDPSessions int
	Logf           func(format string, args ...any)
}

// Interceptor：挂在 wgnet 栈上的过境流拦截层。Close 收全部会话。
type Interceptor struct {
	cfg   Config
	net   *wgnet.Net
	st    *Stats
	seq   atomic.Uint64 // UDP 会话编号（日志口径对齐旧 udp relay）
	conns atomic.Int64

	closeOnce sync.Once
	closed    chan struct{}

	// udpSess：活跃/在建 UDP 会话表（五元组键）。建端点必须在分发路径之外
	// （同步在 demux 里建会死锁——锁重入）；**在建窗口内到达的同五元组包
	// 进 pending 队列、端点就绪后重放**——QUIC 首包就是连发多包，直接丢会
	// 丢掉整个连接的早期飞行包（实测：一问多答用例的第二条请求被吞）。
	udpMu   sync.Mutex
	udpSess map[string]bool
	udpPend map[string][][]byte
}

// udpPendingMax：每五元组在建窗口的缓冲上限（超出丢最新）。
const udpPendingMax = 16

// Attach 把拦截层挂到 wgnet 栈上（promiscuous + 双协议 handler）。
// st 允许为 nil（无统计）。返回的 Interceptor随 wgnet 栈生命周期由调用方 Close。
func Attach(n *wgnet.Net, cfg Config, st *Stats) (*Interceptor, error) {
	if !cfg.TunnelIP.IsValid() {
		return nil, fmt.Errorf("intercept: 需要 TunnelIP")
	}
	if cfg.Dial == nil {
		cfg.Dial = (&net.Dialer{Timeout: dialTimeout}).DialContext
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = defaultMaxConns
	}
	if cfg.TCPIdle <= 0 {
		cfg.TCPIdle = defaultTCPIdle
	}
	if cfg.UDPIdle <= 0 {
		cfg.UDPIdle = defaultUDPIdle
	}
	if cfg.MaxUDPSessions <= 0 {
		cfg.MaxUDPSessions = defaultMaxUDPSessions
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	in := &Interceptor{cfg: cfg, net: n, st: st, closed: make(chan struct{}), udpSess: make(map[string]bool), udpPend: make(map[string][][]byte)}

	stack := n.Stack()
	// 两个开关缺一不可（tun2socks 同款）：
	//   promiscuous：非本机 dst 才能本地投递（否则 IP 层按 InvalidDestination 丢）；
	//   spoofing：Forwarder 建端点时 FindRoute 能为「对端源地址」临时建地址端点
	//             （findEndpoint 只认 spoofing，不认 promiscuous；UDP Bind 到外来
	//              dst 也靠它）。开启的前提是栈 HandleLocal:false（见包注释）。
	if err := stack.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("intercept: promiscuous: %v", err)
	}
	if err := stack.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("intercept: spoofing: %v", err)
	}
	tcpFwd := tcp.NewForwarder(stack, 4096 /*rcvWnd*/, 1024 /*maxInFlight*/, in.handleTCP)
	stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	// UDP 不用 udp.NewForwarder：其 handler 签名在 2026-02 快照里变了（返回 bool），
	// 而本项目两端各钉一个快照（homeway=2025-05 / tier 压平=2026-02）——用导出面
	// 一致的 SetTransportProtocolHandler + gonet.DialUDP 自己实现，两版都可编。
	stack.SetTransportProtocolHandler(header.UDPProtocolNumber, in.handleUDPPacket)
	cfg.Logf("intercept: 过境拦截就绪（隧道IP %v；豁免=转投本机同端口；TCP 并发上限 %d）", cfg.TunnelIP, cfg.MaxConns)
	return in, nil
}

// Close：停接收新会话并尽量通知存量会话收工（真正的回收由各自空闲看门狗完成）。
func (in *Interceptor) Close() {
	in.closeOnce.Do(func() { close(in.closed) })
}

// target：原始目的 → 实际重拨目标（豁免映射 + DNS 端口改写，dns-host-resolver）。
//
// DNS 改写：任意目的地址的 :53（TCP/UDP 共用本函数）→ 127.0.0.1:DNSPort。
// 不筛目的地址——应用写死公共 DNS（8.8.8.8 等）的查询同样进代答，否则 v6
// 过滤对这些查询出现泄漏面。不用 53 端口监听：macOS 非 root 绑不上回环
// 特权端口；绑 0.0.0.0:53 则是开放解析器。DNSPort=0 = 禁用改写。
func (in *Interceptor) target(dst netip.AddrPort) (target netip.AddrPort, exempt bool) {
	if in.cfg.DNSPort != 0 && dst.Port() == 53 {
		return netip.AddrPortFrom(loopback4(), in.cfg.DNSPort), true
	}
	if dst.Addr() == in.cfg.TunnelIP {
		return netip.AddrPortFrom(loopback4(), dst.Port()), true
	}
	return dst, false
}

func loopback4() netip.Addr { return netip.MustParseAddr("127.0.0.1") }

// ---------- TCP ----------

func (in *Interceptor) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	dst := netip.AddrPortFrom(tcpAddr(id.LocalAddress), id.LocalPort)
	src := netip.AddrPortFrom(tcpAddr(id.RemoteAddress), id.RemotePort)
	if in.conns.Add(1) > int64(in.cfg.MaxConns) {
		in.conns.Add(-1)
		if in.st != nil {
			in.st.IncrReject()
		}
		in.cfg.Logf("intercept: tcp 拒绝 %v ← %v（并发上限 %d）", dst, src, in.cfg.MaxConns)
		r.Complete(true)
		return
	}
	go in.serveTCP(r, dst, src)
}

func (in *Interceptor) serveTCP(r *tcp.ForwarderRequest, dst, src netip.AddrPort) {
	defer in.conns.Add(-1)
	select {
	case <-in.closed:
		r.Complete(true)
		return
	default:
	}
	target, exempt := in.target(dst)
	kind := "transit"
	if exempt {
		kind = "exempt"
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	var upstream net.Conn
	var err error
	if exempt {
		if sock, ok := in.cfg.LocalServices[dst.Port()]; ok {
			upstream, err = (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}
	}
	if upstream == nil && err == nil {
		upstream, err = in.cfg.Dial(ctx, "tcp", target.String())
	}
	if err != nil {
		if in.st != nil {
			in.st.IncrFail()
		}
		// RST 回给客户端（应用侧表现为 connection refused）。
		r.Complete(true)
		in.cfg.Logf("intercept: tcp %s %v ← %v 拨号失败：%v", kind, target, src, err)
		return
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		// tun2socks 同款：CreateEndpoint 失败也要 Complete(true)——把请求从
		// Forwarder 的 inFlight 摘除并回 RST（漏了会占住 maxInFlight 槽位，
		// review 2026-09-21）。
		r.Complete(true)
		upstream.Close()
		if in.st != nil {
			in.st.IncrFail()
		}
		in.cfg.Logf("intercept: tcp %s %v ← %v 建端点失败：%v", kind, target, src, terr)
		return
	}
	// 必须显式 Complete(false)：把请求从 Forwarder 的 inFlight 摘除并把段的所有权
	// 交给端点（老 wgcore forwardTCP 同款顺序；漏掉会卡后续同四元组的包处理）。
	r.Complete(false)
	ep.SocketOptions().SetDelayOption(false) // 关 Nagle（同 wgnet 监听面）
	downstream := gonet.NewTCPConn(&wq, ep)
	if in.st != nil {
		in.st.IncrOK()
		in.st.IncrFlow()
	}
	in.cfg.Logf("intercept: tcp %s %v ← %v（dialok）", kind, target, src)
	bridgeConns(downstream, upstream, in.cfg.TCPIdle, in.closed)
	if in.st != nil {
		in.st.DecrFlow()
	}
	in.cfg.Logf("intercept: tcp %s %v ← %v 关闭", kind, target, src)
}

// ---------- UDP ----------

// handleUDPPacket：过境 UDP 的包级入口（每条新五元组一次）。
// 端点创建放到 goroutine（同步建会与 demux 锁重入死锁）；窗口期的重复包按
// 五元组表去重。端点注册后同五元组的后续包走 demux、不再进这里。
func (in *Interceptor) handleUDPPacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	select {
	case <-in.closed:
		return true
	default:
	}
	key := fmt.Sprintf("%s:%d→%s:%d", id.RemoteAddress, id.RemotePort, id.LocalAddress, id.LocalPort)
	dst := netip.AddrPortFrom(tcpAddr(id.LocalAddress), id.LocalPort)
	src := netip.AddrPortFrom(tcpAddr(id.RemoteAddress), id.RemotePort)
	payload, ok := udpPayloadOf(pkt)
	if !ok {
		return false
	}
	in.udpMu.Lock()
	if _, sess := in.udpSess[key]; sess {
		// 在建：入队等重放（活跃会话不会走到这里——端点已注册、demux 直接命中）。
		if pend := in.udpPend[key]; len(pend) < udpPendingMax {
			in.udpPend[key] = append(pend, payload)
		}
		in.udpMu.Unlock()
		return true
	}
	if len(in.udpSess) >= in.cfg.MaxUDPSessions {
		in.udpMu.Unlock()
		if in.st != nil {
			in.st.IncrReject()
		}
		in.cfg.Logf("intercept: udp 会话上限 %d 已满，丢 %v ← %v", in.cfg.MaxUDPSessions, dst, src)
		return false // 未处理 → netstack 回 ICMP 不可达，客户端快速失败
	}
	in.udpSess[key] = true
	in.udpMu.Unlock()
	go func() {
		defer in.dropUDP(key)
		in.serveUDP(dst, src, key, payload)
	}()
	return true
}

// takePending 取走在建窗口缓冲的包（端点就绪后由 serveUDP 重放）。
func (in *Interceptor) takePending(key string) [][]byte {
	in.udpMu.Lock()
	pend := in.udpPend[key]
	delete(in.udpPend, key)
	in.udpMu.Unlock()
	return pend
}

func (in *Interceptor) dropUDP(key string) {
	in.udpMu.Lock()
	delete(in.udpSess, key)
	delete(in.udpPend, key)
	in.udpMu.Unlock()
}

func (in *Interceptor) serveUDP(dst, src netip.AddrPort, key string, first []byte) {
	target, exempt := in.target(dst)
	kind := "transit"
	if exempt {
		kind = "exempt"
	}
	// DNS 会话用更短的空闲回收（review M4）：stub resolver 每查询换源端口时
	// :53 五元组会话高频新建，60s 全局 idle 会把 4096 会话表堆满、挤掉非 DNS
	// UDP（QUIC/游戏）。DNS 一问一答即闲，10s 足够覆盖重传窗口。
	idle := in.cfg.UDPIdle
	if in.cfg.DNSPort != 0 && target.Port() == in.cfg.DNSPort && target.Addr() == loopback4() {
		if in.cfg.DNSIdle > 0 {
			idle = in.cfg.DNSIdle
		} else {
			idle = defaultDNSIdle
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	network := "udp4"
	netProto := ipv4.ProtocolNumber
	if target.Addr().Is6() {
		network = "udp6"
		netProto = ipv6.ProtocolNumber
	}
	// 已连接 UDP 端点：本地 = 原目的地址（spoofing 允许绑外来地址），对端 = 原源。
	peer, err := gonet.DialUDP(in.net.Stack(),
		&tcpip.FullAddress{Addr: tcpip.AddrFromSlice(dst.Addr().AsSlice()), Port: dst.Port()},
		&tcpip.FullAddress{Addr: tcpip.AddrFromSlice(src.Addr().AsSlice()), Port: src.Port()},
		netProto)
	if err != nil {
		if in.st != nil {
			in.st.IncrFail()
		}
		in.cfg.Logf("intercept: udp %s %v ← %v 建端点失败：%v", kind, target, src, err)
		return
	}
	real, err := in.cfg.Dial(ctx, network, target.String())
	if err != nil {
		peer.Close()
		if in.st != nil {
			in.st.IncrFail()
		}
		in.cfg.Logf("intercept: udp %s %v ← %v 开 socket 失败：%v", kind, target, src, err)
		return
	}
	// 首包 + 在建窗口的重放（顺序保持：先 first 再 pending）。
	for _, p := range append([][]byte{first}, in.takePending(key)...) {
		if _, werr := real.Write(p); werr != nil {
			peer.Close()
			real.Close()
			if in.st != nil {
				in.st.IncrFail()
			}
			return
		}
	}

	n := in.seq.Add(1)
	if in.st != nil {
		in.st.IncrFlow()
	}
	in.cfg.Logf("udp intercept: 会话 #%d %s 建立（%v ← %v）", n, kind, target, src)

	// 双向逐报泵 + 空闲看门狗（共享活跃时间戳：双向任一有进展即续命，
	// 防单方向静默误杀 QUIC/长轮询型会话）。downSeen：real→peer 方向写过
	// = 这条会话收到过回包（关闭时上报 IncrUDPSession，udpcap 的实测位靠它）。
	var last atomic.Int64
	var downSeen atomic.Bool
	last.Store(time.Now().UnixNano())
	var wg sync.WaitGroup
	var once sync.Once
	done := make(chan struct{})
	finish := func() { once.Do(func() { _ = peer.Close(); _ = real.Close(); close(done) }) }
	pump := func(from net.Conn, to net.Conn) {
		defer wg.Done()
		buf := make([]byte, bufSize)
		for {
			_ = from.SetReadDeadline(time.Now().Add(readSlice))
			nr, err := from.Read(buf)
			if nr > 0 {
				if _, werr := to.Write(buf[:nr]); werr != nil {
					finish()
					return
				}
				if from == real {
					downSeen.Store(true)
				}
				last.Store(time.Now().UnixNano())
			}
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue // 等看门狗决定
				}
				finish()
				return
			}
		}
	}
	watch := func() {
		defer wg.Done()
		// 节拍自适应：idle 短（测试 300ms）时用 idle/3，别等 30s 的读切片。
		interval := readSlice
		if v := idle / 3; v < interval {
			interval = v
		}
		if interval < 20*time.Millisecond {
			interval = 20 * time.Millisecond
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-in.closed:
				finish()
				return
			case <-done: // 泵已退：看门狗同退，别拖 wg.Wait（关闭日志要等 wg.Wait）
				return
			case <-t.C:
				if time.Since(time.Unix(0, last.Load())) > idle {
					finish()
					return
				}
			}
		}
	}
	wg.Add(3)
	go pump(peer, real)
	go pump(real, peer)
	go watch()
	wg.Wait()
	if in.st != nil {
		in.st.DecrFlow()
		in.st.IncrUDPSession(downSeen.Load())
	}
	in.cfg.Logf("udp intercept: 会话 #%d 关闭（%v ← %v）", n, target, src)
}

// ---------- 双向桥（TCP）----------

// bridgeConns：双向 copy；任一方 EOF/错误即双向关闭；idle 内双向无进展才回收
// （共享活跃时间戳——防单方向静默误杀长轮询）。
func bridgeConns(a, b net.Conn, idle time.Duration, closed <-chan struct{}) {
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	var wg sync.WaitGroup
	var once sync.Once
	done := make(chan struct{})
	shutdown := func() {
		once.Do(func() {
			_ = a.Close()
			_ = b.Close()
			close(done)
		})
	}
	pump := func(from, to net.Conn) {
		defer wg.Done()
		buf := make([]byte, bufSize)
		for {
			_ = from.SetReadDeadline(time.Now().Add(readSlice))
			nr, err := from.Read(buf)
			if nr > 0 {
				if _, werr := to.Write(buf[:nr]); werr != nil {
					shutdown()
					return
				}
				last.Store(time.Now().UnixNano())
			}
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					select {
					case <-closed:
						shutdown()
						return
					default:
						continue // 等看门狗决定
					}
				}
				shutdown()
				return
			}
		}
	}
	wg.Add(2)
	go pump(a, b)
	go pump(b, a)
	// 看门狗：idle 内无任何方向进展 → 关。
	watch := func() {
		defer wg.Done()
		interval := readSlice
		if v := idle / 3; v < interval {
			interval = v
		}
		if interval < 20*time.Millisecond {
			interval = 20 * time.Millisecond
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-closed:
				shutdown()
				return
			case <-done: // 泵已退（EOF/错误/对端关）：看门狗同退，别拖 wg.Wait
				return
			case <-t.C:
				if time.Since(time.Unix(0, last.Load())) > idle {
					shutdown()
					return
				}
			}
		}
	}
	wg.Add(1)
	go watch()
	wg.Wait()
}

func tcpAddr(a tcpip.Address) netip.Addr {
	addr, ok := netip.AddrFromSlice(a.AsSlice())
	if !ok {
		return netip.Addr{}
	}
	return addr.Unmap()
}

// udpPayloadOf 从 PacketBuffer 取 UDP 载荷（跨两版 gVisor 的稳定做法：
// ToView 重建整包后按 IPv4 IHL / IPv6 固定头偏移切）。
func udpPayloadOf(pkt *stack.PacketBuffer) ([]byte, bool) {
	whole := pkt.ToView().AsSlice()
	if len(whole) < 28 {
		return nil, false
	}
	var off int
	switch whole[0] >> 4 {
	case 4:
		ihl := int(whole[0]&0xf) * 4
		if ihl < 20 || len(whole) < ihl+8 {
			return nil, false
		}
		off = ihl + 8
	case 6:
		if len(whole) < 48 {
			return nil, false
		}
		off = 40 + 8
	default:
		return nil, false
	}
	if len(whole) < off {
		return nil, false
	}
	return whole[off:], true
}
