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
	closed    chan struct{} // 停收新流（Close 与 Drain 都关；Drain 下在途 TCP 继续承载）
	tdOnce    sync.Once
	teardown  chan struct{} // 杀在途 TCP（仅 Close 关——Drain 不关，宽限语义靠它）

	// reg：在途 TCP 过境连接登记表（role-management 2.1，r1 中-5——serve stop
	// 的有界宽限收尾用）。Close 只是标记停收新流；Drain 在此基础上等存量
	// 过境连接自然收销账、到期未收的按登记逐条 SetLinger(0) RST。豁免腿
	// （files/term 的 UDS 转投）不登记——它们随本机服务收口（D5 步骤②）。
	regMu sync.Mutex
	reg   map[*regEntry]struct{}

	// udpSess：活跃/在建 UDP 会话表（五元组键）。建端点必须在分发路径之外
	// （同步在 demux 里建会死锁——锁重入）；**在建窗口内到达的同五元组包
	// 进 pending 队列、端点就绪后重放**——QUIC 首包就是连发多包，直接丢会
	// 丢掉整个连接的早期飞行包（实测：一问多答用例的第二条请求被吞）。
	udpMu   sync.Mutex
	udpSess map[string]bool
	udpPend map[string][][]byte
}

// regEntry 一条在途 TCP 过境连接的登记（upstream = 重拨出的本机 socket）。
type regEntry struct {
	conn net.Conn
	done chan struct{} // bridgeConns 返回（自然收尾）后关闭
}

// lingerSetter 可 RST 收口的本机 socket（*net.TCPConn 与测试注入的包装 conn）。
type lingerSetter interface {
	SetLinger(sec int) error
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
	in := &Interceptor{cfg: cfg, net: n, st: st, closed: make(chan struct{}), teardown: make(chan struct{}), udpSess: make(map[string]bool), udpPend: make(map[string][][]byte), reg: make(map[*regEntry]struct{})}

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

// Close：停接收新会话并**通知存量会话收工**（在途 TCP 由 teardown 立即拆、
// UDP 由各自看门狗看到 closed 后即刻终结；真正的回收由各自空闲看门狗兜底）。
// 与 Drain 的分界：Close 是「全停即刻拆」，Drain 是「停新流 + 存量 TCP 宽限承载」。
func (in *Interceptor) Close() {
	in.HaltNew()
	in.tdOnce.Do(func() { close(in.teardown) })
}

// HaltNew：只停新流（D5 步骤①——新 WG 握手/新过境流被拒，在途 TCP 不受影响）。
// Close 与 Drain 都含这一步（幂等）。
func (in *Interceptor) HaltNew() {
	in.closeOnce.Do(func() { close(in.closed) })
}

// Drain：停收新流（不拆在途）+ 在途 TCP 过境连接**有界宽限**收尾（role-management
// 2.1/2.3，design D5 / r1 中-5）：宽限内自然收尾的销账（继续承载双向数据——teardown
// 未关，泵只认空闲与错误）；到期未收的按登记逐条 SetLinger(0) 后 Close = RST 强制关
// （对齐 3e socks off 的教训：优雅 FIN 会让对端静默挂住）。UDP 无收尾概念、即刻终结
// （closed 一关，各自看门狗 finish）。返回到期仍在途（被 RST）的连接数。
func (in *Interceptor) Drain(grace time.Duration) int {
	in.HaltNew()
	deadline := time.Now().Add(grace)
	for {
		if in.regLen() == 0 {
			return 0
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	n := 0
	for _, e := range in.regSnapshot() {
		if tc, ok := e.conn.(lingerSetter); ok {
			_ = tc.SetLinger(0) // 0 = Close 时直接 RST，不发 FIN
		}
		_ = e.conn.Close()
		n++
	}
	// RST 触发泵退出是异步的：有界等销账完成（收尾序判据「Drain 返回 = 过境面已收」
	// 的近似；净空窗口毫秒级）。
	outDeadline := time.Now().Add(2 * time.Second)
	for in.regLen() > 0 && time.Now().Before(outDeadline) {
		time.Sleep(10 * time.Millisecond)
	}
	in.cfg.Logf("intercept: 过境宽限收尾——到期仍 在途 %d 条过境 TCP 连接已 RST", n)
	return n
}

// regAdd / regRemove / regSnapshot / regLen：登记表操作（serveTCP 的 transit 分支）。
func (in *Interceptor) regAdd(c net.Conn) *regEntry {
	e := &regEntry{conn: c, done: make(chan struct{})}
	in.regMu.Lock()
	in.reg[e] = struct{}{}
	in.regMu.Unlock()
	return e
}

func (in *Interceptor) regRemove(e *regEntry) {
	if e == nil {
		return
	}
	in.regMu.Lock()
	delete(in.reg, e)
	in.regMu.Unlock()
	close(e.done) // Drain 的销账信号（幂等性由「每 entry 只 remove 一次」保证）
}

func (in *Interceptor) regSnapshot() []*regEntry {
	in.regMu.Lock()
	defer in.regMu.Unlock()
	out := make([]*regEntry, 0, len(in.reg))
	for e := range in.reg {
		out = append(out, e)
	}
	return out
}

func (in *Interceptor) regLen() int {
	in.regMu.Lock()
	defer in.regMu.Unlock()
	return len(in.reg)
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
	// 过境连接登记（r1 中-5）：Drain 的宽限收尾按登记销账/RST；豁免腿不登记。
	var ent *regEntry
	if !exempt {
		ent = in.regAdd(upstream)
	}
	bridgeConns(downstream, upstream, in.cfg.TCPIdle, in.teardown)
	in.regRemove(ent)
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
	peer, err := dialUDPShared(in.net.Stack(),
		tcpip.FullAddress{Addr: tcpip.AddrFromSlice(dst.Addr().AsSlice()), Port: dst.Port()},
		tcpip.FullAddress{Addr: tcpip.AddrFromSlice(src.Addr().AsSlice()), Port: src.Port()},
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
	// = 这条会话收到过回包（关闭时上报 IncrUDPSession，udpcap 的实测位靠它；
	// 豁免/本机回环会话不报——它们不走真实转发路径，掺进去会让 udpcap 的
	// 「实测有回包」恒真（DNS 代答每查询必回包），掏空这个位的含义）。
	var last atomic.Int64
	var downSeen atomic.Bool
	last.Store(time.Now().UnixNano())
	var wg sync.WaitGroup
	var once sync.Once
	done := make(chan struct{})
	finish := func() { once.Do(func() { _ = peer.Close(); _ = real.Close(); close(done) }) }
	// isReal 显式传参而不是比较 from == real：net.Conn 是接口，若将来注入的
	// Dial 返回带不可比较字段的实现，接口比较会运行期 panic。
	pump := func(from net.Conn, to net.Conn, isReal bool) {
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
				if isReal {
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
	go pump(peer, real, false)
	go pump(real, peer, true)
	go watch()
	wg.Wait()
	if in.st != nil {
		in.st.DecrFlow()
		if !exempt {
			in.st.IncrUDPSession(downSeen.Load())
		}
	}
	in.cfg.Logf("udp intercept: 会话 #%d 关闭（%v ← %v）", n, target, src)
}

// dialUDPShared：与 gonet.DialUDP 同流程（本地 = spoof 的原目的地址、对端 = 原源），
// 唯一差别是 Bind 前开 SO_REUSEADDR/SO_REUSEPORT——同一 (dst,port) 的并发五元组
// 会话都要绑同一个「本地=原目的地址:端口」：stub resolver 每查询换源端口、QUIC
// 多条连接打同一目的地址，都是这个形态。不共享则第二条流起 bind EADDRINUSE、
// 整条流被丢（2026-09-23 实测：手机 DNS 建会话 96% 失败，每个新域名熬解析器
// 多轮超时，出口侧 bind udp <隧道IP>:53: port is in use 十分钟刷 503 次）。
// 共享的 demux 正确性由 Connect 后按全四元组注册保证（各流的端点互不抢占）。
// 「出口自己不在 netstack 里监听 UDP」⇒ 不存在与不设 reuse 的端点互斥的来源，
// 共享语义只属于本函数创建的 spoof 端点。
func dialUDPShared(s *stack.Stack, local, remote tcpip.FullAddress, netProto tcpip.NetworkProtocolNumber) (*gonet.UDPConn, error) {
	var wq waiter.Queue
	ep, terr := s.NewEndpoint(header.UDPProtocolNumber, netProto, &wq)
	if terr != nil {
		return nil, fmt.Errorf("new endpoint: %v", terr)
	}
	so := ep.SocketOptions()
	so.SetReuseAddress(true)
	so.SetReusePort(true)
	if terr := ep.Bind(local); terr != nil {
		ep.Close()
		return nil, fmt.Errorf("bind udp %v: %v", fullAddrPort(local), terr)
	}
	if terr := ep.Connect(remote); terr != nil {
		ep.Close()
		return nil, fmt.Errorf("connect udp %v: %v", fullAddrPort(remote), terr)
	}
	return gonet.NewUDPConn(&wq, ep), nil
}

func fullAddrPort(a tcpip.FullAddress) string {
	addr, ok := netip.AddrFromSlice(a.Addr.AsSlice())
	if !ok {
		return fmt.Sprintf(":%d", a.Port)
	}
	return netip.AddrPortFrom(addr.Unmap(), a.Port).String()
}

// ---------- 双向桥（TCP）----------

// bridgeConns：双向 copy；任一方 EOF/错误即双向关闭；idle 内双向无进展才回收
// （共享活跃时间戳——防单方向静默误杀长轮询）。teardown（仅 Close 关）触发立即
// 拆——Drain 的「停新流」不经过这里，在途连接在宽限内继续承载。
func bridgeConns(a, b net.Conn, idle time.Duration, teardown <-chan struct{}) {
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
					case <-teardown:
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
			case <-teardown:
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
