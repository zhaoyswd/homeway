package servercore

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/zhaoyswd/homeway/pkg/probe"
	"github.com/zhaoyswd/homeway/pkg/proto"
	"golang.zx2c4.com/wireguard/conn"
)

// nowTime 可注入时钟（测试用）。
var nowTime = time.Now

// ServerBind：homewayd 的 conn.Bind。与客户端 wtransport 对称但无赛跑逻辑：
// 监听固定端口，收包按首字节无歧义判别三种形态——
//
//	[0xBB]…      腿帧（来自中继分配 socket）：0=数据入 device / 1=hint 回调 / 2=reg / 未知=忽略
//	"HR"…‖WG     直连 reg 搭车（SplitDirectReg 拆分，先登记后投递）
//	其余          直连裸 WG
//
// Send 恒裸发（对端 endpoint 是中继分配地址或客户端直连地址，两者都收裸 WG；
// 中继负责把回程包包装成腿帧发回客户端）。
type ServerBind struct {
	Port   uint16
	Table  *PeerTable
	Build  string            // 探测应答里回报的构建标记（就绪行/排障用）
	OnHint func(addr string) // 中继观察到的客户端公网地址（打洞用，阶段 6）
	Logf   func(format string, args ...any)
	// BindAddr 非零时把 UDP socket 绑到这张网卡的地址上：
	// ① 出站走该接口（绕开 TUN 型代理抢默认路由，旧栈的 `--bind-interface=physical`）；
	// ② STUN 观测到的才是**这个 socket** 在路由器上的真实映射。
	BindAddr netip.Addr
	// BindIface 非空时**双栈**监听并整条 socket 钉在该网卡上（v4+v6 一起）：
	// 这就是出口同时服务 IPv4/IPv6 客户端的形态；比只绑一个地址更通用（v6 地址会轮换）。
	BindIface *net.Interface

	c        *net.UDPConn
	stunMu   sync.Mutex
	stunWait *stunPending
	pinMu    sync.Mutex
	pinned   *net.Interface // 当前实际钉住的网卡（Open 时设置，Repin 时更新）
}

// Repin 按**名字**重新解析网卡并把它重新钉到当前 socket 上（换网/接口索引变化后调用）。
// 没配 BindIface 时是 no-op（返回 nil, nil）。
//
// 为什么按名字重解析：接口索引会变（Wi-Fi 关开、换网），老的 index 会让 socket 钉在一个
// 不存在的网卡上 —— 表现是"隧道还在、包发不出去"。名字是稳定的。
func (b *ServerBind) Repin() (*net.Interface, error) {
	cfg := b.BindIface
	if cfg == nil {
		return nil, nil
	}
	ifi, err := net.InterfaceByName(cfg.Name)
	if err != nil {
		return nil, fmt.Errorf("server: 网卡 %s 当前不可用: %w", cfg.Name, err)
	}
	c := b.c
	if c == nil {
		return nil, fmt.Errorf("server: socket 还没打开")
	}
	b.pinMu.Lock()
	defer b.pinMu.Unlock()
	if err := pinSocketToIface(c, ifi); err != nil {
		return nil, err
	}
	b.pinned = ifi
	return ifi, nil
}

// PinnedIface 当前钉住的网卡（没绑卡时 nil）。
func (b *ServerBind) PinnedIface() *net.Interface {
	b.pinMu.Lock()
	defer b.pinMu.Unlock()
	return b.pinned
}

// stunPending 一次在飞的 STUN 查询（接收路径匹配事务 ID 后把结果投给它）。
type stunPending struct {
	txid [12]byte
	ch   chan netip.AddrPort
}

// srvEP：服务端视角的真实地址端点（device 的 SetEndpointFromPacket 原生语义即可用）。
type srvEP struct{ ap netip.AddrPort }

func (e srvEP) ClearSrc()           {}
func (e srvEP) SrcToString() string { return "unset" }
func (e srvEP) DstToString() string { return e.ap.String() }
func (e srvEP) DstToBytes() []byte {
	b, _ := e.ap.Addr().MarshalBinary()
	p := uint16(e.ap.Port())
	return append(b, byte(p), byte(p>>8))
}
func (e srvEP) DstIP() netip.Addr { return e.ap.Addr() }
func (e srvEP) SrcIP() netip.Addr { return netip.Addr{} }

func (b *ServerBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	// 网络族：默认**双栈**（v4 + v6），这样出口既能被 IPv4 客户端连，也能被 IPv6 客户端连，
	// 且同一个 socket 上做 STUN 观测对两族都成立。显式绑地址时按该地址的族走单栈。
	network := "udp"
	laddr := &net.UDPAddr{Port: int(port)}
	if b.BindAddr.IsValid() {
		laddr.IP = b.BindAddr.AsSlice()
		if b.BindAddr.Is4() {
			network = "udp4"
		} else {
			network = "udp6"
		}
	}
	c, err := net.ListenUDP(network, laddr)
	if err != nil {
		return nil, 0, err
	}
	if b.BindIface != nil {
		if err := pinSocketToIface(c, b.BindIface); err != nil {
			_ = c.Close()
			return nil, 0, fmt.Errorf("server: 绑定网卡 %s 失败: %w", b.BindIface.Name, err)
		}
		b.pinMu.Lock()
		b.pinned = b.BindIface
		b.pinMu.Unlock()
	} else if laddr.IP != nil {
		// 绑了源地址还要把 socket 钉在该网卡上（见 pinSocketToIface 的注释）：
		// 否则默认路由被 TUN 型代理抢走时，STUN 观测到的是代理的映射而不是路由器上的真实映射。
		if ip, ok := netip.AddrFromSlice(laddr.IP); ok {
			if ifi := ifaceForAddr(ip.Unmap()); ifi != nil {
				if err := pinSocketToIface(c, ifi); err != nil {
					_ = c.Close()
					return nil, 0, fmt.Errorf("server: 绑定网卡 %s 失败: %w", ifi.Name, err)
				}
			}
		}
	}
	b.c = c
	actual := uint16(c.LocalAddr().(*net.UDPAddr).Port)
	fn := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, src, err := c.ReadFromUDPAddrPort(packets[0])
		if err != nil {
			return 0, err
		}
		if src.Addr().Is4In6() {
			src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		}
		buf := packets[0][:n]

		// STUN 观测：只认事务 ID 匹配的应答，消耗掉不进 device（见 STUNQuery）。
		if stunLooksLikeResponse(buf) {
			if b.deliverSTUN(buf) {
				return 0, nil
			}
		}

		// 参照点探测（tasks 3.6）：明文一问一答，不进 WG、不登记 peer、不碰会话状态。
		// 客户端在「全部候选失败」时用它做三档归因（本机 / 链路 / 后端）。
		if resp := probe.Respond(buf, src, b.Build); resp != nil {
			_, _ = c.WriteToUDPAddrPort(resp, src)
			return 0, nil
		}

		if len(buf) > 0 && buf[0] == 0xBB {
			typ, payload, err := proto.DecodeFrame(buf)
			if err != nil {
				return 0, nil // 畸形腿帧：丢弃不中断（fn 返回 0 会继续被调用）
			}
			switch typ {
			case proto.FrameTypeData:
				sizes[0] = len(payload)
				copy(packets[0], payload)
				eps[0] = srvEP{src}
				return 1, nil
			case proto.FrameTypeReg:
				if _, err := b.Table.Register(payload, nowTime()); err != nil {
					b.logf("reg 腿帧验证失败（来源 %v）：%v", src, err)
				}
				return 0, nil
			case proto.FrameTypeControl:
				if b.OnHint != nil {
					if addr, err := proto.DecodeHintPayload(payload); err == nil {
						b.OnHint(addr)
					}
				}
				return 0, nil
			default:
				return 0, nil // 未知类型：忽略（前向兼容）
			}
		}

		if reg, rest, ok := proto.SplitDirectReg(buf); ok {
			if _, err := b.Table.Register(reg, nowTime()); err != nil {
				b.logf("reg 搭车验证失败（来源 %v）：%v", src, err)
				return 0, nil
			}
			sizes[0] = len(rest)
			copy(packets[0], rest)
			eps[0] = srvEP{src}
			return 1, nil
		}

		// 直连裸 WG
		sizes[0] = n
		eps[0] = srvEP{src}
		return 1, nil
	}
	return []conn.ReceiveFunc{fn}, actual, nil
}

func (b *ServerBind) Close() error {
	if b.c == nil {
		return nil
	}
	return b.c.Close()
}

// deliverSTUN 把 STUN 应答交给等待者（事务 ID 匹配才认）。返回 true = 已被消耗。
func (b *ServerBind) deliverSTUN(pkt []byte) bool {
	b.stunMu.Lock()
	w := b.stunWait
	if w == nil {
		b.stunMu.Unlock()
		return false
	}
	ap, ok := stunParseBindingResponse(pkt, w.txid)
	if !ok {
		b.stunMu.Unlock()
		return false // 事务 ID 不匹配：不是我们要的应答，照常交给 device（不会有害）
	}
	b.stunWait = nil
	b.stunMu.Unlock()
	select {
	case w.ch <- ap:
	default:
	}
	return true
}

// LocalPort 返回实际监听的 UDP 端口（Open 之后有效；0 = 还没开）。
func (b *ServerBind) LocalPort() uint16 {
	if b.c == nil {
		return 0
	}
	return uint16(b.c.LocalAddr().(*net.UDPAddr).Port)
}

// STUNQuery 在**本 Bind 的 UDP socket** 上问一次 STUN 服务器「你看到的我是什么地址」（IPv4 路径）。
// 拿到的是「监听端口这个 socket」的 NAT 映射（同一 socket 收发，端口不受源端口改写影响）。
func (b *ServerBind) STUNQuery(ctx context.Context, server string) (netip.AddrPort, error) {
	return b.stunQuery(ctx, server, false)
}

// STUNQueryV6 同 STUNQuery，但走 IPv6：用来确认「双栈 socket 的 v6 路径可用」，
// 并拿到服务器看到的 v6 地址（v6 无 NAT，应当等于本机全局地址）。
func (b *ServerBind) STUNQueryV6(ctx context.Context, server string) (netip.AddrPort, error) {
	return b.stunQuery(ctx, server, true)
}

func (b *ServerBind) stunQuery(ctx context.Context, server string, want6 bool) (netip.AddrPort, error) {
	if b.c == nil {
		return netip.AddrPort{}, fmt.Errorf("server: bind 尚未 Open")
	}
	host, portStr, err := net.SplitHostPort(server)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("解析 STUN 服务器 %q: %w", server, err)
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("STUN 服务器端口 %q: %w", portStr, err)
	}
	network := "ip4"
	if want6 {
		network = "ip6"
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, network, host)
	if err != nil || len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("解析 STUN 服务器 %q 的 %s: %w", server, network, err)
	}
	rap := ips[0]
	if want6 {
		if !rap.Is6() || rap.Is4In6() {
			return netip.AddrPort{}, fmt.Errorf("STUN 服务器 %q 没有可用的 IPv6 地址", server)
		}
	} else {
		if rap = rap.Unmap(); !rap.Is4() {
			return netip.AddrPort{}, fmt.Errorf("STUN 服务器 %q 没有可用的 IPv4 地址", server)
		}
	}
	target := netip.AddrPortFrom(rap, uint16(port))

	var txid [12]byte
	if _, err := rand.Read(txid[:]); err != nil {
		return netip.AddrPort{}, err
	}
	w := &stunPending{txid: txid, ch: make(chan netip.AddrPort, 1)}
	b.stunMu.Lock()
	b.stunWait = w // 同一时刻只允许一次查询（轮询周期都是分钟级）
	b.stunMu.Unlock()
	defer func() {
		b.stunMu.Lock()
		if b.stunWait == w {
			b.stunWait = nil
		}
		b.stunMu.Unlock()
	}()

	if _, err := b.c.WriteToUDPAddrPort(stunBindingRequest(txid), target); err != nil {
		return netip.AddrPort{}, fmt.Errorf("发 STUN 请求: %w", err)
	}
	select {
	case ap := <-w.ch:
		return ap, nil
	case <-ctx.Done():
		return netip.AddrPort{}, fmt.Errorf("等 STUN 应答: %w", ctx.Err())
	}
}

func (b *ServerBind) SetMark(mark uint32) error { return nil }

func (b *ServerBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(srvEP)
	if !ok {
		return fmt.Errorf("server: 未知 endpoint 类型 %T", ep)
	}
	for _, buf := range bufs {
		if _, err := b.c.WriteToUDPAddrPort(buf, e.ap); err != nil {
			return err
		}
	}
	return nil
}

func (b *ServerBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return srvEP{ap}, nil
}

func (b *ServerBind) BatchSize() int { return 1 }

func (b *ServerBind) logf(format string, args ...any) {
	if b.Logf != nil {
		b.Logf(format, args...)
	}
}
