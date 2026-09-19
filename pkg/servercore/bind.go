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

	c        *net.UDPConn
	stunMu   sync.Mutex
	stunWait *stunPending
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
	laddr := &net.UDPAddr{Port: int(port)}
	if b.BindAddr.IsValid() && b.BindAddr.Is4() {
		laddr.IP = b.BindAddr.AsSlice()
	}
	c, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		return nil, 0, err
	}
	if laddr.IP != nil {
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

// STUNQuery 在**本 Bind 的 UDP socket** 上问一次 STUN 服务器「你看到的我是什么地址」。
// 拿到的是「监听端口这个 socket」的 NAT 映射（同一 socket 收发，端口不受源端口改写影响）。
func (b *ServerBind) STUNQuery(ctx context.Context, server string) (netip.AddrPort, error) {
	if b.c == nil {
		return netip.AddrPort{}, fmt.Errorf("server: bind 尚未 Open")
	}
	raddr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("解析 STUN 服务器 %q: %w", server, err)
	}
	rap, ok := netip.AddrFromSlice(raddr.IP)
	if !ok || !rap.Is4() {
		if rap = rap.Unmap(); !rap.Is4() {
			return netip.AddrPort{}, fmt.Errorf("STUN 服务器 %q 不是 IPv4", server)
		}
	}
	target := netip.AddrPortFrom(rap, uint16(raddr.Port))

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
