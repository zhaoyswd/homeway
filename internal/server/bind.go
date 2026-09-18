package server

import (
	"fmt"
	"net"
	"net/netip"
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

	c *net.UDPConn
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
	c, err := net.ListenUDP("udp4", &net.UDPAddr{Port: int(port)})
	if err != nil {
		return nil, 0, err
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
