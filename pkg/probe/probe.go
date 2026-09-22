// Package probe：参照点探测（wg-native-stack tasks 3.6；端点列表段 = endpoint-freshness）。
//
// 为什么需要它：全部候选失败时，客户端要能区分三档 —— ①本机/睡眠问题 ②链路（中继）问题
// ③后端问题。WG 握手本身给不出这种归因（它只会「没响应」），所以在**同一个 UDP 端口**上
// 加一层极小的明文探测：
//
//	请求:  "HWQ" ‖ ver(1) ‖ type(1) ‖ nonce(8) ‖ 填充…        （≥16B）
//	响应:  "HWR" ‖ ver(1) ‖ type(1) ‖ nonce(8) ‖ payload
//	type=1 ping：payload = buildLen(1) ‖ build（长度 ≤32；空 = 未提供）‖ flags(1，可省)
//	             ‖ epCount(1，可省) ‖ epCount × [16B v6(4in6) 地址 ‖ 2B BE 端口]
//	             ——纯回声 + 构建标记 + **出口能力位**（bit0 = 出口默认路径可承载 UDP，
//	             见 server.UDPCapFlag）+ **端点列表段**（endpoint-freshness：出口当前可
//	             公布的公网端点；手机侧旁路探测由此持续保鲜学习缓存）。尾部逐段追加 ⇒
//	             老客户端只读前段，不受影响。
//	type=2 hint：payload = 16B v6(4in6) 地址 ‖ 2B BE 端口 = **后端看到的客户端源地址**
//
// 语义要点：
//   - 探测**不参与**数据面：不进 WG、不登记 peer、不碰任何会话状态；只回答「这个地址的 UDP
//     能不能来回」以及「我在对端眼里是哪个地址」。
//   - 明文是有意的：它就是可达性判据，不含任何密钥材料；响应恒 ≤ 请求 + 45B（不做放大器）。
//     **端点列表段不破坏这条不变量**：只有「带列表的应答总长 ≤ 请求长度」才附列表——请求方
//     把请求 pad 到它愿意接收的长度（新客户端探测前 pad ~200B），老请求方（pad 16）自然
//     拿不到列表段，45B 不变量照旧。
//   - nonce 用 crypto/rand：应答携带手机当候选用的端点数据，可预测 nonce（旧实现 UnixNano）
//     会让盲注入/串答成为可能（endpoint-freshness 评审 C-10）。
//   - 未知 type / 短包一律忽略（前向兼容）。
//
// 魔数与既有判别不冲突：0xBB=腿帧、'H'+'R'=reg 搭车、WG 类型 1–4，这里用 'H'+'W'+'Q'/'R'。
package probe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// 协议常量。
const (
	Version   = 1
	TypePing  = byte(1)
	TypeHint  = byte(2)
	minReqLen = 16
	maxBuild  = 32
	// MaxEndpoints：端点列表段的上限（出口与消费侧同此约束；8 × 18B + 1B 计数 ≈ 145B）。
	MaxEndpoints = 8
)

var (
	reqMagic  = [3]byte{'H', 'W', 'Q'}
	respMagic = [3]byte{'H', 'W', 'R'}

	ErrNotProbe   = errors.New("probe: 不是探测包")
	ErrProbeShort = errors.New("probe: 包太短")
)

// Request 一个探测请求。
type Request struct {
	Type  byte
	Nonce [8]byte
}

// Response 探测响应。
type Response struct {
	Type      byte
	Nonce     [8]byte
	Build     string
	Flags     byte              // 出口能力位（type=ping；老出口不回这一段 ⇒ 0）
	Seen      netip.AddrPort    // type=hint：后端看到的客户端源地址
	Endpoints []netip.AddrPort  // type=ping：出口端点列表段（老出口无此段 ⇒ nil）
}

// EncodeRequest 组请求（pad 为填充长度，建议 16 ⇒ 总长 40B）。
func EncodeRequest(typ byte, nonce [8]byte, pad int) []byte {
	if pad < 0 {
		pad = 0
	}
	out := make([]byte, 13+pad)
	copy(out[0:3], reqMagic[:])
	out[3] = Version
	out[4] = typ
	copy(out[5:13], nonce[:])
	return out
}

// DecodeRequest 解析请求；不是探测包返回 ErrNotProbe（调用方据此放行给数据面）。
func DecodeRequest(b []byte) (Request, error) {
	if len(b) < 3 || [3]byte{b[0], b[1], b[2]} != reqMagic {
		return Request{}, ErrNotProbe
	}
	if len(b) < minReqLen {
		return Request{}, ErrProbeShort
	}
	if b[3] != Version {
		return Request{}, fmt.Errorf("probe: 版本 %d 不支持", b[3])
	}
	req := Request{Type: b[4]}
	copy(req.Nonce[:], b[5:13])
	return req, nil
}

// Respond 处理一个可能为探测包的数据报：是探测且可应答 ⇒ 返回响应字节；否则 nil。
// src = 后端看到的来源地址（type=hint 回给客户端自己的 NAT 映射）；flags 见 Response.Flags。
// 无端点列表的旧形态（=RespondEx endpoints=nil），保留给不需要列表的调用方与测试。
func Respond(req []byte, src netip.AddrPort, build string, flags byte) []byte {
	return RespondEx(req, src, build, flags, nil)
}

// RespondEx：Respond + 端点列表段（endpoint-freshness）。
//
// pad 契约（防放大，MUST）：只有「带列表的应答总长 ≤ 请求长度」才附列表——请求方以 pad 后的
// 长度声明可收上限；老请求方（pad 16，总长 29B）自然拿不到列表段，45B 不变量保持。
// endpoints 超上限截断到 MaxEndpoints；非法条目（无效地址/零端口）跳过。
func RespondEx(req []byte, src netip.AddrPort, build string, flags byte, endpoints []netip.AddrPort) []byte {
	r, err := DecodeRequest(req)
	if err != nil {
		return nil
	}
	base := respondBase(r, src, build, flags)
	if base == nil {
		return nil
	}
	if r.Type != TypePing || len(endpoints) == 0 {
		return base
	}
	// 列表段（与 flags 同款「尾部追加」）：计数(1) + N × 18B（16B v6(4in6) 地址 + 2B BE 端口）。
	var list []netip.AddrPort
	for _, ep := range endpoints {
		if len(list) >= MaxEndpoints {
			break
		}
		if !ep.IsValid() || ep.Port() == 0 {
			continue
		}
		list = append(list, ep)
	}
	if len(list) == 0 {
		return base
	}
	withList := append([]byte(nil), base...)
	withList = append(withList, byte(len(list)))
	for _, ep := range list {
		a := ep.Addr()
		if a.Is4() {
			a = netip.AddrFrom16(a.As16()) // 4in6：与 TypeHint 同一 18B 编码范式
		}
		a16 := a.As16()
		withList = append(withList, a16[:]...)
		var port [2]byte
		binary.BigEndian.PutUint16(port[:], ep.Port())
		withList = append(withList, port[:]...)
	}
	if len(withList) > len(req) {
		return base // 请求没 pad 够：不带列表（老客户端形态），防放大约束优先
	}
	return withList
}

// respondBase：不带列表段的应答（type 分派 + 回声 nonce；未知类型返回 nil）。
func respondBase(r Request, src netip.AddrPort, build string, flags byte) []byte {
	out := make([]byte, 0, 48)
	out = append(out, respMagic[:]...)
	out = append(out, Version, r.Type)
	out = append(out, r.Nonce[:]...)
	switch r.Type {
	case TypePing:
		if build == "" {
			out = append(out, 0, flags)
			return out
		}
		if len(build) > maxBuild {
			build = build[:maxBuild]
		}
		out = append(out, byte(len(build)))
		out = append(out, build...)
		out = append(out, flags)
		return out
	case TypeHint:
		if !src.IsValid() {
			return nil
		}
		a := src.Addr()
		if a.Is4() {
			a = netip.AddrFrom16(a.As16())
		}
		a16 := a.As16()
		out = append(out, a16[:]...)
		var port [2]byte
		binary.BigEndian.PutUint16(port[:], src.Port())
		out = append(out, port[:]...)
		return out
	default:
		return nil // 未知类型：忽略
	}
}

// DecodeResponse 解析响应；magic/nonce 不符返回错误（调用方丢弃）。
func DecodeResponse(b []byte, wantType byte, nonce [8]byte) (Response, error) {
	if len(b) < 13 || [3]byte{b[0], b[1], b[2]} != respMagic {
		return Response{}, ErrNotProbe
	}
	if b[3] != Version || b[4] != wantType {
		return Response{}, fmt.Errorf("probe: 响应版本/类型不符（%d/%d）", b[3], b[4])
	}
	var got [8]byte
	copy(got[:], b[5:13])
	if got != nonce {
		return Response{}, errors.New("probe: nonce 不匹配")
	}
	resp := Response{Type: b[4], Nonce: got}
	payload := b[13:]
	switch wantType {
	case TypePing:
		if len(payload) > 0 {
			n := int(payload[0])
			if n > len(payload)-1 {
				return Response{}, ErrProbeShort
			}
			resp.Build = string(payload[1 : 1+n])
			// flags 追加在 build 之后（老出口没有这一段 ⇒ 保持 0）
			rest := payload[1+n:]
			if len(rest) > 0 {
				resp.Flags = rest[0]
				rest = rest[1:]
			}
			// 端点列表段追加在 flags 之后（endpoint-freshness；老出口没有这一段 ⇒ nil）。
			if len(rest) > 0 {
				cnt := int(rest[0])
				if cnt > MaxEndpoints {
					return Response{}, fmt.Errorf("probe: 端点列表条数超上限（%d > %d）", cnt, MaxEndpoints)
				}
				if len(rest) < 1+cnt*18 {
					return Response{}, ErrProbeShort
				}
				for i := 0; i < cnt; i++ {
					e := rest[1+i*18 : 1+i*18+18]
					var a16 [16]byte
					copy(a16[:], e[:16])
					addr := netip.AddrFrom16(a16).Unmap()
					port := binary.BigEndian.Uint16(e[16:18])
					if !addr.IsValid() || port == 0 {
						return Response{}, ErrProbeShort
					}
					resp.Endpoints = append(resp.Endpoints, netip.AddrPortFrom(addr, port))
				}
			}
		}
	case TypeHint:
		if len(payload) < 18 {
			return Response{}, ErrProbeShort
		}
		var a16 [16]byte
		copy(a16[:], payload[:16])
		addr := netip.AddrFrom16(a16).Unmap()
		port := binary.BigEndian.Uint16(payload[16:18])
		if !addr.IsValid() || port == 0 {
			return Response{}, ErrProbeShort
		}
		resp.Seen = netip.AddrPortFrom(addr, port)
	}
	return resp, nil
}

// Ping 一问一答（可达性 + RTT + 对端构建标记）。旧签名保留（pad 16 = 拿不到端点列表）。
func Ping(ctx context.Context, pc net.PacketConn, target netip.AddrPort, build string) (time.Duration, string, byte, error) {
	res, err := PingEx(ctx, pc, target, build, 16)
	return res.RTT, res.Build, res.Flags, err
}

// PingResult：PingEx 的完整应答（含端点列表段——请求 pad 够长才有；老出口 ⇒ nil）。
type PingResult struct {
	RTT       time.Duration
	Build     string
	Flags     byte
	Endpoints []netip.AddrPort
}

// PingEx：Ping + 端点列表（endpoint-freshness）。pad 是请求填充长度——要拿列表就得把请求
// pad 到期望最大应答长度（列表满配 8 条时 ≈ 基础应答 + 1 + 8×18；建议 200）。
func PingEx(ctx context.Context, pc net.PacketConn, target netip.AddrPort, build string, pad int) (PingResult, error) {
	nonce := randomNonce()
	req := EncodeRequest(TypePing, nonce, pad)
	start := time.Now()
	raw, err := roundTrip(ctx, pc, target, req, TypePing, nonce)
	if err != nil {
		return PingResult{}, err
	}
	resp, err := DecodeResponse(raw, TypePing, nonce)
	if err != nil {
		return PingResult{}, err
	}
	return PingResult{RTT: time.Since(start), Build: resp.Build, Flags: resp.Flags, Endpoints: resp.Endpoints}, nil
}

// Hint 问「我在你眼里是哪个地址」（NAT 映射观察；打洞与三档归因共用）。
func Hint(ctx context.Context, pc net.PacketConn, target netip.AddrPort) (netip.AddrPort, time.Duration, error) {
	nonce := randomNonce()
	req := EncodeRequest(TypeHint, nonce, 16)
	start := time.Now()
	raw, err := roundTrip(ctx, pc, target, req, TypeHint, nonce)
	if err != nil {
		return netip.AddrPort{}, 0, err
	}
	resp, err := DecodeResponse(raw, TypeHint, nonce)
	if err != nil {
		return netip.AddrPort{}, 0, err
	}
	return resp.Seen, time.Since(start), nil
}

func roundTrip(ctx context.Context, pc net.PacketConn, target netip.AddrPort, req []byte, typ byte, nonce [8]byte) ([]byte, error) {
	if dl, ok := ctx.Deadline(); ok {
		_ = pc.SetDeadline(dl)
	} else {
		_ = pc.SetDeadline(time.Now().Add(3 * time.Second))
	}
	if _, err := pc.WriteTo(req, net.UDPAddrFromAddrPort(target)); err != nil {
		return nil, err
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return nil, err
		}
		if ua, ok := from.(*net.UDPAddr); ok && ua != nil {
			// 双栈 socket 上，回包来源可能是 4-in-6 形式——比较前归一，否则 IPv4 目标永远匹配不上
			//（实测：客户端监听 [::]、目标是 127.0.0.1 时，回包来源是 ::ffff:127.0.0.1）。
			if got := ua.AddrPort(); got.IsValid() && !sameAddr(got, target) {
				continue // 不是这个参照点的回应：丢弃
			}
		}
		if _, err := DecodeResponse(buf[:n], typ, nonce); err != nil {
			continue
		}
		return buf[:n], nil
	}
}

// sameAddr：地址+端口比较，4-in-6 与 IPv4 视为同一（netip.AddrPort 没有 Unmap 方法）。
func sameAddr(a, b netip.AddrPort) bool {
	return a.Port() == b.Port() && a.Addr().Unmap() == b.Addr().Unmap()
}

// randomNonce：crypto/rand（应答携带端点列表数据，可预测 nonce 会让盲注入/串答成为可能；
// rand 失败的极端形态退回时间戳——探测本身仍能工作）。
func randomNonce() [8]byte {
	var n [8]byte
	if _, err := rand.Read(n[:]); err != nil {
		binary.BigEndian.PutUint64(n[:], uint64(time.Now().UnixNano()))
	}
	return n
}
