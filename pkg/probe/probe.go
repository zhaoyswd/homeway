// Package probe：参照点探测（wg-native-stack tasks 3.6）。
//
// 为什么需要它：全部候选失败时，客户端要能区分三档 —— ①本机/睡眠问题 ②链路（中继）问题
// ③后端问题。WG 握手本身给不出这种归因（它只会「没响应」），所以在**同一个 UDP 端口**上
// 加一层极小的明文探测：
//
//	请求:  "HWQ" ‖ ver(1) ‖ type(1) ‖ nonce(8) ‖ 填充…        （≥16B）
//	响应:  "HWR" ‖ ver(1) ‖ type(1) ‖ nonce(8) ‖ payload
//	type=1 ping：payload = buildLen(1) ‖ build（长度 ≤32；空 = 未提供）——纯回声 + 构建标记
//	type=2 hint：payload = 16B v6(4in6) 地址 ‖ 2B BE 端口 = **后端看到的客户端源地址**
//
// 语义要点：
//   - 探测**不参与**数据面：不进 WG、不登记 peer、不碰任何会话状态；只回答「这个地址的 UDP
//     能不能来回」以及「我在对端眼里是哪个地址」。
//   - 明文是有意的：它就是可达性判据，不含任何密钥材料；响应恒 ≤ 请求 + 45B（不做放大器）。
//   - 未知 type / 短包一律忽略（前向兼容）。
//
// 魔数与既有判别不冲突：0xBB=腿帧、'H'+'R'=reg 搭车、WG 类型 1–4，这里用 'H'+'W'+'Q'/'R'。
package probe

import (
	"context"
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
	Type  byte
	Nonce [8]byte
	Build string
	Seen  netip.AddrPort // type=hint：后端看到的客户端源地址
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
// src = 后端看到的来源地址（type=hint 回给客户端自己的 NAT 映射）。
func Respond(req []byte, src netip.AddrPort, build string) []byte {
	r, err := DecodeRequest(req)
	if err != nil {
		return nil
	}
	out := make([]byte, 0, 48)
	out = append(out, respMagic[:]...)
	out = append(out, Version, r.Type)
	out = append(out, r.Nonce[:]...)
	switch r.Type {
	case TypePing:
		if build == "" {
			out = append(out, 0)
			return out
		}
		if len(build) > maxBuild {
			build = build[:maxBuild]
		}
		out = append(out, byte(len(build)))
		out = append(out, build...)
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

// Ping 一问一答（可达性 + RTT + 对端构建标记）。
func Ping(ctx context.Context, pc net.PacketConn, target netip.AddrPort, build string) (time.Duration, string, error) {
	nonce := randomNonce()
	req := EncodeRequest(TypePing, nonce, 16)
	start := time.Now()
	raw, err := roundTrip(ctx, pc, target, req, TypePing, nonce)
	if err != nil {
		return 0, "", err
	}
	resp, err := DecodeResponse(raw, TypePing, nonce)
	if err != nil {
		return 0, "", err
	}
	return time.Since(start), resp.Build, nil
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
			if got := ua.AddrPort(); got.IsValid() && got != target {
				continue // 不是这个参照点的回应：丢弃
			}
		}
		if _, err := DecodeResponse(buf[:n], typ, nonce); err != nil {
			continue
		}
		return buf[:n], nil
	}
}

func randomNonce() [8]byte {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(time.Now().UnixNano()))
	return n
}
