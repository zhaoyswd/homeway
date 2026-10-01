package proto

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// 腿帧格式（协议首版即定型；FIX-91 起**所有腿统一套帧**）：
//
//	客户端→中继 listener: [0xAA][peerId(8B)]‖腿帧
//	其余腿（中继→客户端 / 中继↔后端 / 直连双向）: 腿帧 = [0xBB][type][payload]
//	首个握手包可搭车 reg：容器帧（type=4）内 [reg][data] 两条消息（单数据报保 1 RTT）
//
// 例外（明文控制面，非腿）：STUN 观测与参照点探测（probe）保持裸格式。
// 0xAA/0xBB 魔数与 WG 报文类型（1–4）不冲突。
// type：0=数据（不透明 WG 包）1=控制（hint）2=reg 3=中继控制 4=容器（见下）。
// 接收方 MUST 忽略未知 type 且不中断会话（前向兼容的钩子挂在格式上，不挂在实现节奏上）。
const (
	FrameTypeData    = byte(0)
	FrameTypeControl = byte(1)
	FrameTypeReg     = byte(2)
	// FrameTypeBatch：帧内多消息容器——一个数据报携带多条消息（首个握手包 =
	// [reg][data]：同一数据报内 reg 先于 data 被消费，出口无需等下一包即完成登记，
	// 保 1 RTT）。payload = 消息序列：[type(1)][len(2 BE)][payload]*。
	FrameTypeBatch = byte(4)

	relayTagMagic = byte(0xAA)
	legFrameMagic = byte(0xBB)
)

var ErrFrameMalformed = errors.New("homeway/frame: 帧格式非法")

// RelayID 从后端静态公钥派生中继路由键（peerId 的 8 字节压缩）。
func RelayID(pubkey [32]byte) [8]byte {
	sum := sha256.Sum256(pubkey[:])
	var id [8]byte
	copy(id[:], sum[:8])
	return id
}

// EncodeFrame 生成一条腿上帧（[0xBB][type][payload]）。
func EncodeFrame(typ byte, payload []byte) []byte {
	buf := make([]byte, 0, 2+len(payload))
	buf = append(buf, legFrameMagic, typ)
	return append(buf, payload...)
}

// DecodeFrame 解析腿上帧。未知 type 原样返回、不报错（调用方忽略）。
func DecodeFrame(b []byte) (typ byte, payload []byte, err error) {
	if len(b) < 2 || b[0] != legFrameMagic {
		return 0, nil, ErrFrameMalformed
	}
	return b[1], b[2:], nil
}

// EncodeTagged 生成客户端→中继 listener 帧：[0xAA][peerId(8B)]‖腿帧。
// 中继剥掉前 9 字节路由头后原样转发，后端收到的即无歧义腿帧。
func EncodeTagged(peerID [8]byte, typ byte, payload []byte) []byte {
	return EncodeTaggedFrame(peerID, EncodeFrame(typ, payload))
}

// EncodeTaggedFrame：[0xAA][peerId(8B)]‖已编码腿帧（容器帧等预先编码形态，避免二次套帧）。
func EncodeTaggedFrame(peerID [8]byte, frame []byte) []byte {
	buf := make([]byte, 0, 1+8+len(frame))
	buf = append(buf, relayTagMagic)
	buf = append(buf, peerID[:]...)
	return append(buf, frame...)
}

// DecodeTagged 解析 listener 收到的帧。
func DecodeTagged(b []byte) (peerID [8]byte, typ byte, payload []byte, err error) {
	if len(b) < 11 || b[0] != relayTagMagic || b[9] != legFrameMagic {
		return peerID, 0, nil, ErrFrameMalformed
	}
	copy(peerID[:], b[1:9])
	return peerID, b[10], b[11:], nil
}

// ---------- 容器帧（type=4）----------

// BatchMsg：容器内的一条消息。
type BatchMsg struct {
	Type    byte
	Payload []byte
}

// EncodeBatch 组容器帧（[0xBB][4] + 消息序列 [type][len(2BE)][payload]*）。
// 调用方保证每条 payload ≤ 65535 字节（数据面 MTU 远小于此；reg 报文 <1KB）。
func EncodeBatch(msgs ...BatchMsg) []byte {
	size := 2
	for _, m := range msgs {
		size += 3 + len(m.Payload)
	}
	buf := make([]byte, 0, size)
	buf = append(buf, legFrameMagic, FrameTypeBatch)
	for _, m := range msgs {
		buf = append(buf, m.Type, byte(len(m.Payload)>>8), byte(len(m.Payload)))
		buf = append(buf, m.Payload...)
	}
	return buf
}

// DecodeBatch 解容器帧的 payload 段（DecodeFrame 返回的 payload）为消息序列。
func DecodeBatch(payload []byte) ([]BatchMsg, error) {
	var out []BatchMsg
	for len(payload) > 0 {
		if len(payload) < 3 {
			return nil, ErrFrameMalformed
		}
		n := int(payload[1])<<8 | int(payload[2])
		if 3+n > len(payload) {
			return nil, ErrFrameMalformed
		}
		out = append(out, BatchMsg{Type: payload[0], Payload: payload[3 : 3+n]})
		payload = payload[3+n:]
	}
	if len(out) == 0 {
		return nil, ErrFrameMalformed
	}
	return out, nil
}

// ---------- 控制子协议：hint（对端观察地址，不可信线索） ----------
//
// control payload: [len(2B BE)][addr]

// EncodeHint 生成 hint 控制帧（腿上帧）。
func EncodeHint(addr string) []byte {
	p := make([]byte, 2+len(addr))
	binary.BigEndian.PutUint16(p, uint16(len(addr)))
	copy(p[2:], addr)
	return EncodeFrame(FrameTypeControl, p)
}

// DecodeHintPayload 解析 control 帧 payload（不含 0xBB/type 头）里的地址。
func DecodeHintPayload(payload []byte) (addr string, err error) {
	if len(payload) < 2 {
		return "", ErrFrameMalformed
	}
	n := int(binary.BigEndian.Uint16(payload))
	if n == 0 || 2+n != len(payload) {
		return "", ErrFrameMalformed
	}
	return string(payload[2 : 2+n]), nil
}

// DecodeHint 解析整条 hint 帧（EncodeHint 的逆）。
func DecodeHint(frame []byte) (addr string, err error) {
	typ, payload, err := DecodeFrame(frame)
	if err != nil {
		return "", err
	}
	if typ != FrameTypeControl {
		return "", fmt.Errorf("%w: 非 control 帧", ErrFrameMalformed)
	}
	return DecodeHintPayload(payload)
}
