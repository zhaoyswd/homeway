package proto

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// 中继链路帧格式（协议首版即定型，无论中继功能何时实现）：
//
//	客户端→中继 listener: [0xAA][peerId(8B)][type(1B)][payload]
//	其余腿（中继→客户端 / 中继↔后端）: [0xBB][type(1B)][payload]
//	直连（客户端→后端，无帧）: 裸 WG；首个握手可前缀 reg 报文（"HR" 开头，单数据报）
//
// 0xAA/0xBB 魔数与 WG 报文类型（1–4）不冲突，直连路径可无歧义判别。
// type：0=数据（不透明 WG 包）1=控制（hint）2=reg。接收方 MUST 忽略未知 type
// 且不中断会话（前向兼容的钩子挂在格式上，不挂在实现节奏上）。
const (
	FrameTypeData    = byte(0)
	FrameTypeControl = byte(1)
	FrameTypeReg     = byte(2)

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
	buf := make([]byte, 0, 1+8+2+len(payload))
	buf = append(buf, relayTagMagic)
	buf = append(buf, peerID[:]...)
	buf = append(buf, legFrameMagic, typ)
	return append(buf, payload...)
}

// DecodeTagged 解析 listener 收到的帧。
func DecodeTagged(b []byte) (peerID [8]byte, typ byte, payload []byte, err error) {
	if len(b) < 11 || b[0] != relayTagMagic || b[9] != legFrameMagic {
		return peerID, 0, nil, ErrFrameMalformed
	}
	copy(peerID[:], b[1:9])
	return peerID, b[10], b[11:], nil
}

// SplitDirectReg 拆直连路径的「reg‖WG」同数据报搭车。非 reg 前缀原样返回 ok=false。
func SplitDirectReg(b []byte) (reg, rest []byte, ok bool) {
	if len(b) < regFixedLen || string(b[:2]) != regMagic {
		return nil, b, false
	}
	return b[:regFixedLen], b[regFixedLen:], true
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
