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
//	其余腿（中继→客户端 / 中继↔后端）: [type(1B)][payload]
//
// type：0=数据（不透明 WG 包）1=控制（hint）。接收方 MUST 忽略未知 type
// 且不中断会话（前向兼容的钩子挂在格式上，不挂在实现节奏上）。
const (
	FrameTypeData    = byte(0)
	FrameTypeControl = byte(1)

	relayTagMagic = byte(0xAA)
)

var ErrFrameMalformed = errors.New("homeway/frame: 帧格式非法")

// RelayID 从后端静态公钥派生中继路由键（peerId 的 8 字节压缩）。
func RelayID(pubkey [32]byte) [8]byte {
	sum := sha256.Sum256(pubkey[:])
	var id [8]byte
	copy(id[:], sum[:8])
	return id
}

// EncodeFrame 生成一条腿上帧（无路由标签）。
func EncodeFrame(typ byte, payload []byte) []byte {
	return append([]byte{typ}, payload...)
}

// DecodeFrame 解析腿上帧。未知 type 原样返回、不报错（调用方忽略）。
func DecodeFrame(b []byte) (typ byte, payload []byte, err error) {
	if len(b) < 1 {
		return 0, nil, ErrFrameMalformed
	}
	return b[0], b[1:], nil
}

// EncodeTagged 生成客户端→中继 listener 帧（带 peerId 路由标签）。
func EncodeTagged(peerID [8]byte, typ byte, payload []byte) []byte {
	buf := make([]byte, 0, 1+8+1+len(payload))
	buf = append(buf, relayTagMagic)
	buf = append(buf, peerID[:]...)
	buf = append(buf, typ)
	return append(buf, payload...)
}

// DecodeTagged 解析 listener 收到的帧。
func DecodeTagged(b []byte) (peerID [8]byte, typ byte, payload []byte, err error) {
	if len(b) < 10 || b[0] != relayTagMagic {
		return peerID, 0, nil, ErrFrameMalformed
	}
	copy(peerID[:], b[1:9])
	return peerID, b[9], b[10:], nil
}

// ---------- 控制子协议：hint（对端观察地址，不可信线索） ----------
//
// payload: [len(2B BE)][addr]

// EncodeHint 生成 hint 控制帧（腿上帧）。
func EncodeHint(addr string) []byte {
	p := make([]byte, 2+len(addr))
	binary.BigEndian.PutUint16(p, uint16(len(addr)))
	copy(p[2:], addr)
	return EncodeFrame(FrameTypeControl, p)
}

// DecodeHint 解析 hint 控制帧。addr 为 "host:port"（观察到的公网出口）。
func DecodeHint(frame []byte) (addr string, err error) {
	typ, payload, err := DecodeFrame(frame)
	if err != nil {
		return "", err
	}
	if typ != FrameTypeControl {
		return "", fmt.Errorf("%w: 非 control 帧", ErrFrameMalformed)
	}
	if len(payload) < 2 {
		return "", ErrFrameMalformed
	}
	n := int(binary.BigEndian.Uint16(payload))
	if n == 0 || 2+n != len(payload) {
		return "", ErrFrameMalformed
	}
	return string(payload[2 : 2+n]), nil
}
