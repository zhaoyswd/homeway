package proto

// relayctl.go — 控制通道（relay-backend-dial）的编解码。
//
// 控制通道 = 后端发起的 TCP 长连（中继的 UDP 端口同号监听 TCP）。承载：
//   - 鉴权：与 UDP 注册腿**同一套** X25519 挑战（Hello/Challenge/Proof/OK 复用
//     RelaySub* 的载荷编码——控制通道必须证明持有 peerId 私钥，否则任何拿到
//     rl1 token 的人都能冒领别人的 SESSION 通告（DoS 真后端）；
//   - 会话通告：SESSION（客户端到达 + 数据口）/ RELEASE（客户端离开/回收）；
//   - 保活：KEEPALIVE（复用 RelaySubKeepalive；中继侧刷新注册腿 last）。
//
// 线格式：`[2B BE 长度][消息]`；消息 = [子类型][载荷]，子类型即 RelaySub* 家族
// 加两个控制面专属（0x10/0x11，与既有子类型不冲突）。

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// 控制面专属子类型（0x01-0x06 见 relay.go 的 RelaySub*）。
const (
	RelayCtlSession = byte(0x10) // 中继→后端：sessionID(8) ‖ dataPort(2)
	RelayCtlRelease = byte(0x11) // 中继→后端：sessionID(8)
)

// ErrCtlMalformed：控制面消息非法。
var ErrCtlMalformed = errors.New("proto/relayctl: 消息非法")

// relayCtlMax：单条控制消息上限（所有子类型都 ≤64B，防恶意长度行撑爆读侧）。
const relayCtlMax = 256

// CtlSession：SESSION 通告载荷。
type CtlSession struct {
	ID       uint64 // 中继侧会话号（RELEASE 关联用）
	DataPort uint16 // 该客户端专属数据口（后端拨腿的目标端口）
}

// EncodeCtlSession 组 SESSION 消息。
func EncodeCtlSession(s CtlSession) []byte {
	out := make([]byte, 0, 1+10)
	out = append(out, RelayCtlSession)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], s.ID)
	out = append(out, b[:]...)
	binary.BigEndian.PutUint16(b[:2], s.DataPort)
	out = append(out, b[:2]...)
	return out
}

// DecodeCtlSession 解 SESSION 消息。
func DecodeCtlSession(p []byte) (CtlSession, error) {
	if len(p) != 11 || p[0] != RelayCtlSession {
		return CtlSession{}, ErrCtlMalformed
	}
	return CtlSession{
		ID:       binary.BigEndian.Uint64(p[1:9]),
		DataPort: binary.BigEndian.Uint16(p[9:11]),
	}, nil
}

// EncodeCtlRelease 组 RELEASE 消息。
func EncodeCtlRelease(id uint64) []byte {
	out := make([]byte, 0, 1+8)
	out = append(out, RelayCtlRelease)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], id)
	out = append(out, b[:]...)
	return out
}

// DecodeCtlRelease 解 RELEASE 消息。
func DecodeCtlRelease(p []byte) (uint64, error) {
	if len(p) != 9 || p[0] != RelayCtlRelease {
		return 0, ErrCtlMalformed
	}
	return binary.BigEndian.Uint64(p[1:9]), nil
}

// ---------- TCP 流分帧 ----------

// CtlWriteMsg 往 TCP 连接写一条消息（长度前缀分帧）。
func CtlWriteMsg(w io.Writer, msg []byte) error {
	if len(msg) == 0 || len(msg) > relayCtlMax {
		return ErrCtlMalformed
	}
	hdr := [2]byte{byte(len(msg) >> 8), byte(len(msg))}
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(msg)
	return err
}

// CtlReadMsg 从 TCP 连接读一条消息（返回子类型与载荷；连接关闭 = io.EOF）。
func CtlReadMsg(r io.Reader) (typ byte, payload []byte, err error) {
	hdr := [2]byte{}
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(hdr[0])<<8 | int(hdr[1])
	if n == 0 || n > relayCtlMax {
		return 0, nil, ErrCtlMalformed
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		return 0, nil, err
	}
	return msg[0], msg[1:], nil
}

// CtlMsgString：一行可读形态（判据日志用）。
func CtlMsgString(typ byte, payload []byte) string {
	switch typ {
	case RelaySubHello:
		return "HELLO"
	case RelaySubChallenge:
		return "CHALLENGE"
	case RelaySubProof:
		return "PROOF"
	case RelaySubOK:
		return "OK"
	case RelaySubKeepalive:
		return "KEEPALIVE"
	case RelayCtlSession:
		if s, err := DecodeCtlSession(append([]byte{typ}, payload...)); err == nil {
			return fmt.Sprintf("SESSION id=%d port=%d", s.ID, s.DataPort)
		}
	case RelayCtlRelease:
		if id, err := DecodeCtlRelease(append([]byte{typ}, payload...)); err == nil {
			return fmt.Sprintf("RELEASE id=%d", id)
		}
	}
	return fmt.Sprintf("type=0x%02x len=%d", typ, len(payload))
}
