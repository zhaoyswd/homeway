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
	"crypto/hmac"
	"crypto/sha256"
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
	// Cookie：每会话随机（review #3，腿身份认证）。只经控制通道发给**该会话所属的
	// 后端**；后端拨腿首包必须回带 cookie + MAC，中继验过才把该源认作腿——
	// 否则任何扫到数据口的第三方都能抢占会话（收走 WG 密文 / 黑洞上行 / 注入 hint）。
	// HasCookie=false 时按 v1 编码（11B，不带认证——v1 后端/旧路径）。
	Cookie    [16]byte
	HasCookie bool
}

// EncodeCtlSession 组 SESSION 消息（HasCookie 时 27B v2，否则 11B v1）。
func EncodeCtlSession(s CtlSession) []byte {
	out := make([]byte, 0, 1+10+16)
	out = append(out, RelayCtlSession)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], s.ID)
	out = append(out, b[:]...)
	binary.BigEndian.PutUint16(b[:2], s.DataPort)
	out = append(out, b[:2]...)
	if s.HasCookie {
		out = append(out, s.Cookie[:]...)
	}
	return out
}

// DecodeCtlSession 解 SESSION 消息（11B = v1 无 cookie；27B = v2 带 cookie）。
func DecodeCtlSession(p []byte) (CtlSession, error) {
	if len(p) != 11 && len(p) != 27 || p[0] != RelayCtlSession {
		return CtlSession{}, ErrCtlMalformed
	}
	s := CtlSession{
		ID:       binary.BigEndian.Uint64(p[1:9]),
		DataPort: binary.BigEndian.Uint16(p[9:11]),
	}
	if len(p) == 27 {
		copy(s.Cookie[:], p[11:27])
		s.HasCookie = true
	}
	return s, nil
}

// legupMagic + 腿认证（review #3）：
//
//	拨腿首包 = "LEGUP" ‖ cookie(16) ‖ MAC(16)，MAC = HMAC(key, "legup-v2" ‖ sid(8 BE) ‖ cookie)
//	key = token 模式 = 中继鉴权密钥（与后端共享，在线路上永不出现）；
//	     开放模式 = cookie 本身（仅防盲攻击者——能读到线路的观察者在此模式下本就无防）。
//	v1 腿（无 cookie 的 SESSION）回退纯 "LEGUP" 标记（5B）。
const legupMagic = "LEGUP"

// LegupAuthPayload：v2 后端拨腿首包的完整载荷。
func LegupAuthPayload(sid uint64, cookie [16]byte, key [32]byte) []byte {
	out := make([]byte, 0, 5+16+16)
	out = append(out, legupMagic...)
	out = append(out, cookie[:]...)
	out = append(out, LegupMAC(sid, cookie, key)...)
	return out
}

// LegupMAC：腿认证 MAC（两端各算各的，常量时间比较由调用方做）。
func LegupMAC(sid uint64, cookie [16]byte, key [32]byte) []byte {
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte("legup-v2"))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], sid)
	mac.Write(b[:])
	mac.Write(cookie[:])
	return mac.Sum(nil)[:16]
}

// LegupCookie：合法 v2 拨腿首包里取 cookie（不校验 MAC；调用方再走 VerifyLegupAuth）。
func LegupCookie(pkt []byte) ([16]byte, bool) {
	var c [16]byte
	if len(pkt) != 5+16+16 || string(pkt[:5]) != legupMagic {
		return c, false
	}
	copy(c[:], pkt[5:21])
	return c, true
}

// VerifyLegupAuth：完整校验一个 v2 拨腿首包。
func VerifyLegupAuth(pkt []byte, sid uint64, cookie [16]byte, key [32]byte) bool {
	c, ok := LegupCookie(pkt)
	if !ok || c != cookie {
		return false
	}
	return hmac.Equal(LegupMAC(sid, cookie, key), pkt[21:37])
}

// IsPlainLegup：v1 的纯标记形态（5B）。
func IsPlainLegup(pkt []byte) bool {
	return len(pkt) == 5 && string(pkt) == legupMagic
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

// RelayOKAuthMAC：OK 消息里的中继身份材料（review #29）。后端此前无法认证中继：
// 任何能截 TCP 的角色都能发 OK 然后喂假 SESSION（把后端的腿拨去任意地址）。
// MAC = HMAC(中继鉴权密钥, nonce ‖ "ok")——nonce 是本次握手的挑战随机数，
// 只有持有 token 密钥的真中继算得出（开放模式无密钥可依，跳过——测试用）。
func RelayOKAuthMAC(secret [32]byte, nonce [16]byte) []byte {
	mac := hmac.New(sha256.New, secret[:])
	mac.Write(nonce[:])
	mac.Write([]byte("ok"))
	return mac.Sum(nil)[:16]
}

// EncodeRelayOKAuth：v2 OK（1B 子类型 + 16B MAC）。v1 OK 是裸 1B——解码按长度判别。
func EncodeRelayOKAuth(mac []byte) []byte {
	return append([]byte{RelaySubOK}, mac...)
}

// DecodeRelayOKAuth：解 OK。返回 (mac, v2)。v1 形状（裸 1B）mac 为 nil。
func DecodeRelayOKAuth(p []byte) (mac []byte, v2 bool) {
	if len(p) == 1+16 && p[0] == RelaySubOK {
		return p[1:], true
	}
	return nil, false
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
