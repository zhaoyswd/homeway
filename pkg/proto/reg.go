package proto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// 注册报文：客户端临时公钥的入场券，与 WG 首个握手同数据报发出（1 RTT 建连）。
//
//	"HR"(2B) ‖ pubkey(32B) ‖ ts(8B BE 秒) ‖ mac(16B)
//
// mac = HMAC-SHA256(token secret, "hr-reg" ‖ pubkey ‖ ts)[:16]。
// 重放无害：旧公钥没有对应私钥，握手无法完成，仅占后端动态 peer 表名额
// （产品侧 cap/LRU 兜住，见 tasks 3.2）。
var (
	ErrRegMalformed = errors.New("homeway/reg: 报文格式非法")
	ErrRegExpired   = errors.New("homeway/reg: 时间戳超出窗口")
	ErrRegBadMAC    = errors.New("homeway/reg: HMAC 校验失败")
)

const (
	regMagic     = "HR"
	regFixedLen  = 2 + 32 + 8 + 16
	regWindowDef = 90 * time.Second
)

// EncodeReg 生成注册报文。
func EncodeReg(secret [32]byte, pubkey [32]byte, now time.Time) []byte {
	buf := make([]byte, 0, regFixedLen)
	buf = append(buf, regMagic[0], regMagic[1])
	buf = append(buf, pubkey[:]...)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(now.Unix()))
	buf = append(buf, ts...)
	mac := regMAC(secret, pubkey, buf[2:42])
	buf = append(buf, mac...)
	return buf
}

// VerifyReg 校验注册报文，返回其中的客户端公钥。window<=0 用默认 90s。
func VerifyReg(secret [32]byte, pkt []byte, now time.Time, window time.Duration) ([32]byte, error) {
	var pubkey [32]byte
	if len(pkt) != regFixedLen || string(pkt[:2]) != regMagic {
		return pubkey, ErrRegMalformed
	}
	copy(pubkey[:], pkt[2:34])
	if !hmac.Equal(pkt[42:], regMAC(secret, pubkey, pkt[2:42])) {
		return pubkey, ErrRegBadMAC
	}
	ts := time.Unix(int64(binary.BigEndian.Uint64(pkt[34:42])), 0)
	if window <= 0 {
		window = regWindowDef
	}
	if d := now.Sub(ts); d > window || d < -window {
		return pubkey, fmt.Errorf("%w: 偏差 %v", ErrRegExpired, d)
	}
	return pubkey, nil
}

func regMAC(secret [32]byte, pubkey [32]byte, covered []byte) []byte {
	h := hmac.New(sha256.New, secret[:])
	h.Write([]byte("hr-reg"))
	h.Write(covered)
	return h.Sum(nil)[:16]
}
