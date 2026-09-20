package proto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// 注册报文 v2：客户端 WG 公钥的入场券 + 稳定设备标签，与 WG 首个握手同数据报发出（1 RTT 建连）。
//
//	"H2"(2B) ‖ pubkey(32B) ‖ devTag(8B) ‖ ts(8B BE 秒) ‖ mac(16B)
//
// mac = HMAC-SHA256(token secret, "hr-reg2" ‖ pubkey ‖ devTag ‖ ts)[:16]。
//
// devTag 是**设备标签**：设备本地生成、跨连接稳定，出口用它做设备表的键与日志。
// 它在 MAC 覆盖内（防篡改）但**不是凭证**——准入仍只由 HMAC 决定，持 token 者可声称任意标签。
// 重放无害：旧公钥没有对应私钥，握手无法完成；同设备重复注册只刷新既有设备记录（不新增条目）。
// v1（"HR"，58B）不再接受：产品未发布，不留兼容分支——旧格式一律按畸形报文拒绝。
var (
	ErrRegMalformed = errors.New("homeway/reg: 报文格式非法")
	ErrRegExpired   = errors.New("homeway/reg: 报文时间戳超出窗口")
	ErrRegBadMAC    = errors.New("homeway/reg: HMAC 校验失败")
)

const (
	regMagic     = "H2"
	devTagLen    = 8
	regFixedLen  = 2 + 32 + devTagLen + 8 + 16 // 66
	regWindowDef = 90 * time.Second
)

// DevTag 设备标签：设备本地生成、跨连接稳定，用作出口设备表的键。
// 零值合法（设备端生成时避开即可；出口不做额外语义）。
type DevTag [devTagLen]byte

// EncodeReg 生成注册报文（v2）。
func EncodeReg(secret [32]byte, pubkey [32]byte, devTag DevTag, now time.Time) []byte {
	buf := make([]byte, 0, regFixedLen)
	buf = append(buf, regMagic[0], regMagic[1])
	buf = append(buf, pubkey[:]...)
	buf = append(buf, devTag[:]...)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(now.Unix()))
	buf = append(buf, ts...)
	buf = append(buf, regMAC(secret, buf[2:])...)
	return buf
}

// VerifyReg 校验注册报文，返回其中的客户端公钥与设备标签。window<=0 用默认 90s。
func VerifyReg(secret [32]byte, pkt []byte, now time.Time, window time.Duration) (pubkey [32]byte, devTag DevTag, err error) {
	if len(pkt) != regFixedLen || string(pkt[:2]) != regMagic {
		return pubkey, devTag, ErrRegMalformed
	}
	copy(pubkey[:], pkt[2:34])
	copy(devTag[:], pkt[34:42])
	if !hmac.Equal(pkt[50:], regMAC(secret, pkt[2:50])) {
		return pubkey, devTag, ErrRegBadMAC
	}
	ts := time.Unix(int64(binary.BigEndian.Uint64(pkt[42:50])), 0)
	if window <= 0 {
		window = regWindowDef
	}
	if d := now.Sub(ts); d > window || d < -window {
		return pubkey, devTag, fmt.Errorf("%w: 偏差 %v", ErrRegExpired, d)
	}
	return pubkey, devTag, nil
}

func regMAC(secret [32]byte, covered []byte) []byte {
	h := hmac.New(sha256.New, secret[:])
	h.Write([]byte("hr-reg2"))
	h.Write(covered)
	return h.Sum(nil)[:16]
}
