package proto

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

// hmacNew：HMAC-SHA256（域分隔标签由调用方加）。
func hmacNew(key []byte) hash.Hash { return hmac.New(sha256.New, key) }

// 中继控制子协议（frame type = 3；见 design.md D4 与 specs/wg-native-relay）。
//
// 角色与腿：
//
//	后端(NAT 后)  ── 出站注册腿 ──►  中继        注册证明 = X25519 DH(后端静态私钥, 中继临时公钥)
//	客户端        ── 标签帧 ──────►  中继 ──per-client 分配 socket──► 后端注册腿源地址
//
// 为什么用 DH 而不是签名：两端已有的就是 WG 静态密钥（Curve25519）。中继只持有**公钥**
// （peerId），用「临时私钥 × 后端公钥」算出的共享密钥去校验 HMAC，即可证明对方持有私钥，
// 不需要引入第二套密钥或把私钥喂给别的算法。
//
// 全部消息都装在腿上帧里（[0xBB][type=3][subtype ‖ …]），因此：
//   - 客户端/后端的收包路径仍按"未知 type 忽略"前向兼容；
//   - 中继剥掉 [0xAA][label] 路由头后原样转发，数据面零感知。
const (
	// FrameTypeRelayReg：中继控制（注册挑战/证明/心跳）。接收方未知 subtype 一律忽略。
	FrameTypeRelayReg = byte(3)

	RelaySubHello     = byte(0x01) // 后端→中继：pubkey(32)
	RelaySubChallenge = byte(0x02) // 中继→后端：ephPub(32) ‖ nonce(16)
	RelaySubProof     = byte(0x03) // 后端→中继：nonce(16) ‖ macDH(16) ‖ macPSK(16)
	//   macDH  = X25519(后端静态私钥, 中继临时公钥) 的 HMAC（开放模式用）
	//   macPSK = HMAC(中继鉴权密钥, nonce‖pubkey)（token 模式用；没有 token 时全 0）
	RelaySubOK        = byte(0x04) // 中继→后端：注册成功（此后才开始分配转发）
	RelaySubKeepalive = byte(0x05) // 后端→中继：保活（无 payload）
	RelaySubAgain     = byte(0x06) // 中继→后端：腿不在了（中继重启/过期），请重新注册
)

// RelayMACLabel：HMAC 的域分隔（两处实现必须一致）。
var relayMACLabel = []byte("hmac-relay")

// EncodeRelayHello：后端注册第一步（带自己的完整公钥，中继要拿它算 DH）。
func EncodeRelayHello(pubkey [32]byte) []byte {
	out := make([]byte, 0, 1+32)
	out = append(out, RelaySubHello)
	out = append(out, pubkey[:]...)
	return out
}

// DecodeRelayHello：解析注册第一步。
func DecodeRelayHello(p []byte) (pubkey [32]byte, err error) {
	if len(p) != 33 || p[0] != RelaySubHello {
		return pubkey, ErrFrameMalformed
	}
	copy(pubkey[:], p[1:33])
	return pubkey, nil
}

// EncodeRelayChallenge：中继出题（临时公钥 + 随机数）。
func EncodeRelayChallenge(ephPub [32]byte, nonce [16]byte) []byte {
	out := make([]byte, 0, 1+32+16)
	out = append(out, RelaySubChallenge)
	out = append(out, ephPub[:]...)
	out = append(out, nonce[:]...)
	return out
}

// DecodeRelayChallenge：解析挑战。
func DecodeRelayChallenge(p []byte) (ephPub [32]byte, nonce [16]byte, err error) {
	if len(p) != 49 || p[0] != RelaySubChallenge {
		return ephPub, nonce, ErrFrameMalformed
	}
	copy(ephPub[:], p[1:33])
	copy(nonce[:], p[33:49])
	return ephPub, nonce, nil
}

// RelayProofMAC：注册证明的 MAC（DH 为密钥）。
func RelayProofMAC(dh []byte, nonce [16]byte, pubkey [32]byte) []byte {
	mac := hmacNew(dh)
	mac.Write(relayMACLabel)
	mac.Write(nonce[:])
	mac.Write(pubkey[:])
	return mac.Sum(nil)[:16]
}

// EncodeRelayProof：后端回证明（macPSK 为 nil = 开放模式，填 0）。
func EncodeRelayProof(nonce [16]byte, dh []byte, pubkey [32]byte, psk []byte) []byte {
	out := make([]byte, 0, 1+16+16+16)
	out = append(out, RelaySubProof)
	out = append(out, nonce[:]...)
	out = append(out, RelayProofMAC(dh, nonce, pubkey)...)
	if len(psk) == 16 {
		out = append(out, psk...)
	} else {
		out = append(out, make([]byte, 16)...)
	}
	return out
}

// DecodeRelayProof：解析证明（校验留给调用方：它才知道 DH / 鉴权密钥）。
// 兼容老的 33B 版本（只有 macDH）——老中继/老后端混跑时不至于死。
func DecodeRelayProof(p []byte) (nonce [16]byte, macDH, macPSK []byte, err error) {
	if len(p) != 49 && len(p) != 33 || p[0] != RelaySubProof {
		return nonce, nil, nil, ErrFrameMalformed
	}
	copy(nonce[:], p[1:17])
	macDH = p[17:33]
	if len(p) == 49 {
		macPSK = p[33:49]
	}
	return nonce, macDH, macPSK, nil
}

// EncodeRelayOK / EncodeRelayKeepalive：小消息。
func EncodeRelayOK() []byte          { return []byte{RelaySubOK} }
func EncodeRelayAgain() []byte       { return []byte{RelaySubAgain} }
func EncodeRelayKeepalive() []byte   { return []byte{RelaySubKeepalive} }
func RelaySubtype(p []byte) (byte, bool) {
	if len(p) == 0 {
		return 0, false
	}
	return p[0], true
}
