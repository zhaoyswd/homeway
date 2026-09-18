package proto

import (
	"crypto/hkdf"
	"crypto/sha256"
)

// DerivePSK：token secret → WireGuard PSK。
// 保证「偷走后端静态私钥但无 token 的攻击者也无法中间人」（WG 的 PSK 混入握手密钥）。
// 两端（客户端 peer 配置 / 后端动态 peer 登记）共用本函数，域分离标签钉死用途。
func DerivePSK(secret [32]byte) [32]byte {
	var out [32]byte
	key, err := hkdf.Key(sha256.New, secret[:], nil, "homeway/wg-psk", 32)
	if err != nil {
		panic("hkdf: " + err.Error())
	}
	copy(out[:], key)
	return out
}
