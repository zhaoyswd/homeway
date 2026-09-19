package proto

import (
	"crypto/sha256"
	"strings"
)

// 中继凭据 token（可见前缀 "rl1"）：**中继自己签发**，后端拿它来注册。
//
// 为什么要这一层（用户提的设计）：中继先前用「后端白名单（--allow <label>）」做准入，
// 于是顺序被绑死成「先有后端、才能启动中继」，后端身份（label）一变还得改中继配置并重启。
// 倒过来：中继启动时生成/加载自己的**鉴权密钥**并打印一个 token，内容 = 中继地址 + 该密钥；
// 后端 `--relay 'rl1…'` 拿 token 注册即可 —— 中继侧不需要预先知道任何后端身份，
// 换后端/换身份都不用动中继。
//
// 布局与后端 token 完全相同（复用 encodeBody/decodeTokenBytes）：
//
//	"rl1" ‖ base64url( relayID(32) ‖ relaySecret(32) ‖ epCount(1) ‖ [type+len+addr]* ‖ crc4 )
//
// relayID = SHA-256(relaySecret)：只是给人看的稳定标识（日志里去重/排障），不泄露密钥。
// 端点里放中继自己的地址（可多个：v4/v6/域名），后端按顺序试。
const relayTokenPrefix = "rl1"

// （依赖：crypto/sha256、strings——与本文件同包已导入。）

// RelaySecretID：中继密钥的公开标识（日志用）。
func RelaySecretID(secret [32]byte) [32]byte {
	return sha256.Sum256(secret[:])
}

// EncodeRelayToken：中继启动/`token` 子命令打印用。
func EncodeRelayToken(secret [32]byte, endpoints []Endpoint) (string, error) {
	t := Token{PeerID: RelaySecretID(secret), Secret: secret, Endpoints: endpoints}
	return encodeBody(relayTokenPrefix, t)
}

// DecodeRelayToken：后端解析 `--relay rl1…`。
func DecodeRelayToken(s string) (Token, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, relayTokenPrefix) {
		return Token{}, ErrMalformed
	}
	return decodePrefixed(relayTokenPrefix, s)
}

// RelayAuthMAC：token 模式下后端对挑战的应答 MAC（密钥 = 中继鉴权密钥）。
// 域分隔与 DH 那条路分开，避免两类 MAC 互相替换。
func RelayAuthMAC(secret [32]byte, nonce [16]byte, pubkey [32]byte) []byte {
	mac := hmacNew(secret[:])
	mac.Write([]byte("relay-psk"))
	mac.Write(nonce[:])
	mac.Write(pubkey[:])
	return mac.Sum(nil)[:16]
}
