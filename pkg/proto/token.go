// Package proto 定义 homeway 的线上契约（两仓库唯一真源）：
// token（凭证）、注册报文（reg）、中继帧（frame）。
//
// token 布局（可见前缀 + base64url(裸二进制)）：
//
//	"hmw1" ‖ base64url( peerId(32B) ‖ secret(32B) ‖ epCount(1B) ‖ [type(1B)+len(1B)+addr]* ‖ crc(4B) )
//
// peerId = 后端静态 WG 公钥；secret = 凭证种子（派生临时钥注册 HMAC / WG PSK）；
// type：0=direct 1=relay；addr = "host:port"（host 可为域名）；crc = SHA-256(前文)[:4]。
// 版本进可见前缀（"hmw2" = 下一版）：粘贴前就能看出是哪一代，未知前缀直接报错。
package proto

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
)

const (
	// tokenPrefix 是**可见**前缀（版本位），后面跟 base64url 的裸载荷。
	tokenPrefix = "hmw1"

	tokenMinLen = 32 + 32 + 1 + 4 // peerId / secret / epCount / crc

	EndpointTypeDirect = 0
	EndpointTypeRelay  = 1
)

// 三类可区分的失败。App 端按码归因（「串损坏」/「版本不对」/「格式不对」）。
var (
	ErrCorrupted          = errors.New("homeway/token: 校验失败（串被截断或损坏）")
	ErrUnsupportedVersion = errors.New("homeway/token: 不支持的 token 版本")
	ErrMalformed          = errors.New("homeway/token: 格式非法")
)

type Endpoint struct {
	Addr  string // "host:port"，host 可为 IP 或域名
	Relay bool
}

type Token struct {
	PeerID    [32]byte // 后端静态 WG 公钥
	Secret    [32]byte // 凭证种子
	Endpoints []Endpoint
}

func (t *Token) DirectEndpoints() []Endpoint { return t.endpoints(false) }
func (t *Token) RelayEndpoints() []Endpoint  { return t.endpoints(true) }

func (t *Token) endpoints(relay bool) []Endpoint {
	var out []Endpoint
	for _, e := range t.Endpoints {
		if e.Relay == relay {
			out = append(out, e)
		}
	}
	return out
}

// EncodeToken 编码并 base64url（无填充，剪贴板/截图安全字符集）。
func EncodeToken(t Token) (string, error) {
	return encodeBody(tokenPrefix, t)
}

// encodeBody：两个 token 类型（后端 hmw1 / 中继 rl1）共用同一套载荷布局——
// peerId(32) ‖ secret(32) ‖ epCount(1) ‖ [type+len+addr]* ‖ crc4。
func encodeBody(prefix string, t Token) (string, error) {
	for _, e := range t.Endpoints {
		if _, _, err := net.SplitHostPort(e.Addr); err != nil {
			return "", fmt.Errorf("%w: 端点 %q 不是 host:port", ErrMalformed, e.Addr)
		}
		if len(e.Addr) > 255 {
			return "", fmt.Errorf("%w: 端点地址过长", ErrMalformed)
		}
	}
	if len(t.Endpoints) > 255 {
		return "", fmt.Errorf("%w: 端点数超上限", ErrMalformed)
	}

	buf := make([]byte, 0, tokenMinLen+len(t.Endpoints)*3)
	buf = append(buf, t.PeerID[:]...)
	buf = append(buf, t.Secret[:]...)
	buf = append(buf, byte(len(t.Endpoints)))
	for _, e := range t.Endpoints {
		typ := byte(EndpointTypeDirect)
		if e.Relay {
			typ = EndpointTypeRelay
		}
		buf = append(buf, typ, byte(len(e.Addr)))
		buf = append(buf, e.Addr...)
	}
	sum := sha256.Sum256(buf)
	buf = append(buf, sum[0], sum[1], sum[2], sum[3])
	return prefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

// DecodeToken 解析并分类报错。深解析只应在 Go 侧发生（NAPI probe）；
// App/ArkTS 侧只做表面检查（前缀、base64url 字符集、长度）。
func DecodeToken(s string) (Token, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "hmw") && !strings.HasPrefix(s, tokenPrefix) {
		return Token{}, fmt.Errorf("%w: %s", ErrUnsupportedVersion, s[:4])
	}
	if !strings.HasPrefix(s, tokenPrefix) {
		return Token{}, fmt.Errorf("%w: 缺少 %s 前缀", ErrMalformed, tokenPrefix)
	}
	return decodePrefixed(tokenPrefix, s)
}

func decodePrefixed(prefix, s string) (Token, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s[len(prefix):], "="))
	if err != nil {
		return Token{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return decodeTokenBytes(raw)
}

func decodeTokenBytes(raw []byte) (Token, error) {
	if len(raw) < tokenMinLen {
		return Token{}, ErrCorrupted // 截断（含 base64 解码后过短）
	}
	body := raw[:len(raw)-4]
	sum := sha256.Sum256(body)
	if raw[len(raw)-4] != sum[0] || raw[len(raw)-3] != sum[1] || raw[len(raw)-2] != sum[2] || raw[len(raw)-1] != sum[3] {
		return Token{}, ErrCorrupted
	}

	var t Token
	off := 0
	copy(t.PeerID[:], raw[off:])
	off += 32
	copy(t.Secret[:], raw[off:])
	off += 32
	epCount := int(raw[off])
	off++
	t.Endpoints = make([]Endpoint, 0, epCount)
	for i := 0; i < epCount; i++ {
		if off+2 > len(body) {
			return Token{}, ErrMalformed
		}
		typ := raw[off]
		addrLen := int(raw[off+1])
		off += 2
		if addrLen == 0 || off+addrLen > len(body) {
			return Token{}, ErrMalformed
		}
		addr := string(raw[off : off+addrLen])
		off += addrLen
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return Token{}, fmt.Errorf("%w: 端点 %q", ErrMalformed, addr)
		}
		t.Endpoints = append(t.Endpoints, Endpoint{Addr: addr, Relay: typ == EndpointTypeRelay})
	}
	if off != len(body) {
		return Token{}, ErrMalformed
	}
	return t, nil
}
