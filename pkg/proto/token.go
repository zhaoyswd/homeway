// Package proto 定义 homeway 的线上契约（两仓库唯一真源）：
// token（凭证）、注册报文（reg）、中继帧（frame）。
//
// token 布局（裸二进制，整体 base64url 编码）：
//
//	"hmw1"(4B) ‖ peerId(32B) ‖ secret(32B) ‖ epCount(1B) ‖ [type(1B)+len(1B)+addr]* ‖ crc(4B)
//
// peerId = 后端静态 WG 公钥；secret = 凭证种子（派生临时钥注册 HMAC / WG PSK）；
// type：0=direct 1=relay；addr = "host:port"（host 可为域名）；crc = SHA-256(前文)[:4]。
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
	// Magic + 版本。版本升级换尾字节（"hmw2"...），未知版本必须显式报错。
	tokenMagic   = "hmw"
	tokenVersion = byte('1')

	tokenMinLen = 4 + 32 + 32 + 1 + 4 // magic+ver / peerId / secret / epCount / crc

	EndpointTypeDirect = 0
	EndpointTypeRelay  = 1
)

// 三类可区分的失败 + 一个兼容性特判。App 端按码归因（「串损坏」/「旧版地址」/「格式不对」）。
var (
	ErrLegacyTailcat      = errors.New("homeway/token: 旧版 tailcat 地址，请粘贴 homeway token")
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
	buf = append(buf, tokenMagic[0], tokenMagic[1], tokenMagic[2], tokenVersion)
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
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// DecodeToken 解析并分类报错。深解析只应在 Go 侧发生（NAPI probe）；
// App/ArkTS 侧只做表面检查（前缀、base64url 字符集、长度）。
func DecodeToken(s string) (Token, error) {
	if strings.HasPrefix(s, "tcp") {
		return Token{}, ErrLegacyTailcat
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return Token{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return decodeTokenBytes(raw)
}

func decodeTokenBytes(raw []byte) (Token, error) {
	if len(raw) < tokenMinLen {
		return Token{}, ErrCorrupted // 截断（含 base64 解码后过短）
	}
	if string(raw[:3]) != tokenMagic {
		return Token{}, ErrMalformed
	}
	if raw[3] != tokenVersion {
		return Token{}, fmt.Errorf("%w: v%c", ErrUnsupportedVersion, raw[3])
	}
	body := raw[:len(raw)-4]
	sum := sha256.Sum256(body)
	if raw[len(raw)-4] != sum[0] || raw[len(raw)-3] != sum[1] || raw[len(raw)-2] != sum[2] || raw[len(raw)-1] != sum[3] {
		return Token{}, ErrCorrupted
	}

	var t Token
	off := 4
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
