package proto

import (
	"errors"
	"strings"
	"testing"
)

var goldenToken = "hmw1AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyD__v38-_r5-Pf29fTz8vHw7-7t7Ovq6ejn5uXk4-Lh4AMAEDE5Mi4wLjIuMTI6NDE2NDEAFmV4aXQuZXhhbXBsZS5uZXQ6NDE2NDEBEDIwMy4wLjExMy45OjQ0MzAIhj7v"

var goldenFields = Token{
	PeerID: func() [32]byte {
		var k [32]byte
		for i := range k {
			k[i] = byte(i + 1)
		}
		return k
	}(),
	Secret: func() [32]byte {
		var k [32]byte
		for i := range k {
			k[i] = byte(255 - i)
		}
		return k
	}(),
	Endpoints: []Endpoint{
		{Addr: "192.0.2.12:41641"},
		{Addr: "exit.example.net:41641"},
		{Addr: "203.0.113.9:4430", Relay: true},
	},
}

func TestTokenGoldenRoundTrip(t *testing.T) {
	enc, err := EncodeToken(goldenFields)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if enc != goldenToken {
		t.Fatalf("golden 漂移：\n got %s\nwant %s", enc, goldenToken)
	}
	dec, err := DecodeToken(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.PeerID != goldenFields.PeerID || dec.Secret != goldenFields.Secret {
		t.Fatal("peerId/secret 不匹配")
	}
	if len(dec.Endpoints) != 3 {
		t.Fatalf("端点数 %d", len(dec.Endpoints))
	}
	for i, e := range dec.Endpoints {
		if e != goldenFields.Endpoints[i] {
			t.Fatalf("端点[%d] = %+v, want %+v", i, e, goldenFields.Endpoints[i])
		}
	}
	if d := dec.DirectEndpoints(); len(d) != 2 || d[1].Addr != "exit.example.net:41641" {
		t.Fatalf("DirectEndpoints = %+v", d)
	}
	if r := dec.RelayEndpoints(); len(r) != 1 || !r[0].Relay {
		t.Fatalf("RelayEndpoints = %+v", r)
	}
}

func TestTokenWrongPrefix(t *testing.T) {
	// 旧 tailcat 地址、随便一段 base64、空串：都不是 homeway token ⇒ 格式错误
	for _, s := range []string{"tcpGFwWCB3A0uFakeOldTailcatAddress000000", "aG13MABCDEF", ""} {
		if _, err := DecodeToken(s); !errors.Is(err, ErrMalformed) {
			t.Fatalf("DecodeToken(%q) err = %v, want ErrMalformed", s, err)
		}
	}
}

func TestTokenCorrupted(t *testing.T) {
	// 改一个字符（中段，仍在 base64url 字符集内 ⇒ 走 crc 判据）
	b := []byte(goldenToken)
	if b[40] == 'A' {
		b[40] = 'B'
	} else {
		b[40] = 'A'
	}
	if _, err := DecodeToken(string(b)); !errors.Is(err, ErrCorrupted) {
		t.Fatalf("err = %v, want ErrCorrupted", err)
	}
	// 截断：砍掉尾部 4 个 base64 字符（长度仍合法）⇒ 载荷短了、crc 对不上
	if _, err := DecodeToken(goldenToken[:len(goldenToken)-4]); !errors.Is(err, ErrCorrupted) {
		t.Fatalf("err = %v, want ErrCorrupted", err)
	}
}

func TestTokenMalformed(t *testing.T) {
	// 非 base64url 字符集
	if _, err := DecodeToken("hmw1+++++++"); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
	// 合法 base64 但没有 hmw1 前缀
	if _, err := DecodeToken("xxw1"+strings.Repeat("A", 100)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestTokenUnsupportedVersion(t *testing.T) {
	// 版本位在**可见前缀**里：hmw2… 直接报版本不支持（载荷根本不用解）
	if _, err := DecodeToken("hmw2" + strings.Repeat("A", 100)); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("err = %v, want ErrUnsupportedVersion", err)
	}
}

func TestTokenEncodeRejectsBadEndpoints(t *testing.T) {
	tk := goldenFields
	tk.Endpoints = []Endpoint{{Addr: "no-port-here"}}
	if _, err := EncodeToken(tk); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}
