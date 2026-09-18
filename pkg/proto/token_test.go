package proto

import (
	"errors"
	"strings"
	"testing"
)

var goldenToken = "aG13MQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g__79_Pv6-fj39vX08_Lx8O_u7ezr6uno5-bl5OPi4eADABIxOTIuMTY4LjMuMTI6NDE2NDEAFmV4aXQuZXhhbXBsZS5uZXQ6NDE2NDEBEzEyMy41Ni4yMTguMjEyOjQ0MzC8B8pm"

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

func TestTokenLegacyTailcat(t *testing.T) {
	if _, err := DecodeToken("tcpGFwWCB3A0uFakeOldTailcatAddress000000"); !errors.Is(err, ErrLegacyTailcat) {
		t.Fatalf("err = %v, want ErrLegacyTailcat", err)
	}
}

func TestTokenCorrupted(t *testing.T) {
	// 改一个字符（中段）
	b := []byte(goldenToken)
	b[40] ^= 1
	if _, err := DecodeToken(string(b)); !errors.Is(err, ErrCorrupted) {
		t.Fatalf("err = %v, want ErrCorrupted", err)
	}
	// 截断（尾部砍 6 字符）
	if _, err := DecodeToken(goldenToken[:len(goldenToken)-6]); !errors.Is(err, ErrCorrupted) {
		t.Fatalf("err = %v, want ErrCorrupted", err)
	}
}

func TestTokenMalformed(t *testing.T) {
	// 非 base64url 字符集
	if _, err := DecodeToken("hmw1+++++++"); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
	// 未知 magic
	enc, _ := EncodeToken(goldenFields)
	flipMagic := []byte(enc)
	// 解开改首字节再编码成本高，直接构造："xxw1..." 合法 base64 但 magic 不符
	bad := "eHh3MQ" + strings.Repeat("A", 100)
	if _, err := DecodeToken(bad); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
	_ = flipMagic
}

func TestTokenUnsupportedVersion(t *testing.T) {
	// 用解码-改版本位-重编码构造 hmw2
	raw := mustDecode(t, goldenToken)
	raw[3] = '2'
	enc2 := b64url(raw)
	if _, err := DecodeToken(enc2); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("err = %v, want ErrUnsupportedVersion", err)
	}
	// 版本改了 crc 不再匹配也应先报版本（版本检查在 crc 前）
}

func TestTokenEncodeRejectsBadEndpoints(t *testing.T) {
	tk := goldenFields
	tk.Endpoints = []Endpoint{{Addr: "no-port-here"}}
	if _, err := EncodeToken(tk); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}
