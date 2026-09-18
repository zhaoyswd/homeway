package proto

import (
	"encoding/base64"
	"errors"
	"testing"
)

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestFrameRoundTrip(t *testing.T) {
	f := EncodeFrame(FrameTypeData, []byte{4, 4})
	typ, payload, err := DecodeFrame(f)
	if err != nil || typ != FrameTypeData || len(payload) != 2 {
		t.Fatalf("typ=%d payload=%v err=%v", typ, payload, err)
	}
}

// 未知帧类型必须解码成功（调用方忽略），前向兼容的关键。
func TestFrameUnknownTypeIgnored(t *testing.T) {
	f := EncodeFrame(0x7F, []byte("future"))
	typ, payload, err := DecodeFrame(f)
	if err != nil {
		t.Fatalf("未知类型不该报错: %v", err)
	}
	if typ != 0x7F || string(payload) != "future" {
		t.Fatalf("typ=%d payload=%q", typ, payload)
	}
}

func TestTaggedRoundTrip(t *testing.T) {
	id := RelayID(goldenFields.PeerID)
	f := EncodeTagged(id, FrameTypeData, []byte("wg"))
	gotID, typ, payload, err := DecodeTagged(f)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if gotID != id || typ != FrameTypeData || string(payload) != "wg" {
		t.Fatalf("id=%v typ=%d payload=%q", gotID, typ, payload)
	}
}

func TestTaggedMalformed(t *testing.T) {
	if _, _, _, err := DecodeTagged([]byte{0x00, 1, 2}); !errors.Is(err, ErrFrameMalformed) {
		t.Fatalf("err = %v, want ErrFrameMalformed", err)
	}
}

func TestHintRoundTrip(t *testing.T) {
	f := EncodeHint("198.51.100.7:41641")
	addr, err := DecodeHint(f)
	if err != nil || addr != "198.51.100.7:41641" {
		t.Fatalf("addr=%q err=%v", addr, err)
	}
	// 非 control 帧必须拒绝
	if _, err := DecodeHint(EncodeFrame(FrameTypeData, nil)); !errors.Is(err, ErrFrameMalformed) {
		t.Fatalf("err = %v, want ErrFrameMalformed", err)
	}
}

func TestRelayIDDeterministic(t *testing.T) {
	a, b := RelayID(goldenFields.PeerID), RelayID(goldenFields.PeerID)
	if a != b {
		t.Fatal("RelayID 不确定")
	}
	var other [32]byte
	other[0] = 1
	if a == RelayID(other) {
		t.Fatal("不同公钥派生了相同 RelayID")
	}
}
