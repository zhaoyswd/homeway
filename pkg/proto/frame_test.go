package proto

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"
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
	// 首字节非 0xBB（如裸 WG initiation，type=1）必须判畸形——直连路径的判别依据
	if _, _, err := DecodeFrame([]byte{1, 0, 0, 0}); !errors.Is(err, ErrFrameMalformed) {
		t.Fatalf("裸 WG 包误判为合法帧: %v", err)
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
	if _, err := DecodeHintPayload([]byte{0, 3, 'a', 'b'}); !errors.Is(err, ErrFrameMalformed) {
		t.Fatalf("长度不符的 payload 必须报错: %v", err)
	}
}

func TestSplitDirectReg(t *testing.T) {
	var secret, pubkey [32]byte
	pubkey[0] = 7
	reg := EncodeReg(secret, pubkey, time.Now())
	wgPkt := []byte{1, 0, 0, 0, 0x5a, 0x5a}
	joined := append(append([]byte{}, reg...), wgPkt...)

	gotReg, rest, ok := SplitDirectReg(joined)
	if !ok || len(gotReg) != len(reg) || string(rest) != string(wgPkt) {
		t.Fatalf("ok=%v reg=%d rest=%v", ok, len(gotReg), rest)
	}
	if _, err := VerifyReg(secret, gotReg, time.Now(), 0); err != nil {
		t.Fatalf("拆出的 reg 校验失败: %v", err)
	}
	if _, _, ok := SplitDirectReg(wgPkt); ok {
		t.Fatal("裸 WG 包被误判为 reg 搭车")
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
