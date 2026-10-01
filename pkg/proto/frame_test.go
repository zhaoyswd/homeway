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

func TestBatchRoundTrip(t *testing.T) {
	var secret, pubkey [32]byte
	var devTag DevTag
	pubkey[0] = 7
	devTag[0] = 0x33
	reg := EncodeReg(secret, pubkey, devTag, time.Now())
	wgPkt := []byte{1, 0, 0, 0, 0x5a, 0x5a}

	enc := EncodeBatch(
		BatchMsg{Type: FrameTypeReg, Payload: reg},
		BatchMsg{Type: FrameTypeData, Payload: wgPkt},
	)
	typ, payload, err := DecodeFrame(enc)
	if err != nil || typ != FrameTypeBatch {
		t.Fatalf("容器帧头：typ=%d err=%v", typ, err)
	}
	msgs, err := DecodeBatch(payload)
	if err != nil || len(msgs) != 2 {
		t.Fatalf("解容器：%v msgs=%d", err, len(msgs))
	}
	// 顺序即语义：reg 必须先于 data（保 1 RTT 的登记先行）。
	if msgs[0].Type != FrameTypeReg || string(msgs[0].Payload) != string(reg) {
		t.Fatalf("msg[0] 应为 reg：typ=%d", msgs[0].Type)
	}
	if msgs[1].Type != FrameTypeData || string(msgs[1].Payload) != string(wgPkt) {
		t.Fatalf("msg[1] 应为 data：typ=%d", msgs[1].Type)
	}
	if _, _, err := VerifyReg(secret, msgs[0].Payload, time.Now(), 0); err != nil {
		t.Fatalf("容器内 reg 校验失败: %v", err)
	}
	// 畸形：截断的消息头 / 长度越界 / 空容器。
	if _, err := DecodeBatch(payload[:3]); err == nil {
		t.Fatal("截断消息头应报畸形")
	}
	if _, err := DecodeBatch(append([]byte{FrameTypeData, 0xFF, 0xFF}, []byte("x")...)); err == nil {
		t.Fatal("长度越界应报畸形")
	}
	if _, err := DecodeBatch(nil); err == nil {
		t.Fatal("空容器应报畸形")
	}
	// 单消息容器也可解（前向形态）。
	if msgs, err := DecodeBatch(mustBatchPayload(t, BatchMsg{Type: FrameTypeData, Payload: wgPkt})); err != nil || len(msgs) != 1 {
		t.Fatalf("单消息容器：%v msgs=%d", err, len(msgs))
	}
}

func mustBatchPayload(t *testing.T, m BatchMsg) []byte {
	t.Helper()
	_, payload, err := DecodeFrame(EncodeBatch(m))
	if err != nil {
		t.Fatal(err)
	}
	return payload
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
