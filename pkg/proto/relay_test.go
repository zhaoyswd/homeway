package proto

// relay_test.go — 中继协议 v2-only 形状门（FIX-89，2026-10-02）：
// PROOF（50B）/ CtlSession（27B）/ OK（17B）只认单一版本形态——历史形态
// （33B/49B PROOF、11B 无 cookie SESSION、裸 1B OK）与带 "=" 填充的 token 必须被拒。

import (
	"bytes"
	"testing"
)

func TestRelayProofV2OnlyShape(t *testing.T) {
	var nonce [16]byte
	var pub [32]byte
	dh := make([]byte, 32)
	psk := make([]byte, 16)
	full := EncodeRelayProof(nonce, dh, pub, psk, RelayCtlVer)
	if len(full) != 50 {
		t.Fatalf("PROOF 长度 = %d, want 50", len(full))
	}
	gotNonce, macDH, macPSK, ver, err := DecodeRelayProof(full)
	if err != nil || gotNonce != nonce || len(macDH) != 16 || len(macPSK) != 16 || ver != RelayCtlVer {
		t.Fatalf("50B 形态解码失败: err=%v ver=%d", err, ver)
	}
	// 历史形态：49B（无版本字节）与 33B（只有 macDH）必须被拒。
	if _, _, _, _, err := DecodeRelayProof(full[:49]); err == nil {
		t.Fatal("49B（无版本）形态竟然可解——版本门失效")
	}
	if _, _, _, _, err := DecodeRelayProof(full[:33]); err == nil {
		t.Fatal("33B 形态竟然可解——老形态门失效")
	}
}

func TestCtlSessionV2OnlyShape(t *testing.T) {
	s := CtlSession{ID: 7, DataPort: 41641}
	for i := range s.Cookie {
		s.Cookie[i] = byte(i)
	}
	enc := EncodeCtlSession(s)
	if len(enc) != 27 {
		t.Fatalf("SESSION 长度 = %d, want 27", len(enc))
	}
	dec, err := DecodeCtlSession(enc)
	if err != nil || dec.ID != s.ID || dec.DataPort != s.DataPort || !bytes.Equal(dec.Cookie[:], s.Cookie[:]) {
		t.Fatalf("27B 形态解码失败: %+v err=%v", dec, err)
	}
	// 11B（无 cookie 的历史形态）必须被拒。
	if _, err := DecodeCtlSession(enc[:11]); err == nil {
		t.Fatal("11B 形态竟然可解——老形态门失效")
	}
}

func TestRelayOKV2OnlyShape(t *testing.T) {
	// 17B 形态可解。
	if got, ok := DecodeRelayOKAuth(append([]byte{RelaySubOK}, make([]byte, 16)...)); !ok || len(got) != 16 {
		t.Fatal("17B OK 形态解码失败")
	}
	// 裸 1B（老形状）必须被拒。
	if _, ok := DecodeRelayOKAuth([]byte{RelaySubOK}); ok {
		t.Fatal("裸 1B OK 竟然可解——老形态门失效")
	}
	// Encode 恒补零到 17B（开放模式零 MAC 也同形状）。
	if got := EncodeRelayOKAuth(nil); len(got) != 17 || got[0] != RelaySubOK {
		t.Fatalf("零 MAC OK 形状错误：len=%d", len(got))
	}
}

func TestTokenRejectsPaddedBase64(t *testing.T) {
	// 容忍 "=" 尾缀的兼容已删（FIX-89）：填充形态报格式非法（编码侧本就恒无填充）。
	if _, err := DecodeToken(goldenToken + "="); err == nil {
		t.Fatal("带 '=' 填充的 token 竟然可解——填充容忍未删")
	}
}
