package server

import (
	"os"
	"testing"

	"github.com/zhaoyswd/homeway/pkg/proto"
)

// 3.1 判据①：密钥重启不变（两次 OpenState 同目录读同一把钥）。
func TestStateKeyPersistence(t *testing.T) {
	dir := t.TempDir()
	s1, err := OpenState(dir)
	if err != nil {
		t.Fatal(err)
	}
	k1, err := s1.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	// 模拟重启：新实例、同目录
	s2, err := OpenState(dir)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := s2.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if k1 != k2 {
		t.Fatal("身份密钥跨实例变化——token 会全体作废")
	}
	// 权限收紧
	fi, err := os.Stat(dir + "/key.bin")
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key.bin 权限 %v", fi.Mode().Perm())
	}
}

// 3.1 判据②：issue → parse round-trip + secret 台账可回读。
func TestStateIssueTokenRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenState(dir)
	if err != nil {
		t.Fatal(err)
	}
	eps := []proto.Endpoint{
		{Addr: "192.0.2.12:41641"},
		{Addr: "example.net:41641"},
		{Addr: "1.2.3.4:4430", Relay: true},
	}
	tok, err := s.IssueToken(eps)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := proto.EncodeToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := proto.DecodeToken(enc)
	if err != nil {
		t.Fatalf("issue→parse round-trip 失败：%v", err)
	}
	if dec.PeerID != tok.PeerID || dec.Secret != tok.Secret || len(dec.Endpoints) != 3 {
		t.Fatalf("round-trip 字段不匹配：%+v", dec)
	}
	// PeerID 必须是身份公钥（与私钥对应）
	priv, _ := s.PrivateKey()
	pub := priv.PublicKey()
	var want [32]byte
	copy(want[:], pub[:])
	if tok.PeerID != want {
		t.Fatal("token PeerID 与身份公钥不符")
	}

	// 第二个 token secret 不同；台账两条都能回读
	tok2, _ := s.IssueToken(eps)
	if tok2.Secret == tok.Secret {
		t.Fatal("两次签发不应产生相同 secret")
	}
	secrets, err := s.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 2 {
		t.Fatalf("台账条数=%d", len(secrets))
	}
}
