// Package server：homewayd 的服务端内部实现（wg-native-stack tasks 3.1/3.2）。
package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339) }

// State：后端运行态（state 目录）。身份密钥（peerId 的私钥半边）**升级不轮换**
// ——token 里烤的是公钥，换钥=所有 token 作废。
//
//	<dir>/key.bin        身份私钥（0600，genkey 产物，存在即复用）
//	<dir>/tokens.jsonl   已签发 token 台账（每行 {secret, endpoints, issued}）
type State struct{ dir string }

func OpenState(dir string) (*State, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &State{dir: dir}, nil
}

// PrivateKey 返回身份私钥（不存在则生成）。重启不变是 token 稳定性的前提。
func (s *State) PrivateKey() (wgtypes.Key, error) {
	path := filepath.Join(s.dir, "key.bin")
	if b, err := os.ReadFile(path); err == nil {
		if len(b) != 32 {
			return wgtypes.Key{}, fmt.Errorf("state: key.bin 长度 %d 非法", len(b))
		}
		return wgtypes.NewKey(b)
	} else if !errors.Is(err, os.ErrNotExist) {
		return wgtypes.Key{}, err
	}
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, err
	}
	if err := os.WriteFile(path, k[:], 0o600); err != nil {
		return wgtypes.Key{}, err
	}
	return k, nil
}

type tokenRecord struct {
	Secret    string           `json:"secret"`
	Endpoints []proto.Endpoint `json:"endpoints"`
	Issued    string           `json:"issued"`
}

// IssueToken 生成新 token：随机 secret、追加台账、返回可直接 EncodeToken 的结构。
func (s *State) IssueToken(eps []proto.Endpoint) (proto.Token, error) {
	priv, err := s.PrivateKey()
	if err != nil {
		return proto.Token{}, err
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return proto.Token{}, err
	}
	var tok proto.Token
	pub := priv.PublicKey()
	copy(tok.PeerID[:], pub[:])
	tok.Secret = secret
	tok.Endpoints = eps

	rec := tokenRecord{
		Secret:    base64.RawURLEncoding.EncodeToString(secret[:]),
		Endpoints: eps,
		Issued:    nowUTC(),
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return proto.Token{}, err
	}
	f, err := os.OpenFile(filepath.Join(s.dir, "tokens.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return proto.Token{}, err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return proto.Token{}, err
	}
	return tok, nil
}

// Secrets 加载全部已签发 token 的 secret（reg 验证时逐一试 HMAC，个人规模下 N 极小）。
func (s *State) Secrets() ([][32]byte, error) {
	b, err := os.ReadFile(filepath.Join(s.dir, "tokens.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out [][32]byte
	for _, line := range splitLines(b) {
		if len(line) == 0 {
			continue
		}
		var rec tokenRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("state: tokens.jsonl 坏行: %w", err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(rec.Secret)
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("state: tokens.jsonl secret 非法")
		}
		var s32 [32]byte
		copy(s32[:], raw)
		out = append(out, s32)
	}
	return out, nil
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}
