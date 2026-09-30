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
	// 既有目录收紧到 0700（term-host-cli exec-r5 F2）：MkdirAll 的 mode 只对**新建**
	// 目录生效——历史部署可能已是 0755（阿里云实测 /opt/homeway/data=755，与文档
	// 「state 目录 0700 是边界」的口径不符）。chmod 失败只告警不阻断：边界还有
	// socket 0600 那一层兜着（见 serve.go），这里尽力而为。
	if err := os.Chmod(dir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "homewayd: ⚠️ state 目录 %s 收紧 0700 失败（%v）——与文档权限边界口径不一致，建议手工 chmod\n", dir, err)
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

	if err := appendTokenRecord(s.dir, secret, eps); err != nil {
		return proto.Token{}, err
	}
	return tok, nil
}

// AppendToken 台账写入纪律的追加入口（role-management 2.4，r1 高-1 / r2 新-1）：
// 每次铸出与台账末行**不同**的 token 即追加一条（含启动首轮；无变化不追加）——
// 由此「台账末行 = 最近在用 token」成为不变量（`serve token` 未跑直读与 status
// 掩码指纹都以末行为准）。追加记录 = 调用方传入的在用 secret〔secrets[0]〕+ 该枚
// token 的实时端点，append-only 语义不变。
//
// **不复用 IssueToken**：其内部 rand.Read 每次新签发 secret，与「secret 复用在用
// secret」矛盾（照字面调用会写出「末行 secret ≠ 在用 secret」的记录）。
// 去重判据（secret + endpoints 都相同 = 无变化）收在本函数里，调用方每轮铸出后
// 直接调它即可（进程内存 lastToken 去重只管终端一轮制，与台账追加是两回事）。
func (s *State) AppendToken(secret [32]byte, eps []proto.Endpoint) error {
	last, err := s.lastRecord()
	if err != nil {
		return err
	}
	if last != nil {
		var lastSecret [32]byte
		if raw, derr := base64.RawURLEncoding.DecodeString(last.Secret); derr == nil && len(raw) == 32 {
			copy(lastSecret[:], raw)
			if lastSecret == secret && endpointSetEqual(last.Endpoints, eps) {
				return nil // 无变化不追加
			}
		}
	}
	return appendTokenRecord(s.dir, secret, eps)
}

// appendTokenRecord 追加一条台账行（0600、O_APPEND）。
func appendTokenRecord(dir string, secret [32]byte, eps []proto.Endpoint) error {
	rec := tokenRecord{
		Secret:    base64.RawURLEncoding.EncodeToString(secret[:]),
		Endpoints: eps,
		Issued:    nowUTC(),
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "tokens.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return nil
}

// lastRecord 台账末行（nil = 空台账）——「末行 = 最近在用 token」的读半边。
func (s *State) lastRecord() (*tokenRecord, error) {
	b, err := os.ReadFile(filepath.Join(s.dir, "tokens.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	lines := splitLines(b)
	for i := len(lines) - 1; i >= 0; i-- {
		if len(lines[i]) == 0 {
			continue
		}
		var rec tokenRecord
		if err := json.Unmarshal(lines[i], &rec); err != nil {
			return nil, fmt.Errorf("state: tokens.jsonl 坏行: %w", err)
		}
		return &rec, nil
	}
	return nil, nil
}

// endpointSetEqual 端点列表等值比较（顺序敏感——同一轮铸出的端点序固定）。
func endpointSetEqual(a, b []proto.Endpoint) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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
