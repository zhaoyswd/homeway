// Package server：homewayd 的服务端内部实现（wg-native-stack tasks 3.1/3.2）。
package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

// credID：凭证 id = secret 的台账短指纹（8 hex）。**确定派生、不落额外状态**——
// 老台账行没有 id 字段也能按 secret 现算；人可读、可引用（revoke/list 的句柄）。
func credID(secret [32]byte) string {
	sum := sha256.Sum256(secret[:])
	return hex.EncodeToString(sum[:4])
}

// State：后端运行态（state 目录）。身份密钥（peerId 的私钥半边）**升级不轮换**
// ——token 里烤的是公钥，换钥=所有 token 作废。
//
//	<dir>/key.bin        身份私钥（0600，genkey 产物，存在即复用）
//	<dir>/tokens.jsonl   已签发 token 台账（每行 {id, secret, endpoints, issued}）
//	<dir>/revoked.jsonl  凭证吊销表（append-only；每行 {id, secret, revoked, reason}）
//
// 台账 append-only 是写入纪律（末行 = 最近在用 token）；**吊销**不改台账，以独立
// 追加表表达（FIX-64：泄漏响应 = 吊销凭证 + 重启铸新；注册验证对已吊销 secret
// 一律拒——跟随读见 revokedFollower，无需重启即时生效）。
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
	// ID：凭证短指纹（FIX-64；credID(secret) 派生，写入时落字段便于人读，读取
	// 时按 secret 现算兜底——老台账行没有该字段也一致）。
	ID        string           `json:"id,omitempty"`
	Secret    string           `json:"secret"`
	Endpoints []proto.Endpoint `json:"endpoints"`
	Issued    string           `json:"issued"`
}

// TokenRecord / TokenLedgerEntry：台账的只读呈现（`serve token list` 面）。
type TokenLedgerEntry struct {
	ID        string
	Secret    string // base64（调用方决定是否掩码）
	Issued    string
	Endpoints []proto.Endpoint
	Revoked   bool
	Reason    string // 吊销原因（Revoked=true 时）
}

// Revocation：吊销表一条记录。
type Revocation struct {
	ID     string
	Secret string
	At     string
	Reason string
}

// revokedFileName / revocationsPath：吊销表落点（state 目录内，append-only）。
const revokedFileName = "revoked.jsonl"

func (s *State) revocationsPath() string { return filepath.Join(s.dir, revokedFileName) }

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

// ErrSecretRevoked：在用/待写凭证已进吊销表（FIX-64）。运行态据此停止打印 token
// 并大声提示重启铸新（旧 token 已作废，继续打印只会误导）。
var ErrSecretRevoked = errors.New("state: 该凭证已被吊销")

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
//
// FIX-64：已吊销的 secret 一律拒写（ErrSecretRevoked）——否则吊销后端点变化轮会把
// 死凭证的新一轮写进台账，末行不再代表有效 token。
func (s *State) AppendToken(secret [32]byte, eps []proto.Endpoint) error {
	if revoked, rerr := readRevokedSecrets(s.revocationsPath()); rerr != nil {
		return rerr
	} else if revoked[secret] {
		return ErrSecretRevoked
	}
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
		ID:        credID(secret),
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

// revokeRecord 吊销表一行的落盘形态。
type revokeRecord struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
	At     string `json:"revoked"`
	Reason string `json:"reason,omitempty"`
}

// Revoke 把一枚凭证记入吊销表（append-only；幂等：已在表内不重复追加）。
// **不改台账**（写入纪律：末行 = 最近在用 token 的不变量不动）。注册验证按
// 吊销表拒该 secret（在跑出口经跟随读即时生效，见 revokedFollower）。
func (s *State) Revoke(secret [32]byte, reason string) (already bool, err error) {
	if set, rerr := readRevokedSecrets(s.revocationsPath()); rerr == nil {
		if set[secret] {
			return true, nil
		}
	} else if !errors.Is(rerr, os.ErrNotExist) {
		return false, rerr
	}
	rec := revokeRecord{
		ID:     credID(secret),
		Secret: base64.RawURLEncoding.EncodeToString(secret[:]),
		At:     nowUTC(),
		Reason: reason,
	}
	line, merr := json.Marshal(rec)
	if merr != nil {
		return false, merr
	}
	f, oerr := os.OpenFile(s.revocationsPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if oerr != nil {
		return false, oerr
	}
	defer f.Close()
	if _, werr := f.Write(append(line, '\n')); werr != nil {
		return false, werr
	}
	return false, nil
}

// Revocations 吊销表全量（list 面；文件不存在 = 空）。
func (s *State) Revocations() ([]Revocation, error) {
	b, err := os.ReadFile(s.revocationsPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Revocation
	for _, line := range splitLines(b) {
		if len(line) == 0 {
			continue
		}
		var rec revokeRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("state: revoked.jsonl 坏行: %w", err)
		}
		out = append(out, Revocation{ID: rec.ID, Secret: rec.Secret, At: rec.At, Reason: rec.Reason})
	}
	return out, nil
}

// readRevokedSecrets 解析吊销表为 secret 集合（不存在的文件 = 空集）。
// 坏行按错误上报——吊销是安全面，不能静默当「没吊销」放行。
func readRevokedSecrets(path string) (map[[32]byte]bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[[32]byte]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := make(map[[32]byte]bool)
	for _, line := range splitLines(b) {
		if len(line) == 0 {
			continue
		}
		var rec revokeRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("state: revoked.jsonl 坏行: %w", err)
		}
		raw, derr := base64.RawURLEncoding.DecodeString(rec.Secret)
		if derr != nil || len(raw) != 32 {
			return nil, fmt.Errorf("state: revoked.jsonl secret 非法")
		}
		var s32 [32]byte
		copy(s32[:], raw)
		out[s32] = true
	}
	return out, nil
}

// Ledger 台账只读全量（`serve token list` 面）：逐行记录 + 吊销状态（按收紧后的
// 吊销表判定；末行 = 最近在用 token 的不变量由写入纪律保证）。
func (s *State) Ledger() ([]TokenLedgerEntry, error) {
	b, err := os.ReadFile(filepath.Join(s.dir, "tokens.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	revoked, rerr := readRevokedSecrets(s.revocationsPath())
	if rerr != nil {
		return nil, rerr
	}
	reasonOf := map[[32]byte]string{}
	if revs, _ := s.Revocations(); revs != nil {
		for _, r := range revs {
			raw, derr := base64.RawURLEncoding.DecodeString(r.Secret)
			if derr != nil || len(raw) != 32 {
				continue
			}
			var s32 [32]byte
			copy(s32[:], raw)
			reasonOf[s32] = r.Reason
		}
	}
	var out []TokenLedgerEntry
	for _, line := range splitLines(b) {
		if len(line) == 0 {
			continue
		}
		var rec tokenRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("state: tokens.jsonl 坏行: %w", err)
		}
		raw, derr := base64.RawURLEncoding.DecodeString(rec.Secret)
		if derr != nil || len(raw) != 32 {
			return nil, fmt.Errorf("state: tokens.jsonl secret 非法")
		}
		var s32 [32]byte
		copy(s32[:], raw)
		id := rec.ID
		if id == "" {
			id = credID(s32) // 老行没有 id 字段：按 secret 现算
		}
		out = append(out, TokenLedgerEntry{
			ID: id, Secret: rec.Secret, Issued: rec.Issued, Endpoints: rec.Endpoints,
			Revoked: revoked[s32], Reason: reasonOf[s32],
		})
	}
	return out, nil
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
// **已吊销的凭证被滤除**（FIX-64）：全被吊销 = 空集 → 启动路径据此铸出新的凭证
// （serve.go 的「零参首启」分支复用），旧 token 彻底作废。
func (s *State) Secrets() ([][32]byte, error) {
	revoked, rerr := readRevokedSecrets(s.revocationsPath())
	if rerr != nil {
		return nil, rerr
	}
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
		if revoked[s32] {
			continue
		}
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
