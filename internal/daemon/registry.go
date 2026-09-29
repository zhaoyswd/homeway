// Package daemon — homeway 守护进程（host-registry-daemon）：多主机会话注册表、
// 单实例锁、state 布局与角色子系统（D2–D4）。本期（3a）只有 client 角色的骨架。
package daemon

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/hostsession"
	"github.com/zhaoyswd/homeway/pkg/proto"
)

// hostsFileName 主机表持久化文件（0600，D2/D3）。
const hostsFileName = "hosts.json"

// errHostExists 同 token 重复添加（键 = peerID：同后端不同 token = 刷新，不是这个错）。
var errHostExists = errors.New("host 已在表中（同 token 重复添加）")

// HostRecord hosts.json 的一条：一台后端主机的登记（键 = ID = token 里的后端公钥）。
type HostRecord struct {
	ID      string    `json:"id"` // peerID hex（后端实例稳定身份，D2：备选 token 哈希否决——同后端重签发会裂成两条）
	Name    string    `json:"name,omitempty"`
	Token   string    `json:"token"`
	AddedAt time.Time `json:"addedAt"`
}

// hostEntry 一台主机的运行时：登记记录 + 自持会话（recGate/巡检/重建限频全在
// hostsession.Session 内——按记录天然隔离，D2「每记录自持」）。
type hostEntry struct {
	rec  HostRecord
	sess *hostsession.Session
}

// Registry 多主机会话注册表（HD「多主机会话注册表」；D2：键 = peerID，全部状态自持，
// 桥为零——Options.BridgeFactory = nil，桌面直拨隧道端口）。
type Registry struct {
	mu       sync.Mutex
	stateDir string
	hosts    map[[32]byte]*hostEntry
	strict   bool
	logf     hostsession.Logf

	// newSession 会话构造接缝（默认 hostsession.NewSession；同包测试注入桩）。
	newSession func(cfg hostsession.Config, opts hostsession.Options) (*hostsession.Session, error)
}

// RegistryOptions 注册表构造项。
type RegistryOptions struct {
	// StrictIdentity 严格身份（D2/N2：daemon = true——身份不可持久化视为该主机
	// failed reason=identity_ephemeral，杜绝出口设备表被临时钥匙刷爆）。
	StrictIdentity bool
	// Logf 注册表自身日志（nil = 丢弃）。
	Logf hostsession.Logf
}

// OpenRegistry 打开注册表：读 hosts.json（缺失 = 空表）并按表逐后端拉会话
// （「重启按表恢复」——会话与端点缓存/身份按既有目录布局复用）。
func OpenRegistry(stateDir string, opts RegistryOptions) (*Registry, error) {
	r := &Registry{
		stateDir:   stateDir,
		hosts:      make(map[[32]byte]*hostEntry),
		strict:     opts.StrictIdentity,
		logf:       opts.Logf,
		newSession: hostsession.NewSession,
	}
	if r.logf == nil {
		r.logf = hostsession.Discard
	}
	recs, err := loadHosts(filepath.Join(stateDir, hostsFileName))
	if err != nil {
		return nil, err
	}
	for _, rec := range recs {
		var id [32]byte
		b, derr := hex.DecodeString(rec.ID)
		if derr != nil || len(b) != 32 {
			r.logf("hosts: 记录 %q 的 id 非法（跳过启动，条目保留）：%v", rec.ID, derr)
			continue
		}
		copy(id[:], b)
		r.hosts[id] = r.startEntryLocked(rec)
	}
	return r, nil
}

// startEntryLocked 为一条记录构造并启动会话（调用方持锁或单线程装配期）。
func (r *Registry) startEntryLocked(rec HostRecord) *hostEntry {
	e := &hostEntry{rec: rec}
	cfg := hostsession.Config{
		Token:            rec.Token,
		IdentityDir:      filepath.Join(r.stateDir, "identity"),  // 复用 wtransport 机制（D3）
		EndpointCacheDir: filepath.Join(r.stateDir, "endpoints"), // 现布局天然按 peerID 分文件（D2）
		Out:              filepath.Join(r.stateDir, "debug.log"), // 追加写；分级/轮转沿出口口径（D3，2.2/2.3 收口）
	}
	sess, err := r.newSession(cfg, hostsession.Options{StrictIdentity: r.strict})
	if err != nil {
		// 构造期唯一错误源 = 日志文件打不开：条目仍入表（记录在案、状态面 failed），
		// 不因日志问题丢主机登记。
		r.logf("hosts: %s（%s）会话构造失败：%v", rec.ID, rec.Name, err)
		return e
	}
	sess.Start()
	e.sess = sess
	return e
}

// Add 添加/刷新一台主机：同 token 重复添加 → errHostExists；同 peerID 新 token
// （后端重签发）→ 刷新记录（停旧会话、按新 token 起会话）。落盘 hosts.json（0600）。
func (r *Registry) Add(name, token string) (HostRecord, error) {
	tok, err := proto.DecodeToken(token)
	if err != nil {
		return HostRecord{}, fmt.Errorf("token 解析失败：%w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.hosts[tok.PeerID]; ok {
		if e.rec.Token == token {
			return HostRecord{}, errHostExists
		}
		// 同后端重签发：同键刷新（D2——「token 哈希」备选否决的理由）。
		if e.sess != nil {
			_ = e.sess.Stop()
		}
		e.rec.Token = token
		if name != "" {
			e.rec.Name = name
		}
		ne := r.startEntryLocked(e.rec)
		e.sess = ne.sess
		if err := r.saveLocked(); err != nil {
			return HostRecord{}, err
		}
		r.logf("hosts: %s（%s）token 已刷新（同后端重签发）", e.rec.ID, e.rec.Name)
		return e.rec, nil
	}
	rec := HostRecord{
		ID:      hex.EncodeToString(tok.PeerID[:]),
		Name:    name,
		Token:   token,
		AddedAt: time.Now(),
	}
	r.hosts[tok.PeerID] = r.startEntryLocked(rec)
	if err := r.saveLocked(); err != nil {
		delete(r.hosts, tok.PeerID)
		return HostRecord{}, err
	}
	r.logf("hosts: + %s（%s）", rec.ID, rec.Name)
	return rec, nil
}

// Remove 摘除一台主机（停会话、删条目、落盘）。
func (r *Registry) Remove(id [32]byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.hosts[id]
	if !ok {
		return fmt.Errorf("host %s 不在表中", hex.EncodeToString(id[:]))
	}
	if e.sess != nil {
		_ = e.sess.Stop()
	}
	delete(r.hosts, id)
	if err := r.saveLocked(); err != nil {
		return err
	}
	r.logf("hosts: - %s（%s）", e.rec.ID, e.rec.Name)
	return nil
}

// Hosts 表快照（登记记录；按 ID 排序稳定输出）。
func (r *Registry) Hosts() []HostRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]HostRecord, 0, len(r.hosts))
	for _, e := range r.hosts {
		out = append(out, e.rec)
	}
	// 插入排序（表长是个位数）。
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].ID < out[j-1].ID; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// Session 取一台主机的会话（daemon 流腿/状态面用；不在表 = nil）。
func (r *Registry) Session(id [32]byte) *hostsession.Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.hosts[id]; ok {
		return e.sess
	}
	return nil
}

// Close 收工：停全部会话。
func (r *Registry) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, e := range r.hosts {
		if e.sess != nil {
			_ = e.sess.Stop()
		}
		delete(r.hosts, id)
	}
}

// saveLocked 落盘主机表（0600）。调用方持锁。
func (r *Registry) saveLocked() error {
	path := filepath.Join(r.stateDir, hostsFileName)
	if err := os.MkdirAll(r.stateDir, 0o700); err != nil {
		return err
	}
	recs := make([]HostRecord, 0, len(r.hosts))
	for _, e := range r.hosts {
		recs = append(recs, e.rec)
	}
	b, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// loadHosts 读主机表（缺失 = 空表；损坏 = 报错拒启——主机表是持久化真源，
// 静默清空等于丢主机）。
func loadHosts(path string) ([]HostRecord, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var recs []HostRecord
	if err := json.Unmarshal(b, &recs); err != nil {
		return nil, fmt.Errorf("hosts.json 损坏：%w", err)
	}
	return recs, nil
}
