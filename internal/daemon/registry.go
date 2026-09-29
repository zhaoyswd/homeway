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

// 哨兵错误（控制面 Backend 映射到错误码表：errHostExists → host_exists、
// ErrBadToken → bad_token、errNoHost → no_host）。
var (
	// errHostExists 同 token 重复添加（键 = peerID：同后端不同 token = 刷新，不是这个错）。
	errHostExists = errors.New("host 已在表中（同 token 重复添加）")
	// ErrBadToken token 本地解析失败（3a 的 host.add 语义 = 仅解析入表）。
	ErrBadToken = errors.New("token 非法")
	// errNoHost 主机不在表。
	errNoHost = errors.New("host 不在表中")
	// errStopTimeout 用户面操作（同键刷新/Remove）遇会话停止超时（host-cli 3b B7：
	// 拒绝该操作 + events.log 记行——控制面按既有未知错误映射回 bad_request，
	// 语义错位如实注记：不发明新错误码、不合成 state_changed 事件）。
	errStopTimeout = errors.New("会话停止超时（垂死会话仍在收尾）")
)

// stopFunc 会话停步注入缝（host-cli 3b B7②，design D7）：同包测试注入 -1 走
// 「用户面拒绝 + events.log 记行」与「清理面记行后继续」两条路径；生产 =
// Session.Stop（0 = 已收工；-1 = 等待超时，此后 Start 一直 -1 直到真正退出）。
var stopFunc = func(s *hostsession.Session) int { return s.Stop() }

// RegistryEvents 注册表事件接缝（§3 事件面：控制面总线的 session 域事件源）。
// 回调在 Registry 锁外调用（发射锁序：会话/注册表锁 → 总线锁单向，design A4）。
type RegistryEvents interface {
	// HostAdded 新主机入表（session.added）。
	HostAdded(id, name string, addedAt int64)
	// HostRemoved 主机摘除（session.removed）。
	HostRemoved(id, reason string)
	// HostStateChanged 会话状态迁移（session.state_changed——hostsession Observer
	// 的转发；state 值域随状态机：starting/ready/failed/stopping/idle）。
	HostStateChanged(id, from, to, reason string)
}

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
	eventf   func(format string, args ...any)
	events   RegistryEvents
	// carried 装载时 id 非法条目的原样携带（D7-a，term-remote 3.1）：不启动会话、
	// 不进寻址面（Hosts/Sessions 均不含），但**落盘时随有效记录一并写回**——「条目
	// 保留」由 recordsLocked 兑现（改前装载日志声称保留、下次落盘却把它写掉）。
	// 用户可见滞留（日志指路手工清理）；「不丢数据」优先于「表自洁」——自洁正是
	// 被定为 bug 的行为。
	carried []HostRecord

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
	// Events 事件接缝（nil = 不发；控制面装配时注入总线适配）。
	Events RegistryEvents
	// Eventf 事件级告警口（hosts.json 损坏备份等用户应见的异常；nil = 降级 Logf）。
	Eventf func(format string, args ...any)
}

// OpenRegistry 打开注册表：读 hosts.json（缺失 = 空表；损坏 = 备份后空表 + 事件级
// 告警，见 loadHosts）并按表逐后端拉会话（「重启按表恢复」——会话与端点缓存/身份
// 按既有目录布局复用）。
func OpenRegistry(stateDir string, opts RegistryOptions) (*Registry, error) {
	r := &Registry{
		stateDir:   stateDir,
		hosts:      make(map[[32]byte]*hostEntry),
		strict:     opts.StrictIdentity,
		logf:       opts.Logf,
		eventf:     opts.Eventf,
		events:     opts.Events,
		newSession: hostsession.NewSession,
	}
	if r.logf == nil {
		r.logf = hostsession.Discard
	}
	if r.eventf == nil {
		r.eventf = func(format string, args ...any) { r.logf("hosts: "+format, args...) }
	}
	recs, err := loadHosts(filepath.Join(stateDir, hostsFileName), r.eventf)
	if err != nil {
		return nil, err
	}
	for _, rec := range recs {
		var id [32]byte
		b, derr := hex.DecodeString(rec.ID)
		if derr != nil || len(b) != 32 {
			why := fmt.Sprintf("长度 %d ≠ 64 位 hex", len(rec.ID))
			if derr != nil {
				why = derr.Error()
			}
			r.carried = append(r.carried, rec)
			r.logf("hosts: 记录 %q 的 id 非法（%s）——保留在表、不启动会话、不参与寻址；可手工修正或删除该条目", rec.ID, why)
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
	var obs hostsession.Observer
	if r.events != nil {
		hostID := rec.ID
		ev := r.events
		obs = stateChangedFunc(func(s *hostsession.Session, from, to, reason string) {
			ev.HostStateChanged(hostID, from, to, reason)
		})
	}
	sess, err := r.newSession(cfg, hostsession.Options{StrictIdentity: r.strict, Observer: obs})
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
// （后端重签发）→ 刷新记录。落盘 hosts.json（0600）。
//
// B5（host-cli 3b，design D7 拍板）：**先落盘再 Start/换会话**——新键 = 落盘成功
// 才入表 + Start（落盘失败零副作用：内存未动、无会话已起）；同键刷新 = 先落盘新
// token（内存暂不动——失败即回滚，内存不留新 token、旧会话照跑）→ 停旧 → 起新、
// 内存记录换新值。一次落盘失败既不丢已登记主机也不留孤儿会话。
func (r *Registry) Add(name, token string) (HostRecord, error) {
	tok, err := proto.DecodeToken(token)
	if err != nil {
		return HostRecord{}, fmt.Errorf("%w：%v", ErrBadToken, err)
	}
	// B6：事件 payload 锁内拷贝、锁外 emit（回调重入 Hosts()/Sessions() 不再自死锁）。
	var emitAdded func()
	r.mu.Lock()
	defer func() {
		r.mu.Unlock()
		if emitAdded != nil {
			emitAdded()
		}
	}()
	if e, ok := r.hosts[tok.PeerID]; ok {
		if e.rec.Token == token {
			return HostRecord{}, errHostExists
		}
		// 同后端重签发：同键刷新（D2——「token 哈希」备选否决的理由）。
		newRec := e.rec
		newRec.Token = token
		if name != "" {
			newRec.Name = name
		}
		next := replaceRecord(r.recordsLocked(), newRec)
		if err := r.saveRecordsLocked(next); err != nil {
			return HostRecord{}, err // 内存保持旧 token、旧会话照跑（磁盘也未动）
		}
		// 停旧会话。B7①（用户面）：Stop -1 = 拒绝该操作 + events.log 记行——此时
		// 磁盘或已含新 token、内存保持旧值，重试或重启按磁盘收敛（如实注记）。
		// 「拒绝」是名义拒绝（exec-r1 第 7 条措辞对齐）：拒绝的是**更新内存**——
		// Stop 已被调用过一次（stopOnce 不可回退），旧会话对象虽仍在册但已进入
		// 收尾/垂死，该主机短暂离线属预期。
		if e.sess != nil && stopFunc(e.sess) < 0 {
			r.eventf("hosts: %s（%s）token 刷新被拒——会话停止超时（-1，垂死会话仍在收尾；重试或重启按磁盘收敛）", e.rec.ID, e.rec.Name)
			return HostRecord{}, errStopTimeout
		}
		e.rec = newRec
		ne := r.startEntryLocked(newRec)
		e.sess = ne.sess
		r.logf("hosts: %s（%s）token 已刷新（同后端重签发）", e.rec.ID, e.rec.Name)
		return e.rec, nil
	}
	rec := HostRecord{
		ID:      hex.EncodeToString(tok.PeerID[:]),
		Name:    name,
		Token:   token,
		AddedAt: time.Now(),
	}
	if err := r.saveRecordsLocked(append(r.recordsLocked(), rec)); err != nil {
		return HostRecord{}, err // 落盘失败零副作用：内存未动、无会话已起
	}
	r.hosts[tok.PeerID] = r.startEntryLocked(rec)
	r.logf("hosts: + %s（%s）", rec.ID, rec.Name)
	if r.events != nil {
		id, nm, at := rec.ID, rec.Name, rec.AddedAt.UnixMilli()
		ev := r.events
		emitAdded = func() { ev.HostAdded(id, nm, at) }
	}
	return rec, nil
}

// Remove 摘除一台主机（先落盘、停会话、删条目——B5 对称化：落盘失败 = 内存与会话
// 均未动）。停会话遇 -1 = B7① 用户面拒绝 + events.log 记行（磁盘或已不含该记录，
// 重试或重启按磁盘收敛）。
func (r *Registry) Remove(id [32]byte) error {
	var emitRemoved func()
	r.mu.Lock()
	defer func() {
		r.mu.Unlock()
		if emitRemoved != nil {
			emitRemoved()
		}
	}()
	e, ok := r.hosts[id]
	if !ok {
		return fmt.Errorf("%w：%s", errNoHost, hex.EncodeToString(id[:]))
	}
	if err := r.saveRecordsLocked(withoutRecord(r.recordsLocked(), e.rec.ID)); err != nil {
		return err // 内存未动、会话未动
	}
	if e.sess != nil && stopFunc(e.sess) < 0 {
		r.eventf("hosts: %s（%s）删除被拒——会话停止超时（-1，垂死会话仍在收尾；重试或重启按磁盘收敛）", e.rec.ID, e.rec.Name)
		return errStopTimeout
	}
	// 同上（exec-r1 第 7 条）：-1 时磁盘已无该条目、内存条目仍在——「拒绝」= 拒绝
	// 摘除内存；会话已进收尾、该主机短暂离线属预期，重试收敛。
	delete(r.hosts, id)
	r.logf("hosts: - %s（%s）", e.rec.ID, e.rec.Name)
	if r.events != nil {
		rid, reason := e.rec.ID, "user"
		ev := r.events
		emitRemoved = func() { ev.HostRemoved(rid, reason) }
	}
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

// SessionEntry 一台主机的登记与会话对（Sessions 拷贝产物——调用方在锁外做
// 会话快照，锁序路径②：Registry.mu 拷贝集合 → 各会话无锁快照 → 末读总线 seq）。
type SessionEntry struct {
	Rec  HostRecord
	Sess *hostsession.Session
}

// Sessions 拷贝全部 (登记, 会话) 对（状态面/流腿用；每记录自持语义不变）。
func (r *Registry) Sessions() []SessionEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]SessionEntry, 0, len(r.hosts))
	for _, e := range r.hosts {
		out = append(out, SessionEntry{Rec: e.rec, Sess: e.sess})
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

// Close 收工：停全部会话。B7③（清理收工面）：Stop -1 记 events.log 后**继续**
// ——垂死会话不绑架注册表收工与进程退出（尽力语义）。
func (r *Registry) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, e := range r.hosts {
		if e.sess != nil && stopFunc(e.sess) < 0 {
			r.eventf("hosts: %s（%s）收工停止超时（-1），继续收下一台", e.rec.ID, e.rec.Name)
		}
		delete(r.hosts, id)
	}
}

// recordsLocked 当前表记录快照（调用方持锁）。**含 carried**：非法 id 条目随每次
// 落盘原样写回（D7-a「条目保留」由这里兑现——顺序：有效表在前、carried 原序在后；
// Hosts/Sessions 的寻址面仍不含 carried，二者刻意不同源）。
func (r *Registry) recordsLocked() []HostRecord {
	recs := make([]HostRecord, 0, len(r.hosts)+len(r.carried))
	for _, e := range r.hosts {
		recs = append(recs, e.rec)
	}
	return append(recs, r.carried...)
}

// replaceRecord 记录集内同 ID 替换（无则追加）。
func replaceRecord(recs []HostRecord, rec HostRecord) []HostRecord {
	for i := range recs {
		if recs[i].ID == rec.ID {
			recs[i] = rec
			return recs
		}
	}
	return append(recs, rec)
}

// withoutRecord 记录集内剔除指定 ID。
func withoutRecord(recs []HostRecord, id string) []HostRecord {
	out := make([]HostRecord, 0, len(recs))
	for _, rc := range recs {
		if rc.ID != id {
			out = append(out, rc)
		}
	}
	return out
}

// saveRecordsLocked 落盘指定记录集（0600）。调用方持锁。B5：入表/换会话**之前**
// 调用（本函数不要求内存表已含新记录——记录集由调用方组装）。
//
// temp + rename 原子替换：kill -9 落在写窗口也只会留下完整旧表或完整新表，
// 不产生截断 JSON（此前裸 os.WriteFile 覆写 × 损坏即拒启 = 主机表不可恢复——
// exec-r1 M2）。
func (r *Registry) saveRecordsLocked(recs []HostRecord) error {
	path := filepath.Join(r.stateDir, hostsFileName)
	if err := os.MkdirAll(r.stateDir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// stateChangedFunc hostsession.Observer 的函数适配。
type stateChangedFunc func(s *hostsession.Session, from, to, reason string)

func (f stateChangedFunc) StateChanged(s *hostsession.Session, from, to, reason string) {
	f(s, from, to, reason)
}

// loadHosts 读主机表。缺失 = 空表；损坏 = 备份 `hosts.json.corrupt-<ts>` 后按空表
// 启动 + warnf 事件级告警（exec-r1 M2：损坏即拒启会让 client 角色无限退避、daemon
// 永远 not_ready，且无自愈路径——备份保住「不静默清空」的初衷（原件保留可人工修复，
// 修复后重启即恢复），空表启动保住 daemon 不被一份坏文件锁死）。备份本身失败（目录
// 只读等）仍报错拒启：那时空表启动等于下一次落盘就把主机表真清空。
func loadHosts(path string, warnf func(string, ...any)) ([]HostRecord, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var recs []HostRecord
	if err := json.Unmarshal(b, &recs); err != nil {
		backup := fmt.Sprintf("%s.corrupt-%d", path, time.Now().Unix())
		if rerr := os.Rename(path, backup); rerr != nil {
			return nil, fmt.Errorf("hosts.json 损坏（%v）且备份失败：%w", err, rerr)
		}
		warnf("hosts.json 损坏（%v）——已备份 %s，按空表启动（原件保留，可修复后重启恢复）", err, backup)
		return nil, nil
	}
	return recs, nil
}
