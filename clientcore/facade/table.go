package facade

// table.go — 角色级主机表（D1；自 internal/daemon/registry.go 逐段迁入，4a 任务
// 3.1——hosts.json 原子落盘、carried 保真、B5 先落盘再 Start/换会话、B6 锁内拷
// payload 锁外 emit、B7 stopFunc 注入缝、StrictIdentity、每记录自持，语义逐字
// 保留）。表由 Daemon.Attach/Detach 持有（角色级生命周期）；操作面（AddHost 的
// decode→有界探测→入表）自 daemon 侧 controlBackend 迁入 Daemon.AddHost。

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/hostsession"
	"github.com/zhaoyswd/homeway/pkg/probe"
	"github.com/zhaoyswd/homeway/pkg/proto"
)

// hostsFileName 主机表持久化文件（0600）。
const hostsFileName = "hosts.json"

// 表/操作面哨兵错误（绑定层映射到错误码表：ErrHostExists → host_exists、
// ErrBadToken → bad_token、ErrNoHost → no_host、ErrHostUnreachable →
// host_unreachable、ErrNotReady → not_ready 门由绑定层前置）。
var (
	// ErrHostExists 同 token 重复添加（键 = peerID：同后端不同 token = 刷新，不是这个错）。
	ErrHostExists = errors.New("host 已在表中（同 token 重复添加）")
	// ErrBadToken token 本地解析失败（host.add 语义 = 仅解析入表）。
	ErrBadToken = errors.New("token 非法")
	// ErrNoHost 主机不在表（兼作拨号面「登记在册但会话对象不在」——绑定点沿
	// no_host 族映射，保持既有 wire 行为）。
	ErrNoHost = errors.New("host 不在表中")
	// ErrHostUnreachable host.add 验证结论为全不可达且未带 force（不入表）。
	ErrHostUnreachable = errors.New("host 全不可达（探测无应答且未带 force）")
	// ErrNotReady 表未 attach（角色未跑/重建窗口）。
	ErrNotReady = errors.New("主机表未就绪（未 attach/重建窗口）")
	// errStopTimeout 用户面操作（同键刷新/Remove）遇会话停止超时（host-cli 3b B7：
	// 拒绝该操作 + events.log 记行——控制面按既有未知错误映射回 bad_request，
	// 语义错位如实注记：不发明新错误码、不合成 state_changed 事件）。
	errStopTimeout = errors.New("会话停止超时（垂死会话仍在收尾）")
)

// stopFunc 会话停步注入缝（host-cli 3b B7②）：同包测试注入 -1 走「用户面拒绝 +
// events.log 记行」与「清理面记行后继续」两条路径；生产 = Session.Stop（0 = 已
// 收工；-1 = 等待超时，此后 Start 一直 -1 直到真正退出）。
var stopFunc = func(s *hostsession.Session) int { return s.Stop() }

// newSession 会话构造接缝（默认 hostsession.NewSession；同包测试注入计数桩）。
var newSession = hostsession.NewSession

// TableEvents 主机表事件接缝（§3.2 事件面：session 域事件源）。回调在表锁外
// 调用（发射锁序：表锁 → 总线锁单向）。Daemon.Attach 默认接线 = busEvents
// （直发进程级总线）；表级测试注入自定义接缝（B6 重入用例）。
type TableEvents interface {
	// HostAdded 新主机入表（session.added）。
	HostAdded(id, name string, addedAt int64)
	// HostRemoved 主机摘除（session.removed；reason 值域：user = 显式摘除、
	// detach = 表收工〔r2 新-15 契约③——Detach 逐台照发〕）。
	HostRemoved(id, reason string)
	// HostStateChanged 会话状态迁移（session.state_changed——hostsession Observer
	// 的转发；state 值域随状态机：starting/ready/failed/stopping/idle）。
	HostStateChanged(id, from, to, reason string)
}

// busEvents TableEvents → 进程级总线（session 域，§3.2 事件源直发——替代已删的
// daemon 侧 registryEventsAdaptor）。载荷与词表同源（vocab.go）。
type busEvents struct{ bus *Bus }

func (e *busEvents) HostAdded(id, name string, addedAt int64) {
	_, _ = e.bus.Publish(DomainSession, KindSessionAdded,
		SessionAddedPayload{Host: id, Name: name, AddedAt: addedAt})
}

func (e *busEvents) HostRemoved(id, reason string) {
	_, _ = e.bus.Publish(DomainSession, KindSessionRemoved,
		SessionRemovedPayload{Host: id, Reason: reason})
}

func (e *busEvents) HostStateChanged(id, from, to, reason string) {
	_, _ = e.bus.Publish(DomainSession, KindSessionStateChanged,
		SessionStateChangedPayload{Host: id, State: to, Reason: reason})
}

// HostRecord hosts.json 的一条：一台后端主机的登记（键 = ID = token 里的后端公钥）。
type HostRecord struct {
	ID      string    `json:"id"` // peerID hex（后端实例稳定身份：备选 token 哈希否决——同后端重签发会裂成两条）
	Name    string    `json:"name,omitempty"`
	Token   string    `json:"token"`
	AddedAt time.Time `json:"addedAt"`
}

// hostEntry 一台主机的运行时：登记记录 + 自持会话（recGate/巡检/重建限频全在
// hostsession.Session 内——按记录天然隔离，「每记录自持」）+ 需求合成状态
// （§6.2 hostDemand：三源采样/在场腿/拨号计数，随条目生命周期）。
type hostEntry struct {
	rec  HostRecord
	sess *hostsession.Session
	dm   *hostDemand
}

// hostTable 多主机会话注册表（自 internal/daemon/registry.go 迁入；键 = peerID，
// 全部状态自持，桥为零——Options.BridgeFactory = nil，桌面直拨隧道端口）。
type hostTable struct {
	mu       sync.Mutex
	stateDir string
	hosts    map[[32]byte]*hostEntry
	strict   bool
	logf     func(format string, args ...any)
	eventf   func(format string, args ...any)
	events   TableEvents
	hooks    tableHooks
	// opMu 表**变更**（Add/Remove/Close）的串行化（FIX-07）：临界区比 r.mu 宽——覆盖
	// 锁外的会话停止（最长 6s）与会话构造；r.mu 只护内存表快照，读面（Hosts/Sessions/
	// HostStates/Host）不再被刷新/删除/收工窗口整体阻塞。锁序：opMu → r.mu。
	opMu sync.Mutex
	// endpointCacheDir / out L3 注入（空 = 按 stateDir 推导）。
	endpointCacheDir string
	out              string
	// carried 装载时 id 非法条目的原样携带：不启动会话、不进寻址面（Hosts/
	// Sessions 均不含），但**落盘时随有效记录一并写回**——「条目保留」由
	// recordsLocked 兑现（改前装载日志声称保留、下次落盘却把它写掉）。
	// 用户可见滞留（日志指路手工清理）；「不丢数据」优先于「表自洁」——自洁正是
	// 被定为 bug 的行为。
	carried []HostRecord
}

// tableOptions 主机表构造项（Daemon.Options 的表投影）。
type tableOptions struct {
	strict bool
	logf   func(format string, args ...any)
	eventf func(format string, args ...any)
	events TableEvents
	// endpointCacheDir / out client 侧 L3 注入（Options.EndpointCacheDir/Out；
	// 空 = 按 stateDir 推导——现状缺省，role-management D3 拆分表 r1 高-2）。
	endpointCacheDir string
	out              string
	// hooks 每主机会话的 Demand/Diag 钩子装配缝（§6.1/§6.3：注入 hostsession
	// Options——桌面门与诊因发射的接线点；nil = 不接线）。
	hooks tableHooks
}

// tableHooks 每主机会话钩子装配缝的类型（tableOptions.hooks 的字段形态）。
type tableHooks func(rec HostRecord, e *hostEntry) (demand func() (bool, string), diag func(reason string))

// openTable 打开主机表（= 迁移前 OpenRegistry）：读 hosts.json（缺失 = 空表；
// 损坏 = 备份后空表 + 事件级告警，见 loadHosts）并按表逐后端拉会话（「重启按表
// 恢复」——会话与端点缓存/身份按既有目录布局复用）。
//
// 半途失败契约（r2 新-15 ②）：任何装载错误返回时表不挂载（Daemon 只在成功时
// 存指针）；已起会话全部 Stop、表回未 attach 态——装载段唯一硬错误源 = loadHosts
// （先于会话启动），防御性收尾对后续新增的失败点同样成立。
func openTable(stateDir string, opts tableOptions) (*hostTable, error) {
	r := &hostTable{
		stateDir:         stateDir,
		hosts:            make(map[[32]byte]*hostEntry),
		strict:           opts.strict,
		logf:             opts.logf,
		eventf:           opts.eventf,
		events:           opts.events,
		hooks:            opts.hooks,
		endpointCacheDir: opts.endpointCacheDir,
		out:              opts.out,
	}
	if r.logf == nil {
		r.logf = func(string, ...any) {}
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

// startEntryLocked 为一条记录构造条目并起会话（装载/新键入表两路；调用方持锁或
// 单线程装配期）。
func (r *hostTable) startEntryLocked(rec HostRecord) *hostEntry {
	e := newHostEntry(rec)
	r.startSessionLocked(e)
	return e
}

// newHostEntry 条目骨架：登记记录 + 需求合成状态（会话字段留空——起会话见
// startSessionLocked）。
func newHostEntry(rec HostRecord) *hostEntry {
	return &hostEntry{rec: rec, dm: &hostDemand{}}
}

// startSessionLocked 为条目构造并启动会话（exec-r1 中-1：**装回原条目 e**——刷新路径
// 与新键入表共用本段，hooks 绑 e、观测面/计数器读 e.dm，三面同一份状态，不再随刷新
// 裂成孤儿 dm；调用方持锁）。
func (r *hostTable) startSessionLocked(e *hostEntry) {
	rec := e.rec
	// L3 注入（D3 拆分表）：统一进程把端点缓存/会话日志落 <state>/cache/；
	// 空 = 现状按 stateDir 推导（identity 恒在 L2 stateDir——身份与 hosts 表是一对）。
	endpointCacheDir := r.endpointCacheDir
	if endpointCacheDir == "" {
		endpointCacheDir = filepath.Join(r.stateDir, "endpoints") // 现布局天然按 peerID 分文件
	}
	out := r.out
	if out == "" {
		out = filepath.Join(r.stateDir, "debug.log") // 追加写；分级/轮转沿出口口径
	}
	cfg := hostsession.Config{
		Token:            rec.Token,
		IdentityDir:      filepath.Join(r.stateDir, "identity"), // 复用 wtransport 机制
		EndpointCacheDir: endpointCacheDir,
		Out:              out,
	}
	var obs hostsession.Observer
	if r.events != nil {
		hostID := rec.ID
		ev := r.events
		obs = stateChangedFunc(func(s *hostsession.Session, from, to, reason string) {
			ev.HostStateChanged(hostID, from, to, reason)
		})
	}
	sopts := hostsession.Options{StrictIdentity: r.strict, Observer: obs}
	if r.hooks != nil {
		sopts.Demand, sopts.Diag = r.hooks(rec, e) // §6：桌面门 + 诊因发射接线（绑 e）
	}
	sess, err := newSession(cfg, sopts)
	if err != nil {
		// 构造期唯一错误源 = 日志文件打不开：条目仍入表（记录在案、状态面 failed），
		// 不因日志问题丢主机登记。
		r.logf("hosts: %s（%s）会话构造失败：%v", rec.ID, rec.Name, err)
		return
	}
	e.sess = sess // 先装回再 Start（低-1）：会话 goroutine 经 hooks 闭包读 e.sess 需要 happens-before
	sess.Start()
}

// Add 添加/刷新一台主机：同 token 重复添加 → ErrHostExists；同 peerID 新 token
// （后端重签发）→ 刷新记录。落盘 hosts.json（0600）。
//
// B5（host-cli 3b）：**先落盘再 Start/换会话**——新键 = 落盘成功才入表 + Start
// （落盘失败零副作用：内存未动、无会话已起）；同键刷新 = 先落盘新 token（内存
// 暂不动——失败即回滚，内存不留新 token、旧会话照跑）→ 停旧 → 起新、内存记录换
// 新值。一次落盘失败既不丢已登记主机也不留孤儿会话。
//
// FIX-07：变更经 opMu 串行化；**停旧会话（最长 6s）在 r.mu 外做**——读面不被阻塞。
func (r *hostTable) Add(name, token string) (HostRecord, error) {
	tok, err := proto.DecodeToken(token)
	if err != nil {
		return HostRecord{}, fmt.Errorf("%w：%v", ErrBadToken, err)
	}
	r.opMu.Lock()
	defer r.opMu.Unlock()

	r.mu.Lock()
	if e, ok := r.hosts[tok.PeerID]; ok {
		// 同后端重签发：同键刷新（「token 哈希」备选否决的理由）。
		if e.rec.Token == token {
			r.mu.Unlock()
			return HostRecord{}, ErrHostExists
		}
		newRec := e.rec
		newRec.Token = token
		if name != "" {
			newRec.Name = name
		}
		next := replaceRecord(r.recordsLocked(), newRec)
		if err := r.saveRecordsLocked(next); err != nil {
			r.mu.Unlock()
			return HostRecord{}, err // 内存保持旧 token、旧会话照跑（磁盘也未动）
		}
		old := e.sess
		recID, recName := e.rec.ID, e.rec.Name
		r.mu.Unlock()
		// 停旧会话。B7①（用户面）：Stop -1 = 拒绝该操作 + events.log 记行——此时
		// 磁盘或已含新 token、内存保持旧值，重试或重启按磁盘收敛（如实注记）。
		// 「拒绝」是名义拒绝：拒绝的是**更新内存**——Stop 已被调用过一次
		// （stopOnce 不可回退），旧会话对象虽仍在册但已进入收尾/垂死，该主机短暂
		// 离线属预期。
		if old != nil && stopFunc(old) < 0 {
			r.eventf("hosts: %s（%s）token 刷新被拒——会话停止超时（-1，垂死会话仍在收尾；重试或重启按磁盘收敛）", recID, recName)
			return HostRecord{}, errStopTimeout
		}
		r.mu.Lock()
		e.rec = newRec
		e.sess = nil            // 旧会话已停：先摘引用（新会话构造失败时条目呈「会话对象不在」而非挂尸体）
		r.startSessionLocked(e) // 新会话装回原条目：hooks/观测面/计数器同读 e.dm（中-1）
		rec := e.rec
		r.mu.Unlock()
		r.logf("hosts: %s（%s）token 已刷新（同后端重签发）", rec.ID, rec.Name)
		return rec, nil
	}
	rec := HostRecord{
		ID:      hex.EncodeToString(tok.PeerID[:]),
		Name:    name,
		Token:   token,
		AddedAt: time.Now(),
	}
	if err := r.saveRecordsLocked(append(r.recordsLocked(), rec)); err != nil {
		r.mu.Unlock()
		return HostRecord{}, err // 落盘失败零副作用：内存未动、无会话已起
	}
	r.hosts[tok.PeerID] = r.startEntryLocked(rec)
	r.mu.Unlock()
	r.logf("hosts: + %s（%s）", rec.ID, rec.Name)
	// 锁外 emit（B6：payload 锁内拷贝、锁外发；回调重入 Hosts()/Sessions() 不再自死锁）。
	if r.events != nil {
		r.events.HostAdded(rec.ID, rec.Name, rec.AddedAt.UnixMilli())
	}
	return rec, nil
}

// Remove 摘除一台主机（先落盘、停会话、删条目——B5 对称化：落盘失败 = 内存与会话
// 均未动）。停会话遇 -1 = B7① 用户面拒绝 + events.log 记行（磁盘或已不含该记录，
// 重试或重启按磁盘收敛）。
// FIX-07：停会话（最长 6s）在 r.mu 外做（opMu 保变更互斥）——读面不被停止窗阻塞。
func (r *hostTable) Remove(id [32]byte) error {
	r.opMu.Lock()
	defer r.opMu.Unlock()
	r.mu.Lock()
	e, ok := r.hosts[id]
	if !ok {
		r.mu.Unlock()
		return fmt.Errorf("%w：%s", ErrNoHost, hex.EncodeToString(id[:]))
	}
	if err := r.saveRecordsLocked(withoutRecord(r.recordsLocked(), e.rec.ID)); err != nil {
		r.mu.Unlock()
		return err // 内存未动、会话未动
	}
	sess, recID, recName := e.sess, e.rec.ID, e.rec.Name
	r.mu.Unlock()
	if sess != nil && stopFunc(sess) < 0 {
		// -1 时磁盘已无该条目、内存条目仍在——「拒绝」= 拒绝摘除内存；会话已进收尾、
		// 该主机短暂离线属预期，重试收敛。
		r.eventf("hosts: %s（%s）删除被拒——会话停止超时（-1，垂死会话仍在收尾；重试或重启按磁盘收敛）", recID, recName)
		return errStopTimeout
	}
	r.mu.Lock()
	delete(r.hosts, id)
	r.mu.Unlock()
	r.logf("hosts: - %s（%s）", recID, recName)
	if r.events != nil {
		r.events.HostRemoved(recID, "user")
	}
	return nil
}

// Hosts 表快照（登记记录；按 ID 排序稳定输出）。
func (r *hostTable) Hosts() []HostRecord {
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
// 会话快照，锁序路径②：表锁拷贝集合 → 各会话无锁快照 → 末读总线 seq）。
type SessionEntry struct {
	Rec  HostRecord
	Sess *hostsession.Session
}

// Sessions 拷贝全部 (登记, 会话) 对（状态面/流腿用；每记录自持语义不变）。
func (r *hostTable) Sessions() []SessionEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]SessionEntry, 0, len(r.hosts))
	for _, e := range r.hosts {
		out = append(out, SessionEntry{Rec: e.rec, Sess: e.sess})
	}
	return out
}

// Session 取一台主机的会话（流腿/状态面用；不在表 = nil）。
func (r *hostTable) Session(id [32]byte) *hostsession.Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.hosts[id]; ok {
		return e.sess
	}
	return nil
}

// Close 收工：停全部会话 + 逐台 session.removed 照发（r2 新-15 契约③——在途订阅
// 前端经事件面看到完整收工，不静默消失；reason=detach）。B7③（清理收工面）：
// Stop -1 记 events.log 后**继续**——垂死会话不绑架注册表收工与进程退出（尽力
// 语义）。FIX-07：先锁内摘表，再锁外逐台停（6s 级停止不占表锁）。
func (r *hostTable) Close() {
	r.opMu.Lock()
	defer r.opMu.Unlock()
	type stopItem struct {
		sess     *hostsession.Session
		id, name string
	}
	var stops []stopItem
	var gone []string
	r.mu.Lock()
	for id, e := range r.hosts {
		gone = append(gone, e.rec.ID)
		if e.sess != nil {
			stops = append(stops, stopItem{sess: e.sess, id: e.rec.ID, name: e.rec.Name})
		}
		delete(r.hosts, id)
	}
	r.mu.Unlock()
	for _, it := range stops {
		if stopFunc(it.sess) < 0 {
			r.eventf("hosts: %s（%s）收工停止超时（-1），继续收下一台", it.id, it.name)
		}
	}
	// 锁外 emit（B6 发射锁序同守）。
	if r.events != nil {
		for _, g := range gone {
			r.events.HostRemoved(g, "detach")
		}
	}
}

// demandBriefs demand 观测面快照（§6.2：daemon.status 的 demand 段数据源）。
func (r *hostTable) demandBriefs() []HostDemandBrief {
	r.mu.Lock()
	out := make([]HostDemandBrief, 0, len(r.hosts))
	type pair struct {
		id string
		dm *hostDemand
	}
	ps := make([]pair, 0, len(r.hosts))
	for _, e := range r.hosts {
		ps = append(ps, pair{id: e.rec.ID, dm: e.dm})
	}
	r.mu.Unlock()
	for _, p := range ps {
		if p.dm != nil {
			out = append(out, p.dm.brief(p.id))
		}
	}
	return out
}

// recordsLocked 当前表记录快照（调用方持锁）。**含 carried**：非法 id 条目随每次
// 落盘原样写回（「条目保留」由这里兑现——carried 与有效记录**同集落盘，相对
// 顺序不承诺**：有效记录在前但其间顺序不承诺（hosts 是 map，每次迭代序随机，
// 非 addedAt 时间线）、carried 原序恒在集尾；Hosts/Sessions 的寻址面仍不含
// carried，二者刻意不同源）。
func (r *hostTable) recordsLocked() []HostRecord {
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
// 不产生截断 JSON（此前裸 os.WriteFile 覆写 × 损坏即拒启 = 主机表不可恢复）。
func (r *hostTable) saveRecordsLocked(recs []HostRecord) error {
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

// hostsession.Observer 兼容断言（startEntryLocked 的注入形态）。
var _ hostsession.Observer = stateChangedFunc(nil)

// loadHosts 读主机表。缺失 = 空表；损坏 = 备份 `hosts.json.corrupt-<ts>` 后按空表
// 启动 + warnf 事件级告警（损坏即拒启会让 client 角色无限退避、daemon 永远
// not_ready，且无自愈路径——备份保住「不静默清空」的初衷（原件保留可人工修复，
// 修复后重启即恢复），空表启动保住 daemon 不被一份坏文件锁死）。备份本身失败
// （目录只读等）仍报错拒启：那时空表启动等于下一次落盘就把主机表真清空。
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

// ---------- Daemon 的表生命周期与操作面（D1；实现体自 daemon 侧迁入） ----------

// tableRef 取当前表指针（未 attach = nil；调用方随后在表自身锁内操作，与
// Attach/Detach 的指针换手无锁序纠缠）。
func (d *Daemon) tableRef() *hostTable {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.table
}

// Attach 挂载角色级主机表（读 stateDir/hosts.json、按表起会话——语义 = 迁移前
// OpenRegistry）。契约三句（r2 新-15）：① 二次 Attach 幂等——已 attach 时再调
// = 先收工当前表（等价 Detach，逐台 session.removed 照发）再按新 stateDir 重新
// 挂载，不报错、不留双表（supervisor 重建是常规来源）；② 半途失败收尾——装载
// 出错时已起的会话全部 Stop、表回未 attach 态再返回错误（不留半挂表，下一次
// Attach 从盘上状态重来）；③ Attach 装载完成后为每台主机补发 session.added
// （exec-r1 低-3，与 Detach 的逐台 session.removed 对称——control 与 client 角色
// 相互独立，client 角色重建时控制面连接不断，在途订阅者靠这批 added 恢复视图，
// 不静默空表）；stateDir 单一来源 = 只经本方法携带。低-2：attachMu 串行化
// Attach/Detach（并发 Attach 互相覆盖会留孤儿表）。
func (d *Daemon) Attach(stateDir string) error {
	d.attachMu.Lock()
	defer d.attachMu.Unlock()
	// 契约①：先收工当前表（等价 Detach——先摘指针再收工，窗口内 NotReady 与
	// Detach 同款；session.removed 照发；承载面随表同收）。
	d.mu.Lock()
	old := d.table
	oldCar := d.carriers
	d.table = nil
	d.carriers = nil
	d.mu.Unlock()
	if oldCar != nil {
		oldCar.Close() // 先收承载面再收表
	}
	if old != nil {
		old.Close()
	}
	tbl, err := openTable(stateDir, tableOptions{
		strict:           d.opts.StrictIdentity,
		logf:             d.opts.Logf,
		eventf:           d.opts.Eventf,
		events:           &busEvents{bus: d.bus}, // §3.2 事件源直发总线
		hooks:            d.sessionHooks,         // §6：桌面门 + 诊因发射接线（Demand/Diag → hostsession Options）
		endpointCacheDir: d.opts.EndpointCacheDir,
		out:              d.opts.Out,
	})
	if err != nil {
		// 契约②：表未挂载（d.table 保持 nil = 未 attach 态）。
		return err
	}
	// 承载面（3e §3.1）：与表同生命周期、stateDir 同源；拨号缝 = Host 面
	//（DialPort/Dial 家族，同记账同重建感知）。半途失败收尾 = 先关表再返回
	//（不留半挂面，下一次 Attach 从盘上状态重来）。
	car, err := openCarriers(stateDir, carrierDialOf(d), d.opts.Logf, d.opts.Eventf)
	if err != nil {
		tbl.Close()
		return err
	}
	// 成员谓词注入（FIX-05）：AddForward/SocksOn 的成员检查在 addMu 临界区内跑，
	// 与 RemoveHost 的级联互斥——防 host.remove × forward.add 并发造孤儿监听。
	car.hostExists = func(id [32]byte) bool { return d.Host(id) != nil }
	d.mu.Lock()
	d.table = tbl
	d.carriers = car
	d.mu.Unlock()
	// 契约③（added 方向）：装载完成的每台主机补发 session.added（锁外 emit；表已
	// 挂载 = 前端据 added 重取视图时 NotReady 已为假）。首次 Attach（空总线）天然
	// 无人在途，照发无害。
	ev := &busEvents{bus: d.bus}
	for _, rec := range tbl.Hosts() {
		ev.HostAdded(rec.ID, rec.Name, rec.AddedAt.UnixMilli())
	}
	return nil
}

// Detach 收工当前主机表（= 迁移前 Registry.Close + 契约③ 逐台 session.removed
// 照发——在途订阅前端可见收工；未 attach = 无操作）。低-2：与 Attach 同把
// attachMu 串行化。
func (d *Daemon) Detach() {
	d.attachMu.Lock()
	defer d.attachMu.Unlock()
	d.mu.Lock()
	tbl := d.table
	car := d.carriers
	d.table = nil
	d.carriers = nil
	d.mu.Unlock()
	if car != nil {
		car.Close() // 先收承载面（socks 显式关在世连接/speedtest 取消）再收表
	}
	if tbl != nil {
		tbl.Close()
	}
}

// NotReady 表未 attach（角色未跑/重建窗口——绑定层 not_ready 门委托它）。
func (d *Daemon) NotReady() bool { return d.tableRef() == nil }

// AddHost host.add 的进程内面（自 daemon 侧 controlBackend.AddHost 迁入）：
// decode（bad_token 前置——force 不绕过）→ 有界旁路探测（≤3.5s，纯旁路不碰表
// 任何会话状态；探测缝 = Options.Probe，daemon 装配透传 pkg/probe.Reach）→
// 入表。全不可达且未带 force → ErrHostUnreachable（不入表，不产生任何表副作
// 用）；force = 跳过探测直接入表（tier=skipped，端点未实测）。
func (d *Daemon) AddHost(ctx context.Context, name, token string, force bool) (HostAddResult, error) {
	tbl := d.tableRef()
	if tbl == nil {
		return HostAddResult{}, ErrNotReady
	}
	res := HostAddResult{}
	if force {
		res.Reach = &HostReach{Tier: ReachTierSkipped, Tested: []ReachTested{}}
	} else {
		rep, err := d.opts.Probe(ctx, token)
		if err != nil {
			return HostAddResult{}, ErrBadToken // decode 失败（bad_token 前置）
		}
		switch rep.Tier() {
		case probe.TierNone:
			return HostAddResult{}, ErrHostUnreachable
		case probe.TierDirect:
			res.Reach = &HostReach{Tier: ReachTierDirect, Tested: []ReachTested{}}
		case probe.TierRelay:
			res.Reach = &HostReach{Tier: ReachTierRelay, Tested: []ReachTested{}}
		}
		for _, t := range rep.Results {
			res.Reach.Tested = append(res.Reach.Tested, ReachTested{Ep: t.EP, Relay: t.Relay, RttMs: t.RTT.Milliseconds()})
		}
		if best := rep.Best(); best.EP != "" {
			res.Reach.BestEp = best.EP
			res.Reach.RttMs = best.RTT.Milliseconds()
		}
	}
	rec, err := tbl.Add(name, token)
	switch {
	case errors.Is(err, ErrHostExists):
		return HostAddResult{}, ErrHostExists
	case errors.Is(err, ErrBadToken):
		return HostAddResult{}, ErrBadToken
	case err != nil:
		return HostAddResult{}, err
	}
	res.ID = rec.ID
	res.Name = rec.Name
	res.AddedAt = rec.AddedAt.UnixMilli()
	return res, nil
}

// RemoveHost host.remove 的进程内面（id = peerID [32]byte）。删除成功后级联清理
// 承载面（3e §3.1：forward 规则 delete 语义不强关、socks off 语义显式关 + 记忆消失、
// speedtest cancel——D8 级联）。
func (d *Daemon) RemoveHost(id [32]byte) error {
	tbl := d.tableRef()
	if tbl == nil {
		return ErrNotReady
	}
	if err := tbl.Remove(id); err != nil {
		return err
	}
	if c := d.Carriers(); c != nil {
		c.RemoveHost(id)
	}
	return nil
}

// HostBriefs 主机登记面（host.list / snapshot.get 的静态部分；按 ID 排序）。
func (d *Daemon) HostBriefs() []HostBrief {
	tbl := d.tableRef()
	if tbl == nil {
		return nil
	}
	recs := tbl.Hosts()
	out := make([]HostBrief, 0, len(recs))
	for _, r := range recs {
		out = append(out, HostBrief{ID: r.ID, Name: r.Name, AddedAt: r.AddedAt.UnixMilli()})
	}
	return out
}

// HostStates 各主机动态面（state/reason/link/stats——锁序②：表锁内拷贝集合、
// 锁外逐会话无锁快照；seq 由绑定层在**最后**读总线补上）。
func (d *Daemon) HostStates() []HostState {
	tbl := d.tableRef()
	if tbl == nil {
		return nil
	}
	entries := tbl.Sessions() // 锁内拷贝、锁外快照
	out := make([]HostState, 0, len(entries))
	for _, e := range entries {
		out = append(out, hostStateOf(e.Rec, e.Sess))
	}
	return out
}

// Host 取一台主机的进程内面对象（不在表/未 attach = nil）。
func (d *Daemon) Host(id [32]byte) *Host {
	tbl := d.tableRef()
	if tbl == nil {
		return nil
	}
	tbl.mu.Lock()
	defer tbl.mu.Unlock()
	if e, ok := tbl.hosts[id]; ok {
		return &Host{rec: e.rec, sess: e.sess, dm: e.dm}
	}
	return nil
}
