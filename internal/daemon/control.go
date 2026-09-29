package daemon

// control.go — 控制面装配（§3.6 收口）：internal/control 服务器与 Registry/
// supervisor 的桥（Backend adapter）+ 事件接线（Registry 事件 → 控制面总线的
// session 域）。依赖方向单向：daemon import control（control 不 import daemon）。

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/zhaoyswd/homeway/clientcore/hostsession"
	"github.com/zhaoyswd/homeway/internal/control"
	"github.com/zhaoyswd/homeway/pkg/probe"
)

// termServicePort term 服务端口 = 客户端会话的核内约定（spec「流式通道」：
// 端口 MUST NOT 出现在控制面词表；真源 = internal/server DefaultTermPort 7724，
// 此处独立常量避免把出口服务大包拉进 daemon 依赖面）。
const termServicePort = 7724

// reachProbe 探测核注入缝（host-cli 3b，design D3：生产 = 共享核 pkg/probe.Reach
// ——与手机 App 同一份实现；同包测试注入假探测走 1.2 四路单测，不动 Backend 契约）。
var reachProbe = func(ctx context.Context, token string) (*probe.ReachReport, error) {
	return probe.Reach(ctx, token)
}

// registryHolder Registry 的共享槽 + 控制面总线（client 角色持有 Registry、角色
// 重建时换实例——总线与代际随进程唯一不变；控制面 Backend 经它读，角色未跑/
// 重建窗口 = not_ready；clientRole 经 bus() 把 Registry 事件接进总线）。
type registryHolder struct {
	mu     sync.Mutex
	cur    *Registry
	busRef *control.Bus
}

func newRegistryHolder(bus *control.Bus) *registryHolder {
	return &registryHolder{busRef: bus}
}

func (h *registryHolder) set(r *Registry) {
	h.mu.Lock()
	h.cur = r
	h.mu.Unlock()
}

func (h *registryHolder) get() *Registry {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cur
}

func (h *registryHolder) bus() *control.Bus { return h.busRef }

// controlBackend control.Backend 的 daemon 实现。
type controlBackend struct {
	holder  *registryHolder
	sup     *supervisor
	version string
}

func (b *controlBackend) ServerVersion() string { return b.version }

func (b *controlBackend) RolesStatus() []control.RoleBrief {
	stats := b.sup.Statuses()
	out := make([]control.RoleBrief, 0, len(stats))
	for _, st := range stats {
		out = append(out, control.RoleBrief{Name: st.Name, State: st.State, Restarts: st.Restarts, Reason: st.LastError})
	}
	return out
}

func (b *controlBackend) HostBriefs() []control.HostBrief {
	reg := b.holder.get()
	if reg == nil {
		return nil
	}
	recs := reg.Hosts()
	out := make([]control.HostBrief, 0, len(recs))
	for _, r := range recs {
		out = append(out, control.HostBrief{ID: r.ID, Name: r.Name, AddedAt: r.AddedAt.UnixMilli()})
	}
	return out
}

// AddHost host.add 服务端验证路径（host-cli 3b，design D1/D3）：decode（bad_token
// 前置——force 不绕过）→ 有界旁路探测（≤3.5s，纯旁路不碰注册表任何会话状态）→
// 入表。全不可达且未带 force → ErrBackendHostUnreachable（不入表，不产生任何
// 注册表副作用）；force = 跳过探测直接入表（tier=skipped，端点未实测）。
func (b *controlBackend) AddHost(name, token string, force bool) (control.HostAddResult, error) {
	reg := b.holder.get()
	if reg == nil {
		return control.HostAddResult{}, errors.New("注册表未就绪")
	}
	res := control.HostAddResult{}
	if force {
		res.Reach = &control.HostReach{Tier: control.ReachTierSkipped, Tested: []control.ReachTested{}}
	} else {
		rep, err := reachProbe(context.Background(), token)
		if err != nil {
			return control.HostAddResult{}, control.ErrBackendBadToken // decode 失败（bad_token 前置）
		}
		switch rep.Tier() {
		case probe.TierNone:
			return control.HostAddResult{}, control.ErrBackendHostUnreachable
		case probe.TierDirect:
			res.Reach = &control.HostReach{Tier: control.ReachTierDirect, Tested: []control.ReachTested{}}
		case probe.TierRelay:
			res.Reach = &control.HostReach{Tier: control.ReachTierRelay, Tested: []control.ReachTested{}}
		}
		for _, t := range rep.Results {
			res.Reach.Tested = append(res.Reach.Tested, control.ReachTested{Ep: t.EP, Relay: t.Relay, RttMs: t.RTT.Milliseconds()})
		}
		if best := rep.Best(); best.EP != "" {
			res.Reach.BestEp = best.EP
			res.Reach.RttMs = best.RTT.Milliseconds()
		}
	}
	rec, err := reg.Add(name, token)
	switch {
	case errors.Is(err, errHostExists):
		return control.HostAddResult{}, control.ErrBackendHostExists
	case errors.Is(err, ErrBadToken):
		return control.HostAddResult{}, control.ErrBackendBadToken
	case err != nil:
		return control.HostAddResult{}, err
	}
	res.ID = rec.ID
	res.Name = rec.Name
	res.AddedAt = rec.AddedAt.UnixMilli()
	return res, nil
}

func (b *controlBackend) RemoveHost(id string) error {
	reg := b.holder.get()
	if reg == nil {
		return errors.New("注册表未就绪")
	}
	var pid [32]byte
	raw, err := hex.DecodeString(id)
	if err != nil || len(raw) != 32 {
		return control.ErrBackendNoHost // id 非法（值域外）按不存在处理
	}
	copy(pid[:], raw)
	if err := reg.Remove(pid); errors.Is(err, errNoHost) {
		return control.ErrBackendNoHost
	} else if err != nil {
		return err
	}
	return nil
}

// HostStates 快照路径（锁序②）：先拷贝 (登记, 会话) 对集合（Registry.mu 锁内
// 拷贝、锁外快照——各会话 StatusSnapshot 自持锁仅本会话），seq 由控制面层在
// **最后**读总线补上（server.opSnapshotGet）。
func (b *controlBackend) HostStates() []control.HostState {
	reg := b.holder.get()
	if reg == nil {
		return nil
	}
	entries := reg.Sessions() // 锁内拷贝、锁外快照
	out := make([]control.HostState, 0, len(entries))
	for _, e := range entries {
		hs := control.HostState{ID: e.Rec.ID, Name: e.Rec.Name, AddedAt: e.Rec.AddedAt.UnixMilli()}
		if e.Sess == nil {
			hs.State = "failed"
			hs.Reason = "session_not_built" // 构造期失败（如日志文件打不开）的登记面可见性
			out = append(out, hs)
			continue
		}
		snap := e.Sess.StatusSnapshot()
		hs.State = snap.State
		hs.Reason = snap.Reason
		if snap.Link != nil {
			hs.Link = &control.HostLink{Via: snap.Link.Via, Ep: snap.Link.Ep, RttMs: snap.Link.RttMs, At: snap.Link.At}
		}
		if snap.Stats != nil {
			hs.Stats = &control.HostRxTx{RxBytes: snap.Stats.RxBytes, TxBytes: snap.Stats.TxBytes}
		}
		out = append(out, hs)
	}
	return out
}

// DialTerm 流腿：host hex → 会话 → DialPort(termServicePort)（重建感知的隧道
// 端口拨号，hostsession D1 导出面）。
func (b *controlBackend) DialTerm(ctx context.Context, host string) (net.Conn, error) {
	reg := b.holder.get()
	if reg == nil {
		return nil, errors.New("注册表未就绪")
	}
	var pid [32]byte
	raw, err := hex.DecodeString(host)
	if err != nil || len(raw) != 32 {
		return nil, control.ErrBackendNoHost
	}
	copy(pid[:], raw)
	sess := reg.Session(pid)
	if sess == nil {
		return nil, control.ErrBackendNoHost
	}
	conn, err := sess.DialPort(ctx, termServicePort)
	if err != nil {
		if errors.Is(err, hostsession.ErrSessionNotCurrent) {
			return nil, control.ErrBackendNoSession
		}
		return nil, err
	}
	return conn, nil
}

func (b *controlBackend) NotReady() bool { return b.holder.get() == nil }

// registryEventsAdaptor RegistryEvents → 控制面总线（session 域）。
type registryEventsAdaptor struct {
	bus *control.Bus
}

func (a *registryEventsAdaptor) HostAdded(id, name string, addedAt int64) {
	_, _ = a.bus.Publish(control.DomainSession, control.KindSessionAdded,
		control.SessionAddedPayload{Host: id, Name: name, AddedAt: addedAt})
}

func (a *registryEventsAdaptor) HostRemoved(id, reason string) {
	_, _ = a.bus.Publish(control.DomainSession, control.KindSessionRemoved,
		control.SessionRemovedPayload{Host: id, Reason: reason})
}

func (a *registryEventsAdaptor) HostStateChanged(id, from, to, reason string) {
	_, _ = a.bus.Publish(control.DomainSession, control.KindSessionStateChanged,
		control.SessionStateChangedPayload{Host: id, State: to, Reason: reason})
}

// hostsession.Observer 兼容断言（startEntryLocked 的注入形态）。
var _ hostsession.Observer = stateChangedFunc(nil)
var _ control.Backend = (*controlBackend)(nil)

// startControlPlane 装配控制面（cli.go ⑤）：listen → server → accept 循环。
// 监听失败（活实例占用/state 异常）= 报错退出——控制面是 daemon 的用户面，
// 静默缺失会让 CLI 全部 not_ready 且无从排查。
func startControlPlane(version string, stateDir string, sup *supervisor, holder *registryHolder, bus *control.Bus, eventf func(string, ...any)) (*control.Server, func(), error) {
	srv := control.NewServer(control.ServerConfig{
		ServerVersion: version,
		Bus:           bus,
		Backend:       &controlBackend{holder: holder, sup: sup, version: version},
	})
	sock, ln, err := control.ListenControl(stateDir)
	if err != nil {
		return nil, nil, fmt.Errorf("控制面监听失败：%w", err)
	}
	go func() { _ = srv.Serve(ln) }()
	stop := func() { srv.Close() }
	eventf("control: 控制面就绪（sock=%s，0600）", sock)
	return srv, stop, nil
}
