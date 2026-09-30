package daemon

// control.go — 控制面装配（§4 收拢后 = 纯绑定）：internal/control 服务器与
// facade.Daemon 的桥（Backend adapter）。语义全在 facade（AddHost 的 decode→
// 有界探测→入表、表生命周期 Attach/Detach、事件源直发总线）——本文件只做
// 「facade 结果/哨兵 ↔ wire 体/错误码」的映射与装配；依赖方向单向：daemon
// import control 与 facade（control 不 import daemon）。

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"

	"github.com/zhaoyswd/homeway/clientcore/facade"
	"github.com/zhaoyswd/homeway/internal/control"
)

// termServicePort term 服务端口 = 客户端会话的核内约定（spec「流式通道」：
// 端口 MUST NOT 出现在控制面词表；真源 = internal/server DefaultTermPort 7724，
// 此处独立常量避免把出口服务大包拉进 daemon 依赖面——一处定源：绑定点经
// Host.DialPort 携带，facade 不持有端口词表）。
const termServicePort = 7724

// controlBackend control.Backend 的 daemon 实现（纯绑定：逐方法委托 facade）。
type controlBackend struct {
	d       *facade.Daemon
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

// HostBriefs host.list / snapshot.get 的静态部分（登记面）。
func (b *controlBackend) HostBriefs() []control.HostBrief {
	briefs := b.d.HostBriefs()
	out := make([]control.HostBrief, 0, len(briefs))
	for _, r := range briefs {
		out = append(out, control.HostBrief{ID: r.ID, Name: r.Name, AddedAt: r.AddedAt})
	}
	return out
}

// AddHost host.add：委托 facade.Daemon.AddHost（decode → 有界探测〔Options.Probe
// 缝，装配期透传 pkg/probe.Reach〕→ 入表），哨兵翻译到 Backend 错误族。
// 探测不挂请求 ctx（既有口径：客户端先退时服务端继续探测并已入表）。
func (b *controlBackend) AddHost(name, token string, force bool) (control.HostAddResult, error) {
	res, err := b.d.AddHost(context.Background(), name, token, force)
	if err != nil {
		switch {
		case errors.Is(err, facade.ErrHostExists):
			return control.HostAddResult{}, control.ErrBackendHostExists
		case errors.Is(err, facade.ErrBadToken):
			return control.HostAddResult{}, control.ErrBackendBadToken
		case errors.Is(err, facade.ErrHostUnreachable):
			return control.HostAddResult{}, control.ErrBackendHostUnreachable
		default:
			return control.HostAddResult{}, err
		}
	}
	return control.HostAddResult{
		ID:      res.ID,
		Name:    res.Name,
		AddedAt: res.AddedAt,
		Reach:   mapReach(res.Reach),
	}, nil
}

// mapReach facade 结论 → wire 体。
func mapReach(r *facade.HostReach) *control.HostReach {
	if r == nil {
		return nil
	}
	out := &control.HostReach{Tier: r.Tier, BestEp: r.BestEp, RttMs: r.RttMs, Tested: []control.ReachTested{}}
	for _, t := range r.Tested {
		out.Tested = append(out.Tested, control.ReachTested{Ep: t.Ep, Relay: t.Relay, RttMs: t.RttMs})
	}
	return out
}

// RemoveHost host.remove：id hex 解码后委托 facade。
func (b *controlBackend) RemoveHost(id string) error {
	var pid [32]byte
	raw, err := hex.DecodeString(id)
	if err != nil || len(raw) != 32 {
		return control.ErrBackendNoHost // id 非法（值域外）按不存在处理
	}
	copy(pid[:], raw)
	if err := b.d.RemoveHost(pid); errors.Is(err, facade.ErrNoHost) {
		return control.ErrBackendNoHost
	} else if err != nil {
		return err
	}
	return nil
}

// HostStates 快照路径（锁序②在 facade：表锁内拷贝集合、锁外逐会话无锁快照）；
// seq 由控制面层在**最后**读总线补上（server.opSnapshotGet）。
func (b *controlBackend) HostStates() []control.HostState {
	states := b.d.HostStates()
	out := make([]control.HostState, 0, len(states))
	for _, hs := range states {
		out = append(out, control.HostState{
			ID:      hs.ID,
			Name:    hs.Name,
			State:   hs.State,
			Reason:  hs.Reason,
			AddedAt: hs.AddedAt,
			Link:    mapLink(hs.Link),
			Stats:   mapStats(hs.Stats),
		})
	}
	return out
}

func mapLink(l *facade.HostLink) *control.HostLink {
	if l == nil {
		return nil
	}
	return &control.HostLink{Via: l.Via, Ep: l.Ep, RttMs: l.RttMs, At: l.At}
}

func mapStats(s *facade.HostRxTx) *control.HostRxTx {
	if s == nil {
		return nil
	}
	return &control.HostRxTx{RxBytes: s.RxBytes, TxBytes: s.TxBytes}
}

// DialTerm 流腿：host hex → facade.Host.DialPort(termServicePort)（重建感知的
// 隧道端口拨号）。ErrSessionNotCurrent 映射在 facade 哨兵上（§3.3）；「登记在册
// 但会话对象不在」沿 no_host 族——保持既有 wire 行为。
func (b *controlBackend) DialTerm(ctx context.Context, host string) (net.Conn, error) {
	var pid [32]byte
	raw, err := hex.DecodeString(host)
	if err != nil || len(raw) != 32 {
		return nil, control.ErrBackendNoHost
	}
	copy(pid[:], raw)
	h := b.d.Host(pid)
	if h == nil {
		return nil, control.ErrBackendNoHost
	}
	conn, err := h.DialPort(ctx, termServicePort)
	if err != nil {
		switch {
		case errors.Is(err, facade.ErrNoHost):
			return nil, control.ErrBackendNoHost
		case errors.Is(err, facade.ErrSessionNotCurrent):
			return nil, control.ErrBackendNoSession
		default:
			return nil, err
		}
	}
	return conn, nil
}

// NotReady 表未 attach（角色未跑/重建窗口——facade 化的「holder 为 nil」判定）。
func (b *controlBackend) NotReady() bool { return b.d.NotReady() }

// DemandStatus daemon.status 的 demand 段（4a §6.2：各主机最近一拍需求判定——
// facade hostDemand 的 sticky 快照；表未 attach = nil）。
func (b *controlBackend) DemandStatus() []control.HostDemandBrief {
	briefs := b.d.DemandStatus()
	out := make([]control.HostDemandBrief, 0, len(briefs))
	for _, d := range briefs {
		out = append(out, control.HostDemandBrief{Host: d.Host, Active: d.Active, Reason: d.Reason, At: d.At})
	}
	return out
}

var _ control.Backend = (*controlBackend)(nil)

// controlRole control 角色（4a §5.2，D4/L3——r1 高-3）：控制面监听与 Serve 循环
// 的角色化。**首启 fail-fast（r3 低-3）**：装配期 Listen 在 startControlPlane
// 完成（监听失败 = 报错退出——控制面是 daemon 的用户面，静默缺失无从排查）、
// 装配期 listener/server 注入本角色；Run 内的 Listen 只服务**重建路径**。accept
// 瞬态错误由 control.Serve 内部有界退避重试（不重建、用户面不断）；永久错误
// （listener 失效类）→ 角色失败 → supervisor 既有退避重建 = 重新 Listen+Serve
// （无需新增外部重建 API）；重建窗口 = 控制面暂不可达（CLI 既有「守护进程未运行」
// 类可行动文案覆盖，恢复后自动续）。总线/代际进程级不受角色重建影响。
type controlRole struct {
	version  string
	stateDir string
	sup      *supervisor
	d        *facade.Daemon
	eventf   func(format string, args ...any)

	// 首启注入（一次性——Run 取走后置 nil；重建轮次走 Run 内重 Listen）。
	srv  *control.Server
	ln   net.Listener
	sock string
}

func (r *controlRole) Name() string { return "control" }

func (r *controlRole) Run(ctx context.Context) error {
	srv, ln, sock := r.srv, r.ln, r.sock
	r.srv, r.ln, r.sock = nil, nil, ""
	if ln == nil {
		// 重建路径：重新 Listen（上一轮 Run 已 defer srv.Close() 收工旧
		// Server/listener——否则重听被 ListenControl 的 connect 探测命中旧
		// socket、误判「已被另一活实例占用」，重建永远失败，r2 新-4）。
		var err error
		sock, ln, err = control.ListenControl(r.stateDir)
		if err != nil {
			return fmt.Errorf("控制面重听失败：%w", err)
		}
		r.eventf("control: 角色重建——控制面重听（sock=%s，0600）", sock)
	}
	if srv == nil {
		srv = control.NewServer(control.ServerConfig{
			ServerVersion: r.version,
			Bus:           r.d.Bus(),
			Backend:       &controlBackend{d: r.d, sup: r.sup, version: r.version},
		})
	}
	// r2 新-4：角色失败上抛前先收工旧 Server/listener（关 listener + 断在途
	// 连接）——重建收尾判据（新-4）：重听成功 = 旧 listener 已被这里收工。
	// listener 由角色显式再关一次（srv.Close 先于 Serve 接入的瞬收窗口拿不到
	// s.ln——双关幂等，net.Listener 第二次 Close 只回错误）。
	defer func() {
		_ = ln.Close()
		srv.Close()
	}()
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		srv.Close()
		<-serveErr
		return ctx.Err() // ctx 取消族 = 正常收工
	case err := <-serveErr:
		// Serve 只在永久错误/收工时返回（瞬态已在 Serve 内退避重试）。
		return err
	}
}

// startControlPlane 装配控制面（cli.go ⑤）：装配期 Listen（**首启 fail-fast**：
// 监听失败 = 报错退出——控制面是 daemon 的用户面，静默缺失会让 CLI 全部
// not_ready 且无从排查；本机 daemon 为 nohup 非托管形态，进程活着而无控制面比
// 退出更糟）→ server + listener 注入 control 角色交 supervisor 托管（角色化只改
// **运行中失败**的恢复路径：瞬态 accept 错误 Serve 内重试、永久错误退避重建 =
// 重新 Listen+Serve）。总线与代际随进程唯一不变（4.4 同判据）。
func startControlPlane(ctx context.Context, version string, stateDir string, sup *supervisor, d *facade.Daemon, eventf func(string, ...any)) error {
	srv := control.NewServer(control.ServerConfig{
		ServerVersion: version,
		Bus:           d.Bus(),
		Backend:       &controlBackend{d: d, sup: sup, version: version},
	})
	sock, ln, err := control.ListenControl(stateDir)
	if err != nil {
		return fmt.Errorf("控制面监听失败：%w", err)
	}
	first := &controlRole{version: version, stateDir: stateDir, sup: sup, d: d, eventf: eventf, srv: srv, ln: ln, sock: sock}
	sup.Start(ctx, func() Role {
		r := first
		if r != nil {
			first = nil // 首启注入只此一次；重建轮次走 Run 内重 Listen
			return r
		}
		return &controlRole{version: version, stateDir: stateDir, sup: sup, d: d, eventf: eventf}
	}, nil)
	eventf("control: 控制面就绪（sock=%s，0600）", sock)
	return nil
}
