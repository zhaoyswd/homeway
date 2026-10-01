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
	"time"

	"github.com/zhaoyswd/homeway/clientcore/facade"
	"github.com/zhaoyswd/homeway/internal/control"
	"github.com/zhaoyswd/homeway/pkg/speedtest"
)

// 流腿的服务端口 = 客户端会话的核内约定（spec「流式通道」：端口 MUST NOT 出现在
// 控制面词表；真源 = internal/server 的 DefaultTermPort 7724 / DefaultFilesPort
// 7802，此处独立常量避免把出口服务大包拉进 daemon 依赖面——一处定源：绑定点经
// Host.DialPort 携带，facade 不持有端口词表）。files-cli 2.1 起 kind→端口映射
// 收拢在本文件（DialStream 唯一路径：kind → 端口 → facade.Host.DialPort）。
const (
	termServicePort  = 7724
	filesServicePort = 7802
)

// streamServicePort kind → 核内约定端口（files-cli 2.1：DialStream 的唯一映射处；
// 值域外 = 值域闸前移的可判定错误——控制面层同值回 bad_request）。
func streamServicePort(kind string) (uint16, error) {
	switch kind {
	case facade.StreamKindTerm:
		return termServicePort, nil
	case facade.StreamKindFiles:
		return filesServicePort, nil
	}
	return 0, fmt.Errorf("未知流 kind %q", kind)
}

// controlBackend control.Backend 的 daemon 实现（纯绑定：逐方法委托 facade；
// serve/relay 角色管理十方法委托 roleOps——语义在角色接口与 nodeconfig）。
type controlBackend struct {
	d       *facade.Daemon
	sup     *supervisor
	roles   *roleOps
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

// mapReach facade 结论 → wire 体（值类型；facade 侧恒非 nil——三档赋值路径见 table.go）。
func mapReach(r *facade.HostReach) control.HostReach {
	out := control.HostReach{Tested: []control.ReachTested{}}
	if r == nil {
		return out
	}
	out.Tier, out.BestEp, out.RttMs = r.Tier, r.BestEp, r.RttMs
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

// DialStream 流腿（files-cli 2.1 起 DialTerm 泛化）：kind → 核内约定端口 →
// host hex → facade.Host.DialPort（重建感知的隧道端口拨号——**唯一路径**，无旁路
// 直拨；term/files 同缝同映射处）。ErrSessionNotCurrent 映射在 facade 哨兵上
// （§3.3）；「登记在册但会话对象不在」沿 no_host 族——保持既有 wire 行为。
func (b *controlBackend) DialStream(ctx context.Context, kind, host string) (net.Conn, error) {
	port, err := streamServicePort(kind)
	if err != nil {
		return nil, err // 控制面值域闸前置，理论不可达；防御同款
	}
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
	conn, err := h.DialPort(ctx, port)
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

// ---------- 承载面绑定（3e §3.1）：op ↔ facade.Carriers 的字段映射（纯绑定） ----------
//
// 语义全在 facade（规则校验/监听生命周期/runner 状态机）；本层只做 host hex 存在性
// 闸（no_host 族）与结果字段映射。错误透传给 control dispatch 统一落 bad_request。

// hostInTable host 载荷存在性闸：非法 hex 或不在表 = ErrBackendNoHost（no_host）。
func (b *controlBackend) hostInTable(host string) error {
	var pid [32]byte
	raw, err := hex.DecodeString(host)
	if err != nil || len(raw) != 32 {
		return control.ErrBackendNoHost
	}
	copy(pid[:], raw)
	if b.d.Host(pid) == nil {
		return control.ErrBackendNoHost
	}
	return nil
}

// carriers 承载面束（表已 attach 才非 nil；dispatch 层 NotReady 门在前，此处防御）。
func (b *controlBackend) carriers() (*facade.Carriers, error) {
	c := b.d.Carriers()
	if c == nil {
		return nil, control.ErrBackendNoHost
	}
	return c, nil
}

func (b *controlBackend) ForwardAdd(a control.ForwardAddArgs) (control.ForwardAddResult, error) {
	if err := b.hostInTable(a.Host); err != nil {
		return control.ForwardAddResult{}, err
	}
	c, err := b.carriers()
	if err != nil {
		return control.ForwardAddResult{}, err
	}
	rule := facade.ForwardRule{Host: a.Host, Listen: a.Listen, TargetIP: a.TargetIP, TargetPort: a.TargetPort}
	if err := c.AddForward(rule); err != nil {
		return control.ForwardAddResult{}, err
	}
	return control.ForwardAddResult{Rule: forwardBriefOf(facade.ForwardState{Rule: rule, State: "listening"})}, nil
}

func (b *controlBackend) ForwardRemove(a control.ForwardRemoveArgs) error {
	if err := b.hostInTable(a.Host); err != nil {
		return err
	}
	c, err := b.carriers()
	if err != nil {
		return err
	}
	return c.RemoveForward(a.Host, a.Listen)
}

func (b *controlBackend) ForwardList(host string) control.ForwardListResult {
	c, err := b.carriers()
	if err != nil || (host != "" && b.hostInTable(host) != nil) {
		return control.ForwardListResult{Forwards: []control.ForwardRuleBrief{}}
	}
	states := c.ForwardStates(host)
	out := make([]control.ForwardRuleBrief, 0, len(states))
	for _, st := range states {
		out = append(out, forwardBriefOf(st))
	}
	return control.ForwardListResult{Forwards: out}
}

func forwardBriefOf(st facade.ForwardState) control.ForwardRuleBrief {
	return control.ForwardRuleBrief{
		Host: st.Rule.Host, Listen: st.Rule.Listen,
		TargetIP: st.Rule.TargetIP, TargetPort: st.Rule.TargetPort,
		State: st.State, Err: st.Err, Conns: st.Conns, Rejected: st.Rejected,
	}
}

func (b *controlBackend) SocksOn(host string, listen uint16) (control.SocksOnResult, error) {
	if err := b.hostInTable(host); err != nil {
		return control.SocksOnResult{}, err
	}
	c, err := b.carriers()
	if err != nil {
		return control.SocksOnResult{}, err
	}
	port, err := c.SocksOn(host, listen)
	if err != nil {
		return control.SocksOnResult{}, err
	}
	return control.SocksOnResult{Listen: port}, nil
}

func (b *controlBackend) SocksOff(host string) (control.SocksOffResult, error) {
	if err := b.hostInTable(host); err != nil {
		return control.SocksOffResult{}, err
	}
	c, err := b.carriers()
	if err != nil {
		return control.SocksOffResult{}, err
	}
	if err := c.SocksOff(host); err != nil {
		return control.SocksOffResult{}, err
	}
	// 记忆端口回显（off 不抹记忆——CLI 文案「下次 on 沿用」的数据源）。
	for _, st := range c.SocksStates() {
		if st.Host == host {
			return control.SocksOffResult{Listen: st.Listen}, nil
		}
	}
	return control.SocksOffResult{}, nil
}

func (b *controlBackend) SocksStatus() control.SocksStatusResult {
	c, err := b.carriers()
	if err != nil {
		return control.SocksStatusResult{Socks: []control.SocksBrief{}}
	}
	states := c.SocksStates()
	out := make([]control.SocksBrief, 0, len(states))
	for _, st := range states {
		out = append(out, control.SocksBrief{Host: st.Host, On: st.On, Listen: st.Listen, Conns: st.Conns, Err: st.Err})
	}
	return control.SocksStatusResult{Socks: out}
}

func (b *controlBackend) SpeedtestStart(a control.SpeedtestStartArgs) (control.SpeedtestStartAck, error) {
	if err := b.hostInTable(a.Host); err != nil {
		return control.SpeedtestStartAck{}, err
	}
	c, err := b.carriers()
	if err != nil {
		return control.SpeedtestStartAck{}, err
	}
	ack := c.SpeedtestStart(a.Host, facade.SpeedtestStart{
		Down:    time.Duration(a.DownMs) * time.Millisecond,
		Up:      time.Duration(a.UpMs) * time.Millisecond,
		Warmup:  time.Duration(a.WarmupMs) * time.Millisecond,
		Streams: a.Streams,
		WaitMs:  a.WaitMs,
	})
	return control.SpeedtestStartAck{Phase: ack.Phase, Reason: ack.Reason}, nil
}

func (b *controlBackend) SpeedtestStatus(host string) (control.SpeedtestStatusResult, error) {
	if err := b.hostInTable(host); err != nil {
		return control.SpeedtestStatusResult{}, err
	}
	res := control.SpeedtestStatusResult{Host: host, Phase: string(speedtest.PhaseIdle)}
	c, err := b.carriers()
	if err != nil {
		return res, nil
	}
	st := c.SpeedtestStatus(host)
	if st == nil {
		return res, nil // 无运行面（从未 start / 守护进程重启后）——idle 形态
	}
	res.Waiting = st.Waiting
	res.WaitRemainMs = st.WaitRemainMs
	res.Phase = st.Snap.Phase
	res.Reason = st.Snap.Reason
	if st.Snap.Usage != nil {
		res.UsageDown, res.UsageUp = st.Snap.Usage.Down, st.Snap.Usage.Up
	}
	if st.Snap.Live != nil {
		res.Dir, res.Bytes, res.InstBps = st.Snap.Live.Dir, st.Snap.Live.Bytes, st.Snap.Live.InstBps
	}
	res.ElapsedMs = st.Snap.ElapsedMs
	if st.Result != nil {
		res.Result = &control.SpeedtestResultBrief{
			OK: st.Result.OK, Reason: st.Result.Reason, Msg: st.Result.Msg,
			DownBps: st.Result.DownBps, UpBps: st.Result.UpBps,
			UsageDown: st.Result.UsageDown, UsageUp: st.Result.UsageUp, WallMs: st.Result.WallMs,
		}
	}
	return res, nil
}

func (b *controlBackend) SpeedtestCancel(host string) error {
	if err := b.hostInTable(host); err != nil {
		return err
	}
	c, err := b.carriers()
	if err != nil {
		return err
	}
	c.SpeedtestCancel(host)
	return nil
}

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

// ---------- serve/relay 角色管理绑定（role-management 4.2：逐方法委托 roleOps） ----------

// roles == nil = 未装配 roleOps 的测试形态（startControlPlane 传 nil 的既有用例）——
// 状态面给空形状、启停/token 走 ErrBackendRoleStopped 的可判定错误（不 panic）。
func (b *controlBackend) ServeStart() (control.RoleActionResult, error) {
	if b.roles == nil {
		return control.RoleActionResult{}, control.ErrBackendRoleStopped
	}
	return b.roles.ServeStart()
}

func (b *controlBackend) ServeStop() (control.RoleActionResult, error) {
	if b.roles == nil {
		return control.RoleActionResult{}, control.ErrBackendRoleStopped
	}
	return b.roles.ServeStop()
}

func (b *controlBackend) ServeRestart() (control.RoleActionResult, error) {
	if b.roles == nil {
		return control.RoleActionResult{}, control.ErrBackendRoleStopped
	}
	return b.roles.ServeRestart()
}

func (b *controlBackend) ServeStatus() control.ServeStatusResult {
	if b.roles == nil {
		return control.ServeStatusResult{State: "absent", Peers: []control.ServePeerBrief{}}
	}
	return b.roles.ServeStatus()
}

func (b *controlBackend) ServeToken() (control.ServeTokenResult, error) {
	if b.roles == nil {
		return control.ServeTokenResult{}, control.ErrBackendRoleStopped
	}
	return b.roles.ServeToken()
}

func (b *controlBackend) RelayStart() (control.RoleActionResult, error) {
	if b.roles == nil {
		return control.RoleActionResult{}, control.ErrBackendRoleStopped
	}
	return b.roles.RelayStart()
}

func (b *controlBackend) RelayStop() (control.RoleActionResult, error) {
	if b.roles == nil {
		return control.RoleActionResult{}, control.ErrBackendRoleStopped
	}
	return b.roles.RelayStop()
}

func (b *controlBackend) RelayRestart() (control.RoleActionResult, error) {
	if b.roles == nil {
		return control.RoleActionResult{}, control.ErrBackendRoleStopped
	}
	return b.roles.RelayRestart()
}

func (b *controlBackend) RelayStatus() control.RelayStatusResult {
	if b.roles == nil {
		return control.RelayStatusResult{State: "absent", Backends: []control.RelayBackendBrief{}}
	}
	return b.roles.RelayStatus()
}

func (b *controlBackend) RelayToken() (control.RelayTokenResult, error) {
	if b.roles == nil {
		return control.RelayTokenResult{}, control.ErrBackendRoleStopped
	}
	return b.roles.RelayToken()
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
	roles    *roleOps
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
			Backend:       &controlBackend{d: r.d, sup: r.sup, roles: r.roles, version: r.version},
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
func startControlPlane(ctx context.Context, version string, stateDir string, sup *supervisor, d *facade.Daemon, roles *roleOps, eventf func(string, ...any)) error {
	srv := control.NewServer(control.ServerConfig{
		ServerVersion: version,
		Bus:           d.Bus(),
		Backend:       &controlBackend{d: d, sup: sup, roles: roles, version: version},
	})
	sock, ln, err := control.ListenControl(stateDir)
	if err != nil {
		return fmt.Errorf("控制面监听失败：%w", err)
	}
	first := &controlRole{version: version, stateDir: stateDir, sup: sup, d: d, roles: roles, eventf: eventf, srv: srv, ln: ln, sock: sock}
	sup.Start("control", func() Role {
		r := first
		if r != nil {
			first = nil // 首启注入只此一次；重建轮次走 Run 内重 Listen
			return r
		}
		return &controlRole{version: version, stateDir: stateDir, sup: sup, d: d, roles: roles, eventf: eventf}
	}, nil)
	eventf("control: 控制面就绪（sock=%s，0600）", sock)
	return nil
}
