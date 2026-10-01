package daemon

// control_role_test.go — 4a §5.2（L3 accept 错误不吞 = control 角色化）的用例四路
// + 首启 fail-fast：① Accept 永久错误 → 角色重建被触发 + sock 重听恢复（重建前
// 先收工旧 listener——r2 新-4 判据：重听成功本身即证明，否则 ListenControl 的
// connect 探测命中活旧 socket 报「另一活实例占用」、重建永远失败）；② 瞬态错误
// → 同 listener 退避重试、不重建、在途用户面不断；③ 正常 Close 路径零噪声；
// ④ 既有 v1 roles.json（仅 client）→ control 默认在位（r2 新-2）；⑤ 首启 Listen
// 失败保留 fail-fast（占用 sock → 报错退出）。

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/facade"
	"github.com/zhaoyswd/homeway/internal/control"
)

// discardLog 静默日志（本文件最小装配用）。
func discardLog(string, ...any) {}

// injectListener 包一层真 listener 的注入器：Accept 可注入错误序列；Close 委托
// 真关闭（重建收尾判据的载体——角色若不 Close 它，重听的 connect 探测会命中）。
type injectListener struct {
	net.Listener
	mu      sync.Mutex
	errs    []error // Accept 错误序列（耗尽后委托真 Accept）
	closed  bool
	accepts atomic.Int64
}

func (l *injectListener) Accept() (net.Conn, error) {
	l.accepts.Add(1)
	l.mu.Lock()
	var err error
	if len(l.errs) > 0 {
		err, l.errs = l.errs[0], l.errs[1:]
	}
	l.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return l.Listener.Accept()
}

func (l *injectListener) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}

func (l *injectListener) Close() error {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	return l.Listener.Close()
}

// startRoleDaemon 最小角色装配（供本文件用例）：进程级 facade + supervisor +
// 注入 listener 的 control 角色（不经 startControlPlane 的装配期 Listen——首启
// 注入形态直接构造 controlRole；stateDir 由调用方给定——重听落在同一 sock）。
func startRoleDaemon(t *testing.T, stateDir string, ln net.Listener, backoff []time.Duration) (*facade.Daemon, *supervisor) {
	t.Helper()
	d := facade.New(facade.Options{StrictIdentity: true, Logf: discardLog, Eventf: discardLog})
	t.Cleanup(d.Close)
	ctx, cancel := context.WithCancel(context.Background())
	sup := newSupervisor(ctx, discardLog, discardLog)
	t.Cleanup(func() {
		cancel()
		sup.Close()
	})
	first := &controlRole{version: "role-test", stateDir: stateDir, sup: sup, d: d, eventf: discardLog, ln: ln, sock: filepath.Join(stateDir, control.ControlSockName)}
	sup.Start("control", func() Role {
		r := first
		if r != nil {
			first = nil
			return r
		}
		return &controlRole{version: "role-test", stateDir: stateDir, sup: sup, d: d, eventf: discardLog}
	}, backoff)
	return d, sup
}

// roleStats 取某角色状态。
func roleStats(sup *supervisor, name string) (state string, restarts int) {
	for _, st := range sup.Statuses() {
		if st.Name == name {
			return st.State, st.Restarts
		}
	}
	return "", 0
}

// waitControlReadyDial 等 control.sock 可拨（重建/重听完成判据；与 spawn.go 的
// waitControlReady 同义但返回路径——测试本地薄壳）。
func waitControlReadyDial(t *testing.T, dir string) string {
	t.Helper()
	sock := filepath.Join(dir, control.ControlSockName)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("unix", sock); err == nil {
			_ = c.Close()
			return sock
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("control.sock 未在窗口内恢复可拨")
	return sock
}

// TestControlRolePermanentErrorRebuilds ①：Accept 永久错误 → 角色失败 → supervisor
// 退避重建 → Run 内重新 Listen 同一 sock 恢复服务。**重建前先收工旧 listener**
// （r2 新-4）：注入器包着真 listener——若角色失败上抛前没有 srv.Close()，重听的
// connect 探测会命中活的旧 socket 报「已被另一活实例占用」，重建永远失败、
// 用例在 waitControlReady 处红。
func TestControlRolePermanentErrorRebuilds(t *testing.T) {
	// 先用真 ListenControl 占位（角色首启注入的 listener 就用它——真实形态）。
	dir := shortTempDirDaemon(t)
	_, realLn, err := control.ListenControl(dir)
	if err != nil {
		t.Fatal(err)
	}
	ln := &injectListener{Listener: realLn, errs: []error{errors.New("注入：listener 永久失效")}}

	_, sup := startRoleDaemon(t, dir, ln, []time.Duration{50 * time.Millisecond})

	// 角色失败（永久错误上抛）→ 重建 → 重听（新-4：旧 listener 已被 defer srv.Close
	// 收工——isClosed 判据）→ sock 恢复服务。
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ln.isClosed() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ln.isClosed() {
		t.Fatal("角色失败上抛前应收工旧 listener（r2 新-4 判据）")
	}
	sock := waitControlReadyDial(t, dir)
	_, restarts := roleStats(sup, "control")
	if restarts < 1 {
		t.Fatalf("永久错误应触发角色重建（restarts=%d）", restarts)
	}
	// 重建后的控制面照常应答（wire 面）。
	cctx, ccancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer ccancel()
	c, _, err := control.Dial(cctx, sock, control.FrontendInfo{Kind: "cli", Name: "rebuild", Version: "0"})
	if err != nil {
		t.Fatalf("重建后控制面应可拨：%v", err)
	}
	defer c.Close()
	if _, err := c.Request(cctx, facade.OpDaemonStatus, nil); err != nil {
		t.Fatalf("重建后 daemon.status 应应答：%v", err)
	}
}

// TestControlRoleTransientErrorRetries ②：瞬态 accept 错误（ECONNABORTED 两次）
// → 同 listener 退避重试（不重建），随后用户连接照常服务。
func TestControlRoleTransientErrorRetries(t *testing.T) {
	dir := shortTempDirDaemon(t)
	_, realLn, err := control.ListenControl(dir)
	if err != nil {
		t.Fatal(err)
	}
	ln := &injectListener{Listener: realLn, errs: []error{
		os.NewSyscallError("accept", syscall.ECONNABORTED),
		os.NewSyscallError("accept", syscall.EMFILE),
	}}
	_, sup := startRoleDaemon(t, dir, ln, []time.Duration{50 * time.Millisecond})

	sock := waitControlReadyDial(t, dir)
	cctx, ccancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer ccancel()
	c, _, err := control.Dial(cctx, sock, control.FrontendInfo{Kind: "cli", Name: "tr", Version: "0"})
	if err != nil {
		t.Fatalf("瞬态错误后控制面应可拨（重试不重建）：%v", err)
	}
	defer c.Close()
	if _, err := c.Request(cctx, facade.OpDaemonStatus, nil); err != nil {
		t.Fatalf("瞬态重试后请求应照常应答：%v", err)
	}
	// 不重建：control 角色 restarts == 0（瞬态在 Serve 内消化）。
	_, restarts := roleStats(sup, "control")
	if restarts != 0 {
		t.Fatalf("瞬态错误不应触发角色重建（restarts=%d）", restarts)
	}
	if ln.accepts.Load() < 3 {
		t.Fatalf("瞬态错误应被重试（accept 次数 %d < 3）", ln.accepts.Load())
	}
}

// TestControlRoleNormalCloseZeroNoise ③：正常 Close 路径零噪声——Serve 在 Close
// 后返回 nil，不打「瞬态」日志（clos 先行检查）。
func TestControlRoleNormalCloseZeroNoise(t *testing.T) {
	bus := facade.NewBus(facade.NewGeneration(), facade.BusConfig{})
	backend := &noopBackend{}
	var logs atomic.Int64
	srv := control.NewServer(control.ServerConfig{
		ServerVersion: "t", Bus: bus, Backend: backend,
		Logf: func(format string, args ...any) { logs.Add(1) },
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() }) // 慢起窗口兜底（Serve 未接入时 Close 拿不到它）
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	time.Sleep(50 * time.Millisecond)
	srv.Close()
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("正常 Close 应返回 nil（零噪声），得到 %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close 后 Serve 未返回")
	}
	if n := logs.Load(); n != 0 {
		t.Fatalf("正常 Close 路径不应有日志噪声（%d 条）", n)
	}
}

// noopBackend control.RoleBrief 空宿主（本文件最小装配用）。
type noopBackend struct{}

func (b *noopBackend) ServerVersion() string            { return "t" }
func (b *noopBackend) RolesStatus() []control.RoleBrief { return nil }
func (b *noopBackend) HostBriefs() []control.HostBrief  { return nil }
func (b *noopBackend) AddHost(name, token string, force bool) (control.HostAddResult, error) {
	return control.HostAddResult{}, control.ErrBackendBadToken
}
func (b *noopBackend) RemoveHost(id string) error      { return control.ErrBackendNoHost }
func (b *noopBackend) HostStates() []control.HostState { return nil }
func (b *noopBackend) DialStream(ctx context.Context, kind, host string) (net.Conn, error) {
	return nil, control.ErrBackendNoSession
}
func (b *noopBackend) NotReady() bool { return true }

func (b *noopBackend) DemandStatus() []control.HostDemandBrief { return nil }

// 承载面 9 op（3e）：noop 空 impl（本文件只考 control 角色，不走承载面路径）。
func (b *noopBackend) ForwardAdd(a control.ForwardAddArgs) (control.ForwardAddResult, error) {
	return control.ForwardAddResult{}, control.ErrBackendNoHost
}
func (b *noopBackend) ForwardRemove(a control.ForwardRemoveArgs) error {
	return control.ErrBackendNoHost
}
func (b *noopBackend) ForwardList(host string) control.ForwardListResult {
	return control.ForwardListResult{Forwards: []control.ForwardRuleBrief{}}
}
func (b *noopBackend) SocksOn(host string, listen uint16) (control.SocksOnResult, error) {
	return control.SocksOnResult{}, control.ErrBackendNoHost
}
func (b *noopBackend) SocksOff(host string) (control.SocksOffResult, error) {
	return control.SocksOffResult{}, control.ErrBackendNoHost
}
func (b *noopBackend) SocksStatus() control.SocksStatusResult {
	return control.SocksStatusResult{Socks: []control.SocksBrief{}}
}
func (b *noopBackend) SpeedtestStart(a control.SpeedtestStartArgs) (control.SpeedtestStartAck, error) {
	return control.SpeedtestStartAck{}, control.ErrBackendNoHost
}
func (b *noopBackend) SpeedtestStatus(host string) (control.SpeedtestStatusResult, error) {
	return control.SpeedtestStatusResult{}, control.ErrBackendNoHost
}
func (b *noopBackend) SpeedtestCancel(host string) error { return control.ErrBackendNoHost }

// serve/relay 角色管理十方法桩（role-management 3f；真实绑定 = roleOps）。
func (b *noopBackend) ServeStart() (control.RoleActionResult, error) {
	return control.RoleActionResult{Action: "started"}, nil
}
func (b *noopBackend) ServeStop() (control.RoleActionResult, error) {
	return control.RoleActionResult{Action: "stopped"}, nil
}
func (b *noopBackend) ServeRestart() (control.RoleActionResult, error) {
	return control.RoleActionResult{}, control.ErrBackendRoleStopped
}
func (b *noopBackend) ServeStatus() control.ServeStatusResult {
	return control.ServeStatusResult{Peers: []control.ServePeerBrief{}}
}
func (b *noopBackend) ServeToken() (control.ServeTokenResult, error) {
	return control.ServeTokenResult{}, nil
}
func (b *noopBackend) RelayStart() (control.RoleActionResult, error) {
	return control.RoleActionResult{Action: "started"}, nil
}
func (b *noopBackend) RelayStop() (control.RoleActionResult, error) {
	return control.RoleActionResult{Action: "stopped"}, nil
}
func (b *noopBackend) RelayRestart() (control.RoleActionResult, error) {
	return control.RoleActionResult{}, control.ErrBackendRoleStopped
}
func (b *noopBackend) RelayStatus() control.RelayStatusResult {
	return control.RelayStatusResult{Backends: []control.RelayBackendBrief{}}
}
func (b *noopBackend) RelayToken() (control.RelayTokenResult, error) {
	return control.RelayTokenResult{}, nil
}

// TestControlRoleAlwaysOnAssembled（role-management 2.3）：roles.json 退役后
// client/control **恒开**（期望态并入 config，无开关）——roles 面可见二者、
// control=running、控制面可拨（v1 roles.json「未登记默认 on」用例的观测面平移）。
func TestControlRoleAlwaysOnAssembled(t *testing.T) {
	dir := shortTempDirDaemon(t)
	st := OpenDaemonLogs(dir, dir)
	t.Cleanup(st.Close)
	d := facade.New(facade.Options{StrictIdentity: true, Logf: st.Debugf, Eventf: st.Eventf})
	t.Cleanup(d.Close)
	ctx, cancel := context.WithCancel(context.Background())
	sup := newSupervisor(ctx, st.Eventf, st.Debugf)
	t.Cleanup(func() {
		cancel()
		sup.Close()
	})
	// unified.go 同款装配：client/control 恒开（roles = 最小 roleOps——本用例不触
	// serve/relay 面）。
	sup.Start("client", func() Role { return newClientRole(dir, st, d) }, nil)
	ro := &roleOps{stateDir: dir, cacheDir: filepath.Join(dir, "cache"), version: "always-on-test", sup: sup}
	if err := startControlPlane(ctx, "always-on-test", dir, sup, d, ro, st.Eventf); err != nil {
		t.Fatal(err)
	}
	sock := waitControlReadyDial(t, dir)
	cctx, ccancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer ccancel()
	c, _, err := control.Dial(cctx, sock, control.FrontendInfo{Kind: "cli", Name: "always-on", Version: "0"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	raw, err := c.Request(cctx, facade.OpDaemonStatus, nil)
	if err != nil {
		t.Fatal(err)
	}
	sawControl, sawClient := false, false
	for _, r := range parseRolesBrief(t, raw) {
		if r.Name == "control" {
			sawControl = true
			if r.State != "running" {
				t.Fatalf("control 角色应 running：%+v", r)
			}
		}
		if r.Name == "client" {
			sawClient = true
		}
	}
	if !sawControl || !sawClient {
		t.Fatalf("client/control 恒开：roles 面应同时可见二者（control=%v client=%v）", sawControl, sawClient)
	}
}

func parseRolesBrief(t *testing.T, raw []byte) []control.RoleBrief {
	t.Helper()
	var st struct {
		Roles []control.RoleBrief `json:"roles"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	return st.Roles
}

func TestControlPlaneFirstListenFailFast(t *testing.T) {
	dir := shortTempDirDaemon(t)
	// 占用 sock：起一个活监听（connect 探测命中）。
	_, holdLn, err := control.ListenControl(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = holdLn.Close() })
	st := OpenDaemonLogs(dir, dir)
	t.Cleanup(st.Close)
	d := facade.New(facade.Options{StrictIdentity: true, Logf: discardLog, Eventf: discardLog})
	t.Cleanup(d.Close)
	ctx, cancel := context.WithCancel(context.Background())
	sup := newSupervisor(ctx, discardLog, discardLog)
	t.Cleanup(func() {
		cancel()
		sup.Close()
	})
	err = startControlPlane(ctx, "failfast-test", dir, sup, d, nil, discardLog)
	if err == nil {
		t.Fatal("sock 被占用时 startControlPlane 应报错（首启 fail-fast）")
	}
	if !errors.Is(err, err) || err.Error() == "" {
		t.Fatalf("错误应可读：%v", err)
	}
}
