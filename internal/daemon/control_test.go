package daemon

// control_test.go — §3.6 装配级集成：真实 facade 主机表（角色子系统 Attach/
// Detach）+ 控制面全链（control.Client 完整握手/请求/订阅），事件接线
//（session.added/state_changed）与 not_ready 窗口（角色未跑）。token 本地签发
//（facade table_test 同法，不依赖真实后端；会话对不可达端点的暖机失败属异步
// 预期，不影响登记面断言）。§4 收拢后：装配经 facade.New（探测注入缝 =
// facade.Options.Probe——daemon 侧假探测注入点随迁，r1 低-10）。

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/facade"
	"github.com/zhaoyswd/homeway/internal/control"
	"github.com/zhaoyswd/homeway/pkg/probe"
	"github.com/zhaoyswd/homeway/pkg/proto"
)

// fakeProbeDirect 恒 direct 的假探测（会话面端到端用例保持「解析入表 + 事件
// 接线」断言面；真探测四路见 host_add_test.go）。
func fakeProbeDirect(ctx context.Context, token string) (*probe.ReachReport, error) {
	return &probe.ReachReport{
		Peer:    "090909090909",
		Results: []probe.ReachResult{{EP: "203.0.113.99:41641", RTT: 7 * time.Millisecond, Build: "fake"}},
	}, nil
}

// startDaemonForTest 最小 daemon 装配（无单实例锁——测试互不干扰；state 布局 +
// 进程级 facade.Daemon + supervisor + client 角色 + 控制面）。probe = nil 时用
// 生产探测核（host_add_test 的真探测四路）。
func startDaemonForTest(t *testing.T, probe func(ctx context.Context, token string) (*probe.ReachReport, error)) (*DaemonState, string) {
	t.Helper()
	dir := shortTempDirDaemon(t)
	st := OpenDaemonLogs(dir, dir) // 日志面（目录已存在即可；角色状态面的日志槽）
	t.Cleanup(st.Close)
	d := facade.New(facade.Options{
		StrictIdentity: true,
		Logf:           st.Debugf,
		Eventf:         st.Eventf,
		Probe:          probe,
	})
	t.Cleanup(d.Close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	sup := newSupervisor(ctx, st.Eventf, st.Debugf)
	role := newClientRole(dir, st, d)
	sup.Start("client", func() Role { return role }, nil)
	if err := startControlPlane(ctx, "test-daemon", dir, sup, d, nil, st.Eventf); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); sup.Close() }) // 控制面随角色收口（conn 收尾）后停角色
	// 等主机表挂上（角色 goroutine 异步 attach）。
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !d.NotReady() {
			return st, filepath.Join(dir, control.ControlSockName)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("主机表未在窗口内 attach")
	return nil, ""
}

func shortTempDirDaemon(t *testing.T) string {
	t.Helper()
	// control.sock 在 state 目录下：t.TempDir() 的 /var/folders 长路径会超
	// sockaddr_un 上限，用 /tmp 短路径。
	dir, err := os.MkdirTemp("/tmp", "dmn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func dialDaemon(t *testing.T, sock string) *control.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, w, err := control.Dial(ctx, sock, control.FrontendInfo{Kind: "cli", Name: "test", Version: "0"})
	if err != nil {
		t.Fatalf("控制面握手失败：%v", err)
	}
	if w.ServerVersion != "test-daemon" || w.Generation == "" {
		t.Fatalf("welcome 形状：%+v", w)
	}
	t.Cleanup(c.Close)
	return c
}

func TestControlPlaneAssemblyEndToEnd(t *testing.T) {
	_, sock := startDaemonForTest(t, fakeProbeDirect)
	c := dialDaemon(t, sock)
	ctx := context.Background()

	// daemon.status：角色面可见（client 角色由 supervisor 起来）。
	raw, err := c.Request(ctx, facade.OpDaemonStatus, nil)
	if err != nil {
		t.Fatal(err)
	}
	var st control.DaemonStatusResult
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	if st.ServerVersion != "test-daemon" || st.Generation == "" {
		t.Fatalf("daemon.status：%+v", st)
	}
	// 4a §5.2 起 roles 面 = client + control 两角色（map 序不稳定——按名查）。
	hasRole := func(name string) bool {
		for _, r := range st.Roles {
			if r.Name == name {
				return true
			}
		}
		return false
	}
	if !hasRole("client") || !hasRole("control") {
		t.Fatalf("角色面应含 client 与 control：%+v", st.Roles)
	}

	// 订阅 session 域 → host.add（本地签发 token）→ session.added 事件到达。
	if _, err := c.Subscribe(ctx, []string{facade.DomainSession}, nil, "", st.Generation); err != nil {
		t.Fatal(err)
	}
	tok := proto.Token{PeerID: [32]byte{9}, Secret: [32]byte{9, 9}, Endpoints: []proto.Endpoint{{Addr: "203.0.113.99:41641"}}}
	tokStr, err := proto.EncodeToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = c.Request(ctx, facade.OpHostAdd, control.HostAddArgs{Name: "测试后端", Token: tokStr})
	if err != nil {
		t.Fatal(err)
	}
	var added control.HostAddResult
	if err := json.Unmarshal(raw, &added); err != nil || added.ID == "" {
		t.Fatalf("host.add：%v（%s）", err, raw)
	}
	if added.Reach.Tier != facade.ReachTierDirect {
		t.Fatalf("host.add 结论载荷：%+v", added.Reach)
	}
	select {
	case ev := <-c.Events():
		if ev.Kind != facade.KindSessionAdded {
			t.Fatalf("首个事件应为 session.added：%+v", ev)
		}
		var p facade.SessionAddedPayload
		_ = json.Unmarshal(ev.Payload, &p)
		if p.Host != added.ID || p.Name != "测试后端" {
			t.Fatalf("session.added 载荷：%+v", p)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("session.added 事件未到达（事件接线断？）")
	}

	// 错误码映射（facade 哨兵路径）：重复添加 → host_exists；坏 token →
	// bad_token；不存在 → no_host。
	if _, err := c.Request(ctx, facade.OpHostAdd, control.HostAddArgs{Token: tokStr}); !errors.Is(err, control.CodeError(facade.CodeHostExists)) {
		t.Fatalf("同 token 重复应 host_exists：%v", err)
	}
	if _, err := c.Request(ctx, facade.OpHostAdd, control.HostAddArgs{Token: "hmw1garbage"}); !errors.Is(err, control.CodeError(facade.CodeBadToken)) {
		t.Fatalf("坏 token 应 bad_token：%v", err)
	}
	if _, err := c.Request(ctx, facade.OpHostRemove, control.HostRemoveArgs{Host: "ff"}); !errors.Is(err, control.CodeError(facade.CodeNoHost)) {
		t.Fatalf("不存在应 no_host：%v", err)
	}

	// snapshot.get：主机动态面（会话对不可达端点异步暖机失败属预期，状态面可见）。
	raw, err = c.Request(ctx, facade.OpSnapshotGet, nil)
	if err != nil {
		t.Fatal(err)
	}
	var snap control.SnapshotResult
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatal(err)
	}
	if snap.Generation != st.Generation || len(snap.Hosts) != 1 || snap.Hosts[0].ID != added.ID {
		t.Fatalf("snapshot.get：%+v", snap)
	}

	// 流腿寻址（真主机表）：不存在的主机 → no_host（term 拨号路径的入口校验）。
	if _, err := c.OpenStream(ctx, facade.StreamKindTerm, "0102"); !errors.Is(err, control.CodeError(facade.CodeNoHost)) {
		t.Fatalf("不存在主机流打开应 no_host：%v", err)
	}

	// host.remove → session.removed 事件。
	if _, err := c.Request(ctx, facade.OpHostRemove, control.HostRemoveArgs{Host: added.ID}); err != nil {
		t.Fatal(err)
	}
	found := false
	deadline := time.After(3 * time.Second)
	for !found {
		select {
		case ev := <-c.Events():
			if ev.Kind == facade.KindSessionRemoved {
				found = true
			}
		case <-deadline:
			t.Fatal("session.removed 事件未到达")
		}
	}
}

func TestControlPlaneNotReadyWhenRoleDisabled(t *testing.T) {
	// 角色未挂（模拟 client 角色禁用/重建窗口）：host 类操作 not_ready，控制面
	// 本身仍应答（骨架可用）。
	dir := shortTempDirDaemon(t)
	st := OpenDaemonLogs(dir, dir)
	t.Cleanup(st.Close)
	d := facade.New(facade.Options{StrictIdentity: true, Logf: st.Debugf, Eventf: st.Eventf})
	t.Cleanup(d.Close) // 不挂角色（表未 attach = NotReady）
	ctlCtx, ctlCancel := context.WithCancel(context.Background())
	sup := newSupervisor(ctlCtx, st.Eventf, st.Debugf)
	if err := startControlPlane(ctlCtx, "test-daemon", dir, sup, d, nil, st.Eventf); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ctlCancel(); sup.Close() })
	c := dialDaemon(t, filepath.Join(dir, control.ControlSockName))
	ctx := context.Background()
	if _, err := c.Request(ctx, facade.OpHostAdd, control.HostAddArgs{Token: "anything"}); !errors.Is(err, control.CodeError(facade.CodeNotReady)) {
		t.Fatalf("注册表未挂应 not_ready：%v", err)
	}
	if _, err := c.Request(ctx, facade.OpHostList, nil); !errors.Is(err, control.CodeError(facade.CodeNotReady)) {
		t.Fatalf("host.list 未挂应 not_ready：%v", err)
	}
	// 控制面骨架仍应答（daemon.status 不依赖注册表——Backend.NotReady 只挡
	// host/snapshot 面）。
	raw, err := c.Request(ctx, facade.OpDaemonStatus, nil)
	if err != nil {
		t.Fatalf("daemon.status 不应被 not_ready 挡：%v", err)
	}
	var stt control.DaemonStatusResult
	_ = json.Unmarshal(raw, &stt)
	if stt.Generation == "" {
		t.Fatal("daemon.status 骨架应答形状错")
	}
}
