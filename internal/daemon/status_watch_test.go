package daemon

// status_watch_test.go — §7.1 判据：--watch 对测试 daemon 端到端（快照 + 事件
// 驱动的增量渲染：session.added 入行、真实状态迁移随 state_changed 刷新、
// session.removed 出行、Ctrl-C 干净退出）+ 守护进程未运行/中途退出的可行动
// 错误 + usage/互斥。view 声明（启动时列表）与「断开后需求贡献消失」的语义
// 分解见 control/watch_view_test.go 与 facade 侧既有用例（TestDemand
// SynthesisThreeSources 的「退订后贡献消失」段）。

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/facade"
	"github.com/zhaoyswd/homeway/internal/control"
	"github.com/zhaoyswd/homeway/pkg/proto"
)

// syncBuf 并发安全的输出缓冲（watch goroutine 写、测试轮询读）。
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// watchUntil 轮询等渲染内容出现 substr（超时 fatal）。
func watchUntil(t *testing.T, out *syncBuf, substr string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if bytes.Contains([]byte(out.String()), []byte(substr)) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("watch 渲染未出现 %q（%v 内）：\n%s", substr, d, out.String())
}

// watchTestToken 本地签发 token（control_test 同法：peerID=9×32，不可达端点——
// 会话暖机 12s 软失败后 ready，状态迁移真实走 hostsession 状态机）。
func watchTestToken(t *testing.T) string {
	t.Helper()
	tok, err := proto.EncodeToken(proto.Token{
		PeerID:    [32]byte{9},
		Secret:    [32]byte{9, 9},
		Endpoints: []proto.Endpoint{{Addr: "203.0.113.99:41641"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestDaemonStatusWatchEndToEnd(t *testing.T) {
	st, sock := startDaemonForTest(t, fakeProbeDirect)

	wctx, wcancel := context.WithCancel(context.Background())
	out := &syncBuf{}
	done := make(chan error, 1)
	go func() {
		done <- statusWatch(wctx, sock, "cli-test", st.Dir, 5*time.Second, out)
	}()
	// 首帧：骨架 + 空表 + 观测副作用注记（usage 注记的渲染面锚点）。
	watchUntil(t, out, "homeway daemon watch", 5*time.Second)
	watchUntil(t, out, "主机： 无", 5*time.Second)
	watchUntil(t, out, "退出后贡献消失", 5*time.Second)

	// 事件驱动渲染：watch 启动后新增主机——行只能经 session.added 事件出现
	//（快照在空表时已取过，本段证明的是订阅续播而非重快照）。
	c := dialDaemon(t, sock)
	ctx := context.Background()
	raw, err := c.Request(ctx, facade.OpHostAdd, control.HostAddArgs{Name: "测试后端", Token: watchTestToken(t)})
	if err != nil {
		t.Fatal(err)
	}
	var added control.HostAddResult
	if err := json.Unmarshal(raw, &added); err != nil || added.ID == "" {
		t.Fatalf("host.add：%v（%s）", err, raw)
	}
	watchUntil(t, out, "09000000", 5*time.Second) // shortHostID（peerID {9,0,0,…} 的前 8 hex）
	watchUntil(t, out, "测试后端", 5*time.Second)

	// 真实状态迁移随 state_changed 刷新：暖机 12s 软失败 → ready（不可达端点的
	// hostsession 真状态机，非注入）。
	watchUntil(t, out, "state=ready", 20*time.Second)

	// 移除：session.removed → 行消失（再次事件驱动渲染）。
	if _, err := c.Request(ctx, facade.OpHostRemove, control.HostRemoveArgs{Host: added.ID}); err != nil {
		t.Fatal(err)
	}
	watchUntil(t, out, "主机： 无", 5*time.Second)

	// Ctrl-C（ctx 取消）= 正常退出（nil——退订由连接关闭承载）。
	wcancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Ctrl-C 退出应 nil，得：%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watch 未在取消后退出")
	}
}

func TestDaemonStatusWatchDaemonExit(t *testing.T) {
	// 手工装配（startWatchableDaemon，保留收工面供测试中途杀 daemon——
	// 控制面 goodbye(shutting_down) → watch 报可行动错误）。
	_, dir, stop := startWatchableDaemon(t)
	out := &syncBuf{}
	done := make(chan error, 1)
	wctx, wcancel := context.WithCancel(context.Background())
	defer wcancel()
	go func() {
		done <- statusWatch(wctx, filepath.Join(dir, control.ControlSockName), "cli-test", dir, 5*time.Second, out)
	}()
	watchUntil(t, out, "homeway daemon watch", 5*time.Second)

	stop() // 守护进程收工：控制面 goodbye(shutting_down) + 连接关闭
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("守护进程退出后 watch 应报错（非 nil）")
		}
		msg := err.Error()
		if !bytes.Contains([]byte(msg), []byte("断开")) || !bytes.Contains([]byte(msg), []byte("重新运行")) {
			t.Fatalf("错误应可行动（断开原因 + 重试指引）：%s", msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watch 未在守护进程退出后返回")
	}
}

func TestDaemonStatusWatchNotRunning(t *testing.T) {
	dir := shortTempDirDaemon(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := statusWatch(ctx, filepath.Join(dir, control.ControlSockName), "cli-test", dir, 2*time.Second, &bytes.Buffer{})
	if err == nil {
		t.Fatal("未运行时应报错")
	}
	msg := err.Error()
	for _, want := range []string{"homeway daemon 未在运行", "control.sock", "homeway daemon --state"} {
		if !bytes.Contains([]byte(msg), []byte(want)) {
			t.Fatalf("可行动错误缺 %q：%s", want, msg)
		}
	}
}

func TestDaemonStatusWatchUsageAndMutex(t *testing.T) {
	var buf bytes.Buffer
	if err := statusCLI([]string{"--help"}, "cli-test", &buf); err != nil {
		t.Fatalf("--help 不应报错：%v", err)
	}
	out := buf.String()
	for _, want := range []string{"-watch", "视为有需求", "退出后贡献消失"} {
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Fatalf("usage 缺 %q（观测副作用注记）：\n%s", want, out)
		}
	}
	if err := statusCLI([]string{"--watch", "--json"}, "cli-test", &buf); err == nil {
		t.Fatal("--watch 与 --json 应互斥报错")
	}
}

// startWatchableDaemon 手工装配（等价 startDaemonForTest，但把 facade.Daemon 与
// 收工面返回给测试——watch 的 view 语义用例需要进程级总线的导出面（Publish/
// CurrentSeq）作事件源与游标源）。
func startWatchableDaemon(t *testing.T) (*facade.Daemon, string, func()) {
	t.Helper()
	dir := shortTempDirDaemon(t)
	st, err := OpenDaemonState(dir)
	if err != nil {
		t.Fatal(err)
	}
	d := facade.New(facade.Options{StrictIdentity: true, Logf: st.Debugf, Eventf: st.Eventf, Probe: fakeProbeDirect})
	sup := newSupervisor(st.Eventf, st.Debugf)
	ctx, cancel := context.WithCancel(context.Background())
	role := newClientRole(dir, st, d)
	sup.Start(ctx, func() Role { return role }, nil)
	if err := startControlPlane(ctx, "test-daemon", dir, sup, d, st.Eventf); err != nil {
		cancel()
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !d.NotReady() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	stop := func() {
		cancel()
		sup.Close()
		st.Close()
		d.Close()
	}
	t.Cleanup(stop)
	return d, dir, stop
}

// TestDaemonStatusWatchViewOverWire view 声明的 wire 面证据（§7.1「退订后需求
// 贡献消失」用例的 wire 半边）：watch 形态的订阅（link+session 域 + view 多台
// 并列文法）经真实 wire 到总线——订阅确认回显 view（opSubscribe 解析并登记的
// wire 可见半边；总线侧 = server opSubscribe 直调 Bus.Subscribe(..., args.View)，
// 消费语义由 facade 侧 TestDemandSynthesisThreeSources〔含「退订后贡献消失」段〕/
// TestDemandViewAtomicReplace 承载）+ 订阅事件真实投递（渲染供给端）。
// 断开后贡献消失的机制行 = conn close → Bus.Unsubscribe(c.sub)（server.go close()
// 段）——订阅者出 b.subs 即不再被 viewDemand 聚合；本用例锁「断开后总线对新
// 前端照常」与游标续播的完整性。
func TestDaemonStatusWatchViewOverWire(t *testing.T) {
	d, dir, _ := startWatchableDaemon(t)
	sock := filepath.Join(dir, control.ControlSockName)
	c := dialDaemon(t, sock)
	ctx := context.Background()

	id := strings.Repeat("ab", 32)
	view := "host=" + id + ",host=" + strings.Repeat("cd", 32)
	r, err := c.Subscribe(ctx, []string{facade.DomainLink, facade.DomainSession}, nil, view, "")
	if err != nil {
		t.Fatal(err)
	}
	if r.View != view {
		t.Fatalf("view 应回显原声明（登记面），得 %q", r.View)
	}
	got := map[string]bool{}
	for _, dm := range r.Domains {
		got[dm] = true
	}
	if !got[facade.DomainLink] || !got[facade.DomainSession] || len(got) != 2 {
		t.Fatalf("生效域集合应 = {link, session}：%v", r.Domains)
	}

	// 订阅事件投递（渲染供给端）：进程级总线的导出发布面 → wire → 客户端。
	if _, err := d.Bus().Publish(facade.DomainLink, facade.KindLinkChanged, facade.LinkChangedPayload{
		Host: id, Via: "direct", Ep: "192.0.2.10:41641", RttMs: 12, At: 1,
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-c.Events():
		if ev.Kind != facade.KindLinkChanged || ev.Domain != facade.DomainLink {
			t.Fatalf("应为 link.changed：%+v", ev)
		}
		var p facade.LinkChangedPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatal(err)
		}
		if p.Host != id || p.Via != "direct" || p.RttMs != 12 {
			t.Fatalf("link.changed 载荷：%+v", p)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("订阅事件未投递（watch 渲染供给端断）")
	}

	// 断开 = 退订载体（conn close → Bus.Unsubscribe——view 贡献消失的机制行）；
	// 总线对后续发布与新前端照常（同一总线的需求聚合不再含已断开视图）。
	c.Close()
	if _, err := d.Bus().Publish(facade.DomainSession, facade.KindSessionDiag, facade.SessionDiagPayload{
		Host: id, Reason: facade.DiagGated,
	}); err != nil {
		t.Fatalf("断开后发布应照常：%v", err)
	}
	c2 := dialDaemon(t, sock)
	cur := d.Bus().CurrentSeq()
	if r2, err := c2.Subscribe(ctx, []string{facade.DomainSession}, &cur, "", ""); err != nil {
		t.Fatalf("新前端持游标订阅应照常：%v", err)
	} else if r2.Generation == "" {
		t.Fatal("订阅确认缺代际")
	}
}
