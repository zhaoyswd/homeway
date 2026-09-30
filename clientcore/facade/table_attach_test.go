package facade

// table_attach_test.go — Daemon.Attach/Detach 契约三句用例（r2 新-15，任务 3.1
// 验证）+ §3.2 事件源直发总线用例（Add/Remove/state_changed 三 kind）。
// token 本地签发（同 table_test）；表操作经 Daemon 面与表直构两面各自覆盖。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/probe"
)

// newTestDaemon 测试进程级 Daemon（严格身份；日志可注入）。
func newTestDaemon(t *testing.T) *Daemon {
	t.Helper()
	d := New(Options{StrictIdentity: true})
	t.Cleanup(d.Close)
	return d
}

// attachTestHosts 向已 attach 的表直构加两台主机（绕过探测缝——登记面用例）。
func attachTestHosts(t *testing.T, d *Daemon, dir string, peers ...byte) {
	t.Helper()
	tbl := d.tableRef()
	if tbl == nil {
		t.Fatal("前置：表应已 attach")
	}
	for _, pb := range peers {
		tok, _ := testToken(t, pb, "127.0.0.1:40000")
		if _, err := tbl.Add(fmt.Sprintf("机%d", pb), tok); err != nil {
			t.Fatalf("加机 %d：%v", pb, err)
		}
	}
}

// TestAttachSecondAttachIdempotent 契约①：二次 Attach 幂等——等价 Detach+Attach
// （旧表收工、session.removed 照发、不留双表）。
func TestAttachSecondAttachIdempotent(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	d := newTestDaemon(t)

	if err := d.Attach(dirA); err != nil {
		t.Fatal(err)
	}
	attachTestHosts(t, d, dirA, 21)
	if got := len(d.HostBriefs()); got != 1 {
		t.Fatalf("前置：dirA 应 1 台，实得 %d", got)
	}

	// 二次 Attach（不同 stateDir）：不报错；旧表收工（session.removed 照发）、
	// 新表挂载、HostBriefs 反映新 stateDir、无双表残留。
	if err := d.Attach(dirB); err != nil {
		t.Fatalf("二次 Attach 应幂等成功：%v", err)
	}
	if d.NotReady() {
		t.Fatal("二次 Attach 后应已挂新表")
	}
	if got := d.HostBriefs(); len(got) != 0 {
		t.Fatalf("新表应空（dirB 无主机），实得 %d——双表残留", len(got))
	}
	// 回挂 dirA：盘上记录恢复（幂等语义 = 可反复重挂）。
	if err := d.Attach(dirA); err != nil {
		t.Fatal(err)
	}
	if got := len(d.HostBriefs()); got != 1 {
		t.Fatalf("回挂 dirA 应恢复 1 台（盘上持久化），实得 %d", got)
	}
}

// TestAttachHalfwayFailureRollsBack 契约②：装载半途失败——表回未 attach 态再
// 返回错误（不留半挂表；下一次 Attach 从盘上状态重来）。
func TestAttachHalfwayFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, hostsFileName), []byte("{坏表"), 0o600); err != nil {
		t.Fatal(err)
	}
	// 备份失败注入：目录转只读（loadHosts 的 Rename 落 EACCES → 拒启——「备份
	// 失败仍报错」的既有语义；这里恰驱动 Attach 半途失败路径）。
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	d := newTestDaemon(t)
	if err := d.Attach(dir); err == nil {
		t.Fatal("装载失败应返回错误")
	}
	if !d.NotReady() {
		t.Fatal("失败后表应回未 attach 态（NotReady）")
	}
	if got := d.HostBriefs(); got != nil {
		t.Fatalf("未 attach 态 HostBriefs 应 nil，实得 %d 条", len(got))
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// 修复（挪走坏表）后重挂成功——「下一次 Attach 从盘上状态重来」。
	if err := os.Remove(filepath.Join(dir, hostsFileName)); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := d.Attach(dir); err != nil {
		t.Fatalf("修复后重挂应成功：%v", err)
	}
	if d.NotReady() {
		t.Fatal("重挂后应就绪")
	}
}

// TestDetachEmitsSessionRemoved 契约③：Detach 收工逐台 session.removed 照发总线
// （reason=detach——在途订阅前端可见收工，不静默消失）。
func TestDetachEmitsSessionRemoved(t *testing.T) {
	dir := t.TempDir()
	d := newTestDaemon(t)
	if err := d.Attach(dir); err != nil {
		t.Fatal(err)
	}
	// 先订阅（nil 游标 = 纯在线），再入两台——added/removed 都走在线面。
	sub := d.Bus().NewSubscriber()
	if err := d.Bus().Subscribe(sub, []string{DomainSession}, nil, "", ""); err != nil {
		t.Fatal(err)
	}
	attachTestHosts(t, d, dir, 22, 23)
	for range 2 {
		waitEvent(t, sub, KindSessionAdded, func(json.RawMessage) {})
	}

	d.Detach()
	got := map[string]bool{}
	deadline := time.After(2 * time.Second)
	for len(got) < 2 {
		select {
		case ev := <-sub.Events():
			if ev.Kind != KindSessionRemoved {
				continue // 会话暖机期的 state_changed 属预期噪声，跳过
			}
			var p SessionRemovedPayload
			if err := json.Unmarshal(ev.Payload, &p); err != nil {
				t.Fatal(err)
			}
			if p.Reason != "detach" {
				t.Fatalf("Detach 的 removed reason 应 detach，实得 %q", p.Reason)
			}
			got[p.Host] = true
		case <-deadline:
			t.Fatalf("2 台主机应各收一条 session.removed（实得 %d：%v）", len(got), got)
		}
	}
	if !d.NotReady() {
		t.Fatal("Detach 后应未 attach")
	}
	// 幂等：未 attach 再 Detach = 无操作（不 panic、不再发 session.removed——
	// 暖机期的 state_changed 噪声不在此断言面）。
	d.Detach()
	deadline2 := time.After(200 * time.Millisecond)
	for {
		select {
		case ev := <-sub.Events():
			if ev.Kind == KindSessionRemoved {
				t.Fatalf("未 attach 的 Detach 不应再发 session.removed：%+v", ev)
			}
		case <-deadline2:
			return
		}
	}
}

// TestTableEventsPublishToBus §3.2 事件源直发：表事件（added/removed/
// state_changed 三 kind）经 Attach 的默认接线直发总线（session 域、载荷同源）。
func TestTableEventsPublishToBus(t *testing.T) {
	dir := t.TempDir()
	d := newTestDaemon(t)
	if err := d.Attach(dir); err != nil {
		t.Fatal(err)
	}
	sub := d.Bus().NewSubscriber()
	if err := d.Bus().Subscribe(sub, []string{DomainSession}, nil, "", ""); err != nil {
		t.Fatal(err)
	}

	// added：表直构 Add → session.added。
	tbl := d.tableRef()
	tok, peer := testToken(t, 24, "127.0.0.1:40000")
	if _, err := tbl.Add("甲", tok); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, sub, KindSessionAdded, func(p json.RawMessage) {
		var sp SessionAddedPayload
		if err := json.Unmarshal(p, &sp); err != nil {
			t.Fatal(err)
		}
		if sp.Name != "甲" {
			t.Fatalf("session.added 载荷：%+v", sp)
		}
	})

	// state_changed：Observer → TableEvents 接线经 busEvents 直发（确定性驱动
	// 接缝本体——会话面的状态机迁移由 hostsession 侧用例覆盖，发射链同一条）。
	(&busEvents{bus: d.Bus()}).HostStateChanged(mustPeerIDHex(peer), "starting", "ready", "")
	waitEvent(t, sub, KindSessionStateChanged, func(p json.RawMessage) {
		var sp SessionStateChangedPayload
		if err := json.Unmarshal(p, &sp); err != nil {
			t.Fatal(err)
		}
		if sp.State != "ready" {
			t.Fatalf("session.state_changed 载荷：%+v", sp)
		}
	})

	// removed：表 Remove → session.removed（reason=user）。
	if err := tbl.Remove(peer); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, sub, KindSessionRemoved, func(p json.RawMessage) {
		var sp SessionRemovedPayload
		if err := json.Unmarshal(p, &sp); err != nil {
			t.Fatal(err)
		}
		if sp.Reason != "user" {
			t.Fatalf("session.removed 载荷：%+v", sp)
		}
	})
}

// mustPeerIDHex peerID → hex（载荷里的 host 形态）。
func mustPeerIDHex(peer [32]byte) string {
	return fmt.Sprintf("%x", peer[:])
}

// waitEvent 等待一条指定 kind 的总线事件并校验载荷。
func waitEvent(t *testing.T, sub *Subscriber, kind string, check func(json.RawMessage)) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case ev := <-sub.Events():
			if ev.Kind != kind {
				continue
			}
			check(ev.Payload)
			return
		case <-deadline:
			t.Fatalf("等待事件 %s 超时", kind)
		}
	}
}

// TestDaemonAddHostProbeAndForce Daemon.AddHost 操作面（自 daemon 侧
// controlBackend.AddHost 迁入的回归锚点）：探测三档结论 + force 跳过 + 未 attach
// = ErrNotReady。探测经 Options.Probe 注入（r1 低-10——daemon 侧测试注入点随迁）。
func TestDaemonAddHostProbeAndForce(t *testing.T) {
	dir := t.TempDir()
	tokDirect, _ := testToken(t, 24, "127.0.0.1:40024")
	tokDead, _ := testToken(t, 25, "127.0.0.1:40025")
	d := New(Options{
		StrictIdentity: true,
		Probe: func(ctx context.Context, token string) (*probe.ReachReport, error) {
			if token == tokDead {
				return &probe.ReachReport{Peer: "25000000"}, nil // 全不可达（零结果）
			}
			return &probe.ReachReport{
				Peer:    "24000000",
				Results: []probe.ReachResult{{EP: "203.0.113.24:41641", RTT: 9 * time.Millisecond}},
			}, nil
		},
	})
	t.Cleanup(d.Close)

	// 未 attach：ErrNotReady。
	if _, err := d.AddHost(context.Background(), "甲", tokDirect, false); !errors.Is(err, ErrNotReady) {
		t.Fatalf("未 attach 应 ErrNotReady，实得 %v", err)
	}

	if err := d.Attach(dir); err != nil {
		t.Fatal(err)
	}
	// 探测 = direct（注入缝）。
	res, err := d.AddHost(context.Background(), "甲", tokDirect, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Reach == nil || res.Reach.Tier != ReachTierDirect || res.Reach.BestEp != "203.0.113.24:41641" {
		t.Fatalf("direct 结论：%+v", res.Reach)
	}
	if res.ID == "" || res.AddedAt == 0 {
		t.Fatalf("结果登记面：%+v", res)
	}
	// 全不可达（未带 force）：ErrHostUnreachable、不入表。
	if _, err := d.AddHost(context.Background(), "乙", tokDead, false); !errors.Is(err, ErrHostUnreachable) {
		t.Fatalf("全不可达应 ErrHostUnreachable，实得 %v", err)
	}
	if got := len(d.HostBriefs()); got != 1 {
		t.Fatalf("全不可达不得入表（表长 %d）", got)
	}
	// force 跳过探测：tier=skipped、tested 空。
	resF, err := d.AddHost(context.Background(), "乙", tokDead, true)
	if err != nil {
		t.Fatal(err)
	}
	if resF.Reach == nil || resF.Reach.Tier != ReachTierSkipped || len(resF.Reach.Tested) != 0 {
		t.Fatalf("force 结论：%+v", resF.Reach)
	}
	// 同 token 重复：ErrHostExists。
	if _, err := d.AddHost(context.Background(), "again", tokDirect, false); !errors.Is(err, ErrHostExists) {
		t.Fatalf("同 token 重复应 ErrHostExists，实得 %v", err)
	}
	// 坏 token：ErrBadToken（force 不绕过）。
	if _, err := d.AddHost(context.Background(), "", "hmw1-garbage", false); !errors.Is(err, ErrBadToken) {
		t.Fatalf("坏 token 应 ErrBadToken，实得 %v", err)
	}
	if _, err := d.AddHost(context.Background(), "", "hmw1-garbage", true); !errors.Is(err, ErrBadToken) {
		t.Fatalf("force 不得绕过 bad_token，实得 %v", err)
	}
}

// TestDaemonRemoveHostNotInTable RemoveHost 面哨兵：不在表 = ErrNoHost。
func TestDaemonRemoveHostNotInTable(t *testing.T) {
	dir := t.TempDir()
	d := newTestDaemon(t)
	if err := d.Attach(dir); err != nil {
		t.Fatal(err)
	}
	if err := d.RemoveHost([32]byte{99}); !errors.Is(err, ErrNoHost) {
		t.Fatalf("不在表应 ErrNoHost，实得 %v", err)
	}
}

// attachTestDaemonMu 并发面冒烟：Attach 与 HostBriefs/NotReady 并发无 data race
// （-race 门承载；轻量压窗）。
func TestAttachConcurrentReaders(t *testing.T) {
	dir := t.TempDir()
	d := newTestDaemon(t)
	if err := d.Attach(dir); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = d.NotReady()
					_ = d.HostBriefs()
					h := d.Host([32]byte{1})
					if h != nil {
						_ = h.Record()
					}
					time.Sleep(time.Millisecond)
				}
			}
		}()
	}
	attachTestHosts(t, d, dir, 26)
	time.Sleep(50 * time.Millisecond)
	d.Detach()
	if err := d.Attach(dir); err != nil {
		t.Fatal(err)
	}
	close(stop)
	wg.Wait()
}
