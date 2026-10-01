package daemon

// reattach_test.go — 角色重挂语义用例（任务 4.4，r1 高-2 拍板的机器证据——
// 「收拢不换语义」）：注入 client 角色失败 → supervisor 退避重建（重新 Attach）→
// 断言重建前后 Daemon 代际不变、控制面前端持游标重连 resubscribe 不触发
// cursor_stale（总线与代际随进程唯一不变——注释锚点，评审对账）；重建窗口内
// host.add/remove/list、snapshot.get、stream.open 按 not_ready 应答（沿用现口径
// ——这些 op 走 NotReady 门），daemon.status 刻意豁免照答骨架（roles 面可见
// failed/重建、hosts 面为空——r2 新-5，不改 wire 行为）；Detach 的逐台
// session.removed 经 wire 照发（r2 新-15 契约③的端到端面）。

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/facade"
	"github.com/zhaoyswd/homeway/internal/control"
	"github.com/zhaoyswd/homeway/pkg/probe"
	"github.com/zhaoyswd/homeway/pkg/proto"
)

// reattachRole client 角色的门控变体：第一次 Run = attach → 持住（等测试放行）→
// Detach + 返回错误（注入失败 → supervisor 退避重建）；第二次 Run 起 = attach 前
// 先持住（重建窗口确定化）→ 正常服役。总线与代际随进程唯一不变（注释锚点）。
type reattachRole struct {
	stateDir string
	st       *DaemonState
	d        *facade.Daemon
	calls    atomic.Int32

	attached1  chan struct{} // 第 1 次 attach 完成（closed 一次）
	release1   chan struct{} // 放行第 1 次收工（Detach + 失败）
	aboutToAtt chan struct{} // 第 2 次 attach 即将发生（窗口开启）
	release2   chan struct{} // 放行第 2 次 attach
}

func (r *reattachRole) Name() string { return "client" }

func (r *reattachRole) Run(ctx context.Context) error {
	switch r.calls.Add(1) {
	case 1:
		if err := r.d.Attach(r.stateDir); err != nil {
			return err
		}
		close(r.attached1)
		<-r.release1
		r.d.Detach() // 逐台 session.removed 照发（契约③）
		return errors.New("注入失败：角色重挂演练")
	case 2:
		close(r.aboutToAtt)
		<-r.release2
		if err := r.d.Attach(r.stateDir); err != nil {
			return err
		}
		r.st.Eventf("client: 注册表就绪（重挂，主机 %d 台）", len(r.d.HostBriefs()))
		<-ctx.Done()
		return ctx.Err()
	default:
		<-ctx.Done()
		return ctx.Err()
	}
}

// TestReattachKeepsGenerationAndCursor 角色重挂全链（控制面 wire 面）。
func TestReattachKeepsGenerationAndCursor(t *testing.T) {
	dir := shortTempDirDaemon(t)
	st := OpenDaemonLogs(dir, dir)
	t.Cleanup(st.Close)
	d := facade.New(facade.Options{
		StrictIdentity: true,
		Logf:           st.Debugf,
		Eventf:         st.Eventf,
		Probe: func(ctx context.Context, token string) (*probe.ReachReport, error) {
			return &probe.ReachReport{
				Peer:    "27000000",
				Results: []probe.ReachResult{{EP: "203.0.113.27:41641", RTT: 4 * time.Millisecond}},
			}, nil
		},
	})
	t.Cleanup(d.Close)
	role := &reattachRole{
		stateDir:   dir,
		st:         st,
		d:          d,
		attached1:  make(chan struct{}),
		release1:   make(chan struct{}),
		aboutToAtt: make(chan struct{}),
		release2:   make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	sup := newSupervisor(ctx, st.Eventf, st.Debugf)
	sup.Start("client", func() Role { return role }, []time.Duration{50 * time.Millisecond})

	if err := startControlPlane(ctx, "reattach-test", dir, sup, d, nil, st.Eventf); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); sup.Close() })
	sock := dir + "/" + control.ControlSockName

	// ① 首轮 attach 完成 → 前端接入 + 订阅 + 加一台主机（持 seq 游标）。
	select {
	case <-role.attached1:
	case <-time.After(3 * time.Second):
		t.Fatal("首轮 attach 未完成")
	}
	cctx, ccancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer ccancel()
	c, w, err := control.Dial(cctx, sock, control.FrontendInfo{Kind: "cli", Name: "reattach", Version: "0"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	genBefore := w.Generation
	rctx := context.Background()
	if _, err := c.Subscribe(rctx, []string{facade.DomainSession}, nil, "", ""); err != nil {
		t.Fatal(err)
	}
	tokStr, err := proto.EncodeToken(proto.Token{PeerID: [32]byte{27}, Secret: [32]byte{27, 1}, Endpoints: []proto.Endpoint{{Addr: "203.0.113.27:41641"}}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := c.Request(rctx, facade.OpHostAdd, control.HostAddArgs{Name: "重挂机", Token: tokStr})
	if err != nil {
		t.Fatal(err)
	}
	var added control.HostAddResult
	if err := json.Unmarshal(raw, &added); err != nil {
		t.Fatal(err)
	}
	var heldSeq uint64
	sawAdded := false
	deadline := time.After(3 * time.Second)
	for !sawAdded {
		select {
		case ev := <-c.Events():
			if ev.Kind == facade.KindSessionAdded {
				var p facade.SessionAddedPayload
				_ = json.Unmarshal(ev.Payload, &p)
				if p.Host == added.ID {
					heldSeq, sawAdded = ev.Seq, true
				}
			}
		case <-deadline:
			t.Fatal("session.added 未到达")
		}
	}

	// ② 放行收工：Detach（session.removed 照发）→ 角色失败 → 退避重建。
	close(role.release1)
	sawRemoved := false
	deadline = time.After(3 * time.Second)
	for !sawRemoved {
		select {
		case ev := <-c.Events():
			if ev.Kind == facade.KindSessionRemoved {
				var p facade.SessionRemovedPayload
				_ = json.Unmarshal(ev.Payload, &p)
				if p.Host == added.ID {
					if p.Reason != "detach" {
						t.Fatalf("Detach 的 removed reason 应 detach，实得 %q", p.Reason)
					}
					sawRemoved = true
				}
			}
		case <-deadline:
			t.Fatal("Detach 的 session.removed 未照发（契约③断）")
		}
	}

	// ③ 重建窗口（第二次 attach 被门控持住）：host 类 op 按 not_ready；
	// daemon.status 刻意豁免——骨架照答、代际不变、hosts 面空。
	select {
	case <-role.aboutToAtt:
	case <-time.After(3 * time.Second):
		t.Fatal("退避重建未发生（角色失败后应按表重建）")
	}
	if _, err := c.Request(rctx, facade.OpHostList, nil); !errors.Is(err, control.CodeError(facade.CodeNotReady)) {
		t.Fatalf("重建窗口 host.list 应 not_ready：%v", err)
	}
	if _, err := c.Request(rctx, facade.OpHostAdd, control.HostAddArgs{Token: tokStr}); !errors.Is(err, control.CodeError(facade.CodeNotReady)) {
		t.Fatalf("重建窗口 host.add 应 not_ready：%v", err)
	}
	if _, err := c.Request(rctx, facade.OpSnapshotGet, nil); !errors.Is(err, control.CodeError(facade.CodeNotReady)) {
		t.Fatalf("重建窗口 snapshot.get 应 not_ready：%v", err)
	}
	if _, err := c.OpenStream(rctx, facade.StreamKindTerm, added.ID); !errors.Is(err, control.CodeError(facade.CodeNotReady)) {
		t.Fatalf("重建窗口 stream.open 应 not_ready：%v", err)
	}
	raw, err = c.Request(rctx, facade.OpDaemonStatus, nil)
	if err != nil {
		t.Fatalf("daemon.status 刻意豁免（骨架信息，r2 新-5）不应被 not_ready 挡：%v", err)
	}
	var ds control.DaemonStatusResult
	if err := json.Unmarshal(raw, &ds); err != nil {
		t.Fatal(err)
	}
	if ds.Generation != genBefore {
		t.Fatalf("重建窗口代际应变（%q → %q）——总线与代际随进程唯一不变", genBefore, ds.Generation)
	}
	if len(ds.Hosts) != 0 {
		t.Fatalf("重建窗口 hosts 面应为空（表已 detach）：%d 台", len(ds.Hosts))
	}
	sawClientRole := false
	for _, r := range ds.Roles {
		if r.Name == "client" {
			sawClientRole = true
		}
	}
	if !sawClientRole {
		t.Fatalf("roles 面应可见 client（failed/重建中）：%+v", ds.Roles)
	}

	// ④ 放行重挂：表按盘上状态恢复（hosts.json 已持久化）；持游标 resubscribe
	// 不触发 cursor_stale（总线与代际随进程唯一不变——注释锚点：总线与代际挂在
	// 进程级 facade.Daemon 上，角色重建只换表指针，不换总线、不换代际）。
	close(role.release2)
	okDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(okDeadline) {
		if rawL, err := c.Request(rctx, facade.OpHostList, nil); err == nil {
			var list control.HostListResult
			if json.Unmarshal(rawL, &list) == nil && len(list.Hosts) == 1 && list.Hosts[0].ID == added.ID {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := c.Request(rctx, facade.OpHostList, nil); err != nil {
		t.Fatalf("重挂后 host.list 应恢复（盘上记录在）：%v", err)
	}
	if _, err := c.Subscribe(rctx, []string{facade.DomainSession}, &heldSeq, genBefore, ""); err != nil {
		t.Fatalf("持游标 resubscribe 不应报错（cursor_stale = 角色重建换了代际/总线——收拢换语义的红路）：%v", err)
	}
	raw, err = c.Request(rctx, facade.OpDaemonStatus, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(raw, &ds)
	if ds.Generation != genBefore {
		t.Fatalf("重挂后代际应变（%q → %q）", genBefore, ds.Generation)
	}
}
