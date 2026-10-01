package daemon

// role_test.go — 角色子系统顶层 recover（host-registry-daemon 2.4，HD「单进程 +
// 角色子系统」）：注入 panic 的角色——进程存活（测试本身继续跑即证）、状态面 failed
// 可见、有限退避后进程内重建被调用。

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// panicRole 前 N 次 Run panic，之后正常运行（阻塞到 ctx 取消）。
type panicRole struct {
	name     string
	panics   int32 // 剩余 panic 次数
	runs     atomic.Int32
	ranClean chan struct{} // close = 至少一次干净运行已开始
}

func (p *panicRole) Name() string { return p.name }

func (p *panicRole) Run(ctx context.Context) error {
	p.runs.Add(1)
	if p.panics > 0 && atomic.AddInt32(&p.panics, -1) >= 0 {
		panic(errors.New("注入的角色 panic"))
	}
	close(p.ranClean)
	<-ctx.Done()
	return ctx.Err()
}

func TestRolePanicRebuildsBoundedAndStaysInProcess(t *testing.T) {
	role := &panicRole{name: "test-role", panics: 2, ranClean: make(chan struct{})}
	var makes atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sup := newSupervisor(
		ctx,
		func(format string, args ...any) {},
		func(format string, args ...any) {},
	)
	sup.Start("test-role", func() Role {
		makes.Add(1)
		return role // 同一实例继续消耗 panics 计数（等价于重建新实例）
	}, []time.Duration{time.Millisecond, 2 * time.Millisecond})

	// 等两次 panic 消化完、第三次运行干净开跑（有界）。
	select {
	case <-role.ranClean:
	case <-time.After(5 * time.Second):
		t.Fatalf("5s 内未完成退避重建（runs=%d makes=%d）", role.runs.Load(), makes.Load())
	}

	// 状态面：failed 曾可见（LastError 留痕）、当前 running、重建计数 ≥ 2。
	st := sup.statusOf("test-role")
	if st == nil {
		t.Fatal("状态面无该角色")
	}
	if st.Restarts < 2 {
		t.Fatalf("重建计数 %d < 2（panic 两次都应重建）", st.Restarts)
	}
	if st.State != roleStateRunning {
		t.Fatalf("重建后状态 %q，want running", st.State)
	}
	// 进程存活：测试跑到这里、角色 goroutine 还在（MUST NOT os.Exit 的行为面证据）。
	if got := role.runs.Load(); got < 3 {
		t.Fatalf("运行次数 %d < 3", got)
	}

	cancel()
	// ctx 取消 → 角色正常收工（不因取消按失败重建）。
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if st := sup.statusOf("test-role"); st != nil && st.State == roleStateStopped {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("ctx 取消后角色未按 stopped 收工：%+v", sup.Statuses())
}

// 稳定失败的角色：退避表耗尽后按表尾节拍继续重建（不退出进程、不无限加密退避）。
func TestRolePersistentFailureKeepsBoundedRebuild(t *testing.T) {
	var runs atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sup := newSupervisor(ctx, func(string, ...any) {}, func(string, ...any) {})
	sup.Start("always-fail", func() Role {
		return errorRole{name: "always-fail", runs: &runs}
	}, []time.Duration{time.Millisecond, 2 * time.Millisecond, 3 * time.Millisecond})

	// 表长 3：至少跑完一轮全表（4 次运行）仍在本进程内继续。断言口径（race 下
	// 修正）：观测到 failed **或其后的重建 running** 均成立——每次失败都经
	// setStat(failed) 再重建，Restarts>=3 即证明失败可见与「仍在进程内按表尾
	// 重建」两断言（严格「此刻恰为 failed」存在观测窗口竞态：runs 到 4 的瞬间
	// 可能已进入第 5 次运行）。
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if runs.Load() >= 4 {
			st := sup.statusOf("always-fail")
			if st == nil || (st.State != roleStateFailed && st.State != roleStateRunning) {
				t.Fatalf("持续失败的角色状态面异常：%+v", sup.Statuses())
			}
			if st.Restarts >= 3 {
				return // 全表耗尽后仍在进程内按表尾重建——断言达成
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("5s 内未消化完整退避表（runs=%d）", runs.Load())
}

type errorRole struct {
	name string
	runs *atomic.Int32
}

func (e errorRole) Name() string { return e.name }
func (e errorRole) Run(ctx context.Context) error {
	e.runs.Add(1)
	return errors.New("持续失败")
}

// statusOf 取单角色状态（测试便利）。
func (s *supervisor) statusOf(name string) *RoleStatus {
	for _, st := range s.Statuses() {
		if st.Name == name {
			return &st
		}
	}
	return nil
}
