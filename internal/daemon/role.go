package daemon

// role.go — 角色子系统与顶层 recover（host-registry-daemon 2.4，D4「单进程 + 角色
// 子系统」）：每角色一个顶层 goroutine + defer recover——panic/错误 → 角色按 failed
// 收工（状态面可见）→ 按有限退避表**进程内重建**（makeRole 重新构造，退避到表尾后
// 固定尾间隔重试——有界节拍而非退出）；MUST NOT os.Exit（单角色崩溃不杀全家——
// 与「三子进程」方案的裁决分界）。
//
// 兜底序（D4）：角色内自愈 → 进程内角色重建（本文件）→ launchd KeepAlive 重拉进程
//（4.2 模板）。进程死活 = 平台层，链路恢复 = 核内（hostsession），视图重连 = 前端
// 薄 resubscribe（§3 快照 + 游标）。

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Role 一个可独立重拉的角色单元（本期唯一实现 = client：注册表宿主）。
type Role interface {
	Name() string
	// Run 起角色并阻塞到收工：ctx 取消 = 正常收工（返回 nil 或 ctx.Err()）；
	// 返回其它错误 = 角色失败（触发退避重建）。panic 同样触发重建（defer recover）。
	Run(ctx context.Context) error
}

// 角色状态（失败可见：HD「单进程 + 角色子系统」）。
const (
	roleStateRunning = "running"
	roleStateFailed  = "failed"
	roleStateStopped = "stopped"
)

// RoleStatus 角色状态面快照。
type RoleStatus struct {
	Name      string
	State     string
	Restarts  int
	LastError string
}

// defaultRoleBackoff 重建退避表（有限：索引递增取值，越界取表尾——失败节拍收敛到
// 表尾间隔，不无限加密、也绝不退出进程）。
var defaultRoleBackoff = []time.Duration{
	500 * time.Millisecond, 1 * time.Second, 5 * time.Second, 30 * time.Second,
}

// supervisor 角色子系统：管理一组角色的生命周期与退避重建。
type supervisor struct {
	mu    sync.Mutex
	stats map[string]*RoleStatus

	logf   func(format string, args ...any) // 摘要级（events.log + 终端）
	debugf func(format string, args ...any) // 细节级（debug.log）
	wg     sync.WaitGroup
}

func newSupervisor(eventf, debugf func(string, ...any)) *supervisor {
	return &supervisor{
		stats:  make(map[string]*RoleStatus),
		logf:   eventf,
		debugf: debugf,
	}
}

// Start 起一个角色（makeRole 在每次重建时重新调用——角色对象不跨重建复用）。
// backoff 为 nil 时用默认表（测试注入缩短）。ctx 取消 → 角色正常收工、循环退出。
func (s *supervisor) Start(ctx context.Context, makeRole func() Role, backoff []time.Duration) {
	if backoff == nil {
		backoff = defaultRoleBackoff
	}
	s.wg.Add(1)
	go s.runRoleLoop(ctx, makeRole, backoff)
}

// runRoleLoop 一个角色的运行-失败-退避-重建循环（角色 goroutine 本体）。
func (s *supervisor) runRoleLoop(ctx context.Context, makeRole func() Role, backoff []time.Duration) {
	defer s.wg.Done()
	role := makeRole()
	name := role.Name()
	s.setStat(name, roleStateRunning, "")
	fails := 0
	for {
		// 本轮运行：defer recover 兜 panic（MUST NOT os.Exit；recover 后按失败重建）。
		var runErr error
		func() {
			defer func() {
				if r := recover(); r != nil {
					runErr = fmt.Errorf("角色 panic：%v", r)
				}
			}()
			runErr = role.Run(ctx)
		}()
		if runErr == nil || contextDone(runErr) {
			// 正常收工（ctx 取消族也按正常收工——循环退出，不重建）。
			s.setStat(name, roleStateStopped, "")
			s.debugf("role %s: 正常收工", name)
			return
		}
		// 失败：状态面 failed → 退避 → 进程内重建。
		s.setStat(name, roleStateFailed, runErr.Error())
		wait := backoff[min(fails, len(backoff)-1)]
		fails++
		s.logf("role %s: 失败（%v）——退避 %v 后进程内重建", name, runErr, wait)
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			s.setStat(name, roleStateStopped, runErr.Error())
			return
		}
		role = makeRole()
		s.bumpRestarts(name)
		s.setStat(name, roleStateRunning, "")
		s.debugf("role %s: 第 %d 次进程内重建", name, s.statRestarts(name))
	}
}

// setStat 写一角色状态并返回该条目。
func (s *supervisor) setStat(name, state, lastErr string) *RoleStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.stats[name]
	if !ok {
		st = &RoleStatus{Name: name}
		s.stats[name] = st
	}
	st.State = state
	st.LastError = lastErr
	return st
}

func (s *supervisor) bumpRestarts(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats[name].Restarts++
}

func (s *supervisor) statRestarts(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats[name].Restarts
}

// Statuses 状态面快照。
func (s *supervisor) Statuses() []RoleStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]RoleStatus, 0, len(s.stats))
	for _, st := range s.stats {
		out = append(out, *st)
	}
	return out
}

// Close 收工：等全部角色循环退出（角色自身经 ctx/Stop 收口；退避睡眠中的循环最长
// 再等一个表尾间隔——daemon 进程收工不等它，Close 只用于测试与显式停角色场景）。
func (s *supervisor) Close() { s.wg.Wait() }

// contextDone 判 err 是否 ctx 取消族。
func contextDone(err error) bool {
	return err == context.Canceled || err == context.DeadlineExceeded
}
