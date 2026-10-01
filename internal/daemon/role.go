package daemon

// role.go — 角色子系统与顶层 recover（host-registry-daemon 2.4，D4「单进程 + 角色
// 子系统」）：每角色一个顶层 goroutine + defer recover——panic/错误 → 角色按 failed
// 收工（状态面可见）→ 按有限退避表**进程内重建**（makeRole 重新构造，退避到表尾后
// 固定尾间隔重试——有界节拍而非退出）；MUST NOT os.Exit（单角色崩溃不杀全家——
// 与「三子进程」方案的裁决分界）。
//
// 动态生命周期（role-management 2.3，r1 中-2）：在装配期 Start + 失败退避之上加
// StartRole/StopRole/RestartRole——每角色一个子 ctx（进程级 ctx 派生，cancel 只波及
// 该角色）；重建与失败路径合一（无第三条路径）；**start/restart 先等旧角色 Run 返回
// 再 Start（串行化——防端口静默退让，r1 中-4）**；stop = 取消 ctx 立即返回（收尾异步，
// 状态面呈现 stopping → stopped）；Close 顺序与事件总线代际不受动态启停影响（总线
// 进程级唯一）。
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

// Role 一个可独立重拉的角色单元（实现：client/control（既有）+ serve/relay
// （role-management 2.1/2.2 的 internal/server.Role / internal/relay.Role））。
type Role interface {
	Name() string
	// Run 起角色并阻塞到收工：ctx 取消 = 正常收工（返回 nil 或 ctx.Err()）；
	// 返回其它错误 = 角色失败（触发退避重建）。panic 同样触发重建（defer recover）。
	Run(ctx context.Context) error
}

// 角色状态（失败可见：HD「单进程 + 角色子系统」；stopping = 动态 stop 的收尾相位——
// stop 立即应答、收尾异步，role-management 2.3 / r1 中-4）。
const (
	roleStateRunning  = "running"
	roleStateFailed   = "failed"
	roleStateStopped  = "stopped"
	roleStateStopping = "stopping"
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

// managedRole 动态生命周期的一个角色条目（ctx/cancel/done 建后不改；done 随循环退出关闭）。
type managedRole struct {
	name     string
	makeRole func() Role
	backoff  []time.Duration
	ctx      context.Context    // 该角色子 ctx（进程级派生）
	cancel   context.CancelFunc // Stop/Restart/进程收工取消
	done     chan struct{}      // 当前运行轮的循环退出（start 串行化的等待点）
}

// supervisor 角色子系统：管理一组角色的生命周期与退避重建 + 动态启停。
type supervisor struct {
	ctx context.Context // 进程级 ctx（构造时给；每角色子 ctx 由它派生）

	mu    sync.Mutex
	stats map[string]*RoleStatus
	roles map[string]*managedRole

	logf   func(format string, args ...any) // 摘要级（events.log + 终端）
	debugf func(format string, args ...any) // 细节级（debug.log）
	wg     sync.WaitGroup
}

func newSupervisor(ctx context.Context, eventf, debugf func(string, ...any)) *supervisor {
	return &supervisor{
		ctx:    ctx,
		stats:  make(map[string]*RoleStatus),
		roles:  make(map[string]*managedRole),
		logf:   eventf,
		debugf: debugf,
	}
}

// Start 起一个角色（装配期形态；makeRole 在每次重建时重新调用——角色对象不跨重建
// 复用）。name 显式给：**不得**用 makeRole() 的返回值取名（会白白消耗一次工厂调用
// ——startControlPlane 的首启注入就是「一次性的 first 角色」，被误耗即失去注入
// listener）。backoff 为 nil 时用默认表（测试注入缩短）。进程级 ctx 取消 → 全部
// 角色正常收工。
func (s *supervisor) Start(name string, makeRole func() Role, backoff []time.Duration) {
	s.startRole(name, makeRole, backoff)
}

// StartRole 动态首启/重新装载（幂等：运行中 = 成功无动作）。**串行化**：上一轮仍在
// 收尾（stopping）时先等其 Run 返回（端口/socket 释放净）再启动——否则新角色撞未
// 释放的端口、listenWithFallback 静默退让（r1 中-4）。
func (s *supervisor) StartRole(name string, makeRole func() Role, backoff []time.Duration) {
	s.startRole(name, makeRole, backoff)
}

func (s *supervisor) startRole(name string, makeRole func() Role, backoff []time.Duration) {
	for {
		s.mu.Lock()
		if m, ok := s.roles[name]; ok {
			if m.phaseRunning(s.stats[name]) {
				s.mu.Unlock()
				return // 幂等：运行中重复 start = 成功无动作
			}
			select {
			case <-m.done: // 旧轮已退出（stopped）：换代——落到下方建新轮
			default:
				// stopping（收尾中）：锁外等旧轮 Run 返回（端口/socket 释放净）再启。
				done := m.done
				s.mu.Unlock()
				select {
				case <-done:
				case <-s.ctx.Done():
					return
				}
				continue
			}
		}
		roleCtx, cancel := context.WithCancel(s.ctx)
		m := &managedRole{name: name, makeRole: makeRole, backoff: backoff, ctx: roleCtx, cancel: cancel, done: make(chan struct{})}
		s.roles[name] = m
		s.setStatLocked(name, roleStateRunning, "")
		s.wg.Add(1)
		go s.runRoleLoop(m)
		s.mu.Unlock()
		return
	}
}

// StopRole 动态停一个角色：取消其子 ctx 后**立即返回**（成功应答不等收尾——D5 完成语义
// r1 中-4：收尾最长 = 10s 宽限 + UPnP 缩租 8s，同步等会烧穿请求预算）；收尾异步进行，
// 状态面 stopping → stopped。未运行/未装载 = 幂等成功。
func (s *supervisor) StopRole(name string) {
	s.mu.Lock()
	m, ok := s.roles[name]
	if !ok {
		s.mu.Unlock()
		return
	}
	st := s.stats[name]
	if st == nil || st.State != roleStateRunning {
		s.mu.Unlock()
		return // 已停/停中：幂等
	}
	s.setStatLocked(name, roleStateStopping, st.LastError)
	s.mu.Unlock()
	m.cancel()
	s.logf("role %s: 停止（收尾进行中——状态面 stopping 至收尾完成）", name)
}

// RestartRole 动态重启 = 取消子 ctx → **等旧角色 Run 返回**（串行化，r1 中-4）→ 同一条
// 重建路径再启动（期望态不变；Restarts 计数与失败重建同面累计）。未运行 = 可行动错误
// （上层映射「先 serve start」提示，r1 中-6）。
func (s *supervisor) RestartRole(name string) error {
	s.mu.Lock()
	m, ok := s.roles[name]
	if !ok || !m.phaseRunning(s.stats[name]) {
		s.mu.Unlock()
		return fmt.Errorf("角色 %s 未在运行（先 start）", name)
	}
	st := s.stats[name]
	s.setStatLocked(name, roleStateStopping, st.LastError)
	s.mu.Unlock()
	m.cancel()
	select {
	case <-m.done:
	case <-s.ctx.Done():
		return fmt.Errorf("进程收工中，%s 的重启被放弃", name)
	}
	s.startRole(name, m.makeRole, m.backoff)
	s.bumpRestarts(name)
	s.logf("role %s: 显式重启完成（重建计数 %d）", name, s.statRestarts(name))
	return nil
}

// phaseRunning 状态面判运行（stats 由调用方持锁读）。
func (m *managedRole) phaseRunning(st *RoleStatus) bool {
	return st != nil && st.State == roleStateRunning
}

// runRoleLoop 一个角色的运行-失败-退避-重建循环（角色 goroutine 本体；动态 stop =
// 子 ctx 取消 = 正常收工退出，不重建）。
func (s *supervisor) runRoleLoop(m *managedRole) {
	defer s.wg.Done()
	defer close(m.done)
	roleCtx := m.ctx
	role := m.makeRole()
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
			runErr = role.Run(roleCtx)
		}()
		if runErr == nil || contextDone(runErr) {
			// 正常收工（子 ctx 取消族也按正常收工——动态 stop 与进程收工都走这里）。
			s.setStat(name, roleStateStopped, "")
			s.debugf("role %s: 正常收工", name)
			return
		}
		// 失败：状态面 failed → 退避 → 进程内重建（与显式 restart 同一条重建面）。
		s.setStat(name, roleStateFailed, runErr.Error())
		wait := m.backoffAt(fails)
		fails++
		s.logf("role %s: 失败（%v）——退避 %v 后进程内重建", name, runErr, wait)
		select {
		case <-time.After(wait):
		case <-roleCtx.Done():
			s.setStat(name, roleStateStopped, runErr.Error())
			return
		}
		role = m.makeRole()
		s.bumpRestarts(name)
		s.setStat(name, roleStateRunning, "")
		s.debugf("role %s: 第 %d 次进程内重建", name, s.statRestarts(name))
	}
}

func (m *managedRole) backoffAt(fails int) time.Duration {
	if m.backoff == nil {
		m.backoff = defaultRoleBackoff
	}
	return m.backoff[min(fails, len(m.backoff)-1)]
}

// setStat 写一角色状态（内部锁版与外部版）。
func (s *supervisor) setStat(name, state, lastErr string) *RoleStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.setStatLocked(name, state, lastErr)
}

func (s *supervisor) setStatLocked(name, state, lastErr string) *RoleStatus {
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

// Close 收工：等全部角色循环退出（角色自身经子 ctx/StopRole 收口；退避睡眠中的循环
// 最长再等一个表尾间隔——daemon 进程收工不等它，Close 只用于测试与显式停角色场景）。
func (s *supervisor) Close() { s.wg.Wait() }

// contextDone 判 err 是否 ctx 取消族。
func contextDone(err error) bool {
	return err == context.Canceled || err == context.DeadlineExceeded
}
