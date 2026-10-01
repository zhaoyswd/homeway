package daemon

// unified_test.go — supervisor 动态生命周期与统一进程装配（role-management tasks
// 2.3 验证面）：stop→start 往返 / restart 计数与串行化 / stop 立即应答 + stopping
// 相位 / 重复 start 幂等 / stop 期间 Close / 期望态装配矩阵（四组合）/ 坏 config
// 拒启 / 同 state 第二进程锁拒 / **stop 后立即 start 实际监听端口仍为配置口（不退让）**
// + serve restart 代际不变（r1 中-2 / r1 中-4）。

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/internal/nodeconfig"
)

// ---- supervisor 动态生命周期（r1 中-2 四件 + stop 语义） ----

// blockRole 阻塞到 ctx 取消（收尾时长可注入——stop 相位/宽限观察用）。
type blockRole struct {
	name    string
	runs    chan struct{}
	exitDur time.Duration // Run 返回前的收尾时长（模拟 D5 宽限收尾）
}

func (b *blockRole) Name() string { return b.name }
func (b *blockRole) Run(ctx context.Context) error {
	if b.runs != nil {
		b.runs <- struct{}{}
	}
	<-ctx.Done()
	time.Sleep(b.exitDur)
	return ctx.Err()
}

func newSupForTest(t *testing.T) (context.Context, *supervisor, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	sup := newSupervisor(ctx, func(string, ...any) {}, func(string, ...any) {})
	return ctx, sup, func() { cancel(); sup.Close() }
}

func waitRoleState(t *testing.T, sup *supervisor, name, want string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		for _, st := range sup.Statuses() {
			if st.Name == name && st.State == want {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s 未在 %v 内进入 %s（statuses=%+v）", name, d, want, sup.Statuses())
}

// stop→start 往返 + 重复 start 幂等 + restart 未运行报错。
func TestSupervisorStopStartRoundtripAndIdempotent(t *testing.T) {
	_, sup, done := newSupForTest(t)
	defer done()
	runs := make(chan struct{}, 4)
	sup.StartRole("r", func() Role { return &blockRole{name: "r", runs: runs} }, nil)
	<-runs
	// 重复 start（运行中）= 幂等无动作：无第二次 Run。
	sup.StartRole("r", func() Role { return &blockRole{name: "r"} }, nil)
	select {
	case <-runs:
		t.Fatal("重复 start 不得触发第二次 Run（幂等）")
	case <-time.After(150 * time.Millisecond):
	}
	// stop → stopped → start：新实例 Run 起。
	sup.StopRole("r")
	waitRoleState(t, sup, "r", roleStateStopped, 5*time.Second)
	// restart 未运行 = 可行动错误。
	if err := sup.RestartRole("r"); err == nil {
		t.Fatal("未运行角色的 restart 应报错")
	}
	sup.StartRole("r", func() Role { return &blockRole{name: "r", runs: runs} }, nil)
	<-runs
}

// stop 立即应答 + stopping 相位（r1 中-4：取消 ctx 后立即成功，收尾异步呈现 stopping）。
func TestSupervisorStopImmediateAckAndStoppingPhase(t *testing.T) {
	_, sup, done := newSupForTest(t)
	defer done()
	runs := make(chan struct{}, 1)
	sup.StartRole("r", func() Role {
		return &blockRole{name: "r", runs: runs, exitDur: 300 * time.Millisecond}
	}, nil)
	<-runs
	start := time.Now()
	sup.StopRole("r") // 收尾 300ms——stop 调用必须立即返回
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("stop 应立即应答（实际 %v）——收尾异步呈现 stopping", elapsed)
	}
	waitRoleState(t, sup, "r", roleStateStopping, 2*time.Second)
	waitRoleState(t, sup, "r", roleStateStopped, 5*time.Second)
}

// restart = 等旧 Run 返回再 Start（串行化）+ 计数累计（与失败重建同面）。
// 串行化判据（r1 中-4）：旧角色收尾窗口 100ms 内 restart，两轮 Run **从不同时在世**
// ——不等旧 Run 返回就启新轮会看到并发 2。
func TestSupervisorRestartSerialAndCount(t *testing.T) {
	_, sup, done := newSupForTest(t)
	defer done()
	var mu sync.Mutex
	inRun, maxConcurrent := 0, 0
	runs := make(chan struct{}, 4)
	newRole := func() Role {
		return &slowCountRole{name: "r", runs: runs, mu: &mu, inRun: &inRun, maxCon: &maxConcurrent}
	}
	sup.StartRole("r", newRole, nil)
	<-runs
	if err := sup.RestartRole("r"); err != nil {
		t.Fatal(err)
	}
	<-runs // 第二轮 Run 起了（RestartRole 返回即已等旧轮退出）
	if st := roleStateOf(sup, "r"); st.Restarts != 1 {
		t.Fatalf("显式 restart 应计一次重建（Restarts=%d）", st.Restarts)
	}
	mu.Lock()
	got := maxConcurrent
	mu.Unlock()
	if got > 1 {
		t.Fatalf("restart 串行化被破坏：两轮 Run 并发在世（max=%d）", got)
	}
}

// slowCountRole：慢收尾角色（登记并发在世数——restart 串行化判据）。
type slowCountRole struct {
	name   string
	runs   chan struct{}
	mu     *sync.Mutex
	inRun  *int
	maxCon *int
}

func (b *slowCountRole) Name() string { return b.name }
func (b *slowCountRole) Run(ctx context.Context) error {
	b.mu.Lock()
	*b.inRun++
	if *b.inRun > *b.maxCon {
		*b.maxCon = *b.inRun
	}
	b.mu.Unlock()
	b.runs <- struct{}{}
	<-ctx.Done()
	time.Sleep(100 * time.Millisecond) // 收尾窗口（D5 宽限的缩小版）
	b.mu.Lock()
	*b.inRun--
	b.mu.Unlock()
	return ctx.Err()
}

func roleStateOf(sup *supervisor, name string) *RoleStatus {
	for _, st := range sup.Statuses() {
		if st.Name == name {
			return &st
		}
	}
	return nil
}

// stop 期间 Close：Close 等得到收尾中的角色退出（不挂死）。
func TestSupervisorCloseDuringStopping(t *testing.T) {
	_, sup, _ := newSupForTest(t)
	runs := make(chan struct{}, 1)
	sup.StartRole("r", func() Role {
		return &blockRole{name: "r", runs: runs, exitDur: 200 * time.Millisecond}
	}, nil)
	<-runs
	sup.StopRole("r")
	closed := make(chan struct{})
	go func() { sup.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("stop 期间 Close 挂死")
	}
}

// ---- 统一进程装配 ----

func shortStateDirUnified(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "uni")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func freeUDPUnified(t *testing.T) uint16 {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return uint16(pc.LocalAddr().(*net.UDPAddr).Port)
}

// safeUnifiedCfg 测试安全 config（外网探测关、随机端口、代答关）。
func safeUnifiedCfg(listen uint16) *nodeconfig.Config {
	c := nodeconfig.Default()
	c.Serve.Listen = listen
	c.Serve.UPnP = false
	c.Serve.STUN = ""
	c.Serve.STUN6 = ""
	c.Serve.DNSPort = 0
	c.Serve.MaxPeers = 4
	c.Serve.PeerTTL = time.Hour
	c.Relay.Enabled = false
	return c
}

// 期望态装配矩阵（四组合）：serve/relay 按 config 装配或缺席；client/control 恒开。
func TestUnifiedAssembleMatrix(t *testing.T) {
	for _, tc := range []struct {
		serve, relay bool
	}{
		{false, false}, {true, false}, {false, true}, {true, true},
	} {
		dir := shortStateDirUnified(t)
		c := safeUnifiedCfg(freeUDPUnified(t))
		c.Serve.Enabled = tc.serve
		c.Relay.Enabled = tc.relay
		if tc.relay {
			c.Relay.Listen = "127.0.0.1:" + strconv.Itoa(int(freeUDPUnified(t)))
		}
		if err := nodeconfig.Save(nodeconfig.Path(dir), c); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		proc, err := assembleUnified(ctx, "matrix-test", dir, false)
		if err != nil {
			t.Fatalf("serve=%v relay=%v：%v", tc.serve, tc.relay, err)
		}
		t.Cleanup(func() { proc.Close(); cancel() })
		has := func(name string) bool {
			for _, st := range proc.sup.Statuses() {
				if st.Name == name {
					return true
				}
			}
			return false
		}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if has("client") && has("control") {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if !has("client") || !has("control") {
			t.Fatalf("serve=%v relay=%v：client/control 应恒开（statuses=%+v）", tc.serve, tc.relay, proc.sup.Statuses())
		}
		if has("serve") != tc.serve || has("relay") != tc.relay {
			t.Fatalf("serve=%v relay=%v 装配不符（statuses=%+v）", tc.serve, tc.relay, proc.sup.Statuses())
		}
	}
}

// 坏 config 拒启（fail-fast——不静默按默认）。
func TestUnifiedBadConfigRefuses(t *testing.T) {
	dir := shortStateDirUnified(t)
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte("serve.listen = 99999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// 布局先就位（OpenNodeState 才建目录；坏 config 已在）。
	if err := os.MkdirAll(filepath.Join(dir, "cache"), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := assembleUnified(ctx, "badcfg-test", dir, false)
	if err == nil || !strings.Contains(err.Error(), "serve.listen") {
		t.Fatalf("坏 config 应 fail-fast 报字段：%v", err)
	}
}

// 同 state 第二进程锁拒（统一 vs 统一；前台单角色共用同一把锁由 AcquireInstanceLock
// 同一实现保证——lock_test 既有覆盖）。
func TestUnifiedSecondProcessLockRejected(t *testing.T) {
	dir := shortStateDirUnified(t)
	c := safeUnifiedCfg(freeUDPUnified(t))
	if err := nodeconfig.Save(nodeconfig.Path(dir), c); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proc, err := assembleUnified(ctx, "lock-test", dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer proc.Close()
	_, err2 := assembleUnified(context.Background(), "lock-test-2", dir, false)
	if err2 == nil || !strings.Contains(err2.Error(), "拒绝二次启动") {
		t.Fatalf("第二进程应被单实例锁拒：%v", err2)
	}
}

// **stop 后立即 start 实际监听端口仍为配置口（不退让）** + serve restart 代际不变
// （r1 中-4 串行化判据的端到端形态：不经串行化时新角色撞未释放的 WG UDP 端口，
// listenWithFallback 静默 +1…+9 ⇒ 端口漂移）。
func TestUnifiedServeStopStartPortStable(t *testing.T) {
	dir := shortStateDirUnified(t)
	port := freeUDPUnified(t)
	c := safeUnifiedCfg(port)
	if err := nodeconfig.Save(nodeconfig.Path(dir), c); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proc, err := assembleUnified(ctx, "port-test", dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer proc.Close()

	portFile := filepath.Join(dir, "cache", "listen_port.txt")
	waitPortFile(t, portFile, port, 20*time.Second)

	// stop：立即应答；stopped 后立即 start——实际端口必须仍是配置口。
	proc.sup.StopRole("serve")
	waitRoleState(t, proc.sup, "serve", roleStateStopped, 20*time.Second)
	proc.sup.StartRole("serve", proc.roles.makeServeFactory(), nil)
	waitRoleState(t, proc.sup, "serve", roleStateRunning, 20*time.Second)
	waitPortFile(t, portFile, port, 20*time.Second)

	// restart：代际不变（总线进程级唯一）+ 端口仍稳定。
	gen := proc.d.Generation()
	if err := proc.sup.RestartRole("serve"); err != nil {
		t.Fatal(err)
	}
	waitRoleState(t, proc.sup, "serve", roleStateRunning, 20*time.Second)
	waitPortFile(t, portFile, port, 20*time.Second)
	if got := proc.d.Generation(); got != gen {
		t.Fatalf("serve restart 不得换代际（%s → %s）", gen, got)
	}
	if st := roleStateOf(proc.sup, "serve"); st.Restarts != 1 {
		t.Fatalf("一次显式 restart = Restarts 1，got %d", st.Restarts)
	}
}

// 全停常驻（D9）：serve/relay 全停后 client/control 仍在、supervisor 可再启 serve。
func TestUnifiedAllStoppedStaysResident(t *testing.T) {
	dir := shortStateDirUnified(t)
	c := safeUnifiedCfg(freeUDPUnified(t))
	if err := nodeconfig.Save(nodeconfig.Path(dir), c); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proc, err := assembleUnified(ctx, "resident-test", dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer proc.Close()
	proc.sup.StopRole("serve")
	waitRoleState(t, proc.sup, "serve", roleStateStopped, 20*time.Second)
	// client/control 存活断言 + 进程面可再启 serve（常驻进程的恢复能力）。
	waitRoleState(t, proc.sup, "control", roleStateRunning, 5*time.Second)
	waitRoleState(t, proc.sup, "client", roleStateRunning, 5*time.Second)
	proc.sup.StartRole("serve", proc.roles.makeServeFactory(), nil)
	waitRoleState(t, proc.sup, "serve", roleStateRunning, 20*time.Second)
}

// waitPortFile 等 listen_port.txt 出现且值为指定端口（serve 角色的实际监听口落盘）。
func waitPortFile(t *testing.T, path string, port uint16, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil {
			if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n == int(port) {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("listen_port.txt 未在 %v 内写成配置口 %d", d, port)
}

// 统一进程 flag 面：--state 的值不得被误当角色 flag；真角色 flag = 可行动错误。
func TestRunUnifiedFlagSurface(t *testing.T) {
	dir := shortStateDirUnified(t)
	c := safeUnifiedCfg(freeUDPUnified(t))
	c.Serve.Enabled = false // 只装配 client/control——本用例不碰网络
	if err := nodeconfig.Save(nodeconfig.Path(dir), c); err != nil {
		t.Fatal(err)
	}
	// --state <dir>（值位跳过）：能起（后台短跑即收）。
	done := make(chan error, 1)
	go func() {
		done <- RunUnified("flag-test", []string{"--state", dir})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(filepath.Join(dir, "cache", "daemon-events.log")); err == nil && strings.Contains(string(b), "统一进程就绪") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case err := <-done:
		t.Fatalf("统一进程不应自行退出：%v", err)
	default:
	}
	// 角色 flag：可行动错误（不起进程）。
	if err := RunUnified("flag-test", []string{"--state", dir, "--listen", "41641"}); err == nil || !strings.Contains(err.Error(), "角色 flag") {
		t.Fatalf("统一进程角色 flag 应可行动错误：%v", err)
	}
	// --state=DIR 形态同过。
	if err := RunUnified("flag-test", []string{"--state=" + dir, "--listen", "41641"}); err == nil || !strings.Contains(err.Error(), "角色 flag") {
		t.Fatalf("--state=DIR 后的角色 flag 应可行动错误：%v", err)
	}
}
