package daemon

// spawn_cli_test.go — role-management tasks 4.1 判据：--no-spawn fail-fast / 就绪
// 超时可行动错误（含 spawn.log 回显）/ 残留锁文件判未运行 / 双 CLI 同时拉起单锁
// 收敛 / launchd 检测集合。self-exec 的真二进制路径归 e2e（exec-report）——单测经
// spawnStartFn/detectLaunchdAgentFn 注入缝（**测试包级默认值见下方 init**：任何
// 用例误触真实拉起都会得到确定性错误而不是 self-exec 测试二进制）。

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/facade"
	"github.com/zhaoyswd/homeway/internal/cliopts"
	"github.com/zhaoyswd/homeway/internal/control"
	"github.com/zhaoyswd/homeway/internal/nodeconfig"
	"github.com/zhaoyswd/homeway/internal/nodestate"
)

// spawnAttemptedForTest 拉起动做计数（变异自证判别力：纯读命令不得触发拉起——
// 「拉起失败被静默吞掉」与「根本没尝试拉起」在输出面不可区分，用计数区分）。
var spawnAttemptedForTest int

// 测试包级注入默认：拉起 = 确定性错误、launchd 检测 = 恒无。需要真拉起收敛判据的
// 用例（TestSpawnConvergesSingleLock）在用例内另行注入。
func init() {
	spawnStartFn = func(string) (int, error) {
		spawnAttemptedForTest++
		return 0, errors.New("测试默认不拉起（真拉起归 e2e）")
	}
	detectLaunchdAgentFn = func() string { return "" }
}

func spawnTestState(t *testing.T) string {
	t.Helper()
	dir := shortStateDirUnified(t)
	if err := nodeconfig.Save(nodeconfig.Path(dir), safeUnifiedCfg(freeUDPUnified(t))); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestSpawnNoSpawnFailFast --no-spawn = 可行动错误（含 control.sock 路径与启动命令）。
func TestSpawnNoSpawnFailFast(t *testing.T) {
	dir := spawnTestState(t)
	ctx := cliopts.With(context.Background(), cliopts.Opts{NoSpawn: true})
	_, err := dialControlSpawn(ctx, dir, "t", "cli-test")
	if err == nil || !strings.Contains(err.Error(), "--no-spawn") {
		t.Fatalf("--no-spawn 应可行动错误：%v", err)
	}
	for _, want := range []string{"control.sock", "先手动启动"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("错误缺 %q：%v", want, err)
		}
	}
}

// TestSpawnReadyTimeoutActionableError 拉起后 10s（用例缩短）未就绪 = 可行动错误，
// 回显 spawn.log 尾部与路径。
func TestSpawnReadyTimeoutActionableError(t *testing.T) {
	dir := spawnTestState(t)
	// 拉起桩：写一行失败原因进 spawn.log（模拟坏 config 早退）、不监听 control.sock。
	spawnStartFn = func(stateDir string) (int, error) {
		p := spawnLogName(stateDir)
		_ = os.MkdirAll(filepath.Dir(p), 0o700)
		_ = os.WriteFile(p, []byte("homeway: config.toml: serve.listen: 端口越界\n"), 0o600)
		return 4321, nil
	}
	t.Cleanup(func() { spawnStartFn = func(string) (int, error) { return 0, errors.New("测试默认不拉起") } })
	spawnReadyTimeout = 300 * time.Millisecond
	t.Cleanup(func() { spawnReadyTimeout = 10 * time.Second })

	var out bytes.Buffer
	err := ensureRunning(dir, &out)
	if err == nil || !strings.Contains(err.Error(), "未就绪") {
		t.Fatalf("就绪超时应可行动错误：%v", err)
	}
	if !strings.Contains(err.Error(), "端口越界") {
		t.Fatalf("错误应回显 spawn.log 尾部：%v", err)
	}
	if !strings.Contains(err.Error(), spawnLogName(dir)) {
		t.Fatalf("错误应带 spawn.log 路径：%v", err)
	}
	if !strings.Contains(out.String(), "已启动 pid=4321") {
		t.Fatalf("应打印拉起行：\n%s", out.String())
	}
}

// TestSpawnStaleLockJudgedNotRunning 残留锁文件 + 无进程 = 判「未运行可拉起」
// （flock 随进程死亡由内核释放——文件残留不算持锁，r1 低-3）。
func TestSpawnStaleLockJudgedNotRunning(t *testing.T) {
	dir := spawnTestState(t)
	// 伪造残留：真取一次锁后直接 Release（文件留下、flock 释放）。
	lock, err := nodestate.AcquireInstanceLock(dir, "homeway")
	if err != nil {
		t.Fatal(err)
	}
	lock.Release()
	if _, err := os.Stat(filepath.Join(dir, "lock")); err != nil {
		t.Fatalf("锁文件应残留：%v", err)
	}
	if nodestate.LockHeld(dir) {
		t.Fatal("残留锁文件（无进程持有）不得判为在跑")
	}
	// 活进程持锁 = 判在跑（dial 失败也不可拉起——走「不可达」分支）。
	lock2, err := nodestate.AcquireInstanceLock(dir, "homeway")
	if err != nil {
		t.Fatal(err)
	}
	defer lock2.Release()
	if !nodestate.LockHeld(dir) {
		t.Fatal("活进程持锁应判在跑")
	}
	// notRunningDial：锁被持有时即使 ENOENT 也不按未运行（防双拉起）。
	if notRunningDial(os.ErrNotExist, dir) {
		t.Fatal("锁被持有时不得判未运行")
	}
}

// TestSpawnLockHeldStartupWindowConverges 5.1 门禁批实测撞出的竞态钉死（正例）：
// 两个 CLI 同时冷启动的另一交错——第二个 CLI 首拨 ENOENT 时第一个进程**已取锁、
// control.sock 尚未就绪**。期望 = 不立刻报「不可达」，有界等就绪后重拨复用
// （不拉第二个进程：拉起计数为 0）。
func TestSpawnLockHeldStartupWindowConverges(t *testing.T) {
	dir := spawnTestState(t)
	// 本测试进程持锁 = 「正在启动的第一个进程」（取锁 → control.sock 就绪之间的窗口）。
	lock, err := nodestate.AcquireInstanceLock(dir, "homeway")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	// 300ms 后窗口结束：真控制面 listener 上线（真握手，重拨须真成功）。
	go func() {
		time.Sleep(300 * time.Millisecond)
		_, ln, err := control.ListenControl(dir)
		if err != nil {
			return // 用例随后在就绪等待处红
		}
		srv := control.NewServer(control.ServerConfig{
			ServerVersion: "t", Bus: facade.NewBus(facade.NewGeneration(), facade.BusConfig{}),
			Backend: &noopBackend{},
		})
		go func() { _ = srv.Serve(ln) }()
		time.Sleep(2 * time.Second) // 保 listener 在世到重拨完成（随后随进程退出收工）
	}()
	before := spawnAttemptedForTest
	c, err := dialControlSpawn(context.Background(), dir, "t", "cli-test")
	if err != nil {
		t.Fatalf("启动窗口内应等就绪并复用（不得立刻报不可达）：%v", err)
	}
	c.Close()
	if got := spawnAttemptedForTest - before; got != 0 {
		t.Fatalf("锁被持有时不得拉起第二个进程（拉起计数 +%d）", got)
	}
}

// TestSpawnLockHeldNoSocketBoundedError 同窗口的负例：锁被持有且 socket 永不出现
// （持有者卡死/异常）——有界等后按「不可达」报可行动错误（预算注入缩短），零拉起。
func TestSpawnLockHeldNoSocketBoundedError(t *testing.T) {
	dir := spawnTestState(t)
	lock, err := nodestate.AcquireInstanceLock(dir, "homeway")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	spawnReadyTimeout = 300 * time.Millisecond
	t.Cleanup(func() { spawnReadyTimeout = 10 * time.Second })

	before := spawnAttemptedForTest
	_, err = dialControlSpawn(context.Background(), dir, "t", "cli-test")
	if err == nil || !strings.Contains(err.Error(), "未在运行") {
		t.Fatalf("窗口耗尽应报可行动错误：%v", err)
	}
	if got := spawnAttemptedForTest - before; got != 0 {
		t.Fatalf("锁被持有时不得拉起第二个进程（拉起计数 +%d）", got)
	}
}

// TestSpawnConvergesSingleLock 两个 CLI 同时拉起 = 单进程单锁收敛（tasks 4.1）：
// 拉起动做注入为「真 assembleUnified」（第一个进入者）——第二个进入者的拉起动作
// 像**真实 self-exec** 一样「进程拉起成功但子进程撞锁退出」（Start 成功返回 pid），
// 随后 ensureRunning 轮询 control.sock 就绪——第一个进程的 socket 就绪即双方收敛
// （真实世界的收敛机制：单实例锁互斥 + 就绪轮询，launchd 侧重拉同理为预期噪音）。
func TestSpawnConvergesSingleLock(t *testing.T) {
	dir := spawnTestState(t)
	var mu sync.Mutex
	spawned := 0
	spawnStartFn = func(stateDir string) (int, error) {
		mu.Lock()
		spawned++
		first := spawned == 1
		mu.Unlock()
		if !first {
			// 第二个进入者：self-exec 的 Start 成功（返回 pid）、子进程随后撞锁退出
			//——ensureRunning 的就绪轮询会等到第一个进程的 control.sock。
			return 777, nil
		}
		ctx, cancel := context.WithCancel(context.Background())
		proc, err := assembleUnified(ctx, "spawn-conv", stateDir, false)
		if err != nil {
			cancel()
			return 0, err
		}
		t.Cleanup(func() { _ = proc.Close(); cancel() })
		return 99999, nil
	}
	t.Cleanup(func() { spawnStartFn = func(string) (int, error) { return 0, errors.New("测试默认不拉起") } })

	// 并发两个「客户端域命令」：都应在同一条 control.sock 上完成。
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var out bytes.Buffer
			errs[i] = hostCLI([]string{"list", "--state", dir, "--timeout", "30s"}, "t", &out)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("CLI[%d] 未收敛完成：%v", i, err)
		}
	}
	mu.Lock()
	got := spawned
	mu.Unlock()
	if got < 1 {
		t.Fatal("至少一个拉起应发生")
	}
}

// TestSpawnLaunchdDetectSet 检测集合 = LaunchAgents 里任意 homeway plist（泛化覆盖
// 模板 label 与现役 me.zhaozhe.homeway-exit——r2 新-3）。
func TestSpawnLaunchdDetectSet(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("无 HOME")
	}
	agents := filepath.Join(home, "Library", "LaunchAgents")
	if _, err := os.Stat(agents); err != nil {
		t.Skip("无 LaunchAgents 目录（非 darwin 常态）")
	}
	got := detectLaunchdAgent()
	if got == "" {
		t.Skip("本机无 homeway 代理 plist（检测面靠 e2e 的在役形态采证）")
	}
	if !strings.Contains(got, "homeway") {
		t.Fatalf("检测出的 label 应含 homeway：%q", got)
	}
}

// TestSpawnKeepAliveWaitPath 托管形态先短轮询等 KeepAlive 重拉（r1 中-3）：
// ①检测命中 + 窗口内 sock 就绪 → 复用（无自 exec 行、拉起计数为零）；
// ②窗口内未就绪 → 落自 exec 分支（打印「改为自行拉起」）。
func TestSpawnKeepAliveWaitPath(t *testing.T) {
	dir := spawnTestState(t)
	detectLaunchdAgentFn = func() string { return "me.zhaozhe.homeway-test" }
	t.Cleanup(func() { detectLaunchdAgentFn = func() string { return "" } })
	spawned := 0
	spawnStartFn = func(string) (int, error) { spawned++; return 111, nil }
	t.Cleanup(func() { spawnStartFn = func(string) (int, error) { return 0, errors.New("测试默认不拉起") } })

	// ①KeepAlive 重拉到位：窗口内起真进程（模拟 KeepAlive 拉起）→ ensureRunning
	// 复用、零自 exec。
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		time.Sleep(300 * time.Millisecond)
		proc, err := assembleUnified(ctx, "ka-test", dir, false)
		if err == nil {
			t.Cleanup(func() { _ = proc.Close() })
		}
	}()
	var out bytes.Buffer
	if err := ensureRunning(dir, &out); err != nil {
		t.Fatalf("KeepAlive 窗口内就绪应复用：%v（out=%s）", err, out.String())
	}
	if !strings.Contains(out.String(), "等 KeepAlive 重拉") || strings.Contains(out.String(), "自行拉起") {
		t.Fatalf("应走 KeepAlive 复用分支：%s", out.String())
	}
	if spawned != 0 {
		t.Fatalf("复用分支不得自 exec（spawned=%d）", spawned)
	}
	_ = procCloseAll()

	// ②窗口内未就绪 → 自 exec 分支（就绪超时由用例①的真进程已就绪……改用独立
	// state 验证分支路径）。
	dir2 := spawnTestState(t)
	spawnReadyTimeout = 200 * time.Millisecond
	t.Cleanup(func() { spawnReadyTimeout = 10 * time.Second })
	var out2 bytes.Buffer
	err := ensureRunning(dir2, &out2)
	if err == nil || !strings.Contains(out2.String(), "改为自行拉起") {
		t.Fatalf("KeepAlive 超时应落自 exec 分支：%v（%s）", err, out2.String())
	}
	if spawned == 0 {
		t.Fatal("自 exec 分支应发生拉起动做")
	}
}

// procCloseAll 占位（无实际句柄需收——①的真进程经 t.Cleanup 收）。
func procCloseAll() error { return nil }

var _ = fmt.Sprintf
