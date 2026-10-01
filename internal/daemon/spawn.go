package daemon

// spawn.go — 按需拉起（role-management tasks 4.1，design D4 / RM「按需拉起与
// --no-spawn」）：归属守护托管/控制面转发的命令在统一进程未运行时自动拉起——
// 打印一行「守护进程未运行，已启动 pid=N」（非静默）→ 拉起后重试控制面连接。
//
// 未运行判定（r1 低-3，与 lock.go 口径一致）：control.sock connect
// ENOENT/ECONNREFUSED **且** <state>/lock 的 flock 试探拿得到（残留锁文件 + 无进程
// = 可拉起；拿不到 = 进程在跑、不拉第二个——其中「锁被持有但 socket 未就绪」=
// 另一进程正在启动的窗口，有界等就绪复用，等不到才按「不可达」报可行动错误）。
//
// 与 launchd KeepAlive 的交互（r1 中-3 选 a；检测集合 r2 新-3）：检测到托管形态
//（模板 label ∪ 现役 me.zhaozhe.homeway-exit——或本机任意 homeway 代理 plist）时
// 先短轮询等 KeepAlive 重拉（检测到即等 3–5s），等到即复用、超时才自 exec——CLI
// 自 exec 出的进程不归 launchd 管，KeepAlive 会反复重拉自己的实例撞锁。仍不做
// `launchctl kickstart`（不依赖 label 约定命令）。
//
// self-exec：os.Executable + `--state` 透传 + setsid（脱离会话）；stdio 固定接
// <state>/cache/spawn.log（r1 低-2——子进程失败原因发生在启动早期，接 /dev/null
// 会让「就绪超时 = 可行动错误」拿不到失败原因）；有界轮询 control.sock 就绪
//（10s 上限），超时的可行动错误回显该文件尾部若干行 + 路径。
//
// 平台边界：darwin/Linux 生效；Windows = 可行动错误（无 daemon 部署面）。
// --no-spawn（ctx 经 internal/cliopts 挂载）= fail-fast 可行动错误。

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/zhaoyswd/homeway/internal/cliopts"
	"github.com/zhaoyswd/homeway/internal/control"
	"github.com/zhaoyswd/homeway/internal/nodestate"
)

// 拉起节拍（design D4：KeepAlive 等待 3–5s、就绪上限 10s）。var = 测试可缩短
// （生产值如下；同 devOpTimeout 先例）。
var (
	spawnKeepAliveWait = 4 * time.Second  // launchd 托管形态下等 KeepAlive 重拉的窗口
	spawnReadyTimeout  = 10 * time.Second // 自 exec 后 control.sock 就绪的上限
)

const (
	spawnPollStep = 100 * time.Millisecond
	// spawnLogTailLines 就绪超时错误里回显的 spawn.log 尾部行数。
	spawnLogTailLines = 12
)

// 拉起的可注入缝（测试：不真 self-exec 测试二进制/不真探测 launchd）。
var (
	spawnStartFn         = startSpawnedProcess
	detectLaunchdAgentFn = detectLaunchdAgent
)

// dialControlSpawn 按需拉起的统一注入缝（客户端域命令与 serve/relay start 共用）：
// 先按 ctx 预算试拨 control.sock；失败且判定「未运行」→ 拉起（提示行走 cliopts.Out）
// → 就绪后重拨。拉起与就绪等待**不受 ctx 预算约束**（拉起窗口 10s 级 > 命令默认
// 预算；ctx 已被调用方 cancel 时放弃）。--no-spawn / Windows / 进程在跑但不可达 =
// 可行动错误。
func dialControlSpawn(ctx context.Context, stateDir, version, name string) (*control.Client, error) {
	c, err := probeControl(ctx, stateDir, version, name)
	if err != nil {
		return nil, err
	}
	if c != nil {
		return c, nil // 在跑可用
	}
	// c == nil, err == nil：未运行（判定+启动窗口等待已由 probeControl 收口）。
	sock := controlSockOf(stateDir)
	opts := cliopts.From(ctx)
	if opts.NoSpawn {
		return nil, fmt.Errorf("守护进程未运行且 --no-spawn 已给定（不拉起）\nsock=%s\n先手动启动：homeway --state %s（零参统一进程；Ctrl-C 收工）", sock, stateDir)
	}
	if runtime.GOOS == "windows" {
		return nil, fmt.Errorf("守护进程未运行——Windows 不支持按需拉起（darwin/Linux 才有）\n先手动启动：homeway --state %s", stateDir)
	}

	if err := ensureRunning(stateDir, opts.Out); err != nil {
		return nil, err
	}
	// 就绪后重拨（新预算：原 ctx 的预算可能已在首次拨号里烧掉大半）。
	dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c2, _, derr := control.Dial(dctx, sock, control.FrontendInfo{Kind: "cli", Name: name, Version: version})
	if derr != nil {
		return nil, controlDialErr(stateDir, sock, derr)
	}
	return c2, nil
}

// probeControl 「未运行判定 + 启动窗口等待」的**唯一注入缝**（FIX-49：此前 role
// start 自己裸拨一份、dialControlSpawn 一份，启动窗口的等待只在后者有——两个 CLI
// 同时冷启动时，走 role start 的那个会立刻按「不可达」报错）。
//
// 返回：
//   - (client, nil)：在跑可用（含等启动窗口就绪后的重拨成功）；
//   - (nil, nil)  ：判定**未运行**（ENOENT/ECONNREFUSED 族 + flock 试探拿得到）——
//     调用方按自身策略拉起；
//   - (nil, err)  ：其它可行动错误（含「锁被持有但 control.sock 长期不就绪」——提示
//     带持有者形态与 pid，不再误报「未在运行」）。
func probeControl(ctx context.Context, stateDir, version, name string) (*control.Client, error) {
	sock := controlSockOf(stateDir)
	info := control.FrontendInfo{Kind: "cli", Name: name, Version: version}
	c, _, err := control.Dial(ctx, sock, info)
	if err == nil {
		return c, nil
	}
	if notRunningDial(err, stateDir) {
		return nil, nil // 未运行：可拉起
	}
	// 「未运行族错误 + 锁被持有」= 另一进程刚取锁、control.sock 尚未就绪的**启动窗口**
	// （两个 CLI 同时冷启动的竞态：第二个进入者此时不该立刻报错，5.1 门禁批整面负载下
	// 实测撞出）——有界等就绪后重拨复用。等不到：提示说清是被谁占着（形态+pid）。
	if notRunningFamily(err) {
		if waitControlReady(stateDir, spawnReadyTimeout) {
			if c2, _, derr := control.Dial(ctx, sock, info); derr == nil {
				return c2, nil
			}
		}
		held, pid, form := nodestate.LockHolderInfo(stateDir)
		if held {
			return nil, fmt.Errorf("另一 homeway 进程（pid %d，形态 %s）正持有 state 锁，但控制面 %v 内未就绪（该进程可能正在启动或卡住）\nstate=%s\n可稍后重试；卡住时先停该进程再试", pid, form, spawnReadyTimeout, stateDir)
		}
	}
	return nil, controlDialErr(stateDir, sock, err)
}

// ensureRunning 拉起统一进程并等 control.sock 就绪（10s 上限）。
func ensureRunning(stateDir string, w io.Writer) error {
	// launchd 托管形态：先短轮询等 KeepAlive 重拉（r1 中-3；检测集合 = 模板 label ∪
	// 现役 me.zhaozhe.homeway-exit——或泛化为本机任意 homeway 代理 plist）。
	if la := detectLaunchdAgentFn(); la != "" {
		fmt.Fprintf(w, "守护进程未运行（launchd 代理 %s 在册）——等 KeepAlive 重拉…\n", la)
		if waitControlReady(stateDir, spawnKeepAliveWait) {
			return nil // KeepAlive 重拉到位，复用
		}
		fmt.Fprintf(w, "KeepAlive %v 内未重拉——改为自行拉起\n", spawnKeepAliveWait)
	}

	pid, err := spawnStartFn(stateDir)
	if err != nil {
		return fmt.Errorf("拉起统一进程失败：%w", err)
	}
	fmt.Fprintf(w, "守护进程未运行，已启动 pid=%d（state=%s）\n", pid, stateDir)

	// 有界轮询 control.sock 就绪。
	if !waitControlReady(stateDir, spawnReadyTimeout) {
		return fmt.Errorf("拉起的统一进程 %ds 内未就绪（control.sock 未出现/未可连）\n%s 尾部：\n%s\n完整日志：%s",
			int(spawnReadyTimeout.Seconds()), spawnLogName(stateDir), spawnLogTail(stateDir), spawnLogName(stateDir))
	}
	return nil
}

// startSpawnedProcess self-exec：同二进制 + --state 透传 + setsid + stdio →
// <state>/cache/spawn.log。返回子进程 pid（不 Wait——子进程由 init 收养）。
func startSpawnedProcess(stateDir string) (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, err
	}
	logPath := spawnLogName(stateDir)
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return 0, err
	}
	// 追加（多次拉起的失败原因累积可查；轮转交给人工——失败场景才有内容）。
	lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return 0, err
	}
	defer lf.Close()
	cmd := exec.Command(exe, "--state", stateDir)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, lf, lf
	cmd.SysProcAttr = spawnSysProcAttr() // 脱离会话：CLI 退出不带走它（平台拆分）
	fmt.Fprintf(lf, "---- spawn %s ----\n", time.Now().Format(time.RFC3339))
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	// 释放对子进程的引用（不 Wait；setsid 已脱离进程组，CLI 退出不波及）。
	go func() { _ = cmd.Wait() }() // 回收僵尸（子进程退出后的一瞬）
	return cmd.Process.Pid, nil
}

// notRunningDial 拨号失败是否可判「未运行」（r1 低-3）：ENOENT/ECONNREFUSED 族 +
// <state>/lock 的 flock 试探拿得到。
// notRunningFamily 未运行族拨号错误（ENOENT = socket 不存在 / ECONNREFUSED =
// 残留 socket 的监听者已消失）。
func notRunningFamily(dialErr error) bool {
	return errors.Is(dialErr, fs.ErrNotExist) || isConnRefused(dialErr)
}

func notRunningDial(dialErr error, stateDir string) bool {
	if !notRunningFamily(dialErr) {
		return false // 其它错误（超时/权限/协议）不按未运行处理
	}
	return !nodestate.LockHeld(stateDir)
}

// isConnRefused ECONNREFUSED 族判定（connect 到已消失的监听者）。
func isConnRefused(err error) bool {
	var oe *net.OpError
	if errors.As(err, &oe) {
		return errors.Is(oe.Err, syscall.ECONNREFUSED)
	}
	return errors.Is(err, syscall.ECONNREFUSED)
}

// waitControlReady 轮询 control.sock 可连（dial 成功即回 true 并关闭连接）。
func waitControlReady(stateDir string, d time.Duration) bool {
	sock := controlSockOf(stateDir)
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("unix", sock, 500*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return true
		}
		time.Sleep(spawnPollStep)
	}
	return false
}

// controlSockOf state 目录的 control.sock 路径。
func controlSockOf(stateDir string) string {
	return filepath.Join(stateDir, control.ControlSockName)
}

// spawnLogName 拉起子进程 stdio 落点（r1 低-2）。
func spawnLogName(stateDir string) string {
	return filepath.Join(stateDir, "cache", "spawn.log")
}

// spawnLogTail 就绪超时错误回显用：文件尾部若干行（读不到给占位说明）。
func spawnLogTail(stateDir string) string {
	b, err := os.ReadFile(spawnLogName(stateDir))
	if err != nil {
		return "（spawn.log 尚无内容/不可读）"
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > spawnLogTailLines {
		lines = lines[len(lines)-spawnLogTailLines:]
	}
	return strings.Join(lines, "\n")
}

// detectLaunchdAgent launchd 托管形态检测（r2 新-3）：检测集合 = LaunchAgents 目录
// 里任意 homeway 代理 plist（含模板 label me.zhaozhe.homeway-daemon 与现役
// me.zhaozhe.homeway-exit——按文件名泛化覆盖两者与未来改名）。命中返回 label；
// 无 = ""（Linux/未安装场景恒空——直接自 exec）。
func detectLaunchdAgent() string {
	if runtime.GOOS != "darwin" {
		return ""
	}
	dirs := launchAgentDirs()
	for _, d := range dirs {
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range ents {
			n := e.Name()
			if strings.Contains(n, "homeway") && strings.HasSuffix(n, ".plist") {
				return strings.TrimSuffix(n, ".plist")
			}
		}
	}
	return ""
}

// launchAgentDirs launchd 用户代理的候选目录（按存在性探测）。
func launchAgentDirs() []string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil
	}
	return []string{
		filepath.Join(home, "Library", "LaunchAgents"),
		"/Library/LaunchAgents",
	}
}
