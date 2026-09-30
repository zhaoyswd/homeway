package daemon

// cli.go — homeway daemon [--state DIR]（host-registry-daemon 2.3 + §3.6 控制面
// 装配；§4 收拢后经 facade 单入口）：装配序（D4）：取锁 → OpenState → 读期望态
// （损坏按默认 + 告警不拒启）→ 进程级 facade.Daemon（总线/代际/词汇随进程唯一）
// + client 角色挂主机表（Attach/Detach，角色子系统）→ 控制面（§3：
// internal/control——control.sock 0600、事件总线、流腿）→ 等信号收工。
//
// ⚠️ 与出口禁止同 state 目录（D2 组合处置）：daemon 侧硬拦（checkNotExitState——
// state 下有 tokens.jsonl 即拒启）；exit/relay 侧不检测（锁只约束 daemon），方向上
// 仍靠安装说明（4.2）提示，角色/state 合并归 3f。

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/zhaoyswd/homeway/clientcore/facade"
	"github.com/zhaoyswd/homeway/pkg/probe"
)

// CLI daemon 子命令入口（cmd/homeway 转发；version 随构建注入——welcome/
// daemon.status 的 serverVersion）。
//
// 子命令：status（4.1，控制面读面）、host（host-cli 3b：主机表管理命令面）、
// forward/socks/speedtest（3e：承载面三命令面，守护托管）；其余参数 = 守护进程本体。
func CLI(args []string, version string) error {
	if len(args) > 0 && args[0] == "status" {
		return statusCLI(args[1:], version, os.Stdout)
	}
	if len(args) > 0 && args[0] == "host" {
		return hostCLI(args[1:], version, os.Stdout)
	}
	if len(args) > 0 && args[0] == "forward" {
		return forwardCLI(args[1:], version, os.Stdout)
	}
	if len(args) > 0 && args[0] == "socks" {
		return socksCLI(args[1:], version, os.Stdout)
	}
	if len(args) > 0 && args[0] == "speedtest" {
		return speedtestCLI(args[1:], version, os.Stdout, os.Stderr)
	}
	fs := flag.NewFlagSet("homeway daemon", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	stateDir := fs.String("state", DefaultStateDir(), "state 目录（单实例锁/主机表/身份/日志）")
	if err := fs.Parse(args); err != nil {
		// B15（host-cli 3b）：--help 正常化（此前 flag: help requested + exit 1）
		// ——与 status_cli.go 同款 ErrHelp→nil 姿势，usage 已由 flag 集打印。
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	// B15：flag 解析后的意外位置参数报错（此前 `homeway daemon --state X status`
	// 静默吞掉 status 起守护进程）。
	if fs.NArg() > 0 {
		return fmt.Errorf("daemon 不接受位置参数 %q（子命令：status / host / forward / socks / speedtest；启动守护进程 = 无子命令）", fs.Args())
	}

	// ⓪ 与出口/中继禁止同 state 目录（硬拦，见 checkNotExitState）。
	if err := checkNotExitState(*stateDir); err != nil {
		return err
	}

	// ① 单实例锁（装配最早处：先于任何 socket/会话）。
	lock, err := AcquireInstanceLock(*stateDir, "daemon")
	if err != nil {
		return err
	}
	defer lock.Release()

	// ② state 布局（0700/0600 + 两级轮转日志）。
	st, err := OpenDaemonState(*stateDir)
	if err != nil {
		return fmt.Errorf("打开 state %s：%w", *stateDir, err)
	}
	defer st.Close()

	// ③ 期望态（损坏按默认 + 告警不拒启，HD「角色期望态」——client/control
	// 未登记均默认 on，v1 兼容，r2 新-2）。
	desired := loadDesiredState(*stateDir, st.Eventf)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ④ 进程级 facade.Daemon（总线/代际/词汇随进程唯一——角色重建不换不换代际，
	// r1 高-2）+ 角色子系统（client = 主机表宿主：Attach → 等 ctx → Detach；
	// 注册表语义与 host.add 服务端验证全在 facade）。
	d := facade.New(facade.Options{
		StrictIdentity: true, // daemon = 严格身份（D2/N2）
		Logf:           st.Debugf,
		Eventf:         st.Eventf,
		Probe:          probe.Reach, // 生产探测核透传（与手机 App 同源；daemon 侧测试注入假探测经此缝）
	})
	defer d.Close() // Close 唯一调用点 = 进程收工（先 Detach 再总线收尾，r2 新-15）
	sup := newSupervisor(st.Eventf, st.Debugf)
	if desired.roleEnabled("client") {
		sup.Start(ctx, func() Role { return newClientRole(*stateDir, st, d) }, nil)
	} else {
		st.Eventf("daemon: client 角色未启用（roles.json）——控制面只读骨架")
	}

	// ⑤ 控制面（§5.2 control 角色）：装配期 Listen fail-fast 保留（监听失败 =
	// 报错退出），listener/server 注入 control 角色交 supervisor 托管——瞬态
	// accept 错误 Serve 内退避重试、永久错误角色退避重建（重新 Listen+Serve）。
	// 未登记角色默认 on（v1 兼容，r2 新-2）：仅含 client 的既有 roles.json
	// 升级后 control 自动在位；显式 enabled:false 才关（无控制面 = CLI 不可达）。
	if desired.roleEnabled("control") {
		if err := startControlPlane(ctx, version, *stateDir, sup, d, st.Eventf); err != nil {
			cancel()
			return err
		}
	} else {
		st.Eventf("daemon: control 角色未启用（roles.json）——无控制面（CLI 将不可达）")
	}

	st.Eventf("daemon: 就绪（state=%s，client=%v，control=%v，version=%s）",
		*stateDir, desired.roleEnabled("client"), desired.roleEnabled("control"), version)

	// ⑥ 等信号收工。
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	got := <-sig
	st.Eventf("daemon: 收到 %v，收工", got)
	cancel()
	// 等角色循环退出（control：连接收尾 goodbye(shutting_down)；client：Detach
	// 落盘）再走 defer 面（d.Close/st.Close）——顺序即「进程退出前 state 已落盘」。
	sup.Close()
	return nil
}

// checkNotExitState 拒绝把 daemon 指到出口/中继的 state 目录（硬拦，exec-r1 B11：
// 此前只有安装文档的「单实例锁会互相拒绝」提示——而 exit/relay 根本不取 daemon 的
// 锁，真把 daemon 指到在役出口 state 会正常启动并与其共写 events/debug 日志
// （各自 rename 轮转互踩）与 identity 目录）。判据 = state 下存在 tokens.jsonl
// （出口身份特征：签发审计 + 启动加载，D7；daemon 永不写这个文件）。
func checkNotExitState(stateDir string) error {
	if _, err := os.Stat(filepath.Join(stateDir, "tokens.jsonl")); err == nil {
		return fmt.Errorf("state %s 含 tokens.jsonl（出口身份特征）——daemon 禁止与 exit/relay 同 state 目录（共写日志与 identity 目录会互踩；请为 daemon 用独立 --state 目录）", stateDir)
	}
	return nil
}

// clientRole client 角色：主机表的生命周期宿主（r1 高-2 两层拆分——角色级
// Attach/Detach）：attach → 等待 ctx → detach；失败/panic 由 supervisor 退避
// 重建 = 重新 attach（重建窗口 = NotReady；总线与代际随进程唯一不变）。
type clientRole struct {
	stateDir string
	st       *DaemonState
	d        *facade.Daemon
}

func newClientRole(stateDir string, st *DaemonState, d *facade.Daemon) *clientRole {
	return &clientRole{stateDir: stateDir, st: st, d: d}
}

func (r *clientRole) Name() string { return "client" }

func (r *clientRole) Run(ctx context.Context) error {
	if err := r.d.Attach(r.stateDir); err != nil {
		return err // 角色失败 → 退避重建（重新 attach）
	}
	defer r.d.Detach()
	r.st.Eventf("client: 注册表就绪（主机 %d 台，state=%s）", len(r.d.HostBriefs()), r.stateDir)
	<-ctx.Done()
	return ctx.Err() // ctx 取消族 = 正常收工
}
