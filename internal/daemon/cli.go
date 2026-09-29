package daemon

// cli.go — homeway daemon [--state DIR]（host-registry-daemon 2.3 + §3.6 控制面
// 装配）：装配序（D4）：取锁 → OpenState → 读期望态（损坏按默认 + 告警不拒启）→
// client 角色挂注册表（角色子系统，2.4）→ 控制面（§3：internal/control——
// control.sock 0600、事件总线、流腿）→ 等信号收工。
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

	"github.com/zhaoyswd/homeway/clientcore/hostsession"
	"github.com/zhaoyswd/homeway/internal/control"
)

// CLI daemon 子命令入口（cmd/homeway 转发；version 随构建注入——welcome/
// daemon.status 的 serverVersion）。
//
// 子命令：status（4.1，控制面读面）、host（host-cli 3b：主机表管理命令面）；
// 其余参数 = 守护进程本体。
func CLI(args []string, version string) error {
	if len(args) > 0 && args[0] == "status" {
		return statusCLI(args[1:], version, os.Stdout)
	}
	if len(args) > 0 && args[0] == "host" {
		return hostCLI(args[1:], version, os.Stdout)
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
		return fmt.Errorf("daemon 不接受位置参数 %q（子命令：status / host；启动守护进程 = 无子命令）", fs.Args())
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

	// ③ 期望态（损坏按默认 + 告警不拒启，HD「角色期望态」）。
	desired := loadDesiredState(*stateDir, st.Eventf)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ④ 角色子系统：本期仅 client（注册表按 hosts.json 逐后端拉会话）；注册表
	// 经 holder 与控制面共享（角色重建时换实例，重建窗口 = not_ready）。总线
	// 先建（holder 引用；代际每次启动随机）。
	bus := control.NewBus(control.NewGeneration(), control.BusConfig{})
	holder := newRegistryHolder(bus)
	sup := newSupervisor(st.Eventf, st.Debugf)
	if desired.roleEnabled("client") {
		sup.Start(ctx, func() Role { return newClientRole(*stateDir, st, holder) }, nil)
	} else {
		st.Eventf("daemon: client 角色未启用（roles.json）——控制面只读骨架")
	}

	// ⑤ 控制面（§3）：server（control.sock 0600；监听失败 = 报错退出——控制面
	// 是 daemon 的用户面，静默缺失无从排查）。
	srv, stopControl, err := startControlPlane(version, *stateDir, sup, holder, bus, st.Eventf)
	if err != nil {
		cancel()
		return err
	}
	defer stopControl()
	_ = srv // srv 生命周期由 stopControl 收口（引用保留供后续扩展）

	st.Eventf("daemon: 就绪（state=%s，client=%v，version=%s）", *stateDir, desired.roleEnabled("client"), version)

	// ⑥ 等信号收工。
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	got := <-sig
	st.Eventf("daemon: 收到 %v，收工", got)
	cancel()
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

// clientRole client 角色：多主机会话注册表的宿主（失败由 supervisor 退避重建——
// 重建时重新 OpenRegistry，按 hosts.json 恢复会话；Registry 事件接进控制面总线）。
type clientRole struct {
	stateDir string
	st       *DaemonState
	holder   *registryHolder
}

func newClientRole(stateDir string, st *DaemonState, holder *registryHolder) *clientRole {
	return &clientRole{stateDir: stateDir, st: st, holder: holder}
}

func (r *clientRole) Name() string { return "client" }

func (r *clientRole) Run(ctx context.Context) error {
	// 事件接线：Registry 事件 → 控制面总线 session 域（bus 随进程唯一；角色重建
	// 换 Registry 实例、总线与代际不变）。
	reg, err := OpenRegistry(r.stateDir, RegistryOptions{
		StrictIdentity: true, // daemon = 严格身份（D2/N2）
		Logf:           hostsession.Logf(r.st.Debugf),
		Eventf:         r.st.Eventf, // hosts.json 损坏备份等用户应见异常 → events.log
		Events:         &registryEventsAdaptor{bus: r.holder.bus()},
	})
	if err != nil {
		return err // 角色失败 → 退避重建
	}
	r.holder.set(reg)
	defer func() {
		r.holder.set(nil)
		reg.Close()
	}()
	r.st.Eventf("client: 注册表就绪（主机 %d 台，state=%s）", len(reg.Hosts()), r.stateDir)
	<-ctx.Done()
	return ctx.Err() // ctx 取消族 = 正常收工
}
