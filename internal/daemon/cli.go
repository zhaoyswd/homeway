package daemon

// cli.go — homeway daemon [--state DIR]（host-registry-daemon 2.3 + §3.6 控制面
// 装配）：装配序（D4）：取锁 → OpenState → 读期望态（损坏按默认 + 告警不拒启）→
// client 角色挂注册表（角色子系统，2.4）→ 控制面（§3：internal/control——
// control.sock 0600、事件总线、流腿）→ 等信号收工。
//
// ⚠️ 与出口禁止同 state 目录（D2 组合处置）：锁文件内容与失败文案带角色名可辨；
// 安装说明（4.2）明示 `homeway exit --state X` 与 `homeway daemon --state X` 并存
// 未定义（3f 合并前两角色 state 语义不同）。

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/zhaoyswd/homeway/clientcore/hostsession"
	"github.com/zhaoyswd/homeway/internal/control"
)

// CLI daemon 子命令入口（cmd/homeway 转发；version 随构建注入——welcome/
// daemon.status 的 serverVersion）。
//
// 子命令：status（4.1，控制面读面的 CLI 消费）；其余参数 = 守护进程本体。
func CLI(args []string, version string) error {
	if len(args) > 0 && args[0] == "status" {
		return statusCLI(args[1:], version, os.Stdout)
	}
	fs := flag.NewFlagSet("homeway daemon", flag.ContinueOnError)
	stateDir := fs.String("state", DefaultStateDir(), "state 目录（单实例锁/主机表/身份/日志）")
	if err := fs.Parse(args); err != nil {
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
