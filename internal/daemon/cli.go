package daemon

// cli.go — homeway daemon [--state DIR]（host-registry-daemon 2.3）：装配序
// （D4）：取锁 → OpenState → 读期望态（损坏按默认 + 告警不拒启）→ client 角色挂
// 注册表（角色子系统，2.4）→ 控制面占位（§3 落地）→ 等信号收工。
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
)

// CLI daemon 子命令入口（cmd/homeway 转发）。
func CLI(args []string) error {
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

	// ④ 角色子系统：本期仅 client（注册表按 hosts.json 逐后端拉会话）。
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sup := newSupervisor(st.Eventf, st.Debugf)
	if desired.roleEnabled("client") {
		sup.Start(ctx, func() Role { return newClientRole(*stateDir, st) }, nil)
	} else {
		st.Eventf("daemon: client 角色未启用（roles.json）——空转等信号")
	}

	// ⑤ 控制面占位（§3：internal/control 落地后在此装配 server；本期不监听任何
	// socket——守护进程无端口竞争面）。
	st.Eventf("daemon: 就绪（state=%s，client=%v，控制面占位待 §3）", *stateDir, desired.roleEnabled("client"))

	// ⑥ 等信号收工。
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	got := <-sig
	st.Eventf("daemon: 收到 %v，收工", got)
	cancel()
	return nil
}

// clientRole client 角色：多主机会话注册表的宿主（失败由 supervisor 退避重建——
// 重建时重新 OpenRegistry，按 hosts.json 恢复会话）。
type clientRole struct {
	stateDir string
	st       *DaemonState
}

func newClientRole(stateDir string, st *DaemonState) *clientRole {
	return &clientRole{stateDir: stateDir, st: st}
}

func (r *clientRole) Name() string { return "client" }

func (r *clientRole) Run(ctx context.Context) error {
	reg, err := OpenRegistry(r.stateDir, RegistryOptions{
		StrictIdentity: true, // daemon = 严格身份（D2/N2）
		Logf:           hostsession.Logf(r.st.Debugf),
	})
	if err != nil {
		return err // 角色失败 → 退避重建
	}
	defer reg.Close()
	r.st.Eventf("client: 注册表就绪（主机 %d 台，state=%s）", len(reg.Hosts()), r.stateDir)
	<-ctx.Done()
	return ctx.Err() // ctx 取消族 = 正常收工
}
