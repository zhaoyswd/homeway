package daemon

// cli.go — 守护域命令的分发面（role-management 2.3 起：`homeway daemon` 本体已随
// 统一进程退役——进程入口 = `homeway` 零参，见 unified.go；本文件只保留经
// cmd/homeway 转发的客户端域子命令：status / host / forward / socks / speedtest。
// `homeway daemon` 裸调与 `exit` 同款迁移提示（非零码））。

import (
	"context"
	"fmt"
	"os"

	"github.com/zhaoyswd/homeway/clientcore/facade"
)

// CLI daemon 域子命令入口（cmd/homeway 转发；version 随构建注入）。
func CLI(args []string, version string) error {
	if len(args) > 0 {
		switch args[0] {
		case "status":
			return statusCLI(args[1:], version, os.Stdout)
		case "host":
			return hostCLI(args[1:], version, os.Stdout)
		case "forward":
			return forwardCLI(args[1:], version, os.Stdout)
		case "socks":
			return socksCLI(args[1:], version, os.Stdout)
		case "speedtest":
			return speedtestCLI(args[1:], version, os.Stdout, os.Stderr)
		}
	}
	// 裸 `homeway daemon`：旧守护进程形态已并入统一进程（role-management D1）。
	return fmt.Errorf("homeway daemon 已并入统一进程——直接 `homeway`（零参前台；按 config 期望态装配全部角色）；状态看 `homeway daemon status`（随后版本将平移为 `homeway status`）")
}

// clientRole client 角色：主机表的生命周期宿主（r1 高-2 两层拆分——角色级
// Attach/Detach）：attach → 等待 ctx → detach；失败/panic 由 supervisor 退避
// 重建 = 重新 attach（重建窗口 = NotReady；总线与代际随进程唯一不变）。
// stateDir = 统一 state 的 client/ 子目录（L2，D3 拆分表；hosts/身份/承载面状态都在这）。
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
