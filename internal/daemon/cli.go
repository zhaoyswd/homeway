package daemon

// cli.go — client 角色宿主（role-management 3.4 起：`homeway daemon` 命令面已删除
// ——status 由聚合 `homeway status`（status_cli.go）承载、host/forward/socks/
// speedtest 由 cmd/homeway 以顶层名词直连各 CLI；旧名词的迁移提示在 cmd/homeway。
// 本文件只剩 client 角色本体（原守护域分发面退役）。

import (
	"context"

	"github.com/zhaoyswd/homeway/clientcore/facade"
)

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
