package facade

// daemon.go — 进程级 Daemon 骨架（D1 两层拆分，任务 1.3）。生命周期两层：
//   - Daemon（本文件）：总线 + 代际 + 词汇 + 需求/诊因接线，**进程级**创建一次——
//     角色重建不换总线、不换代际（「总线与代际随进程唯一不变」的既有承诺，
//     CP spec「代际 = 每次守护进程启动生成」不被角色重建破坏）；
//   - 主机表：角色级 Attach(stateDir)/Detach()（§3 落地——table.go）。stateDir
//     单一来源：只经 Attach 携带，Options 不设 stateDir 字段（两处携带必漂移）。
//
// 本批为骨架：New 已装配总线与代际（= 现 internal/daemon/cli.go 的进程级
// NewBus(NewGeneration()) 装配迁入）；Attach/Detach 为空实现占位（主机表语义
// §3 整体迁入）。internal/daemon 暂不接线（§4 收拢批一起切）。

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/zhaoyswd/homeway/pkg/probe"
)

// Options facade 装配项（daemon 装配时透传；测试注入缝同源）。
type Options struct {
	// StrictIdentity 严格身份校验（表语义，§3：hosts.json 与会话身份一致性）。
	StrictIdentity bool
	// Logf 常规日志（nil = 丢弃）。Eventf 事件面日志（nil = 同 Logf）。
	Logf   func(format string, args ...any)
	Eventf func(format string, args ...any)
	// Probe host.add 服务端有界探测注入缝（导出——daemon 装配透传
	// pkg/probe.Reach，daemon 侧测试注入假探测的注入点随迁，r1 低-10）。
	Probe func(ctx context.Context, token string) (*probe.ReachReport, error)
}

// Daemon 进程级 facade 对象：总线、代际、词汇接线都在这一层。
type Daemon struct {
	opts Options
	bus  *Bus
	gen  string

	// 主机表（角色级，§3 落地）：当前 attach 的表（hosts.json + 每记录自持）。
	// 未 attach / 重建窗口 = NotReady（绑定层委托）。
}

// New 建进程级 Daemon：总线 + 代际（每次进程启动生成一次，Bus 与绑定层共用）。
func New(opts Options) *Daemon {
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if opts.Eventf == nil {
		opts.Eventf = opts.Logf
	}
	gen := NewGeneration()
	return &Daemon{opts: opts, bus: NewBus(gen, BusConfig{}), gen: gen}
}

// Bus 进程级事件总线（角色重建不换）。
func (d *Daemon) Bus() *Bus { return d.bus }

// Generation 当前代际（角色重建不变）。
func (d *Daemon) Generation() string { return d.gen }

// NewGeneration 生成新代际（16 字节随机 hex）。与 internal/control 的同名函数
// 同式（传输层 Server 侧另有一份——§4 收拢后装配统一走 facade，届时归一）。
func NewGeneration() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand 在真实平台不会失败；退化用时间熵兜底（仅可测性路径）。
		now := time.Now().UnixNano()
		for i := range b {
			b[i] = byte(now >> (uint(i%8) * 8))
		}
	}
	return hex.EncodeToString(b[:])
}

// Attach 挂载角色级主机表（读 stateDir/hosts.json、按表起会话——语义 = 现daemon
// 侧 OpenRegistry，§3 整体迁入）。**占位实现（本批）**：主机表未落地，返回 nil
// 且不持有任何状态；§3 落地后契约三句生效（二次 Attach 幂等 = 先 Detach 再按新
// stateDir 重挂 / 半途失败 = 已起会话全 Stop、表回未 attach 态再返回错误 /
// Detach 逐台 session.removed 照发总线——r2 新-15）。
func (d *Daemon) Attach(stateDir string) error {
	_ = stateDir
	return nil
}

// Detach 收工当前主机表（= 现 Registry.Close；未 attach = 无操作）。占位（§3）。
func (d *Daemon) Detach() {}

// Close 进程收工：先 Detach 再总线收尾（保「进程退出前 state 已落盘」）。
// 唯一调用点 = daemon 进程收工路径（cli.go 主流程 defer，§4 接线）；总线当前
// 无收尾面（进程内对象随进程消亡），占位即 Detach。
func (d *Daemon) Close() { d.Detach() }

// Host 表内一台主机的进程内面（D1）：状态快照 + 操作（重建感知隧道拨号
// DialPort——ErrSessionNotCurrent 哨兵见 vocab.go）+ 事件订阅（经进程级总线按
// 主机过滤）；移除在 Daemon 面，Host 无 Remove（r1 低-4 统一口径）。
// **骨架占位（本批）**：字段与方法随 §3（table.go/host.go）落地。
type Host struct {
	id [32]byte
}
