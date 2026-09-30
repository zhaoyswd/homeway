package facade

// daemon.go — 进程级 Daemon（D1 两层拆分）。生命周期两层：
//   - Daemon（本文件）：总线 + 代际 + 词汇 + 需求/诊因接线，**进程级**创建一次——
//     角色重建不换总线、不换代际（「总线与代际随进程唯一不变」的既有承诺，
//     CP spec「代际 = 每次守护进程启动生成」不被角色重建破坏）；
//   - 主机表：角色级 Attach(stateDir)/Detach()（table.go）。stateDir 单一来源：
//     只经 Attach 携带，Options 不设 stateDir 字段（两处携带必漂移）。
//
// Close 唯一调用点 = daemon 进程收工路径（cli.go 主流程 defer：先 Detach 再总线
// 收尾，保「进程退出前 state 已落盘」；facade 内部无其它调用方——不是公共 API 面）。

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/zhaoyswd/homeway/pkg/probe"
)

// Options facade 装配项（daemon 装配时透传；测试注入缝同源）。
type Options struct {
	// StrictIdentity 严格身份校验（表语义：hosts.json 与会话身份一致性）。
	StrictIdentity bool
	// Logf 常规日志（nil = 丢弃）。Eventf 事件面日志（nil = 同 Logf）。
	Logf   func(format string, args ...any)
	Eventf func(format string, args ...any)
	// Probe host.add 服务端有界探测注入缝（导出——daemon 装配透传
	// pkg/probe.Reach，daemon 侧测试注入假探测的注入点，r1 低-10；nil =
	// pkg/probe.Reach）。
	Probe func(ctx context.Context, token string) (*probe.ReachReport, error)
}

// Daemon 进程级 facade 对象：总线、代际、词汇接线都在这一层；主机表（角色级，
// table.go）为当前 attach 的表指针（nil = 未 attach / 重建窗口 = NotReady，绑定
// 层委托）。
type Daemon struct {
	opts Options
	bus  *Bus
	gen  string

	mu    sync.Mutex
	table *hostTable
	// attachMu Attach/Detach 串行化（低-2：导出 API 防并发——两个并发 Attach 互相
	// 覆盖时输者的表不会被 Close〔会话不 Stop、无 session.removed〕且同 stateDir 下
	// 互踩 hosts.json.tmp；当前装配不可达〔client 角色单 goroutine〕，导出面自守）。
	// 锁序单向：attachMu → d.mu / 表锁，反向不存在（tableRef 等只碰 d.mu）。
	attachMu sync.Mutex
}

// New 建进程级 Daemon：总线 + 代际（每次进程启动生成一次，Bus 与绑定层共用）。
func New(opts Options) *Daemon {
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if opts.Eventf == nil {
		opts.Eventf = opts.Logf
	}
	if opts.Probe == nil {
		opts.Probe = probe.Reach
	}
	gen := NewGeneration()
	return &Daemon{opts: opts, bus: NewBus(gen, BusConfig{}), gen: gen}
}

// Bus 进程级事件总线（角色重建不换）。
func (d *Daemon) Bus() *Bus { return d.bus }

// Generation 当前代际（角色重建不变）。
func (d *Daemon) Generation() string { return d.gen }

// NewGeneration 生成新代际（16 字节随机 hex）——全仓唯一定义（原 internal/control
// 侧同式副本已随 §4 收拢删除，装配与测试统一走 facade）。
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

// Close 进程收工：先 Detach 再总线收尾（保「进程退出前 state 已落盘」）；总线
// 当前无收尾面（进程内对象随进程消亡），即 Detach。
func (d *Daemon) Close() { d.Detach() }

// sessionHooks 每主机会话的 Demand/Diag 钩子装配（§6.2/§6.3，D5/D6）：
//   - Demand = hostDemand.evaluate（三源合成：用户连接出站增量/拨号尝试/在场腿/
//     订阅视图——字节源在 countedConn 记账面、不读会话对象〔exec-r1 中-2〕，
//     重建换会话计数天然延续）；
//   - Diag = 发 session.diag 到进程级总线（gated/budget/probe_window——边沿与
//     单飞在 hostsession 侧；词表/载荷同源 vocab.go）。
func (d *Daemon) sessionHooks(rec HostRecord, e *hostEntry) (demand func() (bool, string), diag func(reason string)) {
	var pid [32]byte
	if b, err := hex.DecodeString(rec.ID); err == nil && len(b) == 32 {
		copy(pid[:], b)
	}
	bus, dm, id := d.bus, e.dm, rec.ID
	demand = func() (bool, string) {
		return dm.evaluate(bus, pid)
	}
	diag = func(reason string) {
		_, _ = bus.Publish(DomainSession, KindSessionDiag, SessionDiagPayload{Host: id, Reason: reason})
	}
	return demand, diag
}

// DemandStatus demand 观测面（§6.2：daemon.status 的 demand 段——各主机最近一拍
// 判定；未 attach = nil）。
func (d *Daemon) DemandStatus() []HostDemandBrief {
	tbl := d.tableRef()
	if tbl == nil {
		return nil
	}
	return tbl.demandBriefs()
}
