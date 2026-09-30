// speedrun.go — 守护侧测速运行面（forward-socks-speedtest 3e §2.4，D4）。
//
// per-host 单飞 + 守护托管：speedtest.start **立即返回 waiting 相位**、等待由 runner
// 状态机在 waitMs 预算内承载（默认 60s，覆盖恢复阶梯最坏 ≈45s；r1 中-3——长等待不
// 占用控制面请求）；引擎数据腿 = Host.DialPort(7803) 直连隧道（MUST NOT 经控制面流）。
//
// 注入缝错误契约（r1 高-2 / r2 新-4）：refused-like 判定与 code 生成归本 runner——
// 拨号错误按 wgnet.ErrRefused 哨兵分类产 DialError{not_supported}（D7①：出口无
// state 目录时 7803 不在 LocalServices、intercept 回 RST、连接未建立，MUST NOT 落进
// 「链路未就绪 = 等 waitMs」一支空烧预算）；会话不在/重建窗口 = link_down（waitMs
// 预算内保持 waiting 重试）。引擎只透传 code（pkg/speedtest 不反向依赖核内部件）。
package facade

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/zhaoyswd/homeway/pkg/speedtest"
	"github.com/zhaoyswd/homeway/pkg/wgnet"
)

// speedtestServicePort 出口测速服务端口（= internal/server.DefaultSpeedtestPort；
// 与手机壳 app_speedtest.go 的同名常量同源同值）。
const speedtestServicePort = 7803

// speedtest runner 节拍。
const (
	speedRetryInterval = 250 * time.Millisecond // link_down 重试节拍（与 CLI 轮询同拍）
)

// SpeedtestStart start 载荷（§3 绑定层做旗标→参数映射）。
type SpeedtestStart struct {
	Down, Up, Warmup time.Duration
	Streams          int
	WaitMs           int64 // 链路未就绪等待预算（0 = 不等，立即失败）
}

// SpeedtestStartAck start 的立即回执（waiting 相位或 busy——busy 是成功载荷里的
// reason，不占错误码表）。
type SpeedtestStartAck struct {
	Phase  string // waiting | busy
	Reason string // busy 时携带
	Listen uint16 // 无意义占位（对齐未来的 ack 面）——当前恒 0
}

// SpeedtestStatus status 面单条：waiting 相位或引擎快照。
type SpeedtestStatus struct {
	Host         string
	Waiting      bool
	WaitRemainMs int64 // waiting 剩余预算
	Snap         speedtest.Snapshot
}

// speedHostRun 一台主机的运行时。
type speedHostRun struct {
	engine    *speedtest.Engine
	cancel    context.CancelFunc
	waitUntil time.Time
	waiting   bool // start 已返回、引擎未真正开跑（link_down 重试窗）
	mu        sync.Mutex
}

func (r *speedHostRun) busy() bool {
	r.mu.Lock()
	w := r.waiting
	r.mu.Unlock()
	return w || r.engine.Running()
}

// SpeedtestManager 守护侧测速运行面（Carriers 持有；拨号缝 = carrierDial）。
type SpeedtestManager struct {
	mu   sync.Mutex
	runs map[string]*speedHostRun
	dial carrierDial
	logf func(format string, args ...any)
}

// newSpeedtestManager 建运行面。
func newSpeedtestManager(dial carrierDial, logf func(string, ...any)) *SpeedtestManager {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &SpeedtestManager{runs: map[string]*speedHostRun{}, dial: dial, logf: logf}
}

// Start 对一台主机开跑：per-host 单飞（busy = 成功载荷 reason，同手机信封形态）；
// 立即返回 waiting 相位，整轮在后台 goroutine 里跑。
func (m *SpeedtestManager) Start(host string, p SpeedtestStart) SpeedtestStartAck {
	m.mu.Lock()
	if r, ok := m.runs[host]; ok && r.busy() {
		m.mu.Unlock()
		return SpeedtestStartAck{Phase: "busy", Reason: speedtest.ReasonBusy}
	}
	engine := speedtest.NewEngine(m.logf)
	ctx, cancel := context.WithCancel(context.Background())
	r := &speedHostRun{engine: engine, cancel: cancel, waiting: true}
	if p.WaitMs > 0 {
		r.waitUntil = time.Now().Add(time.Duration(p.WaitMs) * time.Millisecond)
	} else {
		r.waitUntil = time.Now() // --wait 0 = 不等
	}
	m.runs[host] = r
	m.mu.Unlock()
	go m.runLoop(ctx, host, r, p)
	return SpeedtestStartAck{Phase: "waiting"}
}

// runLoop 整轮承载：link_down 在 waitMs 预算内保持 waiting 重试（恢复阶梯自愈后开跑）；
// 其余终态（含 not_supported——refused-like，MUST NOT 落等待支）立即收场。
func (m *SpeedtestManager) runLoop(ctx context.Context, host string, r *speedHostRun, p SpeedtestStart) {
	params := speedtest.Params{Down: p.Down, Up: p.Up, Warmup: p.Warmup, Streams: p.Streams}
	for {
		// 开跑即离开 waiting（Start 同步跑整轮，期间状态面由引擎快照承载）；
		// link_down 且预算未尽才回到 waiting 相位重试。
		r.setWaiting(false)
		res := r.engine.Start(ctx, m.dialFn(host), params)
		if res.OK || res.Reason != speedtest.ReasonLinkDown {
			return
		}
		if time.Now().After(r.waitUntil) {
			return // link_down 到点（预算耗尽，如实收场）
		}
		r.setWaiting(true)
		select {
		case <-ctx.Done():
			r.setWaiting(false)
			return
		case <-time.After(speedRetryInterval):
		}
	}
}

// dialFn 引擎拨号注入缝：Host.DialPort(7803) + refused-like 分类（r2 新-4——判定与
// code 生成归 runner）。
func (m *SpeedtestManager) dialFn(host string) speedtest.DialFunc {
	return func(ctx context.Context) (net.Conn, error) {
		conn, err := m.dial.dialPort(ctx, host, speedtestServicePort)
		if err != nil {
			switch {
			case ctx.Err() != nil:
				return nil, speedtest.DialErrf(speedtest.ReasonCancelled, "测速已取消")
			case errors.Is(err, ErrSessionNotCurrent):
				return nil, speedtest.DialErrf(speedtest.ReasonLinkDown, "链路未就绪（会话不在/重建窗口）：%v", err)
			case errors.Is(err, wgnet.ErrRefused):
				return nil, speedtest.DialErrf(speedtest.ReasonNotSupported, "出口没有测速服务（出口需升级）")
			default:
				return nil, speedtest.DialErrf(speedtest.ReasonLinkDown, "隧道拨号失败：%v", err)
			}
		}
		return conn, nil
	}
}

// Cancel 取消该主机当前轮（等待期与运行中都收；幂等）。
func (m *SpeedtestManager) Cancel(host string) {
	m.mu.Lock()
	r := m.runs[host]
	m.mu.Unlock()
	if r == nil {
		return
	}
	r.cancel()
	r.engine.CancelActive()
}

// Status 该主机的运行态（无运行面 = nil）。
func (m *SpeedtestManager) Status(host string) *SpeedtestStatus {
	m.mu.Lock()
	r := m.runs[host]
	m.mu.Unlock()
	if r == nil {
		return nil
	}
	r.mu.Lock()
	waiting, waitUntil := r.waiting, r.waitUntil
	r.mu.Unlock()
	if waiting {
		remain := int64(0)
		if d := time.Until(waitUntil); d > 0 {
			remain = d.Milliseconds()
		}
		return &SpeedtestStatus{Host: host, Waiting: true, WaitRemainMs: remain,
			Snap: speedtest.Snapshot{Phase: "waiting", ElapsedMs: -1}}
	}
	return &SpeedtestStatus{Host: host, Snap: r.engine.Snapshot()}
}

// RemoveHost 级联（host.remove）：取消该主机在跑的测速。
func (m *SpeedtestManager) RemoveHost(host string) {
	m.Cancel(host)
}

// Close 收工：取消全部在跑轮。
func (m *SpeedtestManager) Close() {
	m.mu.Lock()
	runs := make([]*speedHostRun, 0, len(m.runs))
	for _, r := range m.runs {
		runs = append(runs, r)
	}
	m.mu.Unlock()
	for _, r := range runs {
		r.cancel()
		r.engine.CancelActive()
	}
}

func (r *speedHostRun) setWaiting(v bool) {
	r.mu.Lock()
	r.waiting = v
	r.mu.Unlock()
}
