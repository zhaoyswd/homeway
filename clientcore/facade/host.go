package facade

// host.go — 每主机 Host 对象（D1，任务 3.3）：状态快照 + 操作（重建感知隧道拨号
// DialPort——ErrSessionNotCurrent 的 facade 哨兵见 vocab.go）+ 登记面；移除在
// Daemon 面（Host 无 Remove）。进程面 DTO（HostBrief/HostState/HostReach 等）
// 定义于此——wire 体留 internal/control（传输段），绑定层做字段映射。

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/zhaoyswd/homeway/clientcore/hostsession"
)

// ---------- 进程面 DTO（wire 体镜像；绑定层映射） ----------

// HostBrief 主机静态信息（登记面，无会话动态）。
type HostBrief struct {
	ID      string
	Name    string
	AddedAt int64 // UnixMilli
}

// HostState 一台主机的动态面（state/reason/link/stats + 登记面添加时间）。
type HostState struct {
	ID      string
	Name    string
	State   string
	Reason  string
	Link    *HostLink
	Stats   *HostRxTx
	AddedAt int64 // UnixMilli
}

// HostLink 链路态（via/ep/rttMs/at）。
type HostLink struct {
	Via   string
	Ep    string
	RttMs int64
	At    int64
}

// HostRxTx 流量面。
type HostRxTx struct {
	RxBytes int64
	TxBytes int64
}

// HostReach host.add 成功结果的验证结论（tier=none 不出现在成功结果——全不可达
// 用 ErrHostUnreachable 表达，不入表）。
type HostReach struct {
	Tier   string
	BestEp string
	RttMs  int64
	Tested []ReachTested // 逐端点实测集（恒非 nil；skipped = 空数组）
}

// ReachTested tested[] 单端点结论（只含应答端点）。
type ReachTested struct {
	Ep    string
	Relay bool
	RttMs int64
}

// HostAddResult host.add 的进程内结果。
type HostAddResult struct {
	ID      string
	Name    string
	AddedAt int64 // UnixMilli
	Reach   *HostReach
}

// ---------- Host 对象 ----------

// Host 表内一台主机的进程内面（D1）：快照拷贝自表条目（登记 + 会话引用）——表
// Detach/重挂后旧 Host 对象的拨号按 ErrSessionNotCurrent/ErrNoHost 收口，消费方
// 经 Daemon.Host 重新取（重连三层口径：视图重连 = 前端薄 resubscribe/重取）。
type Host struct {
	rec  HostRecord
	sess *hostsession.Session
	// dm 需求合成状态（§6.2：拨号尝试/在场腿计数落点——DialPort 计数入 demand 源）。
	dm *hostDemand
}

// Record 登记面（含 carried 不在此面——寻址面不含 carried 的既有口径不变）。
func (h *Host) Record() HostRecord { return h.rec }

// Snapshot 一台主机的动态面快照（= HostStates 单条）。
func (h *Host) Snapshot() HostState { return hostStateOf(h.rec, h.sess) }

// dialPort 拨号注入缝（生产 = Session.DialPort；同包测试注入三态桩——正常/
// 重建窗口/会话构造失败）。
var dialPort = func(s *hostsession.Session, ctx context.Context, port uint16) (net.Conn, error) {
	return s.DialPort(ctx, port)
}

// dialAddr 任意目标拨号注入缝（3e §2.1，D5；生产 = Session.DialAddr——与 dialPort
// 同 healing 路径，测试注入桩同形状）。
var dialAddr = func(s *hostsession.Session, ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return s.DialAddr(ctx, dst)
}

// DialPort 重建感知的隧道端口拨号（hostsession D1 导出面）：会话不在（收工/
// 重建窗口）→ ErrSessionNotCurrent（facade 哨兵，vocab.go）；登记在册但会话
// 对象不在（构造期失败）→ ErrNoHost（绑定点沿 no_host 族映射——保持既有 wire
// 行为）。§6.2：拨号尝试与在场连接计入该主机的需求合成（DemandSignal 源①②）。
func (h *Host) DialPort(ctx context.Context, port uint16) (net.Conn, error) {
	if h.sess == nil {
		return nil, ErrNoHost
	}
	if h.dm != nil {
		h.dm.dials.Add(1) // 源①：本拍拨号尝试
	}
	conn, err := dialPort(h.sess, ctx, port)
	if err != nil {
		if errors.Is(err, hostsession.ErrSessionNotCurrent) {
			return nil, ErrSessionNotCurrent
		}
		return nil, err
	}
	if h.dm != nil {
		h.dm.activeNx.Add(1) // 源②：在场腿（连接关闭时递减——countedConn；Close 幂等）
		return &countedConn{Conn: conn, dm: h.dm, onClose: func() { h.dm.activeNx.Add(-1) }}, nil
	}
	return conn, nil
}

// Dial 任意目标拨号缝（3e §2.1，D5）：与 DialPort 同 healing 路径、同 demand 记账
// （源① 拨号尝试 + 源② 在场腿 countedConn）、同重建窗口语义——消费方 = forward 的
// 任意 IP 目标与 socks 承载面（出口可达目标）；DialPort 仍是出口服务端口的
// 文档主缝（term/files/speedtest 经 UDS 映射、5300 = 隧道内解析腿，既有消费者零改动）。
func (h *Host) Dial(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if h.sess == nil {
		return nil, ErrNoHost
	}
	if h.dm != nil {
		h.dm.dials.Add(1) // 源①：本拍拨号尝试
	}
	conn, err := dialAddr(h.sess, ctx, dst)
	if err != nil {
		if errors.Is(err, hostsession.ErrSessionNotCurrent) {
			return nil, ErrSessionNotCurrent
		}
		return nil, err
	}
	if h.dm != nil {
		h.dm.activeNx.Add(1) // 源②：在场腿（连接关闭时递减——countedConn；Close 幂等）
		return &countedConn{Conn: conn, dm: h.dm, onClose: func() { h.dm.activeNx.Add(-1) }}, nil
	}
	return conn, nil
}

// hostStateOf 一台主机的动态面（锁外：rec/sess 为锁内拷贝；会话快照自持锁仅
// 本会话——锁序路径②）。
func hostStateOf(rec HostRecord, sess *hostsession.Session) HostState {
	hs := HostState{ID: rec.ID, Name: rec.Name, AddedAt: rec.AddedAt.UnixMilli()}
	if sess == nil {
		hs.State = "failed"
		hs.Reason = "session_not_built" // 构造期失败（如日志文件打不开）的登记面可见性
		return hs
	}
	snap := sess.StatusSnapshot()
	hs.State = snap.State
	hs.Reason = snap.Reason
	if snap.Link != nil {
		hs.Link = &HostLink{Via: snap.Link.Via, Ep: snap.Link.Ep, RttMs: snap.Link.RttMs, At: snap.Link.At}
	}
	if snap.Stats != nil {
		hs.Stats = &HostRxTx{RxBytes: snap.Stats.RxBytes, TxBytes: snap.Stats.TxBytes}
	}
	return hs
}
