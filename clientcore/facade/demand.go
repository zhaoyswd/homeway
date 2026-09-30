package facade

// demand.go — 桌面 DemandSignal（4a §6.2，D5）：三源保守或合成（任一源为真即
// 需求为真），经 hostsession Options.Demand 钩子接入巡检证据门（§6.1 桌面门）。
// 判定结果与依据 sticky 落 demand 观测面（daemon.status 的 demand 段——词表只增）。
//
// 三源（D5）：
//   ① 真实流量：本拍 WG 出站字节增量（StatsSnapshot.TxBytes 差分 > 0，采样窗 =
//      巡检拍——「用户在等数据」的本地证据，对端死时出站握手重试仍在涨，不会
//      误判无需求）或本拍内发生隧道拨号尝试（DialPort 计数；hostsession 内部的
//      healingDial 无导出缝、不进合成源——r2 新-18）；
//   ② 在场腿：经 DialPort 的活跃消费连接数 > 0（term 流/未来 files/forward 连接）；
//   ③ 订阅视图：控制面前端 events.subscribe 的 view 声明聚合到主机集合，该主机
//      在集合内（文法见 ParseView；空/未知保守忽略——不算需求也不报错）。
//
// reason 面板对齐手机 patrolDemand 的依据词（出站包/在场腿/订阅视图/无）。

import (
	"encoding/hex"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/hostsession"
)

// hostDemand 一台主机的需求合成状态（挂在表条目上，随条目生命周期）。
type hostDemand struct {
	// ① 采样状态（仅 evaluate 调用串行——hostsession 巡检拍每拍恰一次；读写无锁）。
	lastTx   int64
	sampled  bool
	dials    atomic.Int64 // 本拍拨号尝试（Host.DialPort 计数；evaluate Swap 清零）
	activeNx atomic.Int64 // 在场的 DialPort 消费连接数（countedConn 关闭时递减）

	// 最近一拍判定（sticky，daemon.status 面）。
	mu         sync.Mutex
	lastActive bool
	lastReason string
	lastAt     time.Time
}

// evaluate 一拍的需求合成（巡检拍调用；sess 为该主机当前会话，nil = 构造期失败
// 形态——流量源缺省、其余源照常）。
func (h *hostDemand) evaluate(sess *hostsession.Session, bus *Bus, id [32]byte) (bool, string) {
	// ① 流量源：TxBytes 差分（世代切换清零 → 负差按 0 处理）。
	tx := int64(0)
	if sess != nil {
		if snap := sess.StatusSnapshot(); snap.Stats != nil {
			tx = snap.Stats.TxBytes
		}
	}
	delta := int64(0)
	if h.sampled {
		delta = tx - h.lastTx
		if delta < 0 {
			delta = 0
		}
	}
	h.lastTx, h.sampled = tx, true
	switch {
	case h.dials.Swap(0) > 0:
		return h.record(true, "拨号尝试")
	case delta > 0:
		return h.record(true, "出站包")
	case h.activeNx.Load() > 0:
		return h.record(true, "在场腿")
	case bus.viewDemand(id):
		return h.record(true, "订阅视图")
	default:
		return h.record(false, "无")
	}
}

// record sticky 记录 + 返回。
func (h *hostDemand) record(active bool, reason string) (bool, string) {
	h.mu.Lock()
	h.lastActive, h.lastReason, h.lastAt = active, reason, time.Now()
	h.mu.Unlock()
	return active, reason
}

// brief 观测面快照（daemon.status 的 demand 段）。
func (h *hostDemand) brief(host string) HostDemandBrief {
	h.mu.Lock()
	defer h.mu.Unlock()
	at := int64(0)
	if !h.lastAt.IsZero() {
		at = h.lastAt.UnixMilli()
	}
	return HostDemandBrief{Host: host, Active: h.lastActive, Reason: h.lastReason, At: at}
}

// HostDemandBrief demand 观测面单条（进程内 DTO；wire 体映射在绑定层）。
type HostDemandBrief struct {
	Host   string
	Active bool
	Reason string
	At     int64 // UnixMilli，0 = 从未判定
}

// ParseView view 声明的机器可消费解析（D5 文法，只增不改：host=<id>[,host=<id>]*
// ——条目为 64 位 hex 的 peerID）。空串/未知格式/非法条目保守忽略（不算需求也
// 不报错——现无生产者，老前端空串不受影响）。
func ParseView(view string) [][32]byte {
	if view == "" {
		return nil
	}
	var out [][32]byte
	for _, ent := range strings.Split(view, ",") {
		ent = strings.TrimSpace(ent)
		const p = "host="
		if !strings.HasPrefix(ent, p) {
			continue
		}
		b, err := hex.DecodeString(strings.TrimPrefix(ent, p))
		if err != nil || len(b) != 32 {
			continue
		}
		var id [32]byte
		copy(id[:], b)
		out = append(out, id)
	}
	return out
}

// countedConn DialPort 消费连接的在场计数包装（Close 递减在场腿——term 流生命周期
// 必经 Close〔finish/teardown 统一 backend.Close〕；消费方不 Close 则保守多算一次
// 需求拍，无害）。
type countedConn struct {
	net.Conn
	onClose func()
}

func (c countedConn) Close() error {
	c.onClose()
	return c.Conn.Close()
}
