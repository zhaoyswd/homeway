package intercept

import "sync/atomic"

// Stats：转发面计数器（拦截层是唯一生产写入方）。
//
// 历史注记：这个类型原来住在 pkg/flows（旧栈「每流一协议」时代的共享计数器），
// flows 兼容监听退役（openspec flows-compat-remove）后随包消亡，类型平移到本包——
// 计数键名（dialok/dialfail/flows/rejected）是观测面契约，测试与诊断都在用，不改名。
type Stats struct {
	dialOK, dialFail, flows, rejected uint64
	udpReplied, udpNoReply            uint64 // 转发出去的 UDP 会话：收到过回包 / 只有上行（实测 UDP 可用性）
}

func (s *Stats) IncrOK()   { atomic.AddUint64(&s.dialOK, 1) }
func (s *Stats) IncrFail() { atomic.AddUint64(&s.dialFail, 1) }
func (s *Stats) IncrFlow() { atomic.AddUint64(&s.flows, 1) }
func (s *Stats) DecrFlow() { atomic.AddUint64(&s.flows, ^uint64(0)) }

// IncrUDPSession 记一条**有上行流量**的 UDP 会话的归宿：收到过回包 / 没有回包。
// 这是"这条路对真实 UDP 到底通不通"的实测证据（探针只能证明端口级可达），
// 由拦截层的 UDP 会话在关闭时上报（udpcap 周期读去算探测应答里的实测位）。
func (s *Stats) IncrUDPSession(replied bool) {
	if replied {
		atomic.AddUint64(&s.udpReplied, 1)
		return
	}
	atomic.AddUint64(&s.udpNoReply, 1)
}

// UDPSessions 读 UDP 会话归宿计数（replied, noReply）。
func (s *Stats) UDPSessions() (uint64, uint64) {
	return atomic.LoadUint64(&s.udpReplied), atomic.LoadUint64(&s.udpNoReply)
}

// IncrReject 计一次「并发闸拒绝」（连接在建立流量前被拒）。
func (s *Stats) IncrReject() { atomic.AddUint64(&s.rejected, 1) }

func (s *Stats) Snapshot() map[string]uint64 {
	return map[string]uint64{
		"dialok":   atomic.LoadUint64(&s.dialOK),
		"dialfail": atomic.LoadUint64(&s.dialFail),
		"flows":    atomic.LoadUint64(&s.flows),
		"rejected": atomic.LoadUint64(&s.rejected),
	}
}
