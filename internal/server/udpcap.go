package server

// 出口的「默认路径能不能承载 UDP」探测与暴露。
//
// 背景（2026-09-19 定稿）：转发出去的流量**一律走系统默认路由**，路径上装了什么（Surge 那类
// TUN 代理 / 网关 / 直连）由它按自己的规则处理。我们不再猜、也不再分协议选路 ——
// 但必须把这条路的**属性**测出来并暴露：
//
//   - 出口日志一行（人看）：`UDP 默认路径：可用（往返 42ms）` / `不可用（…）：QUIC 等转发 UDP 会有去无回`；
//   - 探测应答（机器看）：`probe` 的 ping 响应尾部多一个 flags 字节，bit0 = 默认路径可承载 UDP
//     —— App/工具链一次探测就能知道"这台出口的 UDP 能不能用"，不用等 QUIC 超时。
//
// 判据是**可校验的往返**：从默认路由（不绑卡）发 anycast DNS 探针，校验事务 ID + 应答来源。
// 探针每 5 分钟一轮（换网事件也会立刻重探），结论变化才打日志。

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/zhaoyswd/homeway/pkg/egress"
)

// udpCapInterval：默认路径 UDP 能力的重探间隔。
const udpCapInterval = 5 * time.Minute

// 探测应答 flags 的能力位（与 tier 核 session.go 的同名常量同源）。
//
//	bit0：默认路径能承载 **UDP:53（DNS 类）**；
//	bit1：默认路径能承载**通用 UDP（非 53；用 STUN:3478 探）** —— 这一位才对应 QUIC 那类流量。
//
// 分两位是必须的：TUN 型代理对 UDP 按端口区别对待（Surge 转发 DNS 但丢 QUIC），
// 只测 53 会得出"UDP 可用"的错误结论。
const (
	UDPCapDNS      = byte(1 << 0)
	UDPCapGeneric  = byte(1 << 1)
	// UDPCapObserved：**实测证据** —— 最近一轮窗口里有转发的 UDP 会话收到过回包。
	// 探针只能证明"某一类端口可达"，这一位来自真实流量，才对应"QUIC 这类到底能不能用"。
	UDPCapObserved = byte(1 << 2)
	// UDPCapProbed：出口至少完成过一轮探测（用来区分"未知"与"明确探测过"）。
	UDPCapProbed = byte(1 << 3)
	// UDPCapSeen：本轮窗口内有**真实转发**的 UDP 会话（不论有没有回包）——
	// 有它 + 没有 UDPCapObserved = "实测过、确实无回包"，比"没样本"强得多。
	UDPCapSeen = byte(1 << 4)
)

// udpCapState：当前结论（原子读，探测循环写）+ 立刻重探的信号。
type udpCapState struct {
	flags atomic.Uint32 // 见 UDPCapDNS/UDPCapGeneric
	done  atomic.Bool
	kick  chan struct{}
}

// UDPCapFlags：给探测应答用的 flags（还没探过时按"未知=不可用"上报，别给假承诺）。
func (s *Server) UDPCapFlags() byte {
	if s == nil || s.udpCap == nil || !s.udpCap.done.Load() {
		return 0
	}
	return byte(s.udpCap.flags.Load())
}

// UDPCapableGeneric：最近一次探测里"通用 UDP"的结论（未知 = false）。
func (s *Server) UDPCapableGeneric() bool {
	return s.UDPCapFlags()&UDPCapGeneric != 0
}

// startUDPCapProbe 起后台探测循环（非阻塞；先探一轮再进周期）。
func (s *Server) startUDPCapProbe(ctx context.Context, logf func(string, ...any)) {
	s.udpCap = &udpCapState{}
	s.udpCap.kick = make(chan struct{}, 1)
	if logf == nil {
		logf = func(string, ...any) {}
	}
	go func() {
		last := "?"
		var prevReplied, prevNoReply uint64
		probe := func() {
			var flags byte
			dnsNote, genNote := "不可用", "不可用"
			pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			if rtt, err := egress.ProbeDefault(pctx, nil, 2*time.Second); err == nil {
				flags |= UDPCapDNS
				dnsNote = fmt.Sprintf("可用（往返 %v）", rtt.Round(time.Millisecond))
			} else {
				dnsNote = fmt.Sprintf("不可用（%v）", err)
			}
			cancel()
			// 重试一次：启动瞬间/网络刚起来时会有偶发超时（实测容器重启那轮就撞上过），
			// 一次失败不足以判"这条路不回包"。
			var genErr error
			for attempt := 0; attempt < 2; attempt++ {
				pctx2, cancel2 := context.WithTimeout(ctx, 4*time.Second)
				mapped, rtt, err := egress.ProbeSTUN(pctx2, nil, nil, 3*time.Second)
				cancel2()
				if err == nil {
					flags |= UDPCapGeneric
					genNote = fmt.Sprintf("有可校验应答（往返 %v，映射 %v）", rtt.Round(time.Millisecond), mapped)
					genErr = nil
					break
				}
				genErr = err
			}
			if genErr != nil {
				genNote = fmt.Sprintf("**未取得正证据**（%v）—— 可能是探针目标不可达，也可能是这条路不回包；以下面「实测」为准", genErr)
			}
			// 真实流量证据（统计窗口 = 本次探测与上次探测之间）
			replied, noReply := s.Stats.UDPSessions()
			dReplied := replied - prevReplied
			dNoReply := noReply - prevNoReply
			prevReplied, prevNoReply = replied, noReply
			flags |= UDPCapProbed
			if dReplied+dNoReply > 0 {
				flags |= UDPCapSeen
			}
			if dReplied > 0 {
				flags |= UDPCapObserved
			}
			s.udpCap.flags.Store(uint32(flags))
			s.udpCap.done.Store(true)
			cur := fmt.Sprintf("0x%02x", flags)
			// 打印时机：能力位变化，或者**本轮有真实转发的 UDP 会话**（后者才是用户最关心的证据，
			// 且"只有上行"这种失败并不改变能力位，不能因此不报）。
			if cur != last || dReplied+dNoReply > 0 {
				saw := fmt.Sprintf("本轮 %d 条有回包 / %d 条只有上行", dReplied, dNoReply)
				hint := ""
				switch {
				case dReplied == 0 && dNoReply == 0:
					saw = "本轮没有转发的 UDP 会话"
				case dReplied == 0:
					hint = " —— 转发出去的 UDP 全都只有上行没有回包：这条路（多半是 TUN 型代理）不回这类 UDP，" +
						"对应到应用就是 QUIC 会超时回落 TCP"
				}
				logf("UDP 默认路径：DNS:53 %s；通用 UDP（STUN:3478）%s；实测 %s%s"+
					"（探测应答 flags=0x%02x 也会这么报）", dnsNote, genNote, saw, hint, flags)
				last = cur
			}
		}
		probe()
		t := time.NewTicker(udpCapInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-s.udpCap.kick:
				probe()
			case <-t.C:
				probe()
			}
		}
	}()
}

// KickUDPCapProbe：换网后立刻重探（非阻塞；由换网看护调用）。
func (s *Server) KickUDPCapProbe() {
	if s == nil || s.udpCap == nil {
		return
	}
	select {
	case s.udpCap.kick <- struct{}{}:
	default: // 已经有一次待处理
	}
}
