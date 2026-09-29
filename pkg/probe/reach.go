package probe

// reach.go — 添加主机的「连通性探测」编排（add-host-connectivity 落地，host-cli 1.1
// 从 cshared 专属的 app_probe_reach.go 提取共享：手机 NAPI 包装与 daemon host.add
// 服务端验证同调本核——探测实现一份，不漂移）。
//
// 对 token 端点全集做参照点探测（明文一问一答）：每端点独立临时 UDP socket、
// 独立 nonce、总预算 3s，返回逐端点可达性与 RTT（只回报活端点；死端点静默）。
// 纯旁路（spec host-management「与既有连接隔离」）：不进 WG、不登记 peer、无身份、
// 不碰任何会话状态——与扩展进程的隧道会话和本进程的服务会话均无共享状态，探测
// 期间它们照常运行。
//
// 预算（host-management「添加主机必须做真实连通性验证」MUST ≤3.5s）：编排整体套
// **3.5s 父预算**，域名解析并行化并计入同一预算（此前逐端点顺序解析、每个 ≤1.5s，
// 一个 DDNS 端点即最坏 4.5s+）。对手机 App 这是行为收紧（域名慢解析场景总等待
// 封顶 3.5s）而非漂移。

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
)

// 预算与填充常量（daemon host.add 的时延上限由这里真保证）。
const (
	// ReachParentBudget 编排整体父预算：域名解析（并行）与探测共用，总等待封顶
	// 3.5s——spec host-management 的 ≤3.5s MUST 由此成立。
	ReachParentBudget = 3500 * time.Millisecond
	// ReachResolveBudget 单端点域名解析预算（并行；再受父预算约束）。
	ReachResolveBudget = 1500 * time.Millisecond
	// ReachProbeBudget 探测等待预算（死端点等满即判不可达；再受父预算约束——
	// 解析吃掉的部分从这里扣：1.5s 慢解析 + 2s 探测 = 3.5s 封顶）。
	ReachProbeBudget = 3 * time.Second
	// ReachPad 请求填充长度（要拿端点列表段就得 pad 到期望最大应答长度）。
	// 与 clientcore/internal/wgcore 的 probePad（transport.go，同值 200）**登记
	// 同源**：同值两处、注释互指、改必同改——wgcore 侧是巡检旁路探测的独立
	// 调用点，不为合并而合并。
	ReachPad = 200
)

// reachResolver 域名解析注入缝（host-cli r2 ④(c)②）：生产 = 系统默认解析器；
// 单测注入慢解析验证父预算封顶（DNS 并行化后单个端点慢解析不再拖垮总预算）。
var reachResolver = func(ctx context.Context, host string) []netip.Addr {
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, ia := range ips {
		if ip, ok := netip.AddrFromSlice(ia.IP); ok {
			out = append(out, ip.Unmap())
		}
	}
	return out
}

// ReachResult 单端点结论（只回报活端点）。
type ReachResult struct {
	EP    string
	RTT   time.Duration
	Build string
	Relay bool
}

// ReachReport 一次探测编排的完整结论（Results 恒非 nil：空 = 全不可达）。
type ReachReport struct {
	PeerID    [32]byte
	Peer      string // 6 字节短指纹 hex（与探测地址面同款展示）
	Endpoints []string
	Results   []ReachResult
}

// 三档结论值（daemon host.add 服务端消费；手机档位判定沿用 ArkTS 侧推导，
// NAPI 返回体形状不变）。
const (
	TierDirect = "direct" // 有直连端点应答
	TierRelay  = "relay"  // 直连全无应答且中继有应答
	TierNone   = "none"   // 全不可达（daemon 映射 host_unreachable 错误码，不入成功载荷）
)

// Tier 三档结论：direct = 任一直连端点应答；relay = 直连全无应答且中继有应答
// （中继无应答不断言中继故障——兼容不回探测的旧版中继）；none = 全不可达。
func (r *ReachReport) Tier() string {
	var hasDirect, hasRelay bool
	for _, res := range r.Results {
		if res.Relay {
			hasRelay = true
		} else {
			hasDirect = true
		}
	}
	switch {
	case hasDirect:
		return TierDirect
	case hasRelay:
		return TierRelay
	default:
		return TierNone
	}
}

// Best 实测最优端点：direct 档 = RTT 最小的直连活端点；relay 档 = RTT 最小的中继
// 活端点；全不可达 = 零值。
func (r *ReachReport) Best() ReachResult {
	wantRelay := r.Tier() == TierRelay
	var best ReachResult
	found := false
	for _, res := range r.Results {
		if res.Relay != wantRelay {
			continue
		}
		if !found || res.RTT < best.RTT {
			best, found = res, true
		}
	}
	return best
}

// Reach 探测编排：decode → 端点解析（并行，计入父预算）/去重 → 并发 PingEx →
// 结论。parent 为外部取消口（nil = Background）；token 非法返回原样错误
// （调用方就地报错、不发起任何网络探测）。
func Reach(parent context.Context, tokenRaw string) (*ReachReport, error) {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, ReachParentBudget)
	defer cancel()
	tok, err := proto.DecodeToken(strings.TrimSpace(tokenRaw))
	if err != nil {
		return nil, err
	}
	eps := make([]string, 0, len(tok.Endpoints))
	for _, ep := range tok.Endpoints {
		if ep.Relay {
			eps = append(eps, "relay:"+ep.Addr)
		} else {
			eps = append(eps, ep.Addr)
		}
	}

	// 解析并行化：每端点一个 goroutine（域名端点解析失败返回空集，不阻塞其余端点）。
	var mu sync.Mutex
	var direct, relay []netip.AddrPort
	var wg sync.WaitGroup
	for _, ep := range tok.Endpoints {
		wg.Add(1)
		go func(ep proto.Endpoint) {
			defer wg.Done()
			aps := resolveReachTarget(ctx, ep.Addr)
			mu.Lock()
			defer mu.Unlock()
			for _, ap := range aps {
				if ep.Relay {
					relay = append(relay, ap)
				} else {
					direct = append(direct, ap)
				}
			}
		}(ep)
	}
	wg.Wait()
	direct = dedupAddrPorts(direct)
	relay = dedupAddrPorts(relay)

	out := make([]ReachResult, 0, len(direct)+len(relay))
	probeOne := func(target netip.AddrPort, isRelay bool) {
		defer wg.Done()
		pc, err := net.ListenUDP("udp", nil)
		if err != nil {
			return
		}
		defer pc.Close()
		// 探测预算受父预算约束（WithTimeout 取更早的 deadline：min(3s, 父剩余)）。
		pctx, pcancel := context.WithTimeout(ctx, ReachProbeBudget)
		defer pcancel()
		res, err := PingEx(pctx, pc, target, "", ReachPad)
		if err != nil {
			return // 死端点是预期：不回报
		}
		mu.Lock()
		out = append(out, ReachResult{EP: target.String(), RTT: res.RTT, Build: res.Build, Relay: isRelay})
		mu.Unlock()
	}
	for _, ap := range direct {
		wg.Add(1)
		go probeOne(ap, false)
	}
	for _, ap := range relay {
		wg.Add(1)
		go probeOne(ap, true)
	}
	wg.Wait()
	return &ReachReport{PeerID: tok.PeerID, Peer: fmt.Sprintf("%x", tok.PeerID[:6]), Endpoints: eps, Results: out}, nil
}

// resolveReachTarget：addr "host:port"（host 可为域名）→ 探测目标集。
// 端口非数字/越界返回 nil；域名解析失败返回 nil（不阻塞其余端点）。
func resolveReachTarget(ctx context.Context, addr string) []netip.AddrPort {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil
	}
	if ip, perr := netip.ParseAddr(host); perr == nil {
		return []netip.AddrPort{netip.AddrPortFrom(ip.Unmap(), uint16(port))}
	}
	// 单端点解析预算 min(1.5s, 父剩余)。
	rctx, cancel := context.WithTimeout(ctx, ReachResolveBudget)
	defer cancel()
	ips := reachResolver(rctx, host)
	var out []netip.AddrPort
	for _, ip := range ips {
		out = append(out, netip.AddrPortFrom(ip, uint16(port)))
	}
	return out
}

// dedupAddrPorts：去重（域名可能解析出与字面端点相同的 IP；重复探测无意义）。
func dedupAddrPorts(in []netip.AddrPort) []netip.AddrPort {
	seen := make(map[netip.AddrPort]bool, len(in))
	out := make([]netip.AddrPort, 0, len(in))
	for _, ap := range in {
		if !seen[ap] {
			seen[ap] = true
			out = append(out, ap)
		}
	}
	return out
}
