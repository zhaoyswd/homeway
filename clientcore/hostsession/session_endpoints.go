package hostsession

// session_endpoints.go — token 端点 → 建连候选（IP 字面量 / 域名两种形态；
// 随迁自 cshared session_endpoints.go，逐字不动，host-registry-daemon D1）。
//
// 为什么需要：token 的端点在协议里允许写域名（`pkg/proto` 的注释与 `EncodeToken` 的校验
// 都按 `net.SplitHostPort` 放行），但建连候选必须是 `IP:port`（Bind 直接用它做 UDP 目标）。
// 早期实现只 ParseAddrPort ⇒ **带域名的 token 会被整体判成「没有任何可用端点」**
// （真机 2026-09-19 实测：某出口用域名 `exit.example.com:41641` 签发，手机侧起不来隧道）。
//
// 语义：域名在**每次建会话时**解析一次（A + AAAA：隧道内层只承载 IPv4，但**承载**（外层 WG socket）
// 可以是 IPv4 或 IPv6 —— 出口若公布域名或 v6 地址，客户端要能把 AAAA 也当候选）；解析出的每个地址
// 都作为独立候选参与赛跑。解析失败只记一行、跳过该端点（其它端点照常）；全部失败才算「没有可用端点」。

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/internal/wgcore"
	"github.com/zhaoyswd/homeway/clientcore/internal/wtransport"
	"github.com/zhaoyswd/homeway/pkg/proto"
)

// endpointLookup 域名 → IPv4 地址列表（测试注入；生产 = net.DefaultResolver）。
type endpointLookup func(ctx context.Context, host string) ([]netip.Addr, error)

// lookupIPv4 生产实现：系统解析器的 A + AAAA（5s 预算，避免建会话被 DNS 卡住）。
// 名字沿用 lookupIPv4（调用点/测试注入签名不变）；返回顺序 v4 在前（同网段/兼容性更好的先试）。
func lookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	var v4, v6 []netip.Addr
	for _, ip := range ips {
		ip = ip.Unmap()
		switch {
		case ip.Is4():
			v4 = append(v4, ip)
		case ip.Is6() && !ip.Is4In6():
			v6 = append(v6, ip)
		}
	}
	return append(v4, v6...), nil
}

// splitTokenEndpoints：把 token 端点拆成「IP 字面量静态」与「域名条目」两组
// （endpoint-freshness D5：域名组要在重赛跑时重解析，静态组永不变）。
func splitTokenEndpoints(eps []proto.Endpoint) (static []proto.Endpoint, domains []proto.Endpoint) {
	for _, ep := range eps {
		if _, _, err := net.SplitHostPort(ep.Addr); err != nil {
			continue
		}
		if _, err := netip.ParseAddrPort(ep.Addr); err == nil {
			static = append(static, ep)
			continue
		}
		domains = append(domains, ep)
	}
	return static, domains
}

// domainEndpointPorts：域名条目 → (host, port) 对（重赛跑重解析的输入）。
func domainEndpointPorts(domains []proto.Endpoint, logf Logf) []wgcore.DomainEndpoint {
	var out []wgcore.DomainEndpoint
	for _, ep := range domains {
		host, portStr, err := net.SplitHostPort(ep.Addr)
		if err != nil {
			continue
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil || port == 0 {
			logf("token 端点 %q 端口非法（跳过重解析）", ep.Addr)
			continue
		}
		out = append(out, wgcore.DomainEndpoint{Host: host, Port: uint16(port), Relay: ep.Relay})
	}
	return out
}

// resolveCandidates 把 token 端点展开成候选。IP 字面量直接用；域名做一次 A 记录解析。
func resolveCandidates(eps []proto.Endpoint, lookup endpointLookup, logf Logf) []wtransport.Candidate {
	out := make([]wtransport.Candidate, 0, len(eps))
	seen := map[netip.AddrPort]bool{}
	add := func(ap netip.AddrPort, relay bool) {
		if !ap.IsValid() || seen[ap] {
			return
		}
		seen[ap] = true
		out = append(out, wtransport.Candidate{Addr: ap, Relay: relay})
	}
	for _, ep := range eps {
		if ap, err := netip.ParseAddrPort(ep.Addr); err == nil {
			add(ap, ep.Relay)
			continue
		}
		host, portStr, err := net.SplitHostPort(ep.Addr)
		if err != nil {
			logf("token 端点 %q 非法（跳过）：%v", ep.Addr, err)
			continue
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil || port == 0 {
			logf("token 端点 %q 端口非法（跳过）", ep.Addr)
			continue
		}
		ips, err := lookup(context.Background(), host)
		if err != nil || len(ips) == 0 {
			logf("token 端点 %q 域名解析失败（跳过）：%v", ep.Addr, err)
			continue
		}
		for _, ip := range ips {
			add(netip.AddrPortFrom(ip, uint16(port)), ep.Relay)
		}
		logf("token 端点 %s 解析为 %d 个地址（%s）", ep.Addr, len(ips), fmt.Sprint(ips))
	}
	return out
}
