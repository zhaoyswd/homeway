package relay

// token.go — 中继 token 铸造与地址面 helper（原 cli.go 的装配段随角色化挪入；CLI 与
// Role 共用——前台单角色与统一进程两形态同一条铸造路径）。

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/zhaoyswd/homeway/pkg/egress"
	"github.com/zhaoyswd/homeway/pkg/proto"
)

// buildToken：把中继地址（--advertise 优先，否则本机物理网卡地址）+ 端口 + 鉴权密钥编成 rl1 token。
//
// 端口以**实际监听口**为准：--advertise 只给 host 时补上实际端口；给了不同端口则按它写
// （NAT 场景下外部口可以不同），但打一行告警 —— token 里的端口必须真的能连到我们。
// 告警走 ulogf：它属于「token 里的端口信息」且只在配置错误时出现一次。
func buildToken(secret [32]byte, advertise string, port uint16) (string, []string, error) {
	var eps []proto.Endpoint
	var addrs []string
	for _, a := range splitList(advertise) {
		host, p, err := net.SplitHostPort(a)
		if err != nil {
			return "", nil, fmt.Errorf("--advertise %q 不是 host:port", a)
		}
		var pn uint16
		_, _ = fmt.Sscanf(p, "%d", &pn)
		if pn != port {
			ulogf("⚠️ --advertise %q 的端口 %d 与实际监听口 %d 不一致：token 里写的是 %d —— 除非前面有 NAT 端口映射，否则后端连不上", a, pn, port, pn)
		}
		addrs = append(addrs, net.JoinHostPort(host, p))
	}
	var skipped []string
	prefixes := map[string]struct{}{}
	if len(addrs) == 0 {
		// 自动探测**只取公网地址**（永远不把非公网 IP 写进 token）。
		for _, ifi := range egress.PhysicalCandidates() {
			as, err := ifi.Addrs()
			if err != nil {
				continue
			}
			for _, a := range as {
				ipn, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				ip, ok := netip.AddrFromSlice(ipn.IP)
				if !ok {
					continue
				}
				ip = ip.Unmap()
				if !egress.IsPublicAddr(ip) {
					skipped = append(skipped, netip.AddrPortFrom(ip, port).String())
					continue
				}
				// 同一 /64 只留一个：macOS 的 IPv6 临时地址（privacy extensions）会轮换，
				// 同一前缀下往往挂着 7–8 个，全写进 token 既长又容易过期。
				if ip.Is6() {
					pfx, perr := ip.Prefix(64)
					if perr != nil {
						continue
					}
					if _, seen := prefixes[pfx.String()]; seen {
						continue
					}
					prefixes[pfx.String()] = struct{}{}
				}
				addrs = append(addrs, netip.AddrPortFrom(ip, port).String())
			}
		}
	}
	if len(addrs) == 0 {
		if len(skipped) > 0 {
			return "", nil, fmt.Errorf("本机只有非公网地址（%v）—— token 里不放非公网 IP："+
				"公网中继请加 --advertise <公网IP:端口>；局域网内使用也请显式 --advertise <局域网IP:端口>",
				skipped)
		}
		return "", nil, fmt.Errorf("没找到可公布的地址（用 --advertise 指定）")
	}
	for _, a := range addrs {
		eps = append(eps, proto.Endpoint{Addr: a})
	}
	tok, err := proto.EncodeRelayToken(secret, eps)
	return tok, addrs, err
}

// allPrivate：公布的地址全在内网吗（提醒加 --advertise）。
func allPrivate(addrs []string) bool {
	for _, a := range addrs {
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			continue
		}
		ip, err := netip.ParseAddr(host)
		if err == nil && !ip.IsPrivate() && !ip.IsLoopback() {
			return false
		}
	}
	return true
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
