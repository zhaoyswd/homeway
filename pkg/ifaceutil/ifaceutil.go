// Package ifaceutil：网卡判定与钉卡的**单实现**（FIX-72）。
//
// 收拢前：钉卡两份（pkg/egress/bind_*.go 的 bindSocketToIface 与
// pkg/servercore/ifacebind_*.go 的 PinSocketToIface，判据逐字相同、注释互相提醒
// 「两处别漂」），虚拟网卡黑名单两份且内容不同（egress 19 前缀 / server 12 前缀）。
// 现在三处（egress 候选过滤、servercore 绑卡、upnp/ddns 的出口 IP 挑选）共用本包。
package ifaceutil

import (
	"net"
	"net/netip"
	"strings"
)

// virtualPrefixes 虚拟/隧道网卡名前缀（**两份旧清单的并集**：取更保守的一侧——
// 多跳过一张虚拟卡只会让候选少一张，不会选错上行）。
var virtualPrefixes = []string{
	"lo", "utun", "ipsec", "gif", "stf", "awdl", "llw", "anpi", "ap",
	"bridge", "vmnet", "vmenet", "tap", "tun", "tailscale", "docker", "br-", "veth", "virbr",
}

// IsVirtual 名字像隧道/虚拟网卡吗（前缀匹配，大小写不敏感；纯函数）。
func IsVirtual(name string) bool {
	l := strings.ToLower(name)
	for _, p := range virtualPrefixes {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

// IfaceForAddr 找出拥有该地址的网卡（取不到 = nil）。
func IfaceForAddr(ip netip.Addr) *net.Interface { return ifaceForAddr(ip) }

// PinSocketToFD 按裸 fd 钉卡（egress 的拨号 socket 路径；darwin/linux 平台文件实现）。
func PinSocketToFD(fd int, ifi *net.Interface) error { return pinToFD(fd, ifi) }

// ifaceForAddr 平台无关实现（拥有该地址的网卡）。
func ifaceForAddr(ip netip.Addr) *net.Interface {
	ifis, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for i := range ifis {
		addrs, err := ifis[i].Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if got, ok := netip.AddrFromSlice(ipn.IP); ok && got.Unmap() == ip.Unmap() {
				return &ifis[i]
			}
		}
	}
	return nil
}
