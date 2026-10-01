// Package portfwd：端口转发的**值域与目标语义单实现**（FIX-43）。
//
// 此前四处各写一遍（桌面 facade 的 Add 校验、socks 监听校验、手机核的整表校验、
// CLI 的参数面），且已经漂移：桌面强制 listen/targetPort ∈ [1024,65535]，手机核只查
// 「非 0 + 同表不重复」——「127.0.0.1:80 转发到出口自己:22」这类在 App 上能过、在 CLI
// 上被拒。值域与目标语义以后只在这里定义，两侧 import。
package portfwd

import (
	"errors"
	"fmt"
	"net/netip"
)

// MinPort / MaxPort 监听与目标端口的合法值域（1024 起：不占特权端口；上限 = u16）。
const (
	MinPort uint16 = 1024
	MaxPort uint16 = 65535
)

// ErrRange 端口值域外（桌面 facade 的 facade.ErrPortRange 即本值——同一哨兵）。
var ErrRange = errors.New("端口须在 1024–65535")

// ValidPort 端口是否在值域内。
func ValidPort(p uint16) bool { return p >= MinPort && p <= MaxPort }

// ValidateListen 监听端口校验。
func ValidateListen(p uint16) error {
	if !ValidPort(p) {
		return fmt.Errorf("%w：%d", ErrRange, p)
	}
	return nil
}

// ValidateTarget 目标校验：ip 空 = 出口自己（合法）；port 0 = 同监听端口（合法）；
// ip 非空必须是 IPv4 字面量。**目标端口不做 1024 下限**——spec 的「配置校验」只约束
// 监听端口（1024–65535），目标端口是出口去**拨**的（不 bind），privileged 端口合法
// （例如转发到出口自己的 :22 / :80）。桌面原先多加了这条下限，与 App/spec 相反。
func ValidateTarget(ip string, port uint16) error {
	_ = port // 目标端口无额外值域（u16 已限上限；0 = 同监听端口）
	if ip == "" {
		return nil
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return fmt.Errorf("%w：%q", ErrBadTarget, ip)
	}
	return nil
}

// ErrBadTarget 目标地址形态非法（须为空或 IPv4 字面量）。
var ErrBadTarget = errors.New("目标须为空（出口自己）或 IPv4 字面量")

// DescribeTarget 目标的呈现文案（ip 空 = 出口自己；port 0 = 同监听端口 ⇒ 落成 listen）。
func DescribeTarget(ip string, port, listen uint16) string {
	if ip == "" {
		if port == 0 {
			return "出口自己（同端口）"
		}
		return fmt.Sprintf("出口自己:%d", port)
	}
	if port == 0 {
		port = listen
	}
	return fmt.Sprintf("%s:%d", ip, port)
}
