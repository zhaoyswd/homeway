// Package egress：出口的**物理上行绑定**——把转发出去的真实 socket 钉在指定网卡上。
//
// 为什么需要：TUN 型代理（Surge 增强模式等）会把 utun 设为全局默认路由。出口自己不绑卡时，
// flows 转发的 TCP/UDP（以及 UDP 中继给目标开的那条 socket）会走代理出去，后果是
//
//   - QUIC 之类被代理丢掉的 UDP 变成"有去无回"（实测：手机侧上行 314 包，目标零应答）；
//   - 出口侧的 STUN / 路由器映射对不上，公网端点判据失真。
//
// 绑定方式：darwin 用 IP_BOUND_IF（v4）/ IPV6_BOUND_IF（v6），Linux 用 SO_BINDTODEVICE，
// 与 WG socket 的 pinSocketToIface 同一套机制（pkg/servercore）。
//
// 唯一豁免：**回环目标**。出口自己本机的服务（files 7802 / 终端 7724 / 端口转发的本机目标）
// 必须走 lo0，把 socket 钉到物理网卡会把它们统统打断 —— tailscale 的 netns 同样对 localhost 豁免。
package egress

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// Binder 出站绑定器。零值（或 iface == nil）表示不绑，等价于系统默认路由。
type Binder struct {
	iface *net.Interface
}

// FromInterface 给一个已解析的网卡（CLI 的 --bind-interface 已解析过；nil = 不绑）。
func FromInterface(ifi *net.Interface) *Binder { return &Binder{iface: ifi} }

// Enabled 是否真的会绑。
func (b *Binder) Enabled() bool { return b != nil && b.iface != nil }

// shouldBind 判定这条 (network, address) 要不要绑（纯函数，单测覆盖）。
// 不绑：未启用、非 inet、回环目标。
func (b *Binder) shouldBind(network, address string) bool {
	if !b.Enabled() {
		return false
	}
	switch {
	case len(network) >= 3 && network[:3] == "tcp", len(network) >= 3 && network[:3] == "udp":
	default:
		return false // unix / unixgram / packet 等：不是我们要绑的对象
	}
	return !IsLoopbackTarget(address)
}

// IsLoopbackTarget 目标是本机回环吗（127.0.0.0/8、::1、"localhost"、空地址）。
func IsLoopbackTarget(address string) bool {
	if address == "" {
		return false // 空地址 = 监听/未指定：按"要绑"处理（出口的 UDP 中继就是这种）
	}
	if host, _, err := net.SplitHostPort(address); err == nil {
		address = host
	}
	if address == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return false // 域名：按公网目标处理（绑卡不会错，域名解析后也不会是回环）
	}
	return addr.IsLoopback()
}

// Control 是 net.Dialer / net.ListenConfig 的 Control 钩子（在 connect/bind 之前对 fd 设选项）。
func (b *Binder) Control(network, address string, c syscall.RawConn) error {
	if !b.shouldBind(network, address) {
		return nil
	}
	var serr error
	cerr := c.Control(func(fd uintptr) {
		serr = bindSocketToIface(int(fd), b.iface)
	})
	if cerr != nil {
		return cerr
	}
	if serr != nil {
		return fmt.Errorf("egress: 绑定网卡 %s 失败: %w", b.iface.Name, serr)
	}
	return nil
}

// Dialer 返回带绑定的拨号器（未启用时等价于普通 net.Dialer）。
func (b *Binder) Dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, Control: b.Control}
}

// DialContext 拨号（flws.DialFunc 形状，可直接喂给 flows.ServeTCP）。
func (b *Binder) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return b.Dialer(0).DialContext(ctx, network, addr)
}

// ListenUDPFor 给一个**具体目标**开 UDP socket 并钉到该网卡（UDP 中继给每个会话开的那条）。
//
// 家族按目标定：一条中继会话只有一个目标，用 udp4/udp6 比双栈 socket 干净 ——
// darwin 上 `"udp"` 建出来的是 AF_INET6 socket，对 v4-mapped 流量设 IP_BOUND_IF 会 EINVAL，
// 绑卡这件事就悄悄失效了（实测：IP_BOUND_IF 读回来是 0）。
func (b *Binder) ListenUDPFor(dst netip.AddrPort) (*net.UDPConn, error) {
	network := NetworkFor(dst)
	lc := net.ListenConfig{Control: b.Control}
	pc, err := lc.ListenPacket(context.Background(), network, ":0")
	if err != nil {
		return nil, err
	}
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, fmt.Errorf("egress: 期待 *net.UDPConn，拿到 %T", pc)
	}
	return conn, nil
}

// NetworkFor 目标地址对应的 socket 家族（"udp4" / "udp6"）。
func NetworkFor(dst netip.AddrPort) string {
	if dst.IsValid() && dst.Addr().Unmap().Is6() {
		return "udp6"
	}
	return "udp4"
}
