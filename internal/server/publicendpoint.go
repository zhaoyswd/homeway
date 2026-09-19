package server

// 出口的「公网端点自动公布」（从旧 tailcat fork 的 endpoint-hint 机制移植的等价物）。
//
// 目标：出口在 NAT 后面时，把**路由器上真实可达的 公网IP:端口**写进 state 目录，
// 让 `homewayd issue` 能把它一并烤进 token（客户端就能直连，不必只靠局域网地址）。
//
// 两条证据必须一致才公布（旧栈踩过的坑）：
//   - UPnP：向路由器申请的外口（优先与监听端口同号）；
//   - STUN：在**同一个 WG socket** 上问「你看到的我是什么」——得到该 socket 的真实映射。
//
// 若两者端口不一致（路由器改写端口 / 对称 NAT / 出口套了 TUN 型代理），说明这个组合不可达，
// **拒绝公布**并打一行明确日志（宁可不给候选，也不要给一个连不上的假候选）。

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zhaoyswd/homeway/pkg/servercore"
)

const (
	publicRefreshOK   = 10 * time.Minute
	publicRefreshFail = 2 * time.Minute
	publicFile        = "public_endpoint.txt"
)

// PublicOpts 公网端点探测的开关（都来自 serve 的 flag）。
type PublicOpts struct {
	StateDir string
	UPnP     bool
	STUN     string // "" = 不做 STUN 观测；否则是 host:port（IPv4 映射）
	STUN6    string // "" = 跳过 IPv6 校验；否则是有 AAAA 的 STUN 服务器
	Bind     *servercore.ServerBind
	// Pinned：WG socket 已绑物理网卡（--bind-interface）。钉住之后 STUN 观测到的 IP 必然是
	// 这台机器在路由器 WAN 侧的地址（不会是被代理改写过的），所以「外口 != 监听口」时也敢用
	// STUN 的 IP + UPnP 的外口拼端点；没钉住时保守起见要求两者端口一致。
	Pinned bool
	Logf     func(format string, args ...any)
}

// PublicEndpointPath：公布文件路径（issue 读它）。
func PublicEndpointPath(stateDir string) string { return filepath.Join(stateDir, publicFile) }

// ReadPublicEndpoints 读回上次公布的公网端点（可能有多行：IPv4 + 若干 IPv6；空 = 还没有）。
func ReadPublicEndpoints(stateDir string) []string {
	b, err := os.ReadFile(PublicEndpointPath(stateDir))
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if s := strings.TrimSpace(line); s != "" {
			out = append(out, s)
		}
	}
	return out
}


// StartPublicEndpoint 起后台循环（非阻塞）。
func (s *Server) StartPublicEndpoint(ctx context.Context, opts PublicOpts) {
	if !opts.UPnP && opts.STUN == "" {
		return
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	s.pubKick = make(chan struct{}, 1)
	go func() {
		for {
			wait := publicRefreshOK
			if !s.refreshPublicEndpoint(ctx, opts) {
				wait = publicRefreshFail
			}
			select {
			case <-ctx.Done():
				return
			case <-s.pubKick: // 换网事件：别等下一个 10 分钟窗口，立刻重测
				opts.Logf("公网端点：收到换网事件，立即重测")
			case <-time.After(wait):
			}
		}
	}()
}

// KickPublicEndpoint 让公网端点探测立刻跑一轮（换网后调用；非阻塞、可重复）。
func (s *Server) KickPublicEndpoint() {
	if s == nil || s.pubKick == nil {
		return
	}
	select {
	case s.pubKick <- struct{}{}:
	default: // 已经有一次待处理
	}
}

// refreshPublicEndpoint 跑一轮探测；返回是否成功公布。
func (s *Server) refreshPublicEndpoint(ctx context.Context, opts PublicOpts) bool {
	logf := opts.Logf
	port := waitLocalPort(ctx, opts.Bind, 30*time.Second)
	if port == 0 {
		logf("公网端点：WG socket 30s 内还没开，跳过本轮")
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()

	var extPort uint16
	var wanIP netip.Addr
	if opts.UPnP {
		cands := localIPv4Candidates()
		if len(cands) == 0 {
			logf("UPnP：找不到内网 IPv4 候选，跳过端口映射")
		} else if p, used, err := ensurePortMapping(ctx, cands, port, logf); err != nil {
			logf("UPnP：未取得端口映射（%v）；出口在 NAT 后时可在路由器上手动把 UDP %d 转发到本机（候选 %v）", err, port, cands)
		} else {
			extPort = p
			logf("UPnP：已建立端口映射 外部 UDP %d → %v:%d（重启时从路由器表认领，不需本地文件）", extPort, used, port)
			// 路由器自报的 WAN 地址（有些家用路由器返回空值，那就只当没拿到）。
			if g, err := discoverIGD(ctx, used); err == nil {
				if ip, err := g.externalIP(ctx); err == nil && ip.IsValid() && !ip.IsPrivate() {
					wanIP = ip
				}
			}
		}
	}

	var observed netip.AddrPort
	if opts.STUN != "" {
		ap, err := opts.Bind.STUNQuery(ctx, opts.STUN)
		if err != nil {
			logf("STUN：从监听 socket 问 %s 失败（%v）", opts.STUN, err)
		} else {
			observed = ap
			logf("STUN：监听 socket（本地 %d）在 %s 眼里是 %v", port, opts.STUN, ap)
		}
	}

	// 证据合流：
	//   - UPnP 给「外部端口」（我们亲手建的，可信）；
	//   - STUN 给「公网 IP」（同一个 socket 问出来的，钉了网卡就必然是真 WAN 地址）。
	// 两者一致（同号映射）当然最好；**外口 != 监听口**时（沿用历史端口或 +1 回退）端点应为
	// 「STUN 的 IP + UPnP 的外口」—— 出站源端口保持的是监听口，与转发口本来就不一样。
	// 只有没钉网卡时才要求端口一致（防代理把 STUN 观测污染成假的）。
	var pub netip.AddrPort
	switch {
	case observed.IsValid() && extPort != 0 && observed.Port() == extPort && publicAddr(observed.Addr()):
		pub = observed
	case observed.IsValid() && extPort != 0 && opts.Pinned && publicAddr(observed.Addr()):
		pub = netip.AddrPortFrom(observed.Addr(), extPort)
		logf("公网端点：外口 %d ≠ 监听口 %d（沿用历史端口/回退），用 STUN 的 IP + UPnP 的外口公布", extPort, port)
	case observed.IsValid() && extPort == 0 && observed.Port() == port && publicAddr(observed.Addr()):
		pub = observed
	case extPort != 0 && wanIP.IsValid():
		pub = netip.AddrPortFrom(wanIP, extPort)
		logf("公网端点：用路由器自报 WAN 地址 + UPnP 外口公布（没有同 socket STUN 证据）")
	case observed.IsValid() && publicAddr(observed.Addr()):
		logf("公网端点：暂不公布 —— STUN 观测到 %v，但外部端口与监听/UPnP 不一致（%d vs upnp=%d）, "+
			"说明路由器改写端口或有代理抢路由", observed, observed.Port(), extPort)
		return false
	default:
		logf("公网端点：暂不公布（UPnP=%v STUN=%v；两者都没拿到可用证据）", extPort != 0, observed)
		return false
	}

	if !pub.IsValid() {
		return false
	}
	// IPv6 端点：v6 无 NAT，"公网地址"就是本机在该网卡上的全局地址 + 监听端口。
	// 先用同一个 socket 做一次 v6 STUN（验证 v6 路径真的可用、并拿到服务器看到的地址），
	// 失败就不公布 v6 —— 宁可不给，也不给一个发不出去的候选。
	var lines []string
	lines = append(lines, pub.String())
	if opts.STUN6 != "" {
		v6ctx, v6cancel := context.WithTimeout(ctx, 8*time.Second)
		if ap6, err := opts.Bind.STUNQueryV6(v6ctx, opts.STUN6); err == nil {
			if ap6.Addr().Is6() && !ap6.Addr().Is4In6() && !ap6.Addr().IsLinkLocalUnicast() {
				lines = append(lines, netip.AddrPortFrom(ap6.Addr(), pub.Port()).String())
				logf("公网端点：IPv6 路径可用（STUN 看到 %v），公布 [%v]:%d", ap6.Addr(), ap6.Addr(), pub.Port())
			}
		} else {
			logf("公网端点：IPv6 不可用（%v），本轮只公布 IPv4", err)
		}
		v6cancel()
	} else {
		logf("公网端点：未配置 --stun6（需要有 AAAA 的 STUN 服务器），跳过 IPv6 公布")
	}

	if err := os.WriteFile(PublicEndpointPath(opts.StateDir), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		logf("公网端点：写 %s 失败（%v）", PublicEndpointPath(opts.StateDir), err)
		return false
	}
	logf("公网端点：已公布 %v（写进 %s；issue 会把它一并烤进 token）", lines, publicFile)
	return true
}

// waitLocalPort：device 打开 Bind 是异步的（IpcSet 之后由 wireguard-go 拉起），这里等一小会儿。
func waitLocalPort(ctx context.Context, b *servercore.ServerBind, d time.Duration) uint16 {
	deadline := time.Now().Add(d)
	for {
		if p := b.LocalPort(); p != 0 {
			return p
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return 0
		}
		select {
		case <-ctx.Done():
			return 0
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// publicAddr：只接受全局可路由的 IPv4（私网/CGNAT/回环/链路的都不算公网证据）。
func publicAddr(ip netip.Addr) bool {
	if !ip.IsValid() || !ip.Is4() {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return false
	}
	// 100.64/10（CGNAT）也不是公网
	if netip.MustParsePrefix("100.64.0.0/10").Contains(ip) {
		return false
	}
	return true
}

// externalIP：IGD 的 GetExternalIPAddress（部分路由器返回空，调用方自己兜底）。
func (g *igd) externalIP(ctx context.Context) (netip.Addr, error) {
	body, err := g.soap(ctx, "GetExternalIPAddress")
	if err != nil {
		return netip.Addr{}, err
	}
	const tag = "NewExternalIPAddress"
	i := strings.Index(body, "<"+tag+">")
	j := strings.Index(body, "</"+tag+">")
	if i < 0 || j <= i {
		return netip.Addr{}, fmt.Errorf("响应里没有 %s", tag)
	}
	raw := strings.TrimSpace(body[i+len(tag)+2 : j])
	if raw == "" {
		return netip.Addr{}, fmt.Errorf("路由器返回空的外部地址")
	}
	return netip.ParseAddr(raw)
}
