package server

// 出口的「公网端点自动公布」（从旧 tailcat fork 的 endpoint-hint 机制移植的等价物）。
//
// 目标：出口在 NAT 后面时，把**路由器上真实可达的 公网IP:端口**写进 state 目录，
// serve 签发 token 时会把它一并烤进去（客户端就能直连，不必只靠局域网地址）。
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
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/zhaoyswd/homeway/pkg/egress"
	"github.com/zhaoyswd/homeway/pkg/probe"
	"github.com/zhaoyswd/homeway/pkg/proto"
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
	// ⚠️ 判据是**运行期事实**（Bind.PinnedIface()）——钉卡失败会自动降级，这里不能拿配置当真。
	Pinned bool
	Logf   func(format string, args ...any)
}

// ListenPortPath：实际监听端口落盘路径（端口冲突会退让；文件供人查，token 里的端口以签发时为准）。
func ListenPortPath(stateDir string) string { return filepath.Join(stateDir, "listen_port.txt") }

// PublicEndpointPath：公布文件路径（内容 = 已公布的公网端点，供人查）。
func PublicEndpointPath(stateDir string) string { return filepath.Join(stateDir, publicFile) }

// StartPublicEndpoint 起后台循环（非阻塞）。--ddns 自检挂在本循环同拍（endpoint-freshness）。
func (s *Server) StartPublicEndpoint(ctx context.Context, opts PublicOpts) {
	if !opts.UPnP && opts.STUN == "" {
		if s.cfg.DDNS != "" {
			logf("DDNS：公网端点探测未开（--upnp=false --stun=''），自检没有观测可比对、跳过；"+
				"token 的域名条目端口按实际监听口")
		}
		return
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	s.pubKick = make(chan struct{}, 1)
	s.firstProbe = make(chan struct{}, 1)
	go func() {
		first := true
		for {
			wait := publicRefreshOK
			if !s.refreshPublicEndpoint(ctx, opts) {
				wait = publicRefreshFail
			}
			s.runDDNSSelfCheck(opts) // 与探测同拍（换网 kick 轮也会跑到）
			if first {
				// 第一轮结束（成不成都算）：Run 的 token 兜底在等这个信号。
				first = false
				select {
				case s.firstProbe <- struct{}{}:
				default:
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-s.pubKick: // 换网事件：别等下一个 10 分钟窗口，立刻重测
				dlogf("公网端点：收到换网事件，立即重测")
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
		dlogf("公网端点：WG socket 30s 内还没开，跳过本轮")
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
	case observed.IsValid() && extPort != 0 && pinnedNow(opts) && publicAddr(observed.Addr()):
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
	logf("公网端点：已公布 %v（写进 %s；下次签发 token 会带上它）", lines, publicFile)
	s.tokMu.Lock()
	s.lastPublished = lines
	s.tokMu.Unlock()
	s.printClientToken(lines)
	return true
}

// tokenEndpoints：token 端点列表的统一组装（endpoint-freshness tasks 2.2 从 printClientToken
// 抽出——probe 应答的端点列表（probeProbeEndpoints）与 token 打印共用同一口径）。
// 顺序：LAN → 已公布公网 → --ddns 域名条目（叠加不踢除，B-1 拍板）→ 中继。
// domain 条目端口口径 = 已公布公网端点的外部端口；无公网观测时回退实际监听口。
func (s *Server) tokenEndpoints(published []string, listenPort uint16) (eps []proto.Endpoint, labels []string) {
	seen := map[string]bool{}
	// add 收**整个 Endpoint**（review 2：签名只收字符串时 Relay 靠调用点记得带——
	// 57012ad 就是这么丢的标记，token 里中继腿恒标 direct，客户端分桶全失效一
	// 天半）。结构流动，真源只有 s.relayEp 一处。
	add := func(e proto.Endpoint, kind string) {
		if e.Addr == "" || seen[e.Addr] {
			// 中继地址与已有直连端点重合（--relay 指向出口自己地址的退化形态）：
			// 按先到的直连形态保留——那个地址物理上就是出口的 WG socket，打腿帧
			// 必被丢，标 relay 反而必坏。取舍见 tokenprint_test 的反例钉住的契约。
			if e.Relay {
				dlogf("中继端点 %s 与已有直连端点相同，按直连处理（中继腿不生效）", e.Addr)
			}
			return
		}
		seen[e.Addr] = true
		eps = append(eps, e)
		labels = append(labels, e.Addr+"（"+kind+"）")
	}
	for _, a := range localV4Addrs(listenPort) {
		add(proto.Endpoint{Addr: a}, "内网")
	}
	for _, a := range published {
		add(proto.Endpoint{Addr: a}, "公网")
	}
	if s.cfg.DDNS != "" {
		p := ddnsEntryPort(published, listenPort)
		if p != 0 {
			add(proto.Endpoint{Addr: net.JoinHostPort(s.cfg.DDNS, strconv.Itoa(int(p)))}, "域名")
		} else {
			// listenPort=0 的调用形态（探测应答的即时快照）：域名条目这轮缺席，下一轮补上。
			dlogf("域名条目：本轮拿不到端口（socket 未开？），token/列表暂不带 --ddns 条目")
		}
	}
	if s.relayEp.Addr != "" {
		add(s.relayEp, "中继")
	}
	return eps, labels
}

// ddnsEntryPort：--ddns 域名条目的端口 = 已公布公网 v4 端点的外部端口；
// 无公网端点观测（--upnp=false --stun=''）时回退实际监听口（让位退让后的真实口）。
func ddnsEntryPort(published []string, listenPort uint16) uint16 {
	for _, line := range published {
		if ap, err := netip.ParseAddrPort(line); err == nil && ap.Addr().Is4() && ap.Port() != 0 {
			return ap.Port()
		}
	}
	return listenPort
}

// printClientToken：把"客户端要粘的 token"打出去 —— **终端只打第一轮**（进程生命周期内
// 不再重打：端点变化后终端冒出第二串 token 只会让人拿错，2026-09-21 用户口径），之后的
// 端点变化只在摘要文件重写一份（取最新 token：grep 客户端 token events.log | tail -1）。
// 内容 = LAN 端点 + 已公布公网端点 + --ddns 域名条目（若有）+ serve --relay 给的中继端点。
func (s *Server) printClientToken(published []string) {
	port := s.bind.LocalPort()
	if port == 0 {
		// socket 还没开（device 异步拉起 Bind）：本轮不打，等下一轮——别端点端口打出 0。
		return
	}
	eps, labels := s.tokenEndpoints(published, port)
	if len(eps) == 0 {
		return
	}
	// 指定了 --relay：中继端点没并入前不打 token —— 先打一版不带中继的只会
	// 误导（用户粘了它，蜂窝下就没人能连上）（2026-09-20 用户口径）。
	// ⚠️ hasRelay 按**地址**比对而非按 flag：中继地址与直连端点重合的退化形态下
	// （tokenEndpoints 去重按直连保留）它仍为 true、闸门放行——这是有意的
	// fail-open：改成按 flag 判会让退化形态永久早退，连直连 token 都拿不到。
	var hasRelay bool
	for _, e := range eps {
		if e.Addr == s.relayEp.Addr {
			hasRelay = true
		}
	}
	if s.relayWanted && !hasRelay {
		return
	}
	tok, err := proto.EncodeToken(proto.Token{
		PeerID:    PubFromPriv(s.priv),
		Secret:    s.secret,
		Endpoints: eps,
	})
	if err != nil {
		logf("客户端 token 生成失败（%v）", err)
		return
	}
	s.tokMu.Lock()
	if tok == s.lastToken {
		s.tokMu.Unlock()
		return
	}
	first := s.lastToken == ""
	s.lastToken = tok
	s.tokMu.Unlock()
	if first {
		// 终端首轮（进程内仅此一次）：带一行日志落点，之后终端对 token/端点保持沉默。
		if p := EventsLogPath(); p != "" {
			tokenToTerminal("日志：%s（摘要）｜ %s（细节）", p, filepath.Join(filepath.Dir(p), debugLogName))
		}
		tokenToTerminal("客户端 token（粘进 App 的「添加主机」即可；%d 个端点）：%s", len(eps), tok)
		tokenToTerminal("端点：%s", strings.Join(labels, "、"))
	} else {
		// 端点变化轮：只进摘要文件（--verbose 会回显终端，那是显式调试模式）。
		tokenToFile("客户端 token（端点已变化；粘进 App 的「添加主机」即可；%d 个端点）：%s", len(eps), tok)
		tokenToFile("端点：%s", strings.Join(labels, "、"))
	}
}

// probeProbeEndpoints：探测应答端点列表段的来源（endpoint-freshness task 2.2）。
// 与 token 打印同源（lastPublished = 最近一轮已公布公网端点）；只含公网 v4/v6——
// 不含 LAN（应答无认证，不把 RFC1918 地址从 token 凭证扩散给任意 pad 请求者；LAN 本就在
// token 里）、不含域名条目（消费侧逐地址投递，用不了 host）。nil = 未公布过（老出口形态）。
func (s *Server) probeProbeEndpoints() []netip.AddrPort {
	s.tokMu.Lock()
	published := append([]string(nil), s.lastPublished...)
	s.tokMu.Unlock()
	var out []netip.AddrPort
	for _, line := range published {
		ap, err := netip.ParseAddrPort(line)
		if err != nil || !ap.IsValid() || ap.Port() == 0 {
			continue
		}
		if !egress.IsPublicAddr(ap.Addr()) {
			continue
		}
		if len(out) >= probe.MaxEndpoints {
			break
		}
		out = append(out, ap)
	}
	return out
}

// localV4Addrs：本机物理网卡 IPv4 + 实际监听端口（LAN 候选）。
func localV4Addrs(port uint16) []string {
	var out []string
	for _, ifi := range egress.PhysicalCandidates() {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok || !ip.Unmap().Is4() {
				continue
			}
			out = append(out, netip.AddrPortFrom(ip.Unmap(), port).String())
		}
	}
	return out
}

// pinnedNow：当前是否真的钉住了网卡（每次刷新都重读，钉卡失败降级后自动变保守）。
func pinnedNow(opts PublicOpts) bool {
	if opts.Bind != nil && opts.Bind.PinnedIface() != nil {
		return true
	}
	return opts.Pinned
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
		return false // 出口公布端点这条路径保持只认 v4（v6 另有 STUN6 校验）
	}
	return egress.IsPublicAddr(ip)
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
