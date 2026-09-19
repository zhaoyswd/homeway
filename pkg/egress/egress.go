// Package egress：出口的**上行网卡选择与探测**。
//
// 用途（2026-09-19 定稿）：
//   - **WG socket 钉卡**：默认路由可能被 TUN 型代理（Surge 等）抢走，不钉的话 STUN 观测到的是
//     代理的 NAT 映射 ⇒ 打洞与公网端点公布都不成立。钉哪张卡由本包**探针**决定（不看默认路由）：
//     `PhysicalCandidates` 枚举候选，`SelectBest` 逐张发 anycast DNS 探针取最快探通的。
//   - **默认路径的 UDP 能力探测**（`ProbeDefault`）：转发流量一律走系统默认路由，这条路能不能
//     承载 UDP 是**它的属性**（TUN 型代理通常不中继 UDP）—— 测出来暴露给上层/运维，别猜。
//
// 回环例外只与"钉卡"有关：出口自己的 files/终端在 127.0.0.1，钉物理网卡会打断它们，
// 所以钉卡只作用于 WG socket（那条永远不拨回环）。
package egress

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"
)

// 虚拟/隧道网卡的名字黑名单（前缀匹配，大小写不敏感）：这些不是我们的上行网卡。
var virtualIfacePrefixes = []string{
	"lo", "utun", "ipsec", "gif", "stf", "awdl", "llw", "anpi", "ap",
	"bridge", "vmnet", "vmenet", "tap", "tun", "tailscale", "docker", "br-", "veth", "virbr",
}

// IsVirtualIface：名字像隧道/虚拟网卡吗（纯函数，单测覆盖）。
func IsVirtualIface(name string) bool {
	l := strings.ToLower(name)
	for _, p := range virtualIfacePrefixes {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

// ProbeTargets：探针目标（anycast DNS，**字面 IP**：规则型代理会把域名解析成 fake-IP）。
func DefaultProbeTargets() []netip.AddrPort {
	return []netip.AddrPort{
		netip.MustParseAddrPort("223.5.5.5:53"),
		netip.MustParseAddrPort("1.1.1.1:53"),
	}
}

// ProbeDefault：从**系统默认路由**发一次 DNS 探针（不绑卡）。
// 用途：判定"经默认路径转发出去的 UDP 到底能不能回来"。返回 RTT；探不通返回 error。
func ProbeDefault(ctx context.Context, targets []netip.AddrPort, timeout time.Duration) (time.Duration, error) {
	return probeWith(ctx, nil, targets, timeout)
}

// DefaultSTUNTargets：通用 UDP（非 53）探针目标，字面 IP。
// Cloudflare / Google 的 STUN 都在 3478 系端口上，且都是"随便什么 UDP 都能到"的服务。
func DefaultSTUNTargets() []netip.AddrPort {
	return []netip.AddrPort{
		netip.MustParseAddrPort("162.159.207.1:3478"),
		netip.MustParseAddrPort("74.125.250.129:19302"),
	}
}

// ProbeSTUN：从**系统默认路由**（ifi 为 nil）或指定网卡发一次 STUN Binding 探针。
// 返回 STUN 服务器看到的映射地址与 RTT —— 它证明"非 53 的通用 UDP 能出去、也能回来"。
func ProbeSTUN(ctx context.Context, ifi *net.Interface, targets []netip.AddrPort, timeout time.Duration) (netip.AddrPort, time.Duration, error) {
	if len(targets) == 0 {
		targets = DefaultSTUNTargets()
	}
	lc := net.ListenConfig{}
	if ifi != nil {
		lc.Control = func(network, address string, c syscall.RawConn) error {
			var serr error
			cerr := c.Control(func(fd uintptr) { serr = bindSocketToIface(int(fd), ifi) })
			if cerr != nil {
				return cerr
			}
			return serr
		}
	}
	pc, err := lc.ListenPacket(ctx, "udp4", ":0")
	if err != nil {
		return netip.AddrPort{}, 0, err
	}
	defer pc.Close()
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		return netip.AddrPort{}, 0, fmt.Errorf("egress: 期待 *net.UDPConn，拿到 %T", pc)
	}
	txID := NewTxID()
	req := StunRequest(txID, "homeway-probe")
	_ = conn.SetDeadline(time.Now().Add(timeout))
	start := time.Now()
	for _, t := range targets {
		_, _ = conn.WriteToUDPAddrPort(req, t)
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return netip.AddrPort{}, 0, err
		}
		gotTx, mapped, err := ParseStunResponse(buf[:n])
		if err != nil {
			continue
		}
		if gotTx != txID {
			continue
		}
		matched := false
		for _, t := range targets {
			if from.Addr().Unmap() == t.Addr().Unmap() {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		return mapped, time.Since(start), nil
	}
}

// ProbeIface：从 ifi 这张卡发一次 DNS 探针（绑定后发），返回 RTT。
// 判据（三条都要满足）：事务 ID 匹配、来源 == 所查服务器、是合法 DNS 应答。
func ProbeIface(ctx context.Context, ifi *net.Interface, targets []netip.AddrPort, timeout time.Duration) (time.Duration, error) {
	if ifi == nil {
		return 0, errors.New("egress: 探针没有网卡")
	}
	return probeWith(ctx, ifi, targets, timeout)
}

func probeWith(ctx context.Context, ifi *net.Interface, targets []netip.AddrPort, timeout time.Duration) (time.Duration, error) {
	if len(targets) == 0 {
		targets = DefaultProbeTargets()
	}
	lc := net.ListenConfig{}
	if ifi != nil {
		lc.Control = func(network, address string, c syscall.RawConn) error {
			var serr error
			cerr := c.Control(func(fd uintptr) { serr = bindSocketToIface(int(fd), ifi) })
			if cerr != nil {
				return cerr
			}
			return serr
		}
	}
	pc, err := lc.ListenPacket(ctx, "udp4", ":0")
	if err != nil {
		return 0, err
	}
	defer pc.Close()
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		return 0, fmt.Errorf("egress: 期待 *net.UDPConn，拿到 %T", pc)
	}

	var txid [2]byte
	_, _ = rand.Read(txid[:])
	query := dnsProbeQuery(txid)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	start := time.Now()
	for _, t := range targets {
		_, _ = conn.WriteToUDPAddrPort(query, t)
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return 0, err
		}
		if n < 12 || buf[0] != txid[0] || buf[1] != txid[1] {
			continue // 不是我们这条查询的应答
		}
		matched := false
		for _, t := range targets {
			if from.Addr().Unmap() == t.Addr().Unmap() {
				matched = true
				break
			}
		}
		if !matched {
			continue // 被劫持/代答（来源不是我们查的服务器）⇒ 不算探通
		}
		return time.Since(start), nil
	}
}

// dnsProbeQuery：一条最小的 A 查询（随机名 + RD）。应答内容无关紧要，
// 收到 ID 匹配且来源正确的包即证明这条路能承载我们自己的 UDP 往返。
func dnsProbeQuery(txid [2]byte) []byte {
	b := []byte{txid[0], txid[1], 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	var rnd [6]byte
	_, _ = rand.Read(rnd[:])
	label := fmt.Sprintf("p%x", rnd)
	b = append(b, byte(len(label)))
	b = append(b, label...)
	for _, s := range []string{"probe", "invalid"} {
		b = append(b, byte(len(s)))
		b = append(b, s...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, 1) // A
	b = binary.BigEndian.AppendUint16(b, 1) // IN
	return b
}

// PhysicalCandidates：候选上行网卡（up、非回环、非虚拟、至少有一个 IPv4）。
func PhysicalCandidates() []net.Interface {
	ifis, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []net.Interface
	for _, ifi := range ifis {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if IsVirtualIface(ifi.Name) {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		hasV4 := false
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				hasV4 = true
				break
			}
		}
		if hasV4 {
			out = append(out, ifi)
		}
	}
	return out
}

// SelectBest：并发探测所有候选，返回**最快探通**的那张卡；全不通返回 error + 每张卡的结论明细。
func SelectBest(ctx context.Context, cands []net.Interface, targets []netip.AddrPort, timeout time.Duration,
	logf func(string, ...any)) (*net.Interface, error) {
	return selectBestWith(ctx, cands, PreferredIface(), targets, timeout, logf, ProbeIface)
}

// probeFunc：探针的可注入形式（单测覆盖选择逻辑）。
type probeFunc func(ctx context.Context, ifi *net.Interface, targets []netip.AddrPort, timeout time.Duration) (time.Duration, error)

func selectBestWith(ctx context.Context, cands []net.Interface, prefer *net.Interface, targets []netip.AddrPort,
	timeout time.Duration, logf func(string, ...any), probe probeFunc) (*net.Interface, error) {
	if len(cands) == 0 {
		return nil, errors.New("egress: 没有候选物理网卡（都 up/非虚拟/有 IPv4？）")
	}
	type res struct {
		ifi *net.Interface
		rtt time.Duration
		err error
	}
	ch := make(chan res, len(cands))
	var wg sync.WaitGroup
	for i := range cands {
		ifi := cands[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			rtt, err := probe(pctx, &ifi, targets, timeout)
			ch <- res{ifi: &ifi, rtt: rtt, err: err}
		}()
	}
	wg.Wait()
	close(ch)
	var best *net.Interface
	var bestRTT time.Duration
	var preferHit *net.Interface
	var details []string
	for r := range ch {
		if r.err != nil {
			details = append(details, fmt.Sprintf("%s 不通（%v）", r.ifi.Name, r.err))
			continue
		}
		details = append(details, fmt.Sprintf("%s 通（%v）", r.ifi.Name, r.rtt.Round(time.Millisecond)))
		if prefer != nil && r.ifi.Index == prefer.Index {
			preferHit = r.ifi
		}
		if best == nil || r.rtt < bestRTT {
			best, bestRTT = r.ifi, r.rtt
		}
	}
	// 多网卡机器上「探得通」不等于「钉对了」：docker 网桥/内网卡也能探通 DNS，但钉在它上面
	// 收不到入向的 WG 包。**默认路由那张卡**才是外面看到的入口，探通就优先它。
	if preferHit != nil {
		best = preferHit
	}
	if logf != nil {
		logf("网卡探测：%s", strings.Join(details, "；"))
	}
	if best == nil {
		return nil, errors.New("egress: 所有候选网卡都探不通：" + strings.Join(details, "；"))
	}
	return best, nil
}

// PreferredIface：系统默认路由会从哪张卡出去（UDP dial 只做路由查询，不发包）。
// 拿不到（没有默认路由）返回 nil。
func PreferredIface() *net.Interface {
	conn, err := net.Dial("udp4", "223.5.5.5:53")
	if err != nil {
		return nil
	}
	defer conn.Close()
	la, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || la == nil || la.IP == nil {
		return nil
	}
	want, ok := netip.AddrFromSlice(la.IP)
	if !ok {
		return nil
	}
	want = want.Unmap()
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
			got, ok := netip.AddrFromSlice(ipn.IP)
			if ok && got.Unmap() == want {
				return &ifis[i]
			}
		}
	}
	return nil
}
