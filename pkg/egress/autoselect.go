package egress

// 物理网卡的**自动挑选**（老栈 egressbind.go 的等价物，2026-09-19 重写）：
// 不手填网卡名也能钉对卡 —— 枚举候选 → 逐个「绑定后发 DNS 探针」验证 → 取探通的那张。
//
// 为什么要探针而不是「看默认路由」：默认路由可能被 TUN 型代理（Surge 等）抢走，
// 我们要的恰恰是**绕开它**的那张物理网卡；判据只能是"从这张卡出去，包真能回来"。
//
// 探针目标用 **anycast 字面 IP**（国内 223.5.5.5 / 国际 1.1.1.1）：不用域名（规则型代理会把
// 域名解析成 fake-IP），并且校验「应答来源 == 所查服务器」+「事务 ID 匹配」（挡路由器劫持代答）。

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

// 虚拟/隧道网卡的名字黑名单（与"直连候选通告过滤"共用判断口径：那些接口不是我们的上行）。
// 前缀匹配；大小写不敏感。
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

// PhysicalCandidates：候选上行网卡（up、非回环、非虚拟、至少有一个 IPv4）。
// 没有 IPv4 的直接排除：WG 端点和 STUN 都走 v4 为主（v6 只在同一个 socket 上顺带支持）。
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

// DefaultProbeTargets：探针目标（anycast DNS，字面 IP）。
func DefaultProbeTargets() []netip.AddrPort {
	return []netip.AddrPort{
		netip.MustParseAddrPort("223.5.5.5:53"),
		netip.MustParseAddrPort("1.1.1.1:53"),
	}
}

// ProbeIface：从 ifi 这张卡发一次 DNS 探针，返回 RTT；探不通返回 error。
// 判据（三条都要满足）：应答事务 ID 匹配、来源 == 所查服务器、是合法 DNS 应答。
func ProbeIface(ctx context.Context, ifi *net.Interface, targets []netip.AddrPort, timeout time.Duration) (time.Duration, error) {
	if ifi == nil {
		return 0, errors.New("egress: 探针没有网卡")
	}
	if len(targets) == 0 {
		targets = DefaultProbeTargets()
	}
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		var serr error
		cerr := c.Control(func(fd uintptr) { serr = bindSocketToIface(int(fd), ifi) })
		if cerr != nil {
			return cerr
		}
		return serr
	}}
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
	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)
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
