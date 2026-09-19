package server

// 出口节点的 UPnP 端口映射（从旧 tailcat fork 的 portmapping.go 移植，去掉 tailscale 依赖）。
//
// 为什么不用现成的 portmapper 库：它们打分时会校验 GetStatusInfo/GetExternalIPAddress，并在若干
// 「常见控制路径」上探测；家用路由器常有非标准实现（实测某路由器 GetExternalIPAddress 返回空值、
// 控制路径是私有的 /ctrlu/<uuid>/...），于是直接放弃且**不报错** —— 外面看就是「UPnP 开着但没用」。
// 出口真正需要的只有两件事：SSDP 找到 IGD、AddPortMapping 把 UDP 端口映射出去；失败要明确打日志，
// 让人知道该去路由器上手动转发。

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/ipv4"
)

const (
	ssdpAddr        = "239.255.255.250:1900"
	ssdpST          = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
	upnpMapDesc     = "homeway-exit"
	upnpTimeout     = 5 * time.Second
	upnpRenewPeriod = 30 * time.Minute
)

type upnpService struct {
	ServiceType string `xml:"serviceType"`
	ControlURL  string `xml:"controlURL"`
}

type upnpDeviceNode struct {
	Services []upnpService    `xml:"serviceList>service"`
	Devices  []upnpDeviceNode `xml:"deviceList>device"`
}

type upnpRoot struct {
	Device upnpDeviceNode `xml:"device"`
}

// igd 是一个可用的 WAN 连接服务（WANIPConnection / WANPPPConnection）。
type igd struct {
	controlURL  string
	serviceType string
}

// discoverIGD 用 SSDP 找到网关的 UPnP 描述，再解析出 WAN 连接服务的控制地址。
func discoverIGD(ctx context.Context, localIP netip.Addr) (*igd, error) {
	loc, err := ssdpLocation(ctx, localIP)
	if err != nil {
		return nil, err
	}
	base, err := url.Parse(loc)
	if err != nil {
		return nil, fmt.Errorf("解析 LOCATION %q: %w", loc, err)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", loc, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("取描述文件: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var root upnpRoot
	if err := xml.Unmarshal(body, &root); err != nil {
		return nil, fmt.Errorf("解析描述文件: %w", err)
	}
	if svc := findWANService(root.Device); svc != nil {
		u, err := base.Parse(svc.ControlURL)
		if err != nil {
			return nil, fmt.Errorf("解析 controlURL %q: %w", svc.ControlURL, err)
		}
		return &igd{controlURL: u.String(), serviceType: svc.ServiceType}, nil
	}
	return nil, fmt.Errorf("描述文件里没有 WANIPConnection/WANPPPConnection 服务")
}

func findWANService(d upnpDeviceNode) *upnpService {
	for i := range d.Services {
		st := d.Services[i].ServiceType
		if strings.Contains(st, "WANIPConnection") || strings.Contains(st, "WANPPPConnection") {
			return &d.Services[i]
		}
	}
	for i := range d.Devices {
		if svc := findWANService(d.Devices[i]); svc != nil {
			return svc
		}
	}
	return nil
}

// ssdpLocation 发一次 SSDP M-SEARCH，取第一个 IGD 的 LOCATION。
// localIP 非零时把 socket 绑在该地址上并把组播出口显式指定为该网卡：组播发现必须从**物理接口**
// 出去，否则在有 TUN 型代理（Surge 等）抢默认路由的机器上，发现报文永远出不去。
func ssdpLocation(ctx context.Context, localIP netip.Addr) (string, error) {
	var laddr *net.UDPAddr
	if localIP.IsValid() {
		laddr = &net.UDPAddr{IP: localIP.AsSlice()}
	}
	conn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		return "", fmt.Errorf("SSDP socket: %w", err)
	}
	defer conn.Close()
	if localIP.IsValid() {
		if ifi := ifaceForIP(localIP); ifi != nil {
			pc := ipv4.NewPacketConn(conn)
			if err := pc.SetMulticastInterface(ifi); err != nil {
				return "", fmt.Errorf("指定组播出口 %v: %w", ifi.Name, err)
			}
			_ = pc.SetMulticastTTL(2)
			// macOS 上光设 IP_MULTICAST_IF 还不够：默认路由被 TUN 型代理（Surge 等）抢走时，
			// 发往 239.255.255.250 的报文仍按默认路由选路，直接 `no route to host`
			// （实测 2026-09-19）。用 IP_BOUND_IF / SO_BINDTODEVICE 把整条 socket 钉在该网卡上。
			if err := bindSocketToIface(conn, ifi); err != nil {
				return "", fmt.Errorf("把 SSDP socket 钉在 %v: %w", ifi.Name, err)
			}
		}
	}
	raddr, err := net.ResolveUDPAddr("udp4", ssdpAddr)
	if err != nil {
		return "", err
	}
	msg := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\nST: " + ssdpST + "\r\n\r\n"
	deadline := time.Now().Add(upnpTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	buf := make([]byte, 4096)
	// 重试 3 次：家用路由器/交换机的 IGMP 收敛有几秒抖动，实测同一套设置会偶发
	// `sendto: no route to host`（2026-09-19），重发一次通常就通。
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if _, err := conn.WriteToUDP([]byte(msg), raddr); err != nil {
			lastErr = fmt.Errorf("发送 M-SEARCH: %w", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				lastErr = fmt.Errorf("没有 IGD 响应（路由器未开 UPnP，或组播出不去）: %w", err)
				break // 等下一次重试
			}
			if loc := headerValue(string(buf[:n]), "LOCATION"); loc != "" {
				return loc, nil
			}
		}
		if time.Now().After(deadline) {
			break
		}
	}
	return "", lastErr
}

// ifaceForIP 找出拥有该地址的网卡（SSDP 的组播出口）。
func ifaceForIP(ip netip.Addr) *net.Interface {
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

func headerValue(resp, key string) string {
	for _, line := range strings.Split(resp, "\n") {
		line = strings.TrimSpace(line)
		if len(line) > len(key)+1 && strings.EqualFold(line[:len(key)], key) && line[len(key)] == ':' {
			return strings.TrimSpace(line[len(key)+1:])
		}
	}
	return ""
}

func (g *igd) soap(ctx context.Context, action string, args ...[2]string) (string, error) {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"`)
	b.WriteString(` s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:`)
	b.WriteString(action)
	b.WriteString(` xmlns:u="`)
	b.WriteString(g.serviceType)
	b.WriteString(`">`)
	for _, kv := range args {
		b.WriteString("<" + kv[0] + ">" + kv[1] + "</" + kv[0] + ">")
	}
	b.WriteString("</u:" + action + "></s:Body></s:Envelope>")

	req, err := http.NewRequestWithContext(ctx, "POST", g.controlURL, strings.NewReader(b.String()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"`+g.serviceType+"#"+action+`"`)
	// 家用路由器的嵌入式 HTTP 服务很挑：Go 默认的 keep-alive/gzip 会让它直接关连接
	// （实测报 EOF，而同样请求用 urllib 发就正常）。显式 Connection: close + UA 即可。
	req.Close = true
	req.Header.Set("User-Agent", "homeway/upnp")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return string(body), fmt.Errorf("%s: HTTP %d: %s", action, resp.StatusCode, firstLine(string(body)))
	}
	return string(body), nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

func (g *igd) addPortMapping(ctx context.Context, externalPort uint16, internalIP netip.Addr, internalPort uint16) error {
	// 先删同名映射，保证幂等（多数路由器重复添加会返回 718 ConflictInMappingEntry）
	_ = g.deleteMapping(ctx, externalPort, "UDP")
	// 租期：优先 1 小时（出口挂了映射会自动过期，不会在路由器里越积越多）；
	// 有些家用路由器只接受 0（= 永久），那就退回 0 并留日志。
	_, err := g.addWithLease(ctx, externalPort, internalIP, internalPort, 3600)
	if err != nil {
		if _, err0 := g.addWithLease(ctx, externalPort, internalIP, internalPort, 0); err0 == nil {
			return nil
		}
	}
	return err
}

func (g *igd) addWithLease(ctx context.Context, externalPort uint16, internalIP netip.Addr,
	internalPort uint16, lease uint32) (string, error) {
	return g.soap(ctx, "AddPortMapping",
		[2]string{"NewRemoteHost", ""},
		[2]string{"NewExternalPort", fmt.Sprint(externalPort)},
		[2]string{"NewProtocol", "UDP"},
		[2]string{"NewInternalPort", fmt.Sprint(internalPort)},
		[2]string{"NewInternalClient", internalIP.String()},
		[2]string{"NewEnabled", "1"},
		[2]string{"NewPortMappingDescription", upnpMapDesc},
		[2]string{"NewLeaseDuration", fmt.Sprint(lease)},
	)
}

// deleteMapping 删一条（不存在时路由器报 714，忽略即可）。
func (g *igd) deleteMapping(ctx context.Context, externalPort uint16, proto string) error {
	_, err := g.soap(ctx, "DeletePortMapping", [2]string{"NewRemoteHost", ""},
		[2]string{"NewExternalPort", fmt.Sprint(externalPort)}, [2]string{"NewProtocol", proto})
	return err
}

// upnpMapping 路由器表里的一条映射（GetGenericPortMappingEntry）。
type upnpMapping struct {
	Index          int
	RemoteHost     string
	ExternalPort   uint16
	Protocol       string
	InternalPort   uint16
	InternalClient string
	Enabled        bool
	Description    string
	LeaseDuration  uint32
}

// listMappings 枚举路由器上的端口映射（最多 max 条；713 = 到表尾）。
func (g *igd) listMappings(ctx context.Context, max int) ([]upnpMapping, error) {
	var out []upnpMapping
	for i := 0; i < max; i++ {
		body, err := g.soap(ctx, "GetGenericPortMappingEntry", [2]string{"NewPortMappingIndex", fmt.Sprint(i)})
		if err != nil {
			if strings.Contains(err.Error(), "713") || strings.Contains(body, "SpecifiedArrayIndexInvalid") {
				return out, nil
			}
			return out, err
		}
		// 有些路由器把 713 也放在 HTTP 200 的 SOAP Fault 里返回（实测）：同样按「到表尾」处理。
		if strings.Contains(body, "SpecifiedArrayIndexInvalid") || strings.Contains(body, ">713<") {
			return out, nil
		}
		m := upnpMapping{Index: i}
		m.RemoteHost = xmlTag(body, "NewRemoteHost")
		m.ExternalPort = uint16(atoiOr0(xmlTag(body, "NewExternalPort")))
		m.Protocol = xmlTag(body, "NewProtocol")
		m.InternalPort = uint16(atoiOr0(xmlTag(body, "NewInternalPort")))
		m.InternalClient = xmlTag(body, "NewInternalClient")
		m.Enabled = xmlTag(body, "NewEnabled") == "1"
		m.Description = xmlTag(body, "NewPortMappingDescription")
		m.LeaseDuration = uint32(atoiOr0(xmlTag(body, "NewLeaseDuration")))
		out = append(out, m)
	}
	return out, nil
}

func xmlTag(body, tag string) string {
	open, close := "<"+tag+">", "</"+tag+">"
	i := strings.Index(body, open)
	j := strings.Index(body, close)
	if i < 0 || j <= i {
		return ""
	}
	return strings.TrimSpace(body[i+len(open) : j])
}

func atoiOr0(s string) int {
	n := 0
	for _, c := range strings.TrimSpace(s) {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// FindIGD：按内网候选找路由器（CLI 的 upnp list/clean 用）。
func FindIGD(ctx context.Context) (*igd, netip.Addr, error) {
	cands := localIPv4Candidates()
	if len(cands) == 0 {
		return nil, netip.Addr{}, fmt.Errorf("找不到内网 IPv4 候选")
	}
	var lastErr error
	for _, cand := range cands {
		g, err := discoverIGD(ctx, cand)
		if err != nil {
			lastErr = err
			continue
		}
		return g, cand, nil
	}
	return nil, netip.Addr{}, lastErr
}

// ControlURL：给 CLI 打印用的只读访问器。
func (g *igd) ControlURL() string { return g.controlURL }

// ListMappings / DeleteMapping / CleanMappings：给 CLI 用的薄封装。
func (g *igd) ListMappings(ctx context.Context, max int) ([]upnpMapping, error) {
	return g.listMappings(ctx, max)
}

// ProbeAdd 试申请一条映射（**不先删同名**，用于排障"这个端口是不是被占了"）。
// 调用方通常随后删掉它（或给很短租期让它自己过期）。
func (g *igd) ProbeAdd(ctx context.Context, port uint16, internalIP netip.Addr, lease uint32) (string, error) {
	return g.addWithLease(ctx, port, internalIP, port, lease)
}

func (g *igd) DeleteMapping(ctx context.Context, externalPort uint16, proto string) error {
	return g.deleteMapping(ctx, externalPort, proto)
}

// CleanMappings 删掉所有「描述以 descPrefix 开头」的映射（我们自己的）。返回删除条数。
func (g *igd) CleanMappings(ctx context.Context, descPrefix string, onlyPort uint16) (int, []string, error) {
	list, err := g.listMappings(ctx, 200)
	if err != nil {
		return 0, nil, err
	}
	n := 0
	var kept []string
	for _, m := range list {
		ours := strings.HasPrefix(m.Description, descPrefix)
		if onlyPort != 0 && m.ExternalPort != onlyPort {
			ours = false
		}
		if !ours {
			kept = append(kept, fmt.Sprintf("%s/%d → %s:%d (%s)", m.Protocol, m.ExternalPort,
				m.InternalClient, m.InternalPort, m.Description))
			continue
		}
		if err := g.deleteMapping(ctx, m.ExternalPort, m.Protocol); err != nil {
			return n, kept, err
		}
		n++
	}
	return n, kept, nil
}

// ensurePortMapping 为 internalPort 申请一个外部端口，返回实际拿到的外部端口与所用内网地址。
//
// 端口选择顺序（**优先沿用历史上成功过的那个**）：
//  1. prefer：上次成功申请到的外部端口（state 里记着；端口稳定 ⇒ 路由器规则/DDNS/token 里的公网端点都不用改）；
//  2. internalPort：与监听端口同号（最直观，也是绝大多数家用路由器的默认行为）；
//  3. internalPort+1：同号被占时的回退（日志会明确写出来）。
//
// candidates 是本机的内网 IPv4 候选：逐个发 SSDP 试，谁能找到 IGD 就用谁 —— 一台机器上常有多张
// 网卡（虚拟网卡、代理的 utun），只有与路由器同网段的那张能用。
func ensurePortMapping(ctx context.Context, candidates []netip.Addr, internalPort uint16, prefer uint16,
	logf func(string, ...any)) (uint16, netip.Addr, error) {
	var g *igd
	var localIP netip.Addr
	var lastErr error
	for _, cand := range candidates {
		got, err := discoverIGD(ctx, cand)
		if err != nil {
			lastErr = err
			continue
		}
		g, localIP = got, cand
		break
	}
	if g == nil {
		if lastErr == nil {
			lastErr = fmt.Errorf("没有可用的内网 IPv4 候选")
		}
		return 0, netip.Addr{}, lastErr
	}
	// 先扫一遍路由器：把我们自己**同前缀但端口不同**的历史映射清掉（换监听端口/崩溃重启的遗留），
	// 保证 30 分钟一轮的续期不会在路由器里越积越多。
	if n, _, err := g.CleanMappings(ctx, upnpMapDesc, 0); err == nil && n > 0 {
		logf("UPnP：清掉 %d 条同前缀的旧映射（换端口或上次退出的遗留）", n)
	}
	ext, err := selectExternalPort(ctx, g, internalPort, prefer, localIP, logf)
	if err != nil {
		return 0, localIP, err
	}
	return ext, localIP, nil
}

// portMapper：端口选择只依赖这两件事，抽出来便于单测（真实实现 = *igd）。
type portMapper interface {
	addPortMapping(ctx context.Context, externalPort uint16, internalIP netip.Addr, internalPort uint16) error
	CleanMappings(ctx context.Context, descPrefix string, onlyPort uint16) (int, []string, error)
}

// selectExternalPort：按「上次成功的端口 → 监听端口 → 监听端口+1」的顺序申请，返回成功的外部端口。
func selectExternalPort(ctx context.Context, g portMapper, internalPort, prefer uint16, localIP netip.Addr,
	logf func(string, ...any)) (uint16, error) {
	tried := map[uint16]bool{}
	for _, ext := range []uint16{prefer, internalPort, internalPort + 1} {
		if ext == 0 || tried[ext] {
			continue
		}
		tried[ext] = true
		if err := g.addPortMapping(ctx, ext, localIP, internalPort); err == nil {
			if ext == prefer && prefer != internalPort {
				logf("UPnP：沿用上次成功的外部端口 %d → 内网 %d", ext, internalPort)
			}
			return ext, nil
		} else {
			logf("UPnP：外部端口 %d 申请失败（%v），换下一个候选", ext, err)
		}
	}
	return 0, fmt.Errorf("AddPortMapping 失败（外部端口 %v 都被拒）", []uint16{prefer, internalPort, internalPort + 1})
}

// localIPv4Candidates 列出本机可能用于 UPnP 的内网 IPv4 候选。
// 不能只看默认路由接口：代理类工具（Surge 等）的 utun 常占着默认路由；也不能只取第一个，
// 一台机器上常有多张虚拟网卡。过滤掉回环/虚拟网卡与公网地址；真正的判据仍由「谁能联系上路由器」
// （SSDP 自校验）决定。
func localIPv4Candidates() []netip.Addr {
	var out []netip.Addr
	ifis, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifi := range ifis {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if virtualIface(ifi.Name) {
			continue
		}
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
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if !ip.Is4() || !ip.IsPrivate() {
				continue
			}
			out = append(out, ip)
		}
	}
	return out
}

// virtualIface 判据与出口的直连候选过滤共用一份：这些接口上的地址拨不到家用路由器。
func virtualIface(name string) bool {
	for _, p := range []string{"lo", "utun", "tun", "tap", "bridge", "docker", "vmenet", "llw", "awdl", "anpi", "gif", "stf"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}
