package server

// ddnsresolve.go — 出口侧 DDNS 域名解析（endpoint-freshness tasks 1.1/1.2；design D2）。
//
// 只服务自检（周期解析自己的域名与本机观测公网地址对比）——token 生成不依赖它
// （--ddns 条目是叠加、不解析不踢除）。
//
// 纪律（为什么不用现成解析设施）：
//   - raw UDP :53 问公共解析器（回退列表），绝不用系统解析器/net.Resolver——出口宿主机的
//     TUN 型代理（Surge 一类）会劫持 *:53 并以 fake-IP（198.18.0.0/15）应答，系统解析
//     拿到的是假地址（历史实测 dig 返回 198.18.6.169）；
//   - 解析 socket 双族钉当前物理网卡（servercore.PinSocketToIface，与 WG socket 同一纪律）
//     ——v4 与 v6 默认路由被代理接管时查询才真正直出；internal/server 旧有的 bindSocketToIface
//     只钉 v4，AAAA 恰是 v6 保鲜那条腿，已随共享化删除；
//   - 卫兵两档：应答落 fake-IP 段 = 代理污染；非 fake-IP 但非全球单播 = 记录本身不可路由
//     （CGNAT/保留段）——两类成因分开返回，别把 CGNAT 用户引向代理排查。
//
// 信任面：解析结果只驱动自检告警（不进 token、不改端点），伪造应答最坏效果 = 一条错误告警。

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"time"

	"github.com/zhaoyswd/homeway/pkg/egress"
	"github.com/zhaoyswd/homeway/pkg/servercore"
)

const ddnsMaxAnswers = 16 // 单次收集的地址上限（防畸形应答灌爆；正常 DDNS 1-2 条）

// ddnsQueryTimeout：单个查询的问答预算（var 供测试缩短）。
var ddnsQueryTimeout = 2 * time.Second

// ddnsResolvers：公共解析器回退列表（var 供测试注入本地假服务器）。
var ddnsResolvers = []string{"223.5.5.5:53", "119.29.29.29:53"}

// 卫兵两档错误（自检按档分文案）。
var (
	ErrDDNSPoisoned   = errors.New("ddns: 解析结果落在 fake-IP 段（代理环境污染，检查绑卡/代理）")
	ErrDDNSUnroutable = errors.New("ddns: 解析结果非全球单播（DDNS 记录本身不可路由，检查记录值）")
)

// fakeIPRange：Surge 等代理的 fake-IP 段（RFC 2544 benchmark 198.18.0.0/15）。
var fakeIPRange = netip.MustParsePrefix("198.18.0.0/15")

// resolveDDNS：解析 host 的 A+AAAA，只返回通过卫兵的全球单播地址。
// ifi 非空时解析 socket 双族钉该网卡。全部解析器失败返回错误（调用方跳过本轮自检）。
func resolveDDNS(ctx context.Context, host string, ifi *net.Interface) ([]netip.Addr, error) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{}) // 双栈：A 与 AAAA 同一 socket
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if ifi != nil {
		if err := servercore.PinSocketToIface(c, ifi); err != nil {
			return nil, fmt.Errorf("ddns: 解析 socket 钉卡 %v 失败: %w", ifi.Name, err)
		}
	}

	var poisoned bool
	for _, sv := range ddnsResolvers {
		raddr, err := net.ResolveUDPAddr("udp", sv)
		if err != nil {
			continue
		}
		var got []netip.Addr
		for _, qtype := range []uint16{dnsTypeA, dnsTypeAAAA} {
			addrs, err := ddnsQuery(ctx, c, raddr, host, qtype)
			if err != nil {
				continue // 单查询失败不拖垮另一族
			}
			got = append(got, addrs...)
		}
		if len(got) == 0 {
			continue // 该解析器没给出可用应答：试下一个
		}
		for _, a := range got {
			if fakeIPRange.Contains(a) {
				poisoned = true
			}
		}
		var out []netip.Addr
		for _, a := range got {
			if egress.IsPublicAddr(a) && !fakeIPRange.Contains(a) {
				out = append(out, a)
			}
		}
		if len(out) > 0 {
			return out, nil
		}
		// 有应答但全被卫兵拦下：优先报污染（那是环境问题，修了记录问题才能看清）。
		if poisoned {
			return nil, ErrDDNSPoisoned
		}
		return nil, ErrDDNSUnroutable
	}
	return nil, fmt.Errorf("ddns: 全部解析器（%d 个）均无可用应答", len(ddnsResolvers))
}

// ---------- DNS 线格式（仅这一处使用，不引第三方库） ----------

const (
	dnsTypeA     = uint16(1)
	dnsTypeAAAA  = uint16(28)
	dnsHeaderLen = 12
)

// ddnsQuery：一次 A 或 AAAA 问答（随机事务 ID；应答按 ID 匹配，其余丢弃）。
func ddnsQuery(ctx context.Context, c *net.UDPConn, raddr *net.UDPAddr, host string, qtype uint16) ([]netip.Addr, error) {
	qctx, cancel := context.WithTimeout(ctx, ddnsQueryTimeout)
	defer cancel()
	deadline, _ := qctx.Deadline()
	_ = c.SetDeadline(deadline)

	id := uint16(rand.Int31())
	req := buildDNSQuery(id, host, qtype)
	if _, err := c.WriteToUDP(req, raddr); err != nil {
		return nil, err
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := c.ReadFromUDP(buf)
		if err != nil {
			return nil, err
		}
		if from == nil || from.String() != raddr.String() {
			continue // 不是这个解析器的包
		}
		addrs, ok := parseDNSAnswers(buf[:n], id)
		if !ok {
			continue // ID 不符/畸形：丢弃继续等
		}
		return addrs, nil
	}
}

// buildDNSQuery：标准查询报文（RD=1）。
func buildDNSQuery(id uint16, qname string, qtype uint16) []byte {
	out := make([]byte, 0, dnsHeaderLen+len(qname)+8)
	out = binary.BigEndian.AppendUint16(out, id)
	out = binary.BigEndian.AppendUint16(out, 0x0100) // RD=1
	out = binary.BigEndian.AppendUint16(out, 1)      // QDCOUNT
	out = binary.BigEndian.AppendUint16(out, 0)      // ANCOUNT
	out = binary.BigEndian.AppendUint16(out, 0)      // NSCOUNT
	out = binary.BigEndian.AppendUint16(out, 0)      // ARCOUNT
	for _, label := range splitDNSName(qname) {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)                            // QNAME 终止
	out = binary.BigEndian.AppendUint16(out, qtype) // QTYPE
	out = binary.BigEndian.AppendUint16(out, 1)     // QCLASS=IN
	return out
}

// splitDNSName：按 '.' 切标签（不去大小写；空标签丢弃）。
func splitDNSName(name string) [][]byte {
	var out [][]byte
	for _, part := range splitBytes(name) {
		if len(part) > 0 && len(part) <= 63 {
			out = append(out, part)
		}
	}
	return out
}

func splitBytes(s string) [][]byte {
	var out [][]byte
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			if i > start {
				out = append(out, []byte(s[start:i]))
			}
			start = i + 1
		}
	}
	return out
}

// parseDNSAnswers：校验 ID/QR 并抽出应答区里的 A/AAAA 地址（CNAME 跳过）。
// 返回 (地址, 报文是否可用)——ID 不符或畸形时 ok=false，调用方继续等下一包。
func parseDNSAnswers(b []byte, wantID uint16) ([]netip.Addr, bool) {
	if len(b) < dnsHeaderLen {
		return nil, false
	}
	if binary.BigEndian.Uint16(b[0:2]) != wantID || b[2]&0x80 == 0 {
		return nil, false // ID 不符或不是应答
	}
	qd := int(binary.BigEndian.Uint16(b[4:6]))
	an := int(binary.BigEndian.Uint16(b[6:8]))
	p := dnsHeaderLen
	for i := 0; i < qd; i++ { // 跳过问题区
		_, np, ok := parseDNSName(b, p)
		if !ok {
			return nil, false
		}
		p = np + 4 // QTYPE + QCLASS
		if p > len(b) {
			return nil, false
		}
	}
	var out []netip.Addr
	for i := 0; i < an; i++ {
		_, np, ok := parseDNSName(b, p)
		if !ok {
			break // 应答区截断：把已收到的交出去
		}
		p = np
		if p+10 > len(b) {
			break
		}
		typ := binary.BigEndian.Uint16(b[p : p+2])
		rdlen := int(binary.BigEndian.Uint16(b[p+8 : p+10]))
		p += 10
		if p+rdlen > len(b) {
			break
		}
		rdata := b[p : p+rdlen]
		p += rdlen
		switch typ {
		case dnsTypeA:
			if rdlen == 4 {
				if a, ok := netip.AddrFromSlice(rdata); ok {
					out = append(out, a)
				}
			}
		case dnsTypeAAAA:
			if rdlen == 16 {
				if a, ok := netip.AddrFromSlice(rdata); ok {
					out = append(out, a.Unmap())
				}
			}
		}
		if len(out) >= ddnsMaxAnswers {
			break
		}
	}
	return out, true
}

// parseDNSName：解析（可能带 0xc0 压缩指针的）域名；返回结束偏移（指针只跳不跟随——
// 调用方只需要「这个字段到哪结束」，不需要名字本身）。
func parseDNSName(b []byte, p int) (string, int, bool) {
	start := p
	for {
		if p >= len(b) {
			return "", 0, false
		}
		l := int(b[p])
		if l == 0 {
			return "", p + 1, true // 名字结束（不还原字符串，见上）
		}
		if l&0xc0 == 0xc0 { // 压缩指针：本字段到此为止
			if p+2 > len(b) {
				return "", 0, false
			}
			_ = start
			return "", p + 2, true
		}
		if l > 63 || p+1+l > len(b) {
			return "", 0, false
		}
		p += 1 + l
	}
}
