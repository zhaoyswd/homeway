// client.go — A 查询客户端助手（forward-socks-speedtest 3e §2.2，D3 步骤①）。
//
// 消费方 = socks 承载面的远程解析腿（daemon 经 facade Host.DialPort(5300) 拨出口
// DNS 代答的 TCP 面，再在这里完成一次查询）。**包保持零 internal/、零 clientcore/
// 依赖**：查询经调用方注入的已建立连接（不自带拨号），本地零解析（解析发生在出口侧
// ——「走指定主机」语义的一半，fake-ip/内网 DNS/geo 场景下本地解析会拿错地址）。
//
// 应答解析返回**有序候选列表**（r2 新-1：多 A 记录全量按应答顺序返回，socks 层按序
// 拨——首个拨不通换下一个，全部不通才回失败）；NXDOMAIN 与「无 A 记录」两类否定形态
// 以可区分哨兵错误返回（调用方回 rep=0x04 且文案可区分、不缓存）。
package dns

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// 解析失败的哨兵（两类否定形态可区分，r1 低-6）。
var (
	// ErrNXDOMAIN 应答 RCODE=3（域名不存在）。
	ErrNXDomain = errors.New("域名不存在（NXDOMAIN）")
	// ErrNoA 应答成功但答案段没有 A 记录（如纯 CNAME 无终端地址、或只剩被过滤类型）。
	ErrNoA = errors.New("无 IPv4 地址（应答无 A 记录）")
)

const (
	typeA   = 1
	classIN = 1
	// maxQueryName 查询名的编码长度上限（253 字节域名 + 标签长度位）。
	maxQueryName = 255
)

// AQuery 构造一条 A 查询报文（随机事务 ID、RD=1、QDCOUNT=1）。返回 (报文, 事务 ID)。
// 域名非法（空标签/超长/非法字符集外的不约束——只挡结构性非法）返回错误。
func AQuery(domain string) ([]byte, uint16, error) {
	labels, err := splitDomain(domain)
	if err != nil {
		return nil, 0, err
	}
	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, 0, fmt.Errorf("事务 ID 生成失败：%w", err)
	}
	q := make([]byte, 0, 12+maxQueryName+8)
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], binary.BigEndian.Uint16(id[:]))
	hdr[2] = 0x01 // RD=1
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	q = append(q, hdr[:]...)
	for _, l := range labels {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0)                      // 根
	q = append(q, 0x00, 0x01, 0x00, 0x01) // A / IN
	return q, binary.BigEndian.Uint16(id[:]), nil
}

// splitDomain 域名 → 标签序列（结构性校验：非空、每标签 1–63、总长受限）。
func splitDomain(domain string) ([]string, error) {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if domain == "" {
		return nil, errors.New("域名为空")
	}
	if len(domain) > 253 {
		return nil, errors.New("域名超长（>253）")
	}
	labels := strings.Split(domain, ".")
	for _, l := range labels {
		if l == "" {
			return nil, errors.New("域名字段为空（连续点）")
		}
		if len(l) > 63 {
			return nil, errors.New("域名字段超长（>63）")
		}
	}
	return labels, nil
}

// ResolveResult 一次 A 解析的产物。
type ResolveResult struct {
	// Addrs 按应答顺序的 A 记录候选列表（至少一条；socks 层按序拨，r2 新-1）。
	Addrs []netip.Addr
	// TTL 缓存时长（答案段 A 记录 TTL 的最小值；出口代答已钳制 ≤60s）。
	TTL uint32
}

// ResolveOverConn 在一条已建立的连接上完成一次 A 查询（RFC1035 TCP 分帧——两字节
// 长度前缀，复用 server.go 的 readTCPMessage/writeTCPMessage）。budget 覆盖读侧
// （写侧小报文不设独立期限）；连接用后由调用方关闭（每查询一条新连接是消费方的
// 既有形态）。事务 ID 与问题段做最低限度校验（错答/串答不认）。
func ResolveOverConn(conn net.Conn, domain string, budget time.Duration) (ResolveResult, error) {
	q, txid, err := AQuery(domain)
	if err != nil {
		return ResolveResult{}, err
	}
	if budget <= 0 {
		budget = 5 * time.Second
	}
	if dl, ok := conn.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = dl.SetReadDeadline(time.Now().Add(budget))
	}
	if err := writeTCPMessage(conn, q); err != nil {
		return ResolveResult{}, fmt.Errorf("发查询失败：%w", err)
	}
	resp, err := readTCPMessage(conn)
	if err != nil {
		return ResolveResult{}, fmt.Errorf("读应答失败：%w", err)
	}
	return parseAResponse(resp, txid)
}

// parseAResponse 解析 A 查询应答：ID 校验 → RCODE 分流（3 = NXDOMAIN）→ 答案段
// 依序抽取 A 记录（CNAME 跳过、压缩指针由 skipName 处理）→ TTL 取 A 记录最小值。
// 无 A 记录（含 NOERROR 空答案）= ErrNoA。
func parseAResponse(resp []byte, txid uint16) (ResolveResult, error) {
	if len(resp) < 12 {
		return ResolveResult{}, errors.New("应答过短")
	}
	if binary.BigEndian.Uint16(resp[0:2]) != txid {
		return ResolveResult{}, errors.New("事务 ID 不符（串答/错答）")
	}
	switch rcode := resp[3] & 0x0F; rcode {
	case 0: // NOERROR
	case 3:
		return ResolveResult{}, ErrNXDomain
	default:
		return ResolveResult{}, fmt.Errorf("解析失败（RCODE=%d）", rcode)
	}
	off, ok := skipName(resp, 12)
	if !ok || off+4 > len(resp) {
		return ResolveResult{}, errors.New("question 段畸形")
	}
	off += 4
	answers := int(binary.BigEndian.Uint16(resp[6:8]))
	out := ResolveResult{Addrs: make([]netip.Addr, 0, answers)}
	for i := 0; i < answers; i++ {
		p, ok := skipName(resp, off)
		if !ok || p+10 > len(resp) {
			return ResolveResult{}, errors.New("答案段畸形")
		}
		rdlen := int(binary.BigEndian.Uint16(resp[p+8 : p+10]))
		if p+10+rdlen > len(resp) {
			return ResolveResult{}, errors.New("答案段 RDATA 越界")
		}
		if typ := binary.BigEndian.Uint16(resp[p : p+2]); typ == typeA && rdlen == 4 {
			var ip [4]byte
			copy(ip[:], resp[p+10:p+14])
			addr := netip.AddrFrom4(ip)
			ttl := binary.BigEndian.Uint32(resp[p+4 : p+8])
			if out.TTL == 0 || ttl < out.TTL {
				out.TTL = ttl
			}
			out.Addrs = append(out.Addrs, addr)
		}
		off = p + 10 + rdlen
	}
	if len(out.Addrs) == 0 {
		return ResolveResult{}, ErrNoA
	}
	return out, nil
}
