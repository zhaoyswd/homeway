// Package dns：出口侧 DNS 代答的消息处理纯函数（openspec dns-host-resolver）。
//
// 只做四件事：question 段 qtype 提取（过滤判据）、应答普通 RR 的 TTL 钳制
// （OPT/TSIG 例外）、NOERROR 空应答构造（过滤用）、UDP 超限截断（置 TC，客户端
// 改走 TCP）。不引第三方 DNS 库；解析失败一律显式返回 ok=false，调用方按
// 「丢弃或原样透传」处理，绝不 panic（出口单进程多手机共享，畸形报文不得
// 影响隧道转发）。
package dns

import (
	"encoding/binary"
)

// 过滤的 qtype 集合（隧道仅承载 IPv4 的协议事实）：
// AAAA(28)/HTTPS(65)/SVCB(64) 会引导 v6 直连绕过隧道；ANY(255) 应答内容不可控。
const (
	typeAAAA  = 28
	typeHTTPS = 65
	typeSVCB  = 64
	typeANY   = 255
	typeOPT   = 41  // EDNS 伪记录：TTL 位是 extended-RCODE/flags，不可钳制
	typeTSIG  = 250 // TSIG：TTL 必须为 0，不可钳制
)

// FilteredQType 报告该 qtype 是否被代答过滤（回空应答）。
func FilteredQType(qt uint16) bool {
	return qt == typeAAAA || qt == typeHTTPS || qt == typeSVCB || qt == typeANY
}

// QType 提取查询 question 段的 qtype。解析失败返回 false。
func QType(query []byte) (uint16, bool) {
	if len(query) < 12 {
		return 0, false
	}
	off, ok := skipName(query, 12)
	if !ok || off+4 > len(query) {
		return 0, false
	}
	return binary.BigEndian.Uint16(query[off : off+2]), true
}

// EmptyResponse 为被过滤的查询构造 NOERROR 空应答：回显 question 段、置
// QR/RD/RA、三计数为零（QDCOUNT=1）。查询带 OPT 时应答不含 OPT（EDNS 客户端
// 按无 EDNS 退化处理）。畸形查询返回 nil（不硬造应答）。
func EmptyResponse(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	qend, ok := skipName(query, 12)
	if !ok || qend+4 > len(query) {
		return nil
	}
	resp := make([]byte, 12, qend+4)
	copy(resp[0:2], query[0:2])              // ID 原样
	resp[2] = 0x80 | (query[2] & 0x01)       // QR=1，保留 RD
	resp[3] = 0x80                           // RA=1，RCODE=0
	binary.BigEndian.PutUint16(resp[4:6], 1) // QDCOUNT=1
	resp = append(resp, query[12:qend+4]...) // question 原样回显
	return resp
}

// ClampTTL 把应答里普通 RR 的 TTL 压到 ≤max（超过改写为 max），返回改写条数。
// OPT（TTL 位是 extended-RCODE/flags）与 TSIG（TTL 恒 0）跳过；只动 RR 头的
// TTL 字段，不触碰 RDATA（SOA 的 minimum 等）。解析失败返回 0 且不改写。
func ClampTTL(resp []byte, max uint32) int {
	if len(resp) < 12 {
		return 0
	}
	off, ok := skipName(resp, 12)
	if !ok {
		return 0
	}
	off += 4 // question 的 QTYPE+QCLASS
	n := 0
	for sec := 0; sec < 3; sec++ {
		// 三段 RR 的计数在 header 的 AN/NS/AR（[6:8]/[8:10]/[10:12]）——
		// QD 已随 question 跳过（review M1：写成 [4+2*sec] 会取到 QD/AN/NS，
		// ARCOUNT≥2 时尾部 additional 漏钳）。
		count := int(binary.BigEndian.Uint16(resp[6+2*sec : 8+2*sec]))
		for i := 0; i < count; i++ {
			p, ok := skipName(resp, off)
			if !ok || p+10 > len(resp) {
				return n
			}
			rdlen := int(binary.BigEndian.Uint16(resp[p+8 : p+10]))
			if p+10+rdlen > len(resp) {
				return n
			}
			typ := binary.BigEndian.Uint16(resp[p : p+2])
			if typ != typeOPT && typ != typeTSIG {
				if ttl := binary.BigEndian.Uint32(resp[p+4 : p+8]); ttl > max {
					binary.BigEndian.PutUint32(resp[p+4:p+8], max)
					n++
				}
			}
			off = p + 10 + rdlen
		}
	}
	return n
}

// CountAAAA 统计应答答案段的 AAAA 记录数（过滤面收缩的观测：A 查询应答里
// 夹带的 v6 记录只计数不剥离，剥离需重编码，显式不做）。
func CountAAAA(resp []byte) int {
	if len(resp) < 12 {
		return 0
	}
	off, ok := skipName(resp, 12)
	if !ok {
		return 0
	}
	off += 4
	n := 0
	count := int(binary.BigEndian.Uint16(resp[6:8])) // ANCOUNT
	for i := 0; i < count; i++ {
		p, ok := skipName(resp, off)
		if !ok || p+10 > len(resp) {
			return n
		}
		rdlen := int(binary.BigEndian.Uint16(resp[p+8 : p+10]))
		if p+10+rdlen > len(resp) {
			return n
		}
		if binary.BigEndian.Uint16(resp[p:p+2]) == typeAAAA {
			n++
		}
		off = p + 10 + rdlen
	}
	return n
}

// Truncate 把应答截到 ≤max 字节：保留 header + question + 尽可能多条完整
// answer 记录（不留半条），按实存记录修 ANCOUNT/NSCOUNT/ARCOUNT，置 TC 位。
// authority/additional（含 OPT）整体丢弃——客户端按 TC 语义走 TCP 取全量。
// 已 ≤max 或无法解析时原样返回。
func Truncate(resp []byte, max int) []byte {
	if len(resp) <= max || len(resp) < 12 {
		return resp
	}
	qend, ok := skipName(resp, 12)
	if !ok || qend+4 > len(resp) {
		return resp
	}
	out := make([]byte, 12, len(resp))
	copy(out, resp[:12])
	out[2] |= 0x02 // TC=1
	out = append(out, resp[12:qend+4]...)
	binary.BigEndian.PutUint16(out[4:6], 1) // QDCOUNT
	for i := 0; i < 3; i++ {
		binary.BigEndian.PutUint16(out[6+2*i:8+2*i], 0)
	}
	kept := 0
	off := qend + 4
	count := int(binary.BigEndian.Uint16(resp[6:8]))
	for i := 0; i < count; i++ {
		p, ok := skipName(resp, off)
		if !ok || p+10 > len(resp) {
			break
		}
		rdlen := int(binary.BigEndian.Uint16(resp[p+8 : p+10]))
		if p+10+rdlen > len(resp) {
			break
		}
		end := p + 10 + rdlen
		if len(out)+(end-off) > max {
			break
		}
		out = append(out, resp[off:end]...)
		kept++
		off = end
	}
	if kept == 0 {
		// 一条都放不下：只回 header+question（TC 已置），客户端走 TCP。
		return out
	}
	binary.BigEndian.PutUint16(out[6:8], uint16(kept))
	return out
}

// skipName 跳过（不解析）一个 DNS 名字：label 序列或压缩指针。label 线性
// 推进无环；指针就地结束（不跟随——我们只 skip）。
func skipName(msg []byte, off int) (int, bool) {
	for {
		if off >= len(msg) {
			return 0, false
		}
		l := int(msg[off])
		if l == 0 {
			return off + 1, true
		}
		if l&0xC0 == 0xC0 {
			if off+2 > len(msg) {
				return 0, false
			}
			return off + 2, true
		}
		if l&0xC0 != 0 {
			return 0, false
		}
		off += 1 + l
		if off > len(msg) {
			return 0, false
		}
	}
}
