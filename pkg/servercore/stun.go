package servercore

import (
	"encoding/binary"
	"net/netip"
)

// 最小 STUN 客户端（RFC 5389 Binding）：只做一件事 —— 问「你看到的我外网地址是什么」。
//
// 为什么必须**在 WG 的那个 UDP socket 上**发（见 ServerBind.STUNQuery）：从临时 socket 问出来的是
// 本机默认路由的映射，而出口真正要用的是「监听端口那个 socket 的映射」。家用机器上跑着 Surge 之类
// 增强模式代理时，两者完全不是一个地址（前者是代理出口 IP + 随机端口，后者才是路由器上的真实映射）
// —— 旧栈踩过这个坑（PATCHES §2.5 的「源端口被改写」判据），这里用同 socket 观测从根上避开。

const (
	stunMagicCookie         = 0x2112A442
	stunTypeBindingRequest  = 0x0001
	stunTypeBindingResponse = 0x0101

	attrMappedAddress    = 0x0001
	attrXORMappedAddress = 0x0020
)

// stunBindingRequest 组一个 20 字节 Binding Request（无属性）。
func stunBindingRequest(txid [12]byte) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:2], stunTypeBindingRequest)
	binary.BigEndian.PutUint16(b[2:4], 0) // length
	binary.BigEndian.PutUint32(b[4:8], stunMagicCookie)
	copy(b[8:20], txid[:])
	return b
}

// stunParseBindingResponse 解析 Binding Response，取 XOR-MAPPED-ADDRESS（缺省回退 MAPPED-ADDRESS）。
// 校验：类型、magic cookie、事务 ID 必须都对（否则忽略，避免把别的流量当应答）。
func stunParseBindingResponse(b []byte, txid [12]byte) (netip.AddrPort, bool) {
	if len(b) < 20 {
		return netip.AddrPort{}, false
	}
	if binary.BigEndian.Uint16(b[0:2]) != stunTypeBindingResponse {
		return netip.AddrPort{}, false
	}
	if binary.BigEndian.Uint32(b[4:8]) != stunMagicCookie {
		return netip.AddrPort{}, false
	}
	if [12]byte(b[8:20]) != txid {
		return netip.AddrPort{}, false
	}
	msgLen := int(binary.BigEndian.Uint16(b[2:4]))
	end := 20 + msgLen
	if end > len(b) {
		end = len(b)
	}
	var xor, plain netip.AddrPort
	var haveXOR, havePlain bool
	for off := 20; off+4 <= end; {
		at := binary.BigEndian.Uint16(b[off : off+2])
		al := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		off += 4
		if off+al > end {
			break
		}
		val := b[off : off+al]
		off += (al + 3) / 4 * 4 // 属性 4 字节对齐
		if len(val) < 8 {
			continue
		}
		family := val[1]
		// family=1 IPv4（8 字节属性）/ family=2 IPv6（20 字节属性）；其它忽略。
		if (family == 1 && (len(val) != 8 || val[0] != 0)) || (family == 2 && (len(val) != 20 || val[0] != 0)) {
			continue
		}
		port := binary.BigEndian.Uint16(val[2:4])
		var ap netip.AddrPort
		switch at {
		case attrXORMappedAddress:
			port ^= uint16(stunMagicCookie >> 16)
			cookie := make([]byte, 4)
			binary.BigEndian.PutUint32(cookie, stunMagicCookie)
			switch family {
			case 1:
				var ip4 [4]byte
				copy(ip4[:], val[4:8])
				for i := 0; i < 4; i++ {
					ip4[i] ^= cookie[i]
				}
				ap = netip.AddrPortFrom(netip.AddrFrom4(ip4), port)
			case 2:
				// IPv6 的 XOR：前 4 字节异或 magic cookie，后 12 字节异或事务 ID。
				var raw [16]byte
				copy(raw[:], val[4:20])
				for i := 0; i < 4; i++ {
					raw[i] ^= cookie[i]
				}
				for i := 0; i < 12; i++ {
					raw[4+i] ^= txid[i]
				}
				ap = netip.AddrPortFrom(netip.AddrFrom16(raw), port)
			}
			if ap.IsValid() {
				xor, haveXOR = ap, true
			}
		case attrMappedAddress:
			switch family {
			case 1:
				var ip4 [4]byte
				copy(ip4[:], val[4:8])
				plain = netip.AddrPortFrom(netip.AddrFrom4(ip4), port)
			case 2:
				var raw [16]byte
				copy(raw[:], val[4:20])
				plain = netip.AddrPortFrom(netip.AddrFrom16(raw), port)
			}
			if plain.IsValid() {
				havePlain = true
			}
		}
	}
	if haveXOR {
		return xor, true
	}
	if havePlain {
		return plain, true
	}
	return netip.AddrPort{}, false
}

// stunLooksLikeResponse：接收路径的快速判别（比完整解析便宜，用于决定"要不要交给 STUN 等待者"）。
func stunLooksLikeResponse(b []byte) bool {
	return len(b) >= 20 &&
		binary.BigEndian.Uint16(b[0:2]) == stunTypeBindingResponse &&
		binary.BigEndian.Uint32(b[4:8]) == stunMagicCookie
}
