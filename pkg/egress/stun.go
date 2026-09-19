package egress

// 最小 STUN Binding 客户端：判定"默认路径能不能承载**通用 UDP**（非 53）"的可校验探针。
//
// 为什么要单列一类目标：TUN 型代理（Surge 等）对 UDP **按端口区别对待** —— DNS:53 是特例
// （它自己就代理 DNS），QUIC:443 往往被丢。所以只测 53 会得出"UDP 可用"的错误结论。
// 用 STUN:3478 这类非 53 的字面 IP 目标，测的才是"通用 UDP 能不能来回"。
//
// 判据必须可校验：校验事务 ID + magic cookie，不能"收到包就算通"（会被劫持/伪造的应答骗过）。

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const (
	stunMagicCookie = 0x2112A442
	stunBindingReq  = 0x0001
	stunBindingResp = 0x0101

	attrMappedAddress    = 0x0001
	attrXORMappedAddress = 0x0020
	attrSoftware         = 0x8022
)

// NewTxID 12 字节事务 ID。
func NewTxID() [12]byte {
	var id [12]byte
	_, _ = rand.Read(id[:])
	return id
}

// StunRequest 组一条 Binding 请求（带 SOFTWARE 属性；部分服务端只认带属性的请求）。
func StunRequest(txID [12]byte, software string) []byte {
	attrs := []byte{}
	if software != "" {
		attrs = append(attrs, 0x80, 0x22)
		attrs = binary.BigEndian.AppendUint16(attrs, uint16(len(software)))
		attrs = append(attrs, software...)
		for len(attrs)%4 != 0 {
			attrs = append(attrs, 0)
		}
	}
	out := make([]byte, 0, 20+len(attrs))
	out = binary.BigEndian.AppendUint16(out, stunBindingReq)
	out = binary.BigEndian.AppendUint16(out, uint16(len(attrs)))
	out = binary.BigEndian.AppendUint32(out, stunMagicCookie)
	out = append(out, txID[:]...)
	out = append(out, attrs...)
	return out
}

// ParseStunResponse 校验应答并取出 XOR-MAPPED-ADDRESS / MAPPED-ADDRESS。
// txID 不匹配或不是成功应答都算"不是我们的应答"（调用方继续等）。
func ParseStunResponse(b []byte) (txID [12]byte, mapped netip.AddrPort, err error) {
	if len(b) < 20 {
		return txID, netip.AddrPort{}, errors.New("proxy/stun: 报文过短")
	}
	if binary.BigEndian.Uint16(b[0:2]) != stunBindingResp {
		return txID, netip.AddrPort{}, errors.New("proxy/stun: 不是成功应答")
	}
	if binary.BigEndian.Uint32(b[4:8]) != stunMagicCookie {
		return txID, netip.AddrPort{}, errors.New("proxy/stun: magic cookie 不符")
	}
	copy(txID[:], b[8:20])
	length := int(binary.BigEndian.Uint16(b[2:4]))
	if 20+length > len(b) {
		length = len(b) - 20
	}
	attrs := b[20 : 20+length]
	var haveXOR, havePlain bool
	var xorAddr, plainAddr netip.AddrPort
	for len(attrs) >= 4 {
		atype := binary.BigEndian.Uint16(attrs[0:2])
		alen := int(binary.BigEndian.Uint16(attrs[2:4]))
		if 4+alen > len(attrs) {
			break
		}
		val := attrs[4 : 4+alen]
		switch atype {
		case attrXORMappedAddress:
			if ap, ok := parseMapped(val, txID, true); ok {
				xorAddr, haveXOR = ap, true
			}
		case attrMappedAddress:
			if ap, ok := parseMapped(val, txID, false); ok {
				plainAddr, havePlain = ap, true
			}
		}
		pad := (4 - alen%4) % 4
		attrs = attrs[4+alen+pad:]
	}
	switch {
	case haveXOR:
		return txID, xorAddr, nil
	case havePlain:
		return txID, plainAddr, nil
	default:
		return txID, netip.AddrPort{}, fmt.Errorf("proxy/stun: 应答里没有映射地址属性")
	}
}

func parseMapped(v []byte, txID [12]byte, xor bool) (netip.AddrPort, bool) {
	if len(v) < 4 {
		return netip.AddrPort{}, false
	}
	family := v[1]
	port := binary.BigEndian.Uint16(v[2:4])
	if xor {
		port ^= uint16(stunMagicCookie >> 16)
	}
	switch family {
	case 0x01:
		if len(v) < 8 {
			return netip.AddrPort{}, false
		}
		var a [4]byte
		copy(a[:], v[4:8])
		if xor {
			var cookie [4]byte
			binary.BigEndian.PutUint32(cookie[:], stunMagicCookie)
			for i := 0; i < 4; i++ {
				a[i] ^= cookie[i]
			}
		}
		return netip.AddrPortFrom(netip.AddrFrom4(a), port), true
	case 0x02:
		if len(v) < 20 {
			return netip.AddrPort{}, false
		}
		var a [16]byte
		copy(a[:], v[4:20])
		if xor {
			var key [16]byte
			binary.BigEndian.PutUint32(key[0:4], stunMagicCookie)
			copy(key[4:], txID[:])
			for i := 0; i < 16; i++ {
				a[i] ^= key[i]
			}
		}
		return netip.AddrPortFrom(netip.AddrFrom16(a), port), true
	default:
		return netip.AddrPort{}, false
	}
}
