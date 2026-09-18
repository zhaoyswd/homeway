package proto

import (
	"net/netip"
	"testing"
)

func tunSecret(seed byte) [32]byte {
	var s [32]byte
	for i := range s {
		s[i] = byte(i*7+1) ^ seed
	}
	return s
}

func tunPub(seed byte) [32]byte {
	var k [32]byte
	k[0], k[31] = seed, seed^0xff
	return k
}

func TestDeriveTunnelIP(t *testing.T) {
	secret := tunSecret(1)
	a := DeriveTunnelIP(secret, tunPub(1))
	if !a.Is4() {
		t.Fatalf("应为 IPv4：%v", a)
	}
	if !netip.MustParsePrefix("100.64.0.0/16").Contains(a) {
		t.Fatalf("应落在 100.64.0.0/16：%v", a)
	}
	if a == netip.MustParseAddr("100.64.0.0") || a == netip.MustParseAddr("100.64.255.255") {
		t.Fatalf("不应是网段地址/广播地址：%v", a)
	}
	if got := DeriveTunnelIP(secret, tunPub(1)); got != a {
		t.Fatalf("派生必须确定：%v vs %v", got, a)
	}
	// 不同公钥 → 不同地址（逐设备唯一的前提；这里只验两点不同，概率性不等）
	if DeriveTunnelIP(secret, tunPub(2)) == a {
		t.Fatalf("不同公钥派生出同一地址：%v", a)
	}
	// 换 secret（另一个 token）落在不同取值上属常态，相同也合法（不断言，只回归不 panic）
	if DeriveTunnelIP(tunSecret(2), tunPub(1)) == a {
		t.Log("（巧合：换 secret 后地址相同，仍属合法结果）")
	}
}
