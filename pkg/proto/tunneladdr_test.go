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

// #16：双派生地址的跨端一致性——同 (secret, pubkey) 两地址必不相等且派生稳定；
// 相等守卫（hw-app.2 再散列）两端同规则（本包即唯一真源）。
func TestDeriveTunIPNeverEqualsTunnelIP(t *testing.T) {
	var secret, pub [32]byte
	for i := range secret {
		secret[i] = byte(3*i + 7)
	}
	for i := range pub {
		pub[i] = byte(5*i + 11)
	}
	tun := DeriveTunnelIP(secret, pub)
	app := DeriveTunIP(secret, pub)
	if tun == app {
		t.Fatalf("同设备两派生地址相等：%v", tun)
	}
	// 稳定性：重算一致。
	if DeriveTunIP(secret, pub) != app || DeriveTunnelIP(secret, pub) != tun {
		t.Fatal("派生不稳定")
	}
	// 不同身份 → 地址不同（远大于 99.99% 的情形；本用例的固定输入必不等）。
	pub2 := pub
	pub2[0] ^= 1
	if DeriveTunIP(secret, pub2) == app {
		t.Fatal("不同身份派生出相同 TunIP")
	}
}
