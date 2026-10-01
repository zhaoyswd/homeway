package ifaceutil

import (
	"net/netip"
	"testing"
)

// TestIsVirtualUnion：并集语义——两份旧清单里的名字都被认（FIX-72：egress 19 前缀
// 与 server 12 前缀内容不同，取并集后任一侧的判据都不丢）。
func TestIsVirtualUnion(t *testing.T) {
	virtual := []string{
		"lo0", "utun3", "ipsec0", "gif0", "stf0", "awdl0", "llw0", "anpi0", "ap1",
		"bridge0", "vmnet1", "vmenet0", "tap0", "tun0", "tailscale0", "docker0", "br-abc123", "veth1", "virbr0",
		"UTUN5", // 大小写不敏感
	}
	for _, n := range virtual {
		if !IsVirtual(n) {
			t.Errorf("%q 应判为虚拟/隧道网卡", n)
		}
	}
	real := []string{"en0", "en1", "eth0", "wlan0", "wx0"}
	for _, n := range real {
		if IsVirtual(n) {
			t.Errorf("%q 不应判为虚拟（物理上行候选）", n)
		}
	}
}

// TestIfaceForAddrLoopback：地址 → 网卡（回环必然可查；查不到 = nil 不 panic）。
func TestIfaceForAddrLoopback(t *testing.T) {
	ifi := IfaceForAddr(netip.MustParseAddr("127.0.0.1"))
	if ifi == nil {
		t.Fatal("回环地址应能查到网卡")
	}
	if !IsVirtual(ifi.Name) {
		t.Fatalf("回环网卡 %q 应按虚拟判（前缀 lo）", ifi.Name)
	}
	if got := IfaceForAddr(netip.MustParseAddr("203.0.113.7")); got != nil {
		t.Fatalf("不存在的地址应回 nil，got %v", got)
	}
}
