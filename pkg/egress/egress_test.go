package egress

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestIsLoopbackTarget(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:7802", true},
		{"127.0.0.1:53", true},
		{"[::1]:443", true},
		{"localhost:8080", true},
		{"127.0.0.2:1", true},
		{"1.1.1.1:53", false},
		{"[2606:4700::1111]:443", false},
		{"example.com:443", false},
		{"", false}, // 空地址（监听/未指定）按"要绑"处理
	}
	for _, c := range cases {
		if got := IsLoopbackTarget(c.addr); got != c.want {
			t.Errorf("IsLoopbackTarget(%q) = %v，want %v", c.addr, got, c.want)
		}
	}
}

func TestShouldBind(t *testing.T) {
	off := &Binder{} // 未启用
	on := FromInterface(&net.Interface{Name: "en0", Index: 1})
	cases := []struct {
		b       *Binder
		network string
		address string
		want    bool
	}{
		{off, "tcp", "1.1.1.1:443", false},
		{on, "tcp4", "1.1.1.1:443", true},
		{on, "tcp6", "[2606:4700::1111]:443", true},
		{on, "udp", "223.5.5.5:53", true},
		{on, "udp", "", true},                // 出口 UDP 中继：源地址未指定
		{on, "tcp", "127.0.0.1:7802", false}, // 回环豁免
		{on, "tcp", "[::1]:7724", false},
		{on, "unix", "/tmp/x.sock", false},
		{on, "unixgram", "/tmp/x.sock", false},
	}
	for _, c := range cases {
		if got := c.b.shouldBind(c.network, c.address); got != c.want {
			t.Errorf("shouldBind(%v, %q, %q) = %v，want %v", c.b.Enabled(), c.network, c.address, got, c.want)
		}
	}
}

// 回环豁免的行为判据：绑着物理网卡也能拨通本机回环服务
// （出口自己的 files/终端就在回环上；绑卡后如果这里失败，等于把出口自己打瘸）。
func TestLoopbackDialSucceedsWhenBound(t *testing.T) {
	ifi := testIface(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_ = c.Close()
		}
	}()
	b := FromInterface(ifi)
	conn, err := b.Dialer(time.Second).Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("绑卡后拨回环失败（回环必须豁免）：%v", err)
	}
	_ = conn.Close()
}

// 真实 socket 上确实设上了选项（平台实现各自校验，见 bind_*_test.go）。
// v4/v6 两侧都验：家族选错时绑卡会**静默失效**（darwin 上 udp6 socket 设 IP_BOUND_IF 直接 EINVAL）。
func TestListenUDPBindsSocket(t *testing.T) {
	ifi := testIface(t)
	b := FromInterface(ifi)
	for _, target := range []netip.AddrPort{
		netip.MustParseAddrPort("1.1.1.1:53"),
		netip.MustParseAddrPort("[2606:4700:4700::1111]:53"),
	} {
		conn, err := b.ListenUDPFor(target)
		if err != nil {
			t.Fatalf("ListenUDPFor(%v): %v", target, err)
		}
		checkSocketBound(t, conn, ifi, target)
		_ = conn.Close()
	}
}

func TestNetworkFor(t *testing.T) {
	if got := NetworkFor(netip.MustParseAddrPort("1.1.1.1:53")); got != "udp4" {
		t.Errorf("v4 目标 = %q，want udp4", got)
	}
	if got := NetworkFor(netip.MustParseAddrPort("[2001:db8::1]:443")); got != "udp6" {
		t.Errorf("v6 目标 = %q，want udp6", got)
	}
}

// testIface 挑一张真实（非回环、已 up、有地址）的网卡；没有就跳过。
func testIface(t *testing.T) *net.Interface {
	t.Helper()
	ifis, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for i := range ifis {
		ifi := ifis[i]
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if addrs, err := ifi.Addrs(); err == nil && len(addrs) > 0 {
			return &ifi
		}
	}
	t.Skip("没有可用的非回环网卡")
	return nil
}
