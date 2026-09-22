package servercore

// bind_probeeps_test.go — endpoint-freshness task 4.1(a)：ProbeEndpoints 钩子 → 探测应答
// 端点列表 → pad 契约的集成验证（真 ServerBind + 真 UDP 探测，不打 WG 数据面）。

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/probe"
	"golang.zx2c4.com/wireguard/conn"
)

func TestServerBindProbeEndpointsList(t *testing.T) {
	endpoints := []netip.AddrPort{
		netip.MustParseAddrPort("203.0.113.7:41641"),
		netip.MustParseAddrPort("[2001:db8::1]:41641"),
	}
	b := &ServerBind{
		Logf:  func(string, ...any) {},
		Build: "v-probeeps",
		Caps:  func() byte { return 0 },
		ProbeEndpoints: func() []netip.AddrPort { return endpoints },
	}
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	port := b.LocalPort()
	if port == 0 {
		t.Fatal("端口未开")
	}
	// 驱动接收循环（wireguard device 的同款模式：Open 只返回 ReceiveFunc，
	// 这里手动拉起——探测在 ReceiveFunc 里被应答）。
	go func() {
		var bufs [][]byte
		var sizes []int
		var eps []conn.Endpoint
		bufs = append(bufs, make([]byte, 1500))
		for {
			if _, err := fns[0](bufs, sizes, eps); err != nil {
				return
			}
		}
	}()

	// 新客户端（pad 200）：拿到列表。
	cli, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := probe.PingEx(ctx, cli, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port), "", 200)
	if err != nil {
		t.Fatalf("PingEx 失败：%v", err)
	}
	if res.Build != "v-probeeps" || len(res.Endpoints) != 2 {
		t.Fatalf("应答应带 build 与 2 条端点：%+v", res)
	}
	if res.Endpoints[0] != endpoints[0] || res.Endpoints[1] != endpoints[1] {
		t.Fatalf("端点不一致：%v", res.Endpoints)
	}

	// 老客户端（pad 16）：拿不到列表、功能不受影响（pad 契约）。
	_, build, _, err := probe.Ping(ctx, cli, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port), "")
	if err != nil {
		t.Fatalf("旧 Ping 失败：%v", err)
	}
	if build != "v-probeeps" {
		t.Fatalf("旧 Ping 的 build 异常：%q", build)
	}
}

// ProbeEndpoints 为 nil（老接线形态）：应答退化为无列表。
func TestServerBindProbeEndpointsNilHook(t *testing.T) {
	b := &ServerBind{Logf: func(string, ...any) {}, Build: "v-noeps"}
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	go func() {
		var bufs [][]byte
		var sizes []int
		var eps []conn.Endpoint
		bufs = append(bufs, make([]byte, 1500))
		for {
			if _, err := fns[0](bufs, sizes, eps); err != nil {
				return
			}
		}
	}()
	cli, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := probe.PingEx(ctx, cli, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), b.LocalPort()), "", 200)
	if err != nil {
		t.Fatalf("PingEx 失败：%v", err)
	}
	if res.Endpoints != nil {
		t.Fatalf("nil 钩子不该有列表：%v", res.Endpoints)
	}
}
