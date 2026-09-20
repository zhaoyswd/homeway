package wgnet

// refused_test.go — ErrRefused 哨兵（review 2026-09-21）：
// RST 类拨号错误必须在包装后仍 errors.Is 可判——手机核的 PathProbe/打洞探测
// 靠它判「隧道通、出口在、目标只是拒绝」（此前只能子串匹配错误文本，措辞一改
// 判据就翻，巡检会误判 3 连败触发自愈风暴）。

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

func TestDialRefusedSentinel(t *testing.T) {
	cliTun, cliNet, err := Create([]netip.Addr{netip.MustParseAddr("100.64.0.2")}, 1280)
	if err != nil {
		t.Fatalf("client wgnet: %v", err)
	}
	srvTun, srvNet, err := CreateOpts([]netip.Addr{netip.MustParseAddr("100.64.255.1")}, 1280, Opts{HandleLocal: false})
	if err != nil {
		t.Fatalf("server wgnet: %v", err)
	}
	// 交叉泵（客户端出站 → 服务端入站，反之亦然）。
	pump := func(from, to tun.Device) {
		bufs := make([][]byte, 1)
		sizes := make([]int, 1)
		bufs[0] = make([]byte, 65535)
		for {
			n, rerr := from.Read(bufs, sizes, 0)
			if rerr != nil || n == 0 {
				return
			}
			for i := 0; i < n; i++ {
				pkt := make([]byte, sizes[i])
				copy(pkt, bufs[i][:sizes[i]])
				if _, werr := to.Write([][]byte{pkt}, 0); werr != nil {
					return
				}
			}
		}
	}
	go pump(cliTun, srvTun)
	go pump(srvTun, cliTun)
	t.Cleanup(func() { cliNet.Close(); srvNet.Close() })

	// 拨服务端无监听的 1 号端口：服务端栈回 RST → 客户端拿到 refused，
	// 包装错误必须携带 ErrRefused 哨兵。
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, derr := cliNet.DialTCPAddrPortCtx(ctx, netip.MustParseAddrPort("100.64.255.1:1"))
	if derr == nil {
		t.Fatal("拨 1 号端口竟然成功了")
	}
	if !errors.Is(derr, ErrRefused) {
		t.Fatalf("RST 错误没挂 ErrRefused 哨兵：%v", derr)
	}
}
