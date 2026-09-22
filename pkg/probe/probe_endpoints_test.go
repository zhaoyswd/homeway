package probe

// probe_endpoints_test.go — 端点列表段（endpoint-freshness task 2.1）的编解码与契约测试：
// pad 契约（pad 够才带列表、应答 ≤ 请求、老形态 45B 不变量）、上限与非法条目过滤、
// 新旧互解析（老应答→nil、超限/截断→错误）、PingEx 真往返、nonce 随机性。

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

var testEndpoints = []netip.AddrPort{
	netip.MustParseAddrPort("203.0.113.7:41641"),
	netip.MustParseAddrPort("[2001:db8::1]:41641"),
}

func encodeReqPadded(pad int) ([]byte, [8]byte) {
	var nonce [8]byte
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	return EncodeRequest(TypePing, nonce, pad), nonce
}

func TestRespondExCarriesListWhenPadded(t *testing.T) {
	req, nonce := encodeReqPadded(200)
	resp := RespondEx(req, netip.AddrPort{}, "v9", 0, testEndpoints)
	if resp == nil {
		t.Fatal("应有应答")
	}
	if len(resp) > len(req) {
		t.Fatalf("防放大约束被破坏：应答 %d > 请求 %d", len(resp), len(req))
	}
	got, err := DecodeResponse(resp, TypePing, nonce)
	if err != nil {
		t.Fatalf("解码失败：%v", err)
	}
	if len(got.Endpoints) != 2 {
		t.Fatalf("应带 2 条端点，得到 %v", got.Endpoints)
	}
	// v4 以 4in6 编码、解码侧 Unmap 回 v4。
	if got.Endpoints[0] != testEndpoints[0] || got.Endpoints[1] != testEndpoints[1] {
		t.Fatalf("端点往返不一致：%v", got.Endpoints)
	}
	// 字节布局：flags 之后 = 计数(1) + N × 18B（16B 地址 + 2B BE 端口）。
	n := len(got.Build)
	idx := 13 + 1 + n + 1 // magic3+ver1+type1+nonce8 | buildLen1+build | flags
	if int(resp[idx]) != 2 {
		t.Fatalf("计数位不在 flags 后：%v", resp[idx])
	}
	v4in6 := netip.MustParseAddr("203.0.113.7").As16() // v4 → 4in6 编码
	if !bytes.Equal(resp[idx+1:idx+17], v4in6[:]) {
		t.Fatal("v4 条目应按 4in6 的 16B 编码")
	}
	v6raw := testEndpoints[1].Addr().As16()
	if !bytes.Equal(resp[idx+19:idx+35], v6raw[:]) {
		t.Fatal("v6 条目应按 16B 原序编码（第二条）")
	}
}

func TestRespondExDropsListWithoutPad(t *testing.T) {
	req, nonce := encodeReqPadded(16) // 老客户端形态（29B 请求）
	resp := RespondEx(req, netip.AddrPort{}, "v9", 0, testEndpoints)
	if resp == nil {
		t.Fatal("应有应答")
	}
	if len(resp) > len(req)+45 {
		t.Fatalf("45B 不变量被破坏：%d > %d+45", len(resp), len(req))
	}
	got, err := DecodeResponse(resp, TypePing, nonce)
	if err != nil {
		t.Fatalf("解码失败：%v", err)
	}
	if got.Endpoints != nil {
		t.Fatalf("未 pad 的请求不该拿到列表：%v", got.Endpoints)
	}
}

func TestRespondExCapsAndFilters(t *testing.T) {
	req, _ := encodeReqPadded(600)
	var many []netip.AddrPort
	for i := 0; i < 12; i++ {
		many = append(many, netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}), 41641))
	}
	many = append(many, netip.MustParseAddrPort("203.0.113.99:0")) // 零端口：跳过
	resp := RespondEx(req, netip.AddrPort{}, "", 0, many)
	_, nonce := encodeReqPadded(600)
	got, err := DecodeResponse(resp, TypePing, nonce)
	if err != nil {
		t.Fatalf("解码失败：%v", err)
	}
	if len(got.Endpoints) != MaxEndpoints {
		t.Fatalf("应截断到 %d 条，得到 %d", MaxEndpoints, len(got.Endpoints))
	}
}

func TestDecodeResponseListMalformed(t *testing.T) {
	// 计数超上限（>8）→ 错误。
	req, nonce := encodeReqPadded(200)
	base := RespondEx(req, netip.AddrPort{}, "", 0, nil)
	bad := append([]byte(nil), base...)
	bad = append(bad, byte(MaxEndpoints+1))
	if _, err := DecodeResponse(bad, TypePing, nonce); err == nil {
		t.Fatal("计数超上限应报错")
	}
	// 截断（计数 2 但只有 1 条）→ ErrProbeShort。
	trunc := append([]byte(nil), base...)
	trunc = append(trunc, 2)
	trunc = append(trunc, make([]byte, 18)...)
	if _, err := DecodeResponse(trunc, TypePing, nonce); err == nil {
		t.Fatal("截断列表应报错")
	}
}

func TestPingExOverUDPPadContract(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, src, rerr := srv.ReadFromUDPAddrPort(buf)
			if rerr != nil {
				return
			}
			// 新出口：带列表应答（pad 够的请求自动拿到、不够的自动退老形态）。
			if resp := RespondEx(buf[:n], src, "v9-endpoint", 0, testEndpoints); resp != nil {
				srv.WriteToUDPAddrPort(resp, src)
			}
		}
	}()
	target := srv.LocalAddr().(*net.UDPAddr).AddrPort()
	cli, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 新客户端（pad 200）：拿到列表。
	res, err := PingEx(ctx, cli, target, "", 200)
	if err != nil {
		t.Fatalf("PingEx 失败：%v", err)
	}
	if len(res.Endpoints) != 2 || res.Build != "v9-endpoint" {
		t.Fatalf("应拿到列表与 build：%+v", res)
	}
	// 老客户端（旧 Ping = pad 16）：同一个新出口上拿不到列表、功能不受影响。
	_, build, _, err := Ping(ctx, cli, target, "")
	if err != nil {
		t.Fatalf("旧 Ping 打新出口失败：%v", err)
	}
	if build != "v9-endpoint" {
		t.Fatalf("旧 Ping 的 build 异常：%q", build)
	}
}

func TestRandomNonceUnpredictable(t *testing.T) {
	seen := map[[8]byte]bool{}
	for i := 0; i < 100; i++ {
		n := randomNonce()
		if seen[n] {
			t.Fatalf("nonce 重复（可预测性回归）：%v", n)
		}
		seen[n] = true
	}
}
