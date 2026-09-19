package servercore

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// 造一个最小的 Binding Response（含 XOR-MAPPED-ADDRESS）。
func fakeSTUNResponse(txid [12]byte, ap netip.AddrPort) []byte {
	b := make([]byte, 20+12)
	binary.BigEndian.PutUint16(b[0:2], stunTypeBindingResponse)
	binary.BigEndian.PutUint16(b[2:4], 12)
	binary.BigEndian.PutUint32(b[4:8], stunMagicCookie)
	copy(b[8:20], txid[:])
	binary.BigEndian.PutUint16(b[20:22], attrXORMappedAddress)
	binary.BigEndian.PutUint16(b[22:24], 8)
	b[24] = 0 // 保留
	b[25] = 1 // family = IPv4
	port := ap.Port() ^ uint16(stunMagicCookie>>16)
	binary.BigEndian.PutUint16(b[26:28], port)
	cookie := make([]byte, 4)
	binary.BigEndian.PutUint32(cookie, stunMagicCookie)
	ip := ap.Addr().As4()
	for i := 0; i < 4; i++ {
		b[28+i] = ip[i] ^ cookie[i]
	}
	return b
}

func TestSTUNParseRoundTrip(t *testing.T) {
	var txid [12]byte
	for i := range txid {
		txid[i] = byte(i)
	}
	want := netip.MustParseAddrPort("203.0.113.9:41641")
	got, ok := stunParseBindingResponse(fakeSTUNResponse(txid, want), txid)
	if !ok || got != want {
		t.Fatalf("解析结果 = %v ok=%v，want %v", got, ok, want)
	}
	// 事务 ID 不匹配 ⇒ 必须拒绝（否则会把别的流量当应答）
	bad := txid
	bad[0] ^= 1
	if _, ok := stunParseBindingResponse(fakeSTUNResponse(txid, want), bad); ok {
		t.Fatal("事务 ID 不匹配却解析成功")
	}
	if !stunLooksLikeResponse(fakeSTUNResponse(txid, want)) {
		t.Fatal("stunLooksLikeResponse 应认得响应")
	}
	if stunLooksLikeResponse(stunBindingRequest(txid)) {
		t.Fatal("请求不该被当成响应")
	}
}

// 端到端：ServerBind 在**自己的 socket** 上问一个假 STUN 服务器，拿到它回显的映射地址。
func TestServerBindSTUNQuery(t *testing.T) {
	fake, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer fake.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, src, err := fake.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 20 || buf[0] != 0 || buf[1] != 1 {
				continue
			}
			var txid [12]byte
			copy(txid[:], buf[8:20])
			// 假装我们在 NAT 后面：回一个固定公网映射
			resp := fakeSTUNResponse(txid, netip.MustParseAddrPort("198.51.100.7:41641"))
			_, _ = fake.WriteToUDP(resp, src)
		}
	}()

	sb := &ServerBind{Logf: func(string, ...any) {}, BindAddr: netip.MustParseAddr("127.0.0.1")}
	recvs, _, err := sb.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close()
	// 模拟 wireguard-go 的读循环：STUN 应答的拦截发生在 ReceiveFunc 里。
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		pkts := [][]byte{make([]byte, 2048)}
		sizes := make([]int, 1)
		eps := make([]conn.Endpoint, 1)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = recvs[0](pkts, sizes, eps) // 测试里不关心投给 device 的内容
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got, err := sb.STUNQuery(ctx, fake.LocalAddr().String())
	if err != nil {
		t.Fatalf("STUNQuery: %v", err)
	}
	if want := netip.MustParseAddrPort("198.51.100.7:41641"); got != want {
		t.Fatalf("观测结果 = %v，want %v", got, want)
	}
}
