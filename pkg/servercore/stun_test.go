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

// IPv6 的 XOR-MAPPED-ADDRESS（family=2，前 4 字节异或 cookie、后 12 字节异或事务 ID）。
func fakeSTUNResponse6(txid [12]byte, ap netip.AddrPort) []byte {
	b := make([]byte, 20+24)
	binary.BigEndian.PutUint16(b[0:2], stunTypeBindingResponse)
	binary.BigEndian.PutUint16(b[2:4], 24)
	binary.BigEndian.PutUint32(b[4:8], stunMagicCookie)
	copy(b[8:20], txid[:])
	binary.BigEndian.PutUint16(b[20:22], attrXORMappedAddress)
	binary.BigEndian.PutUint16(b[22:24], 20)
	b[24] = 0
	b[25] = 2 // family = IPv6
	binary.BigEndian.PutUint16(b[26:28], ap.Port()^uint16(stunMagicCookie>>16))
	raw := ap.Addr().As16()
	cookie := make([]byte, 4)
	binary.BigEndian.PutUint32(cookie, stunMagicCookie)
	for i := 0; i < 4; i++ {
		b[28+i] = raw[i] ^ cookie[i]
	}
	for i := 0; i < 12; i++ {
		b[32+i] = raw[4+i] ^ txid[i]
	}
	return b
}

func TestSTUNParseV6(t *testing.T) {
	var txid [12]byte
	for i := range txid {
		txid[i] = byte(7 + i)
	}
	want := netip.MustParseAddrPort("[2001:db8:1234:5678:83:cbd4:e4a4:8928]:41641")
	got, ok := stunParseBindingResponse(fakeSTUNResponse6(txid, want), txid)
	if !ok || got != want {
		t.Fatalf("v6 解析 = %v ok=%v，want %v", got, ok, want)
	}
}

// 双栈：默认（不绑地址）监听时，v4 与 v6 客户端都能打进来；STUNQueryV6 也能工作。
func TestServerBindDualStack(t *testing.T) {
	sb := &ServerBind{Logf: func(string, ...any) {}}
	recvs, port, err := sb.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close()
	if port == 0 {
		t.Fatal("端口为 0")
	}
	got := make(chan string, 4)
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
			n, err := recvs[0](pkts, sizes, eps)
			if err != nil || n == 0 {
				continue
			}
			got <- eps[0].DstToString()
		}
	}()
	// v4 客户端
	c4, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	defer c4.Close()
	if _, err := c4.Write([]byte("v4-hello")); err != nil {
		t.Fatal(err)
	}
	// v6 客户端
	c6, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: net.ParseIP("::1"), Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	defer c6.Close()
	if _, err := c6.Write([]byte("v6-hello")); err != nil {
		t.Fatal(err)
	}
	seen4, seen6 := false, false
	deadline := time.After(3 * time.Second)
	for !seen4 || !seen6 {
		select {
		case src := <-got:
			ap, err := netip.ParseAddrPort(src)
			if err != nil {
				continue
			}
			if ap.Addr().Is4() || ap.Addr().Is4In6() {
				seen4 = true
			} else if ap.Addr().Is6() {
				seen6 = true
			}
		case <-deadline:
			t.Fatalf("双栈收包缺失：v4=%v v6=%v", seen4, seen6)
		}
	}
}

// 同 socket 的 v6 STUN 查询（对 ::1 上的假服务器）。
func TestServerBindSTUNQueryV6(t *testing.T) {
	fake, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("::1")})
	if err != nil {
		t.Skipf("环境不支持 v6 loopback: %v", err)
	}
	defer fake.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, src, err := fake.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 20 {
				continue
			}
			var txid [12]byte
			copy(txid[:], buf[8:20])
			_, _ = fake.WriteToUDP(fakeSTUNResponse6(txid, netip.MustParseAddrPort("[2001:db8::5]:41641")), src)
		}
	}()

	sb := &ServerBind{Logf: func(string, ...any) {}}
	recvs, _, err := sb.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close()
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
			_, _ = recvs[0](pkts, sizes, eps)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ap, err := sb.STUNQueryV6(ctx, fake.LocalAddr().String())
	if err != nil {
		t.Fatalf("STUNQueryV6: %v", err)
	}
	if want := netip.MustParseAddrPort("[2001:db8::5]:41641"); ap != want {
		t.Fatalf("v6 观测 = %v，want %v", ap, want)
	}
}
