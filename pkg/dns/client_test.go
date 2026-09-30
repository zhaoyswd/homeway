// client_test.go — A 查询客户端助手（3e §2.2）：对拍真实 Server 双面（dns.Listen 随机
// 端口 → TCP 查询 → 解析应答；fake 上游注入沿用既有测试基建）。
package dns

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

// buildIPsResponse 在查询后追加 N 条指定 IP 的 A 记录（多 A 候选列表用——既有
// buildResponse 的 RDATA 恒 0.0.0.0，无法区分顺序）。
func buildIPsResponse(query []byte, rcode uint16, ips [4]netip.Addr, ttl uint32) []byte {
	resp := make([]byte, len(query))
	copy(resp, query)
	resp[2] = 0x80 | (query[2] & 0x01)
	resp[3] = byte(rcode & 0x0F)
	n := 0
	for _, ip := range ips {
		if !ip.IsValid() {
			continue
		}
		n++
	}
	binary.BigEndian.PutUint16(resp[6:8], uint16(n))
	for _, ip := range ips {
		if !ip.IsValid() {
			continue
		}
		rec := make([]byte, 16) // name 指针(2)+type(2)+class(2)+ttl(4)+rdlen(2)+rdata(4)
		binary.BigEndian.PutUint16(rec[0:2], 0xC00C)
		binary.BigEndian.PutUint16(rec[2:4], 1) // A
		binary.BigEndian.PutUint16(rec[4:6], 1)
		binary.BigEndian.PutUint32(rec[6:10], ttl)
		binary.BigEndian.PutUint16(rec[10:12], 4)
		a := ip.As4()
		copy(rec[12:16], a[:])
		resp = append(resp, rec...)
	}
	return resp
}

// TestAQueryShape 查询构造：RD=1、QDCOUNT=1、qname 编码、A/IN 尾；事务 ID 随机。
func TestAQueryShape(t *testing.T) {
	q, id, err := AQuery("www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(q) < 17 {
		t.Fatalf("查询过短：%d", len(q))
	}
	if q[2]&0x01 == 0 {
		t.Fatal("RD 应置位")
	}
	if binary.BigEndian.Uint16(q[4:6]) != 1 {
		t.Fatal("QDCOUNT 应为 1")
	}
	want := []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	got := q[12 : 12+len(want)]
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("qname 编码不符@%d：%v", i, got)
		}
	}
	tail := q[len(q)-4:]
	if binary.BigEndian.Uint16(tail[0:2]) != 1 || binary.BigEndian.Uint16(tail[2:4]) != 1 {
		t.Fatalf("QTYPE/QCLASS 应为 A/IN：%v", tail)
	}
	if _, id2, _ := AQuery("www.example.com"); id == id2 {
		t.Fatal("事务 ID 应随机（两次相同）")
	}
	for _, bad := range []string{"", "a..b", ".a"} {
		if _, _, err := AQuery(bad); err == nil {
			t.Fatalf("域名 %q 应报错", bad)
		}
	}
}

// TestResolveOverConnMultiA 对拍真实 Server：多 A 记录按应答顺序返回（候选列表，
// r2 新-1）、TTL 取最小值且被出口代答钳制 ≤60。
func TestResolveOverConnMultiA(t *testing.T) {
	ip1 := netip.MustParseAddr("203.0.113.10")
	ip2 := netip.MustParseAddr("198.51.100.20")
	ip3 := netip.MustParseAddr("192.0.2.30")
	up := startFakeUpstream(t, func(q []byte) []byte {
		// TTL 7193 会被代答钳到 60；三条记录同 TTL ⇒ 客户端见 60。
		return buildIPsResponse(q, 0, [4]netip.Addr{ip1, ip2, ip3}, 7193)
	})
	s := newTestServer(t, "nameserver 127.0.0.1:"+portOf(t, up.udp.LocalAddr()), "127.0.0.1:1")

	conn, err := net.Dial("tcp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	res, err := ResolveOverConn(conn, "multi.example", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Addrs) != 3 {
		t.Fatalf("应返回 3 条候选，实得 %d：%v", len(res.Addrs), res.Addrs)
	}
	if res.Addrs[0] != ip1 || res.Addrs[1] != ip2 || res.Addrs[2] != ip3 {
		t.Fatalf("候选顺序应按应答顺序：%v", res.Addrs)
	}
	if res.TTL != 60 {
		t.Fatalf("TTL 应被出口钳到 60，实得 %d", res.TTL)
	}
}

// TestResolveNegative 两类否定形态可区分：NXDOMAIN（RCODE=3）与无 A 记录。
func TestResolveNegative(t *testing.T) {
	up := startFakeUpstream(t, func(q []byte) []byte {
		return buildResponse(q, 3) // NXDOMAIN
	})
	s := newTestServer(t, "nameserver 127.0.0.1:"+portOf(t, up.udp.LocalAddr()), "127.0.0.1:1")
	conn, err := net.Dial("tcp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := ResolveOverConn(conn, "nx.example", 2*time.Second); err != ErrNXDomain {
		t.Fatalf("应 ErrNXDomain，实得 %v", err)
	}

	up2 := startFakeUpstream(t, func(q []byte) []byte {
		return buildResponse(q, 0) // NOERROR 无答案
	})
	s2 := newTestServer(t, "nameserver 127.0.0.1:"+portOf(t, up2.udp.LocalAddr()), "127.0.0.1:1")
	conn2, err := net.Dial("tcp", s2.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	if _, err := ResolveOverConn(conn2, "empty.example", 2*time.Second); err != ErrNoA {
		t.Fatalf("应 ErrNoA，实得 %v", err)
	}
}

// TestResolveTxnMismatch 事务 ID 不符（串答）不认。
func TestResolveTxnMismatch(t *testing.T) {
	// 直连假上游（不经代答——代答会重写 ID），回一条 ID 错位的应答。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		q, err := readTCPMessage(c)
		if err != nil {
			return
		}
		bad := buildIPsResponse(q, 0, [4]netip.Addr{netip.MustParseAddr("203.0.113.9")}, 30)
		bad[0] ^= 0xFF // 破坏事务 ID
		_ = writeTCPMessage(c, bad)
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := ResolveOverConn(conn, "mismatch.example", 2*time.Second); err == nil {
		t.Fatal("事务 ID 不符应报错")
	}
}
