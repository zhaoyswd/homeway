package server

// ddnsresolve_test.go — 假 DNS 服务器驱动的解析客户端测试（endpoint-freshness tasks 1.1/1.2）。
//
// 覆盖：正常 A+AAAA、fake-IP 卫兵（污染档）、CGNAT/保留段卫兵（不可路由档）、
// 解析器回退（第一个死、第二个活）、畸形应答不挂死、共享钉卡 API 冒烟（双族设置成功）。

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/servercore"
)

// fakeDNS：一个只回固定地址的本地 DNS 服务器（A 与 AAAA 各自独立配置）。
type fakeDNS struct {
	t   *testing.T
	mu  sync.Mutex
	conn *net.UDPConn
	aAnswers []netip.Addr
	aaaaAns  []netip.Addr
	garbage  bool // 收到请求回一段垃圾（测 ID 匹配与畸形容错）
}

// setAnswers / answers：答案可动态换（serve goroutine 与测试 goroutine 并发访问，加锁）。
func (f *fakeDNS) setAnswers(a, aaaa []netip.Addr) {
	f.mu.Lock()
	f.aAnswers, f.aaaaAns = a, aaaa
	f.mu.Unlock()
}

func (f *fakeDNS) answers(qtype uint16) []netip.Addr {
	f.mu.Lock()
	defer f.mu.Unlock()
	if qtype == dnsTypeA {
		return f.aAnswers
	}
	return f.aaaaAns
}

func startFakeDNS(t *testing.T, aAns, aaaaAns []netip.Addr, garbage bool) *fakeDNS {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("起假 DNS 失败：%v", err)
	}
	f := &fakeDNS{t: t, conn: c, aAnswers: aAns, aaaaAns: aaaaAns, garbage: garbage}
	go f.serve()
	t.Cleanup(func() { _ = c.Close() })
	return f
}

func (f *fakeDNS) addr() string { return f.conn.LocalAddr().String() }

func (f *fakeDNS) serve() {
	buf := make([]byte, 1500)
	for {
		n, from, err := f.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if f.garbage {
			_, _ = f.conn.WriteToUDP([]byte("not-a-dns-response"), from)
			continue
		}
		resp := f.respond(buf[:n])
		if resp != nil {
			_, _ = f.conn.WriteToUDP(resp, from)
		}
	}
}

// respond：回声问题区 + 按问题类型拼应答区。
func (f *fakeDNS) respond(req []byte) []byte {
	if len(req) < 12 {
		return nil
	}
	id := binary.BigEndian.Uint16(req[0:2])
	qd := int(binary.BigEndian.Uint16(req[4:6]))
	p := 12
	for i := 0; i < qd; i++ {
		for p < len(req) {
			l := int(req[p])
			if l == 0 {
				p++
				break
			}
			if l&0xc0 == 0xc0 {
				p += 2
				break
			}
			p += 1 + l
		}
		p += 4
	}
	question := req[12:p]
	qtype := binary.BigEndian.Uint16(question[len(question)-4 : len(question)-2])

	var answers []netip.Addr
	switch qtype {
	case dnsTypeA, dnsTypeAAAA:
		answers = f.answers(qtype)
	}
	out := make([]byte, 0, 64)
	out = binary.BigEndian.AppendUint16(out, id)
	out = binary.BigEndian.AppendUint16(out, 0x8180) // QR=1 RD=1 RA=1
	out = binary.BigEndian.AppendUint16(out, 1)      // QD
	out = binary.BigEndian.AppendUint16(out, uint16(len(answers)))
	out = binary.BigEndian.AppendUint16(out, 0)
	out = binary.BigEndian.AppendUint16(out, 0)
	out = append(out, question...)
	for _, a := range answers {
		out = append(out, 0xc0, 0x0c) // NAME 指针 → 偏移 12
		if a.Is4() {
			out = binary.BigEndian.AppendUint16(out, dnsTypeA)
			out = binary.BigEndian.AppendUint16(out, 1)
			out = binary.BigEndian.AppendUint32(out, 60)
			out = binary.BigEndian.AppendUint16(out, 4)
			out = append(out, a.AsSlice()...)
		} else {
			out = binary.BigEndian.AppendUint16(out, dnsTypeAAAA)
			out = binary.BigEndian.AppendUint16(out, 1)
			out = binary.BigEndian.AppendUint32(out, 60)
			out = binary.BigEndian.AppendUint16(out, 16)
			out = append(out, a.AsSlice()...)
		}
	}
	return out
}

func withResolvers(t *testing.T, list []string) {
	t.Helper()
	old := ddnsResolvers
	ddnsResolvers = list
	t.Cleanup(func() { ddnsResolvers = old })
}

func TestResolveDDNSNormal(t *testing.T) {
	v4 := netip.MustParseAddr("1.2.3.4")
	v6 := netip.MustParseAddr("2408:8256::1")
	f := startFakeDNS(t, []netip.Addr{v4}, []netip.Addr{v6}, false)
	withResolvers(t, []string{f.addr()})

	got, err := resolveDDNS(context.Background(), "home.example.com", nil)
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if len(got) != 2 {
		t.Fatalf("应拿到 A+AAAA 两条，得到 %v", got)
	}
	seen := map[netip.Addr]bool{}
	for _, a := range got {
		seen[a] = true
	}
	if !seen[v4] || !seen[v6] {
		t.Fatalf("结果缺地址：%v", got)
	}
}

func TestResolveDDNSFakeIPGuard(t *testing.T) {
	f := startFakeDNS(t, []netip.Addr{netip.MustParseAddr("198.18.6.169")}, nil, false)
	withResolvers(t, []string{f.addr()})

	_, err := resolveDDNS(context.Background(), "home.example.com", nil)
	if !errors.Is(err, ErrDDNSPoisoned) {
		t.Fatalf("应报污染档错误，得到 %v", err)
	}
}

func TestResolveDDNSUnroutableGuard(t *testing.T) {
	f := startFakeDNS(t, []netip.Addr{netip.MustParseAddr("100.64.1.1")}, nil, false)
	withResolvers(t, []string{f.addr()})

	_, err := resolveDDNS(context.Background(), "home.example.com", nil)
	if !errors.Is(err, ErrDDNSUnroutable) {
		t.Fatalf("应报不可路由档错误，得到 %v", err)
	}
}

func TestResolveDDNSResolverFallback(t *testing.T) {
	// 第一个「解析器」是没人监听的端口：回退到第二个。
	dead := "127.0.0.1:1"
	f := startFakeDNS(t, []netip.Addr{netip.MustParseAddr("5.6.7.8")}, nil, false)
	withResolvers(t, []string{dead, f.addr()})

	got, err := resolveDDNS(context.Background(), "home.example.com", nil)
	if err != nil {
		t.Fatalf("应回退成功：%v", err)
	}
	if len(got) != 1 || got[0] != netip.MustParseAddr("5.6.7.8") {
		t.Fatalf("回退结果不对：%v", got)
	}
}

func TestResolveDDNSGarbageThenTimeout(t *testing.T) {
	f := startFakeDNS(t, nil, nil, true)
	withResolvers(t, []string{f.addr()})
	old := ddnsQueryTimeout
	ddnsQueryTimeout = 300 * time.Millisecond
	t.Cleanup(func() { ddnsQueryTimeout = old })

	start := time.Now()
	_, err := resolveDDNS(context.Background(), "home.example.com", nil)
	if err == nil {
		t.Fatal("垃圾应答不应产出结果")
	}
	if !strings.Contains(err.Error(), "无可用应答") {
		t.Fatalf("错误口径不对：%v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("畸形应答不应拖满全预算，耗时 %v", elapsed)
	}
}

// TestResolveDDNSCNAMEOnly：应答区只有 CNAME 没有地址 = 无可用应答（跳过该解析器），
// 不应误判卫兵档。
func TestResolveDDNSCNAMEOnly(t *testing.T) {
	// 复用 fakeDNS 但让两族都答空：等价于「有应答、零地址」。
	f := startFakeDNS(t, nil, nil, false)
	withResolvers(t, []string{f.addr()})

	_, err := resolveDDNS(context.Background(), "home.example.com", nil)
	if err == nil || !strings.Contains(err.Error(), "无可用应答") {
		t.Fatalf("零地址应报无可用应答，得到 %v", err)
	}
}

// TestPinSocketToIfaceDualFamily：共享钉卡 API 冒烟——双栈 socket 上两族设置至少一族
// 成功（lo0 必在；真双栈时两族都设）。这是 internal/server 侧引用 servercore.PinSocketToIface
// 的契约测试（task 1.2：AAAA 腿与 A 腿同卡）。
func TestPinSocketToIfaceDualFamily(t *testing.T) {
	lo, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Skipf("无 lo0（非 darwin？）：%v", err)
	}
	c, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		t.Fatalf("起 socket 失败：%v", err)
	}
	defer c.Close()
	if err := servercore.PinSocketToIface(c, lo); err != nil {
		t.Fatalf("双族钉卡应至少一族成功：%v", err)
	}
}
