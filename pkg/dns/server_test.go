package dns

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// fakeUpstream：本地 UDP fake 上游（handler 返回应答；nil = 不应答）。
// 可选 TC 模式：handler 返回的应答置 TC 位时，若配了 tcpResp 则客户端应经 TCP 拿到它。
type fakeUpstream struct {
	udp *net.UDPConn
	tcp *net.TCPListener
	hit atomic.Int32
}

func startFakeUpstream(t *testing.T, handler func(query []byte) []byte) *fakeUpstream {
	return startFakeUpstreamTCP(t, handler, nil)
}

// startFakeUpstreamTCP：UDP handler 之外可选挂 TCP handler（TC→TCP 链路测试用）。
// 上游地址的 UDP/TCP 同端口（resolv 上游的真实形态）。
func startFakeUpstreamTCP(t *testing.T, handler func(query []byte) []byte, tcpHandler func(query []byte) []byte) *fakeUpstream {
	t.Helper()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeUpstream{udp: udp}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			q := append([]byte(nil), buf[:n]...)
			f.hit.Add(1)
			if resp := handler(q); resp != nil {
				udp.WriteToUDP(resp, addr)
			}
		}
	}()
	t.Cleanup(func() { udp.Close() })
	if tcpHandler != nil {
		ua := udp.LocalAddr().(*net.UDPAddr)
		tcp, err := net.ListenTCP("tcp", &net.TCPAddr{IP: ua.IP, Port: ua.Port})
		if err != nil {
			// UDP 随机端口的同号 TCP 极小概率被别的进程占用（review3 低）：skip 而不是红
			t.Skipf("fake 上游的 TCP 端口 %d 被占（罕见冲突），跳过", ua.Port)
		}
		f.tcp = tcp
		go func() {
			for {
				conn, err := tcp.Accept()
				if err != nil {
					return
				}
				go func(conn net.Conn) {
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
					q, err := readTCPMessage(conn)
					if err != nil {
						return
					}
					if resp := tcpHandler(q); resp != nil {
						writeTCPMessage(conn, resp)
					}
				}(conn)
			}
		}()
		t.Cleanup(func() { tcp.Close() })
	}
	return f
}

// udpQuery 向代答发一条 UDP 查询并等应答。
func udpQuery(t *testing.T, server string, query []byte, wait time.Duration) []byte {
	t.Helper()
	c, err := net.DialTimeout("udp", server, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(wait))
	if _, err := c.Write(query); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

// newTestServer：随机端口 + 指定 resolv 内容 + 可注入兜底。
func newTestServer(t *testing.T, resolv string, fallback string) *Server {
	t.Helper()
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte(resolv), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Listen(Config{
		Addr:        "127.0.0.1:0",
		ResolvPath:  path,
		FallbackDNS: fallback,
		Budget:      time.Second,
		Logf:        func(string, ...any) {},
		DLogf:       func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestServerForwardAndClampTTL(t *testing.T) {
	up := startFakeUpstream(t, func(q []byte) []byte {
		return buildResponse(q, 0, 7193)
	})
	s := newTestServer(t, "nameserver 127.0.0.1:"+portOf(t, up.udp.LocalAddr()), "127.0.0.1:1")
	q := buildQuery(0x1234, "example.com", 1)
	resp := udpQuery(t, s.Addr(), q, 2*time.Second)
	if binary.BigEndian.Uint16(resp[0:2]) != 0x1234 {
		t.Fatal("ID 应回显原值")
	}
	if binary.BigEndian.Uint16(resp[6:8]) != 1 {
		t.Fatalf("应有 1 条答案, got %d", binary.BigEndian.Uint16(resp[6:8]))
	}
	// TTL 7193 钳到 60（第一条记录 TTL 在 header+question 之后 18+6）
	qd := questionEnd(resp)
	if got := binary.BigEndian.Uint32(resp[qd+6 : qd+10]); got != 60 {
		t.Fatalf("TTL 应钳到 60, got %d", got)
	}
	if up.hit.Load() != 1 {
		t.Fatalf("上游应被打一次, got %d", up.hit.Load())
	}
}

func TestServerFilter(t *testing.T) {
	up := startFakeUpstream(t, func(q []byte) []byte {
		t.Error("过滤查询不应到达上游")
		return nil
	})
	s := newTestServer(t, "nameserver 127.0.0.1:"+portOf(t, up.udp.LocalAddr()), "127.0.0.1:1")
	for _, qt := range []uint16{28, 65, 64, 255} {
		resp := udpQuery(t, s.Addr(), buildQuery(9, "x.example", qt), time.Second)
		if binary.BigEndian.Uint16(resp[6:8]) != 0 {
			t.Fatalf("qtype %d 应空应答", qt)
		}
		if resp[3]&0x0F != 0 {
			t.Fatalf("qtype %d 应 NOERROR", qt)
		}
	}
	if s.filtered.Load() != 4 {
		t.Fatalf("filter 计数应为 4, got %d", s.filtered.Load())
	}
}

func TestServerFallbackOnlyOnConnFailure(t *testing.T) {
	fb := startFakeUpstream(t, func(q []byte) []byte {
		return buildResponse(q, 0, 5)
	})
	// 主上游 = 死端口（连接层失败）→ 兜底应答
	s := newTestServer(t, "nameserver 127.0.0.1:1", "127.0.0.1:"+portOf(t, fb.udp.LocalAddr()))
	resp := udpQuery(t, s.Addr(), buildQuery(1, "fb.example", 1), 3*time.Second)
	if binary.BigEndian.Uint16(resp[6:8]) != 1 {
		t.Fatal("兜底应给答案")
	}
	if s.fallback.Load() == 0 {
		t.Fatal("fallback 计数应递增")
	}
}

func TestServerNXDOMAINNoFallback(t *testing.T) {
	nx := startFakeUpstream(t, func(q []byte) []byte {
		return buildResponse(q, 3) // NXDOMAIN
	})
	fb := startFakeUpstream(t, func(q []byte) []byte {
		return buildResponse(q, 0, 5) // 若被错误触发会给答案
	})
	s := newTestServer(t, "nameserver 127.0.0.1:"+portOf(t, nx.udp.LocalAddr()), "127.0.0.1:"+portOf(t, fb.udp.LocalAddr()))
	resp := udpQuery(t, s.Addr(), buildQuery(2, "nx.example", 1), 2*time.Second)
	if resp[3]&0x0F != 3 {
		t.Fatalf("NXDOMAIN 应透传, rcode=%d", resp[3]&0x0F)
	}
	if s.fallback.Load() != 0 {
		t.Fatal("否定应答绝不触发兜底")
	}
}

func TestServerServfailWhenAllDead(t *testing.T) {
	s := newTestServer(t, "nameserver 127.0.0.1:1", "127.0.0.1:2")
	resp := udpQuery(t, s.Addr(), buildQuery(3, "dead.example", 1), 5*time.Second)
	if resp[3]&0x0F != 2 {
		t.Fatalf("全死应 SERVFAIL, rcode=%d", resp[3]&0x0F)
	}
}

func TestServerConcurrentSameID(t *testing.T) {
	up := startFakeUpstream(t, func(q []byte) []byte {
		// 按 question 域名末字节给不同 IP，客户端可验证不串答
		name := q[13] // 第一个 label 长度后的首字节（单字符域名 a/b）
		r := buildResponse(q, 0, 5)
		r[len(r)-1] = name
		return r
	})
	s := newTestServer(t, "nameserver 127.0.0.1:"+portOf(t, up.udp.LocalAddr()), "127.0.0.1:1")
	const n = 20
	type res struct {
		id int
		ip byte
	}
	out := make(chan res, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			q := buildQuery(0x00FF, string(rune('a'+i%26))+".example", 1) // 全部同 ID
			resp := udpQuery(t, s.Addr(), q, 3*time.Second)
			qd := questionEnd(resp)
			out <- res{int(binary.BigEndian.Uint16(resp[0:2])), resp[qd+15]} // RDATA 末字节
		}(i)
	}
	for i := 0; i < n; i++ {
		r := <-out
		if r.id != 0x00FF {
			t.Fatalf("ID 回显错误: %x", r.id)
		}
	}
}

func TestServerTruncatesLargeResponse(t *testing.T) {
	up := startFakeUpstream(t, func(q []byte) []byte {
		r := buildResponse(q, 0, make([]uint32, 200)...) // 200 条 ≈ 3.6KB
		return r
	})
	s := newTestServer(t, "nameserver 127.0.0.1:"+portOf(t, up.udp.LocalAddr()), "127.0.0.1:1")
	resp := udpQuery(t, s.Addr(), buildQuery(4, "big.example", 1), 2*time.Second)
	if len(resp) > 1232 {
		t.Fatalf("超限应截断, got %d", len(resp))
	}
	if resp[2]&0x02 == 0 {
		t.Fatal("应置 TC 位")
	}
}

func TestServerMalformedNoPanic(t *testing.T) {
	up := startFakeUpstream(t, func(q []byte) []byte {
		return buildResponse(q, 0, 5)
	})
	s := newTestServer(t, "nameserver 127.0.0.1:"+portOf(t, up.udp.LocalAddr()), "127.0.0.1:1")
	c, _ := net.Dial("udp", s.Addr())
	c.Write([]byte{})
	c.Write([]byte{0xFF, 0xFF, 0xFF})
	c.Close()
	// server 仍正常服务
	resp := udpQuery(t, s.Addr(), buildQuery(5, "alive.example", 1), 2*time.Second)
	if binary.BigEndian.Uint16(resp[6:8]) != 1 {
		t.Fatal("畸形包后应继续正常应答")
	}
}

func TestServerSelfCheck(t *testing.T) {
	up := startFakeUpstream(t, func(q []byte) []byte {
		return buildResponse(q, 3) // NXDOMAIN 也证明链路活着
	})
	s := newTestServer(t, "nameserver 127.0.0.1:"+portOf(t, up.udp.LocalAddr()), "127.0.0.1:1")
	if err := s.SelfCheck(); err != nil {
		t.Fatalf("自验证应通过: %v", err)
	}
}

func TestServerTCPClient(t *testing.T) {
	up := startFakeUpstream(t, func(q []byte) []byte {
		return buildResponse(q, 0, 33)
	})
	s := newTestServer(t, "nameserver 127.0.0.1:"+portOf(t, up.udp.LocalAddr()), "127.0.0.1:1")
	conn, err := net.Dial("tcp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	q := buildQuery(6, "tcp.example", 1)
	if err := writeTCPMessage(conn, q); err != nil {
		t.Fatal(err)
	}
	resp, err := readTCPMessage(conn)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(resp[0:2]) != 6 || binary.BigEndian.Uint16(resp[6:8]) != 1 {
		t.Fatal("TCP 客户端应拿到正确应答")
	}
}

func portOf(t *testing.T, a net.Addr) string {
	t.Helper()
	_, port, err := net.SplitHostPort(a.String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// questionEnd 返回应答里 question 段结束偏移（第一条 RR 起点）。
func questionEnd(resp []byte) int {
	off, _ := skipName(resp, 12)
	return off + 4
}

// review H1+H2：TC→TCP 链路——UDP 上游置 TC、TCP 上游给全量，客户端经代答
// 的 TCP 路径拿到完整应答（且 TCP 上游收到的必须是 QR=0 的查询报文）。
func TestServerTCToTCPFullResponse(t *testing.T) {
	var tcpSawQuery [1]byte
	up := startFakeUpstreamTCP(t,
		func(q []byte) []byte {
			r := buildResponse(q, 0, 60)
			r[2] |= 0x02 // TC=1：UDP 腿只给一条 + 截断标记
			return r
		},
		func(q []byte) []byte {
			tcpSawQuery[0] = q[2] & 0x80 // QR 位：查询必须是 0
			return buildResponse(q, 0, make([]uint32, 200)...)
		})
	s := newTestServer(t, "nameserver 127.0.0.1:"+portOf(t, up.udp.LocalAddr()), "127.0.0.1:1")
	conn, err := net.Dial("tcp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	q := buildQuery(7, "tc.example", 1)
	if err := writeTCPMessage(conn, q); err != nil {
		t.Fatal(err)
	}
	resp, err := readTCPMessage(conn)
	if err != nil {
		t.Fatal(err)
	}
	if tcpSawQuery[0] != 0 {
		t.Fatal("TCP 上游收到的必须是查询报文（QR=0），不是应答——H1 回归")
	}
	if binary.BigEndian.Uint16(resp[6:8]) != 200 {
		t.Fatalf("TCP 路径应拿到全量 200 条, got %d", binary.BigEndian.Uint16(resp[6:8]))
	}
	if resp[2]&0x02 != 0 {
		t.Fatal("全量应答不应再置 TC——H2 回归")
	}
}

// review F1：静默黑洞上游（收包不回）不能吃干总预算——兜底必须有机会命中。
func TestServerFallbackOnSilentUpstream(t *testing.T) {
	silent := startFakeUpstream(t, func(q []byte) []byte {
		return nil // 收包不回：代理残留死指向的典型形态（慢失败）
	})
	fb := startFakeUpstream(t, func(q []byte) []byte {
		return buildResponse(q, 0, 5)
	})
	start := time.Now()
	s := newTestServer(t, "nameserver 127.0.0.1:"+portOf(t, silent.udp.LocalAddr()), "127.0.0.1:"+portOf(t, fb.udp.LocalAddr()))
	resp := udpQuery(t, s.Addr(), buildQuery(8, "slow.example", 1), 5*time.Second)
	if binary.BigEndian.Uint16(resp[6:8]) != 1 {
		t.Fatal("静默上游后兜底应命中")
	}
	if s.fallback.Load() == 0 {
		t.Fatal("fallback 计数应递增（F1：预算被吃干则永远到不了这里）")
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("兜底应在总预算内命中, took %v", el)
	}
}

// review M2：SelfCheck 的失败路径必须真实可达（上游全死 → 返回 error）。
func TestSelfCheckFailsWhenAllDead(t *testing.T) {
	s := newTestServer(t, "nameserver 127.0.0.1:1", "127.0.0.1:2")
	if err := s.SelfCheck(); err == nil {
		t.Fatal("上游全死时自验证必须失败（老实现恒过的回归）")
	}
}

// review M1：authority/additional 段的普通 RR 也要钳制（ARCOUNT≥2 的尾部漏钳回归）。
func TestClampTTLMultiSection(t *testing.T) {
	q := buildQuery(11, "multi.example", 1)
	r := buildResponse(q, 0, 7193)
	// additional 段：一条 OPT（type 41，TTL 位是 flags，不可动）+ 一条 A（TTL 999）
	qd := questionEnd(r)
	ar := make([]byte, 0, 32)
	opt := make([]byte, 11) // name(0)+type(41)+class(512)+ttl(0)+rdlen(0)
	binary.BigEndian.PutUint16(opt[1:3], 41)
	ar = append(ar, opt...)
	a := make([]byte, 16)
	binary.BigEndian.PutUint16(a[0:2], 0xC00C)
	binary.BigEndian.PutUint16(a[2:4], 1)
	binary.BigEndian.PutUint16(a[10:12], 4)
	binary.BigEndian.PutUint32(a[6:10], 999)
	ar = append(ar, a...)
	r = append(r, ar...)
	binary.BigEndian.PutUint16(r[10:12], 2) // ARCOUNT=2
	n := ClampTTL(r, 60)
	if n != 2 { // AN 的 7193 + AR 的 999；OPT 不算
		t.Fatalf("应钳制 2 条（AN+AR），OPT 除外, got %d", n)
	}
	if got := binary.BigEndian.Uint32(r[qd+6 : qd+10]); got != 60 {
		t.Fatalf("AN TTL 应钳到 60, got %d", got)
	}
	arStart := qd + 16
	if got := binary.BigEndian.Uint32(r[arStart+11+6 : arStart+11+10]); got != 60 {
		t.Fatalf("AR 的 A 记录 TTL 应钳到 60（M1 回归：尾部 additional 漏钳）, got %d", got)
	}
}

// review3 中3（D5 新语义）：上游 TCP 腿失败 → 客户端拿到 TC 保持的 UDP 应答。
func TestServerTCPFailFallsBackToTC(t *testing.T) {
	up := startFakeUpstreamTCP(t,
		func(q []byte) []byte {
			r := buildResponse(q, 0, 60)
			r[2] |= 0x02 // UDP 腿：1 条 + TC
			return r
		},
		func(q []byte) []byte {
			return nil // TCP 腿收包不应答（tarpit 形态；拨号成功但读超时）
		})
	s := newTestServer(t, "nameserver 127.0.0.1:"+portOf(t, up.udp.LocalAddr()), "127.0.0.1:1")
	resp := udpQuery(t, s.Addr(), buildQuery(9, "fbtc.example", 1), 5*time.Second)
	if resp[2]&0x02 == 0 {
		t.Fatal("TCP 腿失败应回 TC 保持的 UDP 应答")
	}
	if got := binary.BigEndian.Uint16(resp[6:8]); got != 1 {
		t.Fatalf("应保留 UDP 腿的 1 条答案, got %d", got)
	}
}

// review3 中1 锁定：主上游静默 + 兜底可用（应答 ~1.6s）时 SelfCheck 必须通过
// （期限 ≥ 代答预算；1s 期限会在这种真实故障场景打假告警）。
func TestSelfCheckPassesWithSlowPath(t *testing.T) {
	silent := startFakeUpstream(t, func(q []byte) []byte { return nil })
	fb := startFakeUpstream(t, func(q []byte) []byte { return buildResponse(q, 0, 5) })
	s := newTestServer(t, "nameserver 127.0.0.1:"+portOf(t, silent.udp.LocalAddr()), "127.0.0.1:"+portOf(t, fb.udp.LocalAddr()))
	if err := s.SelfCheck(); err != nil {
		t.Fatalf("慢路径（静默主上游+兜底）下自验证应通过: %v", err)
	}
}

// review M5：TCP 客户端连接上限 + Close 收线（均注入缩短）。
func TestServerTCPCapAndClose(t *testing.T) {
	up := startFakeUpstream(t, func(q []byte) []byte { return buildResponse(q, 0, 5) })
	path := filepath.Join(t.TempDir(), "resolv.conf")
	os.WriteFile(path, []byte("nameserver 127.0.0.1:"+portOf(t, up.udp.LocalAddr())+"\n"), 0o644)
	s, err := Listen(Config{
		Addr: "127.0.0.1:0", ResolvPath: path, FallbackDNS: "127.0.0.1:1",
		Budget: time.Second, MaxTCPConns: 2,
		Logf: func(string, ...any) {}, DLogf: func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	dial := func() net.Conn {
		c, err := net.Dial("tcp", s.Addr())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c1, c2 := dial(), dial()
	defer c1.Close()
	defer c2.Close()
	c3 := dial() // 超上限：accept 后即被关。写可能仍进本地缓冲（TCP 半关闭语义），
	// 判据用「读不到应答」（FIN/RST 到达）。
	_ = c3.SetDeadline(time.Now().Add(2 * time.Second))
	_ = writeTCPMessage(c3, buildQuery(1, "cap.example", 1))
	if _, err := readTCPMessage(c3); err == nil {
		t.Fatal("第 3 条连接应被上限拒绝（读不到应答）")
	}
	c3.Close()
	// Close 收线：已 accept 的连接（c1）随 Server.Close 断开
	s.Close()
	c1.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	if _, err := c1.Read(buf); err == nil {
		t.Fatal("Close 后已 accept 的连接应被断开")
	}
}
