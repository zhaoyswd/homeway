package speedtest

import (
	"bufio"
	"encoding/json"
	"net"
	"testing"
	"time"
)

// 起一个真实 TCP 服务（不用 net.Pipe：零缓冲，必须并发读才能写进——Go 流式测试三坑）。
func startServer(t *testing.T, lim Limits) (*Server, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	srv := NewServer(func(format string, args ...any) { t.Logf(format, args...) })
	srv.SetLimits(lim)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })
	return srv, ln.Addr().String()
}

func dial(t *testing.T, addr string) (net.Conn, *bufio.Reader, *bufio.Writer) {
	t.Helper()
	conn, br, bw := dialRaw(t, addr)
	// 服务端 accept 后恒先发问候（协议序：greeting → request）。
	if err := ReadGreeting(br); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	return conn, br, bw
}

// dialRaw：不消费问候的拨号（拒绝路径/坏流测试用）。
func dialRaw(t *testing.T, addr string) (net.Conn, *bufio.Reader, *bufio.Writer) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn, bufio.NewReader(conn), bufio.NewWriter(conn)
}

// 客户端 role=recv 读循环：数 data 载荷（只计窗口期——由调用方给的时刻门控），
// 直到 report。返回 (窗口内字节, 预热期字节, report)。
func readRecvStream(t *testing.T, br *bufio.Reader, windowStart time.Time) (int64, int64, Report) {
	t.Helper()
	var winBytes, warmBytes int64
	for {
		tt, _, payload, err := readFrame(br)
		if err != nil {
			t.Fatalf("读帧：%v", err)
		}
		switch tt {
		case TypeData:
			if time.Now().Before(windowStart) {
				warmBytes += int64(len(payload))
			} else {
				winBytes += int64(len(payload))
			}
		case TypeReport:
			var rep Report
			if err := json.Unmarshal(payload, &rep); err != nil {
				t.Fatalf("report 解析：%v", err)
			}
			return winBytes, warmBytes, rep
		default:
			t.Fatalf("下行期收到类型 %d", tt)
		}
	}
}

func TestRecvFlow(t *testing.T) {
	_, addr := startServer(t, Limits{})
	_, br, bw := dial(t, addr)

	warmup, window := 300*time.Millisecond, 500*time.Millisecond
	if err := WriteRequest(bw, RoleRecv, warmup, window); err != nil {
		t.Fatalf("request: %v", err)
	}
	if err := bw.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	// 客户端计时起点：请求发出后、预热尾端（把连接建立/预热都排除在窗口外，design D3）。
	winBytes, warmBytes, rep := readRecvStream(t, br, time.Now().Add(warmup-50*time.Millisecond))

	if rep.Error != "" {
		t.Fatalf("report.Error = %q", rep.Error)
	}
	if winBytes <= 0 {
		t.Fatalf("窗口内字节 = %d，应为正", winBytes)
	}
	if warmBytes <= 0 {
		t.Fatalf("预热期字节 = %d，应为正", warmBytes)
	}
	// 服务端报的窗口字节与客户端所数同量级（起点错开 ≤50ms，回环上速率可达 GB/s，
	// 绝对容差会随速率放大 ⇒ 按比例断言）。
	skew := rep.Bytes - winBytes
	if skew < 0 {
		skew = -skew
	}
	basis := rep.Bytes
	if winBytes > basis {
		basis = winBytes
	}
	if basis > 0 && skew*5 > basis { // 偏差 > 20% 才算不对账（500ms 窗允许 ~100ms 抖动）
		t.Fatalf("收发字节对账偏差过大：client=%d server=%d", winBytes, rep.Bytes)
	}
	if rep.WallMs < 400 {
		t.Fatalf("服务端窗口墙钟 %dms，应 ≥ 400", rep.WallMs)
	}
	t.Logf("client win=%dB warm=%dB; server win=%dB warm=%dB wall=%dms",
		winBytes, warmBytes, rep.Bytes, rep.WarmupBytes, rep.WallMs)
}

func TestSendFlow(t *testing.T) {
	_, addr := startServer(t, Limits{})
	_, br, bw := dial(t, addr)

	if err := WriteRequest(bw, RoleSend, 200*time.Millisecond, 400*time.Millisecond); err != nil {
		t.Fatalf("request: %v", err)
	}
	if err := bw.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	// 预热泵（服务端不计入窗口）。
	block := make([]byte, 32<<10)
	var seq uint32
	PumpData(bw, block, &seq, 200*time.Millisecond)
	if err := bw.Flush(); err != nil {
		t.Fatalf("flush 预热: %v", err)
	}
	// 窗口：START → 泵 → FINISH。
	WriteStart(bw)
	if err := bw.Flush(); err != nil {
		t.Fatalf("flush start: %v", err)
	}
	sent := PumpData(bw, block, &seq, 400*time.Millisecond)
	if err := bw.Flush(); err != nil {
		t.Fatalf("flush 窗口: %v", err)
	}
	WriteFinish(bw)
	if err := bw.Flush(); err != nil {
		t.Fatalf("flush finish: %v", err)
	}

	rep, err := ReadReport(br)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if rep.Bytes != sent {
		t.Fatalf("接收端报数 %d ≠ 客户端已发 %d（发送缓冲应已排空）", rep.Bytes, sent)
	}
	if rep.WarmupBytes <= 0 {
		t.Fatalf("服务端预热计数 %d，应为正", rep.WarmupBytes)
	}
	if rep.WallMs < 350 {
		t.Fatalf("窗口墙钟 %dms，应 ≥ 350", rep.WallMs)
	}
	t.Logf("server win=%dB warm=%dB wall=%dms", rep.Bytes, rep.WarmupBytes, rep.WallMs)
}

func TestConcurrencyLimit(t *testing.T) {
	srv, addr := startServer(t, Limits{MaxConns: 1})

	// 占住唯一名额：服务端在发、客户端慢慢读。
	_, br1, bw1 := dial(t, addr)
	if err := WriteRequest(bw1, RoleRecv, 200*time.Millisecond, 1200*time.Millisecond); err != nil {
		t.Fatalf("request1: %v", err)
	}
	if err := bw1.Flush(); err != nil {
		t.Fatalf("flush1: %v", err)
	}

	// 第二路应被拒：满员拒绝发生在问候之前，问候期直接拿到 busy。
	_, br2, bw2 := dialRaw(t, addr)
	if err := WriteRequest(bw2, RoleSend, 100*time.Millisecond, 100*time.Millisecond); err != nil {
		t.Fatalf("request2: %v", err)
	}
	if err := bw2.Flush(); err != nil {
		t.Fatalf("flush2: %v", err)
	}
	gerr := ReadGreeting(br2)
	if gerr == nil || gerr.Error() != "busy" {
		t.Fatalf("第二路问候应报 busy，got %v", gerr)
	}

	// 等第一路自然收尾，再连第三路应放行。
	_, _, rep1 := readRecvStream(t, br1, time.Now().Add(200*time.Millisecond-50*time.Millisecond))
	if rep1.Error != "" {
		t.Fatalf("第一路 report.Error = %q", rep1.Error)
	}
	_, br3, bw3 := dial(t, addr)
	if err := WriteRequest(bw3, RoleRecv, 100*time.Millisecond, 150*time.Millisecond); err != nil {
		t.Fatalf("request3: %v", err)
	}
	if err := bw3.Flush(); err != nil {
		t.Fatalf("flush3: %v", err)
	}
	if _, _, rep3 := readRecvStream(t, br3, time.Now().Add(50*time.Millisecond)); rep3.Error != "" {
		t.Fatalf("第三路 report.Error = %q", rep3.Error)
	}

	total, rejected := srv.Stats()
	if rejected != 1 {
		t.Fatalf("rejected = %d，应为 1", rejected)
	}
	if total != 2 {
		t.Fatalf("total = %d，应为 2（被拒连接不计入受理数）", total)
	}
}

func TestRequestValidation(t *testing.T) {
	_, addr := startServer(t, Limits{})
	cases := []struct {
		name             string
		role             Role
		warmup, window   time.Duration
		wantErrSubstring string
	}{
		{"窗口超上限", RoleRecv, time.Second, 30 * time.Second, "超出"},
		{"窗口过短", RoleRecv, time.Second, 10 * time.Millisecond, "超出"},
		{"未知角色", Role("fast"), time.Second, time.Second, "未知角色"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, br, bw := dial(t, addr)
			if err := WriteRequest(bw, tc.role, tc.warmup, tc.window); err != nil {
				t.Fatalf("request: %v", err)
			}
			if err := bw.Flush(); err != nil {
				t.Fatalf("flush: %v", err)
			}
			rep, err := ReadReport(br)
			if err != nil && rep.Error == "" {
				t.Fatalf("期望 report 内错误，got err=%v", err)
			}
			if rep.Error == "" {
				t.Fatalf("期望错误 report，got %+v", rep)
			}
			if !contains(rep.Error, tc.wantErrSubstring) {
				t.Fatalf("错误 %q 不含 %q", rep.Error, tc.wantErrSubstring)
			}
		})
	}
}

// TestServeOverUnixSocket：UDS 承载全链路（serve.go 的 listenLocalService 对 Serve 透明，
// 这里用真实 UDS listener 钉住「socket 文件承载」这条生产路径）。
func TestServeOverUnixSocket(t *testing.T) {
	dir := t.TempDir()
	ln, err := net.Listen("unix", dir+"/speedtest.sock")
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	srv := NewServer(nil)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close(); ln.Close() })

	conn, err := net.Dial("unix", dir+"/speedtest.sock")
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	defer conn.Close()
	br, bw := bufio.NewReader(conn), bufio.NewWriter(conn)
	if err := ReadGreeting(br); err != nil {
		t.Fatalf("greeting: %v", err)
	}

	// 一轮 send（上行方向）在 UDS 上跑通：预热 → START → 泵 → FINISH → report 对账。
	if err := WriteRequest(bw, RoleSend, 100*time.Millisecond, 200*time.Millisecond); err != nil {
		t.Fatalf("request: %v", err)
	}
	if err := bw.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	block := make([]byte, 8<<10)
	var seq uint32
	PumpData(bw, block, &seq, 100*time.Millisecond)
	_ = bw.Flush()
	WriteStart(bw)
	_ = bw.Flush()
	sent := PumpData(bw, block, &seq, 200*time.Millisecond)
	_ = bw.Flush()
	WriteFinish(bw)
	_ = bw.Flush()

	rep, err := ReadReport(br)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if rep.Error != "" || rep.Bytes != sent {
		t.Fatalf("UDS 载荷对账失败：rep=%+v sent=%d", rep, sent)
	}
}

func TestCorruptMagic(t *testing.T) {
	_, addr := startServer(t, Limits{})
	conn, _, bw := dial(t, addr)
	// 首帧魔数错 ⇒ 服务端丢弃连接（读请求帧失败路径），不回 report 也不崩。
	bad := []byte("NOTSPEEDTEST...")
	bad[0] = 'X'
	if _, err := bw.Write(bad); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := bw.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	// 服务端会先发问候再读请求失败关连接：读到问候是合法的，之后必须以 EOF/错误收场。
	buf := make([]byte, 64)
	for {
		_, err := conn.Read(buf)
		if err != nil {
			break // EOF/复位 = 连接已关（期望行为）
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
