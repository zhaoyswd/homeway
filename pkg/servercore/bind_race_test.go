package servercore

// bind_race_test.go — 2026-09-21 深度评审整改的对抗性回归（组 1）。
//
//	#1  srcSeen 并发写（致命：concurrent map writes 会带走整个 homewayd）
//	#8  腿读循环退出即摘腿（不依赖空闲扫描）
//	#17 腿摘除后 Send 不得回落主 socket
//	#38 Close 幂等；收工后 RegisterLeg no-op

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// TestSrcSeenConcurrentTwoPaths：模拟 Open 返回的两条 ReceiveFunc 各自的 goroutine
// 并发调用 processPacket（内部都会走 noteNewSrc 写 srcSeen）。
// 修复前：`go test -race` 在这里报 DATA RACE；无 -race 的并发压测会
// `fatal error: concurrent map writes` 直接中止进程。
func TestSrcSeenConcurrentTwoPaths(t *testing.T) {
	b := &ServerBind{Logf: func(f string, a ...any) {}}
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	base := netip.MustParseAddr("127.0.0.1")
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			packets := make([][]byte, 1)
			packets[0] = make([]byte, 65535)
			sizes := make([]int, 1)
			eps := make([]conn.Endpoint, 1)
			// 首字节 4 = WG 传输数据：走「直连裸 WG」分支（两条接收路径共用的最热路径）。
			pkt := []byte{4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				127, 0, 0, 1, 127, 0, 0, 1, 0, 53, 0, 53, 0, 0}
			for i := 0; i < 300; i++ {
				src := netip.AddrPortFrom(base, uint16(20000+g*1000+i))
				if n, err := b.processPacket(packets, sizes, eps, pkt, src); err != nil || n != 1 {
					t.Errorf("processPacket: n=%d err=%v", n, err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	b.srcMu.Lock()
	defer b.srcMu.Unlock()
	if len(b.srcSeen) < 1200 {
		t.Fatalf("新源记录不全：%d（4×300 个不同源应全部入表）", len(b.srcSeen))
	}
}

// TestSendDropsAfterLegRemoved（#17）：腿被摘除后，向该端点的 Send 必须丢弃——
// 修复前会从主 socket 发出，打到中继主口/被复用的数据口。对照组：从未当过腿的
// 未知地址照常走主 socket（普通直连客户端不受影响）。
func TestSendDropsAfterLegRemoved(t *testing.T) {
	relayData, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relayData.Close()
	remote := relayData.LocalAddr().(*net.UDPAddr).AddrPort()

	b := &ServerBind{Logf: func(f string, a ...any) {}}
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	if err := b.RegisterLeg(7, remote, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // 等读协程起跑（RegisterLeg 返回即已入表）
	// 排空腿建立的 LEGUP 标记（它会留在 listener 缓冲里干扰断言）。
	_ = relayData.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	drain := make([]byte, 128)
	for {
		if _, _, rerr := relayData.ReadFromUDP(drain); rerr != nil {
			break
		}
	}
	b.RemoveLeg(7)

	if err := b.Send([][]byte{[]byte("must-drop")}, srvEP{remote}); err != nil {
		t.Fatal(err)
	}
	_ = relayData.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 128)
	if n, _, rerr := relayData.ReadFromUDP(buf); rerr == nil {
		t.Fatalf("摘腿后包仍到达中继数据口（%d 字节）——Send 回落了主 socket", n)
	}
	if b.legDropped.Load() == 0 {
		t.Fatal("丢弃计数没有增长（观测面缺失）")
	}

	// 对照：普通未知端点仍走主 socket（不能把「回不到腿」扩大成「谁都发不出去」）。
	// 注意判据是"**这个端口曾当过腿**"（精确到端口，不是整个中继主机）：所以对照组可以
	// 用同一个主机的另一个端口——它从没当过腿，必须照常从主 socket 发出去。
	other, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	otherAP := other.LocalAddr().(*net.UDPAddr).AddrPort()
	if err := b.Send([][]byte{[]byte("plain-direct")}, srvEP{otherAP}); err != nil {
		t.Fatal(err)
	}
	_ = other.SetReadDeadline(time.Now().Add(time.Second))
	if n, _, rerr := other.ReadFromUDP(buf); rerr != nil {
		t.Fatalf("普通未知端点的发送被误丢：%v", rerr)
	} else if string(buf[:n]) != "plain-direct" {
		t.Fatalf("对照包内容不对：%q", buf[:n])
	}
}

// TestLegReadLoopRemovesDeadLeg（#8）：对端端口消失（ICMP 拒绝）让读循环退出，
// 腿必须随即被摘除——修复前 Send 会一直刷新 last，空闲扫描永远扫不掉死腿。
func TestLegReadLoopRemovesDeadLeg(t *testing.T) {
	// 占一个端口然后立刻关掉：腿拨过去的第一发（LEGUP）会招来 ICMP port unreachable，
	// connected UDP socket 的下一次 Read 返回 ECONNREFUSED。
	ghost, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	remote := ghost.LocalAddr().(*net.UDPAddr).AddrPort()
	ghost.Close()

	b := &ServerBind{Logf: func(f string, a ...any) {}}
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.RegisterLeg(9, remote, nil); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		b.legMu.Lock()
		gone := b.legByID[9] == nil
		b.legMu.Unlock()
		if gone {
			return // 读循环退出并自摘 ✓
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("死腿（读循环已退出）3s 后仍在腿表里——摘除只靠空闲扫描")
}

// TestCloseIdempotentAndRegisterAfterClose（#38）：并发/重复 Close 不 panic；
// 收工后 RegisterLeg 拒绝且不留表项。
func TestCloseIdempotentAndRegisterAfterClose(t *testing.T) {
	b := &ServerBind{Logf: func(f string, a ...any) {}}
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = b.Close() }()
	}
	wg.Wait()
	_ = b.Close()

	ap := netip.MustParseAddrPort("127.0.0.1:19999")
	if err := b.RegisterLeg(1, ap, nil); err == nil {
		t.Fatal("收工后 RegisterLeg 应返回错误（no-op 语义）")
	}
	b.legMu.Lock()
	n := len(b.legByID)
	b.legMu.Unlock()
	if n != 0 {
		t.Fatalf("收工后的注册留下了 %d 条腿", n)
	}
}

// TestMainSocketReceiveSurvivesNonCloseErrors 主 socket ReceiveFunc 的「非收工类读
// 错误不交回 wg-go」契约（与 tier 仓 wtransport.Bind 同病同修，2026-09-23）：注入
// 2 次 ENETDOWN 类错误期间 fn 不返回；之后真实收包恢复；Close 后带错误返回（收工
// 语义不变）。
func TestMainSocketReceiveSurvivesNonCloseErrors(t *testing.T) {
	var logs []string
	b := &ServerBind{Logf: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }}
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	fn := fns[0]

	deadErr := &net.OpError{Op: "read", Net: "udp", Err: syscall.ENETDOWN}
	var calls atomic.Int32
	b.readFromMu.Lock()
	b.readFrom = func(c *net.UDPConn, buf []byte) (int, netip.AddrPort, error) {
		if calls.Add(1) <= 2 {
			return 0, netip.AddrPort{}, deadErr
		}
		return c.ReadFromUDPAddrPort(buf)
	}
	b.readFromMu.Unlock()

	packets := make([][]byte, 1)
	packets[0] = make([]byte, 1500)
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)

	type res struct {
		n   int
		err error
	}
	done := make(chan res, 1)
	go func() {
		n, err := fn(packets, sizes, eps)
		done <- res{n, err}
	}()
	select {
	case r := <-done:
		t.Fatalf("fn 在非收工类错误下返回了（n=%d err=%v）", r.n, r.err)
	case <-time.After(600 * time.Millisecond):
	}

	// 真实收包恢复
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("peer: %v", err)
	}
	defer peer.Close()
	port := b.LocalPort()
	if _, err := peer.WriteToUDP([]byte("ok"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)}); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case r := <-done:
		if r.err != nil || r.n != 1 || string(packets[0][:sizes[0]]) != "ok" {
			t.Fatalf("未恢复收包：n=%d err=%v data=%q", r.n, r.err, packets[0][:sizes[0]])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("3s 内未恢复收包")
	}

	// 收工语义
	done2 := make(chan error, 1)
	go func() {
		_, err := fn(packets, sizes, eps)
		done2 <- err
	}()
	_ = b.Close()
	select {
	case err := <-done2:
		if err == nil {
			t.Fatal("Close 后 fn 应返回错误")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close 后 3s 未返回")
	}
	errLogs := 0
	for _, l := range logs {
		if strings.Contains(l, "读错误") {
			errLogs++
		}
	}
	if errLogs != 1 {
		t.Fatalf("读错误限流日志应恰 1 行，实际 %d：%v", errLogs, logs)
	}
}
