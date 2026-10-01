package intercept

// intercept_drain_test.go — Drain 的有界宽限收尾（role-management 2.1，design D5 /
// r1 中-5）：两条假过境连接用例——宽限内自然收（销账、不 RST）/ 超时收 RST
// （登记逐条 SetLinger(0)）。上游 conn 用包装器记录 SetLinger 调用（真 *
// net.TCPConn 的 RST 只能从对端观察，包装器让断言直接落在收口动作上）。

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// lingerConn：包一层真实 TCP conn，记录 SetLinger 调用（Sec 值留存）。
type lingerConn struct {
	net.Conn
	lingerCalls atomic.Int32
	lastLinger  atomic.Int32
}

func (c *lingerConn) SetLinger(sec int) error {
	c.lingerCalls.Add(1)
	c.lastLinger.Store(int32(sec))
	return c.Conn.(lingerSetter).SetLinger(sec)
}

// waitRegistered：等拦截层把过境连接登记进宽限表（dialok 行即登记后打印）。
func waitRegistered(t *testing.T, h *harness) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if h.in.regLen() > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("过境连接未登记进宽限表")
}

// drainHarness：transit TCP 连一条（拨 foreignDst:443，Dial 注入指到回显服务并
// 包 lingerConn）；返回客户端侧 conn 与包装的上游。
func drainHarness(t *testing.T) (net.Conn, *lingerConn, *harness) {
	t.Helper()
	echo := echoTCP(t)
	var upstream *lingerConn
	h := newHarness(t, func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		c, err := d.DialContext(ctx, network, echo.String())
		if err != nil {
			return nil, err
		}
		wrapped := &lingerConn{Conn: c}
		upstream = wrapped
		return wrapped, nil
	})
	c, err := h.cli.DialTCPAddrPort(netip.MustParseAddrPort(foreignDst + ":443"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if got := roundtrip(t, c, "ping-drain"); got != "ping-drain" {
		t.Fatalf("echo = %q", got)
	}
	if upstream == nil {
		t.Fatal("上游包装 conn 未建立")
	}
	return c, upstream, h
}

// 宽限内自然收：客户端 FIN → 拦截层秒级收工销账 → Drain 立即返回 0、零 RST。
func TestDrainGraceNaturalClose(t *testing.T) {
	c, upstream, h := drainHarness(t)
	defer h.dumpLogs(t)
	waitRegistered(t, h)
	c.Close() // 客户端先收（FIN 半关闭传播 → bridgeConns 退出 → 销账）
	rst := make(chan int, 1)
	go func() { rst <- h.in.Drain(3 * time.Second) }()
	select {
	case n := <-rst:
		if n != 0 {
			t.Fatalf("自然收场景到期仍在途 = %d，期望 0", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("自然收场景 Drain 不应等到宽限耗尽")
	}
	if upstream.lingerCalls.Load() != 0 {
		t.Fatalf("自然收不得 RST（SetLinger 调用 %d 次）", upstream.lingerCalls.Load())
	}
}

// 超时收 RST：连接保持打开 → 宽限耗尽 → 按登记 SetLinger(0) + Close（返回 1）。
func TestDrainTimeoutRST(t *testing.T) {
	c, upstream, h := drainHarness(t)
	defer h.dumpLogs(t)
	waitRegistered(t, h)
	rst := make(chan int, 1)
	go func() { rst <- h.in.Drain(300 * time.Millisecond) }()
	select {
	case n := <-rst:
		if n != 1 {
			t.Fatalf("到期仍在途 = %d，期望 1", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Drain 未在宽限+ε内返回")
	}
	if upstream.lingerCalls.Load() == 0 || upstream.lastLinger.Load() != 0 {
		t.Fatalf("到期未收的过境连接应 SetLinger(0)（calls=%d last=%d）",
			upstream.lingerCalls.Load(), upstream.lastLinger.Load())
	}
	// 客户端侧最终感知断链（RST 上游 → 泵退出 → 下游关闭；读侧拿到错误/EOF）。
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := bufio.NewReader(c).ReadString('\n'); err == nil {
		t.Fatal("RST 收口后客户端读侧应见到断链")
	}
}

// Close 后的新流被拒（D5 步骤①：停新握手与新过境流）。
func TestDrainStopsNewFlows(t *testing.T) {
	h := newHarness(t, nil)
	defer h.dumpLogs(t)
	h.in.Drain(10 * time.Millisecond)
	if c, err := h.cli.DialTCPAddrPort(netip.MustParseAddrPort(foreignDst + ":443")); err == nil {
		c.Close()
	}
	// 拦截层不对新过境流重拨上游（Dial 零调用即证「新过境流被停」——netstack 侧
	// 的握手建端点与否是实现细节，出口侧观测面 = dial 不发生）。
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		h.dialMu.Lock()
		n := len(h.dialed)
		h.dialMu.Unlock()
		if n > 0 {
			t.Fatal("停用后仍发生了过境重拨")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
