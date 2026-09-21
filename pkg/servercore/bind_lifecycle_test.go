package servercore

// bind_lifecycle_test.go — ServerBind 腿生命周期的回归（review 复审 a1）：
//
//	腿回收循环必须是**每世代一条**。此前 legInit 用 sync.Once 只起一次，而循环
//	看到"当前世代"的 dead 已关就 return ⇒ 第一次 Close→Open 之后回收循环永久消失：
//	空闲腿永不回收（socket+goroutine+64KB 泄漏）、legRecent 永不过期（#17 的 5 分钟
//	窗口变成永久），攒到 64 条后新会话再也拿不到腿（RegisterLeg 报"腿数已达上限"）。

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// idleUDPPort：一个"有人听、但永不回包"的 UDP 端口。腿 socket 是 connected UDP，
// 指向这里既不会触发 ICMP 拒绝（读循环不会自行退出），也不会打断回收循环的判据。
func idleUDPPort(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	ua := pc.LocalAddr().(*net.UDPAddr)
	ap, _ := netip.ParseAddrPort(ua.String())
	return ap
}

func waitLegGone(t *testing.T, b *ServerBind, id uint64, what string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		b.legMu.RLock()
		_, ok := b.legByID[id]
		b.legMu.RUnlock()
		if !ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	b.legMu.RLock()
	n, recent := len(b.legByID), len(b.legRecent)
	b.legMu.RUnlock()
	t.Fatalf("%s：腿 #%d 未被回收（legReapLoop 没在跑；legs=%d legRecent=%d）", what, id, n, recent)
}

func TestLegReapLoopSurvivesCloseOpenCycle(t *testing.T) {
	oldSweep, oldIdle := legSweepEvery, legIdleAfter
	legSweepEvery, legIdleAfter = 10*time.Millisecond, time.Millisecond
	defer func() { legSweepEvery, legIdleAfter = oldSweep, oldIdle }()

	b := &ServerBind{Logf: func(string, ...any) {}}
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	remote := idleUDPPort(t)

	// 第一世代：注册一条"立刻算空闲"的腿 → 必须被回收。
	if err := b.RegisterLeg(1, remote, []byte("LEGUP")); err != nil {
		t.Fatal(err)
	}
	waitLegGone(t, b, 1, "第一世代")

	// Close → Open（wireguard-go 的 BindUpdate 语义）→ 第二世代同样必须有回收循环。
	_ = b.Close()
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	if err := b.RegisterLeg(2, remote, []byte("LEGUP")); err != nil {
		t.Fatal(err)
	}
	waitLegGone(t, b, 2, "Close→Open 之后的第二世代")
	_ = b.Close()
}

func TestLegRecentSweptAfterReopen(t *testing.T) {
	oldSweep, oldIdle, oldRecent := legSweepEvery, legIdleAfter, legRecentAfter
	legSweepEvery, legIdleAfter, legRecentAfter = 10*time.Millisecond, time.Millisecond, 20*time.Millisecond
	defer func() { legSweepEvery, legIdleAfter, legRecentAfter = oldSweep, oldIdle, oldRecent }()

	b := &ServerBind{Logf: func(string, ...any) {}}
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	remote := idleUDPPort(t)
	if err := b.RegisterLeg(7, remote, []byte("LEGUP")); err != nil {
		t.Fatal(err)
	}
	b.RemoveLeg(7)
	b.legMu.RLock()
	_, inRecent := b.legRecent[remote]
	b.legMu.RUnlock()
	if !inRecent {
		t.Fatal("摘除的腿没进 legRecent（#17 的判定窗口失效）")
	}

	_ = b.Close()
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		b.legMu.RLock()
		n := len(b.legRecent)
		b.legMu.RUnlock()
		if n == 0 {
			_ = b.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("Close→Open 之后 legRecent 永不过期（回收循环没在跑）")
}
