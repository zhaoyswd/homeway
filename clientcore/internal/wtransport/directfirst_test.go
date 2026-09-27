package wtransport

// 直连优先（中继只作后备）的判据：
//  1. 新鲜赛跑：第一发出站包**只**打直连候选；窗口内直连无响应才解锁中继并补发；
//  2. 软赛跑（RearmSoft）：中继立即参与（用于"已在用中继、只想升直连"的时刻，不中断在用路径）；
//  3. 没有直连候选时不需要等（纯中继 token 场景）。

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// listenUDPv4 起一个收包 socket，返回地址与"收到包"的通道。
func listenUDPv4(t *testing.T) (netip.AddrPort, chan []byte) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan []byte, 16)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			cp := make([]byte, n)
			copy(cp, buf[:n])
			ch <- cp
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return pc.LocalAddr().(*net.UDPAddr).AddrPort(), ch
}

func newGateTestBind(t *testing.T, directFirst time.Duration, direct, relay netip.AddrPort) *Bind {
	t.Helper()
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	b := NewBind(Config{
		Identity:    id,
		DirectFirst: directFirst,
		Candidates: []Candidate{
			{Addr: direct},
			{Addr: relay, Relay: true},
		},
		Logf: func(string, ...any) {},
	})
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func TestDirectFirstGatesRelay(t *testing.T) {
	direct, directCh := listenUDPv4(t)
	relay, relayCh := listenUDPv4(t)
	b := newGateTestBind(t, 300*time.Millisecond, direct, relay)
	b.Rearm() // 新鲜赛跑

	if err := b.Send([][]byte{[]byte("wg-handshake")}, raceEP{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-directCh:
	case <-time.After(time.Second):
		t.Fatal("直连候选应当第一发就收到包")
	}
	select {
	case <-relayCh:
		t.Fatal("窗口内不该打中继候选（中继只作后备）")
	case <-time.After(100 * time.Millisecond):
	}

	// 窗口过后：补发一次到中继候选
	select {
	case <-relayCh:
	case <-time.After(2 * time.Second):
		t.Fatal("直连窗口内无响应时应当解锁并补发中继候选")
	}
}

func TestRearmSoftIncludesRelayImmediately(t *testing.T) {
	direct, directCh := listenUDPv4(t)
	relay, relayCh := listenUDPv4(t)
	b := newGateTestBind(t, 5*time.Second, direct, relay)
	b.RearmSoft() // 软赛跑：中继立即参与

	if err := b.Send([][]byte{[]byte("wg")}, raceEP{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-directCh:
	case <-time.After(time.Second):
		t.Fatal("直连候选没收包")
	}
	select {
	case <-relayCh:
	case <-time.After(time.Second):
		t.Fatal("软赛跑时中继应当立即参与（不等待窗口）")
	}
}

func TestNoDirectCandidatesSkipsWindow(t *testing.T) {
	relay, relayCh := listenUDPv4(t)
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	b := NewBind(Config{
		Identity:    id,
		DirectFirst: 10 * time.Second, // 很长，但因为没有直连候选，应当立刻打中继
		Candidates:  []Candidate{{Addr: relay, Relay: true}},
		Logf:        func(string, ...any) {},
	})
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	b.Rearm()
	if err := b.Send([][]byte{[]byte("wg")}, raceEP{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-relayCh:
	case <-time.After(time.Second):
		t.Fatal("纯中继候选时不该等直连窗口")
	}
}
