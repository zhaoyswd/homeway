package server

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// 换网监视的判据：只有指纹**变化**才重钉+重测；网卡消失再回来也算一次变化。
func TestWatchNetworkDetectsChange(t *testing.T) {
	var state atomic.Value
	state.Store(ifaceState{index: 6, up: true, addrs: "192.0.2.12/24"})
	probe := func() (ifaceState, error) { return state.Load().(ifaceState), nil }

	var repins, kicks int32
	repin := func() (*net.Interface, error) {
		atomic.AddInt32(&repins, 1)
		return &net.Interface{Name: "en0", Index: 6}, nil
	}
	kick := func() { atomic.AddInt32(&kicks, 1) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watchNetwork(ctx, "en0", probe, repin, kick, func(string, ...any) {}, 10*time.Millisecond)

	time.Sleep(60 * time.Millisecond) // 无变化：一次都不该触发
	if n := atomic.LoadInt32(&repins); n != 0 {
		t.Fatalf("无变化时不应重钉，实际 %d 次", n)
	}

	state.Store(ifaceState{index: 6, up: true, addrs: "192.168.3.99/24"}) // IP 变了
	waitFor(t, func() bool { return atomic.LoadInt32(&repins) == 1 }, 2*time.Second)
	waitFor(t, func() bool { return atomic.LoadInt32(&kicks) == 1 }, 2*time.Second)

	state.Store(ifaceState{index: 7, up: true, addrs: "192.168.3.99/24"}) // 索引变了（换网）
	waitFor(t, func() bool { return atomic.LoadInt32(&repins) == 2 }, 2*time.Second)

	time.Sleep(60 * time.Millisecond)
	if n := atomic.LoadInt32(&kicks); n != 2 {
		t.Fatalf("踢公网端点重测的次数 = %d，want 2（每次变化一次）", n)
	}
}

func waitFor(t *testing.T, cond func() bool, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("等待条件超时")
}
