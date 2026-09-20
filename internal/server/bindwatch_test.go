package server

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// 自动模式的判据：先挑到 en0；当它连续探针失败时重新挑卡 → 切到 en1，并且每次都踢一次公网端点重测。
func TestWatchBindSwitchesWhenProbeFails(t *testing.T) {
	en0 := &net.Interface{Name: "en0", Index: 6, Flags: net.FlagUp}
	en1 := &net.Interface{Name: "en1", Index: 7, Flags: net.FlagUp}
	states := map[string]ifaceState{
		"en0": {index: 6, up: true, addrs: "192.0.2.12/24"},
		"en1": {index: 7, up: true, addrs: "10.0.0.5/24"},
	}
	var picks int
	resolve := func(context.Context) (*net.Interface, error) {
		picks++
		if picks == 1 {
			return en0, nil
		}
		return en1, nil
	}
	probe := func(context.Context, *net.Interface) error { return errors.New("探针不通") }
	repinned := make(chan string, 4)
	kicks := make(chan struct{}, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	WatchBind(ctx, BindWatchOpts{
		Resolve:  resolve,
		Probe:    probe,
		State:    func(ifi *net.Interface) ifaceState { return states[ifi.Name] },
		Repin:    func(ifi *net.Interface) error { repinned <- ifi.Name; return nil },
		OnChange: func() { kicks <- struct{}{} },
		Logf:     func(string, ...any) {},
		Interval: 10 * time.Millisecond,
	})
	if got := waitName(t, repinned); got != "en0" {
		t.Fatalf("首次应钉 en0，实际 %s", got)
	}
	if got := waitName(t, repinned); got != "en1" {
		t.Fatalf("探针连续失败后应切到 en1，实际 %s", got)
	}
	for i := 0; i < 2; i++ { // 两次重钉，各踢一次端点重测
		select {
		case <-kicks:
		case <-time.After(2 * time.Second):
			t.Fatal("换卡后应踢一次公网端点重测")
		}
	}
}

// 指纹变化的判据：索引/地址变了就重新钉（显式模式按名字重解析）。
func TestWatchBindRepinsOnIfaceChange(t *testing.T) {
	cur := &net.Interface{Name: "en0", Index: 6, Flags: net.FlagUp}
	// state 会被 watchBind 协程（State 回调）与测试主线并发读写——atomic.Pointer
	// 同步（此前 -race 报「81 行写 vs 回调 67 行读」的数据竞争）。
	state := atomic.Pointer[ifaceState]{}
	state.Store(&ifaceState{index: 6, up: true, addrs: "192.0.2.12/24"})
	repinned := make(chan string, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	WatchBind(ctx, BindWatchOpts{
		Explicit: cur,
		Resolve:  func(context.Context) (*net.Interface, error) { return cur, nil },
		Probe:    func(context.Context, *net.Interface) error { return nil },
		State:    func(*net.Interface) ifaceState { return *state.Load() },
		Repin:    func(ifi *net.Interface) error { repinned <- ifi.Name; return nil },
		Logf:     func(string, ...any) {},
		Interval: 10 * time.Millisecond,
	})
	if got := waitName(t, repinned); got != "en0" {
		t.Fatalf("首次应钉 en0，实际 %s", got)
	}
	time.Sleep(80 * time.Millisecond)
	select {
	case name := <-repinned:
		t.Fatalf("指纹没变不该重钉，实际重钉了 %s", name)
	default:
	}
	state.Store(&ifaceState{index: 6, up: true, addrs: "192.168.3.99/24"}) // IP 变了
	if got := waitName(t, repinned); got != "en0" {
		t.Fatalf("指纹变化应重钉，实际 %s", got)
	}
}

func waitName(t *testing.T, ch chan string) string {
	t.Helper()
	select {
	case n := <-ch:
		return n
	case <-time.After(3 * time.Second):
		t.Fatal("等待重钉事件超时")
	}
	return ""
}
