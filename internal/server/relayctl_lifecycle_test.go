package server

// relayctl_lifecycle_test.go — tasks 1.5 要求的判据：中继注册腿与控制客户端必须随
// 上下文收工（Server.Close 取消 relayCtx）。此前它们挂在 context.Background() 上，
// Close 之后仍会一直拨号/重连（进程级无所谓，测试里每次泄漏 goroutine）。

import (
	"context"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/servercore"
)

func TestRelayGoroutinesStopOnContextCancel(t *testing.T) {
	sbind := &servercore.ServerBind{Logf: func(string, ...any) {}}
	if _, _, err := sbind.Open(0); err != nil {
		t.Fatal(err)
	}
	defer sbind.Close()

	var priv, secret [32]byte
	pub := wgPub(priv)
	deadRelay := netip.MustParseAddrPort("127.0.0.1:1") // 端口一定没人听：拨号必败，走重试循环

	before := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	startRelayLeg(ctx, sbind, deadRelay, priv, pub, secret, func(string, ...any) {})
	startControlClient(ctx, sbind, deadRelay, priv, pub, secret, func(string, ...any) {})
	time.Sleep(200 * time.Millisecond) // 让两组协程进入拨号/重试循环

	cancel()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before+1 { // 容差 1：运行时边缘 goroutine
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("ctx 取消后中继协程未收工（goroutine %d→%d）", before, runtime.NumGoroutine())
}
