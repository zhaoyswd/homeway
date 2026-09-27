package wgcore

// 泄漏回归（review A1）：Core.Close 必须把隧道侧 B 栈一并收掉——否则每次
// Start/Close 泄漏一张 gVisor 栈 + 一个卡死的读 goroutine。goroutine 净增断言
// （容差 ±5，吸收 runtime 自身边缘 goroutine；宿主 darwin 无法数 fd）。

import (
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/internal/wtransport"
	"github.com/zhaoyswd/homeway/pkg/wgnet"
)

func TestCoreCloseReleasesGoroutines(t *testing.T) {
	gc := runtime.NumGoroutine()
	for i := 0; i < 8; i++ {
		id, err := wtransport.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		appTun, _, err := wgnet.Create([]netip.Addr{netip.MustParseAddr("10.99.0.2")}, 1280)
		if err != nil {
			t.Fatal(err)
		}
		core, err := start(Config{
			TUN:            appTun,
			MTU:            1280,
			PeerID:         [32]byte{9},
			Secret:         [32]byte{7},
			Identity:       id,
			ServerTunnelIP: netip.MustParseAddr("100.64.255.1"),
		})
		if err != nil {
			t.Fatalf("第 %d 次 Start: %v", i, err)
		}
		core.Close()
		appTun.Close() // 测试假 TUN 是一张完整 wgnet 栈（生产 fdTUN 无需关，所有权在扩展）
	}
	time.Sleep(3 * time.Second) // 收尾 goroutine 退出（device 内部 timer 收敛慢）
	delta := runtime.NumGoroutine() - gc
	if delta > 5 {
		buf := make([]byte, 1<<16)
		n := runtime.Stack(buf, true)
		t.Logf("STACKDUMP\n%s", string(buf[:n]))
		t.Fatalf("goroutine delta=%d", delta)
	}
	// fd 指标不设（宿主 darwin 无 /proc 可数；曾留空断言恒 0——review C6 删）：
	// goroutine 净增已覆盖 B 栈/读协程/event reader 三类泄漏。
}
