package wgcore

// hardening_test.go — l3-relay-hardening 组 5 的核心回归：
//
//	#15 TUN 读循环在**设备所有者** Close 后有界退出（≤~1s，不再等扩展关 fd）；
//	    hub 不越权关外部设备（owner = Core.AttachFD 造的 fdTUN）

import (
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	tun "golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// fakeAppTUN：一个可控的 tun.Device 替身（appReadLoop 的读阻塞由它决定）。
// 读永远阻塞（模拟「扩展还没关 fd」的窗口——旧实现里 appReadLoop 会卡一辈子）。
type blockingTUN struct {
	dead chan struct{}
}

func newBlockingTUN() *blockingTUN { return &blockingTUN{dead: make(chan struct{})} }

func (b *blockingTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	<-b.dead // 永远阻塞直到被关
	return 0, os.ErrClosed
}
func (b *blockingTUN) Write(bufs [][]byte, offset int) (int, error) { return len(bufs), nil }
func (b *blockingTUN) Close() error {
	select {
	case <-b.dead:
	default:
		close(b.dead)
	}
	return nil
}
func (b *blockingTUN) Name() (string, error) { return "fake", nil }
func (b *blockingTUN) File() *os.File        { return nil }
func (b *blockingTUN) MTU() (int, error)     { return 1280, nil }
func (b *blockingTUN) Events() <-chan tun.Event {
	return nil // hub 不用 app 的 Events（自己的 events 通道）
}
func (b *blockingTUN) BatchSize() int { return 1 }

// #15（review 复审重写）：旧断言只数 goroutine —— 降下来的其实是隧道侧 B 的循环，
// appReadLoop 仍阻塞在 dev.Read 里（实测：Close 后 1.2s deviceCloseCalled=false），
// 属于"通过得莫名其妙"，把 #15 的回归保护变成了摆设。真契约有两半：
//
//	① hub.Close **不关**外部 Attach 进来的设备（hub 不是它的主人——关它会当场拆掉
//	   调用方还在用的栈，实测 panic），只关自己的 appDead/events；
//	② 读循环的退出由**设备所有者**的 Close 触发：生产路径 = Core.AttachFD 造的 fdTUN，
//	   Core.Close 负责关它（core.go）；fdTUN.Close 只关 closed 通道，fd 仍归扩展。
//
// 本用例直接验 ②：非阻塞 fd（与 OHOS VPN fd 同形态：EAGAIN → poll(500ms) → 查 closed）
// 造一个真 fdTUN，Close 后读循环必须在 poll 周期 + 余量内返回 os.ErrClosed。
func TestTunReadLoopExitsAfterOwnerClose(t *testing.T) {
	rp, wp, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = wp.Close() }()
	fd := int(rp.Fd())
	if err := unix.SetNonblock(fd, true); err != nil { // OHOS VPN fd 就是非阻塞的
		t.Fatal(err)
	}
	dev, err := NewTunFromFD(fd, 1280)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		bufs := [][]byte{make([]byte, 2048)}
		sizes := make([]int, 1)
		_, rerr := dev.Read(bufs, sizes, 0)
		done <- rerr
	}()
	time.Sleep(120 * time.Millisecond) // 让读循环进入 EAGAIN→poll 圈

	start := time.Now()
	if cerr := dev.Close(); cerr != nil { // owner Close：读循环的收口信号
		t.Fatal(cerr)
	}
	select {
	case rerr := <-done:
		if rerr == nil {
			t.Fatal("读循环返回了 nil 错误")
		}
		t.Logf("owner Close 后读循环 %v 退出（%v）", time.Since(start).Round(time.Millisecond), rerr)
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("owner Close 后 1.5s 读循环仍未退出（#15 回归：closed 未被检查）")
	}
	_ = rp.Close()
}

// ① hub.Close 不关外部设备（所有权语义，防止有人"顺手"在 hub.Close 里关掉调用方的栈）。
func TestHubCloseDoesNotCloseExternalDevice(t *testing.T) {
	h := newHub(newBlockingTUN(), v4Addr("100.64.0.1"), 1280)
	app := newBlockingTUN()
	if err := h.AttachTUN(app); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	_ = h.Close()
	select {
	case <-app.dead:
		t.Fatal("hub.Close 关掉了外部 Attach 的设备（所有权越界：会拆掉调用方仍在用的栈）")
	default:
	}
	_ = app.Close()
}

func v4Addr(s string) tcpip.Address {
	return tcpip.AddrFrom4(netip.MustParseAddr(s).As4())
}
