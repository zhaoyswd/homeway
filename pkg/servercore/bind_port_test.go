package servercore

import (
	"net"
	"testing"
)

// 监听端口被占用**不能**让出口起不来：Open 应当退让到相邻端口并把实际端口回给 device。
func TestOpenFallsBackWhenPortBusy(t *testing.T) {
	// 先占住一个 UDP 端口
	busy, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	busyPort := uint16(busy.LocalAddr().(*net.UDPAddr).Port)
	// 把它的**相邻端口**也占住，验证退让会继续往后找（用 +1）
	next, nerr := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: int(busyPort) + 1})
	nextBusy := nerr == nil
	if nextBusy {
		defer next.Close()
	}

	var logged []string
	b := &ServerBind{Logf: func(f string, a ...any) { logged = append(logged, f) }}
	_, actual, err := b.Open(busyPort)
	if err != nil {
		t.Fatalf("端口被占用时不应失败：%v", err)
	}
	if actual == busyPort {
		t.Fatalf("实际端口仍是 %d（没退让）", actual)
	}
	if nextBusy && actual == busyPort+1 {
		t.Fatalf("相邻端口也被占用时不该选中它：%d", actual)
	}
	if len(logged) == 0 {
		t.Fatal("退让必须留一行可读日志")
	}
	// 收工（Open 已经起了接收循环，直接关 socket 即可）
	if b.c != nil {
		_ = b.c.Close()
	}
}

// 指定端口空闲时不该退让（行为不变）。
func TestOpenKeepsPortWhenFree(t *testing.T) {
	free, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(free.LocalAddr().(*net.UDPAddr).Port)
	_ = free.Close() // 立刻释放（换端口绑定几乎不会撞车）

	b := &ServerBind{}
	_, actual, err := b.Open(port)
	if err != nil {
		t.Fatalf("空闲端口不该失败：%v", err)
	}
	if actual != port {
		t.Logf("端口 %d 刚释放就被别人抢了，退让到 %d（可接受）", port, actual)
	}
	if b.c != nil {
		_ = b.c.Close()
	}
}
