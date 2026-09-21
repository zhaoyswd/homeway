package relay

// relay_lifecycle_test.go — Run 的收工契约（review 复审：TCP 控制监听的关闭时机）。
//
// 复现过的抖动：`TestControlAuthRejected` 偶发卡在"等 CHALLENGE"——上一个用例的中继
// 把 TCP 控制监听交给一个"ctx 到了才关"的 goroutine，而 `Run` 由**另一个** goroutine
// 关 UDP socket 而返回；测试的 `<-done` 于是可能在 `tcpLn.Close()` 之前完成，端口被带进
// 下一个用例：下一个中继的随机 UDP 端口恰好撞上它 ⇒ 控制面 listen 失败、只留一行
// "退回纯 UDP 中继" 的日志 ⇒ 用例等 CHALLENGE 超时。
//
// 现在的契约：**Run 返回 ⇒ 本实例的监听器与会话一定已释放**（同步收尾），
// 调用方/嵌入方看到 Run 返回即可立刻重用同端口。

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestRunReleasesListenersBeforeReturn(t *testing.T) {
	rl := New(Config{Addr: "127.0.0.1:0"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = rl.Run(ctx)
	}()
	for i := 0; i < 200 && !rl.LocalAddr().IsValid(); i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if !rl.LocalAddr().IsValid() {
		t.Fatal("中继没起来")
	}
	port := int(rl.LocalAddr().Port())

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("ctx 取消后 Run 未返回")
	}

	// Run 已返回：UDP 与 TCP（控制面）都必须能立刻重新绑定。
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatalf("Run 返回后 UDP :%d 仍被占用：%v", port, err)
	}
	_ = udp.Close()
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("Run 返回后 TCP :%d 仍被占用（控制监听未随 Run 收工）：%v", port, err)
	}
	_ = ln.Close()
}
