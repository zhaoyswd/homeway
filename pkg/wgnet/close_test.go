package wgnet

// close_test.go — 收期死锁回归（2026-09-30，v0.12.0 发版前 dispatch 验腿实测）：
// 读方（wireguard-go 的 tun 读例程）先于 Net.Close 退出后，gvisor 的发送路径仍会调
// WriteNotify 往 incoming 塞包——旧实现的无界阻塞发送会持锁死等读方，把 Net.Close
// 的拆栈（stack.Close→各端点 Abort 等同一把锁）一起挂死（真机形态 =
// clientcore/wgcore TestRecoverAfterDeviceRecordReaped 在 linux CI 上 10 分钟超时；
// 出口过境拦截侧同一份 Net，同样暴露）。判据：无读方 + 写方阻塞在通知发送时，
// Close 与写方都在预算内返回（修前形态 = 本用例在 Close 上超时挂死）。

import (
	"net/netip"
	"testing"
	"time"
)

func TestCloseReturnsWithNoReaderAndBlockedNotify(t *testing.T) {
	_, n, err := Create([]netip.Addr{netip.MustParseAddr("100.64.0.2")}, 1280)
	if err != nil {
		t.Fatalf("wgnet Create: %v", err)
	}
	// UDP 写路径同步穿过 WritePackets→WriteNotify：无读方 ⇒ 写方阻塞在通知发送上
	//（等价于 CI 挂死形态里持端点锁的 gvisor worker）。
	conn, err := n.DialUDPAddrPort(netip.MustParseAddrPort("100.64.0.2:0"), netip.MustParseAddrPort("192.0.2.9:9"))
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	written := make(chan error, 1)
	go func() {
		_, werr := conn.Write([]byte("bye"))
		written <- werr
	}()
	// 200ms 窗口等写方确实进入阻塞发送（与既有收期用例同款节拍量级）。
	time.Sleep(200 * time.Millisecond)
	select {
	case err := <-written:
		t.Fatalf("无读方时写方不该完成（staging 失效，回归用例失真）：%v", err)
	default:
	}
	closed := make(chan error, 1)
	go func() { closed <- n.Close() }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close 未返回：收期死锁——写方持锁阻塞在 WriteNotify 的发送上，拆栈在等同一把锁")
	}
	select {
	case <-written:
	case <-time.After(5 * time.Second):
		t.Fatal("写方未随收工阀门解阻塞（done 关闭后应丢弃出队包返回）")
	}
}
