package wgcore

// fd 版 tun.Device 的判据：用一对 connected UDP socket 模拟 TUN fd —— 读=收一个「包」、
// 写=发一个「包」，且 offset 语义（wireguard-go 传 MessageTransportHeaderSize）正确。

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/internal/wtransport"
	"github.com/zhaoyswd/homeway/pkg/wgnet"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestTunFromFDPacketSemantics(t *testing.T) {
	b, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	// 「已连接」的 UDP socket：读=收一个包、写=发一个包，与 TUN fd 同形态
	aConn, err := net.DialUDP("udp4", nil, b.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer aConn.Close()

	af, err := aConn.File() // dup fd（阻塞模式），与扩展递进来的形态一致
	if err != nil {
		t.Fatal(err)
	}
	defer af.Close()

	dev, err := NewTunFromFD(int(af.Fd()), 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	if mtu, err := dev.MTU(); err != nil || mtu != 1280 {
		t.Fatalf("MTU=%d err=%v", mtu, err)
	}
	if dev.File() != nil {
		t.Fatal("File() 必须为 nil（不把 fd 包成 *os.File）")
	}

	// 对端发一个「包」→ dev.Read 收到（放在 offset 之后）
	if _, err := b.WriteToUDP([]byte("packet-1"), aConn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	type readResult struct {
		n    int
		size int
		body string
		err  error
	}
	res := make(chan readResult, 1)
	go func() {
		bufs := [][]byte{make([]byte, 2048)}
		sizes := []int{0}
		const off = 16 // 与 wireguard-go 的 MessageTransportHeaderSize 同形态
		n, err := dev.Read(bufs, sizes, off)
		res <- readResult{n: n, size: sizes[0], body: string(bufs[0][off : off+sizes[0]]), err: err}
	}()
	select {
	case r := <-res:
		if r.err != nil || r.n != 1 || r.size != len("packet-1") || r.body != "packet-1" {
			t.Fatalf("Read 结果不符：%+v", r)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Read 超时")
	}

	// dev.Write（offset 语义）→ 对端收到同一个「包」
	const off = 4
	pkt := []byte{0xde, 0xad, 0xbe, 0xef, 'p', 'a', 'y'}
	if _, err := dev.Write([][]byte{pkt}, off); err != nil {
		t.Fatal(err)
	}
	_ = b.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 128)
	n, _, err := b.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("对端未收到写出的包：%v", err)
	}
	if string(buf[:n]) != string(pkt[off:]) {
		t.Fatalf("写出的包内容不符：%q（期望 %q）", buf[:n], pkt[off:])
	}

	// Close 幂等且不关 fd（fd 归扩展）：关掉之后还能用原始 socket
	if err := dev.Close(); err != nil {
		t.Fatal(err)
	}
	if err := dev.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := aConn.Write([]byte("still-alive")); err != nil {
		t.Fatalf("Close 不应影响调用方 fd：%v", err)
	}
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _, err := b.ReadFromUDP(buf); err != nil || string(buf[:n]) != "still-alive" {
		t.Fatalf("fd 在 Close 后不可用：n=%d err=%v", n, err)
	}
}

// 两阶段：Prepare（无 TUN）→ Attach（内存 TUN）→ 数据面可用。
func TestPrepareAttachTwoPhase(t *testing.T) {
	secret := [32]byte{1, 3, 3, 7}
	srvPort := freeUDPPort(t)
	spriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	id, err := wtransport.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	core, err := Prepare(Config{
		PeerID: spriv.PublicKey(), Secret: secret, Identity: id,
		Candidates:     []wtransport.Candidate{{Addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), srvPort)}},
		ServerTunnelIP: netip.MustParseAddr(srvTunnelIP),
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	t.Cleanup(core.Close)
	// 未 attach：隧道侧已就绪、状态可读，但还没收到过任何包 ⇒ via=none
	if core.Bind() == nil || core.ServerTunnelIP().IsValid() == false {
		t.Fatal("Prepare 后隧道侧应已可用")
	}
	if st := core.status(); st.Via != "none" {
		t.Fatalf("Prepare 后不应有采纳路径：%+v", st)
	}
	// attach 内存 TUN（测试里就是 app 栈的 tun.Device）
	appTun, _, err := wgnet.Create([]netip.Addr{netip.MustParseAddr("10.126.126.2")}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	if err := core.Attach(appTun); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if err := core.Attach(appTun); err == nil {
		t.Fatal("重复 Attach 应报错")
	}
}
