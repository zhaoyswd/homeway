// probe_respond_test.go：中继的参照点探测应答（add-host-connectivity）。
//
// 三态契约（spec wg-native-relay「中继应答参照点探测」）：
//   1. 合法探测 → 回声应答（含构建标记），不创建腿/会话；
//   2. 非法探测（版本不支持/长度不足）→ 静默忽略；
//   3. 帧协议包不受影响（垃圾 0xBB 包仍走原 Dropped 语义）。
// 顺带断言防放大不变量（应答 ≤ 请求 + 45B）。
package relay

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/probe"
)

func TestRelayProbeRespond(t *testing.T) {
	r := startRelay(t, Config{Build: "test-relay"})
	target := r.LocalAddr()

	// 1) 合法探测：应答含构建标记，RTT 正常。
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rtt, build, _, err := probe.Ping(ctx, pc, target, "")
	if err != nil {
		t.Fatalf("合法探测无应答：%v", err)
	}
	if build != "test-relay" {
		t.Fatalf("构建标记不符：got %q", build)
	}
	if rtt <= 0 || rtt > time.Second {
		t.Fatalf("RTT 异常：%v", rtt)
	}
	// 应答不建任何状态：腿/分配计数不涨。
	if s := r.Stats(); s.Assigned != 0 || s.Registered != 0 {
		t.Fatalf("探测不应创建状态：%+v", s)
	}
	// 探测被应答而非丢弃。
	if s := r.Stats(); s.Dropped != 0 {
		t.Fatalf("探测包不应计入 Dropped：%d", s.Dropped)
	}
}

func TestRelayProbeInvalidIgnored(t *testing.T) {
	r := startRelay(t, Config{})
	target := r.LocalAddr()

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	// 版本不支持（ver=9）：probe.DecodeRequest 报错 ⇒ probe.Respond 返回 nil ⇒ 静默。
	var nonce [8]byte
	bad := probe.EncodeRequest(probe.TypePing, nonce, 16)
	bad[3] = 9
	if _, err := pc.WriteToUDP(bad, net.UDPAddrFromAddrPort(target)); err != nil {
		t.Fatal(err)
	}
	// 短包（< minReqLen）：同样静默。
	if _, err := pc.WriteToUDP(bad[:10], net.UDPAddrFromAddrPort(target)); err != nil {
		t.Fatal(err)
	}
	pc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 1500)
	if n, _, err := pc.ReadFrom(buf); err == nil {
		t.Fatalf("非法探测不应有应答，却收到 %d 字节", n)
	}
}

func TestRelayProbeAmplificationInvariant(t *testing.T) {
	r := startRelay(t, Config{Build: "test-relay"})
	target := r.LocalAddr()

	// pad 16 的请求：无列表段应答必须 ≤ 请求 + 45B（probe 协议层不变量，
	// 中继侧不带端点列表 ⇒ 严格更短；在这里从 wire 上独立断言一次）。
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	var nonce [8]byte
	req := probe.EncodeRequest(probe.TypePing, nonce, 16)
	if _, err := pc.WriteToUDP(req, net.UDPAddrFromAddrPort(target)); err != nil {
		t.Fatal(err)
	}
	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("无应答：%v", err)
	}
	if n > len(req)+45 {
		t.Fatalf("破坏防放大不变量：应答 %dB > 请求 %dB + 45", n, len(req))
	}
}

func TestRelayProbeDoesNotAffectFrames(t *testing.T) {
	r := startRelay(t, Config{})
	target := r.LocalAddr()

	// 帧协议路径不受探测分支影响：垃圾 0xBB 包仍按 Dropped 语义处理。
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	// 0xBB 开头但解不出帧的包（DecodeTagged 失败 ⇒ Dropped）。
	if _, err := pc.WriteToUDP([]byte{0xBB, 0x00, 0x01}, net.UDPAddrFromAddrPort(target)); err != nil {
		t.Fatal(err)
	}
	// 非探测、非帧的明文包：同样 Dropped。
	if _, err := pc.WriteToUDP([]byte("garbage-not-a-frame"), net.UDPAddrFromAddrPort(target)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if r.Stats().Dropped >= 2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("帧路径的 Dropped 语义被破坏：%+v", r.Stats())
}
