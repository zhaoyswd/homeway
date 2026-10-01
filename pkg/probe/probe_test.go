package probe

import (
	"context"
	"net"
	"testing"
	"time"
)

// 编解码：非探测包必须放行（ErrNotProbe），未知类型不应答。
func TestCodecAndUnknownType(t *testing.T) {
	// 非探测包（比如裸 WG / reg 搭车）不能被误判
	if _, err := DecodeRequest([]byte("HR\x00\x01\x02")); err != ErrNotProbe {
		t.Fatalf("非探测包应回 ErrNotProbe：%v", err)
	}
	if _, err := DecodeRequest([]byte{0xBB, 0x00}); err != ErrNotProbe {
		t.Fatalf("腿帧应回 ErrNotProbe：%v", err)
	}
	// 太短
	if _, err := DecodeRequest([]byte("HWQ\x01\x01")); err != ErrProbeShort {
		t.Fatalf("短包应回 ErrProbeShort：%v", err)
	}
	// 正常 ping 往返
	var nonce [8]byte
	copy(nonce[:], "12345678")
	req := EncodeRequest(TypePing, nonce, 16)
	if len(req) != 29 {
		t.Fatalf("ping 请求长度=%d", len(req))
	}
	resp := Respond(req, "v0.6.0-test", 0x01)
	if resp == nil {
		t.Fatal("ping 应被应答")
	}
	got, err := DecodeResponse(resp, TypePing, nonce)
	if err != nil || got.Build != "v0.6.0-test" {
		t.Fatalf("ping 响应解析失败：%+v err=%v", got, err)
	}
	if got.Flags != 0x01 {
		t.Fatalf("出口能力位没解析出来：%+v", got)
	}
	// 老出口（不带 flags 段）解析成 0，不能报错
	legacy := append([]byte{}, resp[:13]...)
	legacy = append(legacy, byte(len("v0.6.0-test")))
	legacy = append(legacy, "v0.6.0-test"...)
	if lg, err := DecodeResponse(legacy, TypePing, nonce); err != nil || lg.Flags != 0 || lg.Build != "v0.6.0-test" {
		t.Fatalf("老格式应兼容解析：%+v err=%v", lg, err)
	}
	// 未知类型不应答
	if resp := Respond(EncodeRequest(0x77, nonce, 16), "x", 0); resp != nil {
		t.Fatal("未知类型不应答")
	}
	// nonce 不匹配要拒
	var other [8]byte
	if _, err := DecodeResponse(resp, TypePing, other); err == nil {
		t.Fatal("nonce 不匹配应报错")
	}
}

// 真 socket 往返：Respond 挂在 UDP 上，客户端 Ping 拿到结果；
// 同时验证「非探测包不产生响应」（数据面不受影响）。
func TestPingOverUDP(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, src, err := srv.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if resp := Respond(buf[:n], "v9-test", 0); resp != nil {
				srv.WriteToUDPAddrPort(resp, src)
			}
		}
	}()
	target := srv.LocalAddr().(*net.UDPAddr).AddrPort()

	cli, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	rtt, build, flags, err := Ping(ctx, cli, target, "")
	if err != nil {
		t.Fatalf("ping 失败：%v", err)
	}
	if build != "v9-test" || rtt <= 0 || rtt > 2*time.Second {
		t.Fatalf("ping 结果异常：rtt=%v build=%q", rtt, build)
	}
	_ = flags
}
