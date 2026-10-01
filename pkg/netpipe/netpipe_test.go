package netpipe

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// startRelay 起一个「监听 → 拨上游 → Both 透传」的中继（与 facade/socks 的用法同形）。
func startRelay(t *testing.T, upstreamAddr string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(client net.Conn) {
				up, derr := net.DialTimeout("tcp", upstreamAddr, 5*time.Second)
				if derr != nil {
					_ = client.Close()
					return
				}
				Both(nil, client, up)
			}(c)
		}
	}()
	return ln
}

// acceptOne 起一个只服务一条连接的上游。
func acceptOne(t *testing.T, serve func(c net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		serve(c)
	}()
	return ln.Addr().String()
}

func dialRelay(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	return c
}

// TestBothClientHalfCloseKeepsResponse：客户端先半关闭（CloseWrite）再读响应——响应
// 必须完整到达。旧口径「任一向 EOF 即双向 Close」会在这里截断（响应只有上游读到 EOF
// 之后才发，双向收口把上游写端当场拆掉）。这是 HTTP/1.0 式「关写等响应」的确定性形态。
func TestBothClientHalfCloseKeepsResponse(t *testing.T) {
	const respLen = 512 << 10
	want := bytes.Repeat([]byte("R"), respLen)
	upstream := acceptOne(t, func(c net.Conn) {
		defer c.Close()
		req, _ := io.ReadAll(c) // 读到半关闭（FIN）为止
		if string(req) != "REQ" {
			t.Errorf("上游应收到完整请求，实际 %q", req)
			return
		}
		_, _ = c.Write(want)
	})
	ln := startRelay(t, upstream)
	client := dialRelay(t, ln.Addr().String())

	if _, err := client.Write([]byte("REQ")); err != nil {
		t.Fatal(err)
	}
	if tc, ok := client.(*net.TCPConn); ok {
		if err := tc.CloseWrite(); err != nil { // 半关闭：只关写方向
			t.Fatal(err)
		}
	} else {
		t.Fatal("测试客户端应为 *net.TCPConn（半关闭能力）")
	}
	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("读响应失败：%v（已收 %d 字节）", err, len(got))
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("响应被截断/篡改：收到 %d 字节，期望 %d（旧口径会在此红）", len(got), len(want))
	}
}

// TestBothUpstreamHalfCloseKeepsUpload：上游先半关闭（回完问候就关写）但仍继续读——
// 客户端随后发的数据必须完整到达上游。旧口径在问候方向 EOF 时即双向收口，客户端
// 上半段数据会被就地丢弃（写失败或对端 RST）。
func TestBothUpstreamHalfCloseKeepsUpload(t *testing.T) {
	gotCh := make(chan []byte, 1)
	upstream := acceptOne(t, func(c net.Conn) {
		defer c.Close()
		if _, err := c.Write([]byte("HI")); err != nil {
			t.Errorf("上游写问候失败：%v", err)
			return
		}
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.CloseWrite() // 问候之后半关闭：不再发，但还读
		} else {
			t.Error("上游应为 *net.TCPConn")
			return
		}
		body, _ := io.ReadAll(c)
		gotCh <- body
	})
	ln := startRelay(t, upstream)
	client := dialRelay(t, ln.Addr().String())

	greet := make([]byte, 2)
	if _, err := io.ReadFull(client, greet); err != nil || string(greet) != "HI" {
		t.Fatalf("应收到上游问候：%v %q", err, greet)
	}
	if _, err := client.Write([]byte("UPLOAD")); err != nil {
		t.Fatalf("上游半关闭后客户端仍应能上行：%v", err)
	}
	if tc, ok := client.(*net.TCPConn); ok {
		_ = tc.CloseWrite() // 上行完再半关闭：让上游的 ReadAll 收尾（也验证双向半关闭序）
	}
	select {
	case body := <-gotCh:
		if string(body) != "UPLOAD" {
			t.Fatalf("上游应收到完整上传，实际 %q", body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("上游没等到上传数据（透传在半关闭后把连接拆了？）")
	}
}

// TestBothFullCloseOnBothDirectionsEOF：两向都 EOF 后连接正常收口（不泄漏、不悬挂）。
func TestBothFullCloseOnBothDirectionsEOF(t *testing.T) {
	upstream := acceptOne(t, func(c net.Conn) {
		defer c.Close()
		_, _ = io.ReadAll(c) // 等客户端 FIN
	})
	ln := startRelay(t, upstream)
	client := dialRelay(t, ln.Addr().String())
	if _, err := client.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if tc, ok := client.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	// 上游关闭后，本向 EOF ⇒ 客户端读到 EOF（Both 返回并 Close 两端）。
	if _, err := io.ReadAll(client); err != nil {
		t.Fatalf("收口路径应读到干净 EOF：%v", err)
	}
}
