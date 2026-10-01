// Package netpipe：TCP 双向透传的**半关闭**单实现（手机面端口转发 / 桌面端口转发 /
// 桌面 socks 三面共用）。
//
// 为什么单实现：透传的收口语义曾有三份手写实现，其中两份（facade 的 pipeConns、
// pkg/socks 的 pipeBoth）在「任一向 EOF 即双向 Close」——把一条腿的 FIN 当成了整条连接
// 的结束：客户端按 HTTP/1.0（或任何「先关写方向、再读响应」）的协议半关闭后，响应会
// 被当场截断（表现为偶发「响应不完整 / 连接被重置」）。手机面那份（clientcore 的
// pipeBoth）是对的——CloseWrite 让 FIN 穿透；本包即它的提炼。
//
// 语义：
//   - 每个方向 EOF/出错 ⇒ 只收**该方向的写端**（CloseWrite；对端不支持则退化为 Close）；
//   - **两向都收工**才 Close 两端（长连接语义：只要还有一向活着就不拆连接）；
//   - 不做 RST——RST 只属于失败路径（拨号失败 / 显式关停），由调用方负责。
package netpipe

import (
	"errors"
	"io"
	"net"
)

// Logf 传输错误日志缝（nil = 丢弃）。
type Logf func(format string, args ...any)

// closeWriter 半关闭能力（*net.TCPConn 有；包装连接可能没有）。
type closeWriter interface{ CloseWrite() error }

// Both 双向透传并做半关闭（a/b 任一方向先 EOF 都不截断另一向）。
// 调用方负责在返回后不再使用 a/b（本函数返回前已 Close 两端）。
func Both(logf Logf, a, b net.Conn) {
	cp := func(dst, src net.Conn, done chan<- struct{}) {
		n, err := io.Copy(dst, src)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			if logf != nil {
				logf("pipe %v→%v: %v after %dB", src.RemoteAddr(), dst.RemoteAddr(), err, n)
			}
		}
		if hc, ok := dst.(closeWriter); ok {
			_ = hc.CloseWrite()
		} else {
			_ = dst.Close()
		}
		done <- struct{}{}
	}
	done := make(chan struct{}, 2)
	go cp(a, b, done)
	go cp(b, a, done)
	<-done
	<-done
	_ = a.Close()
	_ = b.Close()
}
