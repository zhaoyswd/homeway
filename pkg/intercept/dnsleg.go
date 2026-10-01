package intercept

import (
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// dnsLeg：把代答器包成 UDP 语义的内存腿（net.Conn 形态）。serveUDP 的会话骨架
// （在建窗口重放 / 双向泵 / 空闲看门狗 / closed 收工 / 会话日志与统计）原样复用——
// 与真实 socket 的唯一差别是应答在进程内算出、不落地网络。
//
// Write = 一问一答（**同步**，最长吃满代答预算 ~2.5s）：UDP 客户端的重传语义
// 使阻塞只影响本会话的后续包；读者（real→peer 泵）拿到应答就回投客户端。
type dnsLeg struct {
	ans  DNSAnswerer
	q    chan []byte  // 待回投的应答（容量小；满则丢最新，客户端按超时重试）
	dl   atomic.Int64 // 读期限（UnixNano；0 = 无期限）
	done chan struct{}
	once sync.Once
}

func newDNSLeg(ans DNSAnswerer) *dnsLeg {
	return &dnsLeg{ans: ans, q: make(chan []byte, 8), done: make(chan struct{})}
}

func (l *dnsLeg) Write(p []byte) (int, error) {
	select {
	case <-l.done:
		return 0, net.ErrClosed
	default:
	}
	if resp := l.ans.Answer(p); resp != nil {
		select {
		case l.q <- resp:
		default: // 队列满：丢应答（不阻塞泵）
		}
	}
	return len(p), nil
}

// Read 取一条应答；无应答则等到读期限（os.ErrDeadlineExceeded 满足 net.Error，
// 泵按超时继续——真实 socket 的形态）。
func (l *dnsLeg) Read(b []byte) (int, error) {
	var timeout <-chan time.Time
	if dl := l.dl.Load(); dl != 0 {
		d := time.Until(time.Unix(0, dl))
		if d <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		t := time.NewTimer(d)
		defer t.Stop()
		timeout = t.C
	}
	select {
	case p := <-l.q:
		return copy(b, p), nil // 长于 b 的部分丢弃（UDP 语义）
	case <-l.done:
		return 0, net.ErrClosed
	case <-timeout:
		return 0, os.ErrDeadlineExceeded
	}
}

func (l *dnsLeg) Close() error { l.once.Do(func() { close(l.done) }); return nil }

func (l *dnsLeg) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		l.dl.Store(0)
	} else {
		l.dl.Store(t.UnixNano())
	}
	return nil
}

func (l *dnsLeg) SetWriteDeadline(time.Time) error { return nil }
func (l *dnsLeg) SetDeadline(t time.Time) error    { return l.SetReadDeadline(t) }

// LocalAddr/RemoteAddr：内存腿没有地址（诊断不依赖它）。
func (l *dnsLeg) LocalAddr() net.Addr  { return &net.UDPAddr{} }
func (l *dnsLeg) RemoteAddr() net.Addr { return &net.UDPAddr{} }
