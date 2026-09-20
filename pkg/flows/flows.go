// Package flows：Homeway 内部流协议（wg-native-stack tasks 3.3）。
//
// 承载于 WG 隧道内的 TCP/UDP（隧道 IP 之间）：
//
//	TCP 流：  客户端拨 <后端隧道IP>:<FlowPort>，首行 "CONNECT host:port\n"，
//	          服务端重拨目标后回 "OK\n"，此后裸字节双向管道；
//	          失败回 "ERR <code>\n" 后关流（code 见 ErrCode*）。
//	UDP 数据报（DNS 等）：经 <后端隧道IP>:<UDPFlowPort>，
//	          每报 = [16B v6(4in6) 地址][2B 端口][payload]；回程同构。
//
// 计数键与旧栈 stats 契约对齐：dialok / dialfail / flows。
package flows

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CONNECT 行最大长度（域名 + 端口足够）。
const MaxConnectLine = 512

// 错误码（客户端归因用；后续与 FilesRules 风格的错误表对齐）。
const (
	ErrCodeRefused = "refused"
	ErrCodeTimeout = "timeout"
	ErrCodeNoDNS   = "nodns"
	ErrCodeNet     = "net"
	ErrCodeProto   = "proto"
)

// RemoteError：服务端以 ERR <code> 拒绝（code 见 ErrCode*）。
// 上层按 code 做中文归因（files/端口转发/终端共用），不要靠字符串匹配。
type RemoteError struct{ Code string }

func (e *RemoteError) Error() string { return "flows: 远端拨号失败 code=" + e.Code }

// ---------- CONNECT 编解码 ----------

// WriteConnect 写入 CONNECT 首行。
func WriteConnect(w io.Writer, host string, port uint16) error {
	_, err := fmt.Fprintf(w, "CONNECT %s:%d\n", host, port)
	return err
}

// ReadConnect 读出并解析 CONNECT 首行。
func ReadConnect(r *bufio.Reader) (host string, port uint16, err error) {
	line, err := readLine(r)
	if err != nil {
		return "", 0, err
	}
	return ParseConnectLine(line)
}

// ParseConnectLine 解析 "CONNECT host:port"。
func ParseConnectLine(line string) (host string, port uint16, err error) {
	rest, ok := strings.CutPrefix(line, "CONNECT ")
	if !ok {
		return "", 0, fmt.Errorf("%w: 非 CONNECT 行 %q", errProto, line)
	}
	h, p, err := net.SplitHostPort(rest)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %v", errProto, err)
	}
	pn, err := strconv.ParseUint(p, 10, 16)
	if err != nil || pn == 0 {
		return "", 0, fmt.Errorf("%w: 端口 %q", errProto, p)
	}
	if h == "" {
		return "", 0, fmt.Errorf("%w: 空 host", errProto)
	}
	return h, uint16(pn), nil
}

var errProto = errors.New("flows: 协议错误")

// WriteResponse 写 OK / ERR。
func WriteResponse(w io.Writer, errCode string) error {
	if errCode == "" {
		_, err := io.WriteString(w, "OK\n")
		return err
	}
	_, err := io.WriteString(w, "ERR "+errCode+"\n")
	return err
}

// ReadResponse 读响应；OK 返回 nil，ERR 返回带码错误。
func ReadResponse(r *bufio.Reader) error {
	line, err := readLine(r)
	if err != nil {
		return err
	}
	if line == "OK" {
		return nil
	}
	if code, ok := strings.CutPrefix(line, "ERR "); ok {
		return &RemoteError{Code: code}
	}
	return fmt.Errorf("%w: 未知响应 %q", errProto, line)
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// ---------- 计数（契约：与旧栈 stats 键对齐） ----------

type Stats struct {
	dialOK, dialFail, flows, rejected uint64
	udpReplied, udpNoReply            uint64 // 转发出去的 UDP 会话：收到过回包 / 只有上行（实测 UDP 可用性）
}

func (s *Stats) IncrOK()   { atomic.AddUint64(&s.dialOK, 1) }
func (s *Stats) IncrFail() { atomic.AddUint64(&s.dialFail, 1) }
func (s *Stats) IncrFlow() { atomic.AddUint64(&s.flows, 1) }
func (s *Stats) DecrFlow() { atomic.AddUint64(&s.flows, ^uint64(0)) }

// IncrUDPSession 记一条**有上行流量**的 UDP 会话的归宿：收到过回包 / 没有回包。
// 这是"这条路对真实 UDP 到底通不通"的实测证据（探针只能证明端口级可达）。
func (s *Stats) IncrUDPSession(replied bool) {
	if replied {
		atomic.AddUint64(&s.udpReplied, 1)
		return
	}
	atomic.AddUint64(&s.udpNoReply, 1)
}

// UDPSessions 读 UDP 会话归宿计数（replied, noReply）。
func (s *Stats) UDPSessions() (uint64, uint64) {
	return atomic.LoadUint64(&s.udpReplied), atomic.LoadUint64(&s.udpNoReply)
}

// IncrReject 计一次「并发闸拒绝」（连接在建立流量前被拒）。
func (s *Stats) IncrReject() { atomic.AddUint64(&s.rejected, 1) }
func (s *Stats) Snapshot() map[string]uint64 {
	return map[string]uint64{
		"dialok":   atomic.LoadUint64(&s.dialOK),
		"dialfail": atomic.LoadUint64(&s.dialFail),
		"flows":    atomic.LoadUint64(&s.flows),
		"rejected": atomic.LoadUint64(&s.rejected),
	}
}

// 并发闸与空闲回收默认值（旧栈桥接闸的教训：对端半死时不能让 handler 无限堆积）。
const (
	DefaultMaxConns = 32
	DefaultIdleTime = 5 * time.Minute
)

// Option 服务端可选项（不改既有调用签名）。
type Option func(*limits)

type limits struct {
	maxConns int
	idle     time.Duration
}

// WithMaxConns 每监听端口的并发流上限（超限的连接直接被关，不排队）。
func WithMaxConns(n int) Option { return func(l *limits) { l.maxConns = n } }

// WithIdleTimeout 空闲回收：双向都没有字节流动超过该时长就断开。
func WithIdleTimeout(d time.Duration) Option { return func(l *limits) { l.idle = d } }

// idleConn 给每次读写挂上空闲期限（无需旁观 goroutine）。
type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c *idleConn) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	return c.Conn.Read(p)
}

func (c *idleConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(c.idle))
	return c.Conn.Write(p)
}

// CloseWrite / CloseRead：包装不能把底层能力吞掉——`closeWrite()` 靠类型断言传播半关闭，
// 少了这两个转发方法，半关闭就会在包装层静默失效（对端永远等不到 EOF）。
func (c *idleConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *idleConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

// ---------- TCP 流服务 ----------

// DialFunc 重拨目标（可注入；生产 = 带超时的 net.Dialer）。
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// DefaultDialer：拨号超时 15s。
var DefaultDialer = &net.Dialer{Timeout: 15 * time.Second}

func DefaultDial(ctx context.Context, network, addr string) (net.Conn, error) {
	return DefaultDialer.DialContext(ctx, network, addr)
}

// ServeTCP 在内部流 listener 上服务 CONNECT（accept 循环 + 双向管道 + 并发闸/空闲回收）。
// 返回停止函数。
func ServeTCP(ln net.Listener, dial DialFunc, st *Stats, opts ...Option) (stop func(), err error) {
	if dial == nil {
		dial = DefaultDial
	}
	if st == nil {
		st = &Stats{}
	}
	lim := limits{maxConns: DefaultMaxConns, idle: DefaultIdleTime}
	for _, o := range opts {
		o(&lim)
	}
	if lim.maxConns <= 0 {
		lim.maxConns = DefaultMaxConns
	}
	sem := make(chan struct{}, lim.maxConns)
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					continue
				}
			}
			select {
			case sem <- struct{}{}:
			default:
				// 并发闸：对端半死时不能无限堆积 handler（旧栈桥接闸教训）
				st.IncrReject()
				conn.Close()
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				handleConn(conn, dial, st, lim.idle)
			}()
		}
	}()
	return func() {
		close(done)
		ln.Close()
		wg.Wait()
	}, nil
}

func handleConn(conn net.Conn, dial DialFunc, st *Stats, idle time.Duration) {
	defer conn.Close()
	if idle > 0 {
		conn = &idleConn{Conn: conn, idle: idle}
	}
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return
	}
	br := bufio.NewReader(conn)
	host, port, err := ReadConnect(br)
	if err != nil {
		st.IncrFail()
		return
	}
	conn.SetReadDeadline(time.Time{})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	target, err := dial(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		st.IncrFail()
		WriteResponse(conn, classify(err))
		return
	}
	defer target.Close()
	if idle > 0 {
		target = &idleConn{Conn: target, idle: idle}
	}
	if err := WriteResponse(conn, ""); err != nil {
		return
	}
	st.IncrOK()
	st.IncrFlow()
	defer st.DecrFlow()

	// 双向管道
	var cp sync.WaitGroup
	cp.Add(2)
	// 半关闭必须逐向传播：一端读到 EOF 就 CloseWrite 对端，否则对端在等一个
	// 永远不来的 EOF（测试 cleanup 卡在 wg.Wait() 的根因，见 HANDOFF §5-3）。
	go func() {
		defer cp.Done()
		io.Copy(target, br)
		closeWrite(target)
	}()
	go func() {
		defer cp.Done()
		io.Copy(conn, target)
		closeWrite(conn)
	}()
	cp.Wait()
}

// closeWrite 传播半关闭（TCP 单向 FIN）；不支持该接口的连接忽略。
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func classify(err error) string {
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &dnsErr):
		return ErrCodeNoDNS
	case errors.Is(err, context.DeadlineExceeded):
		return ErrCodeTimeout
	default:
		return ErrCodeRefused
	}
}
