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
		return fmt.Errorf("flows: 远端拨号失败 code=%s", code)
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
	dialOK, dialFail, flows uint64
}

func (s *Stats) IncrOK()      { atomic.AddUint64(&s.dialOK, 1) }
func (s *Stats) IncrFail()    { atomic.AddUint64(&s.dialFail, 1) }
func (s *Stats) IncrFlow()    { atomic.AddUint64(&s.flows, 1) }
func (s *Stats) DecrFlow()    { atomic.AddUint64(&s.flows, ^uint64(0)) }
func (s *Stats) Snapshot() map[string]uint64 {
	return map[string]uint64{
		"dialok":   atomic.LoadUint64(&s.dialOK),
		"dialfail": atomic.LoadUint64(&s.dialFail),
		"flows":    atomic.LoadUint64(&s.flows),
	}
}

// ---------- TCP 流服务 ----------

// DialFunc 重拨目标（可注入；生产 = 带超时的 net.Dialer）。
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// DefaultDialer：拨号超时 15s。
var DefaultDialer = &net.Dialer{Timeout: 15 * time.Second}

func DefaultDial(ctx context.Context, network, addr string) (net.Conn, error) {
	return DefaultDialer.DialContext(ctx, network, addr)
}

// ServeTCP 在内部流 listener 上服务 CONNECT（accept 循环 + 双向管道）。
// 返回停止函数。
func ServeTCP(ln net.Listener, dial DialFunc, st *Stats) (stop func(), err error) {
	if dial == nil {
		dial = DefaultDial
	}
	if st == nil {
		st = &Stats{}
	}
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
			wg.Add(1)
			go func() {
				defer wg.Done()
				handleConn(conn, dial, st)
			}()
		}
	}()
	return func() {
		close(done)
		ln.Close()
		wg.Wait()
	}, nil
}

func handleConn(conn net.Conn, dial DialFunc, st *Stats) {
	defer conn.Close()
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
