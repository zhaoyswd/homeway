// Package socks：SOCKS5 子集服务端（forward-socks-speedtest 3e §2.3，design D3）。
//
// 「桌面无 VPN 的浏览器承载面」的最小 SOCKS5 实现：no-auth + CONNECT only + 域名/IPv4
// 目标。信任模型 = 本机用户即所有者（监听只应绑 127.0.0.1——由消费方保证，本包不
// 强制但文档如此声明）。BIND / UDP ASSOCIATE 回 rep=command not supported；IPv6 目标
// 回 rep=address type not supported（隧道仅承载 IPv4）。
//
// 域名目标 MUST 经注入 resolver 远程解析（返回**有序候选列表**——本包按序拨，首个拨
// 不通换下一个、全部不通才回失败，r2 新-1）；包内**无本地解析**（零 net.Resolver/
// net.LookupIP 调用——「禁止本地解析」由结构保证）。拨号经注入 dialer（生产 =
// facade 拨号缝）。包保持零 internal/、零 clientcore/ 依赖。
//
// 收口口径：上游拨号失败回 rep=0x01（general failure）+ 本地连接 SetLinger(0) RST
// （app_portfwd 同款教训：优雅 FIN 会让浏览器静默挂住）；解析否定（NXDOMAIN/无 A）
// 回 rep=0x04（host unreachable）——SOCKS5 wire 无文案字段，两类否定形态的文案在
// 消费方日志面区分。双向透传不设 deadline（长连接语义）。
package socks

import (
	"context"
	"errors"
	"fmt"
	"github.com/zhaoyswd/homeway/pkg/connreg"
	"github.com/zhaoyswd/homeway/pkg/netpipe"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Resolver 域名解析注入缝：返回按优先级排序的 IPv4 候选列表（按序拨，r2 新-1）。
// 消费方负责远程解析（经隧道到出口代答）与缓存；本包不做任何本地解析。
type Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

// Dialer 上游拨号注入缝（生产 = facade.Host.Dial——同记账同重建感知）。
type Dialer func(ctx context.Context, dst netip.AddrPort) (net.Conn, error)

// ServerConfig 服务端配置（零值字段取默认）。
type ServerConfig struct {
	Resolver      Resolver             // 域名目标解析（必填——ATYP=domain 的连接依赖它）
	Dialer        Dialer               // 上游拨号（必填）
	MaxConns      int                  // 每 listener 并发连接上限（0 = 256）
	DialBudget    time.Duration        // 单次上游拨号预算（0 = 15s）
	ResolveBudget time.Duration        // 单次解析预算（0 = 5s；套在注入 resolver 外）
	Logf          func(string, ...any) // 拒绝/失败类事件（nil = 丢弃）
}

// SOCKS5 rep 码（RFC 1928）。
const (
	repSucceeded      = 0x00
	repGeneralFailure = 0x01
	repHostUnreach    = 0x04
	repCmdNotSup      = 0x07
	repAddrNotSup     = 0x08
)

const (
	defaultMaxConns      = 256
	defaultDialBudget    = 15 * time.Second
	defaultResolveBudget = 5 * time.Second // design D3：单次解析预算 5s（超时归因、不缓存）
	handshakeReadBudget  = 10 * time.Second
	maxAddrLen           = 1 + 255 + 2 // ATYP + 域名 + 端口

	// accept 瞬态错误的有界线性退避（L6/exec-r1）。
	serveAcceptRetryMax  = 8 // 烧尽 = 返回错误（监听失效如实呈现）
	serveAcceptRetryStep = 50 * time.Millisecond
)

// Server SOCKS5 子集服务端（监听器由消费方创建并交给 Serve；Close 显式关全部在世
// 连接——RST 收口，与「socks off」语义同款）。
type Server struct {
	cfg ServerConfig

	// base 服务端生命周期 ctx：Close 即断（L7/exec-r1——上游拨号预算挂它上，
	// socks off 后不再悬挂等 DialBudget）。
	base       context.Context
	baseCancel context.CancelFunc

	mu    sync.Mutex
	conns connreg.Registry // 按 id 记账（FIX-73：不拿 net.Conn 当 map 键）
}

// New 建服务端。
func New(cfg ServerConfig) *Server {
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = defaultMaxConns
	}
	if cfg.DialBudget <= 0 {
		cfg.DialBudget = defaultDialBudget
	}
	if cfg.ResolveBudget <= 0 {
		cfg.ResolveBudget = defaultResolveBudget
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	s := &Server{cfg: cfg}
	s.base, s.baseCancel = context.WithCancel(context.Background())
	return s
}

// Serve 在 listener 上受理（每连接一个 goroutine）；listener 关闭即返回。accept 的
// 瞬态错误（EMFILE 等）按有界线性退避重试（L6/exec-r1：一次瞬态错误即退 = 无人
// 受理的僵尸监听）；烧尽后返回该错误（消费方按监听失效收口）。
func (s *Server) Serve(ln net.Listener) error {
	backoff := 0
	for {
		conn, err := ln.Accept()
		if err == nil {
			backoff = 0
			id, ok := s.conns.Add(conn, s.cfg.MaxConns)
			if !ok {
				s.cfg.Logf("socks: 连接拒绝（并发上限 %d）", s.cfg.MaxConns)
				_ = conn.Close()
				continue
			}
			go func(conn net.Conn, id uint64) {
				defer func() {
					s.conns.Remove(id)
					_ = conn.Close()
				}()
				s.serveConn(conn)
			}(conn, id)
			continue
		}
		if errors.Is(err, net.ErrClosed) {
			return err // 监听器被关（off/级联/收工）——正常收口
		}
		if backoff >= serveAcceptRetryMax {
			return fmt.Errorf("accept 连续失败（%d 次）：%w", backoff+1, err)
		}
		backoff++
		time.Sleep(time.Duration(backoff) * serveAcceptRetryStep)
	}
}

// Conns 当前在世连接数（status 面可观察）。
func (s *Server) Conns() int { return s.conns.Len() }

// Close 显式关全部在世连接（RST 收口——SetLinger(0)：优雅 FIN 会让浏览器 keep-alive
// 静默挂住；「off」之后不得仍有代理流量经隧道跑）。同时断服务端生命周期 ctx——
// 在途的上游拨号/解析预算随之收口（L7/exec-r1）。

func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.baseCancel()
	// RST 收口全部在世连接（优雅 FIN 会让浏览器 keep-alive 挂住）。
	s.conns.CloseAll(rstClose)
}

// rstClose 置 RST 收口（尽力而为——按接口断言：非 TCP 形态〔含包装连接〕静默忽略）。
func rstClose(c net.Conn) {
	if l, ok := c.(interface{ SetLinger(int) error }); ok {
		_ = l.SetLinger(0)
	}
}

// serveConn 单连接：协商 → 请求 → 解析/拨号 → 回执 → 双向透传。
func (s *Server) serveConn(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(handshakeReadBudget))
	if err := s.negotiate(conn); err != nil {
		s.cfg.Logf("socks: 方法协商失败：%v", err)
		return
	}
	dstHost, dstPort, atyp, err := readRequest(conn)
	if err != nil {
		s.cfg.Logf("socks: 读请求失败：%v", err)
		return
	}
	_ = conn.SetDeadline(time.Time{}) // 数据期不设期限（长连接语义）

	var addrs []netip.Addr
	switch atyp {
	case atypIPv4, atypDomain:
		addrs, err = s.resolveTargets(conn, atyp, dstHost)
	default:
		s.replyRep(conn, repAddrNotSup)
		return
	}
	if err != nil {
		// 解析失败：NXDOMAIN / 无 A / 超时（消费方日志按 error 区分文案）。
		s.cfg.Logf("socks: 解析 %s 失败（rep=0x04）：%v", dstHost, err)
		s.replyRep(conn, repHostUnreach)
		return
	}
	upstream, err := s.dialAny(addrs, dstPort)
	if err != nil {
		s.cfg.Logf("socks: 拨 %s:%d 失败（rep=0x01）：%v", dstHost, dstPort, err)
		s.replyRep(conn, repGeneralFailure)
		rstClose(conn) // B3-a/exec-r1：上游失败本地 RST 收口（tasks 2.3 判据——FIN 会让浏览器静默挂住）
		return
	}
	defer upstream.Close()
	if err := s.replyRep(conn, repSucceeded); err != nil {
		return
	}
	// 半关闭透传（FIX-35）：任一向 EOF 只收该向写端——原先「任一向结束即双向
	// RST+Close」会把半关闭客户端（先关写再读响应）的响应当场截断。RST 只留失败路径。
	netpipe.Both(s.cfg.Logf, conn, upstream)
}

// negotiate 方法协商：只接受 no-auth（客户端须提供 method 0x00，否则回 0xFF 关）。
func (s *Server) negotiate(conn net.Conn) error {
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return fmt.Errorf("读协商头：%w", err)
	}
	if hdr[0] != 0x05 {
		return fmt.Errorf("版本 %d 非 5", hdr[0])
	}
	n := int(hdr[1])
	if n == 0 || n > 255 {
		return errors.New("方法数非法")
	}
	methods := make([]byte, n)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("读方法列表：%w", err)
	}
	for _, m := range methods {
		if m == 0x00 {
			if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
				return fmt.Errorf("回方法选择：%w", err)
			}
			return nil
		}
	}
	if _, err := conn.Write([]byte{0x05, 0xFF}); err != nil {
		return fmt.Errorf("回 0xFF：%w", err)
	}
	return errors.New("客户端不提供 no-auth 方法")
}

const (
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
	cmdConnect = 0x01
)

// readRequest 读 CONNECT 请求头，返回（目标主机/IPv4 串, 端口, ATYP）。
// 非 CONNECT 命令回 rep=0x07 后报错收口；IPv6 ATYP 原样返回（调用方回 0x08）。
func readRequest(conn net.Conn) (host string, port uint16, atyp byte, err error) {
	var hdr [4]byte // VER CMD RSV ATYP
	if _, err = io.ReadFull(conn, hdr[:]); err != nil {
		return "", 0, 0, fmt.Errorf("读请求头：%w", err)
	}
	if hdr[0] != 0x05 {
		return "", 0, 0, errors.New("请求版本非 5")
	}
	if hdr[1] != cmdConnect {
		sRepOnce(conn, repCmdNotSup)
		return "", 0, 0, fmt.Errorf("命令 %d 不支持（仅 CONNECT）", hdr[1])
	}
	var addr []byte
	switch hdr[3] {
	case atypIPv4:
		addr = make([]byte, 4)
	case atypDomain:
		var l [1]byte
		if _, err = io.ReadFull(conn, l[:]); err != nil {
			return "", 0, 0, fmt.Errorf("读域名长度：%w", err)
		}
		if l[0] == 0 {
			return "", 0, 0, errors.New("空域名")
		}
		addr = make([]byte, int(l[0]))
	case atypIPv6:
		addr = make([]byte, 16)
	default:
		return "", 0, 0, fmt.Errorf("ATYP %d 非法", hdr[3])
	}
	if _, err = io.ReadFull(conn, addr); err != nil {
		return "", 0, 0, fmt.Errorf("读目标地址：%w", err)
	}
	var pb [2]byte
	if _, err = io.ReadFull(conn, pb[:]); err != nil {
		return "", 0, 0, fmt.Errorf("读端口：%w", err)
	}
	port = uint16(pb[0])<<8 | uint16(pb[1])
	if hdr[3] == atypIPv4 {
		var ip [4]byte
		copy(ip[:], addr)
		host = netip.AddrFrom4(ip).String()
	}
	if hdr[3] == atypDomain {
		host = string(addr)
	}
	return host, port, hdr[3], nil
}

// sRepOnce 读请求阶段的命令拒绝（还没清 deadline 时的最小回执）。
func sRepOnce(conn net.Conn, rep byte) {
	_, _ = conn.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

// replyRep 回 CONNECT 结果（BND 置零地址——代理不暴露本机绑定）。
func (s *Server) replyRep(conn net.Conn, rep byte) error {
	_, err := conn.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

// resolveTargets 目标 → 按序候选列表：IPv4 照拨（解析权不在本面）；域名经注入
// resolver（预算 = ResolveBudget，超时归因解析超时、不缓存——缓存属消费方 resolver）。
func (s *Server) resolveTargets(conn net.Conn, atyp byte, host string) ([]netip.Addr, error) {
	if atyp == atypIPv4 {
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Is4() {
			return nil, fmt.Errorf("IPv4 目标解析失败：%v", err)
		}
		return []netip.Addr{ip}, nil
	}
	// 预算挂服务端生命周期 ctx（s.base）：off/Close 之后在途解析要**当场收**
	// （FIX-45）——原实现挂 context.Background()，off 只能等 ResolveBudget 烧满，
	// 期间解析腿的回包无人消费（悬挂）。上游拨号腿早已是 s.base（见 dialAny）。
	ctx, cancel := context.WithTimeout(s.base, s.cfg.ResolveBudget)
	defer cancel()
	addrs, err := s.cfg.Resolver(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, errors.New("解析返回空候选")
	}
	return addrs, nil
}

// dialAny 按序拨候选（多 A 回退，r2 新-1）：首个拨不通换下一个，全部不通才回错误。
// L7/exec-r1：总预算 = 一份 DialBudget（N 候选共享——最坏不再 N×15s 悬挂）且挂在
// 服务端生命周期 ctx 上（Server.Close / socks off 即断）。
// N2/exec-r2：每候选子预算 = min(DialBudget, 剩余总预算按剩余候选数均分)——单候选
// 超时（黑洞目标）只烧掉自己的份额，总预算有余仍回退下一候选（超时形态恢复回退
// 能力、总上界不破）；总预算耗尽/服务已关不再试下一候选。
func (s *Server) dialAny(addrs []netip.Addr, port uint16) (net.Conn, error) {
	total, cancel := context.WithTimeout(s.base, s.cfg.DialBudget)
	defer cancel()
	var lastErr error
	for i, ip := range addrs {
		if total.Err() != nil {
			break // 总预算耗尽 / 服务端已关
		}
		deadline, _ := total.Deadline()
		remain := time.Until(deadline)
		if remain <= 0 {
			break
		}
		share := remain / time.Duration(len(addrs)-i) // 剩余候选均分（末候选 = 全部剩余）
		subCtx, subCancel := context.WithTimeout(total, min(s.cfg.DialBudget, share))
		upstream, err := s.cfg.Dialer(subCtx, netip.AddrPortFrom(ip, port))
		subCancel()
		if err == nil {
			return upstream, nil
		}
		lastErr = err
		s.cfg.Logf("socks: 候选 %s 拨不通，换下一个：%v", ip, err)
	}
	if lastErr == nil {
		lastErr = errors.New("无候选")
	}
	return nil, lastErr
}
