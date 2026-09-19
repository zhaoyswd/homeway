package proxy

// 最小 SOCKS5 客户端（RFC 1928 + RFC 1929）：CONNECT（TCP）与 UDP ASSOCIATE（UDP 中继）。
//
// 为什么不用 golang.org/x/net/proxy：它只覆盖 CONNECT，UDP ASSOCIATE 与 UDP 数据报封装
// 都得自己写；两半放一起改一处不会漂。

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"
)

const (
	socks5Version = 0x05

	methodNoAuth   = 0x00
	methodUserPass = 0x02
	methodNone     = 0xff

	cmdConnect      = 0x01
	cmdUDPAssociate = 0x03

	atypV4   = 0x01
	atypName = 0x03
	atypV6   = 0x04

	repSuccess          = 0x00
	repCommandNotSupprt = 0x07 // Command not supported：UDP ASSOCIATE 的确定性否定
	repNotAllowed       = 0x02 // Connection not allowed by ruleset
)

var errSocksProto = errors.New("proxy: SOCKS5 协议错误")

// Reply 码中文（日志用；便于一眼看出"代理不支持 UDP"）。
func repString(rep byte) string {
	switch rep {
	case 0x00:
		return "成功"
	case 0x01:
		return "代理内部错误"
	case 0x02:
		return "规则不允许"
	case 0x03:
		return "网络不可达"
	case 0x04:
		return "主机不可达"
	case 0x05:
		return "连接被拒"
	case 0x06:
		return "TTL 过期"
	case 0x07:
		return "不支持该命令（UDP ASSOCIATE）"
	case 0x08:
		return "地址类型不支持"
	default:
		return fmt.Sprintf("未知回复码 0x%02x", rep)
	}
}

// handshake 完成方法协商 + 认证。
func handshake(conn net.Conn, user, pass string, deadline time.Time) error {
	_ = conn.SetDeadline(deadline)
	methods := []byte{methodNoAuth}
	if user != "" {
		methods = []byte{methodNoAuth, methodUserPass}
	}
	req := append([]byte{socks5Version, byte(len(methods))}, methods...)
	if _, err := conn.Write(req); err != nil {
		return err
	}
	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return err
	}
	if resp[0] != socks5Version {
		return fmt.Errorf("%w: 版本 %d", errSocksProto, resp[0])
	}
	switch resp[1] {
	case methodNoAuth:
		return nil
	case methodUserPass:
		if user == "" {
			return fmt.Errorf("%w: 代理要求用户名密码，但未配置", errSocksProto)
		}
		authReq := []byte{0x01, byte(len(user))}
		authReq = append(authReq, user...)
		authReq = append(authReq, byte(len(pass)))
		authReq = append(authReq, pass...)
		if _, err := conn.Write(authReq); err != nil {
			return err
		}
		var ar [2]byte
		if _, err := io.ReadFull(conn, ar[:]); err != nil {
			return err
		}
		if ar[1] != 0x00 {
			return fmt.Errorf("%w: 认证失败", errSocksProto)
		}
		return nil
	case methodNone:
		return fmt.Errorf("%w: 代理不接受无认证/用户密码", errSocksProto)
	default:
		return fmt.Errorf("%w: 代理选择了未知方法 0x%02x", errSocksProto, resp[1])
	}
}

// encodeAddr 把 host:port 编成 SOCKS5 地址段。
func encodeAddr(host string, port uint16) ([]byte, error) {
	out := []byte{}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Unmap().Is4() {
			out = append(out, atypV4)
			a4 := ip.Unmap().As4()
			out = append(out, a4[:]...)
		} else {
			out = append(out, atypV6)
			a16 := ip.As16()
			out = append(out, a16[:]...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("域名过长：%d", len(host))
		}
		out = append(out, atypName, byte(len(host)))
		out = append(out, host...)
	}
	out = binary.BigEndian.AppendUint16(out, port)
	return out, nil
}

// readAddr 读一个 SOCKS5 地址段。
func readAddr(r io.Reader) (netip.AddrPort, string, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return netip.AddrPort{}, "", err
	}
	switch atyp[0] {
	case atypV4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return netip.AddrPort{}, "", err
		}
		var port [2]byte
		if _, err := io.ReadFull(r, port[:]); err != nil {
			return netip.AddrPort{}, "", err
		}
		return netip.AddrPortFrom(netip.AddrFrom4(b), binary.BigEndian.Uint16(port[:])), "", nil
	case atypV6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return netip.AddrPort{}, "", err
		}
		var port [2]byte
		if _, err := io.ReadFull(r, port[:]); err != nil {
			return netip.AddrPort{}, "", err
		}
		return netip.AddrPortFrom(netip.AddrFrom16(b), binary.BigEndian.Uint16(port[:])), "", nil
	case atypName:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return netip.AddrPort{}, "", err
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return netip.AddrPort{}, "", err
		}
		var port [2]byte
		if _, err := io.ReadFull(r, port[:]); err != nil {
			return netip.AddrPort{}, "", err
		}
		return netip.AddrPortFrom(netip.Addr{}, binary.BigEndian.Uint16(port[:])), string(name), nil
	default:
		return netip.AddrPort{}, "", fmt.Errorf("%w: 地址类型 0x%02x", errSocksProto, atyp[0])
	}
}

// request 发一条命令并解析回复（返回 BND 地址与 REP 码；REP != 0 时也解析，便于归因）。
func request(conn net.Conn, cmd byte, dst []byte, deadline time.Time) (netip.AddrPort, byte, error) {
	_ = conn.SetDeadline(deadline)
	req := append([]byte{socks5Version, cmd, 0x00}, dst...)
	if _, err := conn.Write(req); err != nil {
		return netip.AddrPort{}, 0, err
	}
	var head [3]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return netip.AddrPort{}, 0, err
	}
	if head[0] != socks5Version {
		return netip.AddrPort{}, 0, fmt.Errorf("%w: 回复版本 %d", errSocksProto, head[0])
	}
	rep := head[1]
	bound, _, err := readAddr(conn)
	if err != nil {
		return netip.AddrPort{}, rep, err
	}
	return bound, rep, nil
}

// UDPConn：SOCKS5 UDP ASSOCIATE 之后的一条 UDP 通道（net.Conn 形状 + 目标地址）。
// WriteTo 把目标写进 SOCKS5 UDP 头；Read 解出真实来源地址。
type UDPConn struct {
	ctrl net.Conn     // 控制连接：关掉它就撤销关联
	pc   *net.UDPConn // 到代理中继端口的 socket
}

// OpenUDPConn 通过代理建立一条 UDP 关联（dst 仅用于日志/未来"连到特定目标"的优化，
// SOCKS5 的中继本身是按数据报头逐个转发）。
func (c *Client) OpenUDPConn(ctx context.Context, _ netip.AddrPort) (*UDPConn, error) {
	deadline := time.Now().Add(c.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	ctrl, err := c.dialControl(ctx)
	if err != nil {
		return nil, err
	}
	if err := handshake(ctrl, c.user, c.pass, deadline); err != nil {
		ctrl.Close()
		return nil, err
	}
	// DST 全零表示"不限定目标"（RFC 1928 允许）；中继端返回 BND 供我们发数据。
	zero, err := encodeAddr("0.0.0.0", 0)
	if err != nil {
		ctrl.Close()
		return nil, err
	}
	bound, rep, err := request(ctrl, cmdUDPAssociate, zero, deadline)
	if err != nil {
		ctrl.Close()
		return nil, err
	}
	if rep != repSuccess {
		ctrl.Close()
		return nil, &ReplyError{Rep: rep}
	}
	relay := bound
	if !relay.Addr().IsValid() || relay.Addr().IsUnspecified() {
		// 代理给的是 0.0.0.0/::（常见：中继监听在通配地址）⇒ 按 RFC 用控制连接的**主机**
		// 替换地址；**端口必须保留 BND 里的那个**（那才是中继的 UDP 端口，控制连接的端口
		// 是 TCP 的，两者无关——踩过：换掉端口后数据报全打到 TCP 端口上，表现为"中继建了但没应答"）。
		host, ctrlPortStr, serr := net.SplitHostPort(ctrl.RemoteAddr().String())
		if serr == nil {
			port := relay.Port()
			if port == 0 {
				if p, perr := strconv.ParseUint(ctrlPortStr, 10, 16); perr == nil {
					port = uint16(p)
				}
			}
			if ip, ierr := netip.ParseAddr(host); ierr == nil && port != 0 {
				relay = netip.AddrPortFrom(ip, port)
			}
		}
	}
	if !relay.IsValid() || relay.Port() == 0 {
		ctrl.Close()
		return nil, fmt.Errorf("%w: 代理没有给可用的 UDP 中继地址", errSocksProto)
	}
	network := "udp4"
	if relay.Addr().Unmap().Is6() {
		network = "udp6"
	}
	pc, err := net.DialUDP(network, nil, net.UDPAddrFromAddrPort(relay))
	if err != nil {
		ctrl.Close()
		return nil, err
	}
	_ = ctrl.SetDeadline(time.Time{})
	return &UDPConn{ctrl: ctrl, pc: pc}, nil
}

// ReplyError：代理以 REP 码拒绝（供上层归因"代理不支持 UDP"这类确定性否定）。
type ReplyError struct{ Rep byte }

func (e *ReplyError) Error() string { return "proxy: 代理拒绝：" + repString(e.Rep) }

// Unsupported 是"确定性否定"（不支持该命令 / 规则不允许）吗。
func (e *ReplyError) Unsupported() bool {
	return e.Rep == repCommandNotSupprt || e.Rep == repNotAllowed
}

// WriteToUDPAddrPort 组一条 SOCKS5 UDP 数据报（RSV RSV FRAG ATYP ADDR PORT DATA）。
func (u *UDPConn) WriteToUDPAddrPort(p []byte, dst netip.AddrPort) (int, error) {
	head := []byte{0, 0, 0}
	addr, err := encodeAddr(dst.Addr().String(), dst.Port())
	if err != nil {
		return 0, err
	}
	head = append(head, addr...)
	buf := make([]byte, 0, len(head)+len(p))
	buf = append(buf, head...)
	buf = append(buf, p...)
	if _, err := u.pc.Write(buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

// ReadFromUDPAddrPort 解一条 SOCKS5 UDP 数据报，返回真实来源地址。
func (u *UDPConn) ReadFromUDPAddrPort(p []byte) (int, netip.AddrPort, error) {
	buf := make([]byte, 65535)
	n, err := u.pc.Read(buf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	if n < 4 {
		return 0, netip.AddrPort{}, fmt.Errorf("%w: UDP 数据报过短", errSocksProto)
	}
	if buf[2] != 0x00 {
		return 0, netip.AddrPort{}, fmt.Errorf("%w: 不支持分片（FRAG=%d）", errSocksProto, buf[2])
	}
	body := buf[3:n]
	src, _, err := readAddr(bytes.NewReader(body))
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	addrLen := addrSectionLen(body)
	if addrLen <= 0 || addrLen > len(body) {
		return 0, netip.AddrPort{}, fmt.Errorf("%w: UDP 数据报地址段非法", errSocksProto)
	}
	payload := body[addrLen:]
	return copy(p, payload), src, nil
}

// addrSectionLen 算一条 SOCKS5 地址段的字节长度（含端口）；非法返回 -1。
func addrSectionLen(b []byte) int {
	if len(b) < 1 {
		return -1
	}
	switch b[0] {
	case atypV4:
		return 1 + 4 + 2
	case atypV6:
		return 1 + 16 + 2
	case atypName:
		if len(b) < 2 {
			return -1
		}
		return 1 + 1 + int(b[1]) + 2
	default:
		return -1
	}
}

func (u *UDPConn) SetReadDeadline(t time.Time) error  { return u.pc.SetReadDeadline(t) }
func (u *UDPConn) SetWriteDeadline(t time.Time) error { return u.pc.SetWriteDeadline(t) }
func (u *UDPConn) Close() error {
	if u.ctrl != nil {
		_ = u.ctrl.Close()
	}
	return u.pc.Close()
}
func (u *UDPConn) LocalAddr() net.Addr { return u.pc.LocalAddr() }
