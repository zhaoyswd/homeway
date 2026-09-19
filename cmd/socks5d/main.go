// socks5d：开发/验证用的**最小 SOCKS5 服务端**（CONNECT + UDP ASSOCIATE）。
//
// 用途：验证 `homewayd serve --forward-via-proxy=socks5://… --forward-udp=auto|on` 的
// UDP 支路。多数图形代理（Surge 等）不支持 UDP ASSOCIATE，必须有一个人造的"支持 UDP 的
// SOCKS5"才能把这条路走通；否则只能测到"不支持 ⇒ 回落直出"。
//
//	# 在出口机器上跑（默认只监听回环；给别的机器用要显式 --listen 并加 --allow）
//	socks5d --listen 0.0.0.0:1080 --allow 203.0.113.7
//
// 刻意不做的事：不做认证（--allow 是唯一门禁）、不转发 IPv6 之外的奇怪地址族、
// 不在没有 --allow 时监听非回环地址（避免变成开放代理）。
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

const (
	socks5Version = 0x05
	cmdConnect    = 0x01
	cmdUDPAssoc   = 0x03
	atypV4        = 0x01
	atypName      = 0x03
	atypV6        = 0x04
)

func main() {
	listen := flag.String("listen", "127.0.0.1:1080", "监听地址（非回环时必须给 --allow）")
	allow := flag.String("allow", "", "允许的客户端 IP（逗号分隔；空 = 只允许回环客户端）")
	flag.Parse()

	allowIPs := []netip.Addr{}
	for _, s := range strings.Split(*allow, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		ip, err := netip.ParseAddr(s)
		if err != nil {
			fmt.Fprintf(os.Stderr, "socks5d: --allow %q 不是 IP：%v\n", s, err)
			os.Exit(2)
		}
		allowIPs = append(allowIPs, ip.Unmap())
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "socks5d: --listen %q：%v\n", *listen, err)
		os.Exit(2)
	}
	if h, perr := netip.ParseAddr(host); perr == nil && !h.IsLoopback() && len(allowIPs) == 0 {
		fmt.Fprintln(os.Stderr, "socks5d: 拒绝在非回环地址上无 --allow 启动（会变成开放代理）")
		os.Exit(2)
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "socks5d:", err)
		os.Exit(1)
	}
	logf("socks5d 就绪 %s（支持 CONNECT + UDP ASSOCIATE）allow=%v", ln.Addr(), allowIPs)
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		if !allowed(c.RemoteAddr(), allowIPs) {
			logf("拒绝未授权客户端 %v", c.RemoteAddr())
			_ = c.Close()
			continue
		}
		go handle(c)
	}
}

func logf(format string, args ...any) {
	fmt.Printf("[socks5d] "+format+"\n", args...)
}

func allowed(addr net.Addr, allow []netip.Addr) bool {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() {
		return true
	}
	for _, a := range allow {
		if a == ip {
			return true
		}
	}
	return false
}

func handle(c net.Conn) {
	defer c.Close()
	var head [2]byte
	if _, err := io.ReadFull(c, head[:]); err != nil || head[0] != socks5Version {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	if _, err := c.Write([]byte{socks5Version, 0x00}); err != nil { // 只支持无认证
		return
	}
	var req [3]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return
	}
	dst, name, err := readAddr(c)
	if err != nil {
		return
	}
	if name != "" {
		ips, lerr := net.LookupIP(name)
		if lerr != nil || len(ips) == 0 {
			_ = writeReply(c, 0x04, netip.AddrPort{}) // host unreachable
			return
		}
		if a, ok := netip.AddrFromSlice(ips[0]); ok {
			dst = netip.AddrPortFrom(a, dst.Port())
		}
	}
	switch req[1] {
	case cmdConnect:
		up, derr := net.DialTimeout("tcp", dst.String(), 10*time.Second)
		if derr != nil {
			logf("CONNECT %v 失败：%v", dst, derr)
			_ = writeReply(c, 0x05, netip.AddrPort{})
			return
		}
		defer up.Close()
		bnd := netip.AddrPort{}
		if la, ok := up.LocalAddr().(*net.TCPAddr); ok {
			bnd = la.AddrPort()
		}
		if err := writeReply(c, 0x00, bnd); err != nil {
			return
		}
		logf("CONNECT %v ← %v", dst, c.RemoteAddr())
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
		go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
		<-done
	case cmdUDPAssoc:
		network := "udp4"
		if dst.Addr().Is6() && !dst.Addr().IsUnspecified() {
			network = "udp6"
		}
		pc, derr := net.ListenUDP(network, nil)
		if derr != nil {
			_ = writeReply(c, 0x01, netip.AddrPort{})
			return
		}
		defer pc.Close()
		if err := writeReply(c, 0x00, pc.LocalAddr().(*net.UDPAddr).AddrPort()); err != nil {
			return
		}
		logf("UDP ASSOCIATE ← %v（中继 %v）", c.RemoteAddr(), pc.LocalAddr())
		relayUDP(c, pc)
	default:
		_ = writeReply(c, 0x07, netip.AddrPort{})
	}
}

// relayUDP：单读循环 + "客户端第一条数据报定源"（RFC 1928 的常见实现）。
func relayUDP(ctrl net.Conn, pc *net.UDPConn) {
	closed := make(chan struct{})
	go func() {
		buf := make([]byte, 64)
		for {
			if _, err := ctrl.Read(buf); err != nil {
				close(closed)
				return
			}
		}
	}()
	ctrlIPStr, _, _ := net.SplitHostPort(ctrl.RemoteAddr().String())
	ctrlIP, _ := netip.ParseAddr(ctrlIPStr)
	var client netip.AddrPort
	var up, down uint64
	buf := make([]byte, 65535)
	for {
		select {
		case <-closed:
			logf("UDP 关联结束（上行 %d 包 / 下行 %d 包）", atomic.LoadUint64(&up), atomic.LoadUint64(&down))
			return
		default:
		}
		_ = pc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, from, err := pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			continue
		}
		if !client.IsValid() && ctrlIP.IsValid() && from.Addr().Unmap() == ctrlIP.Unmap() {
			client = from
		}
		if from != client {
			if !client.IsValid() {
				continue
			}
			out := append([]byte{0, 0, 0}, mustAddr(from)...)
			out = append(out, buf[:n]...)
			_, _ = pc.WriteToUDPAddrPort(out, client)
			atomic.AddUint64(&down, 1)
			continue
		}
		if n < 4 || buf[2] != 0 {
			continue
		}
		dst, _, derr := readAddrSlice(buf[3:n])
		if derr != nil {
			continue
		}
		alen := addrLen(buf[3:n])
		if alen <= 0 || 3+alen > n {
			continue
		}
		_, _ = pc.WriteToUDPAddrPort(buf[3+alen:n], dst)
		atomic.AddUint64(&up, 1)
	}
}

func mustAddr(ap netip.AddrPort) []byte {
	b, err := encodeAddr(ap.Addr().String(), ap.Port())
	if err != nil {
		panic(err)
	}
	return b
}

func writeReply(c net.Conn, rep byte, bound netip.AddrPort) error {
	out := []byte{socks5Version, rep, 0x00}
	b := netip.AddrPort{}
	if bound.IsValid() {
		b = bound
	}
	addr, err := encodeAddr(b.Addr().String(), b.Port())
	if err != nil {
		return err
	}
	out = append(out, addr...)
	_, err = c.Write(out)
	return err
}

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
		if host == "" || host == "<nil>" {
			out = append(out, atypV4, 0, 0, 0, 0)
		} else {
			if len(host) > 255 {
				return nil, fmt.Errorf("域名过长")
			}
			out = append(out, atypName, byte(len(host)))
			out = append(out, host...)
		}
	}
	out = binary.BigEndian.AppendUint16(out, port)
	return out, nil
}

func readAddr(r io.Reader) (netip.AddrPort, string, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return netip.AddrPort{}, "", err
	}
	var host string
	switch atyp[0] {
	case atypV4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return netip.AddrPort{}, "", err
		}
		host = netip.AddrFrom4(b).String()
	case atypV6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return netip.AddrPort{}, "", err
		}
		host = netip.AddrFrom16(b).String()
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
		return netip.AddrPort{}, "", fmt.Errorf("未知地址类型 0x%02x", atyp[0])
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return netip.AddrPort{}, "", err
	}
	ip, _ := netip.ParseAddr(host)
	return netip.AddrPortFrom(ip, binary.BigEndian.Uint16(port[:])), "", nil
}

func readAddrSlice(b []byte) (netip.AddrPort, string, error) {
	return readAddr(bytes.NewReader(b))
}

// addrLen：SOCKS5 地址段的字节长度（含 ATYP 与端口）；非法返回 -1。
func addrLen(b []byte) int {
	if len(b) < 1 {
		return -1
	}
	switch b[0] {
	case atypV4:
		return 7
	case atypV6:
		return 19
	case atypName:
		if len(b) < 2 {
			return -1
		}
		return 4 + int(b[1])
	default:
		return -1
	}
}
