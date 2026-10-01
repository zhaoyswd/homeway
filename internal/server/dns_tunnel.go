package server

import (
	"fmt"
	"net"
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"

	"github.com/zhaoyswd/homeway/pkg/wgnet"
)

// listenTunnelDNS：DNS 代答在**隧道栈内**建监听面（FIX-60）。
//
//	隧道 IP:53    UDP + TCP —— 手机声明的 DNS（demux 直投真 listener，不经拦截层
//	                          改写；应答源地址即隧道 IP:53）
//	隧道 IP:port  TCP        —— 客户端远程解析腿（clientcore 拨 5300 做域名解析）
//
// port == 53 时不再重复建解析腿。逐面无害：任一面失败只记该面的错误，其余照常
// 服务（调用方逐条告警；全失败才摘除代答）。
func listenTunnelDNS(ns *wgnet.Net, tunnelIP netip.Addr, port uint16) (pcs []net.PacketConn, lns []net.Listener, errs []error) {
	netProto := ipv4.ProtocolNumber
	if tunnelIP.Is6() {
		netProto = ipv6.ProtocolNumber
	}
	ip := tcpip.AddrFromSlice(tunnelIP.AsSlice())

	if pc, err := gonet.DialUDP(ns.Stack(), &tcpip.FullAddress{Addr: ip, Port: 53}, nil, netProto); err != nil {
		errs = append(errs, fmt.Errorf("隧道 %v:53 udp：%w", tunnelIP, err))
	} else {
		pcs = append(pcs, pc)
	}
	if ln, err := gonet.ListenTCP(ns.Stack(), tcpip.FullAddress{Addr: ip, Port: 53}, netProto); err != nil {
		errs = append(errs, fmt.Errorf("隧道 %v:53 tcp：%w", tunnelIP, err))
	} else {
		lns = append(lns, ln)
	}
	if port != 53 {
		if ln, err := gonet.ListenTCP(ns.Stack(), tcpip.FullAddress{Addr: ip, Port: port}, netProto); err != nil {
			errs = append(errs, fmt.Errorf("隧道 %v:%d tcp（客户端解析腿）：%w", tunnelIP, port, err))
		} else {
			lns = append(lns, ln)
		}
	}
	return pcs, lns, errs
}
