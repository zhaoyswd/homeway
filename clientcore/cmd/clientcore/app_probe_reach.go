//go:build cshared

// app_probe_reach.go — 添加主机的「连通性探测」导出（App 专用，add-host-connectivity）。
//
// 在**本进程**（App 进程）对 token 端点全集做参照点探测（pkg/probe 明文一问一答）：
// 每端点独立临时 UDP socket、独立 nonce、pad 200、总预算 3s，返回逐端点可达性与 RTT
// （只回报活端点；死端点静默）。纯旁路（spec host-management「与既有连接隔离」）：
// 不进 WG、不登记 peer、无身份、不碰核任何会话状态——与扩展进程的隧道会话和本进程的
// 服务会话均无共享状态，探测期间它们照常运行。
// 域名端点（--ddns）先解析成 IP 再探测（解析预算单独 1.5s，失败不阻塞其余端点）。
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zhaoyswd/homeway/pkg/probe"
	"github.com/zhaoyswd/homeway/pkg/proto"
)

// reachBudget：探测总预算（所有端点并发等满——死端点等满即判不可达）。
const reachBudget = 3 * time.Second

// reachPad：请求填充长度，与核巡检旁路探测同款（200）。
const reachPad = 200

// reachResult 单端点结论（只回报活端点）。
type reachResult struct {
	EP    string `json:"ep"`
	RTTms int64  `json:"rtt_ms"`
	Build string `json:"build"`
	Relay bool   `json:"relay"`
}

//export TailcatProbeReach
func TailcatProbeReach(cToken *C.char) *C.char {
	return cstr(probeReachJSON(C.GoString(cToken)))
}

// probeReachJSON：token → 并发探测 → JSON（纯 Go 主体，测试直调这里）。
// 成功 `{"ok":true,"peer":"…","endpoints":["a:41641","relay:…"],"results":[{"ep","rtt_ms",
// "build","relay"},…]}`（peer/endpoints 与 TailcatProbeAddr 同款——「仍然添加」路径上
// App 仍可用它自动命名与展示；results 只含应答端点，死端点静默）；
// 解析失败 `{"error":"…"}`。
func probeReachJSON(tokenRaw string) string {
	tok, err := proto.DecodeToken(strings.TrimSpace(tokenRaw))
	if err != nil {
		return errJSON(err.Error())
	}
	eps := make([]string, 0, len(tok.Endpoints))
	for _, ep := range tok.Endpoints {
		if ep.Relay {
			eps = append(eps, "relay:"+ep.Addr)
		} else {
			eps = append(eps, ep.Addr)
		}
	}
	var direct, relay []netip.AddrPort
	for _, ep := range tok.Endpoints {
		for _, ap := range resolveReachTarget(ep.Addr) {
			if ep.Relay {
				relay = append(relay, ap)
			} else {
				direct = append(direct, ap)
			}
		}
	}
	direct = dedupAddrPorts(direct)
	relay = dedupAddrPorts(relay)

	var mu sync.Mutex
	out := make([]reachResult, 0, len(direct)+len(relay))
	var wg sync.WaitGroup
	probeOne := func(target netip.AddrPort, isRelay bool) {
		defer wg.Done()
		pc, err := net.ListenUDP("udp", nil)
		if err != nil {
			return
		}
		defer pc.Close()
		ctx, cancel := context.WithTimeout(context.Background(), reachBudget)
		defer cancel()
		res, err := probe.PingEx(ctx, pc, target, "", reachPad)
		if err != nil {
			return // 死端点是预期：不回报
		}
		mu.Lock()
		out = append(out, reachResult{EP: target.String(), RTTms: res.RTT.Milliseconds(), Build: res.Build, Relay: isRelay})
		mu.Unlock()
	}
	for _, ap := range direct {
		wg.Add(1)
		go probeOne(ap, false)
	}
	for _, ap := range relay {
		wg.Add(1)
		go probeOne(ap, true)
	}
	wg.Wait()
	body, err := json.Marshal(map[string]any{
		"ok":        true,
		"peer":      fmt.Sprintf("%x", tok.PeerID[:6]),
		"endpoints": eps,
		"results":   out,
	})
	if err != nil {
		return errJSON(err.Error())
	}
	return string(body)
}

// resolveReachTarget：addr "host:port"（host 可为域名）→ 探测目标集。
// 端口非数字/越界返回 nil；域名解析失败返回 nil（不阻塞其余端点）。
func resolveReachTarget(addr string) []netip.AddrPort {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil
	}
	if ip, perr := netip.ParseAddr(host); perr == nil {
		return []netip.AddrPort{netip.AddrPortFrom(ip.Unmap(), uint16(port))}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	ips, lerr := net.DefaultResolver.LookupIPAddr(ctx, host)
	if lerr != nil {
		return nil
	}
	var out []netip.AddrPort
	for _, ia := range ips {
		if ip, ok := netip.AddrFromSlice(ia.IP); ok {
			out = append(out, netip.AddrPortFrom(ip.Unmap(), uint16(port)))
		}
	}
	return out
}

// dedupAddrPorts：去重（域名可能解析出与字面端点相同的 IP；重复探测无意义）。
func dedupAddrPorts(in []netip.AddrPort) []netip.AddrPort {
	seen := make(map[netip.AddrPort]bool, len(in))
	out := make([]netip.AddrPort, 0, len(in))
	for _, ap := range in {
		if !seen[ap] {
			seen[ap] = true
			out = append(out, ap)
		}
	}
	return out
}
