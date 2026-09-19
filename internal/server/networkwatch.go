package server

// 出口的换网自愈：网卡**索引/地址/link 状态**变了就重新钉一次 socket，并立刻重测公网端点。
//
// 为什么必须分开做（2026-09-19 与用户讨论后定）：
//   - 「绑卡」管的是 **socket 从哪张网卡出去**（TUN 型代理抢默认路由时，不绑就会走代理，
//     STUN 观测到的是代理的映射 ⇒ 打洞/端点公布全废）；
//   - 「换网重绑」管的是 **网卡切换后让 socket 跟上**（Wi-Fi 换网、接口索引变化、接口消失再回来）。
//     两者正交：重新开一个 socket 并不会绕开默认路由上的代理，所以它替代不了绑卡；
//     反过来绑了卡也不会自动跟上接口变化，所以需要这里的监视。
//
// 客户端（手机）侧有同样的机制（App net observer → TailcatTunRebind）；出口以前只有
// 10 分钟一轮的 STUN 轮询，换网后端点最多 stale 10 分钟，接口索引变了还会把 socket 钉在死索引上。

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"time"
)

// netInterval：轮询节拍。换网是低频事件，5s 足够快且几乎不耗电（出口常驻在 macOS/Linux 上）。
const netInterval = 5 * time.Second

// ifaceState：一张网卡的指纹（索引 + up + 地址集合）。
type ifaceState struct {
	index int
	up    bool
	addrs string
}

func (s ifaceState) String() string {
	up := "down"
	if s.up {
		up = "up"
	}
	return fmt.Sprintf("index=%d %s addrs=[%s]", s.index, up, s.addrs)
}

// probeIface 读一张网卡当前的指纹（网卡不存在/查询失败时返回 error）。
//
// 只看 **IPv4 地址**：macOS 的 IPv6 临时地址（privacy extensions）会自行轮换，算进指纹会
// 频繁误触发重钉；换网真正影响的是 IPv4 地址与接口索引。
func probeIface(name string) (ifaceState, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return ifaceState{}, err
	}
	var addrs []string
	if as, err := ifi.Addrs(); err == nil {
		for _, a := range as {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				addrs = append(addrs, ipn.String())
			}
		}
	}
	sort.Strings(addrs)
	return ifaceState{index: ifi.Index, up: ifi.Flags&net.FlagUp != 0, addrs: strings.Join(addrs, ",")}, nil
}

// WatchNetwork 起后台监视（非阻塞）。ifName 为空表示出口没绑卡，直接返回。
func WatchNetwork(ctx context.Context, ifName string,
	repin func() (*net.Interface, error), onChanged func(), logf func(string, ...any)) {
	if ifName == "" {
		return
	}
	if logf == nil {
		logf = log.Printf
	}
	watchNetwork(ctx, ifName, func() (ifaceState, error) { return probeIface(ifName) }, repin, onChanged, logf, netInterval)
}

// watchNetwork 是 WatchNetwork 的可测内核（probe/interval 可注入）。
func watchNetwork(ctx context.Context, ifName string, probe func() (ifaceState, error),
	repin func() (*net.Interface, error), onChanged func(), logf func(string, ...any), interval time.Duration) {
	go func() {
		prev, prevErr := probe()
		if prevErr == nil {
			logf("网络监视：网卡 %s 当前 %s（变化即重钉 socket + 重测公网端点）", ifName, prev)
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			cur, err := probe()
			switch {
			case err != nil:
				if prevErr == nil {
					logf("网络变化：网卡 %s 不可用（%v）—— 等它回来", ifName, err)
					prevErr = err
				}
				continue
			case prevErr != nil:
				logf("网络变化：网卡 %s 回来了（%s）", ifName, cur)
			case cur == prev:
				continue
			default:
				logf("网络变化：网卡 %s %s → %s", ifName, prev, cur)
			}
			prev, prevErr = cur, nil
			if repin != nil {
				ifi, rerr := repin()
				if rerr != nil {
					logf("网络变化：重新钉网卡 %s 失败（%v）", ifName, rerr)
				} else if ifi != nil {
					logf("网络变化：已重新钉到 %s（index=%d）", ifi.Name, ifi.Index)
				}
			}
			if onChanged != nil {
				onChanged()
			}
		}
	}()
}
