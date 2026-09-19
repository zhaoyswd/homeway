package server

// `--forward-egress=auto`（默认）的运行期重算：默认路由**变成**隧道型网卡（用户开了 Surge）
// 或**变回**物理网卡（关掉 Surge）时，转发路径跟着走 —— 不用重启出口。
//
// 判据与开机时同源（resolveEgressPolicy）：默认路由是隧道型 ⇒ TCP 交给代理的规则、UDP 钉物理网卡；
// 是物理网卡 ⇒ 两块都钉它（与走默认路由等价）。

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/zhaoyswd/homeway/pkg/egress"
)

// egressRecheck：重算节拍（默认路由变化不是高频事件，30s 足够；开销就是一次 UDP dial 查路由）。
const egressRecheck = 30 * time.Second

// watchEgressPolicy：周期重算并应用；mode 全为显式时直接返回（不覆盖用户选择）。
func watchEgressPolicy(ctx context.Context, cfg ForwardEgress, interval time.Duration,
	logf func(string, ...any), resolve func() (EgressMode, EgressMode), apply func(EgressMode, EgressMode)) {
	if cfg.TCP != EgressAuto && cfg.UDP != EgressAuto {
		return // 显式指定：不动
	}
	if logf == nil {
		logf = log.Printf
	}
	if interval <= 0 {
		interval = egressRecheck
	}
	go func() {
		last := ""
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			tcp, udp := resolve()
			key := string(tcp) + "/" + string(udp)
			if key != last {
				last = key
				apply(tcp, udp)
				cur := egress.PreferredIface()
				name := "（没有默认路由）"
				if cur != nil {
					name = cur.Name
				}
				logf("Egress：转发路径 auto ⇒ TCP %s / UDP %s（默认路由卡 %s）", tcp, udp, name)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

// ifaceForMode：该模式该钉哪张卡（default = 不钉）。
func ifaceForMode(m EgressMode, ifi *net.Interface) *net.Interface {
	if m == EgressDefault {
		return nil
	}
	return ifi
}
