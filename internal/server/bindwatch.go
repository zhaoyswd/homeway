package server

// 出口的「WG socket 钉哪张物理网卡」：默认**自动挑**，换网自动重挑 + 重钉。
//
// 三件事的关系（2026-09-19 与用户讨论后定稿）：
//   - **钉卡**决定 socket 从哪张卡出去。默认路由可能被 TUN 型代理（Surge 等）抢走，不钉就会走代理，
//     STUN 观测到的是代理的映射 ⇒ 打洞/端点公布全废。所以这件事**默认要做**，不是可选项。
//   - **挑哪张卡**用探针决定（`egress.SelectBest`）：从候选物理网卡各发一次 anycast DNS 探针，
//     校验事务 ID + 来源，取最快探通的 —— 只认「真能出网」这张判据，不看默认路由。
//   - **换网重挑**：网卡索引/地址变化、或当前卡连探针都不通（连续两次）就重新挑一次，重钉 socket，
//     并踢一轮公网端点探测（不必等下一个 10 分钟窗口）。
//
// 兜底：候选全探不通时**不绑**（退回系统默认路由）并打一行明确日志 —— 永远不要因为挑不到卡就不启动。

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/zhaoyswd/homeway/pkg/egress"
)

// bindInterval：轮询节拍（换网是低频事件；5s 足够快，开销可忽略）。
const bindInterval = 5 * time.Second

// bindHealthEvery：每多少个节拍做一次"当前卡还通不通"的探针（5s × 12 = 60s）。
const bindHealthEvery = 12

// bindFailsBeforeSwitch：当前卡连续几次探针失败才切换（防抖）。
const bindFailsBeforeSwitch = 2

// ifaceState：一张网卡的指纹（索引 + up + IPv4 地址）。
// 只看 IPv4：macOS 的 IPv6 临时地址会自行轮换，算进来会频繁误触发。
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

func stateOf(ifi *net.Interface) ifaceState {
	if ifi == nil {
		return ifaceState{}
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
	return ifaceState{index: ifi.Index, up: ifi.Flags&net.FlagUp != 0, addrs: strings.Join(addrs, ",")}
}

// BindWatchOpts：绑卡看护的参数（Resolve/Probe 可注入，便于单测）。
type BindWatchOpts struct {
	Explicit     *net.Interface                        // 显式指定（--bind-interface <网卡名>）：只做重解析
	ProbeTargets []netip.AddrPort                      // 探针目标（默认 anycast DNS）
	Repin        func(*net.Interface) error            // 把 WG socket 钉到这张卡（servercore.ServerBind.RepinTo）
	OnChange     func()                                // 换卡后要做的事（踢公网端点重测）
	Logf         func(string, ...any)
	Interval     time.Duration
	// Resolve：挑一张要钉的卡。auto = 候选探针取最快；explicit = 按名字重解析。
	Resolve func(ctx context.Context) (*net.Interface, error)
	// Probe：健康检查（当前卡还能出网吗）。
	Probe func(ctx context.Context, ifi *net.Interface) error
	// State：读一张卡的指纹（默认 stateOf；单测注入用）。
	State func(*net.Interface) ifaceState
}

// WatchBind 起后台看护（非阻塞）。
func WatchBind(ctx context.Context, o BindWatchOpts) {
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.Interval <= 0 {
		o.Interval = bindInterval
	}
	if o.ProbeTargets == nil {
		o.ProbeTargets = egress.DefaultProbeTargets()
	}
	if o.Resolve == nil {
		if o.Explicit != nil {
			name := o.Explicit.Name
			o.Resolve = func(context.Context) (*net.Interface, error) {
				ifi, err := net.InterfaceByName(name)
				if err != nil {
					return nil, fmt.Errorf("网卡 %s 当前不可用: %w", name, err)
				}
				return ifi, nil
			}
		} else {
			o.Resolve = func(ctx context.Context) (*net.Interface, error) {
				return egress.SelectBest(ctx, egress.PhysicalCandidates(), o.ProbeTargets, 2*time.Second, o.Logf)
			}
		}
	}
	if o.Probe == nil {
		o.Probe = func(ctx context.Context, ifi *net.Interface) error {
			_, err := egress.ProbeIface(ctx, ifi, o.ProbeTargets, 2*time.Second)
			return err
		}
	}
	if o.State == nil {
		o.State = stateOf
	}
	go watchBind(ctx, o)
}

func watchBind(ctx context.Context, o BindWatchOpts) {
	var cur *net.Interface
	var curState ifaceState
	fails := 0
	tick := 0
	t := time.NewTicker(o.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		tick++

		// 1) 当前卡还在、指纹没变：只做低频健康检查
		if cur != nil {
			now := o.State(cur)
			if now == curState && now.up {
				if tick%bindHealthEvery == 0 {
					pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
					err := o.Probe(pctx, cur)
					cancel()
					if err != nil {
						fails++
						o.Logf("绑卡看护：网卡 %s 探针失败 %d/%d（%v）", cur.Name, fails, bindFailsBeforeSwitch, err)
						if fails < bindFailsBeforeSwitch {
							continue
						}
						o.Logf("绑卡看护：网卡 %s 连续探不通，重新挑卡", cur.Name)
					} else {
						fails = 0
						continue
					}
				} else {
					continue
				}
			} else {
				o.Logf("绑卡看护：网卡 %s %s → %s", cur.Name, curState, now)
			}
		}

		// 2) 需要（重新）挑卡
		rctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		next, err := o.Resolve(rctx)
		cancel()
		if err != nil {
			if cur != nil {
				// 暂时挑不到：保留旧 pin（等它回来），不当成"切到不绑"
				o.Logf("绑卡看护：暂时挑不到可用网卡（%v），先保持现状", err)
				continue
			}
			o.Logf("绑卡看护：挑不到可用物理网卡（%v）—— 本轮不绑，走系统默认路由", err)
			continue
		}
		if cur != nil && next.Index == cur.Index && o.State(next) == curState {
			continue
		}
		if o.Repin != nil {
			if err := o.Repin(next); err != nil {
				o.Logf("绑卡看护：重钉到 %s 失败（%v）", next.Name, err)
				continue
			}
		}
		o.Logf("绑卡看护：WG socket 钉在 %s（%s）", next.Name, o.State(next))
		cur, curState, fails = next, o.State(next), 0
		if o.OnChange != nil {
			o.OnChange()
		}
	}
}
