package relay

import (
	"context"
	"fmt"
	"net/netip"
	"time"
)

type rateBucket struct {
	window time.Time
	count  int
}

func (r *Relay) legRateOKLocked(ip netip.Addr) bool {
	now := time.Now()
	b := r.legRates[ip]
	limit := r.cfg.RateLimit * 10
	if b == nil || now.Sub(b.window) >= time.Second {
		r.legRates[ip] = &rateBucket{window: now, count: 1}
		return true
	}
	b.count++
	return b.count <= limit
}

func (r *Relay) reapInterval() time.Duration {
	d := 5 * time.Second
	for _, c := range []time.Duration{r.cfg.IdleTimeout, r.cfg.DialWait, r.cfg.DownSilent} {
		if c > 0 && c/2 < d {
			d = c / 2
		}
	}
	if d < 20*time.Millisecond {
		d = 20 * time.Millisecond
	}
	return d
}

func (r *Relay) reapLoop(ctx context.Context) {
	t := time.NewTicker(r.reapInterval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now()
		var reclaim int
		var released []*leg
		var releasedIds []uint64
		r.mu.Lock()
		for k, a := range r.assocs {
			why := ""
			switch {
			case now.Sub(a.last) > r.cfg.IdleTimeout:
				why = "" // 普通空闲：走既有聚合计数，不逐条打日志
			case a.dialUp && now.Sub(a.dialUpAt) > r.cfg.DialWait:
				why = fmt.Sprintf("拨腿等待超 %v（通告后无 LEGUP——后端拨腿失败/通告丢失）", r.cfg.DialWait)
			case !a.dialUp && now.Sub(a.lastDown) > r.cfg.DownSilent:
				// 拨腿等待中的会话由 DialWait 看门狗负责（见上一条）：它的 lastDown 从
				// 创建时刻起算，若 DownSilent 比 DialWait 短就会在腿还没认证上来之前被
				// 当"半死会话"拆掉（review 复审 b1 的抖动根因；生产默认 15s < 5min 掩盖了它）。
				why = fmt.Sprintf("下行静默超 %v（上行仍活跃——半死会话兜底）", r.cfg.DownSilent)
			default:
				continue
			}
			if why != "" {
				r.cfg.Logf("中继：会话 #%d 回收：%s", a.sid, why)
			}
			_ = a.sock.Close()
			delete(r.assocs, k)
			reclaim++
			if a.sid != 0 {
				if lg := r.legs[k.label]; lg != nil {
					released = append(released, lg)
					releasedIds = append(releasedIds, a.sid)
				}
			}
		}
		r.mu.Unlock()
		// 拨腿会话回收 → 通告后端放腿（锁外写，避免与 announceSession 抢锁序）。
		for i, lg := range released {
			r.releaseSession(lg, releasedIds[i])
		}
		r.mu.Lock()
		r.stats.Reclaimed += uint64(reclaim)
		for label, lg := range r.legs {
			// 存活判定：挂着控制连接的腿由控制保活续命（readControlLoop 刷 last）；
			// 已验证（UDP 注册挑战或控制面挑战任一）按 last 在 LegTimeout 内；
			// **未验证的腿只保留 legBootstrap 注册窗口**——建腿时 last=now（见
			// legForControl / handleControl Hello），窗口内完成不了验证就摘，
			// 既防匿名 Hello 占位、又让慢握手不与 reap 轮竞争（见 legBootstrap 注释）。
			alive := now.Sub(lg.last) <= r.cfg.LegTimeout
			if lg.ctl == nil && !lg.verified && !lg.ctlVerified {
				alive = now.Sub(lg.last) <= legBootstrap
			}
			if !alive {
				r.cfg.Logf("中继：后端 %x 注册腿过期（%v 无保活）—— 摘掉", label[:], now.Sub(lg.last).Round(time.Second))
				if lg.ctl != nil {
					lg.ctl.close()
				}
				for k, a := range r.assocs {
					if k.label == label {
						_ = a.sock.Close()
						delete(r.assocs, k)
					}
				}
				delete(r.legs, label)
			}
		}
		// 限流桶清理（窗口外的直接丢）
		for ip, b := range r.rates {
			if now.Sub(b.window) > 2*time.Second {
				delete(r.rates, ip)
			}
		}
		for ip, b := range r.legRates {
			if now.Sub(b.window) > 2*time.Second {
				delete(r.legRates, ip)
			}
		}
		r.mu.Unlock()
		if reclaim > 0 {
			r.cfg.Logf("中继：回收 %d 条空闲分配腿（当前 %d 条）", reclaim, r.assocCount())
		}
	}
}

func (r *Relay) rateOK(ip netip.Addr) bool {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.rates[ip]
	if b == nil || now.Sub(b.window) >= time.Second {
		r.rates[ip] = &rateBucket{window: now, count: 1}
		return true
	}
	b.count++
	return b.count <= r.cfg.RateLimit
}
