package relay

import (
	"context"
	"fmt"
	"time"
)

type BackendBrief struct {
	Label       string    // 出口中继标签（16 位 hex 短指纹）
	Addr        string    // 注册腿源地址（后端公网映射，给客户端的 hint）
	LastActive  time.Time // 最近一次注册/控制活动
	Verified    bool      // UDP 注册挑战已证明持有 peerId 私钥
	CtlVerified bool      // TCP 控制面挑战已证明
	HasCtl      bool      // 控制通道（relay-backend-dial 拨腿模式）在世
}

type StatusSnapshot struct {
	Listen   string         // 实际监听地址（UDP）
	Backends []BackendBrief // 注册出口列表
	Assocs   int            // 活跃客户端分配会话数
	Open     bool           // 是否开放注册（显式测试开关 Config.Open）
}

func (r *Relay) BackendBriefs() []BackendBrief {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]BackendBrief, 0, len(r.legs))
	for label, lg := range r.legs {
		addr, last := "", time.Time{}
		if lg != nil {
			addr = lg.addr.String()
			last = lg.last
		}
		out = append(out, BackendBrief{
			Label:       fmt.Sprintf("%x", label),
			Addr:        addr,
			LastActive:  last,
			Verified:    lg.verified,
			CtlVerified: lg.ctlVerified,
			HasCtl:      lg.ctl != nil,
		})
	}
	return out
}

func (r *Relay) Snapshot() StatusSnapshot {
	r.mu.Lock()
	pc := r.pc
	assocs := len(r.assocs)
	open := r.cfg.Open
	r.mu.Unlock()
	snap := StatusSnapshot{Backends: r.BackendBriefs(), Assocs: assocs, Open: open}
	if pc != nil {
		snap.Listen = pc.LocalAddr().String()
	}
	return snap
}

func (r *Relay) statsLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		st := r.Stats()
		r.mu.Lock()
		legs, assocs := len(r.legs), len(r.assocs)
		r.mu.Unlock()
		r.cfg.Logf("中继统计：注册腿 %d（累计成功 %d，伪造 %d）｜分配腿 %d（累计 %d，回收 %d）｜转发 上 %d / 下 %d 包｜丢弃 %d",
			legs, st.Registered, st.Forged, assocs, st.Assigned, st.Reclaimed,
			st.ForwardedUp, st.ForwardedDown, st.Dropped)
	}
}
