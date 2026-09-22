package server

// ddnscheck.go — --ddns 自检告警（endpoint-freshness 任务 1.4；spec「出口侧 DDNS 自检告警」）。
//
// 周期与公网端点探测同拍（10min 成功 / 2min 失败重试；换网 kick 立即跑）：解析自己的域名，
// 与本机观测的公网地址（最近一轮 published）对比。只产日志告警，不改 token、不阻断服务。
//
// 阈值口径（spec）：连续 ≥3 拍不一致才告警「DDNS 记录滞后」、恢复即静默——DDNS 正常传播
// 本来就有几分钟到十几分钟的不一致窗口，单拍不一致是常态，不能一拍就叫。
//
// 两类独立告警：
//   - 滞后：解析结果与观测地址对不上（更新器坏了/记录停在旧值）；
//   - 缺 AAAA：本机有 stun6 验证过的 v6 端点而域名只解析出 A——蜂窝用户将失去 v6 直连路径
//     （v6 无 NAT 不依赖 UPnP，是路径层最优；用户该去让 DDNS 同时更新 AAAA）。
//
// 卫兵两档（resolveDDNS 返回）：fake-IP 段 = 代理污染；非全球单播 = 记录不可路由——
// 解析层失败按档打一行（连续失败只打第一拍），不计入「不一致」拍数。

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// ddnsLagThreshold：告警阈值（拍）。3 拍 × 10min ≈ 30 分钟——正常传播窗口（分钟级）不会触发。
// ddnsLogf：自检告警出口（var 只为测试可替换——与 tokenToTerminal/tokenToFile 同款先例；生产 = logf 摘要级）。
var ddnsLogf = logf

const ddnsLagThreshold = 3

// ddnsCheckState：自检的滚动状态。只在公网端点探测的 goroutine 里读写（单线程，无需锁）。
type ddnsCheckState struct {
	mismatchStreak  int  // 连续「解析与观测不一致」的拍数
	warnedLag       bool // 滞后告警已发（恢复时打一行静默）
	warnedNoAAAA    bool // 缺 AAAA 告警已发（恢复时打一行）
	resolveErrStreak int // 连续解析失败（只打第一拍，防刷屏）
}

// runDDNSSelfCheck：一拍自检。published 为空（探测被关/本轮未公布）时跳过——没有观测就没有对比。
func (s *Server) runDDNSSelfCheck(opts PublicOpts) {
	if s.cfg.DDNS == "" || s.ddns == nil {
		return
	}
	s.tokMu.Lock()
	published := append([]string(nil), s.lastPublished...)
	s.tokMu.Unlock()
	if len(published) == 0 {
		return
	}

	var ifi *net.Interface
	if opts.Bind != nil {
		ifi = opts.Bind.PinnedIface() // 双族钉卡跟随当前实际钉住的网卡（换网重钉后自动跟上）
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	addrs, err := resolveDDNS(ctx, s.cfg.DDNS, ifi)
	if err != nil {
		st := s.ddns
		st.resolveErrStreak++
		if st.resolveErrStreak == 1 { // 连续失败只打第一拍
			ddnsLogf("⚠️ DDNS 自检：解析 %s 失败（%v）——本轮跳过对比", s.cfg.DDNS, err)
		}
		return
	}
	if st := s.ddns; st.resolveErrStreak > 0 {
		st.resolveErrStreak = 0
		ddnsLogf("DDNS 自检：解析恢复（%s → %v）", s.cfg.DDNS, addrs)
	}

	// 观测侧地址集合（按地址比较，端口无关——域名端口是快照、观测端口随映射变）。
	obs := map[netip.Addr]bool{}
	hasV6 := false
	for _, line := range published {
		ap, perr := netip.ParseAddrPort(line)
		if perr != nil {
			continue
		}
		obs[ap.Addr()] = true
		if a := ap.Addr(); a.Is6() && !a.Is4In6() {
			hasV6 = true
		}
	}

	match := false
	resolvedV6 := false
	for _, a := range addrs {
		if obs[a] {
			match = true
		}
		if a.Is6() && !a.Is4In6() {
			resolvedV6 = true
		}
	}

	st := s.ddns
	if match {
		st.mismatchStreak = 0
		if st.warnedLag {
			st.warnedLag = false
			ddnsLogf("DDNS 自检：记录已恢复一致（解析 %v 与观测匹配）", addrs)
		}
	} else {
		st.mismatchStreak++
		if st.mismatchStreak >= ddnsLagThreshold && !st.warnedLag {
			st.warnedLag = true
			ddnsLogf("⚠️ DDNS 自检：记录滞后——域名解析 %v 与本机观测 %v 连续 %d 拍不一致；"+
				"请检查 DDNS 更新器（路由器/脚本）是否还在工作", addrs, published, st.mismatchStreak)
		}
	}

	// 缺 AAAA 告警（含恢复行）：本机有可公布 v6 而域名没有 AAAA。
	if hasV6 && !resolvedV6 {
		if !st.warnedNoAAAA {
			st.warnedNoAAAA = true
			ddnsLogf("⚠️ DDNS 自检：域名 %s 没有 AAAA 记录（只解析出 A）——蜂窝用户将失去 v6 直连路径；"+
				"请让 DDNS 同时更新 AAAA", s.cfg.DDNS)
		}
	} else if st.warnedNoAAAA && resolvedV6 {
		st.warnedNoAAAA = false
		ddnsLogf("DDNS 自检：域名已带 AAAA 记录，v6 直连路径恢复")
	}
}
