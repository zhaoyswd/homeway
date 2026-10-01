package server

// status.go — serve 角色的状态快照接口（role-management 2.1，D3/D10：serve.status 的
// 数据源；§3/§4 的绑定层只做字段映射渲染）。无完整凭证——token 只给掩码指纹
// （reveal 纪律：完整 token 只经 `serve token`）。

import (
	"strconv"

	"github.com/zhaoyswd/homeway/pkg/servercore"
)

// StatusSnapshot serve 状态快照（peer 表、实际监听端口、当前 token 掩码、ddns 解析
// 状态、intercept 计数——tasks 2.1 点名的五件）。
type StatusSnapshot struct {
	ListenPort uint16                   // 实际监听端口（被占退让后的真值）
	Published  []string                 // 最近一轮已公布的公网端点
	TokenMask  string                   // 当前 token 掩码（前 12 字符 + …；空 = 未铸出）
	Endpoints  []string                 // 当前 token 的端点标签（类型标注版）
	Peers      []servercore.DeviceBrief // 设备表（连接的 APP 设备）
	DDNS       []DDNSBrief              // 域名解析自检状态
	Intercept  InterceptBrief           // 过境拦截计数
}

// DDNSBrief 单域名自检快照。
type DDNSBrief struct {
	Domain     string
	LagStreak  int  // 连续不一致拍数（≥ddnsLagThreshold 已告警）
	WarnedLag  bool // 滞后告警在案
	WarnedAAAA bool // 缺 AAAA 告警在案
}

// InterceptBrief 过境拦截计数（dialok/dialfail/拒载——真凭据判据的同源计数面）。
type InterceptBrief struct {
	DialOK, DialFail, Reject, Flows uint64
}

// Snapshot Server 的状态快照（未跑字段为零值；锁内读、锁外组）。ddns 段只在公网
// 端点探测 goroutine 写、此处读——map 迭代无并发写（探测循环与本调用不同步是既有
// 单写者约定；本方法不在探测拍内被调）。
func (s *Server) Snapshot() StatusSnapshot {
	out := StatusSnapshot{}
	if s == nil {
		return out
	}
	if s.bind != nil {
		out.ListenPort = s.bind.LocalPort()
	}
	s.tokMu.Lock()
	out.TokenMask = maskToken(s.lastToken)
	out.Published = append([]string(nil), s.lastPublished...)
	s.tokMu.Unlock()
	if port := out.ListenPort; port != 0 {
		_, labels := s.tokenEndpoints(out.Published, port)
		out.Endpoints = labels
	}
	if s.Table != nil {
		out.Peers = s.Table.Briefs()
	}
	s.ddnsMu.Lock()
	for domain, st := range s.ddns {
		out.DDNS = append(out.DDNS, DDNSBrief{
			Domain: domain, LagStreak: st.mismatchStreak,
			WarnedLag: st.warnedLag, WarnedAAAA: st.warnedNoAAAA,
		})
	}
	s.ddnsMu.Unlock()
	if s.Stats != nil {
		m := s.Stats.Snapshot()
		out.Intercept = InterceptBrief{
			DialOK: m["dialok"], DialFail: m["dialfail"],
			Reject: m["rejected"], Flows: m["flows"],
		}
	}
	return out
}

// maskToken：hmw1… 掩码（凭证纪律：status 只见掩码，完整 token 只经 serve token）。
func maskToken(tok string) string {
	if tok == "" {
		return ""
	}
	if len(tok) <= 12 {
		return tok[:4] + "…"
	}
	return tok[:12] + "…（" + strconv.Itoa(len(tok)) + " 字符）"
}
