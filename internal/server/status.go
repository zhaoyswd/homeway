package server

// status.go — serve 角色的状态快照接口（role-management 2.1，D3/D10：serve.status 的
// 数据源；§3/§4 的绑定层只做字段映射渲染）。无完整凭证——token 只给掩码指纹
// （reveal 纪律：完整 token 只经 `serve token`）。

import (
	"encoding/base64"
	"fmt"
	"strconv"

	"github.com/zhaoyswd/homeway/pkg/proto"
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

// MaskToken hmw1… 掩码的导出面（daemon 绑定层对台账末行的降级掩码用——与包内
// maskToken 同一实现；reveal 纪律：status 族只见掩码）。
func MaskToken(tok string) string { return maskToken(tok) }

// CurrentToken 当前在用 token 全文（reveal 纪律的运行态真源——只经 `serve token`
// 呈现；tokMu 内读）。空 = 本轮尚未铸出（探测未完成/中继腿未并入——serve.token
// 的调用方以此回落台账末行）。
func (s *Server) CurrentToken() string {
	if s == nil {
		return ""
	}
	s.tokMu.Lock()
	defer s.tokMu.Unlock()
	return s.lastToken
}

// LastToken 台账末行重铸（role-management 3.2/3.4：`serve token` 未跑直读与
// status 掩码的降级数据源——台账写入纪律下末行 = 最近在用 token）。第二返回值
// false = 台账为空（全新 state 未预热）。重铸 = 末行 secret + endpoints + 本身份
// 公钥（与铸出路径同一 EncodeToken，逐字一致由批 2 的台账端到端判据守）。
func (s *State) LastToken() (proto.Token, bool, error) {
	rec, err := s.lastRecord()
	if err != nil || rec == nil {
		return proto.Token{}, false, err
	}
	priv, err := s.PrivateKey()
	if err != nil {
		return proto.Token{}, false, err
	}
	var secret [32]byte
	raw, derr := base64.RawURLEncoding.DecodeString(rec.Secret)
	if derr != nil || len(raw) != 32 {
		return proto.Token{}, false, fmt.Errorf("state: 台账末行 secret 非法")
	}
	copy(secret[:], raw)
	var tok proto.Token
	pub := priv.PublicKey()
	copy(tok.PeerID[:], pub[:])
	tok.Secret = secret
	tok.Endpoints = rec.Endpoints
	return tok, true, nil
}

// RevealLastToken 便捷读半边：开 <serveDir> 的 State 并取台账末行 token 全文
// （daemon 绑定层与 CLI 的 `serve token` 未跑直读共用；dir = <state>/serve）。
func RevealLastToken(serveDir string) (string, []string, bool, error) {
	st, err := OpenState(serveDir)
	if err != nil {
		return "", nil, false, err
	}
	tok, ok, err := st.LastToken()
	if err != nil {
		return "", nil, false, err
	}
	if !ok {
		return "", nil, false, nil
	}
	eps := make([]string, 0, len(tok.Endpoints))
	for _, e := range tok.Endpoints {
		eps = append(eps, e.Addr)
	}
	s, err := proto.EncodeToken(tok)
	if err != nil {
		return "", nil, false, err
	}
	return s, eps, true, nil
}
