//go:build !cshared

// token_single_track_test.go — token decode 单轨的判据（host-registry-daemon 1.4，
// D2/A5）：①整会话重建路径零 decode（tokenDecodes 计数器注入断言）；②decode 落结构后
// 域名条目保留**未解析原文**进重解析输入（「不再 decode」绝不等于「不再重解析域名」——
// 重解析的行为层由 wgcore transport_freshness_test 守：解析漂移后 Rearm 换新地址）。
package hostsession

import (
	"context"
	"net/netip"
	"testing"

	"github.com/zhaoyswd/homeway/clientcore/internal/wgcore"
	"github.com/zhaoyswd/homeway/clientcore/internal/wtransport"
	"github.com/zhaoyswd/homeway/pkg/proto"
)

// singleTrackToken 本地签发一枚合法 token（端点指向不可达回环端口：构造/重建路径
// 不依赖端点可达——wgcore.Prepare 只建本地 socket，握手是异步的）。
func singleTrackToken(t *testing.T) (string, proto.Token) {
	t.Helper()
	tok := proto.Token{
		PeerID:    [32]byte{7, 7, 7, 1},
		Secret:    [32]byte{9, 9, 9, 2},
		Endpoints: []proto.Endpoint{{Addr: "127.0.0.1:1"}},
	}
	s, err := proto.EncodeToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	return s, tok
}

// TestRebuildPathZeroDecode 1.4 判据①：入口（NewSession）decode 恰一次；
// 整会话重建（rebuildSession 换入新会话）零 decode。
func TestRebuildPathZeroDecode(t *testing.T) {
	tokStr, _ := singleTrackToken(t)
	before := tokenDecodes.Load()
	s, err := NewSession(Config{Token: tokStr}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	afterStart := tokenDecodes.Load()
	if afterStart != before+1 {
		t.Fatalf("NewSession 应恰好 decode 一次：%d → %d", before, afterStart)
	}
	t.Cleanup(func() {
		if cur := s.curSession(); cur != nil {
			_ = cur.Close()
		}
	})
	s.rebuildSession("测试：整会话重建")
	if got := tokenDecodes.Load(); got != afterStart {
		t.Fatalf("整会话重建路径发生 decode（应零增量）：%d → %d", afterStart, got)
	}
	if cur := s.curSession(); cur == nil {
		t.Fatal("重建后应有新会话在位")
	}
}

// TestBuildExitSessionConsumesDecodedToken 生产构造消费落好的结构：直接以 decoded
// token 调 buildExitSession（绕过入口 decode）计数零增量——证明构造本体不 decode。
func TestBuildExitSessionConsumesDecodedToken(t *testing.T) {
	_, tok := singleTrackToken(t)
	before := tokenDecodes.Load()
	sess, _, err := buildExitSession(Config{Token: "（入口已 decode，串不再使用）"}, Options{}, tok, Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if got := tokenDecodes.Load(); got != before {
		t.Fatalf("构造本体不应 decode：%d → %d", before, got)
	}
}

// TestDomainEntriesKeptVerbatimAfterDecode 1.4 判据②（回归：A5 域名重解析保留）：
// decode 单轨后，域名条目以**未解析原文**进 DomainEndpoint（R3/Rearm 重解析的输入）；
// 解析失败也不丢条目。「指向变化后重解析生效」的行为层判据在
// wgcore/transport_freshness_test.go 的 TestDomainResolveRefreshesCandidates
// （lookup 应答漂移 → Rearm 后新地址进候选、旧地址被替换）。
func TestDomainEntriesKeptVerbatimAfterDecode(t *testing.T) {
	_, tok := singleTrackToken(t)
	tok.Endpoints = append(tok.Endpoints, proto.Endpoint{Addr: "rebind.example.com:41641"})
	lookup := func(ctx context.Context, host string) ([]netip.Addr, error) {
		// 建会话时解析失败（域名暂时不可解析）：条目仍须保留原文。
		return nil, context.DeadlineExceeded
	}
	static, domainCands, domainInputs := sessionEndpointInputs(tok, lookup, Discard)
	if len(static) != 1 || static[0].Addr.String() != "127.0.0.1:1" {
		t.Fatalf("静态候选不符：%v", static)
	}
	if len(domainCands) != 0 {
		t.Fatalf("解析失败时域名候选应为空：%v", domainCands)
	}
	if len(domainInputs) != 1 || domainInputs[0].Host != "rebind.example.com" || domainInputs[0].Port != 41641 {
		t.Fatalf("域名条目未保留原文（重解析输入丢失）：%v", domainInputs)
	}
	// 类型自证：domainInputs 就是喂给 wgcore.TransportConfig.DomainEndpoints 的形态。
	var _ []wgcore.DomainEndpoint = domainInputs
	var _ []wtransport.Candidate = domainCands
}
