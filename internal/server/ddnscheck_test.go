package server

// ddnscheck_test.go — --ddns 条目叠加（task 1.3）与自检告警（task 1.4）的单元测试。
//
// 覆盖 spec「DDNS 域名条目叠加」（既有端点全保留、端口口径外口优先/回退监听口）与
// 「出口侧 DDNS 自检告警」（≥3 拍阈值、恢复静默、缺 AAAA 告警、解析失败只打第一拍）。

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/zhaoyswd/homeway/pkg/servercore"
)

// ---------- task 1.3：token 端点叠加 ----------

func TestTokenEndpointsDDNSAppend(t *testing.T) {
	b := &servercore.ServerBind{Logf: func(string, ...any) {}}
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	listen := b.LocalPort()

	s := &Server{bind: b, cfg: ServeConfig{DDNS: "home.example.com"}}
	published := []string{"203.0.113.7:41641"}
	eps, labels := s.tokenEndpoints(published, listen)

	var hasPub, hasDomain bool
	for _, e := range eps {
		switch e.Addr {
		case "203.0.113.7:41641":
			hasPub = true
		case "home.example.com:41641":
			hasDomain = true
		}
	}
	if !hasPub {
		t.Fatalf("叠加不踢：公网端点必须保留，得到 %v", labels)
	}
	if !hasDomain {
		t.Fatalf("域名条目缺失（端口应取公布外口 41641），得到 %v", labels)
	}
	for _, e := range eps {
		if e.Relay {
			t.Fatalf("域名/公网条目不得带 Relay 标记：%v", e)
		}
	}
}

func TestTokenEndpointsDDNSPortFallback(t *testing.T) {
	s := &Server{cfg: ServeConfig{DDNS: "home.example.com"}}
	eps, _ := s.tokenEndpoints(nil, 41643) // 无公网观测 + 监听口退让过
	found := false
	for _, e := range eps {
		if e.Addr == "home.example.com:41643" {
			found = true
		}
	}
	if !found {
		t.Fatalf("无公网端点时域名端口应回退实际监听口 41643，得到 %v", eps)
	}
}

func TestTokenEndpointsNoDDNSUnchanged(t *testing.T) {
	b := &servercore.ServerBind{Logf: func(string, ...any) {}}
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	s := &Server{bind: b} // 未配 --ddns
	eps, _ := s.tokenEndpoints([]string{"203.0.113.7:41641"}, b.LocalPort())
	for _, e := range eps {
		if strings.Contains(e.Addr, "example.com") {
			t.Fatalf("未配 --ddns 不应出现域名条目：%v", e)
		}
	}
}

// ---------- task 1.4：自检告警 ----------

type ddnsLogCapture struct {
	mu   sync.Mutex
	lines []string
}

func (c *ddnsLogCapture) logf(format string, a ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, fmt.Sprintf(format, a...))
}

func (c *ddnsLogCapture) count(substr string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, l := range c.lines {
		if strings.Contains(l, substr) {
			n++
		}
	}
	return n
}

func newSelfCheckServer(t *testing.T, published []string) *Server {
	t.Helper()
	s := &Server{cfg: ServeConfig{DDNS: "home.example.com"}, ddns: &ddnsCheckState{}}
	s.tokMu.Lock()
	s.lastPublished = published
	s.tokMu.Unlock()
	return s
}

func TestDDNSSelfCheckLagThreshold(t *testing.T) {
	pub := []string{"203.0.113.7:41641"}         // 本机观测
	stale := []netip.Addr{netip.MustParseAddr("198.51.100.9")}      // 域名还指着旧值
	fresh := []netip.Addr{netip.MustParseAddr("203.0.113.7")}
	f := startFakeDNS(t, stale, nil, false)
	// 动态换答案：先 3 拍旧值 → 告警；再 1 拍新值 → 恢复。
	f.setAnswers(stale, nil)
	withResolvers(t, []string{f.addr()})

	s := newSelfCheckServer(t, pub)
	lc := &ddnsLogCapture{}
	old := ddnsLogf
	ddnsLogf = lc.logf
	t.Cleanup(func() { ddnsLogf = old })

	for i := 1; i <= 2; i++ { // 两拍不一致：不告警（正常传播窗口）
		s.runDDNSSelfCheck(PublicOpts{})
		if got := lc.count("记录滞后"); got != 0 {
			t.Fatalf("第 %d 拍不该告警（阈值 3），日志：%v", i, lc.lines)
		}
	}
	s.runDDNSSelfCheck(PublicOpts{}) // 第三拍：告警一次
	if got := lc.count("记录滞后"); got != 1 {
		t.Fatalf("第三拍应恰好告警一次，日志：%v", lc.lines)
	}
	s.runDDNSSelfCheck(PublicOpts{}) // 第四拍：仍是旧值，不重复告警
	if got := lc.count("记录滞后"); got != 1 {
		t.Fatalf("告警应只发一次（恢复才打静默行），日志：%v", lc.lines)
	}

	f.setAnswers(fresh, nil) // 记录追上：恢复行 + streak 清零
	s.runDDNSSelfCheck(PublicOpts{})
	if got := lc.count("已恢复一致"); got != 1 {
		t.Fatalf("恢复应打一行静默，日志：%v", lc.lines)
	}

	// 恢复后单拍不一致：不告警（streak 从 0 数）。
	f.setAnswers(stale, nil)
	s.runDDNSSelfCheck(PublicOpts{})
	if got := lc.count("记录滞后"); got != 1 {
		t.Fatalf("恢复后单拍不一致不该再告警，日志：%v", lc.lines)
	}
}

func TestDDNSSelfCheckNoAAAAWarn(t *testing.T) {
	pub := []string{"203.0.113.7:41641", "[2001:db8::1]:41641"} // 本机有可公布 v6
	f := startFakeDNS(t, []netip.Addr{netip.MustParseAddr("203.0.113.7")}, nil, false)
	withResolvers(t, []string{f.addr()})

	s := newSelfCheckServer(t, pub)
	lc := &ddnsLogCapture{}
	old := ddnsLogf
	ddnsLogf = lc.logf
	t.Cleanup(func() { ddnsLogf = old })

	s.runDDNSSelfCheck(PublicOpts{}) // v4 一致 + 无 AAAA → 缺 AAAA 告警一次
	if got := lc.count("没有 AAAA"); got != 1 {
		t.Fatalf("应告警缺 AAAA 一次，日志：%v", lc.lines)
	}
	s.runDDNSSelfCheck(PublicOpts{}) // 第二拍：不重复
	if got := lc.count("没有 AAAA"); got != 1 {
		t.Fatalf("缺 AAAA 告警应只发一次，日志：%v", lc.lines)
	}

	f.setAnswers([]netip.Addr{netip.MustParseAddr("203.0.113.7")}, []netip.Addr{netip.MustParseAddr("2001:db8::1")}) // AAAA 补上：恢复行
	s.runDDNSSelfCheck(PublicOpts{})
	if got := lc.count("已带 AAAA"); got != 1 {
		t.Fatalf("AAAA 恢复应打一行，日志：%v", lc.lines)
	}
}

func TestDDNSSelfCheckResolveFailureLogsOnce(t *testing.T) {
	f := startFakeDNS(t, nil, nil, true) // 垃圾应答 → 解析失败
	withResolvers(t, []string{f.addr()})
	s := newSelfCheckServer(t, []string{"203.0.113.7:41641"})
	lc := &ddnsLogCapture{}
	old := ddnsLogf
	ddnsLogf = lc.logf
	t.Cleanup(func() { ddnsLogf = old })

	s.runDDNSSelfCheck(PublicOpts{})
	s.runDDNSSelfCheck(PublicOpts{})
	if got := lc.count("本轮跳过对比"); got != 1 {
		t.Fatalf("连续解析失败只应打第一拍，日志：%v", lc.lines)
	}
	// 解析失败不推进 mismatchStreak（后续恢复后单拍不一致不告警）。
	if s.ddns.mismatchStreak != 0 {
		t.Fatalf("解析失败不应计入不一致拍数：%d", s.ddns.mismatchStreak)
	}
}

// TestProbeProbeEndpoints：探测应答列表段与 token 打印同源（都吃 lastPublished），
// 只保留全球单播、上限 MaxEndpoints。
func TestProbeProbeEndpoints(t *testing.T) {
	s := &Server{}
	s.tokMu.Lock()
	s.lastPublished = []string{
		"203.0.113.7:41641",            // 公网 v4
		"[2001:db8::1]:41641",          // 公网 v6
		"192.168.3.12:41641",           // 私网（不该出现，防御性过滤）
		"garbage-line",                 // 解析失败：跳过
	}
	s.tokMu.Unlock()
	got := s.probeProbeEndpoints()
	if len(got) != 2 {
		t.Fatalf("应只保留 2 条全球单播，得到 %v", got)
	}
	if got[0] != netip.MustParseAddrPort("203.0.113.7:41641") || got[1] != netip.MustParseAddrPort("[2001:db8::1]:41641") {
		t.Fatalf("顺序/内容不对：%v", got)
	}

	// 超上限截断。
	var many []string
	for i := 0; i < 12; i++ {
		many = append(many, fmt.Sprintf("203.0.113.%d:41641", i))
	}
	s.tokMu.Lock()
	s.lastPublished = many
	s.tokMu.Unlock()
	if got := s.probeProbeEndpoints(); len(got) != 8 {
		t.Fatalf("应截断到 8 条，得到 %d", len(got))
	}
}
