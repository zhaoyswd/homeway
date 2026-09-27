package wgcore

// transport_freshness_test.go — endpoint-freshness §3 的核内单测：
// 域名重解析（不占 Rearm 预算/失败退缓存/两分支补投软赛跑）、真实往返落已验证
//（按地址去重 + 同地址小时级复标 + relay 不落）、旁路探测（学习 + 消费卫兵 +
// DeliverProbed 接线）。注入采纳用「从任意 socket 往 Bind 端口发包」——Bind 的
// 采纳发生在 device 认证之前，junk 载荷会被 device 丢弃但不影响采纳状态。

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/internal/wtransport"
	"github.com/zhaoyswd/homeway/pkg/probe"
	"github.com/zhaoyswd/homeway/pkg/proto"
)

type logCap struct {
	mu    sync.Mutex
	lines []string
}

func (c *logCap) logf(format string, a ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, fmt.Sprintf(format, a...))
}

func (c *logCap) count(substr string) int {
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

func (c *logCap) has(substr string) bool { return c.count(substr) > 0 }

var (
	freshPeerID = [32]byte{7}
	freshSecret = [32]byte{9}
)

// newFreshTransport：轻量门面（Prepare 无 TUN——Bind/收包循环活着即可，不需要数据面）。
func newFreshTransport(t *testing.T, lc *logCap, domainEps []DomainEndpoint, domainCands []wtransport.Candidate,
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)) (*Transport, *wtransport.EndpointCache, string) {
	t.Helper()
	id, err := wtransport.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	core, err := Prepare(Config{
		PeerID: freshPeerID, Secret: freshSecret, Identity: id,
		Candidates: []wtransport.Candidate{{Addr: netip.MustParseAddrPort("192.0.2.10:41641")}},
		Logf:       lc.logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(core.Close)
	dir := t.TempDir()
	cache := wtransport.OpenEndpointCache(dir, freshPeerID)
	cache.SetLogger(lc.logf)
	tr, err := NewTransport(TransportConfig{
		Core: core, Cache: cache, Logf: lc.logf,
		StaticCandidates: []wtransport.Candidate{{Addr: netip.MustParseAddrPort("192.0.2.10:41641")}},
		DomainCandidates: domainCands, DomainEndpoints: domainEps, LookupHost: lookup,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	return tr, cache, dir
}

// waitFor：轮询断言（重解析/采纳都是异步生效的）。
func waitFor(t *testing.T, d time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("等待超时：%s", what)
}

func bindHas(t *Transport, addr string) bool {
	for _, c := range t.core.Bind().Status().Candidates {
		if c.Addr == addr {
			return true
		}
	}
	return false
}

func TestRearmDoesNotBlockOnDNS(t *testing.T) {
	block := make(chan struct{})
	lc := &logCap{}
	tr, _, _ := newFreshTransport(t, lc, []DomainEndpoint{{Host: "home.example.com", Port: 41641}},
		[]wtransport.Candidate{{Addr: netip.MustParseAddrPort("192.0.2.1:41641")}},
		func(ctx context.Context, host string) ([]netip.Addr, error) {
			<-block // 永不返回：模拟 DNS 空等（蜂窝下常态）
			return nil, nil
		})
	defer close(block)
	started := time.Now()
	tr.Rearm() // 动作本体零 DNS 等待（Rearm 动作预算 2s 有界；塞 DNS 会打成 rc=-3）
	if d := time.Since(started); d > time.Second {
		t.Fatalf("Rearm 不得被 DNS 拖住（%v）—— 那会把恢复阶梯打成 rc=-3 本地超时", d)
	}
}

func TestDomainResolveRefreshesCandidates(t *testing.T) {
	lc := &logCap{}
	tr, _, _ := newFreshTransport(t, lc, []DomainEndpoint{{Host: "home.example.com", Port: 41641}},
		[]wtransport.Candidate{{Addr: netip.MustParseAddrPort("192.0.2.1:41641")}}, // 建会话时的旧解析
		func(ctx context.Context, host string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("192.0.2.99")}, nil // 漂移后的新地址
		})
	tr.Rearm()
	waitFor(t, 3*time.Second, func() bool { return bindHas(tr, "192.0.2.99:41641") }, "新解析地址进候选")
	if bindHas(tr, "192.0.2.1:41641") {
		t.Fatal("旧解析地址应被替换（t.static 已刷新——否则 Merge 会一直带回旧解析）")
	}
	if !bindHas(tr, "192.0.2.10:41641") {
		t.Fatal("IP 字面量静态候选必须保留")
	}
}

func TestDomainResolveFailureKeepsLast(t *testing.T) {
	lc := &logCap{}
	tr, _, _ := newFreshTransport(t, lc, []DomainEndpoint{{Host: "home.example.com", Port: 41641}},
		[]wtransport.Candidate{{Addr: netip.MustParseAddrPort("192.0.2.1:41641")}},
		func(ctx context.Context, host string) ([]netip.Addr, error) {
			return nil, fmt.Errorf("dns unavailable")
		})
	tr.Rearm()
	waitFor(t, 3*time.Second, func() bool { return lc.has("域名重解析") }, "解析失败留痕")
	if !bindHas(tr, "192.0.2.1:41641") {
		t.Fatal("解析失败应退回上次解析结果")
	}
}

// injectAdopt：从 src 直接往 Bind 端口发一个包，让 Bind 采纳该来源（device 会丢弃
// 无效载荷，但采纳已发生）。relay=true 时按腿帧形态发（src 须是 relay 候选）。
func injectAdopt(t *testing.T, tr *Transport, relay bool) netip.AddrPort {
	t.Helper()
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sock.Close() })
	src := sock.LocalAddr().(*net.UDPAddr).AddrPort()
	bind := tr.core.Bind()
	deadline := time.Now().Add(3 * time.Second)
	for bind.Port() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if bind.Port() == 0 {
		t.Fatal("Bind 端口未开")
	}
	dst := net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), bind.Port()))
	payload := []byte("junk-not-wireguard")
	if relay {
		payload = proto.EncodeTagged(proto.RelayID(freshPeerID), proto.FrameTypeData, payload)
	}
	if _, err := sock.WriteToUDP(payload, dst); err != nil {
		t.Fatal(err)
	}
	return src
}

func TestLateDomainResolveSoftRearmOnRelay(t *testing.T) {
	lc := &logCap{}
	tr, _, _ := newFreshTransport(t, lc, []DomainEndpoint{{Host: "home.example.com", Port: 41641}},
		[]wtransport.Candidate{{Addr: netip.MustParseAddrPort("192.0.2.1:41641")}},
		func(ctx context.Context, host string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("192.0.2.50")}, nil
		})
	// 造一条中继候选并注入腿帧 ⇒ 赛跑以中继「结算」（adopted=relay）。
	relaySrc := injectAdopt(t, tr, true)
	tr.core.Bind().SetCandidates([]wtransport.Candidate{
		{Addr: netip.MustParseAddrPort("192.0.2.10:41641")},
		{Addr: relaySrc, Relay: true},
	})
	waitFor(t, 3*time.Second, func() bool {
		_, relay, ok := tr.core.Bind().Adopted()
		return ok && relay
	}, "中继采纳")

	tr.refreshDomainLocked(context.Background()) // 晚到的解析结果
	waitFor(t, 3*time.Second, func() bool { return lc.has("节流软赛跑补投") }, "补投软赛跑")
	if !lc.has("RARM 软赛跑") {
		t.Fatal("补投应实际触发 RearmSoft")
	}
	// 节流：立即再来一次不再补投。
	tr.refreshDomainLocked(context.Background())
	if lc.count("节流软赛跑补投") != 1 {
		t.Fatalf("补投应被节流（15s）：打了 %d 次", lc.count("节流软赛跑补投"))
	}
}

func TestMarkRoundTripPerAddressAndRefresh(t *testing.T) {
	lc := &logCap{}
	tr, cache, _ := newFreshTransport(t, lc, nil, nil, nil)
	a := netip.MustParseAddrPort("192.0.2.10:41641") // 在 static 里 ⇒ SourceToken
	b := netip.MustParseAddrPort("198.51.100.20:9999")

	tr.MarkRoundTrip(a)
	tr.MarkRoundTrip(a) // 同地址立即重复：VerifiedAt 不变（按地址去重）
	var v1 int64
	for _, e := range cache.Entries(time.Now()) {
		if e.Addr == a {
			v1 = e.VerifiedAt
		}
	}
	if v1 == 0 {
		t.Fatal("首次真实往返应落已验证")
	}
	tr.mu.Lock()
	tr.lastMarkedAt = time.Now().Add(-2 * time.Hour) // 模拟长连路径一小时后
	tr.mu.Unlock()
	time.Sleep(5 * time.Millisecond) // VerifiedAt 是毫秒粒度：确保复标时间戳大于首标
	tr.MarkRoundTrip(a)
	v2 := int64(0)
	for _, e := range cache.Entries(time.Now()) {
		if e.Addr == a {
			v2 = e.VerifiedAt
		}
	}
	if v2 <= v1 {
		t.Fatal("同地址超过 1 小时应复标（VerifiedAt 刷新）")
	}
	tr.MarkRoundTrip(b)
	found := false
	for _, e := range cache.Entries(time.Now()) {
		if e.Addr == b && e.Verified() {
			found = true
		}
	}
	if !found {
		t.Fatal("新地址的真实往返应落已验证")
	}
}

func TestNotePathAliveSkipsRelay(t *testing.T) {
	lc := &logCap{}
	tr, cache, _ := newFreshTransport(t, lc, nil, nil, nil)

	// 直连来源：NotePathAlive 落验证。
	directSrc := injectAdopt(t, tr, false)
	waitFor(t, 3*time.Second, func() bool {
		_, relay, ok := tr.core.Bind().Adopted()
		return ok && !relay
	}, "直连采纳")
	tr.NotePathAlive()
	found := false
	for _, e := range cache.Entries(time.Now()) {
		if e.Addr == directSrc && e.Verified() {
			found = true
		}
	}
	if !found {
		t.Fatal("存活探测成功（真实往返）应把采纳地址落已验证——覆盖 R3 救回后闲置窗口")
	}

	// 中继来源：不落（学习地址一律 direct，中继腿由 token/带内给）。
	before := len(cache.Entries(time.Now()))
	relaySrc := injectAdopt(t, tr, true)
	tr.core.Bind().SetCandidates([]wtransport.Candidate{{Addr: relaySrc, Relay: true}})
	waitFor(t, 3*time.Second, func() bool {
		_, relay, ok := tr.core.Bind().Adopted()
		return ok && relay
	}, "中继采纳")
	tr.NotePathAlive()
	if after := len(cache.Entries(time.Now())); after != before {
		t.Fatalf("中继路径不该进学习缓存：%d → %d", before, after)
	}
}

// fakeProbeResponder：一个会带端点列表应答的假出口（RespondEx）。
func fakeProbeResponder(t *testing.T, endpoints []netip.AddrPort) netip.AddrPort {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, src, rerr := c.ReadFromUDPAddrPort(buf)
			if rerr != nil {
				return
			}
			if resp := probe.RespondEx(buf[:n], src, "v-fresh", 0, endpoints); resp != nil {
				_, _ = c.WriteToUDPAddrPort(resp, src)
			}
		}
	}()
	return c.LocalAddr().(*net.UDPAddr).AddrPort()
}

func TestProbeCandidatesLearnsAndGuards(t *testing.T) {
	lc := &logCap{}
	good := netip.MustParseAddrPort("192.0.2.7:41641")
	responder := fakeProbeResponder(t, []netip.AddrPort{
		good,
		netip.MustParseAddrPort("198.18.0.5:53"),  // fake-IP 段：拒
		netip.MustParseAddrPort("100.64.1.1:53"),  // CGNAT：拒
		netip.MustParseAddrPort("192.168.1.2:53"), // 私网：拒
	})
	tr, cache, cacheDir2 := newFreshTransport(t, lc, nil, nil, nil)
	tr.core.Bind().SetCandidates([]wtransport.Candidate{{Addr: responder}})

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	tr.ProbeCandidates(ctx)

	found := false
	for _, e := range cache.Entries(time.Now()) {
		switch e.Addr {
		case good:
			if e.Source != wtransport.SourceProbe {
				t.Fatalf("探测线索来源应为 SourceProbe，得到 %s", e.Source)
			}
			found = true
		case netip.MustParseAddrPort("198.18.0.5:53"),
			netip.MustParseAddrPort("100.64.1.1:53"),
			netip.MustParseAddrPort("192.168.1.2:53"):
			t.Fatalf("消费卫兵应拒绝的条目进了缓存：%v", e.Addr)
		}
	}
	if !found {
		t.Fatal("应答端点列表的好地址应进学习缓存")
	}
	if !lc.has("旁路探测") {
		t.Fatal("旁路探测应留一行判据日志")
	}
	// 4.1(b) 全链收尾：落盘可读——重开缓存仍在（真二进制外的「应答→投递→缓存落盘」闭环）。
	t2 := wtransport.OpenEndpointCache(cacheDir2, freshPeerID)
	foundSaved := false
	for _, e := range t2.Entries(time.Now()) {
		if e.Addr == good && e.Source == wtransport.SourceProbe {
			foundSaved = true
		}
	}
	if !foundSaved {
		t.Fatal("探测线索应已落盘（重开缓存仍在）")
	}
}

func TestDeliverProbedWiring(t *testing.T) {
	lc := &logCap{}
	tr, cache, _ := newFreshTransport(t, lc, nil, nil, nil)
	tr.core.Bind().DeliverProbed("192.0.2.8:41641")
	tr.core.Bind().DeliverProbed("198.18.0.9:53") // fake-IP：拒
	found := false
	for _, e := range cache.Entries(time.Now()) {
		if e.Addr == netip.MustParseAddrPort("192.0.2.8:41641") {
			if e.Source != wtransport.SourceProbe {
				t.Fatalf("来源应为 probe：%s", e.Source)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("DeliverProbed 应落缓存")
	}
	for _, e := range cache.Entries(time.Now()) {
		if e.Addr == netip.MustParseAddrPort("198.18.0.9:53") {
			t.Fatal("卫兵应拒绝 fake-IP 段地址")
		}
	}
}
