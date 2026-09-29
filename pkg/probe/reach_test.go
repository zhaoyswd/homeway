package probe

// reach_test.go — 探测编排本体单测（host-cli 1.1：无 tag 面——cshared 专属时代测
// 不到这里；分档/预算/去重 + 慢解析注入下父预算封顶 + 纯函数面）。

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
)

// reachFakeProber：本地参照点应答器（就绪即回，带构建标记；计数收到的请求数）。
type reachFakeProber struct {
	pc    *net.UDPConn
	build string
	hits  atomic.Int64
	done  chan struct{}
}

func reachStartFakeProber(t *testing.T, build string) *reachFakeProber {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	fp := &reachFakeProber{pc: pc, build: build, done: make(chan struct{})}
	go func() {
		defer close(fp.done)
		buf := make([]byte, 1500)
		for {
			n, src, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			fp.hits.Add(1)
			if resp := Respond(buf[:n], src.AddrPort(), fp.build, 0); resp != nil {
				_, _ = pc.WriteToUDP(resp, src)
			}
		}
	}()
	t.Cleanup(func() { _ = pc.Close(); <-fp.done })
	return fp
}

func reachDeadPort(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().String()
}

func reachToken(t *testing.T, eps ...proto.Endpoint) string {
	t.Helper()
	s, err := proto.EncodeToken(proto.Token{Endpoints: eps})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestReachTiers 分档：direct / relay（直连全死+中继活）/ none（全死）；Best 取
// 实测 RTT 最小的对应档端点。
func TestReachTiers(t *testing.T) {
	direct1 := reachStartFakeProber(t, "t-a")
	direct2 := reachStartFakeProber(t, "t-b")
	relay := reachStartFakeProber(t, "t-r")
	dead := reachDeadPort(t)

	// direct：两个直连端点都活 → direct 档，Best 为其一。
	rep, err := Reach(context.Background(), reachToken(t,
		proto.Endpoint{Addr: direct1.pc.LocalAddr().String()},
		proto.Endpoint{Addr: direct2.pc.LocalAddr().String()},
	))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Tier() != TierDirect {
		t.Fatalf("双直连活端点应 direct：%+v", rep.Results)
	}
	best := rep.Best()
	if best.EP != direct1.pc.LocalAddr().String() && best.EP != direct2.pc.LocalAddr().String() {
		t.Fatalf("Best 应为直连活端点：%+v", best)
	}

	// relay：直连死 + 中继活 → relay 档，Best 为中继端点。
	rep, err = Reach(context.Background(), reachToken(t,
		proto.Endpoint{Addr: dead},
		proto.Endpoint{Addr: relay.pc.LocalAddr().String(), Relay: true},
	))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Tier() != TierRelay {
		t.Fatalf("直连死+中继活应 relay：%+v", rep.Results)
	}
	if b := rep.Best(); b.EP != relay.pc.LocalAddr().String() || !b.Relay {
		t.Fatalf("relay 档 Best 应为中继端点：%+v", b)
	}

	// none：全死 → 空结果（恒非 nil）。
	rep, err = Reach(context.Background(), reachToken(t,
		proto.Endpoint{Addr: dead},
		proto.Endpoint{Addr: reachDeadPort(t), Relay: true},
	))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Tier() != TierNone {
		t.Fatalf("全死应 none：%+v", rep.Results)
	}
	if rep.Results == nil || len(rep.Results) != 0 {
		t.Fatalf("全死 Results 应为空非 nil：%#v", rep.Results)
	}
	if b := rep.Best(); b.EP != "" {
		t.Fatalf("none 档 Best 应为零值：%+v", b)
	}
}

// TestReachDedupAndBuckets 去重：同 IP 重复登记只探测一次（应答计数 = 1）；
// 直连/中继分桶标记正确。
func TestReachDedupAndBuckets(t *testing.T) {
	alive := reachStartFakeProber(t, "t-d")
	ep := alive.pc.LocalAddr().String()
	rep, err := Reach(context.Background(), reachToken(t,
		proto.Endpoint{Addr: ep},
		proto.Endpoint{Addr: ep}, // 同一端点重复登记（域名可能解析出与字面端点相同的 IP）
		proto.Endpoint{Addr: ep, Relay: true},
	))
	if err != nil {
		t.Fatal(err)
	}
	if got := alive.hits.Load(); got != 2 {
		t.Fatalf("去重后应只探测直连 1 次 + 中继 1 次（同地址两桶各一次）：%d", got)
	}
	if len(rep.Results) != 2 {
		t.Fatalf("应两条结果（直连+中继同地址各一）：%+v", rep.Results)
	}
	var sawDirect, sawRelay bool
	for _, r := range rep.Results {
		if r.Relay {
			sawRelay = true
		} else {
			sawDirect = true
		}
	}
	if !sawDirect || !sawRelay {
		t.Fatalf("分桶缺失：%+v", rep.Results)
	}
	if rep.Tier() != TierDirect {
		t.Fatalf("有直连应答应 direct 档")
	}
}

// TestReachParentBudgetSlowResolve 慢解析注入下总等待 3.5s 封顶（host-cli 1.1
// 验证列 / design D2 预算）：解析缝挂死（等到自身 ctx 取消才返回）+ 死端点探测
// ——旧实现（顺序解析、解析不计父预算）此场景最坏 4.5s+。
func TestReachParentBudgetSlowResolve(t *testing.T) {
	dead := reachDeadPort(t)
	orig := reachResolver
	reachResolver = func(ctx context.Context, host string) []netip.Addr {
		<-ctx.Done() // 挂到解析预算/父预算取尽
		return nil
	}
	t.Cleanup(func() { reachResolver = orig })

	start := time.Now()
	rep, err := Reach(context.Background(), reachToken(t,
		proto.Endpoint{Addr: "slow.example.invalid:41641"},
		proto.Endpoint{Addr: dead},
	))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("慢解析 + 死端点应无应答：%+v", rep.Results)
	}
	// 父预算封顶：解析吃 1.5s（并行，两个端点各自缝），探测受父预算压到 ≤2s，
	// 总等待 ≤3.5s（留常规余量）。
	if elapsed > ReachParentBudget+400*time.Millisecond {
		t.Fatalf("总等待超父预算：%v", elapsed)
	}
	if elapsed < ReachResolveBudget {
		t.Fatalf("解析至少应挂满自身预算（验证注入生效）：%v", elapsed)
	}
}

// TestReachParentBudgetSlowResolveMultiple 并行解析：两个慢域名端点并行挂 1.5s
// 而非顺序 3s——总等待仍 3.5s 封顶。
func TestReachParentBudgetSlowResolveMultiple(t *testing.T) {
	orig := reachResolver
	reachResolver = func(ctx context.Context, host string) []netip.Addr {
		<-ctx.Done()
		return nil
	}
	t.Cleanup(func() { reachResolver = orig })

	start := time.Now()
	_, err := Reach(context.Background(), reachToken(t,
		proto.Endpoint{Addr: "a.example.invalid:41641"},
		proto.Endpoint{Addr: "b.example.invalid:41641"},
	))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed > ReachParentBudget+400*time.Millisecond {
		t.Fatalf("并行解析下总等待超父预算：%v", elapsed)
	}
	if elapsed >= 2*ReachResolveBudget {
		t.Fatalf("两慢域名应并行（顺序 = ≥3s）：%v", elapsed)
	}
}

// TestReachBadTokenNoProbe token 非法就地报错：不发起任何网络探测（spec
// host-management「token 格式错误不进入探测」——解析失败的端点集为空）。
func TestReachBadTokenNoProbe(t *testing.T) {
	alive := reachStartFakeProber(t, "t-n")
	if _, err := Reach(context.Background(), "hmw1-not-a-token"); err == nil {
		t.Fatal("坏 token 应报错")
	}
	if got := alive.hits.Load(); got != 0 {
		t.Fatalf("坏 token 不应触发探测：%d", got)
	}
}

// TestResolveReachTargetAndDedup 纯函数面（自 app_probe_reach_test.go 迁入）。
func TestResolveReachTargetAndDedup(t *testing.T) {
	ctx := context.Background()
	if got := resolveReachTarget(ctx, "1.2.3.4:41641"); len(got) != 1 || got[0] != netip.MustParseAddrPort("1.2.3.4:41641") {
		t.Fatalf("IP 直解不符：%v", got)
	}
	if got := resolveReachTarget(ctx, "1.2.3.4:0"); got != nil {
		t.Fatalf("零端口应拒绝：%v", got)
	}
	if got := resolveReachTarget(ctx, "no-host-port"); got != nil {
		t.Fatalf("坏格式应拒绝：%v", got)
	}
	if got := resolveReachTarget(ctx, "1.2.3.4:65536"); got != nil {
		t.Fatalf("越界端口应拒绝：%v", got)
	}
	in := []netip.AddrPort{
		netip.MustParseAddrPort("1.1.1.1:1"),
		netip.MustParseAddrPort("1.1.1.1:1"),
		netip.MustParseAddrPort("2.2.2.2:2"),
	}
	if got := dedupAddrPorts(in); len(got) != 2 {
		t.Fatalf("去重不符：%v", got)
	}
}
