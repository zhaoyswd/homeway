//go:build cshared

// app_probe_reach_test.go — 连通性探测导出的纯 Go 主体（add-host-connectivity 任务 2.1）：
// 活/死端点分桶、relay 标记、预算封顶（全死端点在预算内返回空结果）。
package main

import (
	"encoding/json"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/probe"
	"github.com/zhaoyswd/homeway/pkg/proto"
)

// fakeProber：本地参照点应答器（就绪即回，带构建标记）。
type fakeProber struct {
	pc    *net.UDPConn
	build string
	done  chan struct{}
}

func startFakeProber(t *testing.T, build string) *fakeProber {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	fp := &fakeProber{pc: pc, build: build, done: make(chan struct{})}
	go func() {
		defer close(fp.done)
		buf := make([]byte, 1500)
		for {
			n, src, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if resp := probe.Respond(buf[:n], src.AddrPort(), fp.build, 0); resp != nil {
				_, _ = pc.WriteToUDP(resp, src)
			}
		}
	}()
	t.Cleanup(func() { _ = pc.Close(); <-fp.done })
	return fp
}

// deadPort：本机一个没人监听的端口（探测它 = 无应答）。
func deadPort(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().String()
}

func makeReachToken(t *testing.T, eps ...proto.Endpoint) string {
	t.Helper()
	tok := proto.Token{Endpoints: eps}
	s, err := proto.EncodeToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type reachOutcome struct {
	OK      bool `json:"ok"`
	Results []struct {
		EP    string `json:"ep"`
		RTTms int64  `json:"rtt_ms"`
		Build string `json:"build"`
		Relay bool   `json:"relay"`
	} `json:"results"`
}

func TestProbeReachAliveDeadAndRelay(t *testing.T) {
	alive := startFakeProber(t, "test-exit-v9")
	dead := deadPort(t)
	tok := makeReachToken(t,
		proto.Endpoint{Addr: alive.pc.LocalAddr().String()},
		proto.Endpoint{Addr: dead},
		proto.Endpoint{Addr: alive.pc.LocalAddr().String(), Relay: true},
	)

	var out reachOutcome
	if err := json.Unmarshal([]byte(probeReachJSON(tok)), &out); err != nil {
		t.Fatalf("返回不是合法 JSON：%v", err)
	}
	if !out.OK {
		t.Fatal("ok=false")
	}
	// 死端点不回报；活端点两条（直连 + 中继），中继标记分桶正确。
	if len(out.Results) != 2 {
		t.Fatalf("活端点数不符：%+v", out.Results)
	}
	var sawDirect, sawRelay bool
	for _, r := range out.Results {
		if r.Build != "test-exit-v9" {
			t.Fatalf("构建标记不符：%q", r.Build)
		}
		if r.EP != alive.pc.LocalAddr().String() {
			t.Fatalf("端点不符：%q", r.EP)
		}
		if r.RTTms < 0 {
			t.Fatalf("RTT 异常：%d", r.RTTms)
		}
		if r.Relay {
			sawRelay = true
		} else {
			sawDirect = true
		}
	}
	if !sawDirect || !sawRelay {
		t.Fatalf("直连/中继分桶缺失：%+v", out.Results)
	}
}

func TestProbeReachAllDeadWithinBudget(t *testing.T) {
	d1, d2 := deadPort(t), deadPort(t)
	tok := makeReachToken(t,
		proto.Endpoint{Addr: d1},
		proto.Endpoint{Addr: d2},
	)
	start := time.Now()
	raw := probeReachJSON(tok)
	elapsed := time.Since(start)

	var out reachOutcome
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("返回不是合法 JSON：%v", err)
	}
	if !out.OK || len(out.Results) != 0 {
		t.Fatalf("全死端点应返回空结果：%s", raw)
	}
	// 预算封顶：总耗时不显著超过 reachBudget（ICMP 快退只会更早）。
	if elapsed > reachBudget+500*time.Millisecond {
		t.Fatalf("超预算：%v", elapsed)
	}
}

func TestProbeReachBadToken(t *testing.T) {
	raw := probeReachJSON("hmw1-not-a-token")
	var out map[string]string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("返回不是合法 JSON：%v", err)
	}
	if _, has := out["error"]; !has {
		t.Fatalf("坏 token 应返回 error：%s", raw)
	}
}

// dedupAddrPorts / resolveReachTarget 的纯函数面。
func TestResolveReachTargetAndDedup(t *testing.T) {
	if got := resolveReachTarget("1.2.3.4:41641"); len(got) != 1 || got[0] != netip.MustParseAddrPort("1.2.3.4:41641") {
		t.Fatalf("IP 直解不符：%v", got)
	}
	if got := resolveReachTarget("1.2.3.4:0"); got != nil {
		t.Fatalf("零端口应拒绝：%v", got)
	}
	if got := resolveReachTarget("no-host-port"); got != nil {
		t.Fatalf("坏格式应拒绝：%v", got)
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
