//go:build cshared

// app_probe_reach_test.go — 连通性探测导出的呈现层判据（add-host-connectivity 任务
// 2.1 起；host-cli 1.1 提取共享后）：活/死端点分桶、relay 标记、预算封顶（全死端点
// 在预算内返回空结果）+ 提取前后**规范化解对拍**（键集合/字段顺序/非时序值逐字节；
// results 按 ep 规范排序、rtt_ms 固定桩、空 results 必须 `[]`——口径 host-cli
// design D2/r1 M2；编排本体单测在 pkg/probe/reach_test.go 无 tag 面）。
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
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
	// 预算封顶：总耗时不显著超过探测预算（ICMP 快退只会更早）。
	if elapsed > probe.ReachProbeBudget+500*time.Millisecond {
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

// canonReachJSON 规范化解（对拍口径 host-cli design D2）：map 键序（encoding/json
// 字母序）承载键集合与字段顺序；rtt_ms 固定桩 0；results 按 (ep, relay) 排序——
// 同地址可同时有直连与中继两条结论（relay 决胜；完成序本就随 goroutine 不定）。
func canonReachJSON(t *testing.T, raw string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("非合法 JSON：%v（%s）", err, raw)
	}
	if rs, ok := m["results"].([]any); ok {
		for _, r := range rs {
			if rm, ok := r.(map[string]any); ok {
				rm["rtt_ms"] = float64(0)
			}
		}
		key := func(r any) string {
			rm, _ := r.(map[string]any)
			rel := false
			if v, ok := rm["relay"].(bool); ok {
				rel = v
			}
			return fmt.Sprint(rm["ep"]) + "|" + fmt.Sprint(rel)
		}
		for i := 1; i < len(rs); i++ {
			for j := i; j > 0; j-- {
				if key(rs[j-1]) > key(rs[j]) {
					rs[j-1], rs[j] = rs[j], rs[j-1]
				} else {
					break
				}
			}
		}
	}
	out, _ := json.Marshal(m)
	return string(out)
}

// TestProbeReachCanonicalGolden 提取前后规范化解对拍（host-cli 1.1 验证列）：
// 基线 = 提取前实采（在线出口/离线端点/非法 token 三态，2026-09-29 在 3a 收官态
// homeway 6620815 上以同一 canonicalizer 采得）；端口号是活端点的监听口（每跑不同），
// 对拍前先回填占位。
func TestProbeReachCanonicalGolden(t *testing.T) {
	alive := startFakeProber(t, "cap-exit-v1")
	dead := deadPort(t)

	aliveEp := alive.pc.LocalAddr().String()
	deadEp := dead

	tokAlive := makeReachToken(t,
		proto.Endpoint{Addr: aliveEp},
		proto.Endpoint{Addr: deadEp},
		proto.Endpoint{Addr: aliveEp, Relay: true},
	)
	tokDead := makeReachToken(t,
		proto.Endpoint{Addr: deadEp},
		proto.Endpoint{Addr: "203.0.113.7:41641", Relay: true},
	)

	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"在线出口", canonReachJSON(t, probeReachJSON(tokAlive)),
			`{"endpoints":["<alive>","<dead>","relay:<alive>"],"ok":true,"peer":"000000000000","results":[{"build":"cap-exit-v1","ep":"<alive>","relay":false,"rtt_ms":0},{"build":"cap-exit-v1","ep":"<alive>","relay":true,"rtt_ms":0}]}`},
		{"离线端点", canonReachJSON(t, probeReachJSON(tokDead)),
			`{"endpoints":["<dead>","relay:203.0.113.7:41641"],"ok":true,"peer":"000000000000","results":[]}`},
		{"非法 token", canonReachJSON(t, probeReachJSON("hmw1-not-a-token")),
			`{"error":"homeway/token: 校验失败（串被截断或损坏）"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want := c.want
			want = strings.ReplaceAll(want, "<alive>", aliveEp)
			want = strings.ReplaceAll(want, "<dead>", deadEp)
			if c.raw != want {
				t.Fatalf("规范化解不符：\n got=%s\nwant=%s", c.raw, want)
			}
		})
	}
}

// TestProbeReachRawKeyOrder 键序断言（exec-r1 第 3 条）：design D2 的「字段顺序
// 逐字节」这半条在 canonicalizer（map 重排）下不可判别——这里对**原始 raw** 直接
// 断言：顶层键按 endpoints → ok → peer → results 出现（map marshal 字母序），
// results 元组按结构体声明序 ep → rtt_ms → build → relay。任何一方字段增删/换序
// （含未来改用结构体 marshal 顶层）本用例即红。
func TestProbeReachRawKeyOrder(t *testing.T) {
	alive := startFakeProber(t, "ko-v1")
	tok := makeReachToken(t,
		proto.Endpoint{Addr: alive.pc.LocalAddr().String()},
		proto.Endpoint{Addr: alive.pc.LocalAddr().String(), Relay: true},
	)
	raw := probeReachJSON(tok)
	if !strings.HasPrefix(raw, `{"endpoints":[`) {
		t.Fatalf("顶层首键应为 endpoints（map 字母序）：%.60s", raw)
	}
	last := -1
	for _, k := range []string{`"endpoints":`, `"ok":`, `"peer":`, `"results":`} {
		i := strings.Index(raw, k)
		if i < 0 {
			t.Fatalf("缺顶层键 %s：%s", k, raw)
		}
		if i < last {
			t.Fatalf("顶层键序不符（%s 出现在前一键之前）：%s", k, raw)
		}
		last = i
	}
	// results 元组键序 = reachResult 结构体声明序。
	i := strings.Index(raw, `"results":[{`)
	if i < 0 {
		t.Fatalf("results 应含活端点元组：%s", raw)
	}
	tup := raw[i:]
	last = -1
	for _, k := range []string{`"ep":`, `"rtt_ms":`, `"build":`, `"relay":`} {
		j := strings.Index(tup, k)
		if j < 0 {
			t.Fatalf("results 元组缺键 %s：%s", k, tup)
		}
		if j < last {
			t.Fatalf("元组键序不符（%s 在前一键之前）：%.200s", k, tup)
		}
		last = j
	}
}
