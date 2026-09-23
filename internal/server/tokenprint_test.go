package server

// tokenprint_test.go —— 终端 token 公告「一辈子只打一轮」的回归（2026-09-21 用户口径：
// 端点变化后终端冒出第二串 token 只会让人拿错；变化只进 events.log，取最新靠
// grep 客户端 token events.log | tail -1）。
//
//	1) 首轮（lastToken==""）→ tokenToTerminal 两行（token + 端点），文件流不出；
//	2) 端点变化轮 → tokenToFile 两行（措辞带「端点已变化」），终端流不再出；
//	3) 端点没变 → 两条流都不出（去重）。

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/zhaoyswd/homeway/pkg/proto"
	"github.com/zhaoyswd/homeway/pkg/servercore"
)

func TestPrintClientTokenTerminalOnce(t *testing.T) {
	var mu sync.Mutex
	var term, file []string
	tokenToTerminal = func(f string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		term = append(term, fmt.Sprintf(f, a...))
	}
	tokenToFile = func(f string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		file = append(file, fmt.Sprintf(f, a...))
	}
	t.Cleanup(func() { tokenToTerminal = ulogf; tokenToFile = logf })

	// 真开一个临时 UDP socket：printClientToken 的端口闸要读 bind.LocalPort()。
	b := &servercore.ServerBind{Logf: func(string, ...any) {}}
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	s := &Server{bind: b, priv: [32]byte{1}, secret: [32]byte{2}}

	// 1) 首轮：终端出 token+端点两行，文件流不出（生产里 ulogf 自己会抄一份进文件）。
	s.printClientToken([]string{"203.0.113.7:41641"})
	mu.Lock()
	if len(term) != 2 || len(file) != 0 {
		mu.Unlock()
		t.Fatalf("首轮：终端应恰好 2 行（token+端点）、文件 0 行，实际 term=%d file=%d", len(term), len(file))
	}
	if !strings.Contains(term[0], "客户端 token（") || !strings.Contains(term[1], "端点：") {
		mu.Unlock()
		t.Fatalf("首轮措辞不对：%v", term)
	}
	mu.Unlock()

	// 2) 端点变化（v6 加入）：终端保持沉默，文件流重写一份并带「端点已变化」。
	s.printClientToken([]string{"203.0.113.7:41641", "[2001:db8::1]:41641"})
	mu.Lock()
	if len(term) != 2 {
		mu.Unlock()
		t.Fatalf("变化轮：终端不得再出（应仍为 2 行），实际 %d 行：%v", len(term), term)
	}
	if len(file) != 2 || !strings.Contains(file[0], "端点已变化") {
		mu.Unlock()
		t.Fatalf("变化轮：文件流应恰好 2 行且带「端点已变化」，实际 %d 行：%v", len(file), file)
	}
	mu.Unlock()

	// 3) 端点没变（同清单再打）：两条流都不出。
	s.printClientToken([]string{"203.0.113.7:41641", "[2001:db8::1]:41641"})
	mu.Lock()
	if len(term) != 2 || len(file) != 2 {
		mu.Unlock()
		t.Fatalf("去重：两条流都不该再出，实际 term=%d file=%d", len(term), len(file))
	}
	mu.Unlock()

	// 4) 端点又变回去（v6 掉了，对应一次 STUN 超时）：仍只进文件流。
	s.printClientToken([]string{"203.0.113.7:41641"})
	mu.Lock()
	if len(term) != 2 || len(file) != 4 {
		mu.Unlock()
		t.Fatalf("再次变化：终端应仍 2 行、文件累计 4 行，实际 term=%d file=%d", len(term), len(file))
	}
	mu.Unlock()
}

// 回归（2026-09-23，add-host-connectivity）：token 里的中继腿必须带 Relay 标记——
// 此前 add() 不透传，中继端点被标成 direct，客户端的直连/中继分桶（赛跑窗口、
// relay 升级、添加探测的 relay_only 档）全部失效。
func TestTokenEndpointsRelayFlag(t *testing.T) {
	s := &Server{}
	s.relayEp = proto.Endpoint{Addr: "198.51.100.9:41741", Relay: true}
	eps, labels := s.tokenEndpoints([]string{"203.0.113.7:41641"}, 41641)
	var relaySeen, directSeen bool
	for _, e := range eps {
		if e.Relay {
			relaySeen = true
			if e.Addr != s.relayEp.Addr {
				t.Fatalf("relay 标记落在错误端点上：%q", e.Addr)
			}
		} else {
			directSeen = true
		}
	}
	if !relaySeen || !directSeen {
		t.Fatalf("直连/中继标记分桶缺失：eps=%+v labels=%v", eps, labels)
	}
	// 端点列表可往返（EncodeToken→DecodeToken 后 Relay 仍为 true）。
	tokStr, err := proto.EncodeToken(proto.Token{
		PeerID:    [32]byte{1},
		Secret:    [32]byte{2},
		Endpoints: eps,
	})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := proto.DecodeToken(tokStr)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range decoded.Endpoints {
		if e.Addr == s.relayEp.Addr && !e.Relay {
			t.Fatal("编码往返后中继标记丢失")
		}
	}
}

// printClientToken 集成（review 4 加固）：--relay 形态下终端首轮打出的 token 必须带
// 恰好一条 relay 端点、端点行含「（中继）」——这条路径才是用户真正粘走的产物，且覆盖
// printClientToken 的 hasRelay 闸门（此前测试从未设 relayWanted，闸门路径零覆盖）。
func TestPrintClientTokenRelayIntegrated(t *testing.T) {
	var mu sync.Mutex
	var term []string
	tokenToTerminal = func(f string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		term = append(term, fmt.Sprintf(f, a...))
	}
	tokenToFile = func(string, ...any) {}
	t.Cleanup(func() { tokenToTerminal = ulogf; tokenToFile = logf })

	b := &servercore.ServerBind{Logf: func(string, ...any) {}}
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	s := &Server{bind: b, priv: [32]byte{1}, secret: [32]byte{2}}
	s.relayEp = proto.Endpoint{Addr: "198.51.100.9:41741", Relay: true}
	s.relayWanted = true

	s.printClientToken([]string{"203.0.113.7:41641"})
	mu.Lock()
	defer mu.Unlock()
	if len(term) != 2 {
		t.Fatalf("首轮应恰好 token+端点两行，实际 %d 行：%v", len(term), term)
	}
	if !strings.Contains(term[1], "（中继）") {
		t.Fatalf("端点行应含（中继）标注：%v", term[1])
	}
	// 从 token 行抠出串解回，断言恰好 1 条 relay + ≥1 条 direct。
	i := strings.Index(term[0], "hmw1")
	if i < 0 {
		t.Fatalf("token 行没有 hmw1 串：%v", term[0])
	}
	rest := term[0][i:]
	end := strings.IndexAny(rest, " \t")
	if end > 0 {
		rest = rest[:end]
	}
	tok, err := proto.DecodeToken(rest)
	if err != nil {
		t.Fatalf("终端 token 解码失败：%v", err)
	}
	var relayN, directN int
	for _, e := range tok.Endpoints {
		if e.Relay {
			relayN++
		} else {
			directN++
		}
	}
	if relayN != 1 || directN < 1 {
		t.Fatalf("端点标记分布应 1 relay + ≥1 direct，实际 %d/%d：%+v", relayN, directN, tok.Endpoints)
	}
}

// 去重边界反例（review 3）：中继地址与公网端点重合（--relay 指向出口自己地址的退化
// 形态）→ 地址保留为 direct、不出现 relay 条目。把取舍钉成契约，防后人「顺手改成不丢」。
func TestTokenEndpointsRelayAddrCollision(t *testing.T) {
	s := &Server{}
	s.relayEp = proto.Endpoint{Addr: "203.0.113.7:41641", Relay: true}
	eps, _ := s.tokenEndpoints([]string{"203.0.113.7:41641"}, 41641)
	if len(eps) == 0 {
		t.Fatal("端点表不应为空")
	}
	for _, e := range eps {
		if e.Relay {
			t.Fatalf("退化形态下不应出现 relay 条目（direct 优先，物理上就是出口自己的 WG socket）：%+v", eps)
		}
	}
	found := false
	for _, e := range eps {
		if e.Addr == "203.0.113.7:41641" {
			found = true
		}
	}
	if !found {
		t.Fatalf("重合地址本身必须保留：%+v", eps)
	}
}
