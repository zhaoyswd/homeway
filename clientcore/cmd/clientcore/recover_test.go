//go:build cshared

// recover_test.go — 统一恢复阶梯（openspec recovery-ladder）的档位与单飞行为。
// 假实现即时返回（探测不等待预算），用例因此毫秒级跑完；真实 WG 端到端路径
// 由 internal/wgcore/recover_test.go 覆盖（保采纳/清采纳断言在那里）。
package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeRecoverTransport 动作面假实现：计数 + 场景钩子（钩子里翻转 probe 状态，
// 模拟「哪档动作才治得好」）。
type fakeRecoverTransport struct {
	mu           sync.Mutex
	refreshReg   int
	resetSession int
	rebind       int
	rearm        int
	onReset      func()
	onRebind     func()
	onRearm      func()
	rebindErr    error
}

func (f *fakeRecoverTransport) RefreshReg() bool {
	f.mu.Lock()
	f.refreshReg++
	f.mu.Unlock()
	return true
}

func (f *fakeRecoverTransport) NotePathAlive() {} // endpoint-freshness：阶梯验证通过的落验证；单测不关心

func (f *fakeRecoverTransport) ResetPeerSession() error {
	f.mu.Lock()
	f.resetSession++
	f.mu.Unlock()
	if f.onReset != nil {
		f.onReset()
	}
	return nil
}

func (f *fakeRecoverTransport) Rebind() error {
	f.mu.Lock()
	f.rebind++
	err := f.rebindErr
	f.mu.Unlock()
	if err != nil {
		return err
	}
	if f.onRebind != nil {
		f.onRebind()
	}
	return nil
}

func (f *fakeRecoverTransport) Rearm() {
	f.mu.Lock()
	f.rearm++
	f.mu.Unlock()
	if f.onRearm != nil {
		f.onRearm()
	}
}

func (f *fakeRecoverTransport) counts() (int, int, int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.refreshReg, f.resetSession, f.rebind, f.rearm
}

// ladderDeps 组一套依赖：healthy 决定探测结果（false = 即时报错，不等待）。
func ladderDeps(healthy *atomic.Bool, tr *fakeRecoverTransport) recoverDeps {
	return recoverDeps{
		probe: func(context.Context) error {
			if healthy.Load() {
				return nil
			}
			return errors.New("dead")
		},
		tr:   tr,
		logf: Discard,
	}
}

// ① 会话死、路径/socket 活：R1（丢会话）即恢复，不动 socket、不清采纳。
func TestRecoverLadderR1KeepsAdoption(t *testing.T) {
	healthy := &atomic.Bool{}
	tr := &fakeRecoverTransport{onReset: func() { healthy.Store(true) }}
	rc := runRecoverLadder(ladderDeps(healthy, tr), recoverR1, "测试①")
	if rc != 0 {
		t.Fatalf("R1 应恢复：rc=%d", rc)
	}
	rg, rs, rb, ra := tr.counts()
	if rs != 1 || rb != 0 || ra != 0 {
		t.Fatalf("R1 只该丢会话（refresh=%d reset=%d rebind=%d rearm=%d）", rg, rs, rb, ra)
	}
}

// ② socket 失效、网络没变：R1 治不好，升级 R2（换源）恢复，仍不清采纳。
func TestRecoverLadderR2ResocketKeepsAdoption(t *testing.T) {
	healthy := &atomic.Bool{}
	tr := &fakeRecoverTransport{onRebind: func() { healthy.Store(true) }}
	rc := runRecoverLadder(ladderDeps(healthy, tr), recoverR1, "测试②")
	if rc != 0 {
		t.Fatalf("应升级到 R2 恢复：rc=%d", rc)
	}
	_, _, rb, ra := tr.counts()
	if rb != 1 || ra != 0 {
		t.Fatalf("R2 应换源且不清采纳（rebind=%d rearm=%d）", rb, ra)
	}
}

// ③ 出口端点已变：只有清采纳重赛跑（R3）治得好。
func TestRecoverLadderR3Reroute(t *testing.T) {
	healthy := &atomic.Bool{}
	tr := &fakeRecoverTransport{onRearm: func() { healthy.Store(true) }}
	rc := runRecoverLadder(ladderDeps(healthy, tr), recoverR1, "测试③")
	if rc != 0 {
		t.Fatalf("应升级到 R3 恢复：rc=%d", rc)
	}
	_, _, rb, ra := tr.counts()
	if ra != 1 || rb != 1 {
		t.Fatalf("R3 = 换源 + 清采纳（rebind=%d rearm=%d）", rb, ra)
	}
}

// ③b 直入 R3（换网下推路径）：一次跑齐低档动作（补注册+丢会话+换源+清采纳），各一次。
func TestRecoverLadderDirectR3Catchup(t *testing.T) {
	healthy := &atomic.Bool{}
	tr := &fakeRecoverTransport{onRearm: func() { healthy.Store(true) }}
	rc := runRecoverLadder(ladderDeps(healthy, tr), recoverR3, "测试③b")
	if rc != 0 {
		t.Fatalf("直入 R3 应恢复：rc=%d", rc)
	}
	rg, rs, rb, ra := tr.counts()
	if rg != 1 || rs != 1 || rb != 1 || ra != 1 {
		t.Fatalf("直入 R3 应把低档动作各补一次（refresh=%d reset=%d rebind=%d rearm=%d）", rg, rs, rb, ra)
	}
}

// ④ 全档失败：-1（交上层升级整套重建）。
func TestRecoverLadderExhausted(t *testing.T) {
	healthy := &atomic.Bool{}
	tr := &fakeRecoverTransport{}
	rc := runRecoverLadder(ladderDeps(healthy, tr), recoverR1, "测试④")
	if rc != -1 {
		t.Fatalf("全档失败应返回 -1：rc=%d", rc)
	}
	rg, _, _, ra := tr.counts() // 齐全性：三档动作都执行过
	if ra != 1 {
		t.Fatalf("失败前应跑完三档（refresh=%d rearm=%d）", rg, ra)
	}
}

// ④b 本地动作失败：Rebind 报错 → -4（区别于路径层 -1）。
func TestRecoverLadderLocalActionFail(t *testing.T) {
	healthy := &atomic.Bool{}
	tr := &fakeRecoverTransport{rebindErr: errors.New("no route")}
	rc := runRecoverLadder(ladderDeps(healthy, tr), recoverR1, "测试④b")
	if rc != -4 {
		t.Fatalf("本地动作失败应返回 -4：rc=%d", rc)
	}
}

// ⑤ 探测先行：已恢复时零档位动作（误触发无成本）。
func TestRecoverLadderProbeFirst(t *testing.T) {
	healthy := &atomic.Bool{}
	healthy.Store(true)
	tr := &fakeRecoverTransport{}
	rc := runRecoverLadder(ladderDeps(healthy, tr), recoverR3, "测试⑤")
	if rc != 0 {
		t.Fatalf("探测先行应直接恢复：rc=%d", rc)
	}
	if rg, rs, rb, ra := tr.counts(); rg+rs+rb+ra != 0 {
		t.Fatalf("已恢复时不应执行任何动作（%d %d %d %d）", rg, rs, rb, ra)
	}
}

// ⑥ 重入合并：执行中的第二次触发不起新轮，共享当前轮结果（闸按恢复域实例化，测试用独立实例）。
func TestRecoverMergeSingleFlight(t *testing.T) {
	g := &recoverGate{}
	running := func() bool {
		g.mu.Lock()
		defer g.mu.Unlock()
		return g.cur != nil
	}
	runs := 0
	release := make(chan struct{})
	aRc := make(chan int, 1)
	go func() {
		aRc <- g.merge(recoverR1, "A", func(from recoverLevel) int {
			runs++
			<-release
			return 7 // 哨兵值：证明 B 拿到的是 A 的结果
		})
	}()
	waitFor(t, "A 起跑", running)
	bRc := make(chan int, 1)
	go func() {
		bRc <- g.merge(recoverR3, "B", func(from recoverLevel) int {
			t.Error("B 不应起新轮")
			return 0
		})
	}()
	// B 是无阻塞前奏的简单 goroutine，给调度留一小段即可进入合并等待
	//（合并等待本身无可观测信号；若 B 迟到起成新轮，下方 runs==1 断言会抓住）。
	time.Sleep(50 * time.Millisecond)
	close(release)
	if got := <-aRc; got != 7 {
		t.Fatalf("A 应拿到自己的结果 7：%d", got)
	}
	if got := <-bRc; got != 7 {
		t.Fatalf("B 应共享 A 的结果 7：%d", got)
	}
	if runs != 1 {
		t.Fatalf("应只跑一轮：%d", runs)
	}
}

// recoverTunnelReady：-2 的判定条件唯一真源——四条守卫缺一不可，
// 特别是 prepare 期（stageReady，锁已持有但无数据面）必须回答「没有隧道」。
func TestRecoverTunnelReady(t *testing.T) {
	if !recoverTunnelReady(true, true, stageAttached, true) {
		t.Fatal("四条齐备应可恢复")
	}
	for _, c := range []struct {
		name            string
		hasRun, running bool
		stage           tunStage
		hasClient       bool
	}{
		{"无世代", false, true, stageAttached, true},
		{"核未跑", true, false, stageAttached, true},
		{"prepare 期", true, true, stageReady, true},
		{"failed 期", true, true, stageFailed, true},
		{"无会话", true, true, stageAttached, false},
	} {
		if recoverTunnelReady(c.hasRun, c.running, c.stage, c.hasClient) {
			t.Fatalf("%s：应判没有可恢复的隧道", c.name)
		}
	}
}

// waitFor 带 2s 上界的轮询等待。
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("等待超时：%s", what)
}
