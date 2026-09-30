package facade

// golden_test.go — §2.3 续播 golden（退出口判据机器化，r1 中-10/低-9 集合性质口径）：
// 确定性事件脚本 → 消费者中途杀（关订阅）→ 持游标重连 → 断言集合性质三条：
//  (1) 回放批的所有事件先于任何在线事件出现（消费顺序 pending → ch）；
//  (2) 合并两段流（被杀前已收 + 持游标重连续播）按 seq 幂等去重后覆盖
//      (cursor, 断点] 无缺口——**总线已发事件不丢**（评审对账锚点）；
//  (3) 允许重复与段内乱序（at-least-once + 投递在总线锁外、跨发布者到达次序
//      本就不保段内单调——**不得断言序列本身按 seq 递增**，并发发布下假红）。
// stale 矩阵两行：环淘汰（游标早于 ringStart）/ 代际失配（旧代际游标），各行断言
// 「cursor_stale → 全量重快照 → 续播无洞」。

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// pubN 发布 n 条 session.state_changed（单 goroutine、seq 严格连续）。
func pubN(t *testing.T, b *Bus, from, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := b.Publish(DomainSession, KindSessionStateChanged, SessionStateChangedPayload{
			Host: "golden", State: fmt.Sprintf("s%d", from+i),
		}); err != nil {
			t.Fatalf("发布失败：%v", err)
		}
	}
}

// recvN 从订阅者在线通道收 n 条（带时限）。
func recvN(t *testing.T, s *Subscriber, n int) []uint64 {
	t.Helper()
	out := make([]uint64, 0, n)
	deadline := time.After(5 * time.Second)
	for len(out) < n {
		select {
		case ev := <-s.Events():
			out = append(out, ev.Seq)
		case <-deadline:
			t.Fatalf("在线事件不足：要 %d 只到 %d", n, len(out))
		}
	}
	return out
}

// cover 断言 seq 集合幂等去重后恰覆盖 (lo, hi]（无缺口、无缺段；重复无害）。
func cover(t *testing.T, seqs []uint64, lo, hi uint64, what string) {
	t.Helper()
	seen := make(map[uint64]bool, hi-lo)
	for _, s := range seqs {
		seen[s] = true
	}
	for want := lo + 1; want <= hi; want++ {
		if !seen[want] {
			t.Fatalf("%s：seq %d 缺失（幂等去重后覆盖 (%d,%d] 必须无缺口；重复允许）", what, want, lo, hi)
		}
	}
}

// TestGoldenResumeSetProperties 杀消费者重连续播：集合性质三条（单发布者
// 确定性脚本 + 并发发布者段内乱序路径）。
func TestGoldenResumeSetProperties(t *testing.T) {
	b := NewBus("gen-golden", BusConfig{SubQueue: 64})

	// 第一段：消费者 A 在线订阅，收 10 条后中途杀（关订阅、弃通道）。
	a := b.NewSubscriber()
	if err := b.Subscribe(a, []string{DomainSession}, nil, "gen-golden"); err != nil {
		t.Fatal(err)
	}
	pubN(t, b, 1, 10)
	gotA := recvN(t, a, 10)
	cover(t, gotA, 0, 10, "第一段（被杀前已收）")
	cursor := gotA[9] // 持游标重连（单发布者下恰为末条 seq；作为断点记录）
	b.Unsubscribe(a)  // 杀：此后事件 A 不再收

	// 死亡窗口：A 错过 11..40。
	pubN(t, b, 11, 30)

	// 第二段：持游标重连（B），回放 (10, 40] + 在线收尾。发布者并发双 goroutine
	//（段内乱序/重复不假设单调——集合性质口径）。
	bl := b.NewSubscriber()
	if err := b.Subscribe(bl, []string{DomainSession}, &cursor, "gen-golden"); err != nil {
		t.Fatalf("持游标重连失败：%v", err)
	}
	replay := bl.DrainPending()

	// 性质 (1)：回放批的所有事件先于任何在线事件——回放批内 seq 全部 ≤ 订阅
	// 快照时刻（此处 = 40），其后在线事件（并发发布段）到达次序不保证段内单调，
	// 但回放批必须整体先行（消费顺序 pending → ch 是总线契约）。
	online := make([]uint64, 0, 20)
	var onMu sync.Mutex
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 20; i++ {
			ev := <-bl.Events()
			onMu.Lock()
			online = append(online, ev.Seq)
			onMu.Unlock()
		}
	}()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); pubN(t, b, 41, 10) }()
	go func() { defer wg.Done(); pubN(t, b, 51, 10) }()
	wg.Wait()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("在线事件未收齐")
	}

	for _, ev := range replay {
		if ev.Seq > 40 {
			t.Fatalf("性质(1) 破坏：回放批出现订阅后才发布的事件 seq=%d（回放必须先于在线）", ev.Seq)
		}
	}
	cover(t, seqsOf(replay), 10, 40, "回放批 (cursor,断点]")

	// 性质 (2)：合并两段按 seq 幂等去重后覆盖 (0, 60] 无缺口——总线已发事件不丢。
	merged := append(append([]uint64{}, gotA...), seqsOf(replay)...)
	merged = append(merged, online...)
	cover(t, merged, 0, 60, "合并两段（重连续播）")

	// 性质 (3)：允许重复——刻意再订一次同游标（重复回放段 11..40 全量重投），
	// 幂等覆盖不受影响。
	bl2 := b.NewSubscriber()
	if err := b.Subscribe(bl2, []string{DomainSession}, &cursor, "gen-golden"); err != nil {
		t.Fatal(err)
	}
	dup := bl2.DrainPending()
	cover(t, seqsOf(dup), 10, 40, "重复回放段")
	merged2 := append(append([]uint64{}, merged...), seqsOf(dup)...)
	cover(t, merged2, 0, 60, "合并含重复段（幂等覆盖）")
}

func seqsOf(evs []Event) []uint64 {
	out := make([]uint64, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.Seq)
	}
	return out
}

// TestGoldenStaleRingEviction 矩阵行一：环淘汰（游标早于 ringStart）→
// cursor_stale → 全量重快照 → 续播无洞。
func TestGoldenStaleRingEviction(t *testing.T) {
	b := NewBus("gen-evict", BusConfig{RingEntries: 8})
	pubN(t, b, 1, 20) // 环只保最近 8 条（seq 13..20）
	s := b.NewSubscriber()
	stale := uint64(5)
	if err := b.Subscribe(s, []string{DomainSession}, &stale, "gen-evict"); !errors.Is(err, ErrCursorStale) {
		t.Fatalf("环淘汰游标应 ErrCursorStale，得到 %v", err)
	}
	// 全量重快照（快照本体归消费方；总线面 = 纯在线订阅从当前续播）+ 续播无洞：
	fresh := b.NewSubscriber()
	if err := b.Subscribe(fresh, []string{DomainSession}, nil, "gen-evict"); err != nil {
		t.Fatal(err)
	}
	if p := fresh.DrainPending(); len(p) != 0 {
		t.Fatalf("纯在线订阅不应带回放（快照路径的回放由消费方带 cursor 另行订阅），得到 %d 条", len(p))
	}
	pubN(t, b, 21, 5)
	got := recvN(t, fresh, 5)
	cover(t, got, 20, 25, "stale 后重快照续播（无洞）")
}

// TestGoldenStaleGenerationMismatch 矩阵行二：代际失配（旧代际游标）→
// cursor_stale → 全量重快照 → 续播无洞。
func TestGoldenStaleGenerationMismatch(t *testing.T) {
	b := NewBus("gen-new", BusConfig{})
	pubN(t, b, 1, 5)
	s := b.NewSubscriber()
	cur := uint64(0)
	if err := b.Subscribe(s, []string{DomainSession}, &cur, "gen-old"); !errors.Is(err, ErrCursorStale) {
		t.Fatalf("代际失配应 ErrCursorStale，得到 %v", err)
	}
	fresh := b.NewSubscriber()
	if err := b.Subscribe(fresh, []string{DomainSession}, nil, "gen-new"); err != nil {
		t.Fatal(err)
	}
	pubN(t, b, 6, 5)
	got := recvN(t, fresh, 5)
	cover(t, got, 5, 10, "代际失配后重快照续播（无洞）")
}

// TestBusLargeReplayCompleteDelivery §2.2③：回放条数超过订阅队列容量（默认
// 512）仍完整送达（pending 段不占 ch、不受 subQueue 界），不退化为 cursor_stale。
func TestBusLargeReplayCompleteDelivery(t *testing.T) {
	b := NewBus("gen-large", BusConfig{}) // 默认 SubQueue=512、RingEntries=4096
	pubN(t, b, 1, 600)
	s := b.NewSubscriber()
	cur := uint64(0)
	if err := b.Subscribe(s, []string{DomainSession}, &cur, "gen-large"); err != nil {
		t.Fatalf(">512 条回放不应报错（更不应 cursor_stale）：%v", err)
	}
	replay := s.DrainPending()
	if len(replay) != 600 {
		t.Fatalf("回放应完整送达 600 条，得到 %d", len(replay))
	}
	cover(t, seqsOf(replay), 0, 600, "大回放批完整送达")
	// 订阅后在线事件照常续接（回放不占队列容量——ch 未被回放挤占）。
	pubN(t, b, 601, 3)
	recvN(t, s, 3)
}
