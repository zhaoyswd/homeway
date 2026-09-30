package facade

// bus_test.go — §3.4 事件总线单测（自 internal/control 迁入，4a 任务 2.1；断言不动）：seq 单调无洞、限速取号前（不占号）、环形窗
// 淘汰、游标回放不重不漏、游标过旧/代际失配 → cursor_stale、快照+订阅原子、
// 慢消费者 overrun（标记+停投+不静默丢）、词表闸（session.diag 不发射/term 空
// 载荷/词表外 kind 拒绝）。

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func pubState(t *testing.T, b *Bus, host, state string) uint64 {
	t.Helper()
	seq, err := b.Publish(DomainSession, KindSessionStateChanged, SessionStateChangedPayload{Host: host, State: state})
	if err != nil {
		t.Fatalf("发布 session.state_changed 失败：%v", err)
	}
	return seq
}

func TestBusSeqMonotonicNoHoles(t *testing.T) {
	b := NewBus("gen-1", BusConfig{})
	var last uint64
	for i := 0; i < 10; i++ {
		seq := pubState(t, b, fmt.Sprintf("h%d", i%3), "ready")
		if seq != last+1 {
			t.Fatalf("seq 必须连续无洞：第 %d 条 = %d（期望 %d）", i, seq, last+1)
		}
		last = seq
	}
	if b.CurrentSeq() != 10 {
		t.Fatalf("CurrentSeq = %d，期望 10", b.CurrentSeq())
	}
}

func TestBusTransferRateLimitBeforeTakingSeq(t *testing.T) {
	// transfer 限速：同 host 窗内第二条丢弃且**不占号**（总线上已发事件 seq 无洞）。
	b := NewBus("gen-1", BusConfig{TransferEvery: time.Hour}) // 测试里拍距拉到 1 小时
	s1, ok1 := b.PublishTransfer(TransferSamplePayload{Host: "h1", RxBytes: 1})
	if !ok1 || s1 != 1 {
		t.Fatalf("首条应放行：ok=%v seq=%d", ok1, s1)
	}
	_, ok2 := b.PublishTransfer(TransferSamplePayload{Host: "h1", RxBytes: 2})
	if ok2 {
		t.Fatalf("同 host 窗内第二条应被限速丢弃")
	}
	// 另一个 host 不受影响。
	s3, ok3 := b.PublishTransfer(TransferSamplePayload{Host: "h2"})
	if !ok3 || s3 != 2 {
		t.Fatalf("另一 host 应放行且占号：ok=%v seq=%d", ok3, s3)
	}
	// 限速丢弃不占号：session 域下一条 seq = 3（无洞）。
	seq := pubState(t, b, "h1", "ready")
	if seq != 3 {
		t.Fatalf("限速丢弃不能占号：session 事件 seq=%d，期望 3", seq)
	}
	// 节拍滑过窗口后恢复放行。
	b.transferLast["h1"] = time.Now().Add(-2 * time.Hour)
	s4, ok4 := b.PublishTransfer(TransferSamplePayload{Host: "h1"})
	if !ok4 || s4 != 4 {
		t.Fatalf("窗口滑过后应恢复放行：ok=%v seq=%d", ok4, s4)
	}
}

func TestBusLogBoundedTailBeforeTakingSeq(t *testing.T) {
	b := NewBus("gen-1", BusConfig{LogBurst: 3})
	for i := 0; i < 3; i++ {
		if _, ok := b.PublishLog(LogLinePayload{Level: "info", Msg: fmt.Sprintf("m%d", i)}); !ok {
			t.Fatalf("配额内第 %d 条应放行", i)
		}
	}
	if _, ok := b.PublishLog(LogLinePayload{Level: "info", Msg: "m3"}); ok {
		t.Fatalf("超出窗口配额应丢弃")
	}
	// 丢弃不占号。
	if seq := pubState(t, b, "h", "ready"); seq != 4 {
		t.Fatalf("log 限速丢弃不能占号：seq=%d 期望 4", seq)
	}
	// 窗口滑动（挤掉最老一条）后恢复 1 条配额。
	cut := time.Now().Add(-2 * time.Second)
	for i := range b.logTimes {
		if i == 0 {
			b.logTimes[i] = cut // 最老一条滑出窗口
		}
	}
	if _, ok := b.PublishLog(LogLinePayload{Level: "info", Msg: "m4"}); !ok {
		t.Fatalf("窗口滑出后应恢复放行")
	}
}

func TestBusRingEvictionAndCursorStale(t *testing.T) {
	// 环 = 4 条：发 6 条，最老两条被淘汰；游标落在淘汰段 → cursor_stale。
	b := NewBus("gen-1", BusConfig{RingEntries: 4})
	for i := 0; i < 6; i++ {
		pubState(t, b, "h", fmt.Sprintf("s%d", i))
	}
	sub := b.NewSubscriber()
	stale := uint64(1) // seq 2..3 已被淘汰
	if err := b.Subscribe(sub, []string{DomainSession}, &stale, "gen-1", ""); !errors.Is(err, ErrCursorStale) {
		t.Fatalf("游标过旧应 ErrCursorStale，得到 %v", err)
	}
	// 游标恰在窗起点（cursor+1 == oldest=3）→ 回放 4..6。
	cur := uint64(2)
	err := b.Subscribe(sub, []string{DomainSession}, &cur, "gen-1", "")
	replay := sub.DrainPending()
	if err != nil || len(replay) != 4 {
		t.Fatalf("窗起点回放应 4 条：err=%v n=%d", err, len(replay))
	}
	for i, ev := range replay {
		if ev.Seq != uint64(3+i) {
			t.Fatalf("回放次序/内容错：第 %d 条 seq=%d", i, ev.Seq)
		}
	}
}

func TestBusCursorFutureRejected(t *testing.T) {
	b := NewBus("gen-1", BusConfig{})
	pubState(t, b, "h", "ready")
	sub := b.NewSubscriber()
	future := uint64(99)
	if err := b.Subscribe(sub, []string{DomainSession}, &future, "gen-1", ""); !errors.Is(err, ErrCursorFuture) {
		t.Fatalf("超前游标应 ErrCursorFuture，得到 %v", err)
	}
}

func TestBusGenerationMismatchCursorStale(t *testing.T) {
	b := NewBus("gen-new", BusConfig{})
	pubState(t, b, "h", "ready")
	sub := b.NewSubscriber()
	cur := uint64(0)
	if err := b.Subscribe(sub, []string{DomainSession}, &cur, "gen-old", ""); !errors.Is(err, ErrCursorStale) {
		t.Fatalf("代际失配应 ErrCursorStale，得到 %v", err)
	}
}

func TestBusReplayNoDuplicateNoLoss(t *testing.T) {
	// 「游标重放总线已发事件不重不漏」：发 5 条 → 订阅（cursor=0）→ 回放恰 5 条
	// seq 1..5；订阅后再发 2 条 → 在线流恰收 2 条（无重叠：回放止于订阅时刻）。
	b := NewBus("gen-1", BusConfig{})
	for i := 0; i < 5; i++ {
		pubState(t, b, "h", fmt.Sprintf("s%d", i))
	}
	sub := b.NewSubscriber()
	cur := uint64(0)
	err := b.Subscribe(sub, []string{DomainSession}, &cur, "gen-1", "")
	if err != nil {
		t.Fatalf("订阅失败：%v", err)
	}
	replay := sub.DrainPending()
	if len(replay) != 5 || replay[0].Seq != 1 || replay[4].Seq != 5 {
		t.Fatalf("回放应恰为 seq 1..5：%d 条 [%v]", len(replay), replay)
	}
	for i := 0; i < 2; i++ {
		pubState(t, b, "h", "later")
	}
	for want := uint64(6); want <= 7; want++ {
		select {
		case ev := <-sub.Events():
			if ev.Seq != want {
				t.Fatalf("在线事件 seq=%d，期望 %d", ev.Seq, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("在线事件 %d 未到达", want)
		}
	}
	// 通道内不应再有积压（无重复投递）。
	select {
	case ev := <-sub.Events():
		t.Fatalf("不应有重复事件：%+v", ev)
	default:
	}
}

func TestBusSnapshotPlusSubscribeEquivalence(t *testing.T) {
	// 「快照 + 从游标续播等价全量」：订阅中途接入（先 3 条、订阅带 cursor=0 拿全
	// 量回放、再在线收尾）——前端见到的 seq 集合 = 全程在线订阅者。
	b := NewBus("gen-1", BusConfig{})
	full := b.NewSubscriber()
	if err := b.Subscribe(full, []string{DomainSession}, nil, "gen-1", ""); err != nil {
		t.Fatalf("全程订阅失败：%v", err)
	}
	for i := 0; i < 3; i++ {
		pubState(t, b, "h", "early")
	}
	late := b.NewSubscriber()
	cur := uint64(0) // = 快照带出的序号（这里以 0 模拟「从启动起」）
	err := b.Subscribe(late, []string{DomainSession}, &cur, "gen-1", "")
	replay := late.DrainPending()
	if err != nil || len(replay) != 3 {
		t.Fatalf("晚到订阅回放失败：err=%v n=%d", err, len(replay))
	}
	pubState(t, b, "h", "tail")
	// 两订阅者各自收齐 seq 1..4（集合等价；at-least-once 幂等语义下顺序不比较）。
	seen := func(s *Subscriber, n int) []uint64 {
		out := []uint64{}
		for i := 0; i < n; i++ {
			ev := <-s.Events()
			out = append(out, ev.Seq)
		}
		return out
	}
	fullSeqs := seen(full, 4)
	lateOnline := seen(late, 1)
	all := append(append([]uint64{}, replay[0].Seq, replay[1].Seq, replay[2].Seq), lateOnline...)
	if len(all) != 4 {
		t.Fatalf("晚到订阅者应见 4 条，见 %d", len(all))
	}
	for i, s := range all {
		if s != uint64(i+1) || fullSeqs[i] != uint64(i+1) {
			t.Fatalf("等价性破坏：late=%v full=%v", all, fullSeqs)
		}
	}
}

func TestBusDomainFilter(t *testing.T) {
	b := NewBus("gen-1", BusConfig{})
	sub := b.NewSubscriber()
	if err := b.Subscribe(sub, []string{DomainLink}, nil, "gen-1", ""); err != nil {
		t.Fatalf("订阅 link 域失败：%v", err)
	}
	pubState(t, b, "h", "ready") // session 域：不投
	if _, err := b.Publish(DomainLink, KindLinkChanged, LinkChangedPayload{Host: "h", Via: "direct", Ep: "1.2.3.4:1", RttMs: 9, At: 1}); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-sub.Events():
		if ev.Domain != DomainLink {
			t.Fatalf("应只收 link 域事件，收到 %s", ev.Domain)
		}
	case <-time.After(time.Second):
		t.Fatal("link 事件未到达")
	}
	select {
	case ev := <-sub.Events():
		t.Fatalf("session 域事件不应投给 link 订阅者：%+v", ev)
	default:
	}
	// 词表外域。
	if err := b.Subscribe(sub, []string{"nope"}, nil, "gen-1", ""); err == nil {
		t.Fatal("词表外订阅域应报错")
	}
}

func TestBusOverrunMarksStopsAndDoesNotSilentlyDrop(t *testing.T) {
	// 慢消费者：队列 2、不读；连发多事件 → 订阅被停（Done 关闭 + overrun 标记）、
	// 总线继续服务其它订阅者（不静默丢的语义 = 断连该订阅者而非丢弃）。
	b := NewBus("gen-1", BusConfig{SubQueue: 2})
	slow := b.NewSubscriber()
	fast := b.NewSubscriber()
	if err := b.Subscribe(slow, []string{DomainSession}, nil, "gen-1", ""); err != nil {
		t.Fatal(err)
	}
	if err := b.Subscribe(fast, []string{DomainSession}, nil, "gen-1", ""); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		pubState(t, b, "h", "s")
		<-fast.Events() // fast 实时读空
	}
	select {
	case <-slow.Done():
	default:
		t.Fatal("慢消费者应被标记终止（overrun）")
	}
	if !slow.OverrunDone() {
		t.Fatal("终止原因应为 overrun")
	}
	// overrun 后不再投递 slow（消息不堆积）。
	n := 0
	for {
		select {
		case <-slow.Events():
			n++
			continue
		default:
		}
		break
	}
	if n > 2 {
		t.Fatalf("overrun 订阅者只应滞留队列容量内的 %d 条，实际 %d 条", 2, n)
	}
	// fast 继续收新事件（总线未被慢消费者拖死）。
	pubState(t, b, "h", "after")
	select {
	case ev := <-fast.Events():
		if ev.Kind != KindSessionStateChanged {
			t.Fatalf("fast 应继续收到事件：%+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("overrun 后 fast 收不到事件")
	}
}

func TestBusKindVocabularyGates(t *testing.T) {
	b := NewBus("gen-1", BusConfig{})
	if _, err := b.Publish(DomainSession, "session.nonsense", nil); err == nil {
		t.Fatal("词表外 kind 应拒绝")
	}
	if _, err := b.Publish(DomainLog, KindSessionStateChanged, nil); err == nil {
		t.Fatal("kind/域 不匹配应拒绝")
	}
	// session.diag：4a §6.3 起真发射（「本期不发射」硬闸已拆——词表/载荷不动：
	// host, reason；reason 值域 gated/budget/probe_window 只增不改）。
	if _, err := b.Publish(DomainSession, KindSessionDiag, SessionDiagPayload{Host: "h", Reason: DiagGated}); err != nil {
		t.Fatalf("session.diag 应可发射（闸已拆）：%v", err)
	}
	// term 域：kind 冻结、载荷初始集为空。
	if _, err := b.Publish(DomainTerm, KindTermEnded, nil); err != nil {
		t.Fatalf("term 域空载荷应放行：%v", err)
	}
	if _, err := b.Publish(DomainTerm, KindTermEnded, map[string]string{"x": "y"}); err == nil {
		t.Fatal("term 域非空载荷应拒绝（字段名由后续 delta 增补）")
	}
	// link.changed 载荷结构照常发布。
	if _, err := b.Publish(DomainLink, KindLinkChanged, LinkChangedPayload{Host: "h"}); err != nil {
		t.Fatalf("link.changed 应放行：%v", err)
	}
}

func TestBusRingByteBudgetEvicts(t *testing.T) {
	// 字节量第二上限：两条 state_changed（各 40B，reason 空串也序列化）入环后
	// 130B 预算剩 50B，removed 载荷（62B）进环前淘汰最老直至装得下——最终环 =
	// seq2(40B) + seq3(62B)。
	b := NewBus("gen-1", BusConfig{RingEntries: 8, RingBytes: 130})
	pubState(t, b, "h", "ready")
	pubState(t, b, "h", "ready")
	if _, err := b.Publish(DomainSession, KindSessionRemoved, SessionRemovedPayload{Host: "0123456789abcdef0123456789abcdef", Reason: "removed"}); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	oldest := b.oldestSeqLocked()
	ringLen := b.ringLen
	bytes := b.ringBytes
	b.mu.Unlock()
	if oldest != 2 || ringLen != 2 || bytes != 40+62 {
		t.Fatalf("字节量淘汰后环应剩 seq2+seq3（102B）：oldest=%d len=%d bytes=%d", oldest, ringLen, bytes)
	}
}

// TestBusConcurrentUnsubscribeDomainsVsPublish 并发「退订域 × 发布」的竞态回归
// （exec-r1 H1：此前 server 侧在 subMu 下裸 delete(sub.domains)——与 publish 在
// b.mu 下经 matches 读同一张 map 是运行时 fatal 级竞态，recover 兜不住；修法 =
// 域增删收敛进总线锁 UnsubscribeDomains）。`-race` 下跑：旧实现必报
// concurrent map read and map write。
func TestBusConcurrentUnsubscribeDomainsVsPublish(t *testing.T) {
	b := NewBus("gen-1", BusConfig{SubQueue: 512})
	sub := b.NewSubscriber()
	if err := b.Subscribe(sub, []string{DomainSession, DomainLink}, nil, "", ""); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // 并发发布（publish 在 b.mu 下读 sub.domains）
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_, _ = b.Publish(DomainSession, KindSessionStateChanged, SessionStateChangedPayload{Host: "aa", State: "x"})
		}
	}()
	go func() { // 并发订阅/退订域（写 sub.domains——只在 b.mu 内）
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = b.Subscribe(sub, []string{DomainSession, DomainLink}, nil, "", "")
			b.UnsubscribeDomains(sub, []string{DomainSession})
		}
	}()
	wg.Wait()
	// 语义面顺带断言：摘空全部域 = 整体从总线摘除（此后发布不再投递）。
	b.UnsubscribeDomains(sub, []string{DomainLink})
	b.mu.Lock()
	_, registered := b.subs[sub]
	b.mu.Unlock()
	if registered {
		t.Fatal("摘空全部域后订阅者应已从总线摘除")
	}
}

// TestSubscribeReplacementNotUnion B4（host-cli 1.6，daemon-control-plane delta 钉死）：
// 同订阅者重复 Subscribe = **替换**（生效域集合整体换为新载荷），非并集——先订
// link 再订 session：此后 link 事件不再投递、session 事件照常（有判别力的行为
// 断言层：并集实现下 link 事件仍投递，本测试红）。
func TestSubscribeReplacementNotUnion(t *testing.T) {
	b := NewBus("gen-b4", BusConfig{SubQueue: 64})
	sub := b.NewSubscriber()
	if err := b.Subscribe(sub, []string{DomainLink}, nil, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := b.Subscribe(sub, []string{DomainSession}, nil, "", ""); err != nil {
		t.Fatal(err)
	}
	// 生效域集合 = {session}（matches 为包内可见的过滤真源）。
	if sub.matches(DomainLink) {
		t.Fatal("重复订阅应为替换：link 域不应仍生效（并集 = B4 红路）")
	}
	if !sub.matches(DomainSession) {
		t.Fatal("session 域应生效")
	}
	// 投递面：link 事件不投递、session 事件投递。
	if _, err := b.Publish(DomainLink, KindLinkChanged, LinkChangedPayload{Host: "aa", Via: "direct"}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Publish(DomainSession, KindSessionStateChanged, SessionStateChangedPayload{Host: "bb", State: "ready"}); err != nil {
		t.Fatal(err)
	}
	gotSession := false
	deadline := time.After(2 * time.Second)
	for {
		select {
		case ev := <-sub.Events():
			if ev.Domain == DomainLink {
				t.Fatalf("替换后不应再收到 link 事件：%+v", ev)
			}
			if ev.Domain == DomainSession {
				gotSession = true
			}
		case <-deadline:
			if !gotSession {
				t.Fatal("session 事件应照常投递")
			}
			return
		}
	}
}
