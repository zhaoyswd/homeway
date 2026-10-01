//go:build !cshared

package hostsession

// demand_gate_test.go — 4a §6.1（桌面门五分支 + nil 钩子零行为变化）与 §6.3
//（budget / probe_window 诊因发射点）的用例。gated 分支的发射在 notePatrolResult
// 用例内一并断言；§6.4 的真值表对齐审计向量与手机侧（cmd/clientcore/demand_test.go）
// 共享——两侧同向量对照表落 exec-report。

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/internal/wtransport"
)

var errGateProbe = errors.New("gate: 探测失败（注入）")

// gateCaptureDiag 捕获诊因发射（顺序 + 去重统计）。
type gateCaptureDiag struct {
	mu     sync.Mutex
	reason []string
}

func (c *gateCaptureDiag) diag(reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reason = append(c.reason, reason)
}

func (c *gateCaptureDiag) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.reason...)
}

// newGateSession 手工构造的桌面门测试会话（不经 NewSession 的全量生命周期）。
func newGateSession(demand func() (bool, string), diag func(string)) *Session {
	// logf 兜底：手工构造的 Session 若不设 logf，走失败/门控/逃逸分支时调 nil
	// 函数即 panic（FIX-21 逃逸用例首跑踩中）。
	s := &Session{demand: demand, diag: diag, logf: func(string, ...any) {}}
	if diag != nil {
		s.diagActive = make(map[string]bool)
		s.recGate.onWait = func() { s.noteDiag(diagProbeWindow) }
		s.recGate.onRoundEnd = func() { s.clearDiag(diagProbeWindow) }
	}
	return s
}

// TestPatrolEvidenceGateTruthTable 五分支真值表（§6.4 对齐审计的桌面侧向量——
// 与手机侧 cmd/clientcore/demand_test.go 的 TestPatrolEvidenceGate* 同向量）：
// 成功拍清零 / localNoise 清零 / 无需求清零 / 窗口作废 / 正常计数。
func TestPatrolEvidenceGateTruthTable(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name        string
		noise       bool
		demand      bool
		streak      int
		lastCounted time.Time
		probeErr    error
		wantN       int
		wantCounted bool
	}{
		{"成功拍清零（counted=false）", false, true, 2, now, nil, 0, false},
		{"localNoise 清零（无论需求）", true, true, 2, now, errGateProbe, 0, false},
		{"无需求清零", false, false, 2, now, errGateProbe, 0, false},
		{"窗口作废（间隔 > 10 分钟 → 从 1 重数）", false, true, 2, now.Add(-3 * time.Hour), errGateProbe, 1, true},
		{"窗内正常累加", false, true, 2, now.Add(-2 * time.Minute), errGateProbe, 3, true},
		{"首败不受窗影响（lastCounted 零值）", false, true, 0, time.Time{}, errGateProbe, 1, true},
		{"正常计数（+1）", false, true, 1, now.Add(-time.Minute), errGateProbe, 2, true},
	}
	for _, c := range cases {
		n, counted := PatrolEvidenceGate(c.noise, c.demand, c.streak, c.lastCounted, now, c.probeErr)
		if n != c.wantN || counted != c.wantCounted {
			t.Errorf("%s：得 (%d,%v)，期望 (%d,%v)", c.name, n, counted, c.wantN, c.wantCounted)
		}
	}
	// F,S,F,F 停在 2（评审 H3 验收形态——成功清零不许丢）。
	n, _ := PatrolEvidenceGate(false, true, 0, time.Time{}, now, errGateProbe)
	n, _ = PatrolEvidenceGate(false, true, n, now.Add(time.Minute), now.Add(time.Minute), nil)
	n, _ = PatrolEvidenceGate(false, true, n, now.Add(2*time.Minute), now.Add(2*time.Minute), errGateProbe)
	n, _ = PatrolEvidenceGate(false, true, n, now.Add(3*time.Minute), now.Add(3*time.Minute), errGateProbe)
	if n != 2 {
		t.Errorf("F,S,F,F 应停在 2（不是 3 连败）：%d", n)
	}
}

// TestNotePatrolResultNilHookLegacyParity §6.1 ①：**nil 钩子下巡检行为逐字节
// 不变**——两状态机对拍：nil 钩子的 notePatrolResult 与「未合入前」的旧语义
// （失败 +1 / 成功清零；无窗口、无噪声门）在整段编排（含 >10 分钟空窗）上逐步
// 同判。localSendErrWithin 被注入为恒真——nil 路径若误入噪声分支立即发散（nil
// 漂移检测用例：变异 = 去掉 nil 短路 → 本用例红）。
func TestNotePatrolResultNilHookLegacyParity(t *testing.T) {
	oldNoise := localSendErrWithin
	localSendErrWithin = func(ExitSession, time.Duration) bool { return true } // 误用即发散
	t.Cleanup(func() { localSendErrWithin = oldNoise })

	s2 := newGateSession(nil, nil)
	s2.logf = func(format string, args ...any) {}
	fake := newFakeExitSession()

	t0 := time.Now()
	script := []struct {
		err  error
		away time.Duration // 本拍时刻距 t0 的偏移（制造 > 窗口的空窗）
	}{
		{errGateProbe, 0},
		{errGateProbe, time.Minute},
		{nil, 2 * time.Minute},
		{errGateProbe, 3 * time.Minute},
		{errGateProbe, 14 * time.Minute}, // 11 分钟空窗：旧语义照常 +1（2→3）
		{errGateProbe, 15 * time.Minute},
	}
	legacy := 0 // 旧语义参照机：失败 +1 / 成功清零（改前 patrol 的本地计数行为）
	for _, beat := range script {
		now := t0.Add(beat.away)
		s2.notePatrolResult(fake, beat.err, true, "", now)
		if beat.err == nil {
			legacy = 0
		} else {
			legacy++
		}
		if s2.patrolStreak != legacy {
			t.Fatalf("@%v：nil 钩子行为漂移（得 %d，旧语义 %d）——两条新语义只允许在非 nil 路径生效", beat.away, s2.patrolStreak, legacy)
		}
	}
	if legacy != 3 {
		t.Fatalf("编排末态应为 3（含跨空窗累加——旧语义无时间窗），得 %d", legacy)
	}
}

// TestNotePatrolResultNilHookLogFormat nil 钩子的日志行格式逐字节（旧口径：
// 「巡检失败（连续 N）：err」；成功拍无门控行——门控行只在非 nil 路径出现）。
func TestNotePatrolResultNilHookLogFormat(t *testing.T) {
	var lines []string
	s := newGateSession(nil, nil)
	s.logf = func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }
	fake := newFakeExitSession()
	t0 := time.Now()
	s.notePatrolResult(fake, errGateProbe, true, "", t0)
	s.notePatrolResult(fake, errGateProbe, true, "", t0.Add(time.Minute))
	s.notePatrolResult(fake, nil, true, "", t0.Add(2*time.Minute))
	if len(lines) != 2 {
		t.Fatalf("nil 钩子两失败拍应恰两行（成功拍静默——旧口径），得 %d 行：%v", len(lines), lines)
	}
	want := "巡检失败（连续 1）：" + errGateProbe.Error()
	if lines[0] != want {
		t.Fatalf("失败行格式应逐字节同旧口径：\n得  %q\n期望 %q", lines[0], want)
	}
	if lines[1] != "巡检失败（连续 2）："+errGateProbe.Error() {
		t.Fatalf("第二行：%q", lines[1])
	}
}

// TestNotePatrolResultGateBranches §6.1 ②：非 nil 门控全分支（成功清零 /
// localNoise 清零 / 无需求清零 / 窗口作废 / 正常计数）+ gated 诊因边沿（进入
// 一条、期间静默、需求恢复清态；再次进入可再发）。
func TestNotePatrolResultGateBranches(t *testing.T) {
	oldNoise := localSendErrWithin
	fake := newFakeExitSession()
	t0 := time.Now()

	// —— 无需求清零 + gated 边沿（进入一条）——
	diagCap := &gateCaptureDiag{}
	var demandActive = false
	s := newGateSession(func() (bool, string) { return demandActive, "熄屏" }, diagCap.diag)
	s.logf = func(string, ...any) {}
	localSendErrWithin = func(ExitSession, time.Duration) bool { return false }
	s.notePatrolResult(fake, errGateProbe, false, "熄屏", t0) // streak 0→0（清零）
	if s.patrolStreak != 0 {
		t.Fatalf("无需求拍应清零：%d", s.patrolStreak)
	}
	if got := diagCap.snapshot(); len(got) != 1 || got[0] != "gated" {
		t.Fatalf("无需求拍应发一条 gated 诊因：%v", got)
	}
	s.notePatrolResult(fake, errGateProbe, false, "熄屏", t0.Add(time.Minute)) // 期间静默
	if got := diagCap.snapshot(); len(got) != 1 {
		t.Fatalf("门控态期间不得重复发（单飞）：%v", got)
	}

	// —— 需求恢复：重新计入证据 + gated 清态 ——
	demandActive = true
	s.notePatrolResult(fake, errGateProbe, true, "出站流量", t0.Add(2*time.Minute))
	if s.patrolStreak != 1 {
		t.Fatalf("需求恢复后失败应计入（1）：%d", s.patrolStreak)
	}
	if _, still := s.diagActive["gated"]; still {
		t.Fatal("需求恢复应清 gated 态")
	}

	// —— 窗口作废：计数拍间隔超窗 → 从 1 重数 ——
	s.patrolLastCounted = t0.Add(2 * time.Minute)
	s.notePatrolResult(fake, errGateProbe, true, "出站流量", t0.Add(2*time.Minute).Add(servicePatrolFailWindow+time.Minute))
	if s.patrolStreak != 1 {
		t.Fatalf("跨窗失败应从 1 重数：%d", s.patrolStreak)
	}

	// —— 正常计数 ——
	s.notePatrolResult(fake, errGateProbe, true, "出站流量", time.Now())
	if s.patrolStreak != 2 {
		t.Fatalf("窗内应累加到 2：%d", s.patrolStreak)
	}

	// —— localNoise 清零（即使有需求）+ gated 再进入可再发 ——
	localSendErrWithin = func(ExitSession, time.Duration) bool { return true }
	s.notePatrolResult(fake, errGateProbe, true, "出站流量", time.Now())
	if s.patrolStreak != 0 {
		t.Fatalf("本地噪声拍应清零：%d", s.patrolStreak)
	}
	if got := diagCap.snapshot(); len(got) != 2 || got[1] != "gated" {
		t.Fatalf("再次进入门控态应再发一条 gated：%v", got)
	}

	// —— 成功拍清零（含门控态结束）——
	localSendErrWithin = func(ExitSession, time.Duration) bool { return false }
	s.notePatrolResult(fake, nil, true, "", time.Now())
	if s.patrolStreak != 0 {
		t.Fatalf("成功拍应清零：%d", s.patrolStreak)
	}
	if _, still := s.diagActive["gated"]; still {
		t.Fatal("成功拍应结束门控态")
	}
	t.Cleanup(func() { localSendErrWithin = oldNoise })
}

// TestRebuildBudgetDiag §6.3 ②：budget = rebuildSession 的限频拦截分支——拦截
// 发一条（边沿）、拦截期间静默、实际重建后清态（下一次拦截可再发）。注入缝 =
// 直接调 rebuildSession（不造状态、不靠定时巧合）。
func TestRebuildBudgetDiag(t *testing.T) {
	diagCap := &gateCaptureDiag{}
	s := newGateSession(nil, diagCap.diag)
	s.logf = func(string, ...any) {}
	restore := withFakeServiceBuild(func(cfg Config, logf Logf) (ExitSession, *wtransport.EndpointCache, error) {
		return newFakeExitSession(), nil, nil
	})
	t.Cleanup(restore)

	first := newFakeExitSession()
	s.mu.Lock()
	s.sess = first
	s.rebuildAt = time.Now() // 刚重建过 → 冷却窗内
	s.mu.Unlock()

	s.rebuildSession("测试：限频窗内") // 拦截（不发新会话）
	if got := diagCap.snapshot(); len(got) != 1 || got[0] != "budget" {
		t.Fatalf("限频拦截应发一条 budget 诊因：%v", got)
	}
	if s.curSession() != first {
		t.Fatal("限频拦截不得重建会话")
	}
	s.rebuildSession("测试：限频窗内 2") // 期间静默（单飞）
	if got := diagCap.snapshot(); len(got) != 1 {
		t.Fatalf("budget 态期间不得重复发：%v", got)
	}

	// 冷却过期 → 实际重建 → budget 态清（换新会话）。
	s.mu.Lock()
	s.rebuildAt = time.Now().Add(-serviceRebuildCooldown - time.Minute)
	s.mu.Unlock()
	s.rebuildSession("测试：冷却过期")
	if s.curSession() == first {
		t.Fatal("冷却过期应实际重建")
	}
	if _, still := s.diagActive["budget"]; still {
		t.Fatal("实际重建应清 budget 态")
	}

	// 再次拦截 → 可再发（状态离开过）。
	s.rebuildSession("测试：再拦截")
	if got := diagCap.snapshot(); len(got) != 2 || got[1] != "budget" {
		t.Fatalf("离开后再次拦截应再发 budget：%v", got)
	}
}

// TestRecoverGateProbeWindowDiag §6.3 ③：probe_window = merge 的「有轮在跑 →
// 等待共享结果」分支——在途轮期间等待者发一条（单飞：多等待者也只一条）、轮
// 结束清态（下一轮的等待者可再发）。注入缝 = 直接驱动 recGate.merge。
func TestRecoverGateProbeWindowDiag(t *testing.T) {
	diagCap := &gateCaptureDiag{}
	s := newGateSession(nil, diagCap.diag)
	s.logf = func(string, ...any) {}

	roundStart := make(chan struct{})
	roundHold := make(chan struct{})
	waiter1 := make(chan int, 1)
	waiter2 := make(chan int, 1)
	// 在途轮：起跑后持住（run 不返回 → cur 非 nil）。
	go func() {
		s.recGate.merge(recoverR2, "巡检拍", func(from recoverLevel) int {
			close(roundStart)
			<-roundHold
			return 0
		})
	}()
	<-roundStart
	// 两个等待者（挂起唤醒重绑等待同款分支）：probe_window 单飞恰一条。
	go func() { waiter1 <- s.recGate.merge(recoverR1, "挂起唤醒", func(recoverLevel) int { return 99 }) }()
	go func() { waiter2 <- s.recGate.merge(recoverR1, "拨号失败", func(recoverLevel) int { return 99 }) }()
	deadline := time.After(3 * time.Second)
	for len(diagCap.snapshot()) == 0 {
		select {
		case <-deadline:
			t.Fatal("等待分支应发 probe_window 诊因")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	// 等待者尚未返回（轮仍持住）——再等一小段确认单飞。
	time.Sleep(50 * time.Millisecond)
	if got := diagCap.snapshot(); len(got) != 1 || got[0] != "probe_window" {
		t.Fatalf("在途轮期间 probe_window 应单飞恰一条：%v", got)
	}
	// 轮结束：清态。清位发生在 merge 的 g.mu 临界区内、而等待者从 <-r.done
	// 返回不经 g.mu——清位可能尚未落到测试 goroutine，故锁内读 + 有界轮询
	// 等清位（exec-r2 新-1：测试无锁读 diagActive 是数据竞争，基线即有）。
	close(roundHold)
	<-waiter1
	<-waiter2
	deadline = time.After(3 * time.Second)
	for {
		s.mu.Lock()
		_, still := s.diagActive["probe_window"]
		s.mu.Unlock()
		if !still {
			break
		}
		select {
		case <-deadline:
			t.Fatal("轮结束应清 probe_window 态")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	// 下一轮的等待者可再发（状态离开过）。
	roundStart2 := make(chan struct{})
	roundHold2 := make(chan struct{})
	waiter3 := make(chan int, 1)
	go func() {
		s.recGate.merge(recoverR2, "第二轮", func(recoverLevel) int {
			close(roundStart2)
			<-roundHold2
			return 0
		})
	}()
	<-roundStart2
	go func() { waiter3 <- s.recGate.merge(recoverR1, "第二轮等待", func(recoverLevel) int { return 99 }) }()
	deadline = time.After(3 * time.Second)
	for len(diagCap.snapshot()) != 2 {
		select {
		case <-deadline:
			t.Fatal("第二轮等待应再发 probe_window（状态离开过）")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	close(roundHold2)
	<-waiter3
	if got := diagCap.snapshot(); len(got) != 2 || got[1] != "probe_window" {
		t.Fatalf("第二轮 probe_window：%v", got)
	}
}

// TestNotePatrolResultNoiseEscape FIX-21 接线：噪声长停逃逸——本地噪声持续超过
// NoiseEscalateAfter 后不再按环境噪声拦证据（按质量失败计入升级链），门从清零
// 翻回计数。变异红路：删 notePatrolResult 里的逃逸接线 ⇒ 本用例红（第二拍仍清零）。
func TestNotePatrolResultNoiseEscape(t *testing.T) {
	oldNoise := localSendErrWithin
	localSendErrWithin = func(ExitSession, time.Duration) bool { return true }
	t.Cleanup(func() { localSendErrWithin = oldNoise })

	fake := newFakeExitSession()
	s := newGateSession(func() (bool, string) { return true, "测试需求" }, nil)
	// 首拍噪声：清零 + 记逃逸计时起点。
	s.notePatrolResult(fake, errGateProbe, true, "", time.Now())
	if s.patrolStreak != 0 {
		t.Fatalf("噪声拍应清零：streak=%d", s.patrolStreak)
	}
	// 阈值后的第二拍：逃逸命中，按质量失败计（+1），且计时重置。
	now := time.Now().Add(NoiseEscalateAfter + time.Second)
	s.notePatrolResult(fake, errGateProbe, true, "", now)
	if s.patrolStreak != 1 {
		t.Fatalf("长停逃逸后应按质量失败计数：streak=%d", s.patrolStreak)
	}
	if !s.patrolNoiseSince.IsZero() {
		t.Fatalf("逃逸后计时应重置：%v", s.patrolNoiseSince)
	}
}

// TestSetLinkChangedEdge FIX-22：link.changed 生产者的变化沿——via/ep 变化才通知；
// rtt 波动不触发（巡检 60s 一拍都记快照，若 rtt 入判据事件流就退化成节拍器）。
// 变异红路：删 setLink 里的变化判定 ⇒ 首记丢失或 rtt 拍误发，本用例红。
func TestSetLinkChangedEdge(t *testing.T) {
	var got []string
	s := &Session{logf: func(string, ...any) {}, linkChanged: func(via, ep string, rttMs, at int64) {
		got = append(got, via+"/"+ep)
	}}
	s.setLink("direct", "1.2.3.4:1", 10) // 零值→值：首记即变化
	s.setLink("direct", "1.2.3.4:1", 20) // 仅 rtt 变：不通知
	s.setLink("direct", "1.2.3.4:2", 30) // ep 变：通知
	s.setLink("relay", "1.2.3.4:2", 40)  // via 变：通知
	if len(got) != 3 || got[0] != "direct/1.2.3.4:1" || got[1] != "direct/1.2.3.4:2" || got[2] != "relay/1.2.3.4:2" {
		t.Fatalf("变化沿通知序列不符：%v", got)
	}
}
