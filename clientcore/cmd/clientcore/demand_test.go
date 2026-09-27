//go:build cshared

package main

import (
	"errors"
	"testing"
	"time"
)

// demand-driven-recovery 的纯函数单测：需求合成、activity 新鲜度、证据门控三分支
// 与连败时间窗（2026-09-23 弹窗事故的三个事故面：无需求清零、本地噪声清零、跨挂起拼凑）。

func TestPatrolDemandTunPackets(t *testing.T) {
	// 出站包是最强信号：即使亮屏/前台位陈旧也算需求（App 后台发包形态）。
	setTunActivityForTest(false, false, time.Time{})
	active, why := patrolDemand(3, time.Now())
	if !active || why != "出站包" {
		t.Fatalf("出站包应判需求：active=%v why=%s", active, why)
	}
}

func TestPatrolDemandActivityFresh(t *testing.T) {
	now := time.Now()
	setTunActivityForTest(false, true, now.Add(-10*time.Second))
	if active, why := patrolDemand(0, now); !active || why != "亮屏" {
		t.Fatalf("新鲜亮屏位应判需求：active=%v why=%s", active, why)
	}
	// fg 不参与合成（2026-09-23 实测：熄屏不触发 onBackground，前台名义残留）：
	// fg=true + 熄屏 = 无需求。
	setTunActivityForTest(true, false, now.Add(-10*time.Second))
	if active, why := patrolDemand(0, now); active || why != "熄屏" {
		t.Fatalf("熄屏（名义前台）应判无需求：active=%v why=%s", active, why)
	}
}

func TestPatrolDemandActivityStale(t *testing.T) {
	// 挂起空窗后旧值自然过期（两侧一起冻结）：唤醒第一拍不算需求，等扩展推新值。
	now := time.Now()
	setTunActivityForTest(true, true, now.Add(-2*time.Hour))
	if active, why := patrolDemand(0, now); active || why != "熄屏（位陈旧）" {
		t.Fatalf("陈旧亮屏位不应判需求：active=%v why=%s", active, why)
	}
}

func TestPatrolDemandNoDemand(t *testing.T) {
	now := time.Now()
	setTunActivityForTest(false, false, now.Add(-5*time.Second))
	if active, why := patrolDemand(0, now); active || why != "熄屏" {
		t.Fatalf("熄屏无前台无出站应判无需求：active=%v why=%s", active, why)
	}
}

var errBoom = errors.New("boom")

func TestPatrolEvidenceGateNoise(t *testing.T) {
	// 本地发送错误（挂起禁发）：无论需求状态，清零不计。
	n, counted := patrolEvidenceGate(true, true, 2, time.Now(), time.Now(), errBoom)
	if n != 0 || counted {
		t.Fatalf("本地噪声应清零：n=%d counted=%v", n, counted)
	}
}

func TestPatrolEvidenceGateNoDemand(t *testing.T) {
	// 无需求拍：清零不计——两端的失败不得拼成连败（事故核心形态）。
	n, counted := patrolEvidenceGate(false, false, 2, time.Now(), time.Now(), errBoom)
	if n != 0 || counted {
		t.Fatalf("无需求应清零：n=%d counted=%v", n, counted)
	}
}

func TestPatrolEvidenceGateNormal(t *testing.T) {
	now := time.Now()
	n, counted := patrolEvidenceGate(false, true, 1, now.Add(-time.Minute), now, errBoom)
	if n != 2 || !counted {
		t.Fatalf("需求期失败应 +1：n=%d counted=%v", n, counted)
	}
}

func TestPatrolEvidenceGateWindow(t *testing.T) {
	// 连败时间窗：相邻计数失败间隔 >10 分钟 ⇒ 计数作废重来（事故：三小时攒三败）。
	now := time.Now()
	n, counted := patrolEvidenceGate(false, true, 2, now.Add(-3*time.Hour), now, errBoom)
	if n != 1 || !counted {
		t.Fatalf("跨窗失败应从 1 重数：n=%d counted=%v", n, counted)
	}
	// 窗内则正常累加。
	n, _ = patrolEvidenceGate(false, true, 2, now.Add(-2*time.Minute), now, errBoom)
	if n != 3 {
		t.Fatalf("窗内应累加到 3：n=%d", n)
	}
	// 首败（lastCountedFail 零值）不受窗影响。
	n, _ = patrolEvidenceGate(false, true, 0, time.Time{}, now, errBoom)
	if n != 1 {
		t.Fatalf("首败应为 1：n=%d", n)
	}
}

// setTunActivityForTest 测试直设（绕过 setTunActivity 的「now」）。
func setTunActivityForTest(fg, screen bool, pushedAt time.Time) {
	tunActivity.fg.Store(fg)
	tunActivity.screen.Store(screen)
	if pushedAt.IsZero() {
		tunActivity.pushedAt.Store(0)
	} else {
		tunActivity.pushedAt.Store(pushedAt.UnixNano())
	}
}

func TestPatrolEvidenceGateSuccessResets(t *testing.T) {
	// 评审 H3 的验收形态：F,S,F,F 必须停在 2——成功拍清零不许丢（否则 F,S,F,F 拼出
	// 3 连败 → markUnhealthy，正是本 change 要消灭的假故障升格）。
	now := time.Now()
	n, _ := patrolEvidenceGate(false, true, 0, time.Time{}, now, errBoom) // F → 1
	if n != 1 {
		t.Fatalf("首败应为 1：%d", n)
	}
	n, counted := patrolEvidenceGate(false, true, n, now.Add(time.Minute), now.Add(time.Minute), nil) // S → 0
	if n != 0 || counted {
		t.Fatalf("成功拍应清零：n=%d counted=%v", n, counted)
	}
	n, _ = patrolEvidenceGate(false, true, n, now.Add(2*time.Minute), now.Add(2*time.Minute), errBoom) // F → 1
	n, _ = patrolEvidenceGate(false, true, n, now.Add(3*time.Minute), now.Add(3*time.Minute), errBoom) // F → 2
	if n != 2 {
		t.Fatalf("F,S,F,F 应停在 2（不是 3 连败）：%d", n)
	}
}

// shouldPush 表驱动（评审 4 C 表收口：下推判据链的单测）。
func TestShouldPush(t *testing.T) {
	now := time.Now()
	freshOut := now.Add(-2 * time.Second)
	staleOut := now.Add(-30 * time.Second)
	freshRecv := now.Add(-10 * time.Second)
	staleRecv := now.Add(-3 * time.Minute)
	cases := []struct {
		name      string
		outAt     time.Time
		recvAt    time.Time
		localErr  bool
		sincePush time.Duration
		want      bool
	}{
		{"全条件满足（静默+出站在等+冷却过）", freshOut, staleRecv, false, pushCooldown + time.Second, true},
		{"从未收到对端包按静默", freshOut, time.Time{}, false, pushCooldown, true},
		{"无出站在等", staleOut, staleRecv, false, pushCooldown, false},
		{"从未有出站", time.Time{}, staleRecv, false, pushCooldown, false},
		{"链路最近有回包", freshOut, freshRecv, false, pushCooldown, false},
		{"采纳路径本地错误（挂起禁发）", freshOut, staleRecv, true, pushCooldown, false},
		{"冷却未过", freshOut, staleRecv, false, pushCooldown - time.Second, false},
	}
	for _, c := range cases {
		if got := shouldPush(c.outAt, c.recvAt, now, c.localErr, c.sincePush); got != c.want {
			t.Errorf("%s：shouldPush=%v，期望 %v", c.name, got, c.want)
		}
	}
}
