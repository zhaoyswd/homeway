//go:build !windows

// term_state.go — 状态机卫生（任务 4.7）：防抖 / 降载 / 定期重发，全部是**纯函数或纯状态**，
// 因此可以用夹具单测（喂上轮状态、可见位、时间，出「该不该发布/该不该扫屏」）。
//
// 三个机制（语义照 herdr 的 agent_detection.rs，常量取值也一致）：
//
//  1. **working→idle 确认窗**：agent 重绘瞬间某次扫描可能看到暂态空屏。working 直接掉到
//     「普通 idle」（既没有 visible_idle 也没有 visible_blocker 的强证据）时**先按住不发**：
//     第 1 拍开窗，之后每拍记一次确认，确认数达 pendingIdleConfirmations（或超
//     pendingIdleCap）才放行 —— 即**合计 1+N 拍**（口径与 herdr 一致；把开窗那拍也算确认
//     会让确认窗形同虚设）。
//     有强证据（visible_idle/visible_blocker）、agent 换了、进程退了 ⇒ 立即生效，不按。
//  2. **空闲会话零开销**：状态已是 idle、agent 已知、且 PTY 内容序号没变 ⇒ **跳过屏幕扫描**
//     （不提取文本、不求值规则）。内容序号每批输出自增，所以「真的没动」才短路。
//  3. **blocked 定期重发**：blocked 持续期间每 STABLE_VISIBLE_SIGNAL_REFRESH 重发一次状态，
//     保持消费方（App 列表/诊断）新鲜——状态没变就不发会让界面在重连后停在旧值。
package term

import "time"

const (
	// pendingIdleConfirmations 是 working→普通 idle 需要的连续确认拍数。
	pendingIdleConfirmations = 3
	// pendingIdleCap 是确认窗的封顶时长（超时即放行，避免卡在 working）。
	pendingIdleCap = 700 * time.Millisecond
	// stableVisibleRefresh 是 blocked 持续期间的定期重发间隔。
	stableVisibleRefresh = 800 * time.Millisecond
)

// stateHygiene 一台会话的状态机卫生状态（由会话锁保护）。
type stateHygiene struct {
	pendingIdleSince    time.Time
	pendingIdleConfirms int
	lastBlockedPublish  time.Time
}

// pendingIdle 报告当前是否处于「按住 working→idle」的确认窗内。
func (h *stateHygiene) pendingIdle(now time.Time) bool {
	return !h.pendingIdleSince.IsZero() && now.Sub(h.pendingIdleSince) < pendingIdleCap
}

func (h *stateHygiene) clearPending() {
	h.pendingIdleSince = time.Time{}
	h.pendingIdleConfirms = 0
}

// shouldHoldWorkingToIdle 判定是否要**按住**这次 working→普通 idle 的发布（返回 true = 先不发）。
//
// 纯函数式：只读入参与自身状态，时间由调用方给（夹具可注入）。
func (h *stateHygiene) shouldHoldWorkingToIdle(prev, next byte, visibleIdle, visibleBlocker bool,
	agentChanged, processExited bool, now time.Time) bool {
	plainIdle := prev == stateV2Working && next == stateV2Idle && !visibleIdle && !visibleBlocker &&
		!agentChanged && !processExited
	if !plainIdle {
		h.clearPending()
		return false
	}
	if h.pendingIdleSince.IsZero() {
		h.pendingIdleSince = now
		h.pendingIdleConfirms = 0
		return true
	}
	if now.Sub(h.pendingIdleSince) >= pendingIdleCap {
		h.clearPending()
		return false
	}
	h.pendingIdleConfirms++
	if h.pendingIdleConfirms >= pendingIdleConfirmations {
		h.clearPending()
		return false
	}
	return true
}

// shouldSkipScreenScan 判定是否跳过本拍的屏幕扫描（空闲会话零开销）。
//
// 只有在「已经是 idle + agent 已知 + 不在确认窗 + agent 没换 + 进程没退 + 内容序号与上次扫屏
// 相同」时才跳过——内容序号每次 PTY 输出自增，所以「真的没动」才短路。
func (h *stateHygiene) shouldSkipScreenScan(state byte, agentKnown, agentChanged, processExited bool,
	curSeq uint64, lastScanSeq uint64, now time.Time) bool {
	if state != stateV2Idle || !agentKnown || agentChanged || processExited {
		return false
	}
	if h.pendingIdle(now) {
		return false
	}
	return curSeq == lastScanSeq
}

// shouldRepublishBlocked 判定 blocked 持续期间是否该重发状态（保持消费方新鲜）。
func (h *stateHygiene) shouldRepublishBlocked(state byte, now time.Time) bool {
	if state != stateV2Blocked {
		return false
	}
	if h.lastBlockedPublish.IsZero() || now.Sub(h.lastBlockedPublish) >= stableVisibleRefresh {
		h.lastBlockedPublish = now
		return true
	}
	return false
}
