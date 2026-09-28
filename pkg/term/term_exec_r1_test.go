//go:build !windows && (darwin || linux) && (amd64 || arm64) && cgo

// term_exec_r1_test.go — exec-r1 评审整改的判据（环节 1 / 步骤 6）。
//
// 高1（surface 状态-only 帧）：真实 flushSurface 路径上「无脏行但腿基线有差异」必须发
// count=0 差分（2026-09-24 P0 的回归修复——只看脏行会让方向键/模式位变化一帧都不发）。
// 高2（raw 停滞恢复）：写超时后停滞≠停投——恢复读取能续投；连续停滞超限才断腿
// （写超时/停滞上限经 HOMEWAY_TERM_WRITE_TIMEOUT_MS / HOMEWAY_TERM_STALL_LIMIT_MS 注入，真达阈值）。
// 中4（测试错位）：两种失败模式走 flushSurface 端到端各命中一次计数器；防循环负例 =
// 被动腿收全量后（即便违约回发一帧 RESIZE）也不形成振荡。
// 低7（attach 双哨兵）：一次 attach 只注入一次尺寸哨兵（判据 = 会话级哨兵计数）。
package term

import (
	"net"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/term/vt"
)

// bulkTermShell：持续产输出的会话（停滞恢复的续投量判据要确定性体量）。
const bulkTermShell = "while :; do seq 1 200; sleep 0.05; done & cat"

// pipeSurfaceLeg：经 net.Pipe 接一条 surface 腿（无缓冲 ⇒ 无人读时写必阻塞），
// 返回客户端半边（读 ATTACHED 后停读即成「慢腿」）。
func pipeSurfaceLeg(t *testing.T, svc *termService, name string, cols, rows uint16) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	go svc.ServeConn(server)
	if f, err := readTermFrame(client); err != nil || f.op != opGreeting {
		t.Fatalf("GREETING：%v op=0x%02x", err, f.op)
	}
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	hello := append(encHello(cols, rows, true, name), encCapability(capsSurface)...)
	if _, err := client.Write(encodeTermFrame(opHello, hello)); err != nil {
		t.Fatal(err)
	}
	f, err := readTermFrame(client)
	if err != nil || f.op != opAttached {
		t.Fatalf("surface 腿应先收到 ATTACHED（首帧）：op=0x%02x err=%v", f.op, err)
	}
	return client
}

// surfaceLegOf：取会话里的（第一条）surface 腿（测试助手；持 svc.mu 短锁）。
func surfaceLegOf(t *testing.T, svc *termService, name string) (*termSession, *termClient) {
	t.Helper()
	svc.mu.Lock()
	ss := svc.sessions[name]
	svc.mu.Unlock()
	if ss == nil {
		t.Fatalf("会话 %s 不在注册表里", name)
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()
	for _, l := range ss.legs {
		if l.surface {
			return ss, l
		}
	}
	t.Fatalf("会话 %s 没有 surface 腿", name)
	return nil, nil
}

// ---- 高1：状态-only 帧（评审探针写法的半集成判据）----
//
// 建基线（首帧快照 + 文本差分）→ 只动光标（左方向键经 opInput → PTY → cat 回显 →
// vt 光标移动，无脏行）→ 客户端必须再收到一帧 SURFACE-DIFF（RowCount=0 的「空行 patch」
// 是合法更新）。修复前：无脏行 ⇒ case anyChange 不匹配 ⇒ 一帧都不发（P0 回归）。
func TestSurfaceStateOnlyFrameOnRealFlush(t *testing.T) {
	// 静默会话（无 ticker 输出 ⇒ 判据不会被无关脏行污染）。
	svc, ln := startTestTermServiceShell(t, "stty -icanon -echo; cat")
	defer svc.Close()
	defer ln.Close()
	c, snap := attachSurface(t, ln, "r1s1", 80, 24)
	defer c.Close()

	// 先落几列文本：基线建立 + 光标离开行首（左移才有观察量）。
	writeTermFrame(t, c, opInput, encInputEvent(inputEvent{Kind: inputKindText, Text: "hello"}))
	deadline := time.Now().Add(4 * time.Second)
	textSeen := false
	textCursorX := -1
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		f, err := readTermFrame(c)
		if err != nil {
			continue
		}
		if f.op != opSurfaceDiff {
			continue
		}
		body := surfaceReaderFrom(t, c, f)
		d, derr := decDiffBody(body)
		if derr != nil {
			t.Fatal(derr)
		}
		if d.RowCount > 0 {
			textSeen = true
			textCursorX = int(d.Cursor.X)
			break // 文本差分已到（带脏行），光标此刻在文本末尾（回显次数不定，位置相对判）
		}
	}
	if !textSeen {
		t.Fatal("前置失败：文本差分没到（判据的输入侧没建立）")
	}
	// 静置一拍：让文本相关的 flush 全部落定（避免方向键的回显混进同一脏行窗口）。
	time.Sleep(500 * time.Millisecond)

	// 只动光标：左方向键（无脏行；光标 X-1）⇒ 必须收到 count=0 的差分。负载下仍可能有
	// 文本残尾差分（RowCount>0）在飞——**跳过它们**（同时跟进光标位置），判据是
	// 「最终有一帧 RowCount=0 且光标恰比前一帧左移一列」。
	writeTermFrame(t, c, opInput, encInputEvent(inputEvent{
		Kind: inputKindKey, Key: uint16(vt.KeyArrowLeft), Action: byte(vt.KeyPress)}))
	deadline = time.Now().Add(5 * time.Second)
	lastX := textCursorX
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		f, err := readTermFrame(c)
		if err != nil {
			continue
		}
		if f.op != opSurfaceDiff {
			continue
		}
		body := surfaceReaderFrom(t, c, f)
		d, derr := decDiffBody(body)
		if derr != nil {
			t.Fatal(derr)
		}
		if d.RowCount > 0 {
			lastX = int(d.Cursor.X) // 文本残尾：跟进光标，继续等状态-only 帧
			continue
		}
		if int(d.Cursor.X) != lastX-1 {
			t.Fatalf("左方向键的空行集差分光标应恰左移一列：%d → %d", lastX, d.Cursor.X)
		}
		_ = snap
		return
	}
	t.Fatal("只动光标后没收到 count=0 的差分帧（状态-only 帧丢失 = exec-r1 高1 回归）")
}

// ---- 高2 ①：写超时后停滞≠停投——恢复读取能续投 ≥4KB ----
//
// 注入小写超时（HOMEWAY_TERM_WRITE_TIMEOUT_MS=300ms）让超时**真发生**（旧用例 2.5s <
// 10s 默认值，超时路径从未执行）；net.Pipe 无人读 ⇒ 写必超时 ⇒ 停滞。评审探针在修复前
// 的结果：恢复读取后三个 3s 窗口全 0（永久哑掉）。
func TestRawStallRecoversAfterWriteTimeout(t *testing.T) {
	t.Setenv("HOMEWAY_TERM_WRITE_TIMEOUT_MS", "300")
	svc, ln := startTestTermServiceShell(t, bulkTermShell)
	defer svc.Close()
	defer ln.Close()

	stuckClient, stuckServer := net.Pipe()
	defer stuckServer.Close()
	go svc.ServeConn(stuckServer)
	if f, err := readTermFrame(stuckClient); err != nil || f.op != opGreeting {
		t.Fatalf("GREETING：%v", err)
	}
	_ = stuckClient.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := stuckClient.Write(encodeTermFrame(opHello, encHello(80, 24, true, "r1s2"))); err != nil {
		t.Fatal(err)
	}
	if f, err := readTermFrame(stuckClient); err != nil || f.op != opAttached {
		t.Fatalf("停滞腿应先收到 ATTACHED（首帧）：op=0x%02x err=%v", f.op, err)
	}

	// 无人读 3s（>> 300ms 写超时 × 多个退避周期）⇒ 停滞位置起、腿仍在。
	time.Sleep(3 * time.Second)
	svc.mu.Lock()
	ss := svc.sessions["r1s2"]
	svc.mu.Unlock()
	ss.mu.Lock()
	var stalled *termClient
	for _, l := range ss.legs {
		if l.conn == stuckServer {
			stalled = l
		}
	}
	ss.mu.Unlock()
	if stalled == nil {
		t.Fatal("写超时后腿不该被踢（还在 legs 里才谈得上恢复）")
	}
	if !stalled.out.isStalled() {
		t.Fatal("写超时后停滞位应置起（超时路径必须真的执行到）")
	}

	// 恢复读取 ⇒ 续投恢复 ≥4KB（bulkTermShell 保证有确定性体量；修复前永久 0）。
	buf := make([]byte, 64<<10)
	total := 0
	deadline := time.Now().Add(5 * time.Second)
	for total < 4096 && time.Now().Before(deadline) {
		_ = stuckClient.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, rerr := stuckClient.Read(buf)
		total += n
		if rerr != nil {
			break
		}
	}
	if total < 4096 {
		t.Fatalf("恢复读取后续投不足：%dB（<4KB = exec-r1 高2 停滞永久哑掉）", total)
	}
	// 停滞位随成功续投清除。
	if stalled.out.isStalled() {
		t.Fatal("恢复续投后停滞位应清除")
	}
}

// ---- 高2 ②：连续停滞超 termRawStallLimit 才断腿（断腿 = 从 legs 消失，无 ENDED）----
//
// 注入 200ms 超时 + 1.2s 停滞上限；修复前 noteStall 只在写尝试里被求值而停滞分支
// 跳过环读取 ⇒ 60s 兜底永不可达；修复后每个退避周期都做写尝试 ⇒ 超限即断。
func TestRawStallOverLimitBreaksLeg(t *testing.T) {
	t.Setenv("HOMEWAY_TERM_WRITE_TIMEOUT_MS", "200")
	t.Setenv("HOMEWAY_TERM_STALL_LIMIT_MS", "1200")
	svc, ln := startTestTermServiceShell(t, bulkTermShell)
	defer svc.Close()
	defer ln.Close()

	stuckClient, stuckServer := net.Pipe()
	defer stuckServer.Close()
	go svc.ServeConn(stuckServer)
	if f, err := readTermFrame(stuckClient); err != nil || f.op != opGreeting {
		t.Fatalf("GREETING：%v", err)
	}
	_ = stuckClient.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := stuckClient.Write(encodeTermFrame(opHello, encHello(80, 24, true, "r1s3"))); err != nil {
		t.Fatal(err)
	}
	if f, err := readTermFrame(stuckClient); err != nil || f.op != opAttached {
		t.Fatalf("停滞腿应先收到 ATTACHED：op=0x%02x err=%v", f.op, err)
	}

	// 无人读 6s（> 1.2s 上限 × 多个退避周期）⇒ 腿应被断。
	time.Sleep(6 * time.Second)
	svc.mu.Lock()
	ss := svc.sessions["r1s3"]
	svc.mu.Unlock()
	ss.mu.Lock()
	gone := true
	for _, l := range ss.legs {
		if l.conn == stuckServer {
			gone = false
		}
	}
	ss.mu.Unlock()
	if !gone {
		t.Fatal("连续停滞超限后腿应被断（exec-r1 高2：停滞上限兜底不可达的回归）")
	}
}

// ---- 中4：两种失败模式走 flushSurface 端到端各命中一次计数器 ----
//
// queue_overflow（注入 HOMEWAY_TERM_QUEUE_BYTES=8192）：pipe 腿无人读 ⇒ 写者阻塞在
// 首帧写上 ⇒ 后续 flush 的帧持续入队积压到上限 ⇒ flushSurface 的 enqueueGroup 分支
// 拒绝并 markNeedSnapshot("queue_overflow")。
func TestQueueOverflowViaRealFlush(t *testing.T) {
	t.Setenv("HOMEWAY_TERM_QUEUE_BYTES", "8192")
	svc, ln := startTestTermServiceShell(t, bulkTermShell)
	defer svc.Close()
	defer ln.Close()

	stuck := pipeSurfaceLeg(t, svc, "r1s4", 80, 24)
	defer stuck.Close()
	_, leg := surfaceLegOf(t, svc, "r1s4")

	// bulkTermShell 持续产出 ⇒ flush 每 16–33ms 构帧入队；写者阻塞 ⇒ 积压超 8KiB。
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if st := leg.leg.statsSnapshot(); st.queueOverflow >= 1 {
			return // 检测路径命中（flushSurface 的真分支）
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("队列积压超限应经 flushSurface 命中 queueOverflow 计数器")
}

// backpressure（注入 HOMEWAY_TERM_PENDING_CAP_BYTES=2KiB）：大几何会话的快照体
// （未压缩）必然超单帧上限 ⇒ flushSurface 的既有分支 markNeedSnapshot("backpressure")。
func TestBackpressureViaRealFlush(t *testing.T) {
	t.Setenv("HOMEWAY_TERM_PENDING_CAP_BYTES", "2048")
	svc, ln := startTestTermServiceShell(t, bulkTermShell)
	defer svc.Close()
	defer ln.Close()

	stuck := pipeSurfaceLeg(t, svc, "r1s5", 400, 200) // 大网格 ⇒ 快照体 >> 2KiB
	defer stuck.Close()
	_, leg := surfaceLegOf(t, svc, "r1s5")

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st := leg.leg.statsSnapshot(); st.backpressure >= 1 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("单帧超 perLegPendingCap 应经 flushSurface 命中 backpressure 计数器")
}

// ---- 中4：防循环负例（被动几何不反向上报 / 违约回发也不振荡）----
//
// 正例：腿 B 的 resize 让腿 A 收到被动全量；契约客户端不发任何帧（harness 由本测试
// 驱动 ⇒ 断言落在服务端侧：被动全量不带任何「请上报尺寸」语义，会话尺寸稳定在 B 侧）。
// 负例（违约对照）：A 的 harness 故意回发一帧 RESIZE（模拟违约客户端）⇒ 服务端按 D4
// 活动语义处理（正确），但守约的 B 不再回发 ⇒ 收敛为有界一次反弹，不形成无限振荡。
func TestNoResizeLoopEvenWithEchoingClient(t *testing.T) {
	svc, ln := startTestTermServiceShell(t, "stty -icanon -echo; cat")
	defer svc.Close()
	defer ln.Close()
	cA, _ := attachSurface(t, ln, "r1s6", 80, 24) // A：80x24
	defer cA.Close()
	cB, _ := attachSurface(t, ln, "r1s6", 80, 24) // B：80x24
	defer cB.Close()

	// B 上报新尺寸（活动）⇒ A 收被动全量（新几何 100x30）。
	writeTermFrame(t, cB, opResize, encResize(100, 30))
	sA := waitSnapshot(t, cA, 4*time.Second)
	if sA.Geometry.Cols != 100 || sA.Geometry.Rows != 30 {
		t.Fatalf("被动腿应收到新几何全量：%dx%d", sA.Geometry.Cols, sA.Geometry.Rows)
	}

	// 负例：A 违约回发一帧 RESIZE（自己的尺寸 80x24）⇒ 服务端按活动处理。注意 B 的
	// 第一帧新快照是**它自己 resize** 的产物（applySize 标所有 surface 腿，100x30），
	// A 回发后的被动全量（80x24）在其后——循环等到收敛尺寸为止。
	writeTermFrame(t, cA, opResize, encResize(80, 24))
	snapDeadline := time.Now().Add(4 * time.Second)
	converged := false
	for time.Now().Before(snapDeadline) {
		sB := waitSnapshot(t, cB, 2*time.Second)
		if sB.Geometry.Cols == 80 && sB.Geometry.Rows == 24 {
			converged = true
			break
		}
	}
	if !converged {
		t.Fatal("违约回发一次后应收敛到回发者尺寸（80x24 的被动全量没到）")
	}
	svc.mu.Lock()
	ss := svc.sessions["r1s6"]
	svc.mu.Unlock()
	ss.mu.Lock()
	cols, rows := ss.cols, ss.rows
	ss.mu.Unlock()
	if cols != 80 || rows != 24 {
		t.Fatalf("会话尺寸应稳定（无振荡）：实际 %dx%d", cols, rows)
	}

	// 收敛判据：守约客户端（B）不再回发 ⇒ 稳定窗口内不再出现新的被动全量。
	deadline := time.Now().Add(1200 * time.Millisecond)
	for time.Now().Before(deadline) {
		_ = cB.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		f, err := readTermFrame(cB)
		if err != nil {
			continue
		}
		if f.op == opSnapshot {
			t.Fatal("守约客户端不回发 ⇒ 不该再出现被动全量（振荡未终止）")
		}
	}
}

// ---- 低7：一次 attach 只注入一次尺寸哨兵 ----
//
// 判据 = 会话级哨兵计数（sentinelCount）：A 同尺寸接入（无 resize）= 1 次哨兵；
// B 换尺寸接入 = 再 1 次（applySize 的 setsize 不计——修复前注册路径的
// noteActivityLocked 还会多注入一次哨兵，计数会是 3）。
func TestAttachInjectsSingleSentinel(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()

	cA, _, _, _ := attachTerm(t, ln, "r1s7", true, 80, 24) // 同 spawn 尺寸 ⇒ 无 resize
	defer cA.Close()
	if n := sentinelCountOf(t, svc, "r1s7"); n != 1 {
		t.Fatalf("A 接入后哨兵计数应恰为 1，实际 %d", n)
	}

	cB, _, _, _ := attachTerm(t, ln, "r1s7", false, 120, 40) // 换尺寸接入
	defer cB.Close()
	if n := sentinelCountOf(t, svc, "r1s7"); n != 2 {
		t.Fatalf("B 接入后哨兵计数应恰为 2（一次 attach 一次哨兵；修复前 = 3），实际 %d", n)
	}
}

func sentinelCountOf(t *testing.T, svc *termService, name string) int {
	t.Helper()
	svc.mu.Lock()
	ss := svc.sessions[name]
	svc.mu.Unlock()
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return int(ss.sentinelCount)
}
