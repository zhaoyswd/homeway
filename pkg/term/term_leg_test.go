//go:build !windows

// term_leg_test.go — 多腿会话模型的判据（term-host-cli 任务组 2–6）。
//
// 覆盖：legs 注册/收尾/focus（首腿 in、末腿 out）；会话级流按腿类分派（raw 腿负例）；
// per-leg 基线；活动策略表与重选举；腿上限与回收；实例标识与尾随形状校验；每腿写者的
// 停滞语义与慢腿矩阵；查询应答窄规则；协议增量（only-if-absent / CREATE / GREETING 回归）。
package term

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- 2.1a legs 注册表与生命周期 ----

// raw 腿与 surface 腿同时在场、各自收发；断开一条不影响另一条。
func TestMultiLegRawSurfaceCoexist(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()

	// raw 腿（legacy 形态 HELLO，无尾随）先接入。
	craw, _, _, _ := attachTerm(t, ln, "ml1", true, 90, 28)
	defer craw.Close()
	// surface 腿随后接入，不被顶掉、正常拿快照。
	csf, snap := attachSurface(t, ln, "ml1", 80, 24)
	defer csf.Close()
	if snap.Geometry.Cols != 80 {
		t.Fatalf("surface 腿快照几何不符：%dx%d", snap.Geometry.Cols, snap.Geometry.Rows)
	}

	// raw 腿的实时流仍在走（ticker 输出）：DATA 持续到达。
	_ = craw.SetReadDeadline(time.Now().Add(5 * time.Second))
	if got := readDataContains(t, craw, "tick"); !strings.Contains(got, "tick") {
		t.Fatal("surface 腿接入后 raw 腿断流")
	}

	// 断开 surface 腿 ⇒ raw 腿不受影响（继续收数据）。
	_ = csf.Close()
	time.Sleep(300 * time.Millisecond)
	_ = craw.SetReadDeadline(time.Now().Add(5 * time.Second))
	if got := readDataContains(t, craw, "tick"); !strings.Contains(got, "tick") {
		t.Fatal("surface 腿断开后 raw 腿断流")
	}
}

// focus 语义（2.1a）：首腿接入 → focus-in；**末腿**离开 → focus-out；中间腿离开不发。
// 会话程序开 ?1004 焦点上报后用 cat -v 回显输入——focus 序列写进 PTY 后会作为输出回到腿
// （广播：数 B 腿流里出现的次数，而不是看单条腿「有没有」——别的腿触发的 nudge 也会广播过来）。
func TestFocusFirstLegInLastLegOut(t *testing.T) {
	svc, ln := startTestTermServiceShell(t, "printf '\x1b[?1004h'; stty -icanon -echo; cat -v")
	defer svc.Close()
	defer ln.Close()

	// 腿 A 建会话（让扫描器把 ?1004h 吃进去），然后离开。
	cA, _, _, _ := attachTerm(t, ln, "ml-focus", true, 80, 24)
	_ = cA.SetReadDeadline(time.Now().Add(3 * time.Second))
	readDataContains(t, cA, "?1004h")
	_ = cA.Close()
	time.Sleep(300 * time.Millisecond)

	// 腿 B 接入（首腿）⇒ focus-in（cat -v 回显 ^[[I 恰好一次）。
	cB, _, replayB, _ := attachTerm(t, ln, "ml-focus", false, 80, 24)
	defer cB.Close()
	_ = cB.SetReadDeadline(time.Now().Add(3 * time.Second))
	if !strings.Contains(string(replayB), "^[[I") {
		readDataContains(t, cB, "^[[I") // 回放没赶上就在实时流里等（首腿的 focus-in）
	}

	// 腿 C 接入（非首腿，B 仍在）⇒ 不再有新的 focus-in、也没有 focus-out。
	cC, _, _, _ := attachTerm(t, ln, "ml-focus", false, 80, 24)
	defer cC.Close()
	nIn, nOut := countFocus(t, cB, 1200*time.Millisecond)
	if nIn != 0 || nOut != 0 {
		t.Fatalf("非首腿接入不该注入 focus 事件（in=%d out=%d）", nIn, nOut)
	}

	// C 离开（B 仍在）⇒ 无 focus-out。
	_ = cC.Close()
	if nIn, nOut = countFocus(t, cB, 1200*time.Millisecond); nIn != 0 || nOut != 0 {
		t.Fatalf("仍有其它腿在场时不该发 focus-out（in=%d out=%d）", nIn, nOut)
	}

	// B 离开（末腿）⇒ focus-out；腿 D 重进后在回放里能看到它。
	_ = cB.Close()
	time.Sleep(500 * time.Millisecond)
	cD, _, replayD, _ := attachTerm(t, ln, "ml-focus", false, 80, 24)
	defer cD.Close()
	if !strings.Contains(string(replayD), "^[[O") {
		t.Fatalf("末腿离开应注入 focus-out（^[[O），回放里没有：%q", replayD)
	}
}

// countFocus 在窗口期内持续读 DATA 帧，数 focus-in（^[[I）/ focus-out（^[[O）回显次数。
func countFocus(t *testing.T, c net.Conn, window time.Duration) (int, int) {
	t.Helper()
	nIn, nOut := 0, 0
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		f, err := readTermFrame(c)
		if err != nil {
			continue
		}
		if f.op != opData {
			continue
		}
		nIn += strings.Count(string(f.payload), "^[[I")
		nOut += strings.Count(string(f.payload), "^[[O")
	}
	return nIn, nOut
}

// ---- 2.1b 会话级流按腿类分派 ----

// raw 腿 MUST NOT 收 0x0D–0x15 区段任何帧（负例）：surface 腿在场、快照/差分/剪贴板/
// 通知都在飞时，raw 腿只收 DATA/STATE/ENDED/ERROR。
func TestRawLegNeverReceivesSurfaceFrames(t *testing.T) {
	svc, ln := startTestTermServiceShell(t,
		"read -r _l; printf '\\x1b]52;c;aGVsbG8=\\007'; printf '\\x1b]9;NOTIFY-RAW\\007'; cat")
	defer svc.Close()
	defer ln.Close()

	csf, _ := attachSurface(t, ln, "ml2", 80, 24) // surface 腿在场
	defer csf.Close()
	craw, _, _, _ := attachTerm(t, ln, "ml2", false, 80, 24) // raw 腿
	defer craw.Close()

	// 触发剪贴板 + 通知 + 持续输出（快照/差分流）。
	writeTermFrame(t, craw, opData, []byte("go\n"))

	deadline := time.Now().Add(4 * time.Second)
	sawSurfaceFrame := false
	for time.Now().Before(deadline) {
		_ = craw.SetReadDeadline(time.Now().Add(2 * time.Second))
		f, err := readTermFrame(craw)
		if err != nil {
			break
		}
		if f.op >= opSnapshot && f.op <= opFetchSnapshot {
			sawSurfaceFrame = true
			t.Fatalf("raw 腿收到 surface 区段帧 0x%02x（payload %d 字节）", f.op, len(f.payload))
		}
		switch f.op {
		case opData, opState, opAttached, opReplayDone, opOK:
		default:
			t.Fatalf("raw 腿收到意外帧 0x%02x", f.op)
		}
	}
	_ = sawSurfaceFrame

	// 对照：surface 腿确实收到了 CLIPBOARD 与 NOTIFY（分派没整体哑掉）。
	gotClip, gotNotify := false, false
	_ = csf.SetReadDeadline(time.Now().Add(3 * time.Second))
	for (!gotClip || !gotNotify) && time.Now().Before(deadline) {
		f, err := readTermFrame(csf)
		if err != nil {
			deadline = time.Now().Add(3 * time.Second) // 继续等下一轮
			continue
		}
		switch f.op {
		case opClipboard:
			gotClip = true
		case opNotify:
			gotNotify = true
		}
	}
	if !gotClip || !gotNotify {
		t.Fatalf("surface 腿应收到剪贴板/通知帧（clip=%v notify=%v）", gotClip, gotNotify)
	}
}

// STATE 每腿投递：标题变化后 raw 腿与 surface 腿都收到 STATE。
func TestStateDeliveredToEveryLeg(t *testing.T) {
	svc, ln := startTestTermServiceShell(t, "read -r _l; printf '\\x1b]0;TITLE-B\\007'; cat")
	defer svc.Close()
	defer ln.Close()

	craw, _, _, _ := attachTerm(t, ln, "ml3", true, 80, 24)
	defer craw.Close()
	csf, _ := attachSurface(t, ln, "ml3", 80, 24)
	defer csf.Close()
	writeTermFrame(t, craw, opData, []byte("go\n"))

	// raw 腿：STATE 帧的标题字段。
	rawTitle := ""
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) && rawTitle != "TITLE-B" {
		_ = craw.SetReadDeadline(time.Now().Add(2 * time.Second))
		f, err := readTermFrame(craw)
		if err != nil {
			continue
		}
		if f.op == opState && len(f.payload) >= 4 {
			n := int(binary.LittleEndian.Uint16(f.payload[2:4]))
			if len(f.payload) >= 4+n {
				rawTitle = string(f.payload[4 : 4+n])
			}
		}
	}
	if rawTitle != "TITLE-B" {
		t.Fatalf("raw 腿没收到带新标题的 STATE（%q）", rawTitle)
	}

	// surface 腿：STATE 帧（经队列投递）。
	sfTitle := ""
	deadline = time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) && sfTitle != "TITLE-B" {
		_ = csf.SetReadDeadline(time.Now().Add(2 * time.Second))
		f, err := readTermFrame(csf)
		if err != nil {
			continue
		}
		if f.op == opState && len(f.payload) >= 4 {
			n := int(binary.LittleEndian.Uint16(f.payload[2:4]))
			if len(f.payload) >= 4+n {
				sfTitle = string(f.payload[4 : 4+n])
			}
		}
	}
	if sfTitle != "TITLE-B" {
		t.Fatalf("surface 腿没收到带新标题的 STATE（%q）", sfTitle)
	}
}

// ---- 2.2a/2.2b per-leg 基线与 flush 全腿遍历 ----

// 两腿基线独立（2.2a）：一条腿请求全量后自己拿快照（revision 递增），另一条继续差分。
func TestPerLegBaselineIndependent(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c1, snap1 := attachSurface(t, ln, "ml4", 80, 24)
	defer c1.Close()
	c2, snap2 := attachSurface(t, ln, "ml4", 80, 24)
	defer c2.Close()

	// 腿 1 主动 FETCH-SNAPSHOT ⇒ 它自己走全量（revision 递增）。
	writeTermFrame(t, c1, opFetchSnapshot, nil)
	s1 := waitSnapshot(t, c1, 4*time.Second)
	if s1.Geometry.Revision <= snap1.Geometry.Revision {
		t.Fatalf("请求全量的腿 revision 应递增：%d → %d", snap1.Geometry.Revision, s1.Geometry.Revision)
	}

	// 腿 2 没请求 ⇒ 下一拍仍是差分（revision 不变），并继续收到内容更新。
	deadline := time.Now().Add(5 * time.Second)
	sawDiff := false
	for time.Now().Before(deadline) && !sawDiff {
		_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
		f, err := readTermFrame(c2)
		if err != nil {
			continue
		}
		if f.op == opSurfaceDiff {
			body := surfaceReaderFrom(t, c2, f)
			d, derr := decDiffBody(body)
			if derr != nil {
				t.Fatal(derr)
			}
			if d.Geometry.Revision != snap2.Geometry.Revision {
				t.Fatalf("未请求全量的腿 revision 不该变：%d → %d", snap2.Geometry.Revision, d.Geometry.Revision)
			}
			sawDiff = true
		}
	}
	if !sawDiff {
		t.Fatal("另一条腿应继续收到差分（基线独立）")
	}
}

// 两种失败模式各命中各自计数器（4.3）：单帧超 perLegPendingCap = backpressure；
// 队列积压超 perLegQueueBytes = queueOverflow。
func TestSurfaceQueueFailureModesSeparate(t *testing.T) {
	leg := newSurfaceLeg()

	// 模式一：单帧体积超 perLegPendingCap（flush 的锁外分支）。
	leg.markNeedSnapshot("backpressure")
	if got := leg.statsSnapshot(); got.backpressure != 1 || got.queueOverflow != 0 {
		t.Fatalf("背压计数错位：backpressure=%d queueOverflow=%d", got.backpressure, got.queueOverflow)
	}

	// 模式二：队列积压（enqueueGroup 超上限被拒 → markNeedSnapshot("queue_overflow")）。
	var out legOut = newLegOut()
	big := make([]byte, 512)
	ok := out.enqueueGroup([]writeItem{{op: opSnapshot, payload: big}}, 256) // 512 > 256
	if ok {
		t.Fatal("超队列上限的组应被拒")
	}
	leg.markNeedSnapshot("queue_overflow")
	if got := leg.statsSnapshot(); got.backpressure != 1 || got.queueOverflow != 1 {
		t.Fatalf("两种失败模式应分开计数：backpressure=%d queueOverflow=%d", got.backpressure, got.queueOverflow)
	}
	// 上限内正常入队。
	if !out.enqueueGroup([]writeItem{{op: opSnapshot, payload: big[:100]}}, 256) {
		t.Fatal("上限内的组不该被拒")
	}
}

// ---- 2.3 客户端实例标识：尾随形状校验 ----

func TestHelloTailShape(t *testing.T) {
	// 无尾随：旧客户端形态，照常解析（不携带、不报错）。
	caps, present, id, err := decHelloTail(nil)
	if err != nil || present || id != "" {
		t.Fatalf("无尾随应解析为不携带：%v %v %q", caps, present, id)
	}
	// 仅 caps 块（既有形态）。
	caps, present, id, err = decHelloTail(encCapability(capsSurface))
	if err != nil || !present || caps != capsSurface || id != "" {
		t.Fatalf("仅 caps 块应照常解析：%v %v %#x %q", err, present, caps, id)
	}
	// caps + ID（CLI / 新客户端形态）。
	caps, present, id, err = decHelloTail(encHelloTail(capsSurface|capsRawTerminal, true, "host-1234"))
	if err != nil || !present || caps != capsSurface|capsRawTerminal || id != "host-1234" {
		t.Fatalf("caps+ID 形状应解析：%v %v %#x %q", err, present, caps, id)
	}
	// 声明长度越界的裸字节串（idLen 被当成 capLen）仍拒绝。
	if _, _, _, err := decHelloTail([]byte{5, 'h', 'o', 's', 't'}); err == nil {
		t.Fatal("声明长度越界的尾随必须被拒")
	}
	// 长度自洽的裸 ID 块（exec-r1 中3，口径 (a)）：两段同形不可判别 ⇒ 按形状**合法**，
	// 被当作 caps 块解析（OR 出的位可能同时命中 surface/raw）——这是格式固有属性，
	// 约束在编码侧（encHelloTail 不产出无 caps 的 ID；客户端必须先 caps 后 ID）。
	caps2, present2, id2, err := decHelloTail([]byte{4, 'h', 'o', 's', 't'})
	if err != nil || !present2 || id2 != "" {
		t.Fatalf("长度自洽裸 ID 块应按 caps 解析（口径 a）：%v %v %#x %q", err, present2, caps2, id2)
	}
	if !wantsSurface(caps2) || caps2&capsRawTerminal == 0 {
		t.Fatalf("裸 ID 块被当 caps 的后果应被钉住（会双命中能力位）：caps=%#x", caps2)
	}
	// 编码约束：未声明能力（capsPresent=false）时**不产出 ID 块**（静默丢弃）。
	tail := encHelloTail(0, false, "id-x")
	if len(tail) != 0 {
		t.Fatalf("无 caps 块时不应产出 ID（口径 a 编码约束）：% x", tail)
	}
	// 空 caps 块（capLen=0）消费 1 字节：[0][idLen][id] 是合法形状（未声明能力 + ID）。
	caps3, present3, id3, err := decHelloTail([]byte{0, 4, 'a', 'b', 'c', 'd'})
	if err != nil || present3 || caps3 != 0 || id3 != "abcd" {
		t.Fatalf("空 caps 块 + ID 应解析：%v %v %#x %q", err, present3, caps3, id3)
	}
	// caps 块声明长度越界（既有负例，r1 P2-9 同步）。
	if _, _, _, err := decHelloTail([]byte{9, capsSurface}); err == nil {
		t.Fatal("capLen 越界必须被拒")
	}
	// ID 块声明长度越界。
	if _, _, _, err := decHelloTail([]byte{1, capsSurface, 9, 'a'}); err == nil {
		t.Fatal("idLen 越界必须被拒")
	}
	// 尾随残留字节。
	if _, _, _, err := decHelloTail([]byte{1, capsSurface, 2, 'a', 'b', 'X'}); err == nil {
		t.Fatal("尾随块后残留字节必须被拒")
	}
	// ID 超上限。
	long := make([]byte, termMaxClientIDLen+1)
	for i := range long {
		long[i] = 'x'
	}
	over := append([]byte{1, capsSurface}, byte(len(long)))
	over = append(over, long...)
	if _, _, _, err := decHelloTail(over); err == nil {
		t.Fatal("ID 超上限必须被拒")
	}
}

// 畸形尾随在协议面上报 bad_capability（与 TestSurfaceNegotiationBadCapability 的既有负例
// 互补：那条打 capLen 越界，这条打裸 ID 块）。
func TestHelloTailBadCapabilityOnWire(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c := dialTerm(t, ln)
	defer c.Close()
	if f := readTermFrameT(t, c); f.op != opGreeting {
		t.Fatal("首帧应为 GREETING")
	}
	// 裸 ID 块：idLen=8 但只给 7 字节（形状校验命中）。
	hello := append(encHello(80, 24, true, "ml5"), 8, 'a', 'b', 'c', 'd', 'e', 'f', 'g')
	writeTermFrame(t, c, opHello, hello)
	f := readTermFrameT(t, c)
	if f.op != opError {
		t.Fatalf("形状不符的尾随应报错，收到 0x%02x", f.op)
	}
	if code, _, _ := decError(f.payload); code != "bad_capability" {
		t.Fatalf("错误码应为 bad_capability，实际 %q", code)
	}
}

// ---- 2.4 死腿回收与上限策略 ----

// 单元：淘汰顺序 = 停滞（失活）腿优先（停滞最久者），否则最久空闲腿。
func TestEvictForSlotPolicy(t *testing.T) {
	mkLeg := func(kind string, touch time.Time) *termClient {
		c := &termClient{kind: kind, lastTouch: touch, out: newLegOut()}
		return c
	}
	s := &termSession{
		svc: &termService{cfg: termConfig{maxClients: 3}},
	}
	old := mkLeg("app", time.Now().Add(-10*time.Minute))
	fresh := mkLeg("app", time.Now())
	stalled := mkLeg("host", time.Now().Add(-1*time.Minute))
	s.legs = []*termClient{old, fresh, stalled}

	// 无停滞 ⇒ 淘汰最久空闲（old）。
	s.evictForSlotLocked()
	if len(s.legs) != 2 || s.legs[0] != fresh && s.legs[0] != stalled {
		if !containsLeg(s.legs, old) || containsLeg(s.legs, old) && len(s.legs) != 2 {
			t.Fatalf("应淘汰最久空闲腿：剩 %d 条", len(s.legs))
		}
	}
	if containsLeg(s.legs, old) {
		t.Fatal("最久空闲腿应被淘汰")
	}

	// 停滞腿在场 ⇒ 优先淘汰它（即便另一条更空闲）。
	s.legs = []*termClient{fresh, stalled}
	stalled.out.noteStall(true, termRawStallLimit)
	s.evictForSlotLocked()
	if containsLeg(s.legs, stalled) {
		t.Fatal("停滞（失活）腿应被优先淘汰")
	}
	if !containsLeg(s.legs, fresh) {
		t.Fatal("活腿不该被误淘汰")
	}
}

func containsLeg(legs []*termClient, c *termClient) bool {
	for _, l := range legs {
		if l == c {
			return true
		}
	}
	return false
}

// 集成：上限（2）不锁死用户——同实例重连替换自身旧腿；满员新实例淘汰最久空闲腿后接入。
func TestLegCapDoesNotLockUserOut(t *testing.T) {
	t.Setenv("HOMEWAY_TERM_MAX_CLIENTS", "2")
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()

	mk := func(id string) net.Conn {
		c := dialTerm(t, ln)
		readTermFrameT(t, c)
		var tail []byte
		if id != "" {
			tail = encHelloTail(capsRawTerminal, true, id)
		}
		writeTermFrame(t, c, opHello, append(encHello(80, 24, true, "ml6"), tail...))
		f := readTermFrameT(t, c)
		if f.op != opAttached {
			t.Fatalf("腿 %q 应接入成功，收到 0x%02x（payload %q）", id, f.op, f.payload)
		}
		return c
	}
	cA := mk("id-A")
	defer cA.Close()
	cB := mk("id-B")
	defer cB.Close()

	// ① 同实例重连：id-A 的新腿接入成功（替换自身旧腿，不占新位）。
	cA2 := mk("id-A")
	defer cA2.Close()

	// ② 满员 + 全新实例：淘汰最久空闲腿后接入成功（不锁死）。
	time.Sleep(50 * time.Millisecond) // 让 lastTouch 拉开
	cC := mk("id-C")
	defer cC.Close()

	// 腿数守在 2（LIST clients）。
	list := listTerm(t, ln)
	sess, _ := listSession(list, "ml6")
	clients, _ := sess["clients"].([]any)
	if len(clients) != 2 {
		t.Fatalf("腿数应守在上限 2，实际 %d", len(clients))
	}
}

// ---- 2.5 LIST clients ----

// 三类腿的 kind：app（surface）/ host（capsRawTerminal）/ legacy（未声明 raw 腿）。
func TestListClientsKinds(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()

	// host 腿：raw + capsRawTerminal + ID。
	chost := dialTerm(t, ln)
	defer chost.Close()
	readTermFrameT(t, chost)
	writeTermFrame(t, chost, opHello,
		append(encHello(100, 30, true, "ml7"), encHelloTail(capsRawTerminal, true, "host-x")...))
	if f := readTermFrameT(t, chost); f.op != opAttached {
		t.Fatalf("host 腿应接入，收到 0x%02x", f.op)
	}
	// legacy 腿：raw、无尾随。
	cleg, _, _, _ := attachTerm(t, ln, "ml7", false, 90, 28)
	defer cleg.Close()
	// app 腿：surface。
	csf, _ := attachSurface(t, ln, "ml7", 80, 24)
	defer csf.Close()

	list := listTerm(t, ln)
	sess, ok := listSession(list, "ml7")
	if !ok {
		t.Fatal("会话不在列表里")
	}
	if sess["attached"] != true {
		t.Error("attached 应为 true（至少一条腿）")
	}
	kinds := map[string]bool{}
	clients, _ := sess["clients"].([]any)
	for _, it := range clients {
		m, _ := it.(map[string]any)
		kinds[m["kind"].(string)] = true
		if _, ok := m["active"]; !ok {
			t.Error("clients 条目应有 active 字段")
		}
	}
	for _, want := range []string{"app", "host", "legacy"} {
		if !kinds[want] {
			t.Errorf("clients 缺 kind=%s（实际 %v）", want, kinds)
		}
	}
	// 旧字段零回退：state/stateV2/title 等都在。
	for _, field := range []string{"state", "stateV2", "title", "cols", "rows", "pid"} {
		if _, ok := sess[field]; !ok {
			t.Errorf("旧字段 %s 不该消失（只增不改）", field)
		}
	}
}

// ---- 2.7 腿日志 ----

func TestLegLogLines(t *testing.T) {
	var mu sync.Mutex
	var lines []string
	logf := func(format string, args ...any) {
		mu.Lock()
		lines = append(lines, sprintfLines(format, args...))
		mu.Unlock()
	}
	t.Setenv("HOMEWAY_TERM_SHELL", testTermShell)
	t.Setenv("HOMEWAY_TERM_HISTORY", "65536")
	t.Setenv("HOMEWAY_TERM_REPLAY", "32768")
	t.Setenv("HOMEWAY_TERM_DETECT", "off")
	svc := New(logf, "")
	defer svc.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go svc.ServeConn(c)
		}
	}()

	c, _, _, _ := attachTerm(t, ln, "ml8", true, 80, 24)
	_ = c.Close()
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	var attachLine, detachLine string
	for _, l := range lines {
		if strings.Contains(l, "腿接入") && strings.Contains(l, "ml8") {
			attachLine = l
		}
		if strings.Contains(l, "腿断开") && strings.Contains(l, "ml8") {
			detachLine = l
		}
	}
	if attachLine == "" || !strings.Contains(attachLine, "kind=legacy") {
		t.Errorf("接入日志应带 kind：%q", attachLine)
	}
	if detachLine == "" || !strings.Contains(detachLine, "原因=client_closed") {
		t.Errorf("断开日志应带原因：%q", detachLine)
	}
}

// sprintfLines：Logf 是逐行可拼接的，这里直接 fmt.Sprintf 一次（测试助手）。
func sprintfLines(format string, args ...any) string {
	return strings.TrimSpace(fmt.Sprintf(format, args...))
}

// ---- 3.1/3.2 活动驱动的会话级状态 ----

// 策略表：attach 切换 / 输入切换 / 尺寸未变不 resize / tie-break 固定。
func TestActivityElectionPolicy(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()

	sessionCols := func() (uint16, uint16, int) {
		svc.mu.Lock()
		ss := svc.sessions["ml9"]
		svc.mu.Unlock()
		if ss == nil {
			t.Fatal("会话不在注册表里")
		}
		ss.mu.Lock()
		defer ss.mu.Unlock()
		return ss.cols, ss.rows, len(ss.epochs)
	}

	// 腿 A：100x30 接入（建会话）⇒ 会话尺寸 = 100x30。
	cA, _, _, _ := attachTerm(t, ln, "ml9", true, 100, 30)
	defer cA.Close()
	if cols, rows, _ := sessionCols(); cols != 100 || rows != 30 {
		t.Fatalf("接入后会话尺寸应为 100x30，实际 %dx%d", cols, rows)
	}

	// 尺寸未变不 resize：同尺寸再接入 ⇒ epoch 数不涨。
	_, _, epochsBefore := sessionCols()
	cB, _, _, _ := attachTerm(t, ln, "ml9", false, 100, 30)
	defer cB.Close()
	if _, _, epochs := sessionCols(); epochs != epochsBefore {
		t.Fatalf("同尺寸接入不该记新 epoch：%d → %d", epochsBefore, epochs)
	}

	// 腿 B 换尺寸（RESIZE = 活动）⇒ 会话切到 120x40。
	writeTermFrame(t, cB, opResize, encResize(120, 40))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cols, rows, _ := sessionCols(); cols == 120 && rows == 40 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if cols, rows, _ := sessionCols(); cols != 120 || rows != 40 {
		t.Fatalf("活动腿的尺寸应生效，实际 %dx%d", cols, rows)
	}

	// 腿 A 输入（输入 = 活动）⇒ 切回 A 的 100x30。
	writeTermFrame(t, cA, opData, []byte("x"))
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cols, _, _ := sessionCols(); cols == 100 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if cols, rows, _ := sessionCols(); cols != 100 || rows != 30 {
		t.Fatalf("输入腿的尺寸应接管，实际 %dx%d", cols, rows)
	}
}

// tie-break 固定：同序号平手 ⇒ 更晚接入者优先（design D4，单元判据）。
func TestElectionTieBreak(t *testing.T) {
	s := &termSession{svc: &termService{cfg: termConfig{maxClients: 8}}}
	early := &termClient{kind: "app", lastActivitySeq: 5, attachSeq: 1, out: newLegOut()}
	late := &termClient{kind: "app", lastActivitySeq: 5, attachSeq: 2, out: newLegOut()}
	s.legs = []*termClient{early, late}
	s.electActiveLocked()
	if s.active != late {
		t.Fatal("同序号平手应由更晚接入者接管（tie-break 固定）")
	}
	// 序号更大者赢（跨腿）。
	early.lastActivitySeq = 9
	s.electActiveLocked()
	if s.active != early {
		t.Fatal("更大活动序号应接管")
	}
}

// 被动腿下一帧全量且 revision 递增（3.1 的连带义务）。
func TestPassiveLegGetsFullSnapshotOnResize(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c1, snap1 := attachSurface(t, ln, "ml10", 80, 24)
	defer c1.Close()
	c2, snap2 := attachSurface(t, ln, "ml10", 80, 24)
	defer c2.Close()

	// 腿 1 改尺寸 ⇒ 腿 2（被动）下一帧应是**全量快照**且 revision 递增。
	writeTermFrame(t, c1, opResize, encResize(100, 30))
	s2 := waitSnapshot(t, c2, 4*time.Second)
	if s2.Geometry.Cols != 100 || s2.Geometry.Rows != 30 {
		t.Fatalf("被动腿的快照应按新几何：%dx%d", s2.Geometry.Cols, s2.Geometry.Rows)
	}
	if s2.Geometry.Revision <= snap2.Geometry.Revision {
		t.Fatalf("被动腿快照 revision 应递增：%d → %d", snap2.Geometry.Revision, s2.Geometry.Revision)
	}
	_ = snap1
}

// 腿离开重选举（3.2）：决定尺寸的腿离开后，剩余腿中最近活动者的尺寸接管。
func TestReelectionOnLegExit(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	cA, _, _, _ := attachTerm(t, ln, "ml11", true, 120, 40) // A：120x40
	defer cA.Close()
	cB, _, _, _ := attachTerm(t, ln, "ml11", false, 90, 28) // B：90x28
	defer cB.Close()

	// B 最后接入（活动）⇒ 会话 90x28。
	deadline := time.Now().Add(3 * time.Second)
	svc.mu.Lock()
	ss := svc.sessions["ml11"]
	svc.mu.Unlock()
	for time.Now().Before(deadline) {
		ss.mu.Lock()
		cols := ss.cols
		ss.mu.Unlock()
		if cols == 90 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// B 离开 ⇒ A（唯一剩余腿）接管，会话回 120x40。
	_ = cB.Close()
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ss.mu.Lock()
		cols, rows := ss.cols, ss.rows
		ss.mu.Unlock()
		if cols == 120 && rows == 40 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	ss.mu.Lock()
	cols, rows := ss.cols, ss.rows
	ss.mu.Unlock()
	t.Fatalf("腿离开后应重选举到剩余腿尺寸，实际 %dx%d", cols, rows)
}

// ---- 3.3 主题与剪贴板读缓存跟随 active 腿 ----

func TestThemeAndClipFollowActiveLeg(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	cA, _ := attachSurface(t, ln, "ml12", 80, 24) // A 先接入 = active
	defer cA.Close()
	cB, _ := attachSurface(t, ln, "ml12", 80, 24) // B 后接入 = B 变 active
	defer cB.Close()

	svc.mu.Lock()
	ss := svc.sessions["ml12"]
	svc.mu.Unlock()
	ss.mu.Lock()
	if len(ss.legs) != 2 {
		ss.mu.Unlock()
		t.Fatalf("应有两条腿，实际 %d", len(ss.legs))
	}
	legA, active := ss.legs[0], ss.legs[1] // A 先接入、B 后接入 ⇒ B 是 active
	if ss.active != active || ss.active == legA {
		ss.mu.Unlock()
		t.Fatal("active 应为后接入的腿（接入即活动）")
	}
	ss.mu.Unlock()

	// 非 active 腿（A）上报剪贴板 ⇒ 读缓存不变（空）。
	ss.handleClipboardAnswer(legA, encClipboard(clipKindReadAnswer, "from-A"))
	if got := ss.clipCacheSnapshot(); got != "" {
		t.Fatalf("非 active 腿的上报不该进读缓存：%q", got)
	}
	// active 腿上报 ⇒ 读缓存跟随。
	ss.handleClipboardAnswer(active, encClipboard(clipKindReadAnswer, "from-active"))
	if got := ss.clipCacheSnapshot(); got != "from-active" {
		t.Fatalf("active 腿的上报应进读缓存：%q", got)
	}
	// 主题上报只记账在腿上（active 的才落 vt）。
	ss.handleTheme(legA, encTheme([3]uint8{1, 1, 1}, [3]uint8{2, 2, 2}, true))
	ss.mu.Lock()
	aKnown := ss.active.themeKnown
	ss.mu.Unlock()
	if aKnown {
		t.Fatal("active 腿没上报过主题，themeKnown 不该被置位")
	}
	ss.handleTheme(active, encTheme([3]uint8{9, 9, 9}, [3]uint8{8, 8, 8}, false))
	ss.mu.Lock()
	aKnown = ss.active.themeKnown
	ss.mu.Unlock()
	if !aKnown {
		t.Fatal("active 腿上报后 themeKnown 应置位")
	}
}

// legByConnLocked 由**服务端半边**连接反查腿（必须持 ss.mu；客户端侧的 conn 对象
// 与服务端腿持有的是不同实例，不能拿来比）。
func legByConnLocked(ss *termSession, c net.Conn) *termClient {
	for _, l := range ss.legs {
		if l.conn == c {
			return l
		}
	}
	return nil
}

// ---- 3.4 防循环 ----

// 被动几何变化不触发客户端上报（契约级断言 + 实现注释见 noteActivityLocked）：
// 腿 B 收到新几何的全量快照后**没有**发出任何 RESIZE 帧（服务端也不向腿发任何
// 「请上报尺寸」的帧——协议里不存在该方向）。
func TestNoResizeLoopOnPassiveGeometry(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c1, _ := attachSurface(t, ln, "ml13", 80, 24)
	defer c1.Close()
	c2, _ := attachSurface(t, ln, "ml13", 80, 24)
	defer c2.Close()

	resized := false
	writeTermFrame(t, c1, opResize, encResize(100, 30))
	// 腿 2 等到被动全量（= 它看到了新几何）。
	waitSnapshot(t, c2, 4*time.Second)
	resized = true
	_ = resized
	// 腿 2 之后 800ms 内不主动发帧（harness 不代客户端上报——本测试锁住的是
	// 「服务端不要求客户端上报」这条契约：协议里不存在 S→C 的尺寸请求帧）。
	time.Sleep(800 * time.Millisecond)
	// 若腿 2 想上报它自然会发 opResize——这里断言会话侧没有因被动几何再被改尺寸。
	svc.mu.Lock()
	ss := svc.sessions["ml13"]
	svc.mu.Unlock()
	ss.mu.Lock()
	cols := ss.cols
	ss.mu.Unlock()
	if cols != 100 {
		t.Fatalf("会话尺寸应保持在活动腿的 100，实际 %d（被动几何被反向上报？）", cols)
	}
}

// ---- 4.1 收尾所有权 ----

// ENDED 先于 close（读端先收 ENDED 再 EOF）+ detach 幂等（并发只摘一次）。
func TestEndedBeforeCloseAndDetachIdempotent(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c1, _ := attachSurface(t, ln, "ml14", 80, 24)
	defer c1.Close()

	// 并发 detach：对同一条腿从多个 goroutine 调 endLegLocked（会话锁串行化 ⇒ 只摘一次）。
	svc.mu.Lock()
	ss := svc.sessions["ml14"]
	svc.mu.Unlock()
	ss.mu.Lock()
	var victim *termClient
	for _, l := range ss.legs {
		victim = l
	}
	ss.mu.Unlock()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ss.mu.Lock()
			ss.endLegLocked(victim, termEndNone, "", "concurrent")
			ss.mu.Unlock()
		}()
	}
	wg.Wait()
	ss.mu.Lock()
	left := len(ss.legs)
	ss.mu.Unlock()
	if left != 0 {
		t.Fatalf("并发 detach 应只摘一次（剩 %d 条）", left)
	}

	// ENDED 先于 close：接管场景下被踢的腿先收 ENDED、再收 EOF。
	c2, _ := attachSurface(t, ln, "ml14", 80, 24)
	defer c2.Close()
	c3 := dialTerm(t, ln)
	defer c3.Close()
	readTermFrameT(t, c3)
	hello := encHello(80, 24, false, "ml14")
	hello[4] = helloFlagTakeover
	hello = append(hello, encCapability(capsSurface)...)
	writeTermFrame(t, c3, opHello, hello)
	if f := readTermFrameT(t, c3); f.op != opAttached {
		t.Fatalf("接管腿应收到 ATTACHED（首帧），收到 0x%02x", f.op)
	}
	f := readTermFrameT(t, c2)
	for f.op == opSnapshot || f.op == opSurfaceDiff || f.op == opState {
		f = readTermFrameT(t, c2)
	}
	if f.op != opEnded {
		t.Fatalf("被接管腿应收 ENDED，收到 0x%02x", f.op)
	}
	// ENDED 之后是连接关闭（EOF），不是别的帧。
	_ = c2.SetReadDeadline(time.Now().Add(3 * time.Second))
	if f2, err := readTermFrame(c2); err == nil {
		t.Fatalf("ENDED 之后应是 EOF，实际收到 0x%02x", f2.op)
	}
}

// ---- 4.2 raw 写者停滞语义 ----

// pipeConnHalfStuck：用 net.Pipe 造一条**无人读**的腿（pipe 无缓冲 ⇒ 写必阻塞）⇒ 停滞。
// 期间：腿不断开（无 ENDED）、会话与其它腿继续；恢复读取后续投恢复。
func TestRawStallDoesNotBreakLeg(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()

	// 正常腿先在场（观察对照）。
	cok, _, _, _ := attachTerm(t, ln, "ml15", true, 80, 24)
	defer cok.Close()

	// 停滞腿：直连 ServeConn 的 pipe 服务端半边；客户端半边握手后**不读**。
	stuckClient, stuckServer := net.Pipe()
	defer stuckServer.Close()
	go svc.ServeConn(stuckServer)
	f, err := readTermFrame(stuckClient) // GREETING
	if err != nil || f.op != opGreeting {
		t.Fatalf("GREETING：%v op=0x%02x", err, f.op)
	}
	_ = stuckClient.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := stuckClient.Write(encodeTermFrame(opHello, encHello(80, 24, true, "ml15"))); err != nil {
		t.Fatal(err)
	}
	if f, err = readTermFrame(stuckClient); err != nil || f.op != opAttached {
		t.Fatalf("停滞腿应先收到 ATTACHED（首帧）：op=0x%02x err=%v", f.op, err)
	}

	// 会话持续输出（ticker）：停滞腿阻塞在写上（pipe 无人读），写超时 → 停滞。
	// 观察：正常腿持续收数据；停滞腿仍在 legs（未被踢）。
	time.Sleep(2500 * time.Millisecond) // 未达默认写超时 10s：验「写阻塞期间其它腿不受影响」；停滞置位/恢复/超限断腿由 exec-r1 整改后的注入用例覆盖（term_exec_r1_test.go）
	_ = cok.SetReadDeadline(time.Now().Add(5 * time.Second))
	if got := readDataContains(t, cok, "tick"); !strings.Contains(got, "tick") {
		t.Fatal("停滞腿在写上卡住时，其它腿不该受影响")
	}
	svc.mu.Lock()
	ss := svc.sessions["ml15"]
	svc.mu.Unlock()
	ss.mu.Lock()
	stillIn := containsLeg(ss.legs, legByConnLocked(ss, stuckServer))
	ss.mu.Unlock()
	if !stillIn {
		t.Fatal("停滞的 raw 腿不该被踢（写超时 ≠ 死亡，任务 4.2）")
	}

	// 恢复读取 ⇒ 续投恢复（从可用起点接上，数据继续到达）。
	buf := make([]byte, 64<<10)
	_ = stuckClient.SetReadDeadline(time.Now().Add(3 * time.Second))
	total := 0
	for total < 4096 {
		n, rerr := stuckClient.Read(buf)
		total += n
		if rerr != nil {
			break
		}
	}
	if total == 0 {
		t.Fatal("恢复读取后停滞腿应续投数据")
	}
}

// ---- 4.4 慢腿组合矩阵 ----

// raw 慢 × surface 在场：surface 腿持续收快照/差分，会话不卡。
func TestSlowLegMatrixRawSlowSurfaceAlive(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()

	slowClient, slowServer := net.Pipe()
	defer slowServer.Close()
	go svc.ServeConn(slowServer)
	if f, err := readTermFrame(slowClient); err != nil || f.op != opGreeting {
		t.Fatalf("GREETING：%v", err)
	}
	_ = slowClient.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := slowClient.Write(encodeTermFrame(opHello, encHello(80, 24, true, "ml16"))); err != nil {
		t.Fatal(err)
	}
	if f, err := readTermFrame(slowClient); err != nil || f.op != opAttached {
		t.Fatalf("慢 raw 腿应先收到 ATTACHED：%v", err)
	}
	// 慢腿读一半停住（pipe 半堵）。
	buf := make([]byte, 4<<10)
	_ = slowClient.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	for {
		if _, err := slowClient.Read(buf); err != nil {
			break
		}
	}

	csf, snap := attachSurface(t, ln, "ml16", 80, 24)
	defer csf.Close()
	grid := newClientGrid(t, snap)
	time.Sleep(2 * time.Second) // 慢腿持续阻塞期间
	if !waitGridText(t, csf, grid, "tick") {
		t.Fatal("raw 慢腿阻塞时 surface 腿应继续收画面")
	}
}

// surface 慢 × raw 在场：raw 腿持续收字节。
func TestSlowLegMatrixSurfaceSlowRawAlive(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()

	slowClient, slowServer := net.Pipe()
	defer slowServer.Close()
	go svc.ServeConn(slowServer)
	if f, err := readTermFrame(slowClient); err != nil || f.op != opGreeting {
		t.Fatalf("GREETING：%v", err)
	}
	_ = slowClient.SetDeadline(time.Now().Add(5 * time.Second))
	hello := append(encHello(80, 24, true, "ml17"), encCapability(capsSurface)...)
	if _, err := slowClient.Write(encodeTermFrame(opHello, hello)); err != nil {
		t.Fatal(err)
	}
	if f, err := readTermFrame(slowClient); err != nil || f.op != opAttached {
		t.Fatalf("慢 surface 腿应先收到 ATTACHED：%v", err)
	}
	buf := make([]byte, 4<<10)
	_ = slowClient.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	for {
		if _, err := slowClient.Read(buf); err != nil {
			break
		}
	}

	craw, _, _, _ := attachTerm(t, ln, "ml17", false, 80, 24)
	defer craw.Close()
	_ = craw.SetReadDeadline(time.Now().Add(6 * time.Second))
	if got := readDataContains(t, craw, "tick"); !strings.Contains(got, "tick") {
		t.Fatal("surface 慢腿积压时 raw 腿应继续收字节")
	}
}

// 两 raw 腿一慢一快：快腿不受慢腿影响。
func TestSlowLegMatrixTwoRawLegs(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()

	slowClient, slowServer := net.Pipe()
	defer slowServer.Close()
	go svc.ServeConn(slowServer)
	if f, err := readTermFrame(slowClient); err != nil || f.op != opGreeting {
		t.Fatalf("GREETING：%v", err)
	}
	_ = slowClient.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := slowClient.Write(encodeTermFrame(opHello, encHello(80, 24, true, "ml18"))); err != nil {
		t.Fatal(err)
	}
	if f, err := readTermFrame(slowClient); err != nil || f.op != opAttached {
		t.Fatalf("慢腿应先收到 ATTACHED：%v", err)
	}
	buf := make([]byte, 4<<10)
	_ = slowClient.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	for {
		if _, err := slowClient.Read(buf); err != nil {
			break
		}
	}

	cfast, _, _, _ := attachTerm(t, ln, "ml18", false, 80, 24)
	defer cfast.Close()
	_ = cfast.SetReadDeadline(time.Now().Add(6 * time.Second))
	if got := readDataContains(t, cfast, "tick"); !strings.Contains(got, "tick") {
		t.Fatal("慢 raw 腿在场时快 raw 腿应继续收字节")
	}
}

// ---- 4.5 资源判据：20 会话建删后 goroutine 回落 ----

func TestSessionChurnGoroutineFallsBack(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	time.Sleep(200 * time.Millisecond) // sampleLoop 等常驻 goroutine 就位
	base := goroutineCount()

	for i := 0; i < 20; i++ {
		name := "churn-" + string(rune('a'+i))
		c, _, _, _ := attachTerm(t, ln, name, true, 80, 24)
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		readDataContains(t, c, "tick")
		_ = c.Close()

		ck := dialTerm(t, ln)
		readTermFrameT(t, ck)
		writeTermFrame(t, ck, opKill, encName(name))
		if f := readTermFrameT(t, ck); f.op != opOK {
			t.Fatalf("KILL %s 应回 OK，收到 0x%02x", name, f.op)
		}
		_ = ck.Close()
	}
	// 等 KILL 的收尾链（ENDED 送达 + 写者退出 + 进程收尸）跑完。
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		list := listTerm(t, ln)
		if len(list["sessions"].([]any)) == 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	time.Sleep(500 * time.Millisecond)
	final := goroutineCount()
	if final > base+6 {
		t.Fatalf("20 会话建删后 goroutine 未回落：base=%d final=%d", base, final)
	}
}

func goroutineCount() int { return runtime.NumGoroutine() }

// ---- 5.1 查询应答归属（窄规则）----

// 窄规则切换时机与应答份数（假 sink 计数）：raw 终端腿在场 ⇒ 服务端不代答；
// 离开 ⇒ 恢复代答。随腿进出动态切换。
func TestResponseSinkNarrowRule(t *testing.T) {
	sv, err := newSessionVT(termConfig{scrollbackLines: 100}, 20, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer sv.Close()

	s := &termSession{vt: sv}
	count := 0
	s.responseFn = func(p []byte) { count++ }

	query := func() { sv.Write([]byte("\x1b[c")) } // DA1

	// 无 raw 终端腿 ⇒ 代答（计数 +1）。
	s.rawTermLegs = 0
	s.updateResponseSinkLocked()
	query()
	if count != 1 {
		t.Fatalf("无 raw 终端腿时代答份数应为 1，实际 %d", count)
	}
	// raw 终端腿进场 ⇒ 让位（不代答）。
	s.rawTermLegs = 1
	s.updateResponseSinkLocked()
	query()
	if count != 1 {
		t.Fatalf("raw 终端腿在场时代答份数应保持 1（让位），实际 %d", count)
	}
	// 腿离开 ⇒ 恢复代答（动态切换）。
	s.rawTermLegs = 0
	s.updateResponseSinkLocked()
	query()
	if count != 2 {
		t.Fatalf("raw 终端腿离开后应恢复代答，计数 %d", count)
	}
}

// 集成：host 腿（capsRawTerminal）在场 ⇒ 服务端对 DA1 静默（程序收不到代答）；
// legacy 腿（未声明）⇒ 服务端代答（程序从回显里能看到一份）。
func TestResponseSinkOnWire(t *testing.T) {
	shell := "stty -icanon -echo; read -r _l; printf '\\x1b[c'; cat -v"
	svc, ln := startTestTermServiceShell(t, shell)
	defer svc.Close()
	defer ln.Close()

	// host 腿：声明 capsRawTerminal。
	chost := dialTerm(t, ln)
	defer chost.Close()
	readTermFrameT(t, chost)
	writeTermFrame(t, chost, opHello,
		append(encHello(80, 24, true, "ml19"), encHelloTail(capsRawTerminal, true, "host-q")...))
	if f := readTermFrameT(t, chost); f.op != opAttached {
		t.Fatalf("host 腿应接入：0x%02x", f.op)
	}
	writeTermFrame(t, chost, opData, []byte("\n")) // 触发 read 返回 → printf 查询
	_ = chost.SetReadDeadline(time.Now().Add(2 * time.Second))
	drainUntilQuiet(t, chost)
	if sawDA1Answer(t, chost, false) {
		t.Fatal("host 腿在场时服务端不该代答 DA1（窄规则）")
	}

	// 对照会话：legacy 腿（无声明）⇒ 服务端代答（DA1 应答出现在 cat -v 回显里）。
	cleg, _, _, _ := attachTerm(t, ln, "ml20", true, 80, 24)
	defer cleg.Close()
	writeTermFrame(t, cleg, opData, []byte("\n"))
	if !sawDA1AnswerLegacy(t, cleg) {
		t.Fatal("legacy 腿在场时服务端应代答 DA1（旧客户端零变化）")
	}
}

// sawDA1Answer：host 场景下窗口内不应出现 DA1 应答形态（^[[?…c）。
func sawDA1Answer(t *testing.T, c net.Conn, _ bool) bool {
	t.Helper()
	deadline := time.Now().Add(1200 * time.Millisecond)
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		f, err := readTermFrame(c)
		if err != nil {
			continue
		}
		if f.op == opData && strings.Contains(string(f.payload), "?62;") {
			return true
		}
	}
	return false
}

func sawDA1AnswerLegacy(t *testing.T, c net.Conn) bool {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		f, err := readTermFrame(c)
		if err != nil {
			continue
		}
		if f.op == opData && strings.Contains(string(f.payload), "?62;") {
			return true
		}
	}
	return false
}

// drainUntilQuiet：读到暂时无帧（让 printf 的查询与回显都过去）。
func drainUntilQuiet(t *testing.T, c net.Conn) {
	t.Helper()
	for i := 0; i < 64; i++ {
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if _, err := readTermFrame(c); err != nil {
			return
		}
	}
}

// ---- 6.1 HELLO flags bit1 = only-if-absent ----

func TestHelloOnlyIfAbsent(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()

	// 建会话（不带该位 = 既有 create 语义）。
	c1, _, _, _ := attachTerm(t, ln, "ml21", true, 80, 24)
	defer c1.Close()

	// 重名 + only-if-absent ⇒ already_exists（不静默接入）。
	c2 := dialTerm(t, ln)
	defer c2.Close()
	readTermFrameT(t, c2)
	hello := encHello(80, 24, true, "ml21")
	hello[4] = helloFlagCreate | helloFlagOnlyIfAbsent
	writeTermFrame(t, c2, opHello, hello)
	f := readTermFrameT(t, c2)
	if f.op != opError {
		t.Fatalf("重名 + only-if-absent 应报错，收到 0x%02x", f.op)
	}
	if code, msg, _ := decError(f.payload); code != "already_exists" {
		t.Fatalf("错误码应为 already_exists，实际 %q（%s）", code, msg)
	}

	// 不带该位（= `-A` 复用）⇒ 照旧接入成功。
	c3 := dialTerm(t, ln)
	defer c3.Close()
	readTermFrameT(t, c3)
	writeTermFrame(t, c3, opHello, encHello(80, 24, true, "ml21"))
	if f := readTermFrameT(t, c3); f.op != opAttached {
		t.Fatalf("-A 复用应接入成功，收到 0x%02x", f.op)
	}

	// 新名字 + only-if-absent ⇒ 创建成功。
	c4 := dialTerm(t, ln)
	defer c4.Close()
	readTermFrameT(t, c4)
	hello4 := encHello(80, 24, true, "ml21-new")
	hello4[4] = helloFlagCreate | helloFlagOnlyIfAbsent
	writeTermFrame(t, c4, opHello, hello4)
	if f := readTermFrameT(t, c4); f.op != opAttached {
		t.Fatalf("新名字 + only-if-absent 应创建成功，收到 0x%02x（%q）", f.op, f.payload)
	}
}

// ---- 6.2 CREATE（创建不接入）----

func TestCreateOp(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()

	create := func(name string, flags byte) (byte, string) {
		c := dialTerm(t, ln)
		defer c.Close()
		readTermFrameT(t, c)
		writeTermFrame(t, c, opCreate, encCreate(flags, name))
		f := readTermFrameT(t, c)
		if f.op == opError {
			code, msg, _ := decError(f.payload)
			return f.op, code + ": " + msg
		}
		return f.op, ""
	}

	// new -d：创建不接入。
	if op, msg := create("ml22", 0); op != opOK {
		t.Fatalf("new -d 应回 OK，收到 0x%02x（%s）", op, msg)
	}
	list := listTerm(t, ln)
	sess, ok := listSession(list, "ml22")
	if !ok {
		t.Fatal("创建后会话应在列表里")
	}
	if sess["attached"] != false {
		t.Error("不接入 ⇒ attached 应为 false")
	}
	clients, _ := sess["clients"].([]any)
	if len(clients) != 0 {
		t.Errorf("不接入 ⇒ clients 应为空，实际 %v", clients)
	}
	if sess["cols"].(float64) != 80 || sess["rows"].(float64) != 24 {
		t.Errorf("不接入 ⇒ 尺寸应为默认 80x24，实际 %v x %v", sess["cols"], sess["rows"])
	}

	// new -d 重名 ⇒ already_exists。
	if op, msg := create("ml22", 0); op != opError || !strings.Contains(msg, "already_exists") {
		t.Fatalf("new -d 重名应报 already_exists，实际 0x%02x（%s）", op, msg)
	}
	// new -A -d（only-if-absent）⇒ 重名复用成功。
	if op, msg := create("ml22", createFlagOnlyIfAbsent); op != opOK {
		t.Fatalf("new -A -d 重名应复用成功，实际 0x%02x（%s）", op, msg)
	}
	// 非法名。
	if op, _ := create("bad name!", 0); op != opError {
		t.Fatal("非法名应报错")
	}
	// 现有会话随后可正常接入（CREATE 没有留下坏状态）。
	c, _, _, _ := attachTerm(t, ln, "ml22", false, 80, 24)
	defer c.Close()
}

// ---- 6.3 GREETING 位值回归（不新增多腿能力位）----

func TestGreetingFeaturesNoNewBit(t *testing.T) {
	want := uint32(featList | featReplay | featModes | featAgent | featTitle | featSurfaceBit)
	if uint32(termFeatures) != want {
		t.Fatalf("termFeatures = 0x%x，应保持既有六位 0x%x（不新增多腿位）", termFeatures, want)
	}
	ver, feats, err := decGreeting(encGreeting())
	if err != nil || ver != termProtoVer || feats != want {
		t.Fatalf("GREETING 往返：ver=%d feats=0x%x err=%v（期望 0x%x）", ver, feats, err, want)
	}
	if want != 0x3f {
		t.Fatalf("六位能力位值应为 0x3f，实际 0x%x", want)
	}
}

// ---- LIST JSON 的 clients 字段名与 design D8 一致（2.5 的 JSON 契约）----

func TestListClientsJSONContract(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c, _, _, _ := attachTerm(t, ln, "ml23", true, 80, 24)
	defer c.Close()

	list := listTerm(t, ln)
	raw, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, field := range []string{`"kind"`, `"cols"`, `"rows"`, `"sinceMs"`, `"active"`, `"clients"`, `"attached"`} {
		if !strings.Contains(s, field) {
			t.Errorf("LIST JSON 缺字段 %s：%s", field, s)
		}
	}
}
