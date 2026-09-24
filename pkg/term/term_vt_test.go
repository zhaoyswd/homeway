//go:build !windows

// term_vt_test.go — 会话屏态 vt 化的判据（任务 1.3）。
//
// 真起 PTY 会话（复用 term_service_test.go 的装配），断言：
//
//	① 会话建起来就有 vt，且 PTY 输出真的进了 vt（屏态与字节流一致）
//	② resize 传导到 vt（回滚重排）
//	③ HOMEWAY_TERM_VT=off ⇒ 该会话 legacy-only 但功能照常（逃生口）
//	④ vt 缺失是**每会话**的事，不影响别的会话
package term

import (
	"strings"
	"testing"
	"time"
)

// sessionOf 取会话（测试用；调用方自己持锁查字段）。
func sessionOf(t *testing.T, svc *termService, name string) *termSession {
	t.Helper()
	svc.mu.Lock()
	defer svc.mu.Unlock()
	return svc.sessions[name]
}

// vtTextOf 取会话当前 vt 的纯文本（无 vt 返回 ""）。
func vtTextOf(ss *termSession) string {
	if ss == nil {
		return ""
	}
	ss.mu.Lock()
	vt := ss.vt
	ss.mu.Unlock()
	if vt == nil || vt.Terminal() == nil {
		return ""
	}
	return vt.Terminal().PlainText()
}

// waitVTPred 轮询等 vt 状态满足条件。
func waitVTPred(t *testing.T, svc *termService, name string, pred func(*termSession) bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if pred(sessionOf(t, svc, name)) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("等待「%s」超时", what)
}

func TestSessionVTFeedsFromPTY(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c, _, _, _ := attachTerm(t, ln, "vt1", true, 80, 24)
	defer c.Close()

	ss := sessionOf(t, svc, "vt1")
	ss.mu.Lock()
	hasVT := ss.vt != nil
	ss.mu.Unlock()
	if !hasVT {
		t.Fatal("会话建起来就该有 vt（无 vt 说明 newSessionVT 没接上或创建失败）")
	}
	writeTermFrame(t, c, opData, []byte("echo 屏态真源\r"))
	waitVTPred(t, svc, "vt1", func(ss *termSession) bool {
		return strings.Contains(vtTextOf(ss), "屏态真源")
	}, "vt 里出现会话输出")
}

func TestSessionVTResize(t *testing.T) {
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c, _, _, _ := attachTerm(t, ln, "vt2", true, 80, 24)
	defer c.Close()

	writeTermFrame(t, c, opResize, encResize(100, 30))
	waitVTPred(t, svc, "vt2", func(ss *termSession) bool {
		if ss == nil {
			return false
		}
		ss.mu.Lock()
		vt := ss.vt
		ss.mu.Unlock()
		if vt == nil || vt.Terminal() == nil {
			return false
		}
		cols, rows := vt.Terminal().Size()
		return cols == 100 && rows == 30
	}, "resize 传导到服务端 vt")
}

// 逃生口：HOMEWAY_TERM_VT=off ⇒ 会话照常可用，只是没有 vt（legacy 路径完整）。
func TestSessionVTEscapeHatch(t *testing.T) {
	t.Setenv("HOMEWAY_TERM_VT", "off")
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()
	c, _, _, _ := attachTerm(t, ln, "vt3", true, 80, 24)
	defer c.Close()

	if got := vtTextOf(sessionOf(t, svc, "vt3")); got != "" {
		t.Fatalf("HOMEWAY_TERM_VT=off 时会话不该有 vt，实际屏态 %q", got)
	}
	if VTText() != "off（HOMEWAY_TERM_VT）" {
		t.Errorf("VTText 应报告逃生口生效，实际 %q", VTText())
	}
	// legacy 功能照常：输入有回显（走的是字节环 + DATA，不经过 vt）。
	writeTermFrame(t, c, opData, []byte("echo 逃生口可用\r"))
	if got := readDataContains(t, c, "逃生口可用"); !strings.Contains(got, "逃生口可用") {
		t.Fatalf("逃生口下 legacy 回显失败：%q", got)
	}
}

// vt 缺失是每会话的事：两个会话都能用，互不拖累。
func TestSessionVTUnavailableIsPerSession(t *testing.T) {
	t.Setenv("HOMEWAY_TERM_VT", "off")
	svc, ln := startTestTermService(t)
	defer svc.Close()
	defer ln.Close()

	a, _, _, _ := attachTerm(t, ln, "vtA", true, 80, 24)
	defer a.Close()
	b, _, _, _ := attachTerm(t, ln, "vtB", true, 80, 24)
	defer b.Close()

	svc.mu.Lock()
	n := len(svc.sessions)
	svc.mu.Unlock()
	if n != 2 {
		t.Fatalf("两个会话都该在，实际 %d 个", n)
	}
	writeTermFrame(t, a, opData, []byte("echo A 可用\r"))
	if got := readDataContains(t, a, "A 可用"); !strings.Contains(got, "A 可用") {
		t.Fatalf("会话 A 不可用：%q", got)
	}
	writeTermFrame(t, b, opData, []byte("echo B 可用\r"))
	if got := readDataContains(t, b, "B 可用"); !strings.Contains(got, "B 可用") {
		t.Fatalf("会话 B 不可用：%q", got)
	}
}
