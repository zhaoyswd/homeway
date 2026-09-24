//go:build (darwin || linux) && (amd64 || arm64) && cgo

// response_test.go — vt 写回 PTY 的判据（任务 2.7 的前置）。
//
// 这条腿的意义：vt 搬到服务端后，「程序问终端、终端答」这一路也必须跟着搬——否则 vim/htop/tmux
// 这类启动就探测终端的程序会卡住。测试直接喂查询序列，断言应答真的经回调回来了。
package vt

import (
	"strings"
	"testing"
)

// collector 收应答（回调是同步的，但可能在一次 Write 里被调多次）。
type collector struct{ chunks []string }

func (c *collector) sink(p []byte) { c.chunks = append(c.chunks, string(p)) }
func (c *collector) all() string   { return strings.Join(c.chunks, "") }

func TestResponseDSR(t *testing.T) {
	term, err := New(80, 24, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer term.Close()
	var c collector
	term.SetResponseSink(c.sink)

	term.Write([]byte("\x1b[3;7H")) // 光标移到 (3,7)
	term.Write([]byte("\x1b[6n"))   // DSR：报告光标位置
	if got := c.all(); !strings.Contains(got, "R") {
		t.Fatalf("DSR 应有应答（形如 \\x1b[r;cR），实际 %q", got)
	}
	if got := c.all(); !strings.Contains(got, "[3;7R") {
		t.Errorf("光标位置应答应为 [3;7R，实际 %q", got)
	}
}

func TestResponseDA1(t *testing.T) {
	term, err := New(80, 24, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer term.Close()
	var c collector
	term.SetResponseSink(c.sink)

	term.Write([]byte("\x1b[c")) // DA1：设备属性
	got := c.all()
	if !strings.HasPrefix(got, "\x1b[?") {
		t.Errorf("DA1 应答应以 \\x1b[? 开头，实际 %q", got)
	}
}

// THEME 上报后，OSC 10/11 查询按上报值应答（design D4 的「主题客户端解析」唯一例外）。
func TestResponseOSCColorQueriesFollowTheme(t *testing.T) {
	term, err := New(80, 24, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer term.Close()
	var c collector
	term.SetResponseSink(c.sink)

	term.SetDefaultColors([3]uint8{0x11, 0x22, 0x33}, [3]uint8{0xaa, 0xbb, 0xcc})
	term.Write([]byte("\x1b]11;?\x07")) // 问背景色
	got := c.all()
	if !strings.Contains(got, "11;rgb:") {
		t.Fatalf("OSC 11 查询应按主题应答（形如 11;rgb:…），实际 %q", got)
	}
	if !strings.Contains(got, "aa") || !strings.Contains(got, "cc") {
		t.Errorf("应答里应含上报的背景分量 aa/cc，实际 %q", got)
	}
	c.chunks = nil
	term.Write([]byte("\x1b]10;?\x07")) // 问前景色
	if got := c.all(); !strings.Contains(got, "10;rgb:") {
		t.Errorf("OSC 10 查询应按主题应答，实际 %q", got)
	}
}

// 没装接收方时不能崩（应答直接丢）。
func TestResponseWithoutSinkIsSafe(t *testing.T) {
	term, err := New(20, 5, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer term.Close()
	term.Write([]byte("\x1b[6n\x1b[c\x1b]11;?\x07"))
}

// Close 之后注册表里不该留条目（否则回调会拿到已释放的终端）。
func TestRegistryClearedOnClose(t *testing.T) {
	term, err := New(20, 5, 100)
	if err != nil {
		t.Fatal(err)
	}
	id := term.regID
	if id == 0 {
		t.Fatal("建终端时应注册回调 id")
	}
	term.Close()
	vtRegistryMu.RLock()
	_, still := vtRegistry[id]
	vtRegistryMu.RUnlock()
	if still {
		t.Error("Close 后注册表不该再持有该终端")
	}
}
