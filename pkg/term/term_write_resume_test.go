package term

// term_write_resume_test.go — writeFrameOnce 进度感知续写回归（2026-09-30，linux CI
// 「意外帧 op 0x6e」根因修复的判据面）：net.Conn.Write 在 deadline 中途过期时可返回
// n>0 + timeout——帧写必须从断点续写**剩余部分**，绝不能整帧重发（旧实现丢 n 重发，
// 把已进内核的字节重复一遍 ⇒ 对端帧界失步）；零进展的超时照旧作为停滞错误上抛
//（调用方退避/停滞上限语义不动）。

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// fakePartialConn：脚本化 Write 行为的假连接。
type fakePartialConn struct {
	mu      sync.Mutex
	written []byte
	// script 每项 = 一次 Write 调用的结局：前 n 字节计入、返回 err。
	script []fakeWriteStep
	calls  int
}

type fakeWriteStep struct {
	n   int
	err error
}

func (f *fakePartialConn) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.script) == 0 {
		f.written = append(f.written, p...)
		return len(p), nil
	}
	st := f.script[0]
	f.script = f.script[1:]
	f.calls++
	if st.n > len(p) {
		st.n = len(p)
	}
	f.written = append(f.written, p[:st.n]...)
	return st.n, st.err
}

func (f *fakePartialConn) Read(p []byte) (int, error)         { return 0, io.EOF }
func (f *fakePartialConn) Close() error                       { return nil }
func (f *fakePartialConn) LocalAddr() net.Addr                { return nil }
func (f *fakePartialConn) RemoteAddr() net.Addr               { return nil }
func (f *fakePartialConn) SetDeadline(t time.Time) error      { return nil }
func (f *fakePartialConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakePartialConn) SetWriteDeadline(t time.Time) error { return nil }

func TestWriteFrameOnceResumesPartialWrite(t *testing.T) {
	payload := []byte("line-199999 abcdefghijklmnopqrstuvwxyz 0123456789")
	conn := &fakePartialConn{script: []fakeWriteStep{
		{5, os.ErrDeadlineExceeded}, // 前 5 字节已进内核 + 中途超时
		{0, os.ErrDeadlineExceeded}, // 续写撞上零进展超时（调用方退避后仍重试同帧）
	}}
	c := &termClient{conn: conn}
	// 调用方语义 = rawWriteFrame 的停滞重试：超时上抛 → 退避 → 重写「同一帧」。
	for i := 0; i < 5; i++ {
		err := c.writeFrameOnce(opData, payload, 300*time.Millisecond)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("中途超时应照旧上抛（停滞判定在调用方），得：%v", err)
		}
	}
	want := encodeTermFrame(opData, payload)
	if string(conn.written) != string(want) {
		t.Fatalf("重试续写后字节流必须恰为一帧（无重发/无缺口）：want %d 字节, got %d 字节", len(want), len(conn.written))
	}
	if conn.calls != 2 {
		t.Fatalf("应恰好消耗两步脚本（第三段直写完成断尾+新帧），实际 %d 次脚本 Write", conn.calls)
	}
}

func TestWriteFrameOnceFinishesTornTailBeforeNextFrame(t *testing.T) {
	// 换帧来路（控制帧超时后写者继续处理后续帧）：旧帧断尾必须先续完、再写新帧——
	// 线上不允许「半帧 + 新帧」的拼接形态。
	first := []byte("first-control-payload")
	second := []byte("second-frame-payload")
	conn := &fakePartialConn{script: []fakeWriteStep{
		{3, os.ErrDeadlineExceeded}, // first 帧写进 3 字节后超时（断尾挂起）
		{0, os.ErrDeadlineExceeded}, // 续尾撞零进展（调用方退避）
	}}
	c := &termClient{conn: conn}
	for i := 0; i < 5; i++ {
		if err := c.writeFrameOnce(opState, first, 300*time.Millisecond); err == nil {
			break
		}
	}
	if err := c.writeFrameOnce(opData, second, 300*time.Millisecond); err != nil {
		t.Fatalf("断尾清空后新帧应正常写出：%v", err)
	}
	want := append(encodeTermFrame(opState, first), encodeTermFrame(opData, second)...)
	if string(conn.written) != string(want) {
		t.Fatalf("字节流必须 = first 全帧 + second 全帧：want %d 字节, got %d 字节", len(want), len(conn.written))
	}
}

func TestWriteFrameOnceZeroProgressTimeoutSurfaces(t *testing.T) {
	conn := &fakePartialConn{script: []fakeWriteStep{
		{0, os.ErrDeadlineExceeded}, // 一个字节都没进去：停滞错误必须上抛
	}}
	c := &termClient{conn: conn}
	err := c.writeFrameOnce(opData, []byte("x"), 300*time.Millisecond)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("零进展超时必须作为停滞错误上抛（退避/上限语义在调用方），得：%v", err)
	}
	if len(conn.written) != 0 {
		t.Fatalf("零进展时不应有字节入连接：%d", len(conn.written))
	}
}
