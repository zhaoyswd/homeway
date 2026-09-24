//go:build (darwin || linux) && (amd64 || arm64) && cgo

// clipboard_test.go — 剪贴板读方向（OSC 52 "?"）的服务端判据（任务 2.7 的读半边 / 3.4 的真机复验）。
//
// 为什么值得单测：读回调是**同步**的（请求句柄只在回调期间有效），所以「缓存 + 命中应答」这条
// 设计必须当场答对——真机验证时发现这条腿其实**从没装上**（只装了写回调），OSC 52 读查询一路
// 石沉大海（客户端读到空）。这个测试把它钉住：装了转发器就按内容答、没装就明确不答。
package vt

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestClipboardReadAnswersFromForwarder(t *testing.T) {
	SetClipboardReadForwarder(func(id uintptr, location int) (string, bool) {
		if location != 0 { // 0 = clipboard；primary selection 我们没有数据源
			return "", false
		}
		return "CLIP-TEST", true
	})
	defer SetClipboardReadForwarder(nil)

	term, err := New(40, 5, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer term.Close()
	var out []byte
	term.SetResponseSink(func(p []byte) { out = append(out, p...) })
	term.EnableClipboardRead()

	term.Write([]byte("\x1b]52;c;?\x07"))
	got := string(out)
	want := base64.StdEncoding.EncodeToString([]byte("CLIP-TEST"))
	if !strings.Contains(got, want) {
		t.Fatalf("OSC 52 读查询应命中转发器内容（base64 %q），实际应答 %q", want, got)
	}
	if !strings.Contains(got, "]52;") {
		t.Fatalf("应答应是 OSC 52 形态，实际 %q", got)
	}
}

func TestClipboardReadWithoutForwarderStaysSilent(t *testing.T) {
	SetClipboardReadForwarder(nil)
	term, err := New(40, 5, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer term.Close()
	var out []byte
	term.SetResponseSink(func(p []byte) { out = append(out, p...) })
	term.EnableClipboardRead()

	term.Write([]byte("\x1b]52;c;?\x07"))
	if strings.Contains(string(out), "Q0xJUC1URVNU") { // 不该凭空冒出内容
		t.Fatalf("没有转发器时不该答出内容，实际 %q", string(out))
	}
}
