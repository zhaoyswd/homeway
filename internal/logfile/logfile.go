// Package logfile：带尺寸轮转的日志文件写入器。
//
// 出口/中继的文件日志（events.log / debug.log / relay.log）都走这里：
// 超过 maxBytes 就轮转（name → name.1 → name.2 → …，最旧的删掉），总占用有上界。
// 写入并发安全；打开失败返回 error（调用方决定降级——日志开不了不该挡服务，
// 但至少要知道）。追加写（O_APPEND）：重启不清历史，轮转负责有界。
package logfile

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Writer：一个轮转日志文件。零值不可用，经 Open 创建。
type Writer struct {
	mu        sync.Mutex
	path      string
	maxBytes  int64
	backups   int
	f         *os.File
	size      int64
	openError error // 最近一次 open/rotate 失败（写不进去时给调用方一个说法）
}

// Open 打开（或创建）dir/name，超过 maxBytes 轮转，保留 backups 份历史。
func Open(dir, name string, maxBytes int64, backups int) (*Writer, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	w := &Writer{path: filepath.Join(dir, name), maxBytes: maxBytes, backups: backups}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Writer) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.f, w.size = f, st.Size()
	return nil
}

// Write 追加一段日志（调用方自行带换行）。超限先轮转再写。
// 轮转失败（目录没了/权限变了）不致命：丢弃本段并记住错误，下次 Write 重试 open。
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		if err := w.open(); err != nil {
			w.openError = err
			return 0, err
		}
	}
	if w.size+int64(len(p)) > w.maxBytes {
		w.rotateLocked()
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	if err != nil {
		// 写了一半/全失败：文件句柄可能已坏，下次 Write 走重开。
		w.f.Close()
		w.f = nil
	}
	return n, err
}

// rotateLocked：关当前文件，历史依次后移（.1→.2…），当前改名 .1，重开新文件。
// 失败（比如目录被删）时 w.f 置 nil，Write 的重开路径兜底。
func (w *Writer) rotateLocked() {
	if w.f != nil {
		w.f.Close()
		w.f = nil
	}
	for i := w.backups; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", w.path, i)
		if i == w.backups {
			_ = os.Remove(src) // 最旧的直接删
			continue
		}
		_ = os.Rename(src, fmt.Sprintf("%s.%d", w.path, i+1))
	}
	if err := os.Rename(w.path, w.path+".1"); err != nil {
		w.openError = err
		return
	}
	if err := w.open(); err != nil {
		w.openError = err
	}
}

// Close 关闭当前文件（幂等）。
func (w *Writer) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f != nil {
		w.f.Close()
		w.f = nil
	}
}

// Path 文件路径（排障时告诉用户日志在哪）。
func (w *Writer) Path() string { return w.path }
