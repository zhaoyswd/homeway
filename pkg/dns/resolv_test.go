package dns

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeResolv(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestUpstreamsFollowChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	writeResolv(t, path, "# comment\nnameserver 192.168.3.1\n")
	u, err := NewUpstreams(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.List(); len(got) != 1 || got[0] != "192.168.3.1" {
		t.Fatalf("初始列表错误: %v", got)
	}
	// mtime 未变（节流窗口内也强制看 mtime 不变路径）→ 旧列表
	writeResolv(t, path, "nameserver 198.18.0.2\nnameserver 192.168.3.1\n")
	// 手工推进 mtime（同秒写入 mtime 可能相同）
	future := time.Now().Add(2 * time.Second)
	os.Chtimes(path, future, future)
	// 绕过节流的 lastCheck
	u.mu.Lock()
	u.lastCheck = time.Time{}
	u.mu.Unlock()
	if got := u.List(); len(got) != 2 || got[0] != "198.18.0.2" {
		t.Fatalf("变更后列表应跟随: %v", got)
	}
}

func TestUpstreamsKeepsLastGoodOnCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	writeResolv(t, path, "nameserver 192.168.3.1\n")
	u, err := NewUpstreams(path)
	if err != nil {
		t.Fatal(err)
	}
	// 瞬坏：空文件 / 只有注释
	writeResolv(t, path, "")
	os.Chtimes(path, time.Now().Add(2*time.Second), time.Now().Add(2*time.Second))
	u.mu.Lock()
	u.lastCheck = time.Time{}
	u.mu.Unlock()
	if got := u.List(); len(got) != 1 || got[0] != "192.168.3.1" {
		t.Fatalf("瞬坏应保留 last-good: %v", got)
	}
	// 文件消失同理
	os.Remove(path)
	u.mu.Lock()
	u.lastCheck = time.Time{}
	u.mu.Unlock()
	if got := u.List(); len(got) != 1 {
		t.Fatalf("文件消失应保留 last-good: %v", got)
	}
}

func TestUpstreamsEmptyThenRecover(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	writeResolv(t, path, "search example.com\n") // 无 nameserver：不再失败（review M6）
	u, err := NewUpstreams(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.List(); len(got) != 0 {
		t.Fatalf("空表应返回空, got %v", got)
	}
	// 上游出现（启动竞态恢复）：空表路径不依赖 mtime，重置节流后即载入
	writeResolv(t, path, "nameserver 198.18.0.2\n")
	u.mu.Lock()
	u.lastCheck = time.Time{}
	u.mu.Unlock()
	if got := u.List(); len(got) != 1 || got[0] != "198.18.0.2" {
		t.Fatalf("空表恢复后应载入新上游: %v", got)
	}
}
