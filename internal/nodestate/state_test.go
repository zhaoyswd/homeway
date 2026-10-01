package nodestate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zhaoyswd/homeway/internal/nodeconfig"
)

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestOpenFreshState(t *testing.T) {
	// 全新 state：四子目录 + 默认 config（serve.enabled=true——零参=出口的连续性）。
	dir := t.TempDir()
	st, err := OpenNodeState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, sub := range []string{st.ServeDir(), st.RelayDir(), st.ClientDir(), st.CacheDir()} {
		if !dirExists(sub) {
			t.Fatalf("子目录缺失：%s", sub)
		}
	}
	cfg, err := nodeconfig.Load(nodeconfig.Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Serve.Enabled {
		t.Fatal("全新 state 默认 serve.enabled=true")
	}
	// 目录 0700 收紧（0755 既有目录也收紧）。
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	st2, err := OpenNodeState(dir)
	if err != nil {
		t.Fatal(err)
	}
	st2.Close()
	fi, _ := os.Stat(dir)
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("state 目录应收紧 0700：got %v", fi.Mode().Perm())
	}
}

// TestOpenTightensLooseSubdirs 既有子目录收紧（exec-r1 低-7）：runbook 手建的
// relay/ 0755 这类漂移在 OpenNodeState 归一为 0700（MkdirAll 的 mode 只对新建生效）。
func TestOpenTightensLooseSubdirs(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "relay"), 0o755); err != nil {
		t.Fatal(err)
	}
	st, err := OpenNodeState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	fi, err := os.Stat(st.RelayDir())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("既有子目录应收紧 0700：got %v", fi.Mode().Perm())
	}
}

func TestConfigExistingNotRegenerated(t *testing.T) {
	// config 已存在时不重写（手编意图不被覆盖）。
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := nodeconfig.Path(dir)
	if err := os.WriteFile(path, []byte("[serve]\nlisten = 41000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := read(t, path)
	st, err := OpenNodeState(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	if read(t, path) != before {
		t.Fatal("已有 config 不应被重写")
	}
}
