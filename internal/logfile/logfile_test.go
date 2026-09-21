package logfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotationBySize(t *testing.T) {
	dir := t.TempDir()
	// maxBytes=64、3 份备份：写满多轮后，主文件 + .1/.2/.3 存在、没有 .4。
	w, err := Open(dir, "l.log", 64, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	line := strings.Repeat("x", 30) + "\n" // 31B/行：第 3 行触发轮转
	for i := 0; i < 20; i++ {
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"l.log", "l.log.1", "l.log.2", "l.log.3"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s 应存在: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "l.log.4")); !os.IsNotExist(err) {
		t.Fatalf("l.log.4 不应存在: %v", err)
	}
	// 主文件不超过 maxBytes。
	st, err := os.Stat(filepath.Join(dir, "l.log"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() > 64 {
		t.Fatalf("主文件超限: %d > 64", st.Size())
	}
	// 备份按时间序：.1 是最近归档（内容非空）。
	b1, err := os.ReadFile(filepath.Join(dir, "l.log.1"))
	if err != nil || len(b1) == 0 {
		t.Fatalf("l.log.1 应为最近归档: %v %dB", err, len(b1))
	}
}

func TestWriteAfterManualDelete(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, "l.log", 1<<20, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.Write([]byte("a\n")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "l.log")); err != nil {
		t.Fatal(err)
	}
	// 文件被外部删掉：句柄还在（追加进孤儿 inode），轮转点重开。
	// 直接模拟「句柄失效」路径：关掉再写，应自动重开。
	w.Close()
	if _, err := w.Write([]byte("b\n")); err != nil {
		t.Fatalf("重开后写入应成功: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "l.log"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "b\n" {
		t.Fatalf("重开后文件内容不符: %q", b)
	}
}

func TestAppendOnReopen(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, "l.log", 1<<20, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("old\n")); err != nil {
		t.Fatal(err)
	}
	w.Close()
	// 重启语义：重新 Open 是追加，不截断历史。
	w2, err := Open(dir, "l.log", 1<<20, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	if _, err := w2.Write([]byte("new\n")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "l.log"))
	if string(b) != "old\nnew\n" {
		t.Fatalf("重启应追加: %q", b)
	}
}
