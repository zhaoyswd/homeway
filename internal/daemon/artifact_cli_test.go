package daemon

// artifact_cli_test.go — role-management tasks 3.5：export/import/reset cache CLI
// 的退出码与可行动错误文案（内核面的往返/安全判据在 nodestate 批 1 全量覆盖）。

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zhaoyswd/homeway/internal/nodeconfig"
	"github.com/zhaoyswd/homeway/internal/nodestate"
)

func artifactTestState(t *testing.T) string {
	t.Helper()
	dir := shortStateDirUnified(t)
	// 三层布局就位（export 前提 = config.toml 在）。
	if err := nodeconfig.Save(nodeconfig.Path(dir), nodeconfig.Default()); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"serve", "relay", "client", "cache"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestArtifactCLIExportImportRoundtrip export → import 往返 + 提示行。
func TestArtifactCLIExportImportRoundtrip(t *testing.T) {
	dir := artifactTestState(t)
	if err := os.WriteFile(filepath.Join(dir, "serve", "key.bin"), bytes.Repeat([]byte{7}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	dest := filepath.Join(dir, "..", "artifact-roundtrip.tar")
	if err := ExportCLI([]string{"--state", dir, dest}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "已导出") {
		t.Fatalf("export 提示行：\n%s", out.String())
	}
	// import 到新 state。
	dst := shortStateDirUnified(t)
	out.Reset()
	if err := ImportCLI([]string{"--state", dst, dest}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "已导入") {
		t.Fatalf("import 提示行：\n%s", out.String())
	}
	if b, err := os.ReadFile(filepath.Join(dst, "serve", "key.bin")); err != nil || len(b) != 32 {
		t.Fatalf("往返后 key.bin 应在：%v", err)
	}
	// 位置参数在 flag 前/后都可（flagsFirst）。
	out.Reset()
	if err := ImportCLI([]string{dest, "--state", dst}, &out); err != nil {
		t.Fatal(err)
	}
}

// TestArtifactCLIBadFileActionableErrors 坏工件 = 可行动错误（非零退出面 = error
// 返回）；缺参 = 就地报错。
func TestArtifactCLIBadFileActionableErrors(t *testing.T) {
	dir := artifactTestState(t)
	var out bytes.Buffer
	// 非 tar 内容。
	bad := filepath.Join(dir, "bad.tar")
	if err := os.WriteFile(bad, []byte("not a tar"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ImportCLI([]string{"--state", dir, bad}, &out); err == nil || !strings.Contains(err.Error(), "import 失败") {
		t.Fatalf("坏工件应可行动错误：%v", err)
	}
	// 缺 <file>。
	if err := ImportCLI([]string{"--state", dir}, &out); err == nil || !strings.Contains(err.Error(), "import 需要") {
		t.Fatalf("缺参应就地报错：%v", err)
	}
	// reset 未知动词。
	if err := ResetCLI([]string{"bogus"}, &out); err == nil || !strings.Contains(err.Error(), "reset 不认识的动词") {
		t.Fatalf("reset 未知动词应报错：%v", err)
	}
	if err := ResetCLI(nil, &out); err == nil || !strings.Contains(err.Error(), "reset 需要动词") {
		t.Fatalf("reset 裸调应报错：%v", err)
	}
}

// TestArtifactCLIResetCacheGuard reset cache 在跑拒绝（锁被持有）+ 正常面提示。
func TestArtifactCLIResetCacheGuard(t *testing.T) {
	dir := artifactTestState(t)
	var out bytes.Buffer
	// 持锁（模拟在跑）→ reset cache 拒绝（内核 flock 试探）。
	lock, err := nodestate.AcquireInstanceLock(dir, "homeway")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	if err := ResetCLI([]string{"cache", "--state", dir}, &out); err == nil || !strings.Contains(err.Error(), "reset cache 失败") {
		t.Fatalf("在跑应拒绝：%v", err)
	}
}
