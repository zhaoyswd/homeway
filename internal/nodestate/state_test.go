package nodestate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zhaoyswd/homeway/internal/nodeconfig"
)

// oldMacFixture 造旧 Mac 布局夹具（r1 中-12 逐项）：根下 exit 全套 + daemon/ 子目录
// 全套。全部用假数据（token/密钥是凭证，不进测试产物语义——这里只是字节）。
func oldMacFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("key.bin", "FAKE-KEY-32B")
	write("tokens.jsonl", `{"secret":"FAKE","endpoints":null,"issued":"2026-01-01T00:00:00Z"}`+"\n")
	write("events.log", "旧出口摘要\n")
	write("events.log.1", "旧出口摘要轮转\n")
	write("debug.log", "旧出口细节\n")
	write("listen_port.txt", "41641\n")
	write("public_endpoint.txt", "1.2.3.4:41641\n")
	write("exit.log", "launchd stdout\n")
	write("exit-stdout.log", "nohup stdout\n")
	write("files.sock", "socket-placeholder") // 根下瞬态（真实是 socket；测试用普通文件占位——不在任何迁移清单里）
	write("daemon/roles.json", `{"version":1,"roles":{"client":{"enabled":true}}}`+"\n")
	write("daemon/hosts.json", `[{"id":"h1"}]`+"\n")
	write("daemon/forwards.json", `[{"listen":8080}]`+"\n")
	write("daemon/socks.json", `[{"port":1080}]`+"\n")
	write("daemon/identity/master.key", "FAKE-MASTER-KEY\n")
	write("daemon/endpoints/peer1.json", `{"eps":[]}`+"\n")
	write("daemon/events.log", "旧 daemon 摘要\n")
	write("daemon/debug.log", "旧 daemon 细节\n")
	write("daemon/control.sock", "sock-placeholder")
	write("daemon/lock", "pid=1\nrole=daemon\n")
	return dir
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestMigrateOldMacLayout(t *testing.T) {
	dir := oldMacFixture(t)
	st, err := OpenNodeState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// 目录树断言（逐项清单全落位）。
	for _, c := range []struct{ path, want string }{
		{"serve/key.bin", "FAKE-KEY-32B"},
		{"serve/tokens.jsonl", `{"secret":"FAKE","endpoints":null,"issued":"2026-01-01T00:00:00Z"}` + "\n"},
		{"client/hosts.json", `[{"id":"h1"}]` + "\n"},
		{"client/forwards.json", `[{"listen":8080}]` + "\n"},
		{"client/socks.json", `[{"port":1080}]` + "\n"},
		{"client/identity/master.key", "FAKE-MASTER-KEY\n"},
		{"cache/endpoints/peer1.json", `{"eps":[]}` + "\n"},
		{"cache/events.log", "旧出口摘要\n" + "@PREFIX"}, // 迁移摘要会追加进搬过来的 events.log——只断言历史保留
		{"cache/events.log.1", "旧出口摘要轮转\n"},
		{"cache/debug.log", "旧出口细节\n"},
		{"cache/listen_port.txt", "41641\n"},
		{"cache/public_endpoint.txt", "1.2.3.4:41641\n"},
		{"cache/exit.log", "launchd stdout\n"},
		{"cache/exit-stdout.log", "nohup stdout\n"},
		{"cache/daemon-events.log", "旧 daemon 摘要\n"},
		{"cache/daemon-debug.log", "旧 daemon 细节\n"},
	} {
		if strings.HasSuffix(c.want, "@PREFIX") {
			if prefix := strings.TrimSuffix(c.want, "@PREFIX"); !strings.HasPrefix(read(t, filepath.Join(dir, c.path)), prefix) {
				t.Fatalf("%s 应保留旧内容前缀 %q", c.path, prefix)
			}
			continue
		}
		if got := read(t, filepath.Join(dir, c.path)); got != c.want {
			t.Fatalf("%s 内容不符：got %q want %q", c.path, got, c.want)
		}
	}
	// 旧位置清空：daemon/ 删除（收尾规则）、根下旧特征文件全消失。
	if _, err := os.Lstat(filepath.Join(dir, "daemon")); !os.IsNotExist(err) {
		t.Fatalf("daemon/ 应已删除（空目录收尾）：%v", err)
	}
	for _, gone := range []string{"key.bin", "tokens.jsonl", "events.log", "listen_port.txt", "public_endpoint.txt", "exit.log", "exit-stdout.log"} {
		if _, err := os.Lstat(filepath.Join(dir, gone)); !os.IsNotExist(err) {
			t.Fatalf("根下旧特征文件 %s 应已迁走", gone)
		}
	}
	// 根下瞬态不迁移（files.sock 留在原位）。
	if _, err := os.Lstat(filepath.Join(dir, "files.sock")); err != nil {
		t.Fatalf("根下瞬态 files.sock 不该被迁移：%v", err)
	}
	// config 生成：旧 exit 布局 ⇒ serve.enabled=true（r1 中-9）。
	cfg, err := nodeconfig.Load(nodeconfig.Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Serve.Enabled {
		t.Fatal("旧 exit 布局迁移后 serve.enabled 应为 true")
	}
	// 迁移摘要行进了 cache/events.log（每文件一行落点 + 收尾末行）。
	ev := read(t, filepath.Join(dir, "cache/events.log"))
	for _, want := range []string{"迁移：key.bin → serve/key.bin", "迁移：daemon/hosts.json → client/hosts.json",
		"迁移：daemon/endpoints → cache/endpoints", "迁移：daemon/identity → client/identity",
		"吸收：daemon/roles.json", "旧布局目录已清理", "清理：daemon/control.sock"} {
		if !strings.Contains(ev, want) {
			t.Fatalf("迁移摘要缺行 %q；events.log=\n%s", want, ev)
		}
	}
	// 备份完整：migration-backup-<ts>/ 含全部被动文件（原样拷贝）。
	backup := findBackupDir(t, dir)
	for _, rel := range []string{
		"key.bin", "tokens.jsonl", "events.log", "listen_port.txt", "public_endpoint.txt", "exit.log", "exit-stdout.log", "events.log.1", "debug.log",
		"daemon/roles.json", "daemon/hosts.json", "daemon/forwards.json", "daemon/socks.json",
		"daemon/identity/master.key", "daemon/endpoints/peer1.json", "daemon/events.log", "daemon/debug.log",
	} {
		if _, err := os.Lstat(filepath.Join(backup, rel)); err != nil {
			t.Fatalf("迁移备份缺 %s（%v）", rel, err)
		}
	}
	if got := read(t, filepath.Join(backup, "daemon/hosts.json")); got != `[{"id":"h1"}]`+"\n" {
		t.Fatalf("备份内容应与原文件一致：%q", got)
	}
}

func TestMigrateIdempotentNoSummaryOnRestart(t *testing.T) {
	dir := oldMacFixture(t)
	st, err := OpenNodeState(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	ev1 := read(t, filepath.Join(dir, "cache/events.log"))
	backup1 := findBackupDir(t, dir)

	// 迁移后再启动：零动作、无迁移摘要行、不新增备份目录（r1 中-8 幂等判据）。
	st2, err := OpenNodeState(dir)
	if err != nil {
		t.Fatal(err)
	}
	st2.Close()
	ev2 := read(t, filepath.Join(dir, "cache/events.log"))
	if ev2 != ev1 {
		t.Fatalf("再启动不应追加任何摘要行：\n--第一轮--\n%s\n--第二轮--\n%s", ev1, ev2)
	}
	if got := countDirs(t, dir, "migration-backup-"); got != 1 {
		t.Fatalf("不应新增备份目录：got %d", got)
	}
	_ = backup1
}

func TestMigrateTargetExistsSkips(t *testing.T) {
	dir := oldMacFixture(t)
	// 预置新布局已有件：client/hosts.json 已存在 → daemon/hosts.json 跳过 + 告警。
	if err := os.MkdirAll(filepath.Join(dir, "client"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "client/hosts.json"), []byte("NEW\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := OpenNodeState(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	if got := read(t, filepath.Join(dir, "client/hosts.json")); got != "NEW\n" {
		t.Fatalf("目标已存在时不得覆盖：%q", got)
	}
	if got := read(t, filepath.Join(dir, "daemon/hosts.json")); got != `[{"id":"h1"}]`+"\n" {
		t.Fatalf("跳过项应留在原地：%q", got)
	}
	ev := read(t, filepath.Join(dir, "cache/events.log"))
	if !strings.Contains(ev, "跳过：daemon/hosts.json → client/hosts.json（目标已存在，保留原地）") {
		t.Fatalf("跳过应有告警行：\n%s", ev)
	}
	// daemon/ 非空（hosts.json 残留）→ 逐文件告警保留、不删目录。
	if _, err := os.Lstat(filepath.Join(dir, "daemon")); err != nil {
		t.Fatalf("daemon/ 非空应保留：%v", err)
	}
	if !strings.Contains(ev, "保留：daemon/hosts.json") {
		t.Fatalf("残留文件应有逐文件告警：\n%s", ev)
	}
	// 再启动：已知项已处理（搬走的搬走、跳过的跳过）——不重复搬迁、不重复打跳过行？
	// 跳过项命中「未迁移的旧特征文件」特征 → 每轮逐文件告警（告警不是迁移摘要）。
	st2, err := OpenNodeState(dir)
	if err != nil {
		t.Fatal(err)
	}
	st2.Close()
	ev2 := read(t, filepath.Join(dir, "cache/events.log"))
	if strings.Count(ev2, "迁移：daemon/hosts.json") != 0 {
		t.Fatalf("跳过项不应被搬迁：\n%s", ev2)
	}
}

func TestMigrateDaemonOnlyDisablesServe(t *testing.T) {
	// 仅旧 daemon 布局（无根下 tokens.jsonl/key.bin）⇒ serve.enabled=false（r1 中-9）。
	dir := t.TempDir()
	for _, rel := range []string{"daemon/roles.json", "daemon/hosts.json", "daemon/events.log", "daemon/lock"} {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	st, err := OpenNodeState(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	cfg, err := nodeconfig.Load(nodeconfig.Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Serve.Enabled {
		t.Fatal("仅 daemon 布局迁移应生成 serve.enabled=false（纯 daemon 机不静默开出口）")
	}
	if _, err := os.Lstat(filepath.Join(dir, "daemon")); !os.IsNotExist(err) {
		t.Fatalf("daemon/ 应清空删除：%v", err)
	}
}

func TestOpenFreshState(t *testing.T) {
	// 全新 state：四子目录 + 默认 config（serve.enabled=true——今日零参=出口的连续性）。
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

func TestMigrateConfigExistingNotRegenerated(t *testing.T) {
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

// findBackupDir 找唯一的 migration-backup-<ts> 目录。
func findBackupDir(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var found string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "migration-backup-") {
			if found != "" {
				t.Fatalf("应只有一个备份目录：%s 与 %s", found, e.Name())
			}
			found = filepath.Join(dir, e.Name())
		}
	}
	if found == "" {
		t.Fatal("没有 migration-backup-<ts> 目录")
	}
	return found
}

func countDirs(t *testing.T, dir, prefix string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), prefix) {
			n++
		}
	}
	return n
}
