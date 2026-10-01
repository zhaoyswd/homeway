package nodestate

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// buildState 造一个新布局 state 夹具（不变量四件全 + cache 杂物 + 根下瞬态）。
func buildState(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	st, err := OpenNodeState(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	write := func(rel, content string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("config.toml", "# 手编 config\n[serve]\nlisten = 41000\n")
	write("serve/key.bin", "K")
	write("serve/tokens.jsonl", "T1\nT2\n")
	write("relay/relay.key", "R")
	write("client/hosts.json", "H")
	write("client/forwards.json", "F")
	write("client/socks.json", "S")
	write("client/identity/master.key", "M")
	write("cache/events.log", "可弃日志\n")
	write("cache/endpoints/p1.json", "EP")
	write("files.sock", "瞬态")
	write("lock", "pid=1\n")
	return dir
}

func tarNames(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var names []string
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, hdr.Name)
	}
	return names
}

func TestExportImportRoundTrip(t *testing.T) {
	src := buildState(t)
	art := filepath.Join(t.TempDir(), "state.tar")
	if err := Export(src, art); err != nil {
		t.Fatal(err)
	}
	// 工件 0600。
	fi, err := os.Stat(art)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("工件权限 %v want 0600", fi.Mode().Perm())
	}
	// 工件不含 cache/ 与 socket/lock（瞬态不参与恢复）。
	for _, name := range tarNames(t, art) {
		if strings.Contains(name, "cache") || strings.HasSuffix(name, ".sock") || strings.HasSuffix(name, "/lock") || name == "lock" {
			t.Fatalf("工件不应含可弃/瞬态条目：%s", name)
		}
	}
	// 全新 state B：import → 不变量四件与源逐字节一致。
	dst := t.TempDir()
	if err := Import(dst, art); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{
		"config.toml", "serve/key.bin", "serve/tokens.jsonl", "relay/relay.key",
		"client/hosts.json", "client/forwards.json", "client/socks.json", "client/identity/master.key",
	} {
		a, aerr := os.ReadFile(filepath.Join(src, rel))
		b, berr := os.ReadFile(filepath.Join(dst, rel))
		if aerr != nil || berr != nil {
			t.Fatalf("%s 读取失败：%v / %v", rel, aerr, berr)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("%s 往返不逐字节一致：%q vs %q", rel, a, b)
		}
	}
	// import 后无 .import-old/.import-tmp 残留；cache 不被 import 创建/清空。
	entries, _ := os.ReadDir(dst)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".import-") {
			t.Fatalf("import 收尾残留：%s", e.Name())
		}
	}
}

func TestExportRequiresLayout(t *testing.T) {
	// config.toml 缺失（旧布局未迁移）：可行动错误。
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, subServe), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Export(dir, filepath.Join(t.TempDir(), "x.tar")); err == nil || !strings.Contains(err.Error(), "config.toml") {
		t.Fatalf("未迁移布局应拒绝 export：%v", err)
	}
}

func TestImportRejectsBadArtifacts(t *testing.T) {
	good := func(t *testing.T) string {
		src := buildState(t)
		art := filepath.Join(t.TempDir(), "s.tar")
		if err := Export(src, art); err != nil {
			t.Fatal(err)
		}
		return art
	}

	// ① 缺件：去掉 client/ 目录条目。
	art := good(t)
	stripped := rewriteTar(t, art, func(h *tar.Header) bool {
		return !(h.Name == exportTop+"/"+subClient+"/" || strings.HasPrefix(h.Name, exportTop+"/"+subClient+"/"))
	})
	err := Import(t.TempDir(), stripped)
	if err == nil || !strings.Contains(err.Error(), "缺件") {
		t.Fatalf("缺件应拒绝：%v", err)
	}
	// ② 多件：加 homeway-export/cache/junk。
	extra := rewriteTar(t, art, nil, appendEntry{header: tar.Header{Name: exportTop + "/cache/junk", Typeflag: tar.TypeReg, Mode: 0o600}, data: []byte("x")})
	err = Import(t.TempDir(), extra)
	if err == nil || !strings.Contains(err.Error(), "多件") {
		t.Fatalf("多件应拒绝：%v", err)
	}
	// ③ 顶层外条目（前缀违规）。
	escape := rewriteTar(t, art, nil, appendEntry{header: tar.Header{Name: "../escape", Typeflag: tar.TypeReg, Mode: 0o600}, data: []byte("x")})
	dst := t.TempDir()
	err = Import(dst, escape)
	if err == nil || !strings.Contains(err.Error(), "违规条目") {
		t.Fatalf("路径违规应拒绝：%v", err)
	}
	if _, lerr := os.Lstat(filepath.Join(dst, "..", "escape")); lerr == nil {
		t.Fatal("绝不能解出 state 目录外的文件")
	}
	// ④ 绝对路径条目。
	abs := rewriteTar(t, art, nil, appendEntry{header: tar.Header{Name: "/tmp/absolute-escape", Typeflag: tar.TypeReg, Mode: 0o600}, data: []byte("x")})
	err = Import(t.TempDir(), abs)
	if err == nil || !strings.Contains(err.Error(), "绝对路径") {
		t.Fatalf("绝对路径条目应拒绝：%v", err)
	}
	// ⑤ 符号链接条目。
	link := rewriteTar(t, art, nil, appendEntry{header: tar.Header{Name: exportTop + "/" + subServe + "/key.bin.lnk", Typeflag: tar.TypeSymlink, Mode: 0o777, Linkname: "../../etc/passwd"}})
	err = Import(t.TempDir(), link)
	if err == nil || !strings.Contains(err.Error(), "链接") {
		t.Fatalf("符号链接条目应拒绝：%v", err)
	}
	// ⑥ 异物：config.toml 是目录。
	weird := rewriteTar(t, art, func(h *tar.Header) bool { return h.Name == exportTop+"/config.toml" },
		appendEntry{header: tar.Header{Name: exportTop + "/config.toml/x", Typeflag: tar.TypeReg, Mode: 0o600}, data: []byte("x")})
	err = Import(t.TempDir(), weird)
	if err == nil || !strings.Contains(err.Error(), "缺件") {
		t.Fatalf("config.toml 被换掉应按缺件/异物拒绝：%v", err)
	}
}

// rewriteTar 重写工件：drop 过滤掉条目；extra 追加条目。
func rewriteTar(t *testing.T, path string, drop func(*tar.Header) bool, extra ...appendEntry) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	outPath := filepath.Join(t.TempDir(), "rewritten.tar")
	out, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	tw := tar.NewWriter(out)
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		var data []byte
		if hdr.Typeflag == tar.TypeReg {
			buf := &bytes.Buffer{}
			if _, err := buf.ReadFrom(tr); err != nil {
				t.Fatal(err)
			}
			data = buf.Bytes()
		}
		if drop != nil && drop(hdr) {
			continue
		}
		hdr.Size = int64(len(data))
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if len(data) > 0 {
			if _, err := tw.Write(data); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, e := range extra {
		e.header.Size = int64(len(e.data))
		if err := tw.WriteHeader(&e.header); err != nil {
			t.Fatal(err)
		}
		if len(e.data) > 0 {
			if _, err := tw.Write(e.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return outPath
}

type appendEntry struct {
	header tar.Header
	data   []byte
}

func TestImportRollbackOnPlacementFailure(t *testing.T) {
	src := buildState(t)
	art := filepath.Join(t.TempDir(), "s.tar")
	if err := Export(src, art); err != nil {
		t.Fatal(err)
	}
	dst := buildState(t) // 目标已有全套旧四件

	// 注入：第 3 次 rename 失败（旧四件搬走 4 次 → 失败落在「新件入位」中段）。
	orig := osRename
	n := 0
	osRename = func(oldpath, newpath string) error {
		n++
		if n == 6 {
			return fmt.Errorf("injected disk full")
		}
		return orig(oldpath, newpath)
	}
	defer func() { osRename = orig }()
	err := Import(dst, art)
	osRename = orig
	if err == nil || !strings.Contains(err.Error(), "injected") {
		t.Fatalf("注入失败应上抛：%v", err)
	}
	// 回滚：旧四件归位、逐字节不变、无残留。
	for _, rel := range []string{
		"config.toml", "serve/key.bin", "serve/tokens.jsonl", "relay/relay.key",
		"client/hosts.json", "client/identity/master.key",
	} {
		a, _ := os.ReadFile(filepath.Join(dst, rel))
		if rel == "config.toml" {
			if !strings.Contains(string(a), "listen = 41000") {
				t.Fatalf("%s 回滚后内容不符：%q", rel, a)
			}
			continue
		}
		if len(a) == 0 {
			t.Fatalf("%s 回滚后为空", rel)
		}
	}
	entries, _ := os.ReadDir(dst)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".import-") {
			t.Fatalf("回滚后不应残留 %s", e.Name())
		}
	}
}

func TestImportResetRefuseWhenRunning(t *testing.T) {
	dir := buildState(t)
	// 持有 <state>/lock（模拟统一进程在跑）。
	lf, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer lf.Close()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	src := buildState(t)
	art := filepath.Join(t.TempDir(), "s.tar")
	if err := Export(src, art); err != nil {
		t.Fatal(err)
	}
	if err := Import(dir, art); err == nil || !strings.Contains(err.Error(), "在跑") {
		t.Fatalf("目标进程在跑应拒绝 import：%v", err)
	}
	if err := ResetCache(dir); err == nil || !strings.Contains(err.Error(), "在跑") {
		t.Fatalf("目标进程在跑应拒绝 reset cache：%v", err)
	}
	// state 内容不变（config 还在、未被半改）。
	if b := read(t, filepath.Join(dir, "config.toml")); !strings.Contains(b, "41000") {
		t.Fatalf("import 拒绝后 config 被动了：%q", b)
	}
}

func TestResetCacheBoundary(t *testing.T) {
	dir := buildState(t)
	// 造一个迁移备份（state 顶层——reset cache 不碰，r1 低-7）。
	backup := filepath.Join(dir, "migration-backup-20260101-000000")
	if err := os.MkdirAll(filepath.Join(backup, "daemon"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backup, "daemon/hosts.json"), []byte("BAK"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgBefore := read(t, filepath.Join(dir, "config.toml"))
	serveBefore := read(t, filepath.Join(dir, "serve/tokens.jsonl"))

	if err := ResetCache(dir); err != nil {
		t.Fatal(err)
	}
	// cache/ 清空（重建为空目录）。
	entries, err := os.ReadDir(filepath.Join(dir, subCache))
	if err != nil || len(entries) != 0 {
		t.Fatalf("cache/ 应清空：%v %d", err, len(entries))
	}
	// L1/L2 与 migration-backup 原样。
	if got := read(t, filepath.Join(dir, "config.toml")); got != cfgBefore {
		t.Fatal("reset cache 不得碰 L1")
	}
	if got := read(t, filepath.Join(dir, "serve/tokens.jsonl")); got != serveBefore {
		t.Fatal("reset cache 不得碰 L2")
	}
	if got := read(t, filepath.Join(backup, "daemon/hosts.json")); got != "BAK" {
		t.Fatal("reset cache 不得碰 migration-backup")
	}
}

// TestImportRejectsOversizeArtifact（FIX-55）：工件规模上限（条目数 / 总字节）在
// **解包前**判——10 万个条目的 tar 在旧实现里会被逐条读进内存。
func TestImportRejectsOversizeArtifact(t *testing.T) {
	mkTar := func(entries int, fileSize int64) string {
		path := filepath.Join(t.TempDir(), "big.tar")
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		tw := tar.NewWriter(f)
		// 合法顶层与必件（否则会先撞布局校验，测不到规模闸）。
		if err := tw.WriteHeader(&tar.Header{Name: exportTop + "/", Typeflag: tar.TypeDir, Mode: 0o700}); err != nil {
			t.Fatal(err)
		}
		if err := tw.WriteHeader(&tar.Header{Name: exportTop + "/config.toml", Typeflag: tar.TypeReg, Mode: 0o600, Size: 1}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte("#"))
		for _, sub := range []string{subServe, subRelay, subClient} {
			if err := tw.WriteHeader(&tar.Header{Name: exportTop + "/" + sub + "/", Typeflag: tar.TypeDir, Mode: 0o700}); err != nil {
				t.Fatal(err)
			}
		}
		for i := 0; i < entries; i++ {
			name := fmt.Sprintf("%s/serve/f%05d.bin", exportTop, i)
			if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o600, Size: fileSize}); err != nil {
				t.Fatal(err)
			}
			if fileSize > 0 {
				_, _ = tw.Write(make([]byte, fileSize))
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
		return path
	}

	stateDir := t.TempDir()
	before, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	err = Import(stateDir, mkTar(artifactMaxEntries+10, 0))
	if err == nil || !strings.Contains(err.Error(), "条目数超上限") {
		t.Fatalf("条目数超限应被拒：%v", err)
	}
	// 总量超限：单文件未超 64MB，但累计超 256MB——同样在解包前拦。
	err = Import(stateDir, mkTar(8, 40<<20))
	if err == nil || !strings.Contains(err.Error(), "总字节超上限") {
		t.Fatalf("总字节超限应被拒：%v", err)
	}
	after, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("被拒的 import 不得在 state 里留下任何东西：%v", after)
	}
}
