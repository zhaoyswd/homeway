package daemon

// state_roles_test.go — 2.2/2.3 判据：state 布局权限位（目录 0700、两个 json 0600）；
// 期望态损坏按默认 + 告警不拒启。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 临时目录装配：权限位断言（目录 0700、roles.json/hosts.json 0600）+ 子目录 + 日志落点。
func TestDaemonStateLayoutPermissions(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenDaemonState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		t.Fatalf("state 目录权限 %o ≠ 0700", perm)
	}
	for _, name := range []string{rolesFileName, hostsFileName} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s 未建：%v", name, err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Fatalf("%s 权限 %o ≠ 0600", name, perm)
		}
	}
	for _, sub := range []string{"identity", "endpoints"} {
		if _, err := os.Stat(filepath.Join(dir, sub)); err != nil {
			t.Fatalf("子目录 %s 未建：%v", sub, err)
		}
	}
	// 日志分级落点：Eventf/Debugf 各落各的文件（沿出口口径的文件名）。
	st.Eventf("布局测试：摘要行")
	st.Debugf("布局测试：细节行")
	for _, name := range []string{"events.log", "debug.log"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s 未落：%v", name, err)
		}
	}

	// 既有 0600 文件重开：权限保持（收紧路径幂等）。
	if err := os.Chmod(filepath.Join(dir, hostsFileName), 0o644); err != nil {
		t.Fatal(err)
	}
	st2, err := OpenDaemonState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	fi, err = os.Stat(filepath.Join(dir, hostsFileName))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("重开后 hosts.json 权限 %o ≠ 0600（收紧未生效）", perm)
	}
}

// 期望态三形态：缺失 = 默认；损坏 = 默认 + 告警不拒启；正常 = 按表。
func TestDesiredStateMissingCorruptAndNormal(t *testing.T) {
	var warns []string
	warnf := func(format string, args ...any) { warns = append(warns, format) }

	// 缺失（空目录）：默认 client 启用。
	dir := t.TempDir()
	ds := loadDesiredState(dir, warnf)
	if !ds.roleEnabled("client") {
		t.Fatal("缺失时应按默认装配（client 启用）")
	}
	if len(warns) != 1 {
		t.Fatalf("缺失应告警一次，实得 %d", len(warns))
	}

	// 损坏：默认 + 告警，**不拒启**（返回默认而非错误）。
	warns = warns[:0]
	if err := os.WriteFile(filepath.Join(dir, rolesFileName), []byte("{不是 json"), 0o600); err != nil {
		t.Fatal(err)
	}
	ds = loadDesiredState(dir, warnf)
	if !ds.roleEnabled("client") {
		t.Fatal("损坏时应按默认装配")
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "损坏") {
		t.Fatalf("损坏应告警一次且含「损坏」：%v", warns)
	}

	// 正常表：显式关闭 client。
	warns = warns[:0]
	if err := os.WriteFile(filepath.Join(dir, rolesFileName), []byte(`{"version":1,"roles":{"client":{"enabled":false}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ds = loadDesiredState(dir, warnf)
	if ds.roleEnabled("client") {
		t.Fatal("显式关闭应生效")
	}
	if len(warns) != 0 {
		t.Fatalf("正常表不应告警：%v", warns)
	}
}

// TestRolesV1UnregisteredDefaultOn v1 兼容（r2 新-2 拍板）：既有 v1 roles.json
// （仅登记 client，control 未登记）→ 未登记角色默认 on（启动后 control 在位）；
// 仅显式 enabled:false 才关；既有 roles.json **不被回写**（字节原样）。
func TestRolesV1UnregisteredDefaultOn(t *testing.T) {
	dir := t.TempDir()
	// 本机在役形态（实测 ~/.config/homeway/daemon/roles.json 同款）：仅 client。
	v1 := `{"version":1,"roles":{"client":{"enabled":true}}}` + "\n"
	p := filepath.Join(dir, rolesFileName)
	if err := os.WriteFile(p, []byte(v1), 0o600); err != nil {
		t.Fatal(err)
	}
	ds := loadDesiredState(dir, func(format string, args ...any) { t.Logf(format, args...) })
	if !ds.roleEnabled("client") {
		t.Fatal("v1 登记的 client 应启用")
	}
	if !ds.roleEnabled("control") {
		t.Fatal("未登记的 control 应默认 on（v1 兼容——启动后 control 角色在位）")
	}
	// 不回写用户 state 文件：字节原样。
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != v1 {
		t.Fatalf("既有 roles.json 不得被回写：\n%s", b)
	}
	// 显式关闭才生效。
	v2 := `{"version":1,"roles":{"client":{"enabled":true},"control":{"enabled":false}}}`
	if err := os.WriteFile(p, []byte(v2), 0o600); err != nil {
		t.Fatal(err)
	}
	ds = loadDesiredState(dir, func(format string, args ...any) {})
	if ds.roleEnabled("control") {
		t.Fatal("显式 enabled:false 应关闭")
	}
	if !ds.roleEnabled("client") {
		t.Fatal("client 不受影响")
	}
}

// daemon 拒绝出口 state 目录（exec-r1 B11 硬拦；自 registry_test.go 随 §4 收拢
// 迁入）：tokens.jsonl = 出口身份特征（签发审计 + 启动加载；daemon 永不写它）。
func TestDaemonRefusesExitStateDir(t *testing.T) {
	dir := t.TempDir()
	if err := checkNotExitState(dir); err != nil {
		t.Fatalf("干净目录不应拦：%v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tokens.jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := checkNotExitState(dir)
	if err == nil || !strings.Contains(err.Error(), "tokens.jsonl") {
		t.Fatalf("含 tokens.jsonl 的目录应报错拒启：%v", err)
	}
}
