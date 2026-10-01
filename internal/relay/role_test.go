package relay

// role_test.go — relay 角色生命周期与路径注入（role-management tasks 2.2 验证面）：
// 角色起停（ctx 取消 = 正常收工）、运行中重复 Run 拒、nil 注入 = 现状单旋钮落点
// （relay.key 与 relay.log 同在 StateDir）、注入 = relay.key 在 <D>/relay、relay.log 在
// <D>/cache。快照接口冒烟（label 短指纹/源地址/最近活跃/验证态字段可取）。

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// runRelayRole 起角色并等实际监听地址就绪，返回停止函数。
func runRelayRole(t *testing.T, cfg RoleConfig) (*Role, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	role := NewRole(cfg)
	done := make(chan error, 1)
	go func() { done <- role.Run(ctx) }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cur := role.Current(); cur != nil && cur.LocalAddr().IsValid() {
			return role, func() {
				cancel()
				select {
				case err := <-done:
					if err != nil && err != context.Canceled {
						t.Errorf("角色收工应 nil：%v", err)
					}
				case <-time.After(10 * time.Second):
					t.Error("角色 Run 未在 10s 内收工")
				}
			}
		}
		select {
		case err := <-done:
			t.Fatalf("角色提前退工：%v", err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	t.Fatal("10s 内角色未就绪")
	return nil, nil
}

func shortStateDirRelay(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "rl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// 生命周期 + 运行中重复 Run 拒 + 快照面（监听地址/开放注册位）。
func TestRelayRoleLifecycle(t *testing.T) {
	dir := shortStateDirRelay(t)
	role, stop := runRelayRole(t, RoleConfig{Addr: "127.0.0.1:0", StateDir: dir})
	// 运行中重复 Run 拒。
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	if err := role.Run(ctx2); err == nil || !strings.Contains(err.Error(), "重复启动") {
		t.Fatalf("运行中再 Run 应报重复启动，got %v", err)
	}
	cur := role.Current()
	if cur == nil {
		t.Fatal("运行中应能取到 Relay 实例")
	}
	snap := cur.Snapshot()
	if snap.Listen == "" || !strings.Contains(snap.Listen, "127.0.0.1:") {
		t.Fatalf("快照监听地址形态不对：%q", snap.Listen)
	}
	if snap.Open {
		t.Fatal("Role 恒加载/生成 relay.key（token 模式）——快照的开放注册位应为 false")
	}
	stop()
	if role.Current() != nil {
		t.Fatal("收工后 Current 应为 nil")
	}
}

// nil 注入 = 现状单旋钮：relay.key 与 relay.log 同在 StateDir。
func TestRelayRoleNilInjectionLegacyPaths(t *testing.T) {
	dir := shortStateDirRelay(t)
	_, stop := runRelayRole(t, RoleConfig{Addr: "127.0.0.1:0", StateDir: dir})
	waitRelayFile(t, filepath.Join(dir, "relay.key"))
	stop()
	waitRelayFile(t, filepath.Join(dir, "relay.log"))
	if _, err := os.Stat(filepath.Join(dir, "cache")); !os.IsNotExist(err) {
		t.Fatal("nil 注入不得建 cache/（现状单旋钮缺省）")
	}
}

// 注入 = D3 拆分表：relay.key 在 <D>/relay、relay.log 在 <D>/cache。
func TestRelayRoleInjectedPaths(t *testing.T) {
	dir := shortStateDirRelay(t)
	_, stop := runRelayRole(t, RoleConfig{
		Addr:     "127.0.0.1:0",
		StateDir: filepath.Join(dir, "relay"),
		LogDir:   filepath.Join(dir, "cache"),
	})
	waitRelayFile(t, filepath.Join(dir, "relay", "relay.key"))
	stop()
	waitRelayFile(t, filepath.Join(dir, "cache", "relay.log"))
}

// 快照的注册出口列表字段（r1 低-14：label 短指纹/源地址/最近活跃/验证态）——
// 用真注册腿（server 包外的最小后端注册不在本包测试面；这里以Snapshot 的空表 +
// 字段存在性为准，字段语义由 relay_test 的腿用例覆盖）。
func TestRelaySnapshotBackendsFields(t *testing.T) {
	dir := shortStateDirRelay(t)
	role, stop := runRelayRole(t, RoleConfig{Addr: "127.0.0.1:0", StateDir: dir})
	defer stop()
	snap := role.Snapshot()
	if snap.Backends == nil {
		snap.Backends = []BackendBrief{} // 空表合法（无后端注册）
	}
	// 字段名在编译期锁定（防止后人误删字段——渲染层按名取）。
	var b BackendBrief
	_ = b.Label
	_ = b.Addr
	_ = b.LastActive
	_ = b.Verified
	_ = b.CtlVerified
}

func waitRelayFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s 未出现", path)
}
