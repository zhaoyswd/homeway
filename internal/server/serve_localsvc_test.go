package server

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// listenLocalService 的行为表（exit-service-uds 评审整改 2026-09-22）：
// 正常 / 超长路径 / 死残留（异常退出留下的孤儿 socket 文件）/ 活实例占用
// （同 state 双实例：不抢路径、先到先得）/ Close 只删自己 bind 出来的文件。

// shortDir：t.TempDir() 在 macOS 上路径 ~90B，会顶到 sun_path 上限——测试用
// 短前缀目录（与 App 侧 shortBridgeDir 同款坑）。
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "hw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func TestListenLocalServiceNormal(t *testing.T) {
	dir := shortDir(t)
	sock, ln, own, err := listenLocalService(dir, "svc.sock")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	if own == nil {
		t.Fatal("应返回 bind 出的文件身份")
	}
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("socket 文件应存在: %v", err)
	}
	// 收线时按身份清掉。
	defer removeSockOwn(sock, own)
	ln.Close()
	removeSockOwn(sock, own)
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("Close 后 socket 文件应被清掉: %v", err)
	}
}

func TestListenLocalServiceTooLong(t *testing.T) {
	dir := shortDir(t)
	// 名字凑到 ≥100B（sun_path 保守上限）。
	name := strings.Repeat("s", 100-len(filepath.Join(dir, "")))
	sock, ln, _, err := listenLocalService(dir, name)
	if err == nil {
		ln.Close()
		t.Fatal("超长路径应快速失败")
	}
	if !strings.Contains(err.Error(), "路径超长") {
		t.Fatalf("错误口径不符: %v", err)
	}
	if sock == "" {
		t.Fatal("出错也应带出路径")
	}
}

// 死残留：bind 后异常退出（无 Close）留下的孤儿文件——清掉重绑应成功。
func TestListenLocalServiceStaleResidue(t *testing.T) {
	dir := shortDir(t)
	sock, ln, _, err := listenLocalService(dir, "svc.sock")
	if err != nil {
		t.Fatal(err)
	}
	ul := ln.(*net.UnixListener)
	ul.SetUnlinkOnClose(false) // 模拟「死主人」：关监听但文件仍在（拨它 = ECONNREFUSED）
	ln.Close()
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("残留文件应在: %v", err)
	}
	_, ln2, _, err2 := listenLocalService(dir, "svc.sock")
	if err2 != nil {
		t.Fatalf("死残留应被清理并重绑: %v", err2)
	}
	defer ln2.Close()
}

// 活实例占用：第二个 listenLocalService 不得抢路径（不删活 socket、报占用）。
func TestListenLocalServiceLiveOccupant(t *testing.T) {
	dir := shortDir(t)
	sock, ln, own, err := listenLocalService(dir, "svc.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	defer removeSockOwn(sock, own)

	_, ln2, _, err2 := listenLocalService(dir, "svc.sock")
	if err2 == nil {
		ln2.Close()
		t.Fatal("活实例占用时应报错（先到先得），不得抢路径")
	}
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("活实例的 socket 文件不得被删: %v", err)
	}
	// 原监听仍可用：拨得通。
	c, derr := net.DialTimeout("unix", sock, time.Second)
	if derr != nil {
		t.Fatalf("原监听应仍活着: %v", derr)
	}
	c.Close()
}

// Close 的身份比对：路径被别的实例接管后，旧实例的收线不得删掉新实例的文件。
func TestRemoveSockOwnNotOthers(t *testing.T) {
	dir := shortDir(t)
	sock, lnA, ownA, err := listenLocalService(dir, "svc.sock")
	if err != nil {
		t.Fatal(err)
	}
	// A 让位（不删文件——模拟被抢占前的形态）：直接模拟 = A 收线（listener 关、
	// SetUnlinkOnClose(false) 已由 listenLocalService 设置，文件保留）。
	lnA.Close()
	// 确定性构造「路径已被接管」：替身文件在 A 的 inode **仍占用时**先创建（保证 inode ≠ A），
	// 再删原路径、改名占位——rename 不产生新 inode，任何文件系统的分配顺序都骗不过它。
	// （直接让真 B bind 会踩 inode 复用：linux 上刚释放的 inode 号常被发给下一个同路径
	// socket，SameFile 被骗成真——那是 removeSockOwn 身份比对固有的 best-effort 局限，
	// 不是本测试要验证的防线逻辑，见其注释。）
	standin, serr := os.CreateTemp(dir, "takeover-*")
	if serr != nil {
		t.Fatal(serr)
	}
	standin.Close()
	if err := os.Remove(sock); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(standin.Name(), sock); err != nil {
		t.Fatal(err)
	}
	// A 的收线动作（晚到的 Close）：不得删掉接管者的文件。
	removeSockOwn(sock, ownA)
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("接管者的文件被 A 的收线删掉了: %v", err)
	}
	// 清场后 B 真实接管（活监听）：自己的收线正常删除。
	if err := os.Remove(sock); err != nil {
		t.Fatal(err)
	}
	_, lnB, ownB, err := listenLocalService(dir, "svc.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer lnB.Close()
	removeSockOwn(sock, ownB)
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("B 收线后文件应被删: %v", err)
	}
}

