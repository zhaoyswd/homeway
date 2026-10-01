package nodestate

// lock_test.go — 单实例锁（host-registry-daemon 2.1，HD「守护进程单实例」两场景）：
// 二次实例失败（文案含 pid 与角色）、模拟崩溃后 flock 自动释放（子进程持锁被 KILL，
// 父进程随即取得——flock 随进程死亡由内核释放，无 stale 文件）。

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestInstanceLockSecondAcquireFails(t *testing.T) {
	dir := t.TempDir()
	l1, err := AcquireInstanceLock(dir, "relay")
	if err != nil {
		t.Fatal(err)
	}
	defer l1.Release()

	_, err = AcquireInstanceLock(dir, "relay")
	if err == nil {
		t.Fatal("二次实例应失败")
	}
	msg := err.Error()
	if !strings.Contains(msg, "已在运行") || !strings.Contains(msg, "state=") {
		t.Fatalf("失败文案缺关键信息：%q", msg)
	}
	// FIX-49：锁里记的是**形态**（unified/serve/relay），不再把 role 归一成 homeway
	// 后丢掉这个信息——文案带形态，冷启动窗口/冲突提示才说得清「谁占着 state」。
	if !strings.Contains(msg, "pid ") || !strings.Contains(msg, "形态 relay") {
		t.Fatalf("失败文案应含持有 pid 与形态：%q", msg)
	}
	if !strings.Contains(msg, "pid "+itoa(os.Getpid())) {
		t.Fatalf("失败文案应含持有者 pid=%d：%q", os.Getpid(), msg)
	}
}

// itoa 不引 strconv 的本地小函数（保持断言输出简洁）。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// TestInstanceLockReleasedOnCrash 模拟崩溃后 flock 自动释放：子进程取锁并驻留，
// KILL 后父进程立即可取。
func TestInstanceLockReleasedOnCrash(t *testing.T) {
	if child := os.Getenv("HOMEWAY_DAEMON_LOCK_CHILD"); child != "" {
		// 子进程形态：取锁、落就绪文件（比 stdout 管道稳——测试框架的输出缓冲不参与）、
		// 驻留等被杀（不走 Release：模拟崩溃）。
		l, err := AcquireInstanceLock(child, "daemon")
		if err != nil {
			os.Exit(2)
		}
		defer l.Release()
		if err := os.WriteFile(filepath.Join(child, "child-ready"), []byte("1"), 0o600); err != nil {
			os.Exit(3)
		}
		time.Sleep(30 * time.Second)
		return
	}

	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=TestInstanceLockReleasedOnCrash")
	cmd.Env = append(os.Environ(), "HOMEWAY_DAEMON_LOCK_CHILD="+dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// 等子进程就绪文件（有界轮询）。
	ready := filepath.Join(dir, "child-ready")
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			t.Fatal("子进程 10s 内未取得锁")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// 持锁期间父进程取不到（互斥成立）。
	if _, err := AcquireInstanceLock(dir, "relay"); err == nil {
		_ = cmd.Process.Kill()
		t.Fatal("子进程持锁期间父进程不应取得")
	}

	// KILL（模拟崩溃：不走 Release）→ flock 由内核释放 → 父进程可取。
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	l, err := AcquireInstanceLock(dir, "relay")
	if err != nil {
		t.Fatalf("崩溃释放后应可取得：%v", err)
	}
	defer l.Release()
}

// TestLockHolderInfoForm（FIX-49）：锁文件记录形态，LockHolderInfo 能读出——
// CLI 的冷启动窗口提示据此说清「谁占着 state」（旧格式锁回 legacy:<role>）。
func TestLockHolderInfoForm(t *testing.T) {
	dir := t.TempDir()
	l, err := AcquireInstanceLock(dir, "serve")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	held, pid, form := LockHolderInfo(dir)
	if !held || pid != os.Getpid() || form != "serve" {
		t.Fatalf("LockHolderInfo = (%v,%d,%q)，期望 (true,%d,serve)", held, pid, form, os.Getpid())
	}
	if !LockHeld(dir) {
		t.Fatal("LockHeld 应与 LockHolderInfo 一致")
	}
	// 旧格式锁（只有 role=homeway，无 form）：解析回 legacy:homeway，不谎报已知形态。
	l.Release()
	if err := os.WriteFile(filepath.Join(dir, lockFileName), []byte("pid=1\nrole=homeway\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, oerr := os.Open(filepath.Join(dir, lockFileName))
	if oerr != nil {
		t.Fatal(oerr)
	}
	defer f.Close()
	if pid, form := readLockHolder(f); pid != 1 || form != "legacy:homeway" {
		t.Fatalf("旧格式锁解析 = (%d,%q)，期望 (1,legacy:homeway)", pid, form)
	}
}
