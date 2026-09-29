package daemon

// lock.go — 守护进程单实例锁（host-registry-daemon 2.1，HD「守护进程单实例」；D3）。
//
// flock(LOCK_EX|LOCK_NB) on <state>/lock：取得后写 pid 与**角色名**；拿不到则读出
// 持有 pid 报错退出（文案带角色与 state 路径）。flock 随进程死亡由内核自动释放
//（无 stale 文件问题；备选「pid 文件 + kill -0 探活」否决：竞态窗口 + 僵尸 pid 误判）。
// 锁在装配最早处取（先于任何 socket/会话）。
//
// 平台拆分（r1 A3）：flock 调用在 lock_unix.go / lock_other.go（非 unix 恒成功降级，
// 参照 pkg/egress/bind_*.go 先例）——windows 桩门（GOOS=windows CGO_ENABLED=0
// go build ./internal/daemon/...）依赖本包不引 unix.Flock。

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// lockFileName 单实例锁文件名（内容 = "pid=<n>\nrole=<role>\n"）。
const lockFileName = "lock"

// InstanceLock 一个 state 目录的单实例锁句柄。
type InstanceLock struct {
	f    *os.File
	path string
	role string
}

// AcquireInstanceLock 取 <state>/lock 的排他非阻塞锁；成功写 pid+角色，失败读出
// 持有者并报错（错误文案带角色与 state 路径——exit 与 daemon 同目录并存时能看出
// 是谁占的，D2 组合处置）。
func AcquireInstanceLock(stateDir, role string) (*InstanceLock, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("单实例锁：建 state 目录 %s 失败：%w", stateDir, err)
	}
	path := filepath.Join(stateDir, lockFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("单实例锁：打开 %s 失败：%w", path, err)
	}
	if err := lockFile(int(f.Fd())); err != nil {
		pid, hrole := readLockHolder(f)
		_ = f.Close()
		return nil, fmt.Errorf("homeway %s 已在运行（pid %d，角色 %s，state=%s）——拒绝二次启动",
			role, pid, hrole, stateDir)
	}
	// 写持有者信息（截断重写：崩溃残留的旧内容不该存活）。
	if err := f.Truncate(0); err == nil {
		_, _ = f.WriteAt([]byte(fmt.Sprintf("pid=%d\nrole=%s\n", os.Getpid(), role)), 0)
	}
	return &InstanceLock{f: f, path: path, role: role}, nil
}

// Release 主动释放（进程退出时内核也会自动释放；幂等）。
func (l *InstanceLock) Release() {
	if l == nil || l.f == nil {
		return
	}
	_ = unlockFile(int(l.f.Fd()))
	_ = l.f.Close()
	l.f = nil
}

// readLockHolder 从锁文件读持有者 pid/角色（读不到 = pid 0 / 角色 "?"）。
func readLockHolder(f *os.File) (int, string) {
	b := make([]byte, 128)
	n, err := f.ReadAt(b, 0)
	if err != nil && n == 0 {
		return 0, "?"
	}
	pid, role := 0, "?"
	for _, line := range strings.Split(string(b[:n]), "\n") {
		if v, ok := strings.CutPrefix(line, "pid="); ok {
			if p, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				pid = p
			}
		}
		if v, ok := strings.CutPrefix(line, "role="); ok {
			role = strings.TrimSpace(v)
		}
	}
	return pid, role
}
