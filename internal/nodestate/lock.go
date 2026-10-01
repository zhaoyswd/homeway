package nodestate

// lock.go — 单实例锁（host-registry-daemon 2.1 起；role-management 2.3 起随统一
// state 合并**全形态共用**：统一进程与 serve/relay 前台单角色都取 <state>/lock，
// 持有者角色名归一为 homeway——同 state 双进程在任何形态组合下互斥）。
//
// flock(LOCK_EX|LOCK_NB) on <state>/lock：取得后写 pid 与角色名；拿不到则读出
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

// lockFileName 单实例锁文件名（内容 = "pid=<n>\nrole=homeway\nform=<形态>\n"）。
const lockFileName = "lock"

// InstanceLock 一个 state 目录的单实例锁句柄。
type InstanceLock struct {
	f    *os.File
	path string
	form string
}

// AcquireInstanceLock 取 <state>/lock 的排他非阻塞锁；成功写 pid + 归一角色（恒
// homeway）+ **形态**（unified/serve/relay），失败读出持有者并报错（错误文案带形态与
// state 路径——能看出是谁占的，D2 组合处置）。形态只作**诊断/文案**（FIX-49：单实例
// 互斥判定不看它，role 曾归一成 homeway ⇒ 锁被持有时 CLI 分不清是统一进程还是前台
// 单角色，冷启动窗口只能给误导性提示 + 白等）。
func AcquireInstanceLock(stateDir, form string) (*InstanceLock, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("单实例锁：建 state 目录 %s 失败：%w", stateDir, err)
	}
	path := filepath.Join(stateDir, lockFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("单实例锁：打开 %s 失败：%w", path, err)
	}
	if err := lockFile(int(f.Fd())); err != nil {
		pid, _ := readLockHolder(f)
		_, _, hform := LockHolderInfo(stateDir)
		_ = f.Close()
		return nil, fmt.Errorf("homeway 已在运行（pid %d，形态 %s，state=%s）——拒绝二次启动",
			pid, formOr(hform), stateDir)
	}
	// 写持有者信息（截断重写：崩溃残留的旧内容不该存活）。
	if err := f.Truncate(0); err == nil {
		_, _ = f.WriteAt([]byte(fmt.Sprintf("pid=%d\nrole=homeway\nform=%s\n", os.Getpid(), form)), 0)
	}
	return &InstanceLock{f: f, path: path, form: form}, nil
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

// readLockHolder 从锁文件读持有者 pid/形态（读不到 = pid 0 / 形态 "?"）。第二个
// 返回值是形态（旧字段名 role——历史内容归一为 homeway）。
func readLockHolder(f *os.File) (int, string) {
	b := make([]byte, 128)
	n, err := f.ReadAt(b, 0)
	if err != nil && n == 0 {
		return 0, "?"
	}
	pid, form := 0, "?"
	for _, line := range strings.Split(string(b[:n]), "\n") {
		if v, ok := strings.CutPrefix(line, "pid="); ok {
			if p, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				pid = p
			}
		}
		if v, ok := strings.CutPrefix(line, "form="); ok {
			form = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(line, "role="); ok && form == "?" {
			// 旧格式（role 归一为 homeway）——形态未知。
			form = "legacy:" + strings.TrimSpace(v)
		}
	}
	return pid, form
}

func formOr(form string) string {
	if form == "" || form == "?" {
		return "未知（旧格式锁或读不到）"
	}
	return form
}

// LockHolderInfo 锁持有者的形态与 pid（FIX-49：CLI 的冷启动窗口/不可达提示要能说清
// 「谁占着 state」）。held = 有活进程持锁（flock 试探同 LockHeld）。
func LockHolderInfo(stateDir string) (held bool, pid int, form string) {
	path := filepath.Join(stateDir, lockFileName)
	// **不带 O_CREATE**（只读探测不该在 state 里造文件；文件不存在 = 还没人取过锁 =
	// 未运行。O_CREATE 形态会让任何一次「未运行判定/import 前置探测」都留下一个 lock）。
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return false, 0, ""
	}
	defer f.Close()
	if err := lockFile(int(f.Fd())); err != nil {
		pid, form = readLockHolder(f)
		return true, pid, form
	}
	_ = unlockFile(int(f.Fd()))
	return false, 0, ""
}

// LockHeld 活进程持锁探测（role-management 4.1「未运行判定」的读半边，r1 低-3）：
// 对 <state>/lock 做与 AcquireInstanceLock 同口径的 flock(LOCK_EX|LOCK_NB) **试探**——
// 拿得到 = 无活进程（残留锁文件不算持锁，flock 随进程死亡由内核释放），拿不到 =
// 进程在跑。CLI 侧的按需拉起据此判定「未运行可拉起」；不引入「pid 文件 + kill -0
// 探活」（lock.go 头注已否决的竞态判定）。非 unix（lockFile 恒成功桩）恒 false
// （= 按「未运行」处理——Windows 拉起 = 可行动错误，方向不变）。
func LockHeld(stateDir string) bool {
	held, _, _ := LockHolderInfo(stateDir)
	return held
}
