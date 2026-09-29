package daemon

// state.go — daemon state 布局（host-registry-daemon 2.2，D3）：
//
//	<state>/lock            单实例锁（2.1）
//	<state>/roles.json      角色期望态（0600）
//	<state>/hosts.json      主机表（0600，Registry 持有）
//	<state>/identity/       设备身份（复用 wtransport 机制）
//	<state>/endpoints/      端点学习缓存（按 peerID 分文件）
//	<state>/control.sock    控制面（§3 落；本期占位）
//	<state>/events.log      摘要日志（轮转沿出口口径）
//	<state>/debug.log       细节日志（轮转沿出口口径）
//
// 默认 <state> = ~/.config/homeway/daemon（同根子目录：与在役出口 ~/.config/homeway
// 零冲突，3f 身份合并是同根内搬迁）。目录收紧 0700（OpenState 同款：MkdirAll 的
// mode 只对新建生效，既有目录显式 chmod；失败告警不阻断）。

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/zhaoyswd/homeway/internal/logfile"
)

const (
	rolesFileName = "roles.json"

	// 日志分级与轮转沿出口口径（internal/server/logging.go 同款参数）。
	eventsMaxBytes = 2 << 20 // 2MB
	eventsBackups  = 3
	debugMaxBytes  = 8 << 20 // 8MB
	debugBackups   = 2

	logTimePrefix = "2006-01-02 15:04:05.000 [homeway-daemon] "
)

// DefaultStateDir 默认 state 目录（~/.config/homeway/daemon）。
func DefaultStateDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "homeway-daemon-state" // 兜底相对路径（无 HOME 的测试环境；实际部署都有）
	}
	return filepath.Join(home, ".config", "homeway", "daemon")
}

// DaemonState 打开/收紧 state 目录并立起两级日志。
type DaemonState struct {
	Dir  string
	logs *daemonLogs
}

// OpenDaemonState 装配 state：目录 0700（既有收紧）、子目录、0600 的 roles.json/
// hosts.json（缺失则按默认/空表建）、两级轮转日志。roles.json 的**语义**读取走
// loadDesiredState（损坏按默认 + 告警不拒启，D4）；这里只保证文件存在与权限位。
func OpenDaemonState(dir string) (*DaemonState, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// 既有目录收紧（term-host-cli exec-r5 F2 同款：chmod 失败只告警不阻断——
	// 边界还有 json 0600 / socket 0600 那几层兜着）。
	if err := os.Chmod(dir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "homeway daemon: ⚠️ state 目录 %s 收紧 0700 失败（%v）——建议手工 chmod\n", dir, err)
	}
	for _, sub := range []string{"identity", "endpoints"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, err
		}
	}
	if err := ensureFile0600(filepath.Join(dir, rolesFileName), defaultRolesJSON); err != nil {
		return nil, err
	}
	if err := ensureFile0600(filepath.Join(dir, hostsFileName), "[]\n"); err != nil {
		return nil, err
	}
	st := &DaemonState{Dir: dir, logs: openDaemonLogs(dir)}
	return st, nil
}

// Close 收工（关日志）。
func (st *DaemonState) Close() {
	if st.logs != nil {
		st.logs.close()
	}
}

// Eventf 摘要级日志（events.log；终端同显——daemon 的用户面公告走这条）。
func (st *DaemonState) Eventf(format string, args ...any) {
	if st.logs != nil {
		st.logs.eventf(format, args...)
		return
	}
	fmt.Printf(format+"\n", args...)
}

// Debugf 细节级日志（debug.log）。
func (st *DaemonState) Debugf(format string, args ...any) {
	if st.logs != nil {
		st.logs.debugf(format, args...)
	}
}

// ensureFile0600 文件不存在则按给定内容创建（0600）；存在则只收紧权限位。
func ensureFile0600(path, content string) error {
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return os.WriteFile(path, []byte(content), 0o600)
	} else if err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// daemonLogs 两级轮转日志（沿 internal/server/logging.go 的口径；daemon 侧独立
// 实例——不与出口进程共 state）。
type daemonLogs struct {
	sumW *logfile.Writer
	dbgW *logfile.Writer
}

func openDaemonLogs(dir string) *daemonLogs {
	sumW, errE := logfile.Open(dir, "events.log", eventsMaxBytes, eventsBackups)
	dbgW, errD := logfile.Open(dir, "debug.log", debugMaxBytes, debugBackups)
	if errE != nil || errD != nil {
		fmt.Fprintf(os.Stderr, "homeway daemon: ⚠️ 文件日志打开失败（events: %v debug: %v）——本轮日志缺失，服务继续\n", errE, errD)
	}
	return &daemonLogs{sumW: sumW, dbgW: dbgW}
}

func (l *daemonLogs) close() {
	if l.sumW != nil {
		l.sumW.Close()
	}
	if l.dbgW != nil {
		l.dbgW.Close()
	}
}

func (l *daemonLogs) stamp() string { return time.Now().Format(logTimePrefix) }

func (l *daemonLogs) eventf(format string, args ...any) {
	line := l.stamp() + fmt.Sprintf(format, args...)
	fmt.Println(line)
	if l.sumW != nil {
		_, _ = l.sumW.Write([]byte(line + "\n"))
	}
}

func (l *daemonLogs) debugf(format string, args ...any) {
	line := l.stamp() + fmt.Sprintf(format, args...)
	if l.dbgW != nil {
		_, _ = l.dbgW.Write([]byte(line + "\n"))
	}
}
