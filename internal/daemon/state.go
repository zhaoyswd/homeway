package daemon

// state.go — 统一进程的守护侧日志面（role-management 2.3，D1/D11）：
//
//	state 布局本体（三层 + 同根迁移）在 internal/nodestate；本文件只持有**守护侧
//	自有日志**——cache/daemon-events.log（摘要，终端同显）+ cache/daemon-debug.log
//	（细节）。落名沿用迁移映射（旧 daemon 自有 events/debug.log → 前缀改名防与
//	serve 角色的 cache/events.log|debug.log 同名碰撞——nodestate 迁移 1.2 的既定
//	落名，两写者永不同文件）。
//
//	roles.json / hosts.json / identity/ / endpoints/ 的建目录与权限位职责已随
//	roles.json 退役移交：期望态并入 config.toml（nodeconfig）；hosts/身份/端点缓存
//	由 facade 表（Attach <state>/client/）自建自管。

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/zhaoyswd/homeway/internal/logfile"
)

const (
	// hostsFileName 主机表持久化文件名（facade table.go 的既有约定；此处不再
	// 预建——表自管存在性，仅为文档锚点保留）。
	hostsFileName = "hosts.json"

	// 日志分级与轮转沿出口口径（internal/server/logging.go 同款参数）。
	eventsMaxBytes = 2 << 20 // 2MB
	eventsBackups  = 3
	debugMaxBytes  = 8 << 20 // 8MB
	debugBackups   = 2

	logTimePrefix = "2006-01-02 15:04:05.000 [homeway] "
)

// DefaultStateDir 默认 state 目录（统一 state 根；role-management D1：daemon 旧默认
// ~/.config/homeway/daemon 随单进程合并退役，客户端域命令的 --state 默认值随之统一）。
func DefaultStateDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "homeway-state" // 兜底相对路径（无 HOME 的测试环境；实际部署都有）
	}
	return filepath.Join(home, ".config", "homeway")
}

// DaemonState 守护侧日志句柄（cache/daemon-{events,debug}.log）。
type DaemonState struct {
	Dir  string // 统一 state 根（装配层引用）
	logs *daemonLogs
}

// OpenDaemonLogs 装配守护侧日志对（cacheDir = <state>/cache；目录由 OpenNodeState
// 建好）。打开失败只告警不阻断（日志不该挡启动）。
func OpenDaemonLogs(stateDir, cacheDir string) *DaemonState {
	st := &DaemonState{Dir: stateDir, logs: openDaemonLogs(cacheDir)}
	return st
}

// Close 收工（关日志）。
func (st *DaemonState) Close() {
	if st.logs != nil {
		st.logs.close()
	}
}

// Eventf 摘要级日志（daemon-events.log；终端同显——角色生命周期等用户面公告走这条）。
func (st *DaemonState) Eventf(format string, args ...any) {
	if st.logs != nil {
		st.logs.eventf(format, args...)
		return
	}
	fmt.Printf(format+"\n", args...)
}

// Debugf 细节级日志（daemon-debug.log）。
func (st *DaemonState) Debugf(format string, args ...any) {
	if st.logs != nil {
		st.logs.debugf(format, args...)
	}
}

// daemonLogs 两级轮转日志（沿 internal/server/logging.go 的口径；独立实例——与
// serve/relay 角色的日志对不同文件，见文件头注）。
type daemonLogs struct {
	sumW *logfile.Writer
	dbgW *logfile.Writer
}

func openDaemonLogs(dir string) *daemonLogs {
	sumW, errE := logfile.Open(dir, "daemon-events.log", eventsMaxBytes, eventsBackups)
	dbgW, errD := logfile.Open(dir, "daemon-debug.log", debugMaxBytes, debugBackups)
	if errE != nil || errD != nil {
		fmt.Fprintf(os.Stderr, "homeway: ⚠️ 守护侧日志打开失败（events: %v debug: %v）——本轮日志缺失，服务继续\n", errE, errD)
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
