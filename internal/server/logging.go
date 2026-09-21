// Package server：三级日志（2026-09-21 用户口径：终端只出 token 与 IP 信息）。
//
//	ulogf —— 用户流（终端）：**只**放 token/端点公告行（启动一次 + IP/端口变化时重打）；
//	         同时抄送一份进摘要文件（排障/取 token 都靠文件：grep 客户端 token events.log）。
//	logf  —— 摘要级（<state>/events.log）：网卡/绑卡、IP（STUN/公网端点）、UPnP、
//	         各服务就绪行、运行期告警。2026-09-21 前这些打终端，现全部收进文件。
//	dlogf —— 细节级（<state>/debug.log）：peer 表流水、入站新源、周期观测、盲打、
//	         会话/流量过程（与旧口径相同）。
//
// 两个文件都走 internal/logfile 的尺寸轮转（events.log 2MB×3、debug.log 8MB×2），
// 总占用有上界；--verbose 时摘要+细节同时回显终端（现场调试用）。
package server

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/zhaoyswd/homeway/internal/logfile"
)

const (
	eventsLogName  = "events.log"
	eventsMaxBytes = 2 << 20 // 2MB
	eventsBackups  = 3
	debugLogName   = "debug.log"
	debugMaxBytes  = 8 << 20 // 8MB
	debugBackups   = 2
	logTimePrefix  = "2006-01-02 15:04:05.000 [homewayd] "
)

var (
	logMu   sync.Mutex
	sumW    *logfile.Writer // 摘要级（events.log）
	dbgW    *logfile.Writer // 细节级（debug.log）
	echoAll bool            // --verbose：摘要+细节同时回显终端
	logDir  string          // 已初始化的 state 目录（同目录重复 init 跳过）
)

// initLogs 立起两级文件日志（摘要 events.log + 细节 debug.log，均轮转）。
// CLI 在参数解析后立刻调用（resolveBind 的告警也得有地方落）；Start 里会幂等再调一次。
func initLogs(stateDir string, echo bool) {
	logMu.Lock()
	defer logMu.Unlock()
	if stateDir == "" {
		return
	}
	if sumW != nil && stateDir == logDir && echo == echoAll {
		return // 同目录重复初始化（CLI→Start 两跳）：跳过
	}
	closeLogsLocked()
	echoAll = echo
	var errE, errD error
	sumW, errE = logfile.Open(stateDir, eventsLogName, eventsMaxBytes, eventsBackups)
	dbgW, errD = logfile.Open(stateDir, debugLogName, debugMaxBytes, debugBackups)
	if errE == nil {
		logDir = stateDir
	}
	// 打不开不致命：终端提示一句（「文件日志不可用」本身要让人知道），服务照常。
	if errE != nil || errD != nil {
		fmt.Fprintln(os.Stderr, "homeway: ⚠️ 文件日志打开失败（events:", errE, "debug:", errD,
			"）—— 本轮日志缺失，服务继续")
	}
}

// EventsLogPath：摘要日志路径（给「日志在哪」的提示行用；未初始化时空串）。
func EventsLogPath() string {
	logMu.Lock()
	defer logMu.Unlock()
	if sumW != nil {
		return sumW.Path()
	}
	return ""
}

// closeLogs 收工（幂等；Server.Close 里调用）。
func closeLogs() {
	logMu.Lock()
	defer logMu.Unlock()
	closeLogsLocked()
}

func closeLogsLocked() {
	if sumW != nil {
		sumW.Close()
		sumW = nil
	}
	if dbgW != nil {
		dbgW.Close()
		dbgW = nil
	}
	logDir = ""
}

func stamp() string { return time.Now().Format(logTimePrefix) }

// ulogf：用户流 —— 终端只走这一条路（token/端点公告），同时抄进摘要文件。
func ulogf(format string, args ...any) {
	line := stamp() + fmt.Sprintf(format, args...)
	fmt.Println(line)
	logMu.Lock()
	w := sumW
	logMu.Unlock()
	if w != nil {
		_, _ = w.Write([]byte(line + "\n"))
	}
}

// logf：摘要级 —— events.log（--verbose 时回显终端）。
func logf(format string, args ...any) {
	line := stamp() + fmt.Sprintf(format, args...)
	logMu.Lock()
	w, echo := sumW, echoAll
	logMu.Unlock()
	if echo {
		fmt.Println(line)
	}
	if w != nil {
		_, _ = w.Write([]byte(line + "\n"))
	}
}

// dlogf：细节级 —— debug.log（--verbose 时回显终端）。
// 排查「直连为什么不通」这类问题全靠这些行（入站新源/盲打/周期观测）。
func dlogf(format string, args ...any) {
	line := stamp() + fmt.Sprintf(format, args...)
	logMu.Lock()
	w, echo := dbgW, echoAll
	logMu.Unlock()
	if echo {
		fmt.Println(line)
	}
	if w != nil {
		_, _ = w.Write([]byte(line + "\n"))
	}
}
