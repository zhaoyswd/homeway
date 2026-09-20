// Package server：两级日志（2026-09-20 用户口径）。
//
// 终端（以及 launchd 的 exit.log）只看**摘要级**：网卡/绑卡、IP（STUN/公网端点）、
// UPnP、token、各服务就绪行。**细节级**（peer 表流水、入站新源、周期观测、盲打、
// 会话/流量过程）写进 state 目录的 debug.log——排查时要看，平时不刷屏；
// --verbose 时细节同时回显到摘要流（终端现场调试用）。
package server

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	dbgMu   sync.Mutex
	dbgFile *os.File
	dbgLog  *log.Logger
	dbgEcho bool // --verbose：细节同时进摘要流
)

// initDebugLog 打开细节日志（<state>/debug.log，追加写）。路径为空或打开失败时
// 细节日志丢弃（不阻塞启动）；返回的 close 在进程退出时调用。
func initDebugLog(stateDir string, echo bool) func() {
	dbgMu.Lock()
	defer dbgMu.Unlock()
	dbgEcho = echo
	if stateDir == "" {
		return func() {}
	}
	f, err := os.OpenFile(filepath.Join(stateDir, "debug.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		// 细节日志开不了不致命：摘要流照常，排查信息这一轮缺失。
		logf("⚠️ 细节日志打开失败（%v）—— debug.log 本轮不可用", err)
		return func() {}
	}
	dbgFile = f
	dbgLog = log.New(f, "", 0)
	return func() {
		dbgMu.Lock()
		defer dbgMu.Unlock()
		if dbgFile != nil {
			_ = dbgFile.Close()
			dbgFile = nil
			dbgLog = nil
		}
	}
}

// dlogf：细节级日志。排查「直连为什么不通」这类问题全靠这些行（入站新源/盲打/周期观测），
// 平时只落 debug.log；--verbose 时同时回显终端。
func dlogf(format string, args ...any) {
	line := time.Now().Format("2006-01-02 15:04:05.000 ") + "[homewayd] " + fmt.Sprintf(format, args...)
	dbgMu.Lock()
	lg := dbgLog
	echo := dbgEcho
	dbgMu.Unlock()
	if echo {
		fmt.Println(line)
	}
	if lg != nil {
		lg.Println(line)
	}
}
