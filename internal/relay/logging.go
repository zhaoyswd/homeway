// Package relay：两级日志（2026-09-21 用户口径：终端只出 token 与端点信息）。
//
//	ulogf —— 用户流（终端）：只放 token/端点公告（启动一次 + 端口/地址变化时重打）；
//	         同时抄进 <state>/relay.log。
//	logf  —— <state>/relay.log（2MB×3 轮转）：中继的全部运行日志（注册腿/会话/回收/
//	         分钟统计/告警）。2026-09-21 前这些打终端，现全部收进文件。
//
// 中继转发逻辑（relay.go/control.go）经 Config.Logf 注入，CLI 接的是这里的 logf；
// 测试继续注入自己的收集器，不受影响。
package relay

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/zhaoyswd/homeway/internal/logfile"
)

const relayLogPrefix = "2006-01-02 15:04:05.000 [homeway-relay] "

var (
	rlogMu sync.Mutex
	rlW    *logfile.Writer
)

// initRelayLog 立起 <state>/relay.log（CLI 在参数解析后调用）。
func initRelayLog(stateDir string) {
	if stateDir == "" {
		return
	}
	rlogMu.Lock()
	defer rlogMu.Unlock()
	if rlW != nil && rlW.Path() == stateDir+"/relay.log" {
		return
	}
	if rlW != nil {
		rlW.Close()
		rlW = nil
	}
	w, err := logfile.Open(stateDir, "relay.log", 2<<20, 3)
	if err != nil {
		// 打不开不致命（中继没有必须落盘的状态）：终端提示一句，服务继续。
		fmt.Fprintln(os.Stderr, "homeway-relay: ⚠️ 文件日志打开失败（", err, "）—— 本轮日志缺失，服务继续")
		return
	}
	rlW = w
}

// relayLogPath：relay.log 路径（未初始化时空串）。
func relayLogPath() string {
	rlogMu.Lock()
	defer rlogMu.Unlock()
	if rlW != nil {
		return rlW.Path()
	}
	return ""
}

func rstamp() string { return time.Now().Format(relayLogPrefix) }

// ulogf：用户流 —— 终端只走这一条路（token/端点公告），同时抄进 relay.log。
func ulogf(format string, args ...any) {
	line := rstamp() + fmt.Sprintf(format, args...)
	fmt.Println(line)
	rlogMu.Lock()
	w := rlW
	rlogMu.Unlock()
	if w != nil {
		_, _ = w.Write([]byte(line + "\n"))
	}
}

// logf：运行日志 —— relay.log（终端不再出现）。
func logf(format string, args ...any) {
	line := rstamp() + fmt.Sprintf(format, args...)
	rlogMu.Lock()
	w := rlW
	rlogMu.Unlock()
	if w != nil {
		_, _ = w.Write([]byte(line + "\n"))
	}
}
