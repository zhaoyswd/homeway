//go:build cshared

// App 专用：c-shared 导出与状态机（CLI 不编）
// probe_lib.go — c-shared 导出层（HarmonyOS HSP 用，非上游代码）。
// 导出面 = 隧道生命周期（Prepare/Attach/Status/Stop/Recover/...）+ 隧道/服务日志 + 探测；
// 运行状态经 TailcatTunStatus 的 JSON 下发（tunStatusJSON），不再有 CLI 命令面。
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"unsafe"
)

var probeRunning atomic.Int32

// tunHealthy 由 tun 的两条 fd 循环维护：fd 读写报错（TUN 被系统收回等）就置 false，
// 让 TailcatTunRunning() 返回 0 —— App 侧据此把状态翻成「已断开」，
// 避免「界面显示已连接、隧道其实已死」的漂谎。
var tunHealthy atomic.Bool

// tunUnhealthyWhy 不健康的原因分类（demand-driven-recovery D3：patrol=传输类（受需求
// 门控）/ fd / panic / stop=设备层与核内部（不门控）。状态 JSON 的 unhealthyReason 消费方
// 是扩展：传输类+无需求 ⇒ 整块拦下终态失败；设备层 ⇒ 立即如实呈现）。
var tunUnhealthyWhy atomic.Value

func cstr(s string) *C.char { return C.CString(s) }

//export TailcatVersion
func TailcatVersion() *C.char {
	v := "(devel)"
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		v = bi.Main.Version
	}
	return cstr(fmt.Sprintf("tier core %s (%s, c-shared)", v, runtime.Version()))
}

// 保持 unsafe 引用（C.CString 返回值由调用方 free）。
var _ = unsafe.Pointer(nil)

// tunStdio 隧道日志/stdout 的重定向状态（两阶段启动下由 prepare 入口建立、世代收工时还原）。
type tunStdio struct {
	out     *os.File
	oldArgs []string
	oldOut  *os.File
	oldErr  *os.File
	oldLogW io.Writer
}

// stdio 重定向是**进程级全局状态**，而世代可能重叠（tunStopWait 3s 超时强制放锁后，旧世代
// 还在收尾时新世代已经 begin）⇒ 必须知道"当前活跃的是谁"，否则旧世代晚到的 end() 会把新世代的
// 重定向一起撤掉。现象：新核的日志从此写到进程真实 stderr，隧道日志文件再无新行（恰在最需要
// 日志的异常重建场景）。
var (
	stdioMu     sync.Mutex
	stdioActive *tunStdio
)

// tunStdioBegin 打开隧道日志（追加写）并把 stdout/stderr/log 重定向过去。
// O_APPEND 而不是 O_TRUNC：隧道日志要跨重连保留（重连后仍能看到上次为什么断），
// 轮转由调用方在启动前做（保留最近一段即可）。
func tunStdioBegin(cfg tunConfig) (*tunStdio, error) {
	s := &tunStdio{oldArgs: os.Args, oldOut: os.Stdout, oldErr: os.Stderr, oldLogW: log.Writer()}
	if cfg.Out != "" {
		f, err := os.OpenFile(cfg.Out, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, err
		}
		s.out = f
	}
	os.Args = []string{"tailcat"}
	if s.out != nil {
		os.Stdout, os.Stderr = s.out, s.out
		log.SetOutput(s.out)
	}
	stdioMu.Lock()
	if prev := stdioActive; prev != nil {
		// **接力**：继承上一个活跃世代的"真正原始目标"，而不是继承它当前的重定向值。
		// 否则链式还原会指向已被它关闭的文件（agent 复核时点名的坑）。
		s.oldOut, s.oldErr, s.oldLogW, s.oldArgs = prev.oldOut, prev.oldErr, prev.oldLogW, prev.oldArgs
	}
	stdioActive = s
	stdioMu.Unlock()
	return s, nil
}

func (s *tunStdio) end() {
	if s.out != nil {
		stdioMu.Lock()
		// 只有"当前活跃的那个"才有权还原 stdout/log；旧世代晚到的 end() 只关自己的文件。
		if stdioActive == s {
			stdioActive = nil
			os.Stdout, os.Stderr = s.oldOut, s.oldErr
			log.SetOutput(s.oldLogW)
		}
		stdioMu.Unlock()
		_ = s.out.Close()
	}
	os.Args = s.oldArgs
}

func (s *tunStdio) panicLine(r any) {
	if s.out != nil {
		fmt.Fprintf(s.out, "\n[probe panic] %v\n%s\n", r, debug.Stack())
	}
}

func (s *tunStdio) errorLine(err error) {
	if s.out != nil {
		fmt.Fprintf(s.out, "[tun error] %v\n", err)
	}
}

// tunBegin 两阶段启动的公共起点：取单飞锁 → 校验配置 → 重定向日志 → 起世代 goroutine；
// TUN fd 之后由 TailcatTunAttach 递进来（prepare 阶段不碰 fd）。
func tunBegin(cConfig *C.char) C.int {
	if !probeRunning.CompareAndSwap(0, 1) {
		return -1
	}
	var cfg tunConfig
	if err := json.Unmarshal([]byte(C.GoString(cConfig)), &cfg); err != nil {
		probeRunning.Store(0)
		return -3
	}
	// 参数预检（同步可判的硬失败，没必要跑一遍暖机）：
	// 只认 homeway token（hmw1…）：空串是唯一能在这一关同步判死的配置错。
	if cfg.Token == "" {
		probeRunning.Store(0)
		return -3
	}
	stdio, err := tunStdioBegin(cfg)
	if err != nil {
		probeRunning.Store(0)
		return -2
	}
	tunUnhealthyWhy.Store("") // 评审 M3：新世代不带上一世代的分类残留（先清——顺序即注释，与写序契约同向）
	tunHealthy.Store(true)    // 本次启动健康；fd 循环异常会置回 false
	run := beginTunRun()      // 新世代：旧世代退出不得再改 probeRunning/tunHealthy
	run.setStageIfCurrent(stagePreparing, "", "", false)

	go func() {
		defer stdio.end()  // 最后执行：还原 stdout/log、关日志文件
		defer run.finish() // 按世代释放单飞锁（旧世代不得清掉新世代的锁）
		defer func() {
			if r := recover(); r != nil {
				stdio.panicLine(r)
			}
		}()
		if err := runTun2Tailcat(cfg, run); err != nil {
			// 硬失败：置失败态供扩展读原因（阶段只会被当前世代改）
			if run.isCurrent() {
				// runTun2Tailcat 已在失败点写过带原因码的失败态；这里兜底（例如 panic 之外的
				// 未归因错误）用通用码，避免把更具体的原因覆盖掉。
				if st, _, _, _ := tunStageSnapshot(); st != stageFailed {
					setStage(stageFailed, "core", err.Error(), false)
				}
			}
			fmt.Fprintln(os.Stderr, "[tun error]", err) // 同时落日志
			stdio.errorLine(err)
		}
	}()
	return 0
}

// TailcatTunPrepare 两阶段启动的第一阶段：暖机（拉地图/建引擎/meow 注册/等 meowed），
// **不需要 TUN fd**。调用后轮询 TailcatTunStatus 直到 state=ready（或 failed）。
// 返回 0 已开始 / -1 忙 / -2 日志文件打不开 / -3 参数错（含 token 为空）。
// 约束：就绪后必须在 attachDeadline 内调 TailcatTunAttach，否则该世代自行收工放锁
// （调用方若要放弃，应主动调 TailcatTunStop）。
//
//export TailcatTunPrepare
func TailcatTunPrepare(cConfig *C.char) C.int { return tunBegin(cConfig) }

// TailcatTunAttach 两阶段启动的第二阶段：把 TUN fd 交给已就绪的世代，开始接管流量。
// 返回 0 已接管 / -1 没有处于 ready 的世代 / -4 接管失败（世代已整体收工，状态可查原因）。
//
//export TailcatTunAttach
func TailcatTunAttach(fd C.int) C.int {
	// fd <= 0 直接拒：`os.NewFile(0)` 是**合法的**（就是进程的 stdin）⇒ fd=0 会让核去读
	// 扩展进程的标准输入，表现成"隧道没流量"这种极难查的现象。组合入口（probe_lib 的
	// tunBegin）一直有这个校验，两阶段入口原来漏了。
	if fd <= 0 {
		setStage(stageFailed, "attach", "attach 收到非法 fd", false)
		return C.int(-3)
	}
	return C.int(attachTun(int(fd)))
}

// TailcatTunStatus 状态查询（JSON）：{"state":"idle|preparing|ready|attached|failed",
// "reason":"...","meowed":bool,"elapsedMs":n,"running":0|1}。
// 扩展以此替代"读日志找 running"：就绪、失败原因、是否已接管都从这里读，日志只用于排查。
//
//export TailcatTunStatus
func TailcatTunStatus() *C.char { return cstr(tunStatusJSON()) }

// TailcatTunStop 停止 tun 模式并等待收尾：扩展要重建隧道时先调它，
// 否则 Go 核的单飞锁会拒绝下一次 TailcatTunStart。
// 返回 0 = 已停止（或本就没在跑），-1 = 等待超时（世代仍在，锁未放），
// **-2 = 等超时后强制放锁**（收工超时且期间没有新世代启动 ⇒ 直接放锁让扩展能重连；
// 此时旧世代的 goroutine 可能还在收尾 —— 所以它写 stage 之前必须过 `setStageIfCurrent`）。
//
//export TailcatTunStop
func TailcatTunStop() C.int { return C.int(tunStopWait()) }

// TailcatTunRecover 恢复阶梯的扩展下推入口（openspec recovery-ladder；收编旧 TailcatTunRebind）：
// from = 起跑档位（1=R1 重握手（保采纳）/ 2=R2 换源（保采纳）/ 3=R3 重赛跑（清采纳），
// 越界钳到边界档；换网重绑 = from 3）。阶梯内自动升级、每档探测先行（详见 recover.go）。
// 返回码契约（改这里要同步 ArkTS 侧 rebindRcText/attribute 与 AGENTS）：
//
//	 0 = 某档探测通过（恢复）；-1 = 走完 R3 仍对端不可达（应升级整套重建）；
//	-2 = 当前没有已接管数据面的隧道（不构成网络结论）；-3 = 本地动作超时（挂起期/低功耗）；
//	-4 = 本地动作立即失败（或没有新栈传输门面）。
//
//export TailcatTunRecover
func TailcatTunRecover(from C.int) C.int {
	raw := int(from)
	lvl := clampRecoverLevel(raw)
	if raw < int(recoverR1) || raw > int(recoverR3) {
		// 越界档位钳到边界档（评审建议：别静默降级，留一行现场证据）
		if r := currentTunRun(); r != nil {
			tunLogf(r)("TailcatTunRecover 收到越界档位 %d，已钳到 %d（%s）", raw, int(lvl), recoverLevelName(lvl))
		}
	}
	return C.int(runRecoverAt(lvl, fmt.Sprintf("扩展下推(%s)", recoverLevelName(lvl))))
}

//export TailcatTunRunning
func TailcatTunRunning() C.int { return C.int(tunRunningValue()) }

// TailcatTunSetForeground 由扩展下发"App 是否在前台"（1 = 前台，0 = 后台）。
// 巡检节拍固定 60s、不随前后台变；此调用只在"回到前台"的转变时补探一次，
// 让界面链路快照在用户注视恢复时立即新鲜。只影响巡检时机，不影响隧道本身。
// 返回上一状态（0/1），便于调用方确认下发是否生效。
//
//export TailcatTunSetForeground
func TailcatTunSetForeground(fg C.int) C.int {
	prev := tunForeground.Load()
	setTunForeground(fg != 0)
	if prev {
		return 1
	}
	return 0
}

// TailcatTunSetActivity 需求信号下发（demand-driven-recovery D1/D5）：扩展每拍上报
// 「App 是否前台（fg）」与「设备是否亮屏（screen）」，两处独立于 SetForeground 的
// 「false→true 才踢巡检」语义——本入口每拍必发、核按最新值 + 新鲜期（90s）参与
// 巡检证据门控与状态 JSON 的 demand 段。唤醒拍（notePumpGap 后）扩展会立即补发一次，
// 保证「先刷新需求位再评估升级」的时序。
//
//export TailcatTunSetActivity
func TailcatTunSetActivity(fg, screen C.int) {
	setTunActivity(fg != 0, screen != 0)
}
