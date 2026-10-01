//go:build cshared

// App 专用：测速壳（openspec tunnel-speedtest / forward-socks-speedtest 3e §1.1–1.2）。
// CLI 不编。
//
// 引擎已收拢 pkg/speedtest.Engine（轮级状态机/窗口对齐/接收端报数/期限与归因/看门狗
// 全在那边——「口径与手机一致由共享实现保证」）；本文件只做三件事：
//   - NAPI 三导出（Start/Status/Cancel）与 JSON 信封**逐字段不变**（导出面 20 个不动）；
//   - 桥鉴权拨号（speedDial：unix 拨 + bridgeWriteAuth）——注入缝错误契约 = 返回
//     *speedtest.DialError{Code}（引擎原样透传：bridge_down/bridge_auth 在这里产生，
//     refused-like 判定与 code 生成归注入缝，r2 新-4）；
//   - 壳层参数前置校验（invalid_arg）与结果信封映射。
//
// 3e 去问候帧后的归因形态：busy/link_down 由引擎在请求-应答相位吃到 report 归因；
// not_supported 三条判据在引擎内（拨号 refused-like=注入缝 code 透传 / 请求后零字节
// EOF / 非 data/report 帧按通道错误）。App 的 SpeedTestRules.ets reason→短因映射零变化。
//
// via/rtt 不在这层取：App 进程没有 Transport，App 侧在开跑时从状态快照冻结。
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/zhaoyswd/homeway/pkg/speedtest"
)

// speedtestServicePort 出口测速服务端口（= homeway internal/server.DefaultSpeedtestPort；
// 改任何一侧都要同步另一侧；app_bridge.go 的 speed-bridge 拨号消费）。
const speedtestServicePort = 7803

// speedLogf 测速判据行（进隧道日志/日志页）。前缀「speedtest: 」写在**调用方的字面量**
// 里——check-code-map.sh 按源码字面 grep，包装器里拼前缀会让判据串搜不到（评审 F8）。
func speedLogf(format string, args ...any) {
	log.Printf(format, args...)
}

// speedParams Start 的入参（JSON；字段名与迁移前逐字一致）。
type speedParams struct {
	Auth     string `json:"auth"`     // 桥鉴权 blob（状态 JSON 的 bridgeAuth）
	Sock     string `json:"sock"`     // speedtest 桥 socket 路径（状态 JSON 的 bridgeSpeedSock）
	DownMs   int64  `json:"downMs"`   // 下行窗口（0 = 10000）
	UpMs     int64  `json:"upMs"`     // 上行窗口（0 = 10000）
	WarmupMs int64  `json:"warmupMs"` // 预热（0 = 2000）
	Streams  int    `json:"streams"`  // 并行流数（0 = 4）
}

// speed 全核唯一的引擎实例（单飞在引擎内；NAPI 在 async work 线程上同步跑完整轮）。
var speed = speedtest.NewEngine(speedLogf)

//export ClientCoreSpeedTestStart
func ClientCoreSpeedTestStart(cParams *C.char) *C.char {
	raw := C.GoString(cParams)
	return speedMarshal(speedStart(raw))
}

//export ClientCoreSpeedTestStatus
func ClientCoreSpeedTestStatus() *C.char {
	return speedMarshal(speedSnapshotJSON(speed.Snapshot()))
}

//export ClientCoreSpeedTestCancel
func ClientCoreSpeedTestCancel() *C.char {
	speed.CancelActive()
	return speedMarshal(map[string]any{"ok": true})
}

// speedStart 同步跑完整轮（NAPI 在 async work 线程上）；失败一律走返回值
// {"ok":false,"reason","msg"}（与迁移前信封逐字段一致）。
func speedStart(raw string) map[string]any {
	var p speedParams
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return speedFail(speedtest.ReasonInvalidArg, fmt.Sprintf("参数不是合法 JSON：%v", err))
	}
	if p.Auth == "" || p.Sock == "" {
		return speedFail(speedtest.ReasonBridgeDown, "桥未就绪（缺 auth/sock：VPN 未连接且服务会话未就绪）")
	}
	params := speedtest.Params{
		Down:    time.Duration(p.DownMs) * time.Millisecond,
		Up:      time.Duration(p.UpMs) * time.Millisecond,
		Warmup:  time.Duration(p.WarmupMs) * time.Millisecond,
		Streams: p.Streams,
	}
	if _, err := params.Normalize(); err != nil {
		return speedFail(speedtest.ReasonInvalidArg, err.Error())
	}
	res := speed.Start(context.Background(), func(ctx context.Context) (net.Conn, error) {
		return speedDial(ctx, p.Auth, p.Sock) // ctx 透传（FIX-39：取消/超时要能打断在途拨号）
	}, params)
	return speedResultJSON(res)
}

// speedDial 拨本机测速桥（注入缝——引擎错误契约：*speedtest.DialError{Code} 透传）：
//   - unix 拨不上 = bridge_down（链路/服务会话都不在）；
//   - 鉴权失败 = bridge_auth。
//
// busy/link_down/not_supported 不在这层产生：去问候帧后它们由引擎在请求-应答相位
// 按三条判据归因（report 帧 / 零字节 EOF / 非 data/report 帧）。
func speedDial(ctx context.Context, authHex, sock string) (net.Conn, error) {
	// 拨号吃 ctx（FIX-39）：引擎的拨号预算/取消经这个 ctx 到达；原实现的
	// net.Dial 完全不看它（超时/取消只能等内核返回）。
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", sock)
	if err != nil {
		return nil, speedtest.DialErrf(speedtest.ReasonBridgeDown, "测速通道暂时不可用（桥未就绪或正在恢复）：%v", err)
	}
	if err := bridgeWriteAuth(conn, authHex); err != nil {
		_ = conn.Close()
		return nil, speedtest.DialErrf(speedtest.ReasonBridgeAuth, "测速通道鉴权失败：%v", err)
	}
	return conn, nil
}

// speedFail 业务失败的统一返回（与迁移前同形态）。
func speedFail(reason, msg string) map[string]any {
	return map[string]any{"ok": false, "reason": reason, "msg": msg}
}

// speedResultJSON 引擎 Result → 手机信封（成功/失败两形态，字段名与迁移前逐字一致）。
func speedResultJSON(res speedtest.Result) map[string]any {
	if !res.OK {
		return map[string]any{"ok": false, "reason": res.Reason, "msg": res.Msg}
	}
	return map[string]any{
		"ok":        true,
		"phase":     string(speedtest.PhaseDone),
		"downBps":   res.DownBps,
		"upBps":     res.UpBps,
		"usageDown": res.UsageDown,
		"usageUp":   res.UsageUp,
		"wallMs":    res.WallMs,
	}
}

// speedSnapshotJSON 引擎 Snapshot → 手机 Status 信封（字段按需出现，与迁移前逐字段
// 一致：usage 随轮次、dir/bytes/instBps 随窗口、elapsedMs 随开跑）。
func speedSnapshotJSON(s speedtest.Snapshot) map[string]any {
	m := map[string]any{
		"phase":  s.Phase,
		"reason": s.Reason,
	}
	if s.Usage != nil {
		m["usageDown"] = s.Usage.Down
		m["usageUp"] = s.Usage.Up
	}
	if s.Live != nil {
		m["dir"] = s.Live.Dir
		m["bytes"] = s.Live.Bytes
		m["instBps"] = s.Live.InstBps
	}
	if s.ElapsedMs >= 0 {
		m["elapsedMs"] = s.ElapsedMs
	}
	return m
}

// ---------- JSON 信封 ----------

func speedMarshal(res map[string]any) *C.char {
	return C.CString(speedMarshalJSON(res))
}

// speedMarshalJSON speedMarshal 的纯 Go 面（返回 string——兜底字节的逐字回归可不经
// cgo 直接测，contract-ledger 2.1；行为与旧一体式逐字相同）。
func speedMarshalJSON(res map[string]any) string {
	out, err := json.Marshal(res)
	if err != nil {
		// 兜底改走 speedFail 构造器（首参 reason 进族⑤词表对账——r2 N-1）；键序用固定
		// 模板钉成与迁移前字面量逐字同形（ok,reason,msg——map 经 json.Marshal 是字母序，
		// 会改字节序）。
		f := speedFail(speedtest.ReasonInvalidArg, "结果序列化失败")
		out = []byte(fmt.Sprintf(`{"ok":false,"reason":%q,"msg":%q}`, f["reason"], f["msg"]))
	}
	return string(out)
}
