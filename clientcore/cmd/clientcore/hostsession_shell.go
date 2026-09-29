//go:build cshared

// hostsession_shell.go — cshared 留守面对 clientcode/hostsession 的接缝（host-registry-daemon
// D1「cshared 留守壳/别名清单」16 接缝，r2 A1-2 + r3 闭包补）：类型别名/常量别名/薄壳。
// 留守文件（tunmode/demand/probe_lib/app_bridge…）对移出符号的引用全部经本文件闭合，
// 引用点零改动。
//
// 16 接缝与留守引用点（基线 796c0fb 行号）：
//  1. ExitSession（类型别名）      — demand.go:166、tunmode.go:112/133/143/318/1367
//  2. NewTransport（薄壳）          — tunmode.go 8 处
//  3. Logf（类型别名）              — app_bridge.go:151/177、demand.go:166、tunmode.go:747/1296
//  4. Discard（var 别名）           — tunmode.go:1300（tunLogf）、app_bridge 测试
//  5. WithPrefix（var 别名）        — tunmode.go:747、app_service.go（留守期）
//  6. GetLogf（薄壳 getLogf）       — tunmode.go:747
//  7. RecoverGate（类型别名）       — tunmode.go:115（字段类型）
//     8-10. RecoverR1/R2/R3（常量别名）— tunmode.go:962/1127/1143、demand.go:207、probe_lib.go:239
//  11. RecoverLevelName（薄壳）     — probe_lib.go:242/245
//  12. ClampRecoverLevel（薄壳）    — probe_lib.go:238
//  13. RecoverLevel（类型别名）     — recover.go 留守段（runRecoverAt 形参/闭包）
//  14. RecoverDeps（导出字段直接构造）— recover.go 留守段（runRecoverAt 复合字面量）
//  15. RunRecoverLadder（var 别名） — recover.go 留守段（runRecoverAt 调用）
//  16. RecoverGate.Merge（导出版方法）— recover.go 留守段（runRecoverAt 的 .merge 走 .Merge）
//
// runBoundedAction/errActionTimeout **无壳**（r4 订正：随迁后本包无调用点残留）；
// runRecoverAt/recoverTunnelReady 留守隧道域、不出现在壳清单。
package main

import (
	"github.com/zhaoyswd/homeway/clientcore/hostsession"
	"github.com/zhaoyswd/homeway/clientcore/internal/wgcore"
)

// ---- 接缝 1-2：会话传输面（session.go 随迁） ----

type exitSession = hostsession.ExitSession

func newTransport(s exitSession) *wgcore.Transport { return hostsession.NewTransport(s) }

// newCore（留守期垫片）：原 session.go 的 newCore 未导出随迁；留守 serviceStatusJSON
// 的流量计数经 NewTransport().Core() 等价取核（nil 语义一致：仅测试假会话）。
// 1.3 状态面改读 StatusSnapshot 后本垫片随之消亡。
func newCore(s exitSession) *wgcore.Core {
	if tp := newTransport(s); tp != nil {
		return tp.Core()
	}
	return nil
}

// startSession 起出口会话（wg-native-stack tasks 4.1；随 session.go 迁出后留守在壳文件——
// 它引用留守的 tunRun，属隧道域装配）：homeway token 驱动 —— token 自带后端公钥/凭证种子/
// 端点列表，因此不需要（也拿不到）tailcat 地址那套出口信息/DERP 地图；身份按设计每进程
// 临时生成（后端靠 cap/LRU 兜住累积）。
func startSession(cfg tunConfig, run *tunRun, logf Logf) (exitSession, error) {
	sess, _, err := hostsession.BuildExitSession(cfg, logf)
	if err != nil {
		return nil, err
	}
	run.setClient(sess) // 供 stop 打断暖机、以及 ClientCoreTunRecover 下推恢复阶梯
	return sess, nil
}

// ---- 接缝 3-6：日志设施（logf.go 随迁） ----

type Logf = hostsession.Logf

var (
	Discard    = hostsession.Discard
	WithPrefix = hostsession.WithPrefix
)

func getLogf() Logf { return hostsession.GetLogf() }

// ---- 接缝 7-16：共享恢复阶梯（recover.go 随迁） ----

type recoverGate = hostsession.RecoverGate
type recoverLevel = hostsession.RecoverLevel

const (
	recoverR1 = hostsession.RecoverR1
	recoverR2 = hostsession.RecoverR2
	recoverR3 = hostsession.RecoverR3
)

func recoverLevelName(l recoverLevel) string  { return hostsession.RecoverLevelName(l) }
func clampRecoverLevel(from int) recoverLevel { return hostsession.ClampRecoverLevel(from) }

// runRecoverLadder：hostsession.RunRecoverLadder 的留守别名（var 而非 func——
// 壳清单明示「或薄壳」，两形态等价）。
var runRecoverLadder = hostsession.RunRecoverLadder

// recoverDeps 随迁后为导出结构 hostsession.RecoverDeps（字段 Probe/Tr/Logf 导出，
// 跨包复合字面量构造——D1 恢复闭包接缝）：留守 runRecoverAt 直接以导出名构造，
// 不再设本地壳类型。

// ---- tunConfig → hostsession.Config（D1：别名 + 薄壳，留守引用零改动） ----

type tunConfig = hostsession.Config
type tunPortForward = hostsession.PortForward

func normalizeTunConfig(cfg *tunConfig) { hostsession.Normalize(cfg) }
