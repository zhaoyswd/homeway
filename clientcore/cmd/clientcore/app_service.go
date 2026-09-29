//go:build cshared

// app_service.go — ClientCoreService* 导出面（openspec app-service-session 任务 2.1/2.2）：
// App 进程内、无 TUN 的 WG 会话，VPN 未连接时承载 files/term 两座回环桥。
//
// host-registry-daemon 1.3（D1/A6）：会话状态机与单例守卫已随迁
// clientcore/hostsession/service.go（Session + Default()）；本文件只剩两层**只读适配**——
// ①JSON 解析+校验 → hostsession.Default().Start（注入真实桥工厂 + 非严格身份）；
// ②StatusSnapshot → 状态 JSON（键集合与取值路径与随迁前逐字一致，形状由包装冒烟守）。
// **导出函数签名与返回码逐字不变**。
//
// ⚠️ 坑 56 纪律：本文件禁 log.Fatal*（c-shared 里会 os.Exit 杀死宿主 App 进程），
// 失败一律走状态机的 failed + reason。
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"net"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/hostsession"
)

// serviceStartFromJSON ClientCoreServiceStart 的逻辑体（导出壳只做 C 字符串转换；
// 纯 Go 形态供单测直接调用）。
// 返回码：0 已启动（幂等：starting/ready 下重复调用直接 0）｜-1 上一个实例还在收工｜
// -2 服务日志文件打不开｜-3 配置不是合法 JSON｜-4 token 为空。
func serviceStartFromJSON(config string) int {
	var cfg tunConfig
	if err := json.Unmarshal([]byte(config), &cfg); err != nil {
		return -3
	}
	if cfg.Token == "" {
		return -4
	}
	return hostsession.Default().Start(cfg, hostsession.Options{
		BridgeFactory:  serviceBridgeFactory,
		StrictIdentity: false, // 手机现状（r1 N2）：身份不可持久化时打警告继续——「无论如何先连上」
	})
}

// serviceBridgeFactory 服务会话的回环桥构造（D1/A2：桥实现留守本包——手机侧能力，
// App 沙箱内的 UDS 桥；目录从 IdentityDir 推得，bridgeHost 经导出方法面满足
// hostsession.Bridge）。
func serviceBridgeFactory(cfg hostsession.Config, logf hostsession.Logf, dial func(ctx context.Context, port uint16) (net.Conn, error), dialTimeout time.Duration) hostsession.Bridge {
	return newBridgeHost("服务桥", bridgeDirFromCfg(cfg), logf, dial, dialTimeout)
}

//export ClientCoreServiceStart
func ClientCoreServiceStart(cConfig *C.char) C.int {
	return C.int(serviceStartFromJSON(C.GoString(cConfig)))
}

// serviceStopInternal ClientCoreServiceStop 的逻辑体（纯 Go 形态供单测）。
// 返回 0 = 已收工（或本就没在跑）｜-1 = 等待超时（旧实例仍在收尾；此后 Start 会
// 一直 -1 直到它真正退出 —— 防止同钥匙双会话，调用方应重试 Stop）。
func serviceStopInternal() int {
	return hostsession.Default().Stop()
}

// serviceStatusJSON ClientCoreServiceStatus 的数据源。
// bridgeAuth = 桥鉴权首包 blob 的 hex（魔数+令牌）：只经本进程内存到 ArkTS，
// 不落盘、不进日志/诊断报告（隧道宿主的同名键经 IPC 状态通道分发，语义相同）。
// 形状契约：键集合、缺省条件与随迁前一致（elapsedMs 随 Since、bridge*/link/identity/
// stats 随快照指针缺省）——包装冒烟 + hostsession 快照用例守。
func serviceStatusJSON() string {
	snap := hostsession.Default().Snapshot()
	// 无实例短路（迁移前形状逐字节）：serviceCur == nil 时原实现直接返回
	// `{"state":"idle"}`（不带 reason）。实例一经构造 Since 必非零（构造/每次 setState
	// 都打时间戳），零值 Since 即无实例——冒烟用例逐字节钉住。
	if snap.Since.IsZero() && snap.State == "idle" {
		return `{"state":"idle"}`
	}
	m := map[string]any{
		"state":  snap.State,
		"reason": snap.Reason,
	}
	if !snap.Since.IsZero() {
		m["elapsedMs"] = time.Since(snap.Since).Milliseconds()
	}
	if snap.BridgeAuth != "" {
		m["bridgeAuth"] = snap.BridgeAuth
	}
	if snap.BridgeFilesSock != "" {
		m["bridgeFilesSock"], m["bridgeTermSock"], m["bridgeSpeedSock"] = snap.BridgeFilesSock, snap.BridgeTermSock, snap.BridgeSpeedSock
	}
	if snap.Link != nil {
		m["link"] = map[string]any{"via": snap.Link.Via, "ep": snap.Link.Ep, "at": snap.Link.At, "rttMs": snap.Link.RttMs}
		if snap.Identity != nil {
			m["identity"] = map[string]any{"dev": snap.Identity.Dev, "pub": snap.Identity.Pub}
		}
	}
	if snap.Stats != nil {
		m["stats"] = map[string]any{"rxBytes": snap.Stats.RxBytes, "txBytes": snap.Stats.TxBytes}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return `{"state":"unknown"}`
	}
	return string(b)
}

//export ClientCoreServiceStop
func ClientCoreServiceStop() C.int { return C.int(serviceStopInternal()) }

//export ClientCoreServiceStatus
func ClientCoreServiceStatus() *C.char { return cstr(serviceStatusJSON()) }
