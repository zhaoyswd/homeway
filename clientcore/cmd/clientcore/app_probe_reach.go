//go:build cshared

// app_probe_reach.go — 添加主机的「连通性探测」导出（App 专用，add-host-connectivity）。
//
// 纯 Go 主体（decode → 端点解析/去重 → 并发 PingEx → 结论结构）已提取为共享核
// pkg/probe.Reach（host-cli 1.1：手机 NAPI 与 daemon host.add 服务端同调一份，探测
// 实现不漂移；探测编排与预算常量见 pkg/probe/reach.go）。本文件只剩 NAPI 导出与
// JSON 呈现层：返回 JSON 形状不变（档位判定手机沿用 ArkTS 侧推导）。
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/zhaoyswd/homeway/pkg/probe"
)

// reachResult 单端点结论（只回报活端点；JSON 字段序与既有返回形状逐字节一致——
// 提取前后规范化解对拍守着，host-cli 1.1）。
type reachResult struct {
	EP    string `json:"ep"`
	RTTms int64  `json:"rtt_ms"`
	Build string `json:"build"`
	Relay bool   `json:"relay"`
}

//export ClientCoreProbeReach
func ClientCoreProbeReach(cToken *C.char) *C.char {
	return cstr(probeReachJSON(C.GoString(cToken)))
}

// probeReachJSON：token → 共享探测编排（pkg/probe.Reach）→ JSON（测试直调这里）。
// 成功 `{"ok":true,"peer":"…","endpoints":["a:41641","relay:…"],"results":[{"ep","rtt_ms",
// "build","relay"},…]}`（peer/endpoints 与 ClientCoreProbeAddr 同款——「仍然添加」路径上
// App 仍可用它自动命名与展示；results 只含应答端点，死端点静默）；
// 解析失败 `{"error":"…"}`。
func probeReachJSON(tokenRaw string) string {
	rep, err := probe.Reach(context.Background(), strings.TrimSpace(tokenRaw))
	if err != nil {
		return errJSON(err.Error())
	}
	results := make([]reachResult, 0, len(rep.Results))
	for _, r := range rep.Results {
		results = append(results, reachResult{EP: r.EP, RTTms: r.RTT.Milliseconds(), Build: r.Build, Relay: r.Relay})
	}
	body, err := json.Marshal(map[string]any{
		"ok":        true,
		"peer":      rep.Peer,
		"endpoints": rep.Endpoints,
		"results":   results,
	})
	if err != nil {
		return errJSON(err.Error())
	}
	return string(body)
}
