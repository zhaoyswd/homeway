//go:build cshared

// app_probe.go — 添加主机的「token 解析」导出（App 专用）。
//
// 入参就是用户粘贴的那串 token（hmw1…），**不联网**：本地解出后端公钥指纹与端点列表。
// 返回 `{"ok":true,"peer":"…","endpoints":["a:41641","relay:b:41641"]}`，失败 `{"error":"…"}`。
// 之所以不走 CLI（parse/ping）：CLI 路径里可达的 log.Fatal* 会 os.Exit(1)，
// 在 c-shared 里直接杀死宿主 App 进程。
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zhaoyswd/homeway/pkg/proto"
)

//export ClientCoreProbeAddr
func ClientCoreProbeAddr(cToken *C.char) *C.char {
	raw := strings.TrimSpace(C.GoString(cToken))
	tok, err := proto.DecodeToken(raw)
	if err != nil {
		return cstr(errJSON(err.Error()))
	}
	eps := make([]string, 0, len(tok.Endpoints))
	for _, ep := range tok.Endpoints {
		if ep.Relay {
			eps = append(eps, "relay:"+ep.Addr)
		} else {
			eps = append(eps, ep.Addr)
		}
	}
	body, err := json.Marshal(map[string]any{
		"ok":        true,
		"peer":      fmt.Sprintf("%x", tok.PeerID[:6]),
		"endpoints": eps,
	})
	if err != nil {
		return cstr(errJSON(err.Error()))
	}
	return cstr(string(body))
}

func errJSON(msg string) string {
	b, _ := json.Marshal(map[string]string{"error": msg})
	return string(b)
}
