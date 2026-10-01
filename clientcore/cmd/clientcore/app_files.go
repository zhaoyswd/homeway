//go:build cshared

// App 专用：文件管理（CLI 不编）。
//
// app_files.go 现在只剩**公共壳**：错误/结果类型、传输快照类型、JSON 信封与 cgo 导出。
// 真正的实现在 app_files_native.go（files 原生协议，wg-native-stack tasks 4.2）；
// 旧的 SFTP-over-SSH 实现已随 4.4 删除（历史见 git log 与 HANDOFF）。
//
// 出入口只有 ClientCoreFilesCall 一个 cgo 导出：JSON 进、JSON 出，操作名分发——
// connect/close/list/stat/mkdir/readText/readImage/download/upload/transfers/cancel
// （分发名与语义一个字都没变，ArkTS 零改动）。
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
)

// maxFilesSessions 限制同时存在的文件会话数：正常只有文件页一个；超限驱逐最老的，
// 防止"页面忘了 close"把客户端（UDP socket 等）漏成一串。
const maxFilesSessions = 4

// 会话表已随旧 SFTP 实现删除：原生实现的会话表在 app_files_native.go。
var (
	filesMu   sync.Mutex
	filesNext int
)

func filesLogf(format string, args ...any) {
	log.Printf("[files] "+format, args...)
}

// filesTransfer 一次上传/下载的运行态（transfers 轮询的数据源；原生实现复用）。
type filesTransfer struct {
	id         int
	Direction  string // download | upload
	RemotePath string
	localPath  string // 不进 transfers 输出（仅 Go 侧使用）
	bytes      int64
	total      int64
	err        string
	done       bool
	cancel     chan struct{}
	cancelOnce sync.Once
}

// filesError 带稳定错误码（ArkTS 侧据此给中文归因）。
type filesError struct {
	Code string `json:"code"`
	Msg  string `json:"msg"`
}

func (e *filesError) Error() string { return e.Code + ": " + e.Msg }

// files 桥层归一码词表（filesErrf 首参——contract-ledger 台账族⑥，与 App 的
// FilesRules.ets filesErrorMessage 对账、只增不改；与 pkg/files 协议码〔族④〕是两个
// 独立冻结空间，值交集之外的同名仅为透传巧合。4b 2.1 提常量前是调用点字面量；
// marshal 原为 marshalFiles 兜底里的原始 JSON 字面量，随 2.1 收进构造器）。
const (
	filesCodeBridgeDown = "bridge_down"
	filesCodeBridgeAuth = "bridge_auth"
	filesCodeNoSession  = "no_session"
	filesCodeInvalidArg = "invalid_arg"
	filesCodeOpFailed   = "op_failed"
	filesCodeBusy       = "busy"
	filesCodeMarshal    = "marshal"
)

func filesErrf(code, format string, args ...any) *filesError {
	return &filesError{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// filesResult 是操作的成功载荷（与 error 二选一）。
type filesResult map[string]any

// filesEntry 列表条目（ArkTS 侧排序展示，Go 只回原始事实）。
type filesEntry struct {
	Name    string `json:"name"`
	IsDir   bool   `json:"isDir"`
	Size    int64  `json:"size"`
	MtimeMs int64  `json:"mtimeMs"`
}

func filesDispatch(opJson string) string {
	return nativeFilesDispatch(opJson)
}

func marshalFiles(res filesResult, ferr *filesError) string {
	out := map[string]any{}
	for k, v := range res {
		out[k] = v
	}
	if ferr != nil {
		out["error"] = ferr
	} else {
		out["ok"] = true
	}
	b, err := json.Marshal(out)
	if err != nil {
		// 兜底走构造器（marshal 进族⑥ active 集、可提取——r2 N-1）；marshalFiles(nil, …)
		// 输出与旧原始 JSON 字面量逐字同形（error 单键 map）。
		return marshalFiles(nil, filesErrf(filesCodeMarshal, "结果序列化失败"))
	}
	return string(b)
}

//export ClientCoreFilesCall
func ClientCoreFilesCall(cOp *C.char) *C.char {
	return cstr(filesDispatch(C.GoString(cOp)))
}
