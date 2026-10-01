//go:build cshared

// App 专用：终端服务的**一次性操作**（CLI 不编）。
//
// app_term.go — 会话列表 / 终止会话这两件事不需要终端渲染，直接经**终端通道桥**
// （127.0.0.1:7723 → 隧道 → 出口 term 端口，见 app_termbridge.go）说帧协议即可：
// 每次操作开一条短连接、发一帧、读回复、关连接。JSON 进 JSON 出（NAPI 侧整体挪出 JS 线程）。
//
// 帧操作码与协议版本经 import `pkg/term` 编译期锚定（core-homeway-merge 任务 2.6，
// 此前是手抄常量）；帧编解码（3 字节头）与 ERROR/KILL 载荷布局仍是本文件的手抄子集，
// 升级帧格式时须与 homeway `pkg/term/frames.go` 两侧同改。这里只实现一次性操作需要的子集：
// GREETING / LIST / KILL / OK / ERROR。
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/zhaoyswd/homeway/pkg/term"
)

const (
	termDialTimeout = 15 * time.Second
	termIOTimeout   = 15 * time.Second
)

// termError 带稳定错误码（ArkTS 侧映射中文归因）。
type termError struct {
	Code string `json:"code"`
	Msg  string `json:"msg"`
}

func (e *termError) Error() string { return e.Code + ": " + e.Msg }

// term 桥层归一码词表（termErrf 首参——contract-ledger 台账族⑦，与 App 的
// TermRules.ets termErrorMessage 对账、只增不改；与 pkg/term ERROR 帧码〔族③〕是两个
// 独立冻结空间（族③经本层透传消费）。4b 2.1 提常量前是调用点字面量；marshal 原为
// termMarshal 兜底里的原始 JSON 字面量，随 2.1 收进构造器）。
const (
	termCodeBadJson         = "bad_json"
	termCodeInvalidArg      = "invalid_arg"
	termCodeBridgeDown      = "bridge_down"
	termCodeBridgeAuth      = "bridge_auth"
	termCodeTermUnreachable = "term_unreachable"
	termCodeTermForeign     = "term_foreign_service"
	termCodeTermVersion     = "term_version"
	termCodeIO              = "io"
	termCodeBadReply        = "bad_reply"
	termCodeRemote          = "remote"
	termCodeMarshal         = "marshal"
)

func termErrf(code, format string, args ...any) *termError {
	return &termError{Code: code, Msg: fmt.Sprintf(format, args...)}
}

//export ClientCoreTermCall
func ClientCoreTermCall(cOp *C.char) *C.char {
	raw := C.GoString(cOp)
	var op map[string]any
	if err := json.Unmarshal([]byte(raw), &op); err != nil {
		return termMarshal(nil, termErrf(termCodeBadJson, "参数不是合法 JSON：%v", err))
	}
	res, terr := termDispatch(op)
	return termMarshal(res, terr)
}

func termDispatch(op map[string]any) (map[string]any, *termError) {
	name, _ := op["op"].(string)
	auth, _ := op["auth"].(string)
	sock, _ := op["sock"].(string)
	switch name {
	case "list":
		return termList(auth, sock)
	case "kill":
		who, _ := op["name"].(string)
		if who == "" {
			return nil, termErrf(termCodeInvalidArg, "kill 需要 name")
		}
		return termKill(who, auth, sock)
	default:
		return nil, termErrf(termCodeInvalidArg, "未知操作 %q", name)
	}
}

// termDial 经终端桥连到出口的终端服务，并校验 GREETING。
// authHex = 桥鉴权首包 blob（app_bridge.go；隧道宿主经 IPC 拿、服务会话宿主直接读状态）。
func termDial(authHex, sock string) (net.Conn, *termError) {
	if sock == "" {
		return nil, termErrf(termCodeBridgeDown, "终端通道暂时不可用（桥未就绪：VPN 未连接且服务会话未就绪，或正在恢复）")
	}
	conn, err := net.DialTimeout("unix", sock, termDialTimeout)
	if err != nil {
		return nil, termErrf(termCodeBridgeDown, "终端通道暂时不可用（桥未就绪或正在恢复）：%v", err)
	}
	if err := bridgeWriteAuth(conn, authHex); err != nil {
		_ = conn.Close()
		return nil, termErrf(termCodeBridgeAuth, "终端通道鉴权失败：%v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(termIOTimeout))
	code, payload, err := termReadFrame(conn)
	if err != nil {
		_ = conn.Close()
		// 两种可能都在这条分支上：① 出口根本没有 term 服务（官方版/旧版，链路会先被
		// exit-node 回落成本机端口，表现为对端 banner 或直接断开）；② 出口有服务，但**这条
		// 隧道的回程地址已失效**（真机实测：出口侧 `no candidates available for endpoint`
		// → 响应发不回来，终端与文件同时全挂，见 openspec exit-terminal 10.3）。
		// 二者靠"桥能不能拨通 + 对端有没有吐过任何字节"分不开，所以给一个**可行动**的合并文案，
		// 并提示先重连 VPN（这是 ② 的标准恢复动作；① 重连也没用，文案里同样说清了）。
		return nil, termErrf(termCodeTermUnreachable,
			"终端服务没有应答：可能是该出口未启用终端（官方版/旧版 tailcat），"+
				"也可能是本机隧道的回程地址已失效（出口日志会看到 no candidates available for endpoint）。"+
				"先重连一次 VPN；若仍不行，请把出口升级到增强版 tailcat。详情：%v", err)
	}
	if code != term.OpGreeting {
		_ = conn.Close()
		return nil, termErrf(termCodeTermForeign,
			"出口 %d 端口上不是终端服务（收到帧 0x%02x）", termServicePort(), code)
	}
	if len(payload) < 5 || payload[0] != term.ProtoVer {
		_ = conn.Close()
		return nil, termErrf(termCodeTermVersion, "出口终端服务协议版本不匹配（本端 %d）", term.ProtoVer)
	}
	return conn, nil
}

func termList(authHex, sock string) (map[string]any, *termError) {
	conn, terr := termDial(authHex, sock)
	if terr != nil {
		return nil, terr
	}
	defer conn.Close()
	if err := termWriteFrame(conn, term.OpList, nil); err != nil {
		return nil, termErrf(termCodeIO, "发送 LIST 失败：%v", err)
	}
	code, payload, err := termReadFrame(conn)
	if err != nil {
		return nil, termErrf(termCodeIO, "读取 LIST 回复失败：%v", err)
	}
	switch code {
	case term.OpList:
		var out map[string]any
		if err := json.Unmarshal(payload, &out); err != nil {
			return nil, termErrf(termCodeBadReply, "LIST 回复不是合法 JSON：%v", err)
		}
		if out == nil {
			out = map[string]any{}
		}
		if _, ok := out["sessions"]; !ok {
			out["sessions"] = []any{}
		}
		return out, nil
	case term.OpError:
		return nil, termDecodeError(payload)
	default:
		return nil, termErrf(termCodeBadReply, "LIST 回复帧意外（0x%02x）", code)
	}
}

func termKill(name string, authHex, sock string) (map[string]any, *termError) {
	conn, terr := termDial(authHex, sock)
	if terr != nil {
		return nil, terr
	}
	defer conn.Close()
	// KILL 载荷 = [nameLen:1][name]
	payload := make([]byte, 1+len(name))
	payload[0] = byte(len(name))
	copy(payload[1:], name)
	if err := termWriteFrame(conn, term.OpKill, payload); err != nil {
		return nil, termErrf(termCodeIO, "发送 KILL 失败：%v", err)
	}
	code, reply, err := termReadFrame(conn)
	if err != nil {
		return nil, termErrf(termCodeIO, "读取 KILL 回复失败：%v", err)
	}
	switch code {
	case term.OpOK:
		return map[string]any{"killed": name}, nil
	case term.OpError:
		return nil, termDecodeError(reply)
	default:
		return nil, termErrf(termCodeBadReply, "KILL 回复帧意外（0x%02x）", code)
	}
}

// termDecodeError 解 ERROR 载荷：[codeLen:1][code][msgLen:2 LE][msg]。
func termDecodeError(p []byte) *termError {
	if len(p) < 1 {
		return termErrf(termCodeRemote, "出口返回了空错误帧")
	}
	codeLen := int(p[0])
	if len(p) < 1+codeLen+2 {
		return termErrf(termCodeRemote, "出口错误帧格式不完整")
	}
	code := string(p[1 : 1+codeLen])
	off := 1 + codeLen
	msgLen := int(binary.LittleEndian.Uint16(p[off : off+2]))
	if len(p) < off+2+msgLen {
		return termErrf(termCodeRemote, "出口错误帧消息不完整（code=%s）", code)
	}
	return &termError{Code: code, Msg: string(p[off+2 : off+2+msgLen])}
}

// ---- 帧编解码（子集）----

func termWriteFrame(w io.Writer, op byte, payload []byte) error {
	buf := make([]byte, 3+len(payload))
	buf[0] = op
	binary.LittleEndian.PutUint16(buf[1:3], uint16(len(payload)))
	copy(buf[3:], payload)
	_, err := w.Write(buf)
	return err
}

func termReadFrame(r io.Reader) (byte, []byte, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.LittleEndian.Uint16(hdr[1:3]))
	var payload []byte
	if n > 0 {
		payload = make([]byte, n)
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}
	return hdr[0], payload, nil
}

func termMarshal(res map[string]any, err *termError) *C.char {
	return C.CString(termMarshalJSON(res, err))
}

// termMarshalJSON termMarshal 的纯 Go 面（返回 string——兜底字节的逐字回归可不经
// cgo 直接测，contract-ledger 2.1；行为与旧一体式逐字相同）。
func termMarshalJSON(res map[string]any, err *termError) string {
	out := map[string]any{}
	for k, v := range res {
		out[k] = v
	}
	if err != nil {
		out["error"] = err
	} else {
		out["ok"] = true
	}
	b, merr := json.Marshal(out)
	if merr != nil {
		// 兜底走构造器（marshal 进族⑦ active 集、可提取——r2 N-1）；error 单键 map
		// 的输出与旧原始 JSON 字面量逐字同形。
		return termMarshalJSON(nil, termErrf(termCodeMarshal, "结果序列化失败"))
	}
	return string(b)
}
