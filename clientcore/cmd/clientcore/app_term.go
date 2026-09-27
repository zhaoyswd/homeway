//go:build cshared

// App 专用：终端服务的**一次性操作**（CLI 不编）。
//
// app_term.go — 会话列表 / 终止会话这两件事不需要终端渲染，直接经**终端通道桥**
// （127.0.0.1:7723 → 隧道 → 出口 term 端口，见 app_termbridge.go）说帧协议即可：
// 每次操作开一条短连接、发一帧、读回复、关连接。JSON 进 JSON 出（NAPI 侧整体挪出 JS 线程）。
//
// ⚠️ 帧布局必须与 homeway `pkg/term/frames.go` 逐字段一致（双向契约，无编译期
// 锚定——升级帧格式时两侧同改）。这里只实现一次性操作需要的子集：
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
)

// 帧操作码（子集；完整表见 homeway pkg/term/frames.go 与 exit-terminal 设计 D4）。
const (
	termOpList     byte = 0x04 // C→S 请求；S→C 回复（payload 是 JSON）
	termOpKill     byte = 0x05
	termOpError    byte = 0x06
	termOpOK       byte = 0x0B
	termOpGreeting byte = 0x0C

	termProtoVer = 1

	termDialTimeout = 15 * time.Second
	termIOTimeout   = 15 * time.Second
)

// termError 带稳定错误码（ArkTS 侧映射中文归因）。
type termError struct {
	Code string `json:"code"`
	Msg  string `json:"msg"`
}

func (e *termError) Error() string { return e.Code + ": " + e.Msg }

func termErrf(code, format string, args ...any) *termError {
	return &termError{Code: code, Msg: fmt.Sprintf(format, args...)}
}

//export TailcatTermCall
func TailcatTermCall(cOp *C.char) *C.char {
	raw := C.GoString(cOp)
	var op map[string]any
	if err := json.Unmarshal([]byte(raw), &op); err != nil {
		return termMarshal(nil, termErrf("bad_json", "参数不是合法 JSON：%v", err))
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
			return nil, termErrf("invalid_arg", "kill 需要 name")
		}
		return termKill(who, auth, sock)
	default:
		return nil, termErrf("invalid_arg", "未知操作 %q", name)
	}
}

// termDial 经终端桥连到出口的终端服务，并校验 GREETING。
// authHex = 桥鉴权首包 blob（app_bridge.go；隧道宿主经 IPC 拿、服务会话宿主直接读状态）。
func termDial(authHex, sock string) (net.Conn, *termError) {
	if sock == "" {
		return nil, termErrf("bridge_down", "终端通道暂时不可用（桥未就绪：VPN 未连接且服务会话未就绪，或正在恢复）")
	}
	conn, err := net.DialTimeout("unix", sock, termDialTimeout)
	if err != nil {
		return nil, termErrf("bridge_down", "终端通道暂时不可用（桥未就绪或正在恢复）：%v", err)
	}
	if err := bridgeWriteAuth(conn, authHex); err != nil {
		_ = conn.Close()
		return nil, termErrf("bridge_auth", "终端通道鉴权失败：%v", err)
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
		return nil, termErrf("term_unreachable",
			"终端服务没有应答：可能是该出口未启用终端（官方版/旧版 tailcat），"+
				"也可能是本机隧道的回程地址已失效（出口日志会看到 no candidates available for endpoint）。"+
				"先重连一次 VPN；若仍不行，请把出口升级到增强版 tailcat。详情：%v", err)
	}
	if code != termOpGreeting {
		_ = conn.Close()
		return nil, termErrf("term_foreign_service",
			"出口 %d 端口上不是终端服务（收到帧 0x%02x）", termServicePort(), code)
	}
	if len(payload) < 5 || payload[0] != termProtoVer {
		_ = conn.Close()
		return nil, termErrf("term_version", "出口终端服务协议版本不匹配（本端 %d）", termProtoVer)
	}
	return conn, nil
}

func termList(authHex, sock string) (map[string]any, *termError) {
	conn, terr := termDial(authHex, sock)
	if terr != nil {
		return nil, terr
	}
	defer conn.Close()
	if err := termWriteFrame(conn, termOpList, nil); err != nil {
		return nil, termErrf("io", "发送 LIST 失败：%v", err)
	}
	code, payload, err := termReadFrame(conn)
	if err != nil {
		return nil, termErrf("io", "读取 LIST 回复失败：%v", err)
	}
	switch code {
	case termOpList:
		var out map[string]any
		if err := json.Unmarshal(payload, &out); err != nil {
			return nil, termErrf("bad_reply", "LIST 回复不是合法 JSON：%v", err)
		}
		if out == nil {
			out = map[string]any{}
		}
		if _, ok := out["sessions"]; !ok {
			out["sessions"] = []any{}
		}
		return out, nil
	case termOpError:
		return nil, termDecodeError(payload)
	default:
		return nil, termErrf("bad_reply", "LIST 回复帧意外（0x%02x）", code)
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
	if err := termWriteFrame(conn, termOpKill, payload); err != nil {
		return nil, termErrf("io", "发送 KILL 失败：%v", err)
	}
	code, reply, err := termReadFrame(conn)
	if err != nil {
		return nil, termErrf("io", "读取 KILL 回复失败：%v", err)
	}
	switch code {
	case termOpOK:
		return map[string]any{"killed": name}, nil
	case termOpError:
		return nil, termDecodeError(reply)
	default:
		return nil, termErrf("bad_reply", "KILL 回复帧意外（0x%02x）", code)
	}
}

// termDecodeError 解 ERROR 载荷：[codeLen:1][code][msgLen:2 LE][msg]。
func termDecodeError(p []byte) *termError {
	if len(p) < 1 {
		return termErrf("remote", "出口返回了空错误帧")
	}
	codeLen := int(p[0])
	if len(p) < 1+codeLen+2 {
		return termErrf("remote", "出口错误帧格式不完整")
	}
	code := string(p[1 : 1+codeLen])
	off := 1 + codeLen
	msgLen := int(binary.LittleEndian.Uint16(p[off : off+2]))
	if len(p) < off+2+msgLen {
		return termErrf("remote", "出口错误帧消息不完整（code=%s）", code)
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
		return C.CString(`{"error":{"code":"marshal","msg":"结果序列化失败"}}`)
	}
	return C.CString(string(b))
}
