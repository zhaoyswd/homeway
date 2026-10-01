// Package files：files 原生协议（wg-native-stack tasks 3.4）。
//
// 承载：隧道内 TCP 流上**每命令一条流**（拨隧道 IP 同端口，出口豁免转投）。线上格式：
//
//	服务端 → 客户端（流的第一个东西，恒有）：
//	  {"ok":true,"root":"/Users/xx","ver":1}\n               ← 问候帧
//	客户端 → 服务端（一行 JSON 请求，≤64KB）：
//	  {"op":"list","path":"photos"}\n
//	服务端 → 客户端（一行 JSON 响应）：
//	  {"ok":true,"entries":[…]}\n  或  {"ok":false,"code":"not_found","msg":"…"}\n
//
// 流式（大文件）用 [4B BE len][payload] 帧，**len=0 是终止帧**：
//   - download：响应行给出 size，然后若干帧，最后终止帧；
//   - write（上传）：请求行 → 服务端回 {"ok":true} 表示已备好 .tierpart →
//     客户端发帧 → 终止帧 = 提交（rename）；**提前关流 = 取消**（服务端删 .tierpart，
//     目标文件保持原样/不存在）。
//
// 动词六枚：list / stat / mkdir / read / download / write（+ 问候帧）。
// 路径一律**相对于根**（""/"." = 根）；越界（`..`、绝对路径逃逸、符号链接逃逸）由
// os.Root 拒绝（Go 1.24 标准库沙箱）。
//
// 错误码与旧 NAPI 契约对齐（ArkTS 侧 FilesRules.filesErrorMessage 直接消费）：
// invalid_arg / invalid_name / not_found / permission / is_dir / already_exists / op_failed。
package files

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Version 协议版本（问候帧里的 ver；ArkTS 侧不解析，供诊断与未来演进）。
const Version = 1

// MaxRequestLine 请求行上限（一行 JSON；路径/参数都很小）。
const MaxRequestLine = 64 * 1024

// MaxChunk 单帧载荷上限（客户端应遵守；服务端只做防御性校验）。
const MaxChunk = 256 * 1024

// 协议错误码词表（包粒度 8 码 = 7 稳定码 + canceled——contract-ledger 台账族④，只增
// 不改；Errf/Errw 首参一律引用本表，散点字面量已随 4b 2.1 提常量收拢）。CodeStreamOpen
// （stream_open，client.go 流开场失败）同属本族、随其真源声明在 client.go。
const (
	CodeInvalidArg    = "invalid_arg"
	CodeInvalidName   = "invalid_name"
	CodeNotFound      = "not_found"
	CodePermission    = "permission"
	CodeIsDir         = "is_dir"
	CodeAlreadyExists = "already_exists"
	CodeOpFailed      = "op_failed"
	CodeCanceled      = "canceled"
	// CodeServerBusy 并发闸拒绝（FIX-36 新增）：服务端在册流满 MaxConns 时的明确拒绝。
	// 与桥层的 `busy`（App 自己的「已有传输进行中」）**不是一回事**——不复用那个值，
	// 免得 App 把它讲成本地有传输在跑。经族⑥透传、App 走 default（带服务端 msg）。
	CodeServerBusy = "server_busy"
)

// Request 一条命令的请求。
type Request struct {
	Op       string `json:"op"`
	Path     string `json:"path"`
	MaxBytes int64  `json:"maxBytes,omitempty"` // read：内联载荷上限
	Mode     string `json:"mode,omitempty"`     // read：text|image（image 回 base64）
	Size     int64  `json:"size,omitempty"`     // write：声明的大小（可选，仅用于日志/校验）
}

// Entry 目录条目（与旧 filesEntry 字段一致：name/isDir/size/mtimeMs）。
type Entry struct {
	Name    string `json:"name"`
	IsDir   bool   `json:"isDir"`
	Size    int64  `json:"size"`
	MtimeMs int64  `json:"mtimeMs"`
	Mode    uint32 `json:"mode,omitempty"` // 权限位（诊断/展示用；NAPI 侧忽略）
}

// Greeting 问候帧（连接建立后的第一个响应）。
type Greeting struct {
	Ok   bool   `json:"ok"`
	Root string `json:"root"`
	Ver  int    `json:"ver"`
}

// Response 统一响应（ok=false 时给 code/msg）。
type Response struct {
	Ok        bool    `json:"ok"`
	Code      string  `json:"code,omitempty"`
	Msg       string  `json:"msg,omitempty"`
	Entries   []Entry `json:"entries,omitempty"`
	Entry     *Entry  `json:"entry,omitempty"`
	Size      int64   `json:"size,omitempty"`
	Truncated bool    `json:"truncated,omitempty"`
	Text      string  `json:"text,omitempty"`
	Base64    string  `json:"base64,omitempty"`
}

// Error 带稳定错误码（对应 ArkTS 的 filesErrorMessage 表）。
type Error struct {
	Code string
	Msg  string
	// wrapped 被包错误（Errw 构造；nil = Errf 产的纯文案错误）。**不出 wire**：
	// response() 序列化面只含 Code/Msg，恒不变。
	wrapped error
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

// Unwrap 暴露被包错误（Go 侧错误链——files-cli 1.2 新增；wire 零改动）。
// 用途：读方向（下载中断/读响应失败等）的底层终结错误（如 streamend.Error）经链
// 可达——CLI 的 errors.As(err, &streamend.Error) 由此命中（r2 新-1）。
func (e *Error) Unwrap() error { return e.wrapped }

// Errf 构造带码错误（纯文案——内部 Sprintf 产不出 %w 链，实测 %w 只打出
// %!w(...)；要保留被包错误用 Errw）。
func Errf(code, format string, args ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Errw 构造带码且**保留被包错误**的错误（files-cli 1.2 新增；Msg 文案与 Errf 同形——
// format 仍经 Sprintf，被包错误只进链不进文案——Response 序列化面与既有逐字相同）。
func Errw(code string, err error, format string, args ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...), wrapped: err}
}

func (e *Error) response() Response {
	return Response{Ok: false, Code: e.Code, Msg: e.Msg}
}

// WriteLine 写一行 JSON（响应/问候帧）。
func WriteLine(w io.Writer, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	_, err = w.Write(raw)
	return err
}

// ReadRequest 读一行请求并解析。
func ReadRequest(br *bufio.Reader) (*Request, error) {
	line, err := readLineLimited(br, MaxRequestLine)
	if err != nil {
		return nil, err
	}
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		return nil, Errf(CodeInvalidArg, "请求不是合法 JSON：%v", err)
	}
	if req.Op == "" {
		return nil, Errf(CodeInvalidArg, "缺少 op")
	}
	return &req, nil
}

func readLineLimited(br *bufio.Reader, max int) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := br.ReadSlice('\n')
		buf = append(buf, chunk...)
		if len(buf) > max {
			return nil, Errf(CodeInvalidArg, "请求行超过 %d 字节", max)
		}
		if err == nil {
			return trimEOL(buf), nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return nil, err
	}
}

func trimEOL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// unmarshalLine 解析一行 JSON（去行尾）。
func unmarshalLine(line []byte, v any) error {
	return json.Unmarshal(trimEOL(line), v)
}

// WriteFrame 写一个数据帧（len=0 表示终止/提交）。
func WriteFrame(w io.Writer, payload []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame 读一个帧。n=0, err=nil 表示收到终止帧；EOF（未收到终止帧）返回 io.EOF。
func ReadFrame(r io.Reader, buf []byte) (int, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint32(hdr[:]))
	if n == 0 {
		return 0, nil
	}
	if n > MaxChunk {
		return 0, Errf(CodeInvalidArg, "帧长 %d 超过上限 %d", n, MaxChunk)
	}
	if n > len(buf) {
		return 0, Errf(CodeInvalidArg, "帧长 %d 超过缓冲区 %d", n, len(buf))
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return 0, err
	}
	return n, nil
}
