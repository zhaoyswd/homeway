// Package control — 守护进程控制面（host-registry-daemon §3，spec daemon-control-plane）。
//
// 单条 UDS 连接多路复用三类流量（请求/响应、事件推送、流式通道数据），统一二进制
// 帧封装 [op:1][len:4 大端][body]。语义契约冻结在 tier 仓 openspec
// daemon-control-plane spec；本包是它的 Go 实现 + fixtures（testdata/fixtures/v1）
// + Go 客户端（client.go，CLI 与测试共用）。
//
// 帧长上限（spec「帧封装」，冻结）：控制帧 body ≤ 1MiB、流 DATA 帧 body ≤ 256KiB；
// 解码器先验长度、超限在读取 body 之前报 ErrBadFrame（连接层回 goodbye(bad_frame)
// 断连——「回错误码」的载体：goodbye 帧的 reason 引用错误码表的稳定字符串）。
package control

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ProtoVersion 控制面协议版本（spec 按 protoVersion 分 fixtures 目录：v1/…）。
const ProtoVersion = 1

// op 码位分配表（spec「帧封装」初始集，只增不改；预留段 0x05–0x0F / 0x14–0x1F /
// 0x22–0x2F，新段自 0x30 起）。帧字节层面的合法 op = 下表 10 个已分配值；预留段或
// 任意其它值 = 非法 op（bad_frame 断连）。注意与操作名（req 帧 JSON 的 op 字符串）
// 区分：词表外**操作名**是 unknown_op（不断连）。
const (
	OpHello      = 0x01 // hello：前端首发（protoVersion + frontend 标识）
	OpWelcome    = 0x02 // welcome：serverVersion + generation + serverSeq
	OpReload     = 0x03 // reload：版本不匹配（原因 proto_mismatch）后关闭
	OpGoodbye    = 0x04 // goodbye：带原因的告别（overrun/bad_frame/bad_json…）
	OpReq        = 0x10 // req：请求（corr id 关联）
	OpRsp        = 0x11 // rsp：响应（corr id 关联）
	OpEvt        = 0x12 // evt：事件推送（seq 自包含）
	OpStreamData = 0x20 // stream.data：[streamId:4][原始字节] 双向透传
	OpStreamEnd  = 0x21 // stream.end：{streamId, reason}（reason ∈ closed|gone）
)

// OpName op 码的规范名（fixtures/日志用；未知码返回空串）。
var opNames = map[byte]string{
	OpHello:      "hello",
	OpWelcome:    "welcome",
	OpReload:     "reload",
	OpGoodbye:    "goodbye",
	OpReq:        "req",
	OpRsp:        "rsp",
	OpEvt:        "evt",
	OpStreamData: "stream.data",
	OpStreamEnd:  "stream.end",
}

// OpName 返回 op 码的规范名（码位表内），不在表内返回空串。
func OpName(op byte) string { return opNames[op] }

// ValidOp 帧字节是否为码位表内的已分配 op（预留段与未知值都算非法）。
func ValidOp(op byte) bool {
	_, ok := opNames[op]
	return ok
}

// 帧长上限（冻结，spec「帧封装」）。
const (
	// MaxControlBody 控制类帧（JSON body）的上限：1MiB。
	MaxControlBody = 1 << 20
	// MaxStreamBody 流 DATA 帧 body（含 4 字节 streamId 前缀）的上限：256KiB。
	MaxStreamBody = 256 << 10
	// streamIDSize 流 body 的 streamId 前缀宽度。
	streamIDSize = 4
)

// ErrBadFrame 帧层不可恢复错误（长度超限 / 流 body 短于 streamId 前缀）。
// 连接层收到 = 回 goodbye(bad_frame) 后断连；调用方 MUST NOT 继续在该流上解码。
var ErrBadFrame = errors.New("bad_frame")

// fitsLimit 长度先验的 uint32 比较（host-cli 3b L1，exec-r2 ②）：**任意架构**下
// 无符号溢出——32 位平台 `int(h.N)` 对 ≥2^31 的声明长度变负，直接 `int(n) > max`
// 比较会绕过先验，随后 `make([]byte, n)` 以负长度 panic（conn goroutine 无
// recover ⇒ 进程崩；armv7 是发版目标）。Go 不允许 uint32 与 int 直接比较
// （无符号/有符号混比），抽 helper 使任意架构可红绿。
func fitsLimit(n uint32, max int) bool { return uint64(n) <= uint64(max) }

// ReadFrame 从 r 读一帧：[op:1][len:4 大端][body]。
//
// maxBody 是本帧的长度上限（控制/流两类各自传 spec 冻结值）。**先验 len**：声明
// 长度超限时**不读 body**直接返回 ErrBadFrame（body 留在流里，连接层随后断连——
// spec 场景「超限帧在读 body 前被拒」）。
func ReadFrame(r io.Reader, maxBody int) (op byte, body []byte, err error) {
	var head [5]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return 0, nil, err
	}
	op = head[0]
	n := binary.BigEndian.Uint32(head[1:5])
	if !fitsLimit(n, maxBody) {
		return op, nil, fmt.Errorf("%w: 声明长度 %d 超上限 %d（op=0x%02x）", ErrBadFrame, n, maxBody, op)
	}
	body = make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return op, body, err
	}
	return op, body, nil
}

// FrameHead 已过上限先验的帧头（op + 声明 body 长度）。
type FrameHead struct {
	Op byte
	N  uint32
}

// maxBodyFor 按 op 选帧长上限（spec「帧封装」冻结：流 DATA 帧 256KiB、其余控制
// 类 1MiB）。读循环 MUST 走这条路——一律按控制上限读会让流帧的 256KiB 上限
// 在读路径根本不生效（exec-r1 B2：512KiB 的 stream.data 此前被完整读下）。
func maxBodyFor(op byte) int {
	if op == OpStreamData {
		return MaxStreamBody
	}
	return MaxControlBody
}

// ReadHeader 读 5 字节帧头并按 op 选上限做长度先验（超限**不读 body** 返回
// ErrBadFrame）。服务器/客户端读循环用（ReadHeader+ReadBody 组合 = 按 op 的
// 两档上限）；显式传 maxBody 的旧用法见 ReadFrame。长度先验走 fitsLimit
// （uint32 比较——32 位防绕过，见其注释）。
func ReadHeader(r io.Reader) (FrameHead, error) {
	var head [5]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return FrameHead{}, err
	}
	h := FrameHead{Op: head[0], N: binary.BigEndian.Uint32(head[1:5])}
	if !fitsLimit(h.N, maxBodyFor(h.Op)) {
		return h, fmt.Errorf("%w: 声明长度 %d 超上限 %d（op=0x%02x）", ErrBadFrame, h.N, maxBodyFor(h.Op), h.Op)
	}
	return h, nil
}

// ReadBody 读 FrameHead 声明的 body（head 已过 ReadHeader 的上限先验）。
func ReadBody(r io.Reader, head FrameHead) ([]byte, error) {
	body := make([]byte, head.N)
	if _, err := io.ReadFull(r, body); err != nil {
		return body, err
	}
	return body, nil
}

// WriteFrame 向 w 写一帧。len 由 body 长度推导；调用方保证 body 不超所属类的上限
// （EncodeFrame 系列产物天然满足）。
func WriteFrame(w io.Writer, op byte, body []byte) error {
	head := [5]byte{op}
	binary.BigEndian.PutUint32(head[1:5], uint32(len(body)))
	if _, err := w.Write(head[:]); err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	_, err := w.Write(body)
	return err
}

// EncodeFrame 帧编码为字节（fixtures 生成与测试用）。
func EncodeFrame(op byte, body []byte) []byte {
	out := make([]byte, 5+len(body))
	out[0] = op
	binary.BigEndian.PutUint32(out[1:5], uint32(len(body)))
	copy(out[5:], body)
	return out
}

// ---------- 流 DATA 帧的 body 封装（spec「帧封装」：[streamId:4 大端][原始字节]） ----------

// EncodeStreamBody 流 DATA 帧 body = [streamId:4 大端][bytes]。
func EncodeStreamBody(streamID uint32, payload []byte) []byte {
	out := make([]byte, streamIDSize+len(payload))
	binary.BigEndian.PutUint32(out[:4], streamID)
	copy(out[4:], payload)
	return out
}

// DecodeStreamBody 解流 DATA 帧 body；短于 4 字节前缀 = ErrBadFrame（连接层断连）。
func DecodeStreamBody(body []byte) (streamID uint32, payload []byte, err error) {
	if len(body) < streamIDSize {
		return 0, nil, fmt.Errorf("%w: 流 body 短于 streamId 前缀（%d 字节）", ErrBadFrame, len(body))
	}
	return binary.BigEndian.Uint32(body[:4]), body[4:], nil
}
