//go:build !windows

// term_frames.go — 终端服务的帧协议编解码（纯函数，有单测）。
//
// 帧 = [op:1][len:2 LE][payload]，len ≤ 65535；DATA 由发送方按 ≤16KiB 分片。
// 这套字节布局是**两端契约**：App 侧 terminal 模块的 cpp/stream/term_frames.h
// 必须逐字段一致（见 openspec exit-terminal 设计 D4）。
package term

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

const (
	termProtoVer     = 1
	termMaxPayload   = 65535
	termDataChunk    = 16 << 10
	termMaxNameLen   = 64
	termMaxReasonLen = 200
)

// op：帧类型。两个方向共用一个字节空间，靠连接方向区分（DATA 双向同 op）。
const (
	opHello      byte = 0x00
	opData       byte = 0x01
	opResize     byte = 0x02
	opEnded      byte = 0x03
	opList       byte = 0x04 // C→S 请求；S→C 为 LIST-REPLY（payload 是 JSON）
	opKill       byte = 0x05
	opError      byte = 0x06
	opState      byte = 0x07
	opReserved08 byte = 0x08 // 保留（旧提案里曾是 LIST-REPLY；不得复用，避免老客户端误读）
	opAttached   byte = 0x09
	opReplayDone byte = 0x0A
	opOK         byte = 0x0B
	opGreeting   byte = 0x0C
	// surface 协议（任务 2.2；契约见 design D2）。0x08 是历史保留位，绝不复用。
	opSnapshot      byte = 0x0D // S→C 全量帧（可分片）
	opSnapshotDone  byte = 0x0E // S→C 快照完成标志（= surface 版 REPLAY-DONE）
	opSurfaceDiff   byte = 0x0F // S→C 脏行差分（可分片）
	opFetchRows     byte = 0x10 // C→S 请求 / S→C 应答（可分片）
	opInput         byte = 0x11 // C→S 抽象输入（键/文本/滚轮/焦点）
	opTheme         byte = 0x12 // C→S 客户端主题上报（默认色/深浅）
	opClipboard     byte = 0x13 // S↔C OSC 52 转发（写/读请求/读应答）
	opNotify        byte = 0x14 // S→C OSC 9 通知转发
	opFetchSnapshot byte = 0x15 // C→S 断档/拒收后请求全量

	// opExplain 是**诊断用**的 EXPLAIN 请求/应答（任务 4.8 的 `homeway term explain <会话名>`）。
	// 放在 0x16 是刻意的：0x0D–0x15 留给 surface 协议（design D2 的 op 分配），
	// 诊断帧不占那条线，也不会被 surface 客户端误读。
	opExplain byte = 0x16
	// opCreate 创建会话但不接入（term-host-cli 任务 6.2，`homeway term new -d`）：
	// 不动 PTY 尺寸、不产生腿、不触发哨兵/焦点。载荷 [flags:1][nameLen:1][name]，
	// flags bit0 = reuse-if-exists（见 createFlagReuseIfExists 的极性说明）；应答沿用一锤子帧（OK / ERROR）。
	opCreate byte = 0x17
)

// HELLO flags（bit0 既有；bit1/bit2 是 term-host-cli 的协议增量，design D8）。
const (
	helloFlagCreate       = 1 << 0 // 创建语义（既有）
	helloFlagOnlyIfAbsent = 1 << 1 // 名字已存在则报 already_exists（`new` 不带 -A）
	helloFlagTakeover     = 1 << 2 // 显式接管：踢掉其它腿（`attach -d`；ENDED reason=replaced）
)

// GREETING 的 features 位（客户端不认识的位忽略）。
const (
	featList   = 1 << 0
	featReplay = 1 << 1
	featModes  = 1 << 2
	featAgent  = 1 << 3
	featTitle  = 1 << 4
	// featSurface 是 surface 能力位（任务 2.1）：客户端见位才在 HELLO 尾随 capability 块。
	featSurfaceBit = 1 << 5

	termFeatures = featList | featReplay | featModes | featAgent | featTitle | featSurfaceBit
)

// agent 枚举（与 App 侧一一对应）。STATE/ATTACHED 的 state 字节值域 = stateV2 枚举
// （agent.go：working/blocked/idle/unknown = 1/2/3/0——数值与折价前的旧枚举
// running/waiting/idle/unknown 同构，旧客户端零 wire 差异；term-remote 3.3 起单轨）。
const (
	agentShell    byte = 0
	agentCodex    byte = 1
	agentClaude   byte = 2
	agentOpencode byte = 3
	agentOpenclaw byte = 4
	agentOther    byte = 5
	agentUnknown  byte = 255
)

// ended 的 code：≥0 是子进程退出码；负数表示由服务侧给出的原因（见 reason）。
const (
	termEndReplaced       = -1 // 同一会话被新的 attach 顶掉
	termEndKilled         = -2 // App 主动 kill
	termEndServiceStopped = -3 // 出口服务退出
)

// termEndNone 是「不发 ENDED」的哨兵值（硬错误/客户端已关）：断腿只关连接，
// 客户端看到裸 EOF（CLI 按 D7 给可行动文案）。
const termEndNone = math.MinInt32

// ENDED code=-1 的 reason 受控词表（term-host-cli design D8，r1 P1-4 冻结）：
// 新增取值 MUST 先扩本表再实现（出口与客户端同批交付）。
const (
	termReasonReplaced      = "replaced"       // 被另一客户端显式接管（attach -d）
	termReasonSelfReconnect = "self_reconnect" // 被同一实例标识的重连替换
)

// agentName 把枚举渲染成可检索的短名（日志/JSON 用）。
func agentName(a byte) string {
	switch a {
	case agentShell:
		return "shell"
	case agentCodex:
		return "codex"
	case agentClaude:
		return "claude"
	case agentOpencode:
		return "opencode"
	case agentOpenclaw:
		return "openclaw"
	case agentOther:
		return "other"
	}
	return "unknown"
}

// stateName 已随 legacy 状态枚举退役（term-remote 3.3 单轨化）：STATE/ATTACHED/LIST
// 统一 stateV2 词表，渲染用 agent.go 的 stateNameV2。

type termFrame struct {
	op      byte
	payload []byte
}

var errTermFrame = errors.New("term: bad frame")

// encodeTermFrame 组帧（len 由这里算，调用方只管 payload）。
func encodeTermFrame(op byte, payload []byte) []byte {
	if len(payload) > termMaxPayload {
		payload = payload[:termMaxPayload]
	}
	out := make([]byte, 3+len(payload))
	out[0] = op
	binary.LittleEndian.PutUint16(out[1:3], uint16(len(payload)))
	copy(out[3:], payload)
	return out
}

// readTermFrame 读一帧；短读/超长/未知长度一律报错（连接由调用方关掉）。
func readTermFrame(r io.Reader) (termFrame, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return termFrame{}, err
	}
	n := int(binary.LittleEndian.Uint16(hdr[1:3]))
	f := termFrame{op: hdr[0]}
	if n > 0 {
		f.payload = make([]byte, n)
		if _, err := io.ReadFull(r, f.payload); err != nil {
			return termFrame{}, err
		}
	}
	return f, nil
}

// ---- payload 编解码 ----

func encGreeting() []byte {
	p := make([]byte, 5)
	p[0] = termProtoVer
	binary.LittleEndian.PutUint32(p[1:5], uint32(termFeatures))
	return p
}

func decGreeting(p []byte) (ver byte, features uint32, err error) {
	if len(p) < 5 {
		return 0, 0, fmt.Errorf("%w: greeting len %d", errTermFrame, len(p))
	}
	return p[0], binary.LittleEndian.Uint32(p[1:5]), nil
}

// encHello / decHello：cols/rows + flags + nameLen + name。
// flags 见 helloFlag*（create / only-if-absent / takeover）。
func encHello(cols, rows uint16, create bool, name string) []byte {
	var flags byte
	if create {
		flags = helloFlagCreate
	}
	return encHelloFlags(cols, rows, flags, name)
}

// encHelloFlags 是 encHello 的全 flags 形态（exec-r3 低8）：bit1/bit2 无法经 encHello 的
// create bool 表达，需要它们的编码方（CLI）用它，不再手改字节偏移。
func encHelloFlags(cols, rows uint16, flags byte, name string) []byte {
	p := make([]byte, 6+len(name))
	binary.LittleEndian.PutUint16(p[0:2], cols)
	binary.LittleEndian.PutUint16(p[2:4], rows)
	p[4] = flags
	p[5] = byte(len(name))
	copy(p[6:], name)
	return p
}

func decHello(p []byte) (cols, rows uint16, flags byte, name string, err error) {
	if len(p) < 6 {
		return 0, 0, 0, "", fmt.Errorf("%w: hello len %d", errTermFrame, len(p))
	}
	cols = binary.LittleEndian.Uint16(p[0:2])
	rows = binary.LittleEndian.Uint16(p[2:4])
	flags = p[4]
	// 布局：cols(2) rows(2) flags(1) nameLen(1) name
	n := int(p[5])
	if len(p) < 6+n {
		return 0, 0, 0, "", fmt.Errorf("%w: hello name len %d > %d", errTermFrame, n, len(p)-6)
	}
	name = string(p[6 : 6+n])
	return cols, rows, flags, name, nil
}

// helloTail 取 HELLO 载荷里 name 之后的**尾随字节**（capability / 实例标识块所在）。
// 旧客户端不发尾随字节 ⇒ 返回空，向后兼容（decHello 本来就只读 name 之前的部分）。
func helloTail(p []byte, name string) []byte {
	off := 6 + len(name)
	if off >= len(p) {
		return nil
	}
	return p[off:]
}

// ---- HELLO 尾随块：capability + 客户端实例标识（term-host-cli 任务 2.3，design D8）----
//
// 形状（顺序固定）：[capLen:1][caps:capLen][idLen:1][clientID:idLen]，两段都可省略，
// 解析**必须恰好耗尽**尾随字节（畸形声明长度/残留字节一律拒绝，沿用 bad_capability
// 错误码，r1 P2-9）。
//
// ⚠️ 同形不可判别（exec-r1 中3，口径 (a)）：两段都是 [len][bytes]，解码器无法从形状上
// 区分「裸 ID 块」与「caps 块」——长度自洽的裸 ID 块（如 [4]"host"）会被当作 caps 解析
//（OR 出的能力位可能同时命中 capsSurface/capsRawTerminal）。这不是缺陷而是格式的固有
// 属性；**约束落在编码侧**：带 ID 必带 caps 块（encHelloTail 保证不产出「无 caps 的 ID」），
// 客户端实现（任务 7 CLI / 可选 8.2）必须遵守。

// termMaxClientIDLen 是实例标识的字节上限（CLI 侧是主机名+uid+tty 的短哈希，16 字节量级）。
const termMaxClientIDLen = 64

// encHelloTail 组尾随块（capability 可省略；ID 可省略；顺序固定）。
//
// 编码约束（exec-r1 中3）：**带 ID 必带 caps 块**——没声明能力就不产出 ID 块（静默丢弃，
// 与解码侧的「同形不可判别」配套：ID 块只允许跟在 caps 块之后出现）。
func encHelloTail(caps byte, capsPresent bool, id string) []byte {
	var out []byte
	if capsPresent {
		out = append(out, encCapability(caps)...)
		if id != "" {
			out = append(out, byte(len(id)))
			out = append(out, id...)
		}
	}
	return out
}

// decHelloTail 解 HELLO 尾随：形状校验 + capability + 实例标识。
// 返回 (caps, 是否携带 caps, clientID, 错误)；畸形形状返回错误（调用方报 bad_capability）。
func decHelloTail(tail []byte) (caps byte, capsPresent bool, id string, err error) {
	off := 0
	if len(tail) > off {
		n := int(tail[off])
		if n > 0 {
			if len(tail) < off+1+n {
				return 0, false, "", fmt.Errorf("%w: capability 块声明 %d 字节，实际只有 %d",
					errTermFrame, n, len(tail)-off-1)
			}
			for i := 0; i < n; i++ {
				caps |= tail[off+1+i]
			}
			capsPresent = true
		}
		// 空 caps 块（capLen=0）同样消费 1 字节（exec-r1 中3：注释与实现对齐）：
		// [0][idLen][id] 是合法形状（= 未声明能力 + 携带 ID——编码侧不会产出，但形状合法）。
		off += 1 + n
	}
	if len(tail) > off {
		n := int(tail[off])
		if len(tail) < off+1+n {
			return 0, false, "", fmt.Errorf("%w: 实例标识块声明 %d 字节，实际只有 %d",
				errTermFrame, n, len(tail)-off-1)
		}
		if n > termMaxClientIDLen {
			return 0, false, "", fmt.Errorf("%w: 实例标识 %d 字节超过上限 %d",
				errTermFrame, n, termMaxClientIDLen)
		}
		id = string(tail[off+1 : off+1+n])
		off += 1 + n
	}
	if len(tail) > off {
		return 0, false, "", fmt.Errorf("%w: 尾随块后还有 %d 字节残留", errTermFrame, len(tail)-off)
	}
	return caps, capsPresent, id, nil
}

// ---- CREATE（任务 6.2）：[flags:1][nameLen:1][name]，flags bit0 = reuse-if-exists ----

// createFlagReuseIfExists 是 CREATE 的 bit0：**置位 = 名字已存在则静默复用成功**
// （`new -d -A`）；不置位 = 已存在则报 already_exists（`new -d` 不静默接管别人的会话）。
//
// ⚠️ 极性注意（exec-r3 中2 改述）：同名「存在时怎么办」，CREATE 与 HELLO 的位**相反**——
// HELLO bit1（helloFlagOnlyIfAbsent）置位 = 存在则**报错** already_exists；CREATE bit0
// 置位 = 存在则**复用**。wire 值与两者行为均按 tasks 6.2 实测口径不动，只在此把差异写死：
// 照 HELLO 的字面语义实现 CREATE 会让 `new -d` 静默复用既有会话，恰是要避免的。
const createFlagReuseIfExists = 1 << 0

func encCreate(flags byte, name string) []byte {
	p := make([]byte, 2+len(name))
	p[0] = flags
	p[1] = byte(len(name))
	copy(p[2:], name)
	return p
}

func decCreate(p []byte) (flags byte, name string, err error) {
	if len(p) < 2 {
		return 0, "", fmt.Errorf("%w: create len %d", errTermFrame, len(p))
	}
	n := int(p[1])
	if len(p) < 2+n {
		return 0, "", fmt.Errorf("%w: create name len %d > %d", errTermFrame, n, len(p)-2)
	}
	return p[0], string(p[2 : 2+n]), nil
}

func encResize(cols, rows uint16) []byte {
	p := make([]byte, 4)
	binary.LittleEndian.PutUint16(p[0:2], cols)
	binary.LittleEndian.PutUint16(p[2:4], rows)
	return p
}

func decResize(p []byte) (cols, rows uint16, err error) {
	if len(p) < 4 {
		return 0, 0, fmt.Errorf("%w: resize len %d", errTermFrame, len(p))
	}
	return binary.LittleEndian.Uint16(p[0:2]), binary.LittleEndian.Uint16(p[2:4]), nil
}

// encAttached：cols/rows + modes(4) + agent/state + name。
func encAttached(cols, rows uint16, modes uint32, agent, state byte, name string) []byte {
	p := make([]byte, 10+len(name))
	binary.LittleEndian.PutUint16(p[0:2], cols)
	binary.LittleEndian.PutUint16(p[2:4], rows)
	binary.LittleEndian.PutUint32(p[4:8], modes)
	p[8] = agent
	p[9] = state
	copy(p[10:], name)
	return p
}

// decAttachedHead 解 ATTACHED 载荷头部（encAttached 的逆；exec-r3 低8——客户端不再
// 裸下标 p[8]/p[9]）。载荷过短时 ok=false。
func decAttachedHead(p []byte) (cols, rows uint16, modes uint32, agent, state byte, name string, ok bool) {
	if len(p) < 10 {
		return 0, 0, 0, 0, 0, "", false
	}
	cols = binary.LittleEndian.Uint16(p[0:2])
	rows = binary.LittleEndian.Uint16(p[2:4])
	modes = binary.LittleEndian.Uint32(p[4:8])
	return cols, rows, modes, p[8], p[9], string(p[10:]), true
}

// replayDoneFlags：bit0 = 头部被截断；bit1 = 回放窗口跨过尺寸变化。
const (
	replayFlagTruncated  = 1 << 0
	replayFlagSizeChange = 1 << 1
)

func encReplayDone(replayed uint32, flags byte) []byte {
	p := make([]byte, 5)
	binary.LittleEndian.PutUint32(p[0:4], replayed)
	p[4] = flags
	return p
}

func encEnded(code int32, reason string) []byte {
	if len(reason) > termMaxReasonLen {
		reason = reason[:termMaxReasonLen]
	}
	p := make([]byte, 5+len(reason))
	binary.LittleEndian.PutUint32(p[0:4], uint32(code))
	p[4] = byte(len(reason))
	copy(p[5:], reason)
	return p
}

func encState(agent, state byte, title string) []byte {
	if len(title) > 512 {
		title = title[:512]
	}
	p := make([]byte, 4+len(title))
	p[0] = agent
	p[1] = state
	binary.LittleEndian.PutUint16(p[2:4], uint16(len(title)))
	copy(p[4:], title)
	return p
}

func encError(code, msg string) []byte {
	if len(code) > 255 {
		code = code[:255]
	}
	if len(msg) > 4096 {
		msg = msg[:4096]
	}
	p := make([]byte, 3+len(code)+len(msg))
	p[0] = byte(len(code))
	copy(p[1:], code)
	off := 1 + len(code)
	binary.LittleEndian.PutUint16(p[off:off+2], uint16(len(msg)))
	copy(p[off+2:], msg)
	return p
}

// encName / decName：统一的「nameLen + name」载荷（KILL 与 ATTACHED 之后的 name 都用它）。
func encName(name string) []byte {
	if len(name) > termMaxNameLen {
		name = name[:termMaxNameLen]
	}
	out := make([]byte, 1+len(name))
	out[0] = byte(len(name))
	copy(out[1:], name)
	return out
}

func decName(p []byte) (string, error) {
	if len(p) < 1 {
		return "", fmt.Errorf("%w: name len %d", errTermFrame, len(p))
	}
	n := int(p[0])
	if len(p) < 1+n {
		return "", fmt.Errorf("%w: name %d > %d", errTermFrame, n, len(p)-1)
	}
	return string(p[1 : 1+n]), nil
}

// decError 解 ERROR 载荷（CLI 要把错误码与文案分开呈现）。
func decError(p []byte) (code, msg string, err error) {
	if len(p) < 1 {
		return "", "", fmt.Errorf("%w: error len %d", errTermFrame, len(p))
	}
	n := int(p[0])
	if len(p) < 1+n+2 {
		return "", "", fmt.Errorf("%w: error code len %d", errTermFrame, n)
	}
	code = string(p[1 : 1+n])
	ml := int(binary.LittleEndian.Uint16(p[1+n : 3+n]))
	if len(p) < 3+n+ml {
		return "", "", fmt.Errorf("%w: error msg len %d", errTermFrame, ml)
	}
	msg = string(p[3+n : 3+n+ml])
	return code, msg, nil
}
