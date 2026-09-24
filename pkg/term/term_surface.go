//go:build !windows

// term_surface.go — surface 协议的**线格式**（任务 2.1/2.2；契约见 design D2）。
//
// 双轨并存的形态：legacy（replay + DATA 原始字节）原样保留，surface 是**新客户端的主径**，
// 靠 GREETING 的能力位协商启用。本文件只定义「字节怎么排」，投递策略在 term_surface_leg.go。
//
// # 能力协商（2.1）
//
// GREETING 的 features 增 1 位 `featSurface`（位号顺延，旧客户端按既有语义忽略未知位）；
// 客户端**只在看到该位时**才在 HELLO 尾随 capability 块（HELLO 解码对尾随字节向后兼容）。
// 服务端见 capability 即按 surface 模式服务该腿，否则按 legacy。
//
// # op 码（2.2）
//
// 0x0D SNAPSHOT / 0x0E SNAPSHOT-DONE / 0x0F SURFACE-DIFF / 0x10 FETCH-ROWS /
// 0x11 INPUT / 0x12 THEME / 0x13 CLIPBOARD / 0x14 NOTIFY / 0x15 FETCH-SNAPSHOT
// （0x08 是历史保留位，绝不复用；0x16 是诊断用的 EXPLAIN，见 frames.go）。
//
// # 分片契约（2.2，评审 H2）
//
// 现状 u16 帧长 + 超限**静默截断**对原始字节无害，对 surface 致命 ⇒ surface 的大帧
// （快照/差分/回滚应答）自带分片头：payload = [flags:1][gzip 分片数据]，flags bit0 = more。
// 分片数据 ≤ fragChunk（60KiB，gzip 后），服务端硬保证单帧 payload ≤ 64KiB；
// 客户端**攒齐全部分片才解压与应用**，不完整分片组超时丢弃并请求全量快照。
package term

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// featSurface 是 GREETING features 里的 surface 能力位（位号顺延：0-4 已被占用）。
	featSurface = 1 << 5

	// surfaceVer 是 surface 载荷的版本（进每个大帧的体头）。
	//
	// v2（2026-09-23，任务 3.10）：SURFACE-DIFF 的体尾补了**光标块**（x/y/flags/shape，6 字节，
	// 见 diffBody）。原因：光标原先只随快照来 ⇒ surface 腿下打字时光标停在 attach 那一刻的位置
	// （真机对照：legacy 跟随、surface 不动），且「IME 候选窗锚定随光标帧」没有可用输入。
	// v3（2026-09-24，任务 3.3）：SNAPSHOT 在 misc 之后补了**回滚条**（total/offset/len，18 字节）。
	// 原因：客户端要把镜像窗口/按需拉取锚到绝对行号空间、要算「距缓存顶多远」触发预取。
	// **布局变了就必须升版本**——实测教训：先只改了字段没升版本，结果「出口二进制是旧布局、
	// 版本号一样」的错位让客户端静默错解（快照网格截断刷屏），版本门本来能当场拦住。
	// ⇒ 两端必须同升（本 change 的部署口径本就是出口+App 一起走，见 tasks 6.3）。
	surfaceVer byte = 3

	// fragChunk 是**单个分片**里 gzip 数据的字节上限（评审 H2 定的 60KiB）。
	// 加 1 字节分片头后 61441 < 65535（u16 帧长上限），留足余量。
	fragChunk = 60 << 10

	// surfaceMaxFrame 是服务端对单帧 payload 的硬上限（= u16 帧长上限）。
	surfaceMaxFrame = termMaxPayload

	// fragMoreBit 是分片头的「还有后续片」标志（flags bit0）。
	fragMoreBit byte = 1 << 0

	// mirrorViewports 是 SNAPSHOT 附带的回滚镜像窗口大小（视口数的倍数）。
	// design D3：镜像 = 10 视口；配成常量便于 2.3 与测试引用。
	mirrorViewports = 10
)

// surface 大帧的载荷头（分片层）。
type fragHeader struct {
	flags byte
}

// encFragment 把一个分片编成帧载荷。
func encFragment(flags byte, data []byte) []byte {
	out := make([]byte, 1+len(data))
	out[0] = flags
	copy(out[1:], data)
	return out
}

// decFragment 解一个分片载荷。
func decFragment(p []byte) (flags byte, data []byte, err error) {
	if len(p) < 1 {
		return 0, nil, fmt.Errorf("%w: 分片头缺失", errTermFrame)
	}
	return p[0], p[1:], nil
}

// gzipBytes 压一段数据（surface 的所有大载荷都压缩后分片）。
func gzipBytes(p []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(p); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// gunzipBytes 解压（客户端侧也会用同一套；这里是服务端自测与 golden fixture 用）。
func gunzipBytes(p []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(p))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(zr)
}

// fragmentPayload 把「压缩后的整块数据」切成帧载荷序列（每个元素就是一帧的 payload）。
//
// 空数据也发一片（flags=0、data 空）——让客户端能明确看到「这一组到齐了」，
// 而不是靠超时判定（空快照是合法状态：刚建的会话可能什么都还没输出）。
func fragmentPayload(data []byte) [][]byte {
	if len(data) <= fragChunk {
		return [][]byte{encFragment(0, data)}
	}
	var out [][]byte
	for off := 0; off < len(data); off += fragChunk {
		end := off + fragChunk
		if end > len(data) {
			end = len(data)
		}
		var flags byte
		if end < len(data) {
			flags = fragMoreBit
		}
		out = append(out, encFragment(flags, data[off:end]))
	}
	return out
}

// fragAssembler 是客户端侧的攒片器（服务端单测也用它做往返验证；任务 3.1 的 Go 参考实现）。
//
// 语义：喂入分片 → 集齐后返回整块 gzip 数据；中途出错（超片数上限）返回错误并复位。
type fragAssembler struct {
	buf   []byte
	parts int
}

// maxFragParts 是单组分片的片数上限（防病态对端用无限分片拖死内存）。
const maxFragParts = 512

// push 喂一片；more=false 表示本组结束，返回整块数据。
func (a *fragAssembler) push(payload []byte) (done bool, data []byte, err error) {
	flags, chunk, derr := decFragment(payload)
	if derr != nil {
		return false, nil, derr
	}
	a.parts++
	if a.parts > maxFragParts {
		a.reset()
		return false, nil, fmt.Errorf("%w: 分片数超过 %d", errTermFrame, maxFragParts)
	}
	a.buf = append(a.buf, chunk...)
	if flags&fragMoreBit != 0 {
		return false, nil, nil
	}
	out := a.buf
	a.reset()
	return true, out, nil
}

func (a *fragAssembler) reset() {
	a.buf = nil
	a.parts = 0
}

// ---- SNAPSHOT / SURFACE-DIFF 的体格式 ----

// surfaceGeometry 一次判定所用的几何（FETCH-ROWS 应答与 revision 对账都要它）。
type surfaceGeometry struct {
	Cols, Rows uint16
	Revision   uint32
}

// snapshotBody 是 SNAPSHOT 解压后的体（design D2 的「全网格 + 光标/形状 + 模式位 + 标题 +
// 镜像窗口」）。网格与镜像都复用 cell 行编码（任务 1.4 的选型结论：同一套 cell 契约，
// 不为镜像另立格式）。
type snapshotBody struct {
	Geometry surfaceGeometry
	Cursor   surfaceCursor
	Modes    uint32 // legacy 模式位布局（客户端已有这套位）
	Kitty    uint8  // kitty 键盘协议标志
	Misc     uint8  // bit0 = modifyOtherKeys mode 2 等
	Title    string
	// Scroll 是回滚条状态（任务 3.3）：客户端要靠它把镜像窗口/按需拉取锚到**绝对行号空间**，
	// 也要靠它算「距缓存顶还有多远」来触发预取。行号空间 = [0, Total)，视口占
	// [Offset, Offset+Len)。镜像窗口就是紧邻视口上方的那些行 ⇒ 客户端按
	// `镜像基址 = Offset - len(镜像行)` 自行编号（服务端发的镜像行 y 是视口相对值，
	// 分块读取还会重复，**不能**当绝对行号用——探针实测）。
	Scroll scrollbar
	Grid   []byte // EncodeGrid 的整块字节
	Mirror []byte // EncodeGrid 的整块字节（可能为空）
}

// scrollbar 是回滚条状态（与 vt 的 Scrollbar 同口径；行号 = 同一套绝对空间）。
type scrollbar struct {
	Total  uint64 // 可滚动区总行数（含视口）
	Offset uint64 // 视口顶行的绝对行号
	Len    uint16 // 视口行数
}

type surfaceCursor struct {
	X, Y  uint16
	Flags uint8 // bit0 可见、bit1 闪烁、bit2 宽字符尾、bit3 密码输入
	Shape uint8
}

const (
	cursorFlagVisible  = 1 << 0
	cursorFlagBlinking = 1 << 1
	cursorFlagWideTail = 1 << 2
	cursorFlagPassword = 1 << 3
	// miscModifyOtherKeys：xterm modifyOtherKeys mode 2（vendor 补丁 0002 的查询值）。
	miscModifyOtherKeys = 1 << 0
)

// encSnapshotBody 组 SNAPSHOT 体。
func encSnapshotBody(s snapshotBody) []byte {
	out := make([]byte, 0, 32+len(s.Title)+len(s.Grid)+len(s.Mirror))
	out = append(out, surfaceVer)
	out = appendU32(out, s.Geometry.Revision)
	out = appendU16(out, s.Geometry.Cols)
	out = appendU16(out, s.Geometry.Rows)
	out = appendU16(out, s.Cursor.X)
	out = appendU16(out, s.Cursor.Y)
	out = append(out, s.Cursor.Flags, s.Cursor.Shape)
	out = appendU32(out, s.Modes)
	out = append(out, s.Kitty, s.Misc)
	// 回滚条（任务 3.3）：total/offset 是 u64（与 FETCH-ROWS 的行号同宽），len 是 u16。
	out = appendU64(out, s.Scroll.Total)
	out = appendU64(out, s.Scroll.Offset)
	out = appendU16(out, s.Scroll.Len)
	out = appendU16(out, uint16(len(s.Title)))
	out = append(out, s.Title...)
	out = appendU32(out, uint32(len(s.Grid)))
	out = append(out, s.Grid...)
	out = appendU32(out, uint32(len(s.Mirror)))
	out = append(out, s.Mirror...)
	return out
}

// decSnapshotBody 解体（客户端参考实现；服务端单测做往返）。
func decSnapshotBody(p []byte) (snapshotBody, error) {
	var s snapshotBody
	r := &byteReader{p: p}
	ver, err := r.u8()
	if err != nil || ver != surfaceVer {
		return s, fmt.Errorf("%w: snapshot 版本 %d", errTermFrame, ver)
	}
	if s.Geometry.Revision, err = r.u32(); err != nil {
		return s, err
	}
	if s.Geometry.Cols, err = r.u16(); err != nil {
		return s, err
	}
	if s.Geometry.Rows, err = r.u16(); err != nil {
		return s, err
	}
	if s.Cursor.X, err = r.u16(); err != nil {
		return s, err
	}
	if s.Cursor.Y, err = r.u16(); err != nil {
		return s, err
	}
	if s.Cursor.Flags, err = r.u8(); err != nil {
		return s, err
	}
	if s.Cursor.Shape, err = r.u8(); err != nil {
		return s, err
	}
	if s.Modes, err = r.u32(); err != nil {
		return s, err
	}
	if s.Kitty, err = r.u8(); err != nil {
		return s, err
	}
	if s.Misc, err = r.u8(); err != nil {
		return s, err
	}
	if s.Scroll.Total, err = r.u64(); err != nil {
		return s, err
	}
	if s.Scroll.Offset, err = r.u64(); err != nil {
		return s, err
	}
	if s.Scroll.Len, err = r.u16(); err != nil {
		return s, err
	}
	n, err := r.u16()
	if err != nil {
		return s, err
	}
	if s.Title, err = r.str(int(n)); err != nil {
		return s, err
	}
	gl, err := r.u32()
	if err != nil {
		return s, err
	}
	if s.Grid, err = r.bytes(int(gl)); err != nil {
		return s, err
	}
	ml, err := r.u32()
	if err != nil {
		return s, err
	}
	if s.Mirror, err = r.bytes(int(ml)); err != nil {
		return s, err
	}
	return s, nil
}

// diffBody 是 SURFACE-DIFF 解压后的体：脏行 patch + revision + **本拍光标**。
//
// 只发脏行（同一套行编码），客户端按 Y 覆盖到自己的网格上；revision 断档由客户端请求全量。
//
// 光标为什么在差分里（surfaceVer 2，任务 3.10）：光标是**每拍都可能变**的状态——打字、方向键、
// TUI 输入框都会移动它，而它不体现在任何一行 cell 的内容里（行内编辑时行内容可能完全不变）。
// 只随快照发的后果是「光标停在 attach 那一刻」；6 字节换每帧正确，远比让客户端去猜便宜。
type diffBody struct {
	Geometry surfaceGeometry
	Cursor   surfaceCursor // 本拍视口光标（与快照同一套字段/取值口径）
	Rows     []byte        // 行编码（[y:2][格流…] 的序列）
	RowCount uint16
}

func encDiffBody(d diffBody) []byte {
	out := make([]byte, 0, 22+len(d.Rows))
	out = append(out, surfaceVer)
	out = appendU32(out, d.Geometry.Revision)
	out = appendU16(out, d.Geometry.Cols)
	out = appendU16(out, d.Geometry.Rows)
	out = appendU16(out, d.RowCount)
	// 光标块与快照同位序（x,y,flags,shape）：两处解码共用同一段代码路径。
	out = appendU16(out, d.Cursor.X)
	out = appendU16(out, d.Cursor.Y)
	out = append(out, d.Cursor.Flags, d.Cursor.Shape)
	out = append(out, d.Rows...)
	return out
}

func decDiffBody(p []byte) (diffBody, error) {
	var d diffBody
	r := &byteReader{p: p}
	ver, err := r.u8()
	if err != nil || ver != surfaceVer {
		return d, fmt.Errorf("%w: diff 版本 %d", errTermFrame, ver)
	}
	if d.Geometry.Revision, err = r.u32(); err != nil {
		return d, err
	}
	if d.Geometry.Cols, err = r.u16(); err != nil {
		return d, err
	}
	if d.Geometry.Rows, err = r.u16(); err != nil {
		return d, err
	}
	if d.RowCount, err = r.u16(); err != nil {
		return d, err
	}
	if d.Cursor.X, err = r.u16(); err != nil {
		return d, err
	}
	if d.Cursor.Y, err = r.u16(); err != nil {
		return d, err
	}
	if d.Cursor.Flags, err = r.u8(); err != nil {
		return d, err
	}
	if d.Cursor.Shape, err = r.u8(); err != nil {
		return d, err
	}
	d.Rows = r.rest()
	return d, nil
}

// fetchRowsReq 是 FETCH-ROWS 请求：从绝对行号 from 起要 count 行（与滚动条同一套行号空间，
// 所以镜像窗口的边界与它天然对齐）。
type fetchRowsReq struct {
	From  uint64
	Count uint16
}

func encFetchRowsReq(r fetchRowsReq) []byte {
	out := make([]byte, 10)
	binary.LittleEndian.PutUint64(out[0:8], r.From)
	binary.LittleEndian.PutUint16(out[8:10], r.Count)
	return out
}

func decFetchRowsReq(p []byte) (fetchRowsReq, error) {
	var r fetchRowsReq
	if len(p) < 10 {
		return r, fmt.Errorf("%w: fetch-rows 请求 len=%d", errTermFrame, len(p))
	}
	r.From = binary.LittleEndian.Uint64(p[0:8])
	r.Count = binary.LittleEndian.Uint16(p[8:10])
	return r, nil
}

// fetchRowsReply 是 FETCH-ROWS 应答：**带几何与 revision**（客户端据此丢弃过期应答，评审 M3）。
type fetchRowsReply struct {
	Geometry surfaceGeometry
	From     uint64
	Count    uint16
	Rows     []byte // 行编码
}

func encFetchRowsReply(r fetchRowsReply) []byte {
	out := make([]byte, 0, 24+len(r.Rows))
	out = append(out, surfaceVer)
	out = appendU32(out, r.Geometry.Revision)
	out = appendU16(out, r.Geometry.Cols)
	out = appendU16(out, r.Geometry.Rows)
	out = appendU64(out, r.From)
	out = appendU16(out, r.Count)
	out = append(out, r.Rows...)
	return out
}

func decFetchRowsReply(p []byte) (fetchRowsReply, error) {
	var r fetchRowsReply
	br := &byteReader{p: p}
	ver, err := br.u8()
	if err != nil || ver != surfaceVer {
		return r, fmt.Errorf("%w: fetch-rows 应答版本 %d", errTermFrame, ver)
	}
	if r.Geometry.Revision, err = br.u32(); err != nil {
		return r, err
	}
	if r.Geometry.Cols, err = br.u16(); err != nil {
		return r, err
	}
	if r.Geometry.Rows, err = br.u16(); err != nil {
		return r, err
	}
	if r.From, err = br.u64(); err != nil {
		return r, err
	}
	if r.Count, err = br.u16(); err != nil {
		return r, err
	}
	r.Rows = br.rest()
	return r, nil
}

// ---- 小工具（与 cellcodec.go 同款；这里独立一份，因为 service 层不该依赖 vt 包） ----

func appendU16(b []byte, v uint16) []byte { return append(b, byte(v), byte(v>>8)) }

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func appendU64(b []byte, v uint64) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24),
		byte(v>>32), byte(v>>40), byte(v>>48), byte(v>>56))
}

// byteReader 是带边界检查的小端读取器（所有 surface 体解码都走它，越界一律报错）。
type byteReader struct {
	p   []byte
	off int
}

func (r *byteReader) need(n int) error {
	if r.off+n > len(r.p) {
		return fmt.Errorf("%w: 载荷截断（需要 %d，剩 %d）", errTermFrame, n, len(r.p)-r.off)
	}
	return nil
}

func (r *byteReader) u8() (byte, error) {
	if err := r.need(1); err != nil {
		return 0, err
	}
	v := r.p[r.off]
	r.off++
	return v, nil
}

func (r *byteReader) u16() (uint16, error) {
	if err := r.need(2); err != nil {
		return 0, err
	}
	v := binary.LittleEndian.Uint16(r.p[r.off:])
	r.off += 2
	return v, nil
}

func (r *byteReader) u32() (uint32, error) {
	if err := r.need(4); err != nil {
		return 0, err
	}
	v := binary.LittleEndian.Uint32(r.p[r.off:])
	r.off += 4
	return v, nil
}

func (r *byteReader) u64() (uint64, error) {
	if err := r.need(8); err != nil {
		return 0, err
	}
	v := binary.LittleEndian.Uint64(r.p[r.off:])
	r.off += 8
	return v, nil
}

func (r *byteReader) bytes(n int) ([]byte, error) {
	if err := r.need(n); err != nil {
		return nil, err
	}
	v := r.p[r.off : r.off+n]
	r.off += n
	return v, nil
}

func (r *byteReader) str(n int) (string, error) {
	b, err := r.bytes(n)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (r *byteReader) rest() []byte {
	v := r.p[r.off:]
	r.off = len(r.p)
	return v
}

// ---- 能力协商（2.1） ----

// capsSurface 是客户端 capability 块里的 surface 标志位。
const capsSurface = 1 << 0

// encCapability 组 HELLO 尾随的 capability 块：[capLen:1][flags:capLen]。
//
// 用「长度 + 位图」而不是单个字节：将来加能力只加位，不必改布局；capLen 让旧出口能安全忽略
// （旧出口的 decHello 本来就读不完尾随字节）。
func encCapability(caps byte) []byte {
	return []byte{1, caps}
}

// decCapability 解 HELLO 尾随的 capability 块。返回 (caps, 是否携带, 错误)。
//
// 畸形块（长度越界）返回**独立错误**，调用方要给出与「协议版本不匹配」不同的错误码
// （规格「协商失败可区分」）。
func decCapability(tail []byte) (caps byte, present bool, err error) {
	if len(tail) == 0 {
		return 0, false, nil
	}
	n := int(tail[0])
	if n == 0 {
		return 0, false, nil
	}
	if len(tail) < 1+n {
		return 0, false, fmt.Errorf("%w: capability 块声明 %d 字节，实际只有 %d", errTermFrame, n, len(tail)-1)
	}
	var c byte
	for i := 0; i < n; i++ {
		c |= tail[1+i]
	}
	return c, true, nil
}

// wantsSurface 报告客户端能力块是否声明了 surface。
func wantsSurface(caps byte) bool { return caps&capsSurface != 0 }

// ---- 上行帧的载荷格式（2.7）----

// 输入事件的种类（INPUT 帧 payload 的首字节）。
const (
	inputKindKey   byte = 0 // 键：[key:2][mods:2][action:1][utf8Len:1][utf8]
	inputKindText  byte = 1 // 文本（IME/粘贴）：[flags:1][len:2][text]，flags bit0 = 粘贴语义
	inputKindMouse byte = 2 // 鼠标：[action:1][button:1][mods:2][x:2][y:2]（x/y 是**网格坐标**）
	inputKindFocus byte = 3 // 焦点：[gained:1]
)

// textPasteBit 是文本事件的粘贴语义位（括号粘贴按模式包装，design D4）。
const textPasteBit byte = 1 << 0

// inputEvent 一次抽象输入（wire 形态；服务端按 vt 真实模式编码）。
type inputEvent struct {
	Kind   byte
	Key    uint16
	Mods   uint16
	Action byte
	Text   string
	Paste  bool
	Button byte
	X, Y   uint16
	Gained bool
}

func encInputEvent(ev inputEvent) []byte {
	// ⚠️ 每个分支都必须带上种类字节（解码侧第一件事就是读它）；漏了会让解码把载荷当成
	// 别的种类去解，报出「载荷截断」这类看着像帧坏了、其实是编码端少了 1 字节的错。
	out := make([]byte, 0, 8+len(ev.Text))
	out = append(out, ev.Kind)
	switch ev.Kind {
	case inputKindKey:
		out = appendU16(out, ev.Key)
		out = appendU16(out, ev.Mods)
		out = append(out, ev.Action, byte(len(ev.Text)))
		return append(out, ev.Text...)
	case inputKindText:
		var flags byte
		if ev.Paste {
			flags = textPasteBit
		}
		out = append(out, flags)
		out = appendU16(out, uint16(len(ev.Text)))
		return append(out, ev.Text...)
	case inputKindMouse:
		out = append(out, ev.Action, ev.Button)
		out = appendU16(out, ev.Mods)
		out = appendU16(out, ev.X)
		out = appendU16(out, ev.Y)
		return out
	case inputKindFocus:
		var b byte
		if ev.Gained {
			b = 1
		}
		return append(out, b)
	}
	return nil
}

func decInputEvent(p []byte) (inputEvent, error) {
	var ev inputEvent
	if len(p) < 1 {
		return ev, fmt.Errorf("%w: input 空载荷", errTermFrame)
	}
	ev.Kind = p[0]
	r := &byteReader{p: p, off: 1}
	var err error
	switch ev.Kind {
	case inputKindKey:
		if ev.Key, err = r.u16(); err != nil {
			return ev, err
		}
		if ev.Mods, err = r.u16(); err != nil {
			return ev, err
		}
		if ev.Action, err = r.u8(); err != nil {
			return ev, err
		}
		n, err := r.u8()
		if err != nil {
			return ev, err
		}
		if ev.Text, err = r.str(int(n)); err != nil {
			return ev, err
		}
	case inputKindText:
		flags, err := r.u8()
		if err != nil {
			return ev, err
		}
		ev.Paste = flags&textPasteBit != 0
		n, err := r.u16()
		if err != nil {
			return ev, err
		}
		if ev.Text, err = r.str(int(n)); err != nil {
			return ev, err
		}
	case inputKindMouse:
		if ev.Action, err = r.u8(); err != nil {
			return ev, err
		}
		if ev.Button, err = r.u8(); err != nil {
			return ev, err
		}
		if ev.Mods, err = r.u16(); err != nil {
			return ev, err
		}
		if ev.X, err = r.u16(); err != nil {
			return ev, err
		}
		if ev.Y, err = r.u16(); err != nil {
			return ev, err
		}
	case inputKindFocus:
		b, err := r.u8()
		if err != nil {
			return ev, err
		}
		ev.Gained = b != 0
	default:
		return ev, fmt.Errorf("%w: 未知输入种类 %d", errTermFrame, ev.Kind)
	}
	return ev, nil
}

// themeFlagsDark 是 THEME 帧里的深浅色标志位。
const themeFlagsDark byte = 1 << 0

// encTheme 组 THEME 载荷：[flags:1][fgR][fgG][fgB][bgR][bgG][bgB]。
func encTheme(fg, bg [3]uint8, dark bool) []byte {
	var flags byte
	if dark {
		flags = themeFlagsDark
	}
	return []byte{flags, fg[0], fg[1], fg[2], bg[0], bg[1], bg[2]}
}

func decTheme(p []byte) (fg, bg [3]uint8, dark bool, err error) {
	if len(p) < 7 {
		return fg, bg, false, fmt.Errorf("%w: theme len=%d", errTermFrame, len(p))
	}
	dark = p[0]&themeFlagsDark != 0
	fg = [3]uint8{p[1], p[2], p[3]}
	bg = [3]uint8{p[4], p[5], p[6]}
	return fg, bg, dark, nil
}

// 剪贴板帧的种类（CLIPBOARD 帧 payload 的首字节）。
const (
	clipKindWrite      byte = 0 // S→C：程序要写剪贴板（客户端写系统剪贴板）
	clipKindReadReq    byte = 1 // S→C：程序要读剪贴板（客户端回 clipKindReadAnswer）
	clipKindReadAnswer byte = 2 // C→S：客户端对读请求的应答
)

// clipMaxBytes 是剪贴板内容的长度上限（沿用既有粘贴语义的量级）。
const clipMaxBytes = 256 << 10

// encClipboard 组 CLIPBOARD 载荷：[kind:1][len:2][text]。
func encClipboard(kind byte, text string) []byte {
	if len(text) > clipMaxBytes {
		text = text[:clipMaxBytes]
	}
	out := make([]byte, 0, 3+len(text))
	out = append(out, kind)
	out = appendU16(out, uint16(len(text)))
	return append(out, text...)
}

// decClipboardAnswer 解客户端对读请求的应答。
func decClipboardAnswer(p []byte) (string, error) {
	if len(p) < 3 || p[0] != clipKindReadAnswer {
		return "", fmt.Errorf("%w: 非读应答", errTermFrame)
	}
	n := int(binary.LittleEndian.Uint16(p[1:3]))
	if len(p) < 3+n {
		return "", fmt.Errorf("%w: 剪贴板载荷截断", errTermFrame)
	}
	return string(p[3 : 3+n]), nil
}

// decClipboard 解任意方向的剪贴板帧（服务端自测与客户端参考实现用）。
func decClipboard(p []byte) (kind byte, text string, err error) {
	if len(p) < 3 {
		return 0, "", fmt.Errorf("%w: clipboard len=%d", errTermFrame, len(p))
	}
	n := int(binary.LittleEndian.Uint16(p[1:3]))
	if len(p) < 3+n {
		return 0, "", fmt.Errorf("%w: 剪贴板载荷截断", errTermFrame)
	}
	return p[0], string(p[3 : 3+n]), nil
}

// encNotify 组 NOTIFY 载荷：[len:2][text]。
func encNotify(text string) []byte {
	if len(text) > 4096 {
		text = text[:4096]
	}
	out := make([]byte, 0, 2+len(text))
	out = appendU16(out, uint16(len(text)))
	return append(out, text...)
}

// decNotify 解 NOTIFY 载荷。
func decNotify(p []byte) (string, error) {
	if len(p) < 2 {
		return "", fmt.Errorf("%w: notify len=%d", errTermFrame, len(p))
	}
	n := int(binary.LittleEndian.Uint16(p[0:2]))
	if len(p) < 2+n {
		return "", fmt.Errorf("%w: notify 载荷截断", errTermFrame)
	}
	return string(p[2 : 2+n]), nil
}
