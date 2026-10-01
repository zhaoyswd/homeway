// surface.go — 净室的 surface 下行 golden 解码面（contract-ledger 4b，design D4）。
//
// 覆盖：帧序列文件（[u32 帧数]{[op][u32 片数]{[u32 长][字节]}…}）→ 分片重组
// （每片 [flags:1][gzip 部分]，攒齐解压）→ SNAPSHOT / SURFACE-DIFF 体（v4 布局）
// → cell 行编码网格 → 文本摘要（FNV-1a 64「行 \n 连接、占位格跳过、空符号补空格、
// 行尾裁空白」——与出口 Go / 客户端 C++ 两端逐字节同口径）。只做解码 + 摘要方向。
package cleanroom

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
)

// surface op（spec 分配；净室按 spec 重新声明）。
const (
	opSnapshot    byte = 0x0D
	opSurfaceDiff byte = 0x0F
)

// GoldenSample manifest.tsv 一行（列序与 golden 生成端一致）。
type GoldenSample struct {
	Name       string
	Op         byte
	Cols, Rows int
	Revision   uint32
	Digest     string
	Title      string
	FrameCount int
	Cx, Cy     int
	Cflags     int
	Cshape     int
	Total      int64
	Offset     int64
	Slen       int
}

// LoadGoldenManifest 解析 manifest.tsv（自解析 TSV——与两端同款）。
func LoadGoldenManifest(data []byte) ([]GoldenSample, error) {
	var out []GoldenSample
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 8 {
			return nil, fmt.Errorf("cleanroom: golden manifest 行缺列（%d 列）：%q", len(f), line)
		}
		atoi := func(s string) int {
			n, _ := strconv.Atoi(s)
			return n
		}
		op64, err := strconv.ParseUint(strings.TrimPrefix(f[1], "0x"), 16, 8)
		if err != nil {
			return nil, fmt.Errorf("cleanroom: golden manifest op 列非法：%q", f[1])
		}
		rev64, _ := strconv.ParseUint(f[4], 10, 32)
		s := GoldenSample{
			Name: f[0], Op: byte(op64),
			Cols: atoi(f[2]), Rows: atoi(f[3]), Revision: uint32(rev64),
			Digest: f[5], Title: f[6], FrameCount: atoi(f[7]),
		}
		if len(f) >= 12 {
			s.Cx, s.Cy, s.Cflags, s.Cshape = atoi(f[8]), atoi(f[9]), atoi(f[10]), atoi(f[11])
		}
		if len(f) >= 15 {
			s.Total, s.Offset, s.Slen = int64(atoi(f[12])), int64(atoi(f[13])), atoi(f[14])
		}
		out = append(out, s)
	}
	return out, nil
}

// GoldenFrame 一帧：op + 分片序列（每片 = 一个帧载荷 = [flags:1][gzip 部分]）。
type GoldenFrame struct {
	Op     byte
	Chunks [][]byte
}

// ReadGoldenFrames 解样例文件：[u32 帧数]{[op:1][u32 片数]{[u32 长][字节]}}。
func ReadGoldenFrames(b []byte) ([]GoldenFrame, error) {
	if len(b) < 4 {
		return nil, errors.New("cleanroom: 样例文件太短")
	}
	count := int(binary.LittleEndian.Uint32(b[0:4]))
	off := 4
	frames := make([]GoldenFrame, 0, count)
	for i := 0; i < count; i++ {
		if off+5 > len(b) {
			return nil, fmt.Errorf("cleanroom: 第 %d 帧头截断", i)
		}
		op := b[off]
		chunkCount := int(binary.LittleEndian.Uint32(b[off+1 : off+5]))
		off += 5
		fr := GoldenFrame{Op: op}
		for c := 0; c < chunkCount; c++ {
			if off+4 > len(b) {
				return nil, fmt.Errorf("cleanroom: 第 %d 帧第 %d 片长前缀截断", i, c)
			}
			n := int(binary.LittleEndian.Uint32(b[off : off+4]))
			off += 4
			if off+n > len(b) {
				return nil, fmt.Errorf("cleanroom: 第 %d 帧第 %d 片截断", i, c)
			}
			fr.Chunks = append(fr.Chunks, b[off:off+n])
			off += n
		}
		frames = append(frames, fr)
	}
	return frames, nil
}

// Deframe 一个分片组：逐片剥掉分片头（flags:1），拼接后解压出体。
func Deframe(fr GoldenFrame) ([]byte, error) {
	var gz []byte
	for _, ch := range fr.Chunks {
		if len(ch) < 1 {
			return nil, errors.New("cleanroom: 分片头缺失")
		}
		gz = append(gz, ch[1:]...)
	}
	return Gunzip(gz)
}

// SurfaceState 应用完帧序列后的可断言面（与 manifest 列一一对应）。
type SurfaceState struct {
	Cols, Rows int
	Revision   uint32
	Lines      []string
	Cursor     struct{ X, Y, Flags, Shape int }
	Scroll     struct {
		Total, Offset int64
		Len           int
	}
}

// ApplyFrames 按序喂帧：首帧必须是 SNAPSHOT（建基线），后续 SURFACE-DIFF 覆盖脏行
// 并刷新光标/回滚条。revision 断档/布局不符 = 拒收（与客户端状态机同语义的净室最小版）。
func ApplyFrames(frames []GoldenFrame) (*SurfaceState, error) {
	if len(frames) == 0 {
		return nil, errors.New("cleanroom: 样例无帧")
	}
	body, err := Deframe(frames[0])
	if err != nil {
		return nil, err
	}
	snap, err := decodeSnapshotBody(body)
	if err != nil {
		return nil, err
	}
	if frames[0].Op != opSnapshot {
		return nil, fmt.Errorf("cleanroom: 首帧 op=0x%02x 应为 SNAPSHOT", frames[0].Op)
	}
	st := &SurfaceState{Cols: snap.cols, Rows: snap.rows, Revision: snap.rev, Lines: snap.lines}
	st.Cursor = snap.cursor
	st.Scroll = snap.scroll
	for _, fr := range frames[1:] {
		if fr.Op != opSurfaceDiff {
			return nil, fmt.Errorf("cleanroom: 后续帧 op=0x%02x 应为 SURFACE-DIFF", fr.Op)
		}
		body, err := Deframe(fr)
		if err != nil {
			return nil, err
		}
		d, err := decodeDiffBody(body)
		if err != nil {
			return nil, err
		}
		if d.rev != st.Revision {
			return nil, fmt.Errorf("cleanroom: 差分 revision %d 与基线 %d 断档（应拒收）", d.rev, st.Revision)
		}
		for _, r := range d.rows {
			if r.y >= 0 && r.y < len(st.Lines) {
				st.Lines[r.y] = r.text
			}
		}
		st.Cursor = d.cursor
		st.Scroll = d.scroll
	}
	return st, nil
}

// DigestHex 文本摘要：FNV-1a 64 of「行以 \n 连接」（两端逐字节一致口径）。
func DigestHex(lines []string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(strings.Join(lines, "\n")))
	return fmt.Sprintf("%016x", h.Sum64())
}

// ---- SNAPSHOT 体（v4）：ver rev cols rows cursor(2+2+1+1) modes kitty misc
// scroll(total u64+offset u64+len u16) titleLen title gridLen grid mirrorLen mirror ----

type surfaceSnapshot struct {
	cols, rows int
	rev        uint32
	lines      []string
	cursor     struct{ X, Y, Flags, Shape int }
	scroll     struct {
		Total, Offset int64
		Len           int
	}
}

type cursor4 struct{ X, Y, Flags, Shape int }
type scroll3 struct {
	Total, Offset int64
	Len           int
}

func decodeSnapshotBody(p []byte) (surfaceSnapshot, error) {
	var s surfaceSnapshot
	r := &breader{p: p}
	ver, err := r.u8()
	if err != nil || ver != 4 {
		return s, fmt.Errorf("cleanroom: snapshot 版本 %d（期望 4）", ver)
	}
	if s.rev, err = r.u32(); err != nil {
		return s, err
	}
	cols, err := r.u16()
	if err != nil {
		return s, err
	}
	rows, err := r.u16()
	if err != nil {
		return s, err
	}
	s.cols, s.rows = int(cols), int(rows)
	cx, _ := r.u16()
	cy, _ := r.u16()
	cflags, _ := r.u8()
	cshape, _ := r.u8()
	s.cursor = cursor4{int(cx), int(cy), int(cflags), int(cshape)}
	if _, err = r.u32(); err != nil { // modes
		return s, err
	}
	if _, err = r.u8(); err != nil { // kitty
		return s, err
	}
	if _, err = r.u8(); err != nil { // misc
		return s, err
	}
	total, err := r.u64()
	if err != nil {
		return s, err
	}
	offset, err := r.u64()
	if err != nil {
		return s, err
	}
	slen, err := r.u16()
	if err != nil {
		return s, err
	}
	s.scroll = scroll3{int64(total), int64(offset), int(slen)}
	tl, err := r.u16()
	if err != nil {
		return s, err
	}
	if _, err = r.str(int(tl)); err != nil { // title（净室不比标题，只按布局消费）
		return s, err
	}
	gl, err := r.u32()
	if err != nil {
		return s, err
	}
	grid, err := r.bytes(int(gl))
	if err != nil {
		return s, err
	}
	ml, err := r.u32()
	if err != nil {
		return s, err
	}
	if _, err = r.bytes(int(ml)); err != nil { // mirror（同构网格，摘要面只看视口）
		return s, err
	}
	s.lines, err = DecodeGridLines(grid)
	return s, err
}

// ---- SURFACE-DIFF 体（v4）：ver rev cols rows rowCount cursor modes scroll rows ----

type surfaceDiff struct {
	rev    uint32
	cursor cursor4
	scroll scroll3
	rows   []gridRow
}

func decodeDiffBody(p []byte) (surfaceDiff, error) {
	var d surfaceDiff
	r := &breader{p: p}
	ver, err := r.u8()
	if err != nil || ver != 4 {
		return d, fmt.Errorf("cleanroom: diff 版本 %d（期望 4）", ver)
	}
	if d.rev, err = r.u32(); err != nil {
		return d, err
	}
	cols, err := r.u16()
	if err != nil {
		return d, err
	}
	if _, err = r.u16(); err != nil { // rows
		return d, err
	}
	rc, err := r.u16()
	if err != nil {
		return d, err
	}
	cx, _ := r.u16()
	cy, _ := r.u16()
	cflags, _ := r.u8()
	cshape, _ := r.u8()
	d.cursor = cursor4{int(cx), int(cy), int(cflags), int(cshape)}
	if _, err = r.u32(); err != nil { // modes
		return d, err
	}
	total, err := r.u64()
	if err != nil {
		return d, err
	}
	offset, err := r.u64()
	if err != nil {
		return d, err
	}
	slen, err := r.u16()
	if err != nil {
		return d, err
	}
	d.scroll = scroll3{int64(total), int64(offset), int(slen)}
	d.rows, err = DecodeRows(r.rest(), int(rc), int(cols))
	return d, err
}

// ---- cell 行编码（cellcodec 契约的净室解码） ----

type gridRow struct {
	y    int
	text string
}

// DecodeGridLines 解网格块：[ver:1][cols:2][rows:2] + 逐行 [y:2][格流…]。
func DecodeGridLines(b []byte) ([]string, error) {
	if len(b) < 5 {
		return nil, errors.New("cleanroom: 网格头太短")
	}
	if b[0] != 1 {
		return nil, fmt.Errorf("cleanroom: 网格版本 %d 不认识", b[0])
	}
	cols := int(binary.LittleEndian.Uint16(b[1:3]))
	rows := int(binary.LittleEndian.Uint16(b[3:5]))
	rl, err := DecodeRows(b[5:], rows, cols)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(rl))
	for i, r := range rl {
		out[i] = r.text
	}
	return out, nil
}

// DecodeRows 解「每行 [y:2][格流…]」序列（count 行）。格流标记：
// 0x00=空白游程（后跟 varint）、0x01=完整格、0x02=重复上一格（后跟 varint）。
// 文本口径：占位格（格头高位）跳过不画、空符号补空格、行尾裁空白。
func DecodeRows(b []byte, count, cols int) ([]gridRow, error) {
	out := make([]gridRow, 0, count)
	off := 0
	for i := 0; i < count; i++ {
		if off+2 > len(b) {
			return nil, errors.New("cleanroom: 行头截断")
		}
		y := int(binary.LittleEndian.Uint16(b[off:]))
		off += 2
		var sb strings.Builder
		prev := ""
		prevSkip := false
		havePrev := false
		cells := 0
		for cells < cols && off < len(b) {
			switch b[off] {
			case 0x00: // 空白游程
				off++
				n, adv, err := varint(b[off:])
				if err != nil {
					return nil, err
				}
				off += adv
				for k := uint64(0); k < n && cells < cols; k++ {
					sb.WriteByte(' ')
					cells++
				}
			case 0x02: // 重复上一格
				off++
				n, adv, err := varint(b[off:])
				if err != nil {
					return nil, err
				}
				off += adv
				if !havePrev {
					return nil, errors.New("cleanroom: 重复格前没有上一格")
				}
				for k := uint64(0); k < n && cells < cols; k++ {
					if !prevSkip {
						if prev == "" {
							sb.WriteByte(' ')
						} else {
							sb.WriteString(prev)
						}
					}
					cells++
				}
			case 0x01: // 完整格：[hdr: symLen|skip<<7][sym][fg 色][bg 色][属性 2]
				off++
				if off >= len(b) {
					return nil, errors.New("cleanroom: 格头截断")
				}
				hdr := b[off]
				off++
				symLen := int(hdr & 0x7f)
				skip := hdr&0x80 != 0
				if off+symLen > len(b) {
					return nil, errors.New("cleanroom: 符号截断")
				}
				sym := string(b[off : off+symLen])
				off += symLen
				for c := 0; c < 2; c++ { // 前景/背景色：kind 0=1B 1=2B 2=4B
					if off >= len(b) {
						return nil, errors.New("cleanroom: 颜色截断")
					}
					switch b[off] {
					case 0:
						off++
					case 1:
						off += 2
					case 2:
						off += 4
					default:
						return nil, fmt.Errorf("cleanroom: 未知颜色标记 0x%02x", b[off])
					}
				}
				if off+2 > len(b) {
					return nil, errors.New("cleanroom: 属性截断")
				}
				off += 2
				cells++ // 占位格也占一格
				prev, prevSkip, havePrev = sym, skip, true
				if skip {
					continue
				}
				if sym == "" {
					sb.WriteByte(' ')
				} else {
					sb.WriteString(sym)
				}
			default:
				return nil, fmt.Errorf("cleanroom: 未知格标记 0x%02x", b[off])
			}
		}
		out = append(out, gridRow{y: y, text: strings.TrimRight(sb.String(), " ")})
	}
	return out, nil
}

func varint(b []byte) (uint64, int, error) {
	var v uint64
	for i := 0; i < len(b) && i < 10; i++ {
		v |= uint64(b[i]&0x7f) << (7 * uint(i))
		if b[i]&0x80 == 0 {
			return v, i + 1, nil
		}
	}
	return 0, 0, errors.New("cleanroom: varint 截断")
}

// breader 净室的小字节读取器（体解码用）。
type breader struct {
	p   []byte
	off int
}

func (r *breader) need(n int) error {
	if r.off+n > len(r.p) {
		return fmt.Errorf("cleanroom: 体截断（要 %d 有 %d）", r.off+n, len(r.p))
	}
	return nil
}

func (r *breader) u8() (byte, error) {
	if err := r.need(1); err != nil {
		return 0, err
	}
	v := r.p[r.off]
	r.off++
	return v, nil
}

func (r *breader) u16() (uint16, error) {
	if err := r.need(2); err != nil {
		return 0, err
	}
	v := binary.LittleEndian.Uint16(r.p[r.off:])
	r.off += 2
	return v, nil
}

func (r *breader) u32() (uint32, error) {
	if err := r.need(4); err != nil {
		return 0, err
	}
	v := binary.LittleEndian.Uint32(r.p[r.off:])
	r.off += 4
	return v, nil
}

func (r *breader) u64() (uint64, error) {
	if err := r.need(8); err != nil {
		return 0, err
	}
	v := binary.LittleEndian.Uint64(r.p[r.off:])
	r.off += 8
	return v, nil
}

func (r *breader) bytes(n int) ([]byte, error) {
	if err := r.need(n); err != nil {
		return nil, err
	}
	v := r.p[r.off : r.off+n]
	r.off += n
	return v, nil
}

func (r *breader) str(n int) (string, error) {
	b, err := r.bytes(n)
	return string(b), err
}

func (r *breader) rest() []byte {
	if r.off >= len(r.p) {
		return nil
	}
	return r.p[r.off:]
}
