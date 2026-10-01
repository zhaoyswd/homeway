// Package cleanroom — 净室最小解码器（contract-ledger 4b，design D4）。
//
// 纪律：只 import 标准库（import 面审计测试钉死白名单）；不 import 任何生产包。
// 这里的一切都只凭「spec 口径 + fixtures 文件」从零解出——它存在的目的就是证明
// 三族 fixtures + 上行字节表自足（今天净室 Go 能从零解出 = 未来 TS 消费者同路径
// 可行），不是生产解码器的替代或搬运。只做解码 + 摘要方向（spec 冻结等级②：
// 编码方向只要求结构等价，不设净室义务）。
//
// **冻结（FIX-103）**：净室是为未立项 4c（web 客户端）投的保——冻结期只解码、
// 不加族；导出面清单由 frozen_test.go 机器钉死。新增族必须等 4c 立项后**按 spec
// 重写净室**，不允许在冻结期内顺手扩面（净室一旦追着生产跑，「自足证明」就没了）。
package cleanroom

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// RepoRoot 自 cwd 向上找 go.mod（净室自含版——不 import contracts，防依赖面渗漏）。
func RepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if dir == string(filepath.Separator) || dir == "" {
			return "", fmt.Errorf("cleanroom: 未找到仓根（go.mod）")
		}
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		dir = filepath.Dir(dir)
	}
}

// ---- 控制面帧：[op:1][len:4 BE][body]（daemon-control-plane「帧封装」冻结口径） ----

// DecodeControlFrame 解一帧控制面字节。返回 op 与 body（JSON 或流透传）。
func DecodeControlFrame(b []byte) (op byte, body []byte, err error) {
	if len(b) < 5 {
		return 0, nil, fmt.Errorf("cleanroom: 控制帧头截断（%d 字节）", len(b))
	}
	op = b[0]
	n := binary.BigEndian.Uint32(b[1:5])
	if uint64(n) != uint64(len(b)-5) {
		return op, nil, fmt.Errorf("cleanroom: 控制帧声明 %d 字节，实际 %d", n, len(b)-5)
	}
	return op, b[5:], nil
}

// DecodeControlBody 把 body 解成可与 expect 深比较的值：流 DATA（op=0x20）=
// [streamId:4 BE][原始字节] → {"streamId":N,"bytesHex":"…"}；其余 = JSON 对象。
func DecodeControlBody(op byte, body []byte) (any, error) {
	if op == 0x20 { // stream.data
		if len(body) < 4 {
			return nil, fmt.Errorf("cleanroom: 流 body 短于 streamId 前缀（%d）", len(body))
		}
		id := binary.BigEndian.Uint32(body[:4])
		return map[string]any{
			"streamId": float64(id),
			"bytesHex": hex.EncodeToString(body[4:]),
		}, nil
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("cleanroom: 控制帧 body 非法 JSON（op=0x%02x）：%w", op, err)
	}
	return m, nil
}

// ---- term 帧：[op:1][len:2 LE][payload]（exit-terminal design D4） ----

// term op（spec 分配；净室按 spec 重新声明——与生产包各持一份正是被对拍的两面）。
const (
	termOpHello      byte = 0x00
	termOpData       byte = 0x01
	termOpResize     byte = 0x02
	termOpEnded      byte = 0x03
	termOpKill       byte = 0x05
	termOpError      byte = 0x06
	termOpState      byte = 0x07
	termOpReplayDone byte = 0x0A
	termOpOK         byte = 0x0B
	termOpGreeting   byte = 0x0C
)

// 解码错误类别（负例向量 expect.error 的值域）。
var (
	ErrShortHeader = errors.New("cleanroom: 短头")
	ErrTruncated   = errors.New("cleanroom: 截断")
	ErrBadPayload  = errors.New("cleanroom: 畸形载荷")
)

// BuildTermFrame 组帧（期望重建用）。
func BuildTermFrame(op byte, payload []byte) []byte {
	out := make([]byte, 3+len(payload))
	out[0] = op
	binary.LittleEndian.PutUint16(out[1:3], uint16(len(payload)))
	copy(out[3:], payload)
	return out
}

// DecodeTermFrame 解一帧：头不足 = ErrShortHeader；声明长度超过实际 = ErrTruncated。
func DecodeTermFrame(b []byte) (op byte, payload []byte, err error) {
	if len(b) < 3 {
		return 0, nil, ErrShortHeader
	}
	op = b[0]
	n := int(binary.LittleEndian.Uint16(b[1:3]))
	if n > len(b)-3 {
		return op, nil, ErrTruncated
	}
	return op, b[3 : 3+n], nil
}

// DecodeTermPayload 按 op 把 payload 解成 expect 形态的结构
// （{"greeting":{ver,features}} 等——该结构即 term 帧族的跨语言解码契约，design D3）。
// 载荷畸形返回 ErrBadPayload。
func DecodeTermPayload(op byte, p []byte) (map[string]any, error) {
	u16 := func(off int) (uint16, bool) {
		if off+2 > len(p) {
			return 0, false
		}
		return binary.LittleEndian.Uint16(p[off : off+2]), true
	}
	u32 := func(off int) (uint32, bool) {
		if off+4 > len(p) {
			return 0, false
		}
		return binary.LittleEndian.Uint32(p[off : off+4]), true
	}
	str := func(off, n int) (string, bool) {
		if off+n > len(p) {
			return "", false
		}
		return string(p[off : off+n]), true
	}
	bad := func() (map[string]any, error) { return nil, ErrBadPayload }
	switch op {
	case termOpGreeting: // [ver:1][features:4 LE]
		if len(p) < 5 {
			return bad()
		}
		feats, _ := u32(1)
		return map[string]any{"greeting": map[string]any{
			"ver": float64(p[0]), "features": float64(feats),
		}}, nil
	case termOpHello: // [cols:2][rows:2][flags:1][nameLen:1][name]
		if len(p) < 6 {
			return bad()
		}
		cols, _ := u16(0)
		rows, _ := u16(2)
		name, ok := str(6, int(p[5]))
		if !ok {
			return bad()
		}
		return map[string]any{"hello": map[string]any{
			"cols": float64(cols), "rows": float64(rows),
			"flags": float64(p[4]), "name": name,
		}}, nil
	case termOpResize: // [cols:2][rows:2]
		if len(p) < 4 {
			return bad()
		}
		cols, _ := u16(0)
		rows, _ := u16(2)
		return map[string]any{"resize": map[string]any{
			"cols": float64(cols), "rows": float64(rows),
		}}, nil
	case termOpReplayDone: // [rev:4 LE][flags:1]
		if len(p) < 5 {
			return bad()
		}
		rev, _ := u32(0)
		return map[string]any{"replayDone": map[string]any{
			"rev": float64(rev), "flags": float64(p[4]),
		}}, nil
	case termOpEnded: // [code:4 LE][reasonLen:1][reason]
		if len(p) < 5 {
			return bad()
		}
		code, _ := u32(0)
		reason, ok := str(5, int(p[4]))
		if !ok {
			return bad()
		}
		return map[string]any{"ended": map[string]any{
			"code": float64(int32(code)), "reason": reason,
		}}, nil
	case termOpState: // [agent:1][stateV2:1][titleLen:2 LE][title]
		if len(p) < 4 {
			return bad()
		}
		tl, _ := u16(2)
		title, ok := str(4, int(tl))
		if !ok {
			return bad()
		}
		return map[string]any{"state": map[string]any{
			"agent": float64(p[0]), "stateV2": float64(p[1]), "title": title,
		}}, nil
	case termOpError: // [codeLen:1][code][msgLen:2 LE][msg]
		if len(p) < 1 {
			return bad()
		}
		cl := int(p[0])
		code, ok := str(1, cl)
		if !ok || len(p) < 1+cl+2 {
			return bad()
		}
		ml := int(binary.LittleEndian.Uint16(p[1+cl : 3+cl]))
		msg, ok := str(3+cl, ml)
		if !ok {
			return bad()
		}
		return map[string]any{"error": map[string]any{"code": code, "msg": msg}}, nil
	case termOpOK: // 空载荷
		if len(p) != 0 {
			return bad()
		}
		return map[string]any{"ok": map[string]any{}}, nil
	case termOpKill: // [nameLen:1][name]
		if len(p) < 1 {
			return bad()
		}
		name, ok := str(1, int(p[0]))
		if !ok {
			return bad()
		}
		return map[string]any{"kill": map[string]any{"name": name}}, nil
	case termOpData: // 按字节等价断言、不设字段结构（N-10）
		return map[string]any{"data": map[string]any{"bytes": hex.EncodeToString(p)}}, nil
	}
	return nil, fmt.Errorf("cleanroom: term op 0x%02x 不在净室面（新增帧型须同步向量 schema 两端）", op)
}

// ---- surface 上行（客户端 → 出口）：TSV manifest 的「按期望 hex 解码」方向 ----

// DecodeUplink 按字节表 manifest 的 category 解上行载荷，返回与 args 对拍的字段表
// （数值一律 float64、颜色为 hex 串——与测试侧 args 解析同构）。
func DecodeUplink(category string, p []byte) (map[string]any, error) {
	u16 := func(off int) (uint16, error) {
		if off+2 > len(p) {
			return 0, ErrBadPayload
		}
		return binary.LittleEndian.Uint16(p[off : off+2]), nil
	}
	switch category {
	case "key": // [kind=0][key:2 LE][mods:2 LE][action:1][textLen:1][text]
		if len(p) < 7 {
			return nil, ErrBadPayload
		}
		key, err := u16(1)
		if err != nil {
			return nil, err
		}
		mods, err := u16(3)
		if err != nil {
			return nil, err
		}
		if 7+int(p[6]) > len(p) {
			return nil, ErrBadPayload
		}
		return map[string]any{
			"kind": float64(p[0]), "key": float64(key), "mods": float64(mods),
			"action": float64(p[5]), "text": string(p[7 : 7+int(p[6])]),
		}, nil
	case "text": // [kind=1][flags:1][len:2 LE][text]（bit0=paste bit1=more bit2=cont）
		if len(p) < 4 {
			return nil, ErrBadPayload
		}
		n, err := u16(2)
		if err != nil || 4+int(n) > len(p) {
			return nil, ErrBadPayload
		}
		return map[string]any{
			"kind": float64(p[0]), "flags": float64(p[1]), "text": string(p[4 : 4+int(n)]),
		}, nil
	case "mouse": // [kind=2][action:1][button:1][mods:2 LE][x:2 LE][y:2 LE]
		if len(p) < 9 {
			return nil, ErrBadPayload
		}
		mods, err := u16(3)
		if err != nil {
			return nil, err
		}
		x, err := u16(5)
		if err != nil {
			return nil, err
		}
		y, err := u16(7)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"kind": float64(p[0]), "action": float64(p[1]), "button": float64(p[2]),
			"mods": float64(mods), "x": float64(x), "y": float64(y),
		}, nil
	case "focus": // [kind=3][gained:1]
		if len(p) < 2 {
			return nil, ErrBadPayload
		}
		return map[string]any{"kind": float64(p[0]), "gained": float64(p[1])}, nil
	case "theme": // [flags:1][fg:3][bg:3]（bit0=dark；深浅在前）
		if len(p) < 7 {
			return nil, ErrBadPayload
		}
		return map[string]any{
			"dark": float64(p[0] & 1),
			"fg":   hex.EncodeToString(p[1:4]), "bg": hex.EncodeToString(p[4:7]),
		}, nil
	case "clipboard": // 读应答：[kind=2][len:2 LE][text]
		if len(p) < 3 {
			return nil, ErrBadPayload
		}
		n, err := u16(1)
		if err != nil || 3+int(n) > len(p) {
			return nil, ErrBadPayload
		}
		return map[string]any{
			"kind": float64(p[0]), "text": string(p[3 : 3+int(n)]),
		}, nil
	case "caps": // [capLen:1][flags:capLen]（capLen 是 flags 的字节数）
		if len(p) < 1 || 1+int(p[0]) > len(p) {
			return nil, ErrBadPayload
		}
		var flags byte
		for _, b := range p[1 : 1+int(p[0])] {
			flags |= b
		}
		return map[string]any{"capLen": float64(p[0]), "flags": float64(flags)}, nil
	case "hello-tail": // [capLen:1][caps:capLen][ver:1?][idLen:1][id]（FIX-29 版本门）
		// ver 只在 caps 位 7（capsProtoVer）置位时出现；未出现与 args 同口径返回 0。
		const capsProtoVerBit = 0x80 // 与服务端 pkg/term capsProtoVer / codec kCapsProtoVer 同值
		if len(p) < 1 || 1+int(p[0]) > len(p) {
			return nil, ErrBadPayload
		}
		var caps byte
		for _, b := range p[1 : 1+int(p[0])] {
			caps |= b
		}
		off := 1 + int(p[0])
		var ver byte
		if caps&capsProtoVerBit != 0 {
			if off >= len(p) {
				return nil, ErrBadPayload
			}
			ver = p[off]
			off++
		}
		id := ""
		if off < len(p) {
			n := int(p[off])
			if off+1+n > len(p) {
				return nil, ErrBadPayload
			}
			id = string(p[off+1 : off+1+n])
		}
		return map[string]any{"caps": float64(caps), "ver": float64(ver), "id": id}, nil
	}
	return nil, fmt.Errorf("cleanroom: 上行 category %q 不认识（扩表须同步两端）", category)
}

// ---- 小件 ----

// Gunzip 解一段 gzip（surface 大载荷 = gzip 后分片）。
func Gunzip(p []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(p))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(zr)
}
