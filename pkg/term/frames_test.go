//go:build !windows

package term

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// 帧编解码判据（openspec exit-terminal 设计 D4；contract-ledger 3.1 起语言无关化）。
//
// 向量真源 = testdata/frames.v1.jsonl（跨语言解码契约：正向例 payloadHex + expect
// 期望解码结构；负例整帧 hex + 解码错误类别）。本测试与 contracts/cleanroom 净室
// 实现共用同一份期望——内嵌表驱动已删，不留双轨（改布局 = 改向量文件，两端同红）。

// termVector fixtures 一行：正向例带 payloadHex，负例（category=negative）带整帧 hex。
type termVector struct {
	Name       string          `json:"name"`
	Category   string          `json:"category"`
	Op         string          `json:"op"`
	PayloadHex string          `json:"payloadHex,omitempty"`
	Hex        string          `json:"hex,omitempty"`
	Expect     json.RawMessage `json:"expect"`
}

func loadTermVectors(t *testing.T) []termVector {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "frames.v1.jsonl"))
	if err != nil {
		t.Fatalf("读向量文件：%v", err)
	}
	defer f.Close()
	var out []termVector
	dec := json.NewDecoder(f)
	for dec.More() {
		var v termVector
		if err := dec.Decode(&v); err != nil {
			t.Fatalf("向量行非法 JSON：%v", err)
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		t.Fatal("向量文件为空（空集假绿）")
	}
	return out
}

func parseOp(t *testing.T, s string) byte {
	t.Helper()
	var op byte
	if _, err := fmt.Sscanf(s, "0x%02x", &op); err != nil {
		t.Fatalf("op 字段非法：%q", s)
	}
	return op
}

func TestTermFrameVectors(t *testing.T) {
	for _, v := range loadTermVectors(t) {
		op := parseOp(t, v.Op)
		if v.Hex != "" {
			checkNegativeVector(t, v, op)
			continue
		}
		payload, err := hex.DecodeString(v.PayloadHex)
		if err != nil {
			t.Fatalf("%s：payloadHex 非法：%v", v.Name, err)
		}
		raw := encodeTermFrame(op, payload)
		got, err := readTermFrame(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("%s: readTermFrame: %v", v.Name, err)
		}
		if got.op != op || !bytes.Equal(got.payload, payload) {
			t.Fatalf("%s: 往返不一致 got op=0x%02x payload=%q", v.Name, got.op, got.payload)
		}
		checkTermExpect(t, v, op, got.payload)
	}
}

// checkTermExpect 按 expect 的唯一键（= 帧类型）分派到生产解码器，与期望解码结构
// 逐字段比较——这是「期望解码」而不是「往返一致」的自证（contract-ledger 中-7）。
func checkTermExpect(t *testing.T, v termVector, op byte, payload []byte) {
	t.Helper()
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(v.Expect, &keys); err != nil {
		t.Fatalf("%s：expect 非法：%v", v.Name, err)
	}
	if len(keys) != 1 {
		t.Fatalf("%s：expect 应恰有一个类型键， got %d 个", v.Name, len(keys))
	}
	for kind, raw := range keys {
		decode := func(dst any) {
			t.Helper()
			if err := json.Unmarshal(raw, dst); err != nil {
				t.Fatalf("%s：expect.%s 非法：%v", v.Name, kind, err)
			}
		}
		fail := func(got, want any) {
			t.Helper()
			t.Errorf("%s：expect.%s 不符：got %v want %v", v.Name, kind, got, want)
		}
		switch kind {
		case "greeting":
			var e struct {
				Ver      byte   `json:"ver"`
				Features uint32 `json:"features"`
			}
			decode(&e)
			ver, features, err := decGreeting(payload)
			if err != nil {
				t.Fatalf("%s：decGreeting：%v", v.Name, err)
			}
			if ver != e.Ver {
				fail(ver, e.Ver)
			}
			if features != e.Features {
				fail(features, e.Features)
			}
		case "hello":
			var e struct {
				Cols  uint16 `json:"cols"`
				Rows  uint16 `json:"rows"`
				Flags byte   `json:"flags"`
				Name  string `json:"name"`
			}
			decode(&e)
			cols, rows, flags, name, err := decHello(payload)
			if err != nil {
				t.Fatalf("%s：decHello：%v", v.Name, err)
			}
			if cols != e.Cols || rows != e.Rows || flags != e.Flags || name != e.Name {
				fail([]any{cols, rows, flags, name}, []any{e.Cols, e.Rows, e.Flags, e.Name})
			}
		case "resize":
			var e struct {
				Cols uint16 `json:"cols"`
				Rows uint16 `json:"rows"`
			}
			decode(&e)
			cols, rows, err := decResize(payload)
			if err != nil {
				t.Fatalf("%s：decResize：%v", v.Name, err)
			}
			if cols != e.Cols || rows != e.Rows {
				fail([]any{cols, rows}, []any{e.Cols, e.Rows})
			}
		case "replayDone":
			// 无独立生产解码器（服务端只发不收）：按 D4 布局 [rev:4 LE][flags:1] 解。
			var e struct {
				Rev   uint32 `json:"rev"`
				Flags byte   `json:"flags"`
			}
			decode(&e)
			if len(payload) < 5 {
				t.Fatalf("%s：REPLAY-DONE 载荷过短", v.Name)
			}
			if rev := binary.LittleEndian.Uint32(payload[0:4]); rev != e.Rev {
				fail(rev, e.Rev)
			}
			if payload[4] != e.Flags {
				fail(payload[4], e.Flags)
			}
		case "ended":
			var e struct {
				Code   int32  `json:"code"`
				Reason string `json:"reason"`
			}
			decode(&e)
			code, reason := decEndedParts(payload)
			if code != e.Code || reason != e.Reason {
				fail([]any{code, reason}, []any{e.Code, e.Reason})
			}
		case "state":
			var e struct {
				Agent   byte   `json:"agent"`
				StateV2 byte   `json:"stateV2"`
				Title   string `json:"title"`
			}
			decode(&e)
			agent, st, title := decStateTitle(payload)
			if agent != e.Agent || st != e.StateV2 || title != e.Title {
				fail([]any{agent, st, title}, []any{e.Agent, e.StateV2, e.Title})
			}
		case "error":
			var e struct {
				Code string `json:"code"`
				Msg  string `json:"msg"`
			}
			decode(&e)
			code, msg, err := decError(payload)
			if err != nil {
				t.Fatalf("%s：decError：%v", v.Name, err)
			}
			if code != e.Code || msg != e.Msg {
				fail([]any{code, msg}, []any{e.Code, e.Msg})
			}
		case "ok":
			if len(payload) != 0 {
				fail(len(payload), 0)
			}
		case "kill":
			var e struct {
				Name string `json:"name"`
			}
			decode(&e)
			name, err := decName(payload)
			if err != nil {
				t.Fatalf("%s：decName：%v", v.Name, err)
			}
			if name != e.Name {
				fail(name, e.Name)
			}
		case "data":
			// payload 按字节等价断言、不设字段结构（N-10）。
			var e struct {
				Bytes string `json:"bytes"`
			}
			decode(&e)
			if got := hex.EncodeToString(payload); got != e.Bytes {
				fail(got, e.Bytes)
			}
		default:
			t.Fatalf("%s：expect 类型键 %q 不认识（新增帧型须同步向量 schema 两端）", v.Name, kind)
		}
	}
}

// checkNegativeVector 负例：整帧 hex 必须按声明的错误类别被拒收。
//
//	short_header = 3 字节头都没读全；truncated = 头完整但声明长度 > 实际载荷；
//	bad_payload  = 帧完整、载荷层解码报错。
func checkNegativeVector(t *testing.T, v termVector, op byte) {
	t.Helper()
	var e struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(v.Expect, &e); err != nil || e.Error == "" {
		t.Fatalf("%s：负例 expect 应为 {\"error\":\"类别\"}", v.Name)
	}
	raw, err := hex.DecodeString(v.Hex)
	if err != nil {
		t.Fatalf("%s：hex 非法：%v", v.Name, err)
	}
	_, ferr := readTermFrame(bytes.NewReader(raw))
	switch e.Error {
	case "short_header":
		if ferr == nil || len(raw) >= 3 {
			t.Errorf("%s：短头应当报错（err=%v len=%d）", v.Name, ferr, len(raw))
		}
	case "truncated":
		if ferr == nil {
			t.Errorf("%s：截断的帧应当报错", v.Name)
		} else if len(raw) >= 3 {
			declared := int(binary.LittleEndian.Uint16(raw[1:3]))
			if declared <= len(raw)-3 {
				t.Errorf("%s：类别不符——声明 %d 未超过实际 %d", v.Name, declared, len(raw)-3)
			}
		}
	case "bad_payload":
		if ferr != nil {
			t.Errorf("%s：帧本身应完整（err=%v）", v.Name, ferr)
			return
		}
		payload := raw[3:]
		var derr error
		switch op {
		case opHello:
			_, _, _, _, derr = decHello(payload)
		default:
			t.Fatalf("%s：op 0x%02x 无负例载荷解码器（新增须同步）", v.Name, op)
		}
		if derr == nil {
			t.Errorf("%s：畸形载荷应当报错", v.Name)
		}
	default:
		t.Fatalf("%s：负例类别 %q 不认识", v.Name, e.Error)
	}
}
