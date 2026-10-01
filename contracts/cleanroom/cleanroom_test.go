// cleanroom_test.go — 净室对拍（contract-ledger tasks 4.2，退出口判据②）：
// 只凭 spec 口径 + fixtures 文件，把三族向量与上行字节表全部从零解出——
//
//	① 控制面向量（hex 帧 + JSON body 解码断言）、② term 帧向量（op/payloadHex/expect）、
//	③ surface 下行 golden（manifest 摘要口径逐字节同两侧）、④ surface 上行字节表
//	（读 3.2 manifest 按期望 hex 解码对拍）。
//
// decode_check.py 保留可跑（在 internal/control 的测试里，净室是增益不是替换）。
package cleanroom

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func root(t *testing.T) string {
	t.Helper()
	r, err := RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestCleanroomControlPlane 控制面向量：hex 帧 → op/body → JSON 结构，与 expect 深比较。
func TestCleanroomControlPlane(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(root(t), "internal/control/testdata/fixtures/v1/frames.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var v struct {
			Name   string          `json:"name"`
			Cat    string          `json:"category"`
			Op     string          `json:"op"`
			Hex    string          `json:"hex"`
			Expect json.RawMessage `json:"expect"`
		}
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Fatalf("向量 %s 非法 JSON：%v", v.Name, err)
		}
		raw, err := hex.DecodeString(v.Hex)
		if err != nil {
			t.Fatalf("%s：hex 非法：%v", v.Name, err)
		}
		op, body, err := DecodeControlFrame(raw)
		if err != nil {
			t.Fatalf("%s：%v", v.Name, err)
		}
		if want := strings.TrimPrefix(v.Op, "0x"); want != hex.EncodeToString([]byte{op}) {
			t.Fatalf("%s：op=0x%02x 与声明 %s 不符", v.Name, op, v.Op)
		}
		got, err := DecodeControlBody(op, body)
		if err != nil {
			t.Fatalf("%s：%v", v.Name, err)
		}
		// expect 形态：流向量是裸 {streamId,bytesHex}，JSON 向量带 {"json":…} 包装。
		var want any
		var wrapped struct {
			JSON json.RawMessage `json:"json"`
		}
		if err := json.Unmarshal(v.Expect, &wrapped); err == nil && len(wrapped.JSON) > 0 {
			if err := json.Unmarshal(wrapped.JSON, &want); err != nil {
				t.Fatalf("%s：expect.json 非法：%v", v.Name, err)
			}
		} else if err := json.Unmarshal(v.Expect, &want); err != nil {
			t.Fatalf("%s：expect 非法：%v", v.Name, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s：净室解码与期望不符（「语言无关 fixtures 自足」被打破？）\n  解码=%v\n  期望=%v", v.Name, got, want)
		}
		n++
	}
	if n == 0 {
		t.Fatal("控制面向量零例（空集假绿）")
	}
	t.Logf("净室控制面：%d 向量全解出", n)
}

// TestCleanroomTermVectors term 帧向量：payloadHex 组帧 → 解码 → expect 结构深比较；
// 负例 = 解码错误类别。
func TestCleanroomTermVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(root(t), "pkg/term/testdata/frames.v1.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var v struct {
			Name       string          `json:"name"`
			Category   string          `json:"category"`
			Op         string          `json:"op"`
			PayloadHex string          `json:"payloadHex"`
			Hex        string          `json:"hex"`
			Expect     json.RawMessage `json:"expect"`
		}
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Fatalf("向量 %s 非法 JSON：%v", v.Name, err)
		}
		opByte, err := strconv.ParseUint(strings.TrimPrefix(v.Op, "0x"), 16, 8)
		if err != nil {
			t.Fatalf("%s：op 非法 %q", v.Name, v.Op)
		}
		if v.Hex != "" { // 负例
			raw, err := hex.DecodeString(v.Hex)
			if err != nil {
				t.Fatalf("%s：hex 非法：%v", v.Name, err)
			}
			var e struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(v.Expect, &e); err != nil || e.Error == "" {
				t.Fatalf("%s：负例 expect 应为类别", v.Name)
			}
			op, payload, ferr := DecodeTermFrame(raw)
			switch e.Error {
			case "short_header":
				if ferr != ErrShortHeader {
					t.Errorf("%s：应 ErrShortHeader，got %v", v.Name, ferr)
				}
			case "truncated":
				if ferr != ErrTruncated {
					t.Errorf("%s：应 ErrTruncated，got %v", v.Name, ferr)
				}
			case "bad_payload":
				if ferr != nil {
					t.Fatalf("%s：帧应完整（%v）", v.Name, ferr)
				}
				if _, derr := DecodeTermPayload(op, payload); derr != ErrBadPayload {
					t.Errorf("%s：应 ErrBadPayload，got %v", v.Name, derr)
				}
			default:
				t.Fatalf("%s：负例类别 %q 不认识", v.Name, e.Error)
			}
			n++
			continue
		}
		payload, err := hex.DecodeString(v.PayloadHex)
		if err != nil {
			t.Fatalf("%s：payloadHex 非法：%v", v.Name, err)
		}
		op, gotPayload, err := DecodeTermFrame(BuildTermFrame(byte(opByte), payload))
		if err != nil {
			t.Fatalf("%s：%v", v.Name, err)
		}
		if op != byte(opByte) || hex.EncodeToString(gotPayload) != v.PayloadHex {
			t.Fatalf("%s：帧往返不一致", v.Name)
		}
		got, err := DecodeTermPayload(op, gotPayload)
		if err != nil {
			t.Fatalf("%s：%v", v.Name, err)
		}
		var want any
		if err := json.Unmarshal(v.Expect, &want); err != nil {
			t.Fatalf("%s：expect 非法：%v", v.Name, err)
		}
		if !reflect.DeepEqual(any(got), want) {
			t.Errorf("%s：净室解码与期望解码结构不符\n  解码=%v\n  期望=%v", v.Name, got, want)
		}
		n++
	}
	if n == 0 {
		t.Fatal("term 向量零例（空集假绿）")
	}
	t.Logf("净室 term 帧：%d 向量全解出（含负例）", n)
}

// TestCleanroomSurfaceGolden surface 下行 golden：帧序列 → 状态 → 文本摘要
// （FNV-1a 64）+ 几何/光标/回滚条，与 manifest.tsv 逐列对拍。
func TestCleanroomSurfaceGolden(t *testing.T) {
	r := root(t)
	mb, err := os.ReadFile(filepath.Join(r, "surface/test/golden/manifest.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	samples, err := LoadGoldenManifest(mb)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) == 0 {
		t.Fatal("golden manifest 零样例（空集假绿）")
	}
	for _, s := range samples {
		bin, err := os.ReadFile(filepath.Join(r, "surface/test/golden", s.Name+".bin"))
		if err != nil {
			t.Fatalf("%s：读样例：%v", s.Name, err)
		}
		frames, err := ReadGoldenFrames(bin)
		if err != nil {
			t.Fatalf("%s：%v", s.Name, err)
		}
		if len(frames) != s.FrameCount {
			t.Errorf("%s：帧数 %d ≠ manifest %d", s.Name, len(frames), s.FrameCount)
			continue
		}
		st, err := ApplyFrames(frames)
		if err != nil {
			t.Errorf("%s：净室应用失败：%v", s.Name, err)
			continue
		}
		digest := DigestHex(st.Lines)
		var problems []string
		if st.Cols != s.Cols || st.Rows != s.Rows {
			problems = append(problems, "几何不符")
		}
		if st.Revision != s.Revision {
			problems = append(problems, "revision 不符")
		}
		if digest != s.Digest {
			problems = append(problems, "摘要不符")
		}
		if st.Cursor.X != s.Cx || st.Cursor.Y != s.Cy || st.Cursor.Flags != s.Cflags || st.Cursor.Shape != s.Cshape {
			problems = append(problems, "光标不符")
		}
		if st.Scroll.Total != s.Total || st.Scroll.Offset != s.Offset || st.Scroll.Len != s.Slen {
			problems = append(problems, "回滚条不符")
		}
		if len(problems) > 0 {
			t.Errorf("%s：%v（摘要 %s 期望 %s，几何 %dx%d 期望 %dx%d，光标 (%d,%d,%d,%d) 期望 (%d,%d,%d,%d)，回滚条 (%d,%d,%d) 期望 (%d,%d,%d)）",
				s.Name, problems, digest, s.Digest,
				st.Cols, st.Rows, s.Cols, s.Rows,
				st.Cursor.X, st.Cursor.Y, st.Cursor.Flags, st.Cursor.Shape, s.Cx, s.Cy, s.Cflags, s.Cshape,
				st.Scroll.Total, st.Scroll.Offset, st.Scroll.Len, s.Total, s.Offset, s.Slen)
		}
	}
	t.Logf("净室 surface golden：%d 样例全解出", len(samples))
}

// TestCleanroomUplinkCases surface 上行字节表：读 3.2 manifest，按期望 hex 解码、
// 与 args 对拍——上行布局自此 Go 侧有独立表，不再只由 C++ 测试单侧钉（r2 N-5）。
func TestCleanroomUplinkCases(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(root(t), "surface/test/host/surface_input_cases.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 4 {
			t.Fatalf("上行表行缺列：%q", line)
		}
		name, category, args, wantHex := f[0], f[1], f[2], f[3]
		raw, err := hex.DecodeString(wantHex)
		if err != nil {
			t.Fatalf("%s：hex 非法：%v", name, err)
		}
		got, err := DecodeUplink(category, raw)
		if err != nil {
			t.Fatalf("%s：%v", name, err)
		}
		want, err := uplinkArgsToFields(category, args)
		if err != nil {
			t.Fatalf("%s：%v", name, err)
		}
		if !reflect.DeepEqual(any(got), any(want)) {
			t.Errorf("%s：净室上行解码与 args 不符\n  解码=%v\n  args=%v", name, got, want)
		}
		n++
	}
	if n == 0 {
		t.Fatal("上行字节表零例（空集假绿）")
	}
	t.Logf("净室上行字节表：%d 例全解出", n)
}

// uplinkArgsToFields 把 TSV 的 args 列解析成与 DecodeUplink 同构的字段表
// （两侧同构本身被 DeepCompare 钉住——args 语义改了这里跟红）。
func uplinkArgsToFields(category, args string) (map[string]any, error) {
	split := func() []string {
		parts := strings.Split(args, ",")
		return parts
	}
	num := func(s string) float64 {
		v, err := strconv.ParseUint(s, 0, 64)
		if err != nil {
			return -1
		}
		return float64(v)
	}
	parts := split()
	need := func(n int) error {
		if len(parts) != n {
			return errBadArgs
		}
		return nil
	}
	switch category {
	case "key":
		if err := need(4); err != nil {
			return nil, err
		}
		return map[string]any{
			"kind": float64(0), "key": num(parts[0]), "mods": num(parts[1]),
			"action": num(parts[2]), "text": parts[3],
		}, nil
	case "text":
		if err := need(4); err != nil {
			return nil, err
		}
		flags := 0
		if parts[1] == "1" {
			flags |= 1
		}
		if parts[2] == "1" {
			flags |= 2
		}
		if parts[3] == "1" {
			flags |= 4
		}
		return map[string]any{"kind": float64(1), "flags": float64(flags), "text": parts[0]}, nil
	case "mouse":
		if err := need(5); err != nil {
			return nil, err
		}
		return map[string]any{
			"kind": float64(2), "action": num(parts[0]), "button": num(parts[1]),
			"mods": num(parts[2]), "x": num(parts[3]), "y": num(parts[4]),
		}, nil
	case "focus":
		if err := need(1); err != nil {
			return nil, err
		}
		return map[string]any{"kind": float64(3), "gained": num(parts[0])}, nil
	case "theme":
		if err := need(3); err != nil {
			return nil, err
		}
		return map[string]any{
			"dark": num(parts[0]), "fg": strings.ToLower(parts[1]), "bg": strings.ToLower(parts[2]),
		}, nil
	case "clipboard":
		return map[string]any{"kind": float64(2), "text": args}, nil
	case "caps":
		switch args {
		case "surface":
			return map[string]any{"capLen": float64(1), "flags": float64(1)}, nil // kCapsSurface = 1<<0
		}
		return nil, errBadArgs
	case "hello-tail":
		// args = caps,ver,id（ver/id 空串 = 不出现；与 DecodeUplink 的 0/"" 同口径）。
		if err := need(3); err != nil {
			return nil, err
		}
		var ver float64
		if parts[1] != "" {
			ver = num(parts[1])
			if ver < 0 {
				return nil, errBadArgs
			}
		}
		return map[string]any{
			"caps": num(parts[0]), "ver": ver, "id": parts[2],
		}, nil
	}
	return nil, errBadArgs
}

type argsError string

func (e argsError) Error() string { return string(e) }

const errBadArgs = argsError("args 列与 category 形态不符")
