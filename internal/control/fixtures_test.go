package control

// fixtures_test.go — §3.7 golden fixtures 对拍（spec「词表冻结与语言无关
// fixtures」三层冻结等级的机检）：
//
//	①二进制帧双向：解码向 = fixtures hex 帧解出的 body 与声明结构**逐字节锚定**
//	（hex → ReadFrame → op/body；body 再编码回帧 = 与原 hex 完全一致）；
//	②JSON 结构等价：解码解出的结构与 expect.json 深比较（经 map 归一，键序不敏感
//	——编码方向只要求结构等价）；编码自洽 = expect.json → Go 结构 → marshal →
//	再解码 → 等价（decode → 结构 → encode → decode 双向自洽）；
//	③未知字段忽略：每个控制类向量注入未知字段后仍解出同一结构（前向兼容）。
//
// 独立语言自证见同目录 decode_check.py（对拍脚本本身不入 Go 测试框架）。

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// fixtureEntry frames.jsonl 的一行。
type fixtureEntry struct {
	Name     string          `json:"name"`
	Category string          `json:"category"`
	Op       string          `json:"op"`
	Hex      string          `json:"hex"`
	Expect   json.RawMessage `json:"expect"`
	// Dir 所属版本目录（v1/v2…；加载时填充，不来自 JSON）——目录遍历化后错误信息
	// 要带版本上下文（contract-ledger tasks 5.1）。
	Dir string `json:"-"`
}

// fixtureVersionDirs 列 root 下的版本目录（v1、v2…，数值序）。版本治理目录遍历
// （contract-ledger tasks 5.1）：未来新增 v2/ 目录落盘即自动进对拍回归；空目录
// 幂等跳过（loadFixtures 对无 frames.jsonl 的目录不报错）。零版本目录 = 异常
// （v1 是冻结基线，不可能被删——fail-closed）。
func fixtureVersionDirs(t *testing.T, root string) []string {
	t.Helper()
	ents, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	type vn struct {
		name string
		n    int
	}
	var dirs []vn
	for _, e := range ents {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "v") {
			continue
		}
		n, err := strconv.Atoi(e.Name()[1:])
		if err != nil || n < 1 {
			continue
		}
		dirs = append(dirs, vn{e.Name(), n})
	}
	if len(dirs) == 0 {
		t.Fatalf("%s 下没有版本目录（v1 是冻结基线，缺席即异常）", root)
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].n < dirs[j].n })
	out := make([]string, len(dirs))
	for i, d := range dirs {
		out[i] = d.name
	}
	return out
}

// loadFixturesDir 读单个版本目录的 frames.jsonl（dir 缺文件 = 空目录，返回 nil——幂等）。
func loadFixturesDir(t *testing.T, root, dir string) []fixtureEntry {
	t.Helper()
	p := filepath.Join(root, dir, "frames.jsonl")
	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	defer f.Close()
	var out []fixtureEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var e fixtureEntry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("%s：行损坏：%v（%s）", dir, err, line)
		}
		e.Dir = dir
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// loadFixtures 全部版本目录的向量并集（目录遍历化：今天只有 v1，未来 v2… 自动进回归）。
func loadFixtures(t *testing.T) []fixtureEntry {
	t.Helper()
	root := filepath.Join("testdata", "fixtures")
	var out []fixtureEntry
	for _, dir := range fixtureVersionDirs(t, root) {
		out = append(out, loadFixturesDir(t, root, dir)...)
	}
	if len(out) == 0 {
		t.Fatal("fixtures 为空")
	}
	return out
}

// bodyStructFor 按 op 给出该帧 body 的 Go 结构（编码自洽用）。
func bodyStructFor(op byte) any {
	switch op {
	case OpHello:
		return &HelloBody{}
	case OpWelcome:
		return &WelcomeBody{}
	case OpReload:
		return &ReloadBody{}
	case OpGoodbye:
		return &GoodbyeBody{}
	case OpReq:
		return &RequestBody{}
	case OpRsp:
		return &ResponseBody{}
	case OpEvt:
		return &EventBody{}
	case OpStreamEnd:
		return &StreamEndBody{}
	}
	return nil // stream.data：二进制 body（无 JSON 结构）
}

func TestFixturesDecodeExactBytes(t *testing.T) {
	// ①解码向：hex 帧 → op/body；**再编码 = 原 hex 逐字节一致**（帧布局锚定）。
	for _, fx := range loadFixtures(t) {
		replayFixtureDecode(t, fx)
	}
}

// replayFixtureDecode 单向量对当前生产解码器的解码断言（①逐字节 + ②结构等价）——
// fixtures_test 与 version_governance_test（按版本目录回归）共用同一判据。
func replayFixtureDecode(t *testing.T, fx fixtureEntry) {
	t.Helper()
	name := fx.Name
	if fx.Dir != "" {
		name = fx.Dir + "/" + fx.Name
	}
	raw := hexBytes(t, fx.Hex)
	r := bufio.NewReader(bytes.NewReader(raw))
	op, body, err := ReadFrame(r, MaxControlBody)
	if err != nil {
		t.Fatalf("%s：解码失败：%v", name, err)
	}
	if fmt.Sprintf("0x%02x", op) != fx.Op {
		t.Fatalf("%s：op=0x%02x 与声明 %s 不符", name, op, fx.Op)
	}
	if got := EncodeFrame(op, body); !bytes.Equal(got, raw) {
		t.Fatalf("%s：再编码与原字节不一致：%x ≠ %x", name, got, raw)
	}
	if op == OpStreamData {
		checkStreamFixture(t, name, body, fx.Expect)
	} else {
		checkJSONFixture(t, name, op, body, fx.Expect)
	}
}

func checkStreamFixture(t *testing.T, name string, body []byte, expect json.RawMessage) {
	t.Helper()
	id, payload, err := DecodeStreamBody(body)
	if err != nil {
		t.Fatalf("%s：%v", name, err)
	}
	var exp struct {
		StreamID uint32 `json:"streamId"`
		BytesHex string `json:"bytesHex"`
	}
	if err := json.Unmarshal(expect, &exp); err != nil {
		t.Fatal(err)
	}
	if id != exp.StreamID || fmt.Sprintf("%x", payload) != exp.BytesHex {
		t.Fatalf("%s：流 body 不一致：id=%d payload=%x（期望 id=%d %s）", name, id, payload, exp.StreamID, exp.BytesHex)
	}
}

func checkJSONFixture(t *testing.T, name string, op byte, body, expect json.RawMessage) {
	t.Helper()
	// 声明的期望 JSON（expect.json）。
	var expWrapped struct {
		JSON json.RawMessage `json:"json"`
	}
	if err := json.Unmarshal(expect, &expWrapped); err != nil || len(expWrapped.JSON) == 0 {
		// 已是裸 JSON（流 end 等）。
		expWrapped.JSON = expect
	}
	// ② 解码解出的结构经 map 归一后与声明深比较（键序不敏感）。
	var wantMap, gotMap map[string]any
	if err := json.Unmarshal(expWrapped.JSON, &wantMap); err != nil {
		t.Fatalf("%s：expect JSON 非法：%v", name, err)
	}
	if err := json.Unmarshal(body, &gotMap); err != nil {
		t.Fatalf("%s：帧 body 非法 JSON：%v", name, err)
	}
	if !reflect.DeepEqual(wantMap, gotMap) {
		t.Fatalf("%s：JSON 结构不等价：\n  解码=%v\n  声明=%v", name, gotMap, wantMap)
	}
	// ②' 结构化解码（按 op 给类型）+ 编码自洽：结构 → marshal → 再解码 → 等价。
	dst := bodyStructFor(op)
	if dst == nil {
		t.Fatalf("%s：无对应结构", name)
	}
	if err := json.Unmarshal(body, dst); err != nil {
		t.Fatalf("%s：结构化解码失败：%v", name, err)
	}
	re, err := json.Marshal(dst)
	if err != nil {
		t.Fatal(err)
	}
	_, againBody, err := ReadFrame(bufio.NewReader(bytes.NewReader(EncodeFrame(op, re))), MaxControlBody)
	if err != nil {
		t.Fatalf("%s：%v", name, err)
	}
	var againMap map[string]any
	_ = json.Unmarshal(againBody, &againMap)
	if !reflect.DeepEqual(gotMap, againMap) {
		t.Fatalf("%s：编码自洽失败：\n  原=%v\n  往返=%v", name, gotMap, againMap)
	}
}

func TestFixturesUnknownFieldsIgnored(t *testing.T) {
	// ③ 解码忽略未知字段（「字段只增不改」与 fixtures 共存的机制：加字段不破旧
	// fixtures 的解码方向）。对每个 JSON 类向量注入未来字段后结构不变。
	for _, fx := range loadFixtures(t) {
		raw := hexBytes(t, fx.Hex)
		op, body, err := ReadFrame(bufio.NewReader(bytes.NewReader(raw)), MaxControlBody)
		if err != nil || op == OpStreamData {
			continue // 流帧无 JSON（二进制透传本身无字段概念）
		}
		var m map[string]any
		if err := json.Unmarshal(body, &m); err != nil {
			t.Fatalf("%s：%v", fx.Name, err)
		}
		m["futureFieldFromV2"] = map[string]any{"nested": true, "num": 3}
		injected, _ := json.Marshal(m)
		dst := bodyStructFor(op)
		if err := json.Unmarshal(injected, dst); err != nil {
			t.Fatalf("%s：注入未知字段后解码失败：%v", fx.Name, err)
		}
		clean := bodyStructFor(op)
		_ = json.Unmarshal(body, clean)
		// 结构含 RawMessage（如 rsp.Result）时按语义归一比较（map 键序不敏感）。
		if !structurallyEqual(dst, clean) {
			t.Fatalf("%s：未知字段泄漏进结构（语义归一后仍不等）", fx.Name)
		}
	}
}

func TestFixturesVocabularyCoversSpec(t *testing.T) {
	// fixtures 覆盖面自检：握手 4 帧、快照 2、错误 4+、事件 5+、流 3+——spec
	//「JSON 用例：握手/快照/事件/错误」各一组 + 二进制帧向量的最低覆盖。
	cats := map[string]int{}
	ops := map[byte]bool{}
	for _, fx := range loadFixtures(t) {
		cats[fx.Category]++
		op := hexBytes(t, fx.Hex)[0]
		ops[op] = true
	}
	for _, c := range []string{"handshake", "snapshot", "event", "error", "stream"} {
		if cats[c] == 0 {
			t.Fatalf("fixtures 缺少 %s 类用例", c)
		}
	}
	for _, op := range []byte{OpHello, OpWelcome, OpReload, OpGoodbye, OpReq, OpRsp, OpEvt, OpStreamData, OpStreamEnd} {
		if !ops[op] {
			t.Fatalf("fixtures 缺少 op=0x%02x 的帧向量", op)
		}
	}
}

func TestDecodeCheckPyIndependent(t *testing.T) {
	// 独立对拍脚本必须在无 Go 参与下全绿（语言无关自证——CI/本地同一判据）。
	if _, err := os.Stat(filepath.Join("testdata", "fixtures", "v1", "decode_check.py")); err != nil {
		t.Fatal("decode_check.py 应随 fixtures 入库")
	}
	out, err := runPyScript(t)
	if err != nil {
		t.Fatalf("decode_check.py 执行失败：%v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("帧向量对拍通过")) {
		t.Fatalf("decode_check.py 输出异常：%s", out)
	}
}

// structurallyEqual 两个同型结构的语义等价（经 JSON 归一——RawMessage 字节序与
// 数值编码差异不参与比较）。
func structurallyEqual(a, b any) bool {
	ja, err := json.Marshal(a)
	if err != nil {
		return false
	}
	jb, err := json.Marshal(b)
	if err != nil {
		return false
	}
	var ma, mb map[string]any
	if json.Unmarshal(ja, &ma) != nil || json.Unmarshal(jb, &mb) != nil {
		return false
	}
	return reflect.DeepEqual(ma, mb)
}

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	if len(s)%2 != 0 {
		t.Fatalf("hex 长度非偶：%s", s)
	}
	b := make([]byte, len(s)/2)
	for i := 0; i < len(b); i++ {
		if _, err := fmt.Sscanf(s[2*i:2*i+2], "%02x", &b[i]); err != nil {
			t.Fatalf("hex 非法 @%d：%s", i, s)
		}
	}
	return b
}

// runPyScript 独立执行同目录 decode_check.py（python3）。
func runPyScript(t *testing.T) ([]byte, error) {
	t.Helper()
	cmd := exec.Command("python3", filepath.Join("testdata", "fixtures", "v1", "decode_check.py"))
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return append(out.Bytes(), errb.Bytes()...), err
	}
	return out.Bytes(), nil
}
