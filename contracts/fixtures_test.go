// fixtures_test.go — 对账规则②（fixtures 引用值 ⊆ 台账）与规则③（台账摘要 ==
// 实算 sha256，字节冻结门），加 NAPI 导出面形状门（tasks 2.3）。
package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestLedgerFixturesRefsRule2 规则②：控制面 fixtures v1 的 46 向量里，按路径分类的
// 词汇引用值必须 ⊆ 台账对应族/单元。诊断性自由文本（payload.reason/level/msg 等）
// 不在检查面（D7：仅展示的自由文本不冻结）。
func TestLedgerFixturesRefsRule2(t *testing.T) {
	root := testRoot(t)
	led, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	type unitRef struct {
		family, unit string
		union        bool // true = 多单元并集（reason 混空间）
	}
	// 路径 → 台账单元（与向量 schema 一一对应；未列路径 = 非契约词面，不查）。
	paths := map[string]unitRef{
		"/json/op":                      {family: "cp", unit: "op"},
		"/json/kind":                    {family: "cp", unit: "kind"},
		"/json/args/kind":               {family: "cp", unit: "stream-kind"},
		"/json/error":                   {family: "cp", unit: "code"},
		"/json/result/error":            {family: "cp", unit: "code"},
		"/json/domain":                  {family: "cp", unit: "domain"},
		"/json/args/domains[]":          {family: "cp", unit: "domain"},
		"/json/result/domains[]":        {family: "cp", unit: "domain"},
		"/json/payload/via":             {family: "event-payload", unit: "via"},
		"/json/result/hosts[]/link/via": {family: "event-payload", unit: "via"},
		"/json/payload/state":           {family: "event-payload", unit: "state"},
		"/json/result/hosts[]/state":    {family: "event-payload", unit: "state"},
		"/json/result/reach/tier":       {family: "cp", unit: "reach"},
		"/json/reason":                  {family: "cp", unit: "code", union: true},
	}
	reasonUnion := map[string]string{} // reason 混空间：code ∪ stream-end ∪ close-reason
	for _, fu := range [][2]string{{"cp", "code"}, {"cp", "stream-end"}, {"cp", "close-reason"}} {
		for v := range led.All(fu[0], fu[1]) {
			reasonUnion[v] = fmt.Sprintf("%s/%s", fu[0], fu[1])
		}
	}

	data, err := os.ReadFile(filepath.Join(root, "internal/control/testdata/fixtures/v1/frames.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	bad := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var v struct {
			Name   string          `json:"name"`
			Expect json.RawMessage `json:"expect"`
		}
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Fatalf("向量 %s 非法 JSON：%v", v.Name, err)
		}
		var walk func(o any, path string)
		walk = func(o any, path string) {
			switch x := o.(type) {
			case map[string]any:
				keys := make([]string, 0, len(x))
				for k := range x {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					walk(x[k], path+"/"+k)
				}
			case []any:
				for _, e := range x {
					walk(e, path+"[]")
				}
			case string:
				ref, ok := paths[path]
				if !ok {
					return
				}
				if ref.union {
					if fam, hit := reasonUnion[x]; hit {
						_ = fam
						return
					}
					t.Errorf("规则② 向量 %s：%s=%q 不在 reason 混空间（cp code/stream-end/close-reason）", v.Name, path, x)
					bad++
					return
				}
				if !led.All(ref.family, ref.unit)[x] {
					t.Errorf("规则② 向量 %s：%s=%q 未登记（%s/%s）", v.Name, path, x, ref.family, ref.unit)
					bad++
				}
			}
		}
		var expect any
		if len(v.Expect) > 0 {
			if err := json.Unmarshal(v.Expect, &expect); err != nil {
				t.Fatalf("向量 %s expect 非法：%v", v.Name, err)
			}
			walk(expect, "")
		}
	}
	if bad == 0 {
		t.Log("规则② 绿：46 向量全部词面引用 ⊆ 台账")
	}
}

// TestLedgerFixturesDigestsRule3 规则③（字节冻结门）：台账摘要行 == 实算 sha256。
// cp-v1 = 整行原文摘要（帧字节/期望/name 全冻结；重排行序绿）；golden = 文件字节。
func TestLedgerFixturesDigestsRule3(t *testing.T) {
	root := testRoot(t)
	led, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	// 实算侧。
	actual := map[string]map[string]string{
		"cp-v1": {}, "surface-golden-bin": {}, "surface-golden-manifest": {},
	}
	data, err := os.ReadFile(filepath.Join(root, "internal/control/testdata/fixtures/v1/frames.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var v struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(line))
		actual["cp-v1"][v.Name] = hex.EncodeToString(sum[:])
	}
	gd := filepath.Join(root, "surface/test/golden")
	entries, err := os.ReadDir(gd)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(gd, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		if e.Name() == "manifest.tsv" {
			actual["surface-golden-manifest"][e.Name()] = hex.EncodeToString(sum[:])
		} else {
			actual["surface-golden-bin"][e.Name()] = hex.EncodeToString(sum[:])
		}
	}
	// 对账（双向：台账多 = 幽灵摘要；实算多 = 漏登/删了台账行掩删——只增门两侧都挡）。
	byUnit := map[string]map[string]string{}
	for _, fr := range led.Fixtures {
		if byUnit[fr.Unit] == nil {
			byUnit[fr.Unit] = map[string]string{}
		}
		byUnit[fr.Unit][fr.Name] = fr.SHA256
	}
	for unit, want := range actual {
		got := byUnit[unit]
		if len(got) == 0 {
			t.Errorf("规则③ %s：台账零登记（空集假绿——fixtures 在而台账无行）", unit)
			continue
		}
		for name, sum := range want {
			if got[name] != sum {
				t.Errorf("规则③ %s/%s：摘要不符（台账 %s ≠ 实算 %s）——改既有向量字节必须红", unit, name, got[name], sum)
			}
		}
		for name := range got {
			if _, ok := want[name]; !ok {
				t.Errorf("规则③ %s/%s：台账幽灵摘要（实算侧无此向量）", unit, name)
			}
		}
	}
	for unit := range byUnit {
		if _, ok := actual[unit]; !ok {
			t.Errorf("规则③：台账登记了未知摘要单元 %s", unit)
		}
	}
}

// TestLedgerNAPIExportFace NAPI 导出面形状门（红线①）：cmd/clientcore 的 //export
// 集合 == 台账 napi-face 行——加/删导出不同批过台账即红（四处同步由 tier
// check-napi-sync.sh 承载，这里钉 homeway 侧真源）。
func TestLedgerNAPIExportFace(t *testing.T) {
	root := testRoot(t)
	led, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	files, _, err := Files(root, "clientcore/cmd/clientcore")
	if err != nil {
		t.Fatal(err)
	}
	exports := map[string]bool{}
	for _, f := range files {
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				if rest, ok := strings.CutPrefix(c.Text, "//export "); ok {
					exports[strings.TrimSpace(rest)] = true
				}
			}
		}
	}
	if len(exports) == 0 {
		t.Fatal("//export 空集（解析异常，拒绝假绿）")
	}
	want := led.Active("napi-face", "export")
	for e := range exports {
		if !want[e] {
			t.Errorf("//export %s 未登记 napi-face（导出面变更须同批过台账+四处同步）", e)
		}
	}
	for e := range want {
		if !exports[e] {
			t.Errorf("台账 napi-face 登记 %s 但源码无此导出（台账腐化）", e)
		}
	}
	if len(want) != 20 {
		t.Errorf("导出面 = %d 个，期望 20（红线①：本期零增删）", len(want))
	}
}
