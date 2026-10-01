// ledger.go — 台账数据文件的加载面（contract-ledger 4b，design D1）。
//
// 台账 = contracts/ledger.jsonl，一条一值（手写真源：spec 表格的机器影子）。行 schema：
//
//	词汇行：{"family","unit","value","note","faces","status","spec"}
//	摘要行：{"family":"fixtures","unit","name","sha256","note","faces","status","spec"}
//
// status = 产出状态（D1 三状态判定表）：active / compat-passthrough / legacy-unreachable。
package contracts

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Row 台账词汇行（一条一个值）。
type Row struct {
	Family string   `json:"family"`
	Unit   string   `json:"unit"`
	Value  string   `json:"value"`
	Note   string   `json:"note,omitempty"`
	Faces  []string `json:"faces"`
	Status string   `json:"status"`
	Spec   string   `json:"spec"`
	// Exempt：**结构化豁免**（FIX-102：取代 note 里自由文本「App 走 default」标记——
	// 后者是「谁都能写的逃生口」）。值域冻结：目前仅 "app-default"（App 侧按值分派
	// 无 case、走 default 展示服务端 msg）。非空时 ExemptSpec/ExemptSince **必填**
	//（豁免依据的能力域/change 名 + 生效日期 YYYY-MM-DD；TestLedgerExemptSchema 校验）。
	Exempt      string `json:"exempt,omitempty"`
	ExemptSpec  string `json:"exemptSpec,omitempty"`
	ExemptSince string `json:"exemptSince,omitempty"`
}

// FixturesRow 台账摘要行（fixtures 逐向量内容寻址——字节冻结门的数据面）。
type FixturesRow struct {
	Family string   `json:"family"` // 恒为 "fixtures"
	Unit   string   `json:"unit"`   // cp-v1 / surface-golden-bin / surface-golden-manifest …
	Name   string   `json:"name"`
	SHA256 string   `json:"sha256"`
	Note   string   `json:"note,omitempty"`
	Faces  []string `json:"faces"`
	Status string   `json:"status"`
	Spec   string   `json:"spec"`
}

// Ledger 加载后的台账。
type Ledger struct {
	Rows     []Row
	Fixtures []FixturesRow
}

// Load 自仓根读 ledger.jsonl（逐行 JSON；空行跳过；畸形行硬错——台账是门的数据面，
// 半份可解析的台账比没有更危险）。
func Load(root string) (*Ledger, error) {
	path := filepath.Join(root, "contracts", "ledger.jsonl")
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("contracts: 台账缺失（%s）：%w", path, err)
	}
	defer f.Close()
	l := &Ledger{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	ln := 0
	for sc.Scan() {
		ln++
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var probe struct {
			Family string `json:"family"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			return nil, fmt.Errorf("contracts: ledger.jsonl:%d 非法 JSON：%w", ln, err)
		}
		if probe.Family == "fixtures" {
			var fr FixturesRow
			if err := json.Unmarshal(line, &fr); err != nil {
				return nil, fmt.Errorf("contracts: ledger.jsonl:%d 摘要行解析失败：%w", ln, err)
			}
			l.Fixtures = append(l.Fixtures, fr)
			continue
		}
		var r Row
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("contracts: ledger.jsonl:%d 词汇行解析失败：%w", ln, err)
		}
		if r.Family == "" || r.Unit == "" || r.Value == "" || r.Status == "" {
			return nil, fmt.Errorf("contracts: ledger.jsonl:%d 缺必要字段（family/unit/value/status）", ln)
		}
		l.Rows = append(l.Rows, r)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(l.Rows) == 0 && len(l.Fixtures) == 0 {
		return nil, fmt.Errorf("contracts: 台账 0 行（空集假绿——先例「真源 0 导出拒绝假绿」同款）")
	}
	return l, nil
}

// Active 某族/单元的 active 值集（规则① 比较基集；spec-only 行不计入——载荷字段名
// 是 struct tag 非 const）。
func (l *Ledger) Active(family, unit string) map[string]bool {
	out := map[string]bool{}
	for _, r := range l.Rows {
		if r.Family == family && r.Unit == unit && r.Status == "active" && !IsSpecOnly(r.Note) {
			out[r.Value] = true
		}
	}
	return out
}

// All 某族/单元的全部登记值（不分状态——规则⑤ 的比较基集，batch 2 tier 侧脚本同款口径）。
func (l *Ledger) All(family, unit string) map[string]bool {
	out := map[string]bool{}
	for _, r := range l.Rows {
		if r.Family == family && r.Unit == unit && !IsSpecOnly(r.Note) {
			out[r.Value] = true
		}
	}
	return out
}

// IsSpecOnly note 是否标 spec-only（r3 N-12：struct tag 词面只登记、不进生产值集比对）。
func IsSpecOnly(note string) bool {
	return len(note) >= len("spec-only") && note[:len("spec-only")] == "spec-only"
}
