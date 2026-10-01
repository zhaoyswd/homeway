// ledgergen — 台账值行生成器（FIX-101）：active 值行由 extract 生成，人工只留
// annotations（note/spec/faces）。规则① 的双向红（未登记/腐化）从此有 -write 出口，
// 「值行手写双份」退役。
//
// 用法（在 homeway 仓根）：
//
//	go run ./contracts/cmd/ledgergen -check   # 只报告 diff（退出码 1 = 有 diff）
//	go run ./contracts/cmd/ledgergen -write   # 对齐台账（新增未登记行 / 删除腐化行）
//
// 生成范围（与规则① 同源——ComputedSets）：constRules/payloadRules/ctorRules 覆盖的
// (family, unit) 上的 active 值行。明确不生成：
//   - fixtures 摘要行（sha 内容寻址，由 fixtures 工具产）；
//   - compat-passthrough / legacy-unreachable 状态行（人工判定，走 delta）；
//   - spec-only 行（note 前缀，登记而不计生产值——既有的不动、也不生成新的）；
//   - spec/note/faces 字段（annotations：新行 spec 取同 (family,unit) 既有行的值，
//     无既有行则留空待人工补）。
//
// 行级重写：未动的行**字节级原样**保留（fixtures 行的 note 引用 frames.jsonl 行号，
// 与 ledger 行序无关，插入不影响）。
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/zhaoyswd/homeway/contracts"
)

func main() {
	check := flag.Bool("check", false, "只报告 diff（不写文件）")
	write := flag.Bool("write", false, "对齐台账（新增未登记行 / 删除腐化行）")
	flag.Parse()
	if *check == *write {
		fmt.Fprintln(os.Stderr, "用法：ledgergen -check | -write（恰好其一）")
		os.Exit(2)
	}

	root, err := contracts.RepoRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	computed, err := contracts.ComputedSets(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: 提取失败：", err)
		os.Exit(2)
	}
	led, err := contracts.Load(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: 台账加载失败：", err)
		os.Exit(2)
	}
	units := contracts.ExtractUnits()
	if len(units) == 0 {
		fmt.Fprintln(os.Stderr, "error: 提取清单为空（空集假绿）——拒绝")
		os.Exit(2)
	}

	path := filepath.Join(root, "contracts", "ledger.jsonl")
	rawLines, err := readLines(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	// ---- diff 计算 ----
	type key struct{ family, unit string }
	// 生成集（按单元）
	gen := map[key]map[string]bool{}
	for _, u := range units {
		k := key{u.Family, u.Unit}
		if gen[k] == nil {
			gen[k] = map[string]bool{}
		}
		for v := range computed[u.Family][u.Unit] {
			gen[k][v] = true
		}
	}
	// 台账 active 集（排除 spec-only——与 Ledger.Active 同口径）
	ledActive := map[key]map[string]bool{}
	for _, r := range led.Rows {
		if r.Status != "active" || contracts.IsSpecOnly(r.Note) {
			continue
		}
		k := key{r.Family, r.Unit}
		if ledActive[k] == nil {
			ledActive[k] = map[string]bool{}
		}
		ledActive[k][r.Value] = true
	}

	var adds []contracts.Row
	var dels []string // 删除行的人类可读标识
	delValues := map[key]map[string]bool{}
	for _, u := range units {
		k := key{u.Family, u.Unit}
		for v := range gen[k] {
			if !ledActive[k][v] {
				adds = append(adds, contracts.Row{Family: u.Family, Unit: u.Unit, Value: v, Faces: []string{}, Status: "active"})
			}
		}
		for v := range ledActive[k] {
			if !gen[k][v] {
				dels = append(dels, fmt.Sprintf("%s/%s/%s", u.Family, u.Unit, v))
				if delValues[k] == nil {
					delValues[k] = map[string]bool{}
				}
				delValues[k][v] = true
			}
		}
	}
	sort.Slice(adds, func(i, j int) bool {
		if adds[i].Family != adds[j].Family {
			return adds[i].Family < adds[j].Family
		}
		if adds[i].Unit != adds[j].Unit {
			return adds[i].Unit < adds[j].Unit
		}
		return adds[i].Value < adds[j].Value
	})
	sort.Strings(dels)

	if len(adds) == 0 && len(dels) == 0 {
		fmt.Println("ok: 台账 active 值行与生产集一致（零 diff）")
		return
	}
	fmt.Printf("diff：未登记 %d 条 / 腐化 %d 条\n", len(adds), len(dels))
	for _, a := range adds {
		fmt.Printf("  + %s/%s/%s\n", a.Family, a.Unit, a.Value)
	}
	for _, d := range dels {
		fmt.Printf("  - %s\n", d)
	}
	if *check {
		os.Exit(1)
	}

	// ---- -write：行级重写 ----
	// 既有行的 spec（annotations）：同 (family,unit) 取首个非空
	specOf := map[key]string{}
	for _, r := range led.Rows {
		k := key{r.Family, r.Unit}
		if specOf[k] == "" && r.Spec != "" {
			specOf[k] = r.Spec
		}
	}
	// 待插入：按 (family,unit) 分组；插入点 = 该 (family,unit) 词汇行的最后一行之后
	insertAfter := map[key]int{} // ledger 行下标（0-based）
	for i, ln := range rawLines {
		var probe struct {
			Family string `json:"family"`
			Unit   string `json:"unit"`
		}
		if json.Unmarshal([]byte(ln), &probe) != nil || probe.Family == "fixtures" {
			continue
		}
		insertAfter[key{probe.Family, probe.Unit}] = i
	}
	// 删除集（原始行下标）
	delLine := map[int]bool{}
	for i, ln := range rawLines {
		var r contracts.Row
		if json.Unmarshal([]byte(ln), &r) != nil || r.Family == "fixtures" {
			continue
		}
		if r.Status == "active" && delValues[key{r.Family, r.Unit}][r.Value] {
			delLine[i] = true
		}
	}
	// 组装：原序保留（跳过删除行），在插入点后追加新行
	addBy := map[key][]contracts.Row{}
	for _, a := range adds {
		k := key{a.Family, a.Unit}
		if a.Spec == "" {
			a.Spec = specOf[k]
		}
		addBy[k] = append(addBy[k], a)
	}
	var out []string
	emitted := map[key]bool{}
	for i, ln := range rawLines {
		if delLine[i] {
			continue
		}
		out = append(out, ln)
		var probe struct {
			Family string `json:"family"`
			Unit   string `json:"unit"`
		}
		if json.Unmarshal([]byte(ln), &probe) != nil || probe.Family == "fixtures" {
			continue
		}
		k := key{probe.Family, probe.Unit}
		if insertAfter[k] == i && !emitted[k] {
			emitted[k] = true
			for _, a := range addBy[k] {
				b, merr := json.Marshal(a)
				if merr != nil {
					fmt.Fprintln(os.Stderr, "error: 序列化新行失败：", merr)
					os.Exit(2)
				}
				out = append(out, string(b))
			}
		}
	}
	// 无既有行可挂的单元：追加到文件末尾（并提示人工补 spec）
	for _, u := range units {
		k := key{u.Family, u.Unit}
		if len(addBy[k]) == 0 || emitted[k] {
			continue
		}
		fmt.Printf("⚠ %s/%s 无既有词汇行可挂——新行追加到文件末尾（spec 留空，请人工补）\n", u.Family, u.Unit)
		for _, a := range addBy[k] {
			b, _ := json.Marshal(a)
			out = append(out, string(b))
		}
	}
	if err := os.WriteFile(path, []byte(strings.Join(out, "\n")+"\n"), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "error: 写台账失败：", err)
		os.Exit(2)
	}
	fmt.Printf("已写回 %s（新增 %d / 删除 %d）\n", path, len(adds), len(dels))
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		out = append(out, sc.Text())
	}
	return out, sc.Err()
}
