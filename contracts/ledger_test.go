// ledger_test.go — 对账规则①（生产值集 == 台账 active 集，双向）与规则④（版本空间
// 结构化面 == versions.go），含族⑥⑦的透传并集口径与族⑨值源引用完整性
// （contract-ledger tasks 2.2）。
package contracts

import (
	"sort"
	"testing"
)

func testRoot(t *testing.T) string {
	t.Helper()
	root, err := RepoRoot()
	if err != nil {
		t.Fatalf("找不到仓根：%v", err)
	}
	return root
}

// TestLedgerProductionMatches 规则①：每个配置了提取源的族/单元上，
// 生产值集 == 台账 active 集（spec-only 行不计入）。代码多出台账 = 未登记红；
// 台账多于代码 = 台账腐化红。
func TestLedgerProductionMatches(t *testing.T) {
	root := testRoot(t)
	ex, err := ExtractAll(root)
	if err != nil {
		t.Fatalf("提取失败：%v", err)
	}
	led, err := Load(root)
	if err != nil {
		t.Fatalf("台账加载失败：%v", err)
	}

	// 族⑥⑦的生产集 = 自产常量 ∪ 透传族全集（mapNativeFilesErr/ERROR 帧透传不滤值）。
	computed := Extracted{}
	for fam, units := range ex {
		computed[fam] = map[string]map[string]string{}
		for u, vals := range units {
			m := map[string]string{}
			for v, n := range vals {
				m[v] = n
			}
			computed[fam][u] = m
		}
	}
	mergeInto := func(family, unit string, src map[string]string) {
		if computed[family][unit] == nil {
			computed[family][unit] = map[string]string{}
		}
		for v, n := range src {
			if _, ok := computed[family][unit][v]; !ok {
				computed[family][unit][v] = n
			}
		}
	}
	mergeInto("bridge-files", "code", ex["files-proto"]["code"])
	mergeInto("bridge-term", "code", ex["term-error"]["code"])

	checked := 0
	for _, r := range constRules {
		units := map[string]bool{}
		for _, u := range r.Units {
			units[u] = true
		}
		for unit := range units {
			checked++
			got := map[string]bool{}
			for v := range computed[r.Family][unit] {
				got[v] = true
			}
			want := led.Active(r.Family, unit)
			var unregistered, stale []string
			for v := range got {
				if !want[v] {
					unregistered = append(unregistered, v)
				}
			}
			for v := range want {
				if !got[v] {
					stale = append(stale, v)
				}
			}
			if len(unregistered) > 0 || len(stale) > 0 {
				sort.Strings(unregistered)
				sort.Strings(stale)
				t.Errorf("规则① %s/%s 不一致：代码未登记 %v（红：先登台账+spec delta 再进代码）；台账腐化 %v（红：产出者已不在，改状态或删行须走 delta）",
					r.Family, unit, unregistered, stale)
			}
		}
	}
	if checked == 0 {
		t.Fatal("提取清单为空（空集假绿）")
	}
}

// TestLedgerVersionsRule4 规则④：版本空间族对拍 facade/versions.go——由规则①的
// versions 族承担（结构化面 = const 声明；升版规则散文以 note 登记、退出逐字门）。
// 这里只显式断言版本空间族确有对账面（防空转）。
func TestLedgerVersionsRule4(t *testing.T) {
	root := testRoot(t)
	led, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	ex, err := ExtractAll(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(led.Active("versions", "control-proto")) != 1 ||
		led.Active("versions", "control-proto")["1"] != true {
		t.Errorf("版本空间 control-proto 应恰为 1（protoVersion=1）")
	}
	if len(ex["versions"]["surface-payload"]) != 1 {
		t.Errorf("surface-payload 提取面异常：%v", ex["versions"]["surface-payload"])
	}
}

// TestLedgerBridgeTablesReferential 族⑨（App 机读码表）值源引用完整性：五张表的
// 每个值必须落在 ⑥/⑦/①code/⑤ 的已登记值里——App 侧不得发明台账外码。
func TestLedgerBridgeTablesReferential(t *testing.T) {
	root := testRoot(t)
	led, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, fu := range [][2]string{
		{"bridge-files", "code"}, {"bridge-term", "code"},
		{"cp", "code"}, {"speedtest-reason", "reason"},
	} {
		for v := range led.All(fu[0], fu[1]) {
			known[v] = true
		}
	}
	tables := map[string][]string{}
	for _, r := range led.Rows {
		if r.Family == "bridge-tables" {
			tables[r.Unit] = append(tables[r.Unit], r.Value)
		}
	}
	wantTables := []string{"deterministic-files", "deterministic-term", "channel-files", "channel-term", "auth-codes"}
	for _, u := range wantTables {
		vals, ok := tables[u]
		if !ok || len(vals) == 0 {
			t.Errorf("族⑨缺表 %s", u)
			continue
		}
	}
	if len(tables) != len(wantTables) {
		t.Errorf("族⑨出现登记外表：%v", tables)
	}
	for u, vals := range tables {
		for _, v := range vals {
			if !known[v] {
				t.Errorf("族⑨ %s 的值 %q 不属于任何已登记值源族（⑥/⑦/①code/⑤）", u, v)
			}
		}
	}
}

// TestLedgerExemptionNotes 五条豁免 note（r3 N-11 + r4 新-3 修订）与单函数 default
// note 必须逐条在位——note 是规则⑤（tier 侧脚本）的减法/记录数据面，丢了即假红。
func TestLedgerExemptionNotes(t *testing.T) {
	root := testRoot(t)
	led, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	must := []struct{ family, unit, value, substr string }{
		{"bridge-files", "code", "op_failed", "App 走 default"},
		{"bridge-files", "code", "stream_open", "App 走 default"},
		{"bridge-files", "code", "marshal", "App 走 default"},
		{"bridge-term", "code", "remote", "App 走 default"},
		{"bridge-term", "code", "marshal", "App 走 default"},
		// 6.2 补登（App 面对账首跑检出）：③透传里 App 无 case 的 already_exists 与
		// termEndNone 哨兵同样落 default（design 族⑦「③无 case 值走 default（note 豁免）」
		// / tasks 1.1「ENDED code −1/哨兵——note『App 走 default』」）。
		{"bridge-term", "code", "already_exists", "App 走 default"},
		{"term-frame", "ended-code", "math.MinInt32", "App 走 default"},
		{"event-payload", "via", "none", "不入豁免减法"},
		{"event-payload", "via", "tunnel", "本仓零产出者"},
		{"event-payload", "state", "stopping", "App 走 default"},
		{"term-frame", "agent", "unknown", "App 走 default"},
		{"term-frame", "ended-code", "-1", "App 走 default"},
		{"speedtest-reason", "reason", "invalid_arg", "不入豁免减法"},
	}
	for _, m := range must {
		found := false
		for _, r := range led.Rows {
			if r.Family == m.family && r.Unit == m.unit && r.Value == m.value {
				found = true
				if !containsStr(r.Note, m.substr) {
					t.Errorf("%s/%s=%s note 缺 %q（现 note：%q）", m.family, m.unit, m.value, m.substr, r.Note)
				}
				if m.value == "tunnel" && r.Status != "legacy-unreachable" {
					t.Errorf("%s/%s=%s 应为 legacy-unreachable（现 %s）", m.family, m.unit, m.value, r.Status)
				}
			}
		}
		if !found {
			t.Errorf("缺行 %s/%s=%s", m.family, m.unit, m.value)
		}
	}
}

// TestLedgerLegacyStatusLegacy 三状态纪律：实测零产出者一律 legacy-unreachable
// （r2 N-2）；compat-passthrough 初始集按双出口在役采证、零实例即空集——这里断言
// 登记面没有歧义状态值。
func TestLedgerLegacyStatusLegacy(t *testing.T) {
	root := testRoot(t)
	led, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	valid := map[string]bool{"active": true, "compat-passthrough": true, "legacy-unreachable": true}
	legacyWant := map[string]bool{
		"dial_failed": true, "files_not_enabled": true, "files_other_service": true,
		"invalid_addr": true, "stalled": true,
		"async_failed": true, "invalid_name": true, "timeout": true, "term_not_enabled": true,
	}
	var compat, legacy int
	for _, r := range led.Rows {
		if !valid[r.Status] {
			t.Errorf("%s/%s=%s 非法 status %q", r.Family, r.Unit, r.Value, r.Status)
		}
		if r.Status == "compat-passthrough" {
			compat++
		}
		if r.Status == "legacy-unreachable" {
			legacy++
			if r.Family == "bridge-files" && !legacyWant[r.Value] {
				t.Errorf("族⑥ %s 意外归 legacy（须按双出口在役采证定状态）", r.Value)
			}
			if r.Family == "bridge-term" && !legacyWant[r.Value] {
				t.Errorf("族⑦ %s 意外归 legacy", r.Value)
			}
		}
	}
	if legacy != 10 { // 族⑥ 5 + 族⑦ 4 + via=tunnel 1
		t.Errorf("legacy 行数 = %d，期望 10（compat-passthrough 初始集如实为空集——双出口在役 v0.10.0 与本仓同 lineage，r2 实测归位；%d 行 compat）", legacy, compat)
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
