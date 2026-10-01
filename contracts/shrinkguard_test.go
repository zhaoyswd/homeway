// shrinkguard_test.go — FIX-112：fixtures 规模基线冻结。
//
// 盲区：有人**同时删** fixtures 向量与对应台账摘要行——现有门（内容寻址比对）两侧
// 一致地少一行 ⇒ 全绿静默缩面。本门把 fixtures 的条目数**基线冻结**：减少即红
// （显式缩面须同步改基线常量——diff 可见）；增长仅提示（新增向量走正常登记流程）。
//
// 形态说明（相对评审处方「numstat 断言（有 git 环境时跑）」的偏离，登记）：基线常量
// 无 git 环境依赖（CI 干净 checkout 同样生效），且对「已提交的删除」也生效——比
// 工作区 numstat 更强。基线值 = 2026-10-02 实测。
package contracts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixturesBaseline fixtures 条目数基线（减少即红）。
var fixturesBaseline = []struct {
	path  string
	lines int
}{
	{"internal/control/testdata/fixtures/v1/frames.jsonl", 43},
	{"surface/test/golden/manifest.tsv", 8},
}

func TestFixturesShrinkGuard(t *testing.T) {
	root := testRoot(t)
	for _, b := range fixturesBaseline {
		p := filepath.Join(root, b.path)
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("%s 读不到（fixtures 被删/挪？）：%v", b.path, err)
		}
		n := 0
		for _, ln := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
			if strings.TrimSpace(ln) != "" {
				n++
			}
		}
		if n < b.lines {
			t.Errorf("%s 条目数 %d < 基线 %d——fixtures 缩面必须显式（改基线常量 + 台账/spec 同批；先例 FIX-23/FIX-92 的删向量流程）", b.path, n, b.lines)
		} else if n > b.lines {
			t.Logf("提示：%s 条目数 %d > 基线 %d——若为有意新增，请同步基线常量", b.path, n, b.lines)
		}
	}
}
