//go:build !windows

package facade_test

// versions_test.go — 版本空间台账对拍（任务 1.2）：台账值（facade/versions.go）
// 与各空间真源常量（经 pkg/term 只读访问器暴露）机器对拍——真源改了台账没跟 =
// 红（变异自证：临时改 surfaceVer → 本测试红）。外部测试包（package facade_test，
// r1 中-2）：facade 包内测试 import internal/control 会与其 import facade 成环，
// 外部测试包合法；import 面 = pkg/*（不 import 根 internal/——CD delta 纯洁性口径）。
// 控制面 protoVersion 真源留 internal/control（wire 握手体），对拍断言落 control
// 侧测试（control→facade 无环）。

import (
	"testing"

	"github.com/zhaoyswd/homeway/clientcore/facade"
	"github.com/zhaoyswd/homeway/pkg/term"
)

func TestVersionLedgerMatchesTermSources(t *testing.T) {
	if got := term.SurfaceVersion(); got != facade.SurfacePayloadVersion {
		t.Errorf("surface 载荷版本漂移：真源 surfaceVer=%d，台账=%d（布局变更必须同升版本——两空间互不联动）", got, facade.SurfacePayloadVersion)
	}
	if got := term.TermProtoVersion(); got != facade.TermProtoVersion {
		t.Errorf("term 帧协议版本漂移：真源 termProtoVer=%d，台账=%d", got, facade.TermProtoVersion)
	}
	hf := term.HelloFlags()
	if hf.Create != facade.HelloFlagCreate || hf.OnlyIfAbsent != facade.HelloFlagOnlyIfAbsent || hf.Takeover != facade.HelloFlagTakeover {
		t.Errorf("HELLO flags 位漂移：真源 %+v，台账 create=%d onlyIfAbsent=%d takeover=%d", hf, facade.HelloFlagCreate, facade.HelloFlagOnlyIfAbsent, facade.HelloFlagTakeover)
	}
	caps := term.FrameCaps()
	if caps.Surface != facade.CapsSurface || caps.RawTerminal != facade.CapsRawTerminal {
		t.Errorf("capability caps 位漂移：真源 %+v，台账 surface=%d rawTerminal=%d", caps, facade.CapsSurface, facade.CapsRawTerminal)
	}
	feats := term.GreetingFeatures()
	if feats.List != facade.FeatList || feats.Replay != facade.FeatReplay || feats.Modes != facade.FeatModes ||
		feats.Agent != facade.FeatAgent || feats.Title != facade.FeatTitle || feats.Surface != facade.FeatSurface {
		t.Errorf("GREETING features 位漂移：真源 %+v，台账 list=%d replay=%d modes=%d agent=%d title=%d surface=%d",
			feats, facade.FeatList, facade.FeatReplay, facade.FeatModes, facade.FeatAgent, facade.FeatTitle, facade.FeatSurface)
	}
	st := term.StateV2Values()
	if st.Unknown != facade.StateV2Unknown || st.Working != facade.StateV2Working || st.Blocked != facade.StateV2Blocked || st.Idle != facade.StateV2Idle {
		t.Errorf("stateV2 值域漂移：真源 %+v，台账 unknown=%d working=%d blocked=%d idle=%d", st, facade.StateV2Unknown, facade.StateV2Working, facade.StateV2Blocked, facade.StateV2Idle)
	}
}

// TestVersionSpacesIndependent 空间独立（不联动）：surface 布局升版（v4→v5 假想）
// 不得折算到 term 帧协议版本/控制面版本——台账三值各自登记、互不推导。本用例
// 断言台账形态（三个空间值可同时不同），是「帧体版本与 cell 编码版本是两个独立
// 空间」教训的成文化锚点。
func TestVersionSpacesIndependent(t *testing.T) {
	if facade.SurfacePayloadVersion == 0 || facade.TermProtoVersion == 0 || facade.ControlProtoVersion == 0 {
		t.Fatal("版本空间值必须显式登记（非零）")
	}
	// 各空间独立登记：不存在「A 空间升版自动改 B」的联动面——台账是常量表，
	// 每个值单独可改、单独对拍（见上一用例逐空间断言）。
}
