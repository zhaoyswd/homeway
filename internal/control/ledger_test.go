package control

// ledger_test.go — 版本台账对拍（控制面空间，任务 1.2）：控制面 protoVersion 真源
// 留在传输层（wire 握手体），对拍断言落 control 侧测试（control→facade 无环）——
// 断言 ProtoVersion == facade 台账值。真源改了台账没跟 = 红。

import (
	"testing"

	"github.com/zhaoyswd/homeway/clientcore/facade"
)

func TestProtoVersionMatchesFacadeLedger(t *testing.T) {
	if ProtoVersion != facade.ControlProtoVersion {
		t.Fatalf("控制面协议版本漂移：真源 ProtoVersion=%d，facade 台账=%d（握手不兼容变更才升版，两处必须同步）", ProtoVersion, facade.ControlProtoVersion)
	}
}
