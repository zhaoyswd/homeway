package control

// role_ops_test.go — role-management 4.2：serve/relay 十 op 的 dispatch 层单测
//（正常/幂等载荷/旧 daemon unknown_op 锁步形态——错误码零新增的用例锁死）。
// 宿主 = server_test.go 的 fakeBackend + roleOpsStub（真实绑定 = internal/daemon
// 的 roleOps，其进程级判据在 daemon 包 servegroup_cli_test）。

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/zhaoyswd/homeway/clientcore/facade"
)

func TestRoleOpsServeRelayDispatch(t *testing.T) {
	ts := startTestServer(t, facade.BusConfig{})
	c, _ := dialTest(t, ts)
	ctx := context.Background()

	// 正常 + 幂等：start → started / already（幂等语义在成功载荷，不借道错误码）。
	raw, err := c.Request(ctx, facade.OpServeStart, nil)
	if err != nil {
		t.Fatal(err)
	}
	var res RoleActionResult
	if err := json.Unmarshal(raw, &res); err != nil || res.Action != "started" {
		t.Fatalf("serve.start 回执：%s（%v）", raw, err)
	}
	// stop → stopped（stub 恒 stopped/started——幂等面由 daemon 侧用例锁；这里锁
	// dispatch 的成功载荷形状）。
	raw, err = c.Request(ctx, facade.OpServeStop, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &res); err != nil || res.Action != "stopped" {
		t.Fatalf("serve.stop 回执：%s（%v）", raw, err)
	}

	// status：载荷结构解回（掩码纪律字段在——完整 token 只经 token op）。
	raw, err = c.Request(ctx, facade.OpServeStatus, nil)
	if err != nil {
		t.Fatal(err)
	}
	var sv ServeStatusResult
	if err := json.Unmarshal(raw, &sv); err != nil || sv.Peers == nil {
		t.Fatalf("serve.status 回执：%s（%v）", raw, err)
	}
	raw, err = c.Request(ctx, facade.OpRelayStatus, nil)
	if err != nil {
		t.Fatal(err)
	}
	var rv RelayStatusResult
	if err := json.Unmarshal(raw, &rv); err != nil || rv.Backends == nil {
		t.Fatalf("relay.status 回执：%s（%v）", raw, err)
	}

	// token：完整凭证经 socket（属主边界）——载荷含 token 字段。
	raw, err = c.Request(ctx, facade.OpServeToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	var stok ServeTokenResult
	// exec-r2 N1：runtime 来源的回执必须带端点（真实绑定在 roleops.go runtime 分支
	// 回填快照端点——CLI 侧 warnNoEndpoints 以 Eps 为据；回执缺 Eps = 稳态假告警）。
	if err := json.Unmarshal(raw, &stok); err != nil || stok.Token == "" || len(stok.Eps) == 0 {
		t.Fatalf("serve.token 回执（token+endpoints 均须在）：%s（%v）", raw, err)
	}
	raw, err = c.Request(ctx, facade.OpRelayToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	var rtok RelayTokenResult
	if err := json.Unmarshal(raw, &rtok); err != nil || rtok.Token == "" {
		t.Fatalf("relay.token 回执：%s（%v）", raw, err)
	}

	// relay 三生命周期同形状。
	for _, op := range []string{facade.OpRelayStart, facade.OpRelayStop} {
		if _, err := c.Request(ctx, op, nil); err != nil {
			t.Fatalf("%s 失败：%v", op, err)
		}
	}

	// 带未知字段的载荷仍可解（JSON 面纪律：忽略未知字段——词表只增的前向兼容）。
	var sr struct{}
	if _, err := c.Request(ctx, facade.OpServeStatus, sr); err != nil {
		t.Fatalf("空载荷对象应可解：%v", err)
	}
}

// TestRoleOpsRestartStoppedIsBadRequest restart 无重建对象 = bad_request（错误码
// 零新增；CLI 预检兜住「先 serve start」提示——wire 侧防御映射）。
func TestRoleOpsRestartStoppedIsBadRequest(t *testing.T) {
	ts := startTestServer(t, facade.BusConfig{})
	c, _ := dialTest(t, ts)
	if _, err := c.Request(context.Background(), facade.OpServeRestart, nil); err == nil || errCodeOf(err) != facade.CodeBadRequest {
		t.Fatalf("restart 无对象应 bad_request：%v", err)
	}
	if _, err := c.Request(context.Background(), facade.OpRelayRestart, nil); err == nil || errCodeOf(err) != facade.CodeBadRequest {
		t.Fatalf("relay.restart 无对象应 bad_request：%v", err)
	}
}

// TestRoleOpsNotGatedByNotReady serve/relay op 不受 not_ready 挡（进程层角色管理，
// 与 client 注册表就绪无关——同 daemon.status 口径）。
func TestRoleOpsNotGatedByNotReady(t *testing.T) {
	ts := startTestServer(t, facade.BusConfig{})
	ts.backend.notReady = true
	c, _ := dialTest(t, ts)
	if _, err := c.Request(context.Background(), facade.OpServeStatus, nil); err != nil {
		t.Fatalf("serve.status 不应被 not_ready 挡：%v", err)
	}
}
