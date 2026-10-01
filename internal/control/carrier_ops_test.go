package control

// carrier_ops_test.go — 承载面 9 op 的 dispatch 层单测（3e §3.1）：逐 op 正常路径、
// 错误码映射（值域外/冲突 = bad_request、无主机 = no_host——零新增错误码的用例
// 锁死）、busy = 成功载荷 reason、not_ready 门、未知字段忽略（词表只增的前向
// 兼容）。宿主 = server_test.go 的 fakeBackend（承载面语义桩）。

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/facade"
)

// regCarrierHost 假登记面加一台主机（返回 hex id）。
func regCarrierHost(t *testing.T, ts *testServer, id, name string) string {
	t.Helper()
	ts.backend.mu.Lock()
	defer ts.backend.mu.Unlock()
	ts.backend.briefs = append(ts.backend.briefs, HostBrief{ID: id, Name: name, AddedAt: 1700000000})
	return id
}

const carrierHostA = "aa0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
const carrierHostB = "bb0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

func TestCarrierForwardOps(t *testing.T) {
	ts := startTestServer(t, facade.BusConfig{})
	c, _ := dialTest(t, ts)
	ctx := context.Background()
	a := regCarrierHost(t, ts, carrierHostA, "ali")
	b := regCarrierHost(t, ts, carrierHostB, "mac")

	// add 正常：listening 态回执。
	raw, err := c.Request(ctx, facade.OpForwardAdd, ForwardAddArgs{Host: a, Listen: 8080, TargetIP: "192.168.3.5", TargetPort: 5000})
	if err != nil {
		t.Fatal(err)
	}
	var add ForwardAddResult
	if err := json.Unmarshal(raw, &add); err != nil {
		t.Fatal(err)
	}
	if add.Rule.State != "listening" || add.Rule.Listen != 8080 || add.Rule.TargetIP != "192.168.3.5" || add.Rule.TargetPort != 5000 {
		t.Fatalf("forward.add 回执：%+v", add.Rule)
	}

	// add 冲突（全局端口唯一）：bad_request。
	if _, err := c.Request(ctx, facade.OpForwardAdd, ForwardAddArgs{Host: b, Listen: 8080}); err == nil || errCodeOf(err) != facade.CodeBadRequest {
		t.Fatalf("端口冲突应 bad_request：%v", err)
	}
	// add 值域外（端口 0）：bad_request。
	if _, err := c.Request(ctx, facade.OpForwardAdd, ForwardAddArgs{Host: a, Listen: 0}); err == nil || errCodeOf(err) != facade.CodeBadRequest {
		t.Fatalf("端口 0 应 bad_request：%v", err)
	}
	// add 无主机：no_host。
	if _, err := c.Request(ctx, facade.OpForwardAdd, ForwardAddArgs{Host: "cc00", Listen: 9090}); err == nil || errCodeOf(err) != facade.CodeNoHost {
		t.Fatalf("不在表主机应 no_host：%v", err)
	}

	// list：全部 + 按 host 过滤。
	raw, err = c.Request(ctx, facade.OpForwardList, ForwardListArgs{})
	if err != nil {
		t.Fatal(err)
	}
	var lst ForwardListResult
	if err := json.Unmarshal(raw, &lst); err != nil {
		t.Fatal(err)
	}
	if len(lst.Forwards) != 1 || lst.Forwards[0].Host != a {
		t.Fatalf("forward.list：%+v", lst.Forwards)
	}
	raw, err = c.Request(ctx, facade.OpForwardList, ForwardListArgs{Host: a})
	if err != nil {
		t.Fatal(err)
	}
	lst = ForwardListResult{}
	if err := json.Unmarshal(raw, &lst); err != nil {
		t.Fatal(err)
	}
	if len(lst.Forwards) != 1 {
		t.Fatalf("按 host 过滤应 1 条：%+v", lst.Forwards)
	}

	// remove：正常 / 规则不存在 bad_request / 无主机 no_host。
	if _, err := c.Request(ctx, facade.OpForwardRemove, ForwardRemoveArgs{Host: a, Listen: 8080}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Request(ctx, facade.OpForwardRemove, ForwardRemoveArgs{Host: a, Listen: 8080}); err == nil || errCodeOf(err) != facade.CodeBadRequest {
		t.Fatalf("规则不存在应 bad_request：%v", err)
	}
	if _, err := c.Request(ctx, facade.OpForwardRemove, ForwardRemoveArgs{Host: "cc00", Listen: 8080}); err == nil || errCodeOf(err) != facade.CodeNoHost {
		t.Fatalf("无主机应 no_host：%v", err)
	}
}

func TestCarrierSocksOps(t *testing.T) {
	ts := startTestServer(t, facade.BusConfig{})
	c, _ := dialTest(t, ts)
	ctx := context.Background()
	a := regCarrierHost(t, ts, carrierHostA, "ali")
	b := regCarrierHost(t, ts, carrierHostB, "mac")

	// on 默认 1080；同端口幂等。
	raw, err := c.Request(ctx, facade.OpSocksOn, SocksOnArgs{Host: a})
	if err != nil {
		t.Fatal(err)
	}
	var on SocksOnResult
	if err := json.Unmarshal(raw, &on); err != nil {
		t.Fatal(err)
	}
	if on.Listen != 1080 {
		t.Fatalf("缺省端口应 1080：%+v", on)
	}
	if _, err := c.Request(ctx, facade.OpSocksOn, SocksOnArgs{Host: a}); err != nil {
		t.Fatalf("同端口重复 on 应幂等：%v", err)
	}

	// 第二主机抢 1080：bad_request（FS Scenario「第二主机需另选端口」）。
	if _, err := c.Request(ctx, facade.OpSocksOn, SocksOnArgs{Host: b}); err == nil || errCodeOf(err) != facade.CodeBadRequest {
		t.Fatalf("跨主机端口冲突应 bad_request：%v", err)
	}
	// --listen 1081 则成功（换端口语义）。
	if _, err := c.Request(ctx, facade.OpSocksOn, SocksOnArgs{Host: b, Listen: 1081}); err != nil {
		t.Fatal(err)
	}
	// 值域外（80）：bad_request——与 forward 同一条值域。
	if _, err := c.Request(ctx, facade.OpSocksOn, SocksOnArgs{Host: b, Listen: 80}); err == nil || errCodeOf(err) != facade.CodeBadRequest {
		t.Fatalf("端口 80 应 bad_request：%v", err)
	}
	// 无主机：no_host。
	if _, err := c.Request(ctx, facade.OpSocksOn, SocksOnArgs{Host: "cc00"}); err == nil || errCodeOf(err) != facade.CodeNoHost {
		t.Fatalf("无主机应 no_host：%v", err)
	}

	// status：off 也出现（记忆端口暴露）。
	if _, err := c.Request(ctx, facade.OpSocksOff, SocksOffArgs{Host: a}); err != nil {
		t.Fatal(err)
	}
	raw, err = c.Request(ctx, facade.OpSocksStatus, nil)
	if err != nil {
		t.Fatal(err)
	}
	var st SocksStatusResult
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	var offAli *SocksBrief
	for i := range st.Socks {
		if st.Socks[i].Host == a {
			offAli = &st.Socks[i]
		}
	}
	if offAli == nil || offAli.On || offAli.Listen != 1080 {
		t.Fatalf("off 后记忆端口应可见（ali off 1080）：%+v", st.Socks)
	}
}

func TestCarrierSpeedtestOps(t *testing.T) {
	ts := startTestServer(t, facade.BusConfig{})
	c, _ := dialTest(t, ts)
	ctx := context.Background()
	a := regCarrierHost(t, ts, carrierHostA, "ali")

	// start：立即返回 waiting 相位（waitMs 载荷承载等待预算）。
	raw, err := c.Request(ctx, facade.OpSpeedtestStart, SpeedtestStartArgs{Host: a, DownMs: 10000, UpMs: 10000, WarmupMs: 2000, Streams: 4, WaitMs: 60000})
	if err != nil {
		t.Fatal(err)
	}
	var ack SpeedtestStartAck
	if err := json.Unmarshal(raw, &ack); err != nil {
		t.Fatal(err)
	}
	if ack.Phase != "waiting" {
		t.Fatalf("start 应立即返回 waiting：%+v", ack)
	}

	// 同主机重复 start：busy = 成功载荷里的 reason（零新增错误码）。
	raw, err = c.Request(ctx, facade.OpSpeedtestStart, SpeedtestStartArgs{Host: a})
	if err != nil {
		t.Fatal(err)
	}
	ack = SpeedtestStartAck{}
	if err := json.Unmarshal(raw, &ack); err != nil {
		t.Fatal(err)
	}
	if ack.Phase != "busy" || ack.Reason != "busy" {
		t.Fatalf("重复 start 应 busy 载荷：%+v", ack)
	}

	// status：waiting 相位 + 剩余预算。
	raw, err = c.Request(ctx, facade.OpSpeedtestStatus, SpeedtestStatusArgs{Host: a})
	if err != nil {
		t.Fatal(err)
	}
	var st SpeedtestStatusResult
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	if !st.Waiting || st.Phase != "waiting" {
		t.Fatalf("status 应 waiting：%+v", st)
	}

	// cancel：只作用指定主机；随后 status = cancelled 终态（Result 携带）。
	if _, err := c.Request(ctx, facade.OpSpeedtestCancel, SpeedtestCancelArgs{Host: a}); err != nil {
		t.Fatal(err)
	}
	raw, err = c.Request(ctx, facade.OpSpeedtestStatus, SpeedtestStatusArgs{Host: a})
	if err != nil {
		t.Fatal(err)
	}
	st = SpeedtestStatusResult{}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	if st.Result == nil || st.Result.Reason != "cancelled" {
		t.Fatalf("cancel 后终态应 cancelled：%+v", st)
	}

	// 无主机：start/status/cancel 均 no_host。
	for _, op := range []string{facade.OpSpeedtestStart, facade.OpSpeedtestStatus, facade.OpSpeedtestCancel} {
		if _, err := c.Request(ctx, op, map[string]string{"host": "cc00"}); err == nil || errCodeOf(err) != facade.CodeNoHost {
			t.Fatalf("%s 无主机应 no_host：%v", op, err)
		}
	}
}

func TestCarrierNotReadyGate(t *testing.T) {
	ts := startTestServer(t, facade.BusConfig{})
	c, _ := dialTest(t, ts)
	ctx := context.Background()
	a := regCarrierHost(t, ts, carrierHostA, "ali")

	ts.backend.mu.Lock()
	ts.backend.notReady = true
	ts.backend.mu.Unlock()

	ops := []struct {
		op   string
		args any
	}{
		{facade.OpForwardAdd, ForwardAddArgs{Host: a, Listen: 8080}},
		{facade.OpForwardRemove, ForwardRemoveArgs{Host: a, Listen: 8080}},
		{facade.OpForwardList, ForwardListArgs{}},
		{facade.OpSocksOn, SocksOnArgs{Host: a}},
		{facade.OpSocksOff, SocksOffArgs{Host: a}},
		{facade.OpSocksStatus, nil},
		{facade.OpSpeedtestStart, SpeedtestStartArgs{Host: a}},
		{facade.OpSpeedtestStatus, SpeedtestStatusArgs{Host: a}},
		{facade.OpSpeedtestCancel, SpeedtestCancelArgs{Host: a}},
	}
	for _, tc := range ops {
		if _, err := c.Request(ctx, tc.op, tc.args); err == nil || errCodeOf(err) != facade.CodeNotReady {
			t.Fatalf("%s 未就绪应 not_ready：%v", tc.op, err)
		}
	}
}

func TestCarrierUnknownFieldsIgnored(t *testing.T) {
	// 词表只增的前向兼容：载荷注入未来字段后照常解码（spec「未知字段忽略」——
	// encoding/json 默认行为，这里锁死承载面载荷不引入 DisallowUnknownField）。
	ts := startTestServer(t, facade.BusConfig{})
	c, _ := dialTest(t, ts)
	ctx := context.Background()
	a := regCarrierHost(t, ts, carrierHostA, "ali")

	raw, err := c.Request(ctx, facade.OpForwardAdd, map[string]any{
		"host": a, "listen": 7070, "futureFieldFromV2": map[string]any{"x": 1},
	})
	if err != nil {
		t.Fatalf("未知字段应被忽略：%v", err)
	}
	var add ForwardAddResult
	if err := json.Unmarshal(raw, &add); err != nil || add.Rule.Listen != 7070 {
		t.Fatalf("解码结果异常：%+v %v", add, err)
	}
}

// errCodeOf 取错误的稳定码（FIX-50 起错误可能是 *OpError（带 detail）或 CodeError）。
func errCodeOf(err error) string {
	code, _, ok := CodeDetailOf(err)
	if !ok {
		return ""
	}
	return string(code)
}

// TestCarrierErrDetailCarried（FIX-50）：可行动归因随错误一起到 CLI——稳定码保持
// 窄值域（bad_request），具体原因（「已被 X 占用」）走 detail，不再被吞成三个字。
// 变异自证：去掉 reply 里的 rsp.Detail 赋值 ⇒ 本用例红（detail 空）。
func TestCarrierErrDetailCarried(t *testing.T) {
	ts := startTestServer(t, facade.BusConfig{})
	c, _ := dialTest(t, ts)
	ctx := context.Background()
	a := regCarrierHost(t, ts, carrierHostA, "ali")
	b := regCarrierHost(t, ts, carrierHostB, "mac")
	if _, err := c.Request(ctx, facade.OpForwardAdd, ForwardAddArgs{Host: a, Listen: 8080}); err != nil {
		t.Fatal(err)
	}
	// 端口冲突（跨主机）：真实错误文本应完整到达（含端口号与占用者）。
	_, err := c.Request(ctx, facade.OpForwardAdd, ForwardAddArgs{Host: b, Listen: 8080})
	if err == nil {
		t.Fatal("应冲突")
	}
	code, detail, ok := CodeDetailOf(err)
	if !ok || code != facade.CodeBadRequest {
		t.Fatalf("码应为 bad_request（窄值域），got %v/%v", code, ok)
	}
	if detail == "" {
		t.Fatal("detail 应携带服务端可行动归因（FIX-50）")
	}
	// 既有断言面不受影响：errors.Is / errors.As 对 CodeError 仍成立。
	if !errors.Is(err, CodeError(facade.CodeBadRequest)) {
		t.Fatal("errors.Is(err, CodeError) 应成立")
	}
	var ce CodeError
	if !errors.As(err, &ce) || string(ce) != facade.CodeBadRequest {
		t.Fatalf("errors.As 应取到码：%v", err)
	}
}

// TestHeldFramesBounded（FIX-54）：订阅确认门闩期的事件暂存有显式上限——超限按
// overrun 断连自保（原实现无界，订阅者不收确认 + 事件持续来 = 每连接内存无界增长）。
func TestHeldFramesBounded(t *testing.T) {
	// 手搓最小可用 conn（门闩置位 = 确认未写出的形态）：close 需要 highC（可排空）、
	// nc（可 Close）、streams/subConfirm（非 nil）三件；s.sub 保持 nil，不走 Bus。
	nc1, nc2 := net.Pipe()
	defer nc2.Close()
	c := &conn{
		nc:         nc1,
		highC:      make(chan highItem, 8),
		closed:     make(chan struct{}),
		streams:    map[uint32]*stream{},
		subConfirm: map[uint64]bool{1: true},
	}
	// 先塞到接近上限，再跨过——跨过那次必须触发 fatal（overrun）。
	for i := 0; i < heldFramesMax; i++ {
		if !c.takeEvent(facade.Event{Seq: uint64(i + 1), Domain: facade.DomainLink, Kind: facade.KindLinkChanged}) {
			t.Fatalf("第 %d 条暂存不应触发断连", i+1)
		}
	}
	if c.takeEvent(facade.Event{Seq: uint64(heldFramesMax + 1), Domain: facade.DomainLink, Kind: facade.KindLinkChanged}) {
		t.Fatal("超限应拒绝（overrun 断连）")
	}
	select {
	case <-c.closed:
	case <-time.After(time.Second):
		t.Fatal("超限应关闭连接（fatal → closed）")
	}
}

// TestNotReadyGateCoversBackendOps（FIX-52）：**操作词表级**的 NotReady 门核对——
// 后端类 op（host.*/snapshot.get/承载面 9 op）在未就绪时都必须回 not_ready。门已统一
// 成 gateNotReady 一处；本表按 spec 词表逐个 op 打一遍，新增 op 漏加门 = 本用例红。
// 非后端类（daemon.status/events.*/stream.*/serve|relay.*）不在此表：它们不依赖后端
// 就绪（角色面由 Backend 方法自己的错误映射承载）。
func TestNotReadyGateCoversBackendOps(t *testing.T) {
	ts := startTestServer(t, facade.BusConfig{})
	c, _ := dialTest(t, ts)
	ctx := context.Background()
	a := regCarrierHost(t, ts, carrierHostA, "ali")
	ts.backend.mu.Lock()
	ts.backend.notReady = true
	ts.backend.mu.Unlock()

	ops := []struct {
		op   string
		args any
	}{
		{facade.OpHostAdd, HostAddArgs{Token: "hmw1x"}},
		{facade.OpHostRemove, HostRemoveArgs{Host: a}},
		{facade.OpHostList, nil},
		{facade.OpSnapshotGet, nil},
		{facade.OpForwardAdd, ForwardAddArgs{Host: a, Listen: 8080}},
		{facade.OpForwardRemove, ForwardRemoveArgs{Host: a, Listen: 8080}},
		{facade.OpForwardList, ForwardListArgs{}},
		{facade.OpSocksOn, SocksOnArgs{Host: a}},
		{facade.OpSocksOff, SocksOffArgs{Host: a}},
		{facade.OpSocksStatus, nil},
		{facade.OpSpeedtestStart, SpeedtestStartArgs{Host: a}},
		{facade.OpSpeedtestStatus, SpeedtestStatusArgs{Host: a}},
		{facade.OpSpeedtestCancel, SpeedtestCancelArgs{Host: a}},
	}
	for _, tc := range ops {
		if _, err := c.Request(ctx, tc.op, tc.args); err == nil || errCodeOf(err) != facade.CodeNotReady {
			t.Fatalf("%s 未就绪应 not_ready（gateNotReady 漏挂？）：%v", tc.op, err)
		}
	}
}
