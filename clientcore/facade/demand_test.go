package facade

// demand_test.go — 4a §6.2（三源合成 + view 文法 + 需求观测面）与 §6.3（Diag
// 回调 → session.diag 总线事件）与 §6.4（真值表对齐审计的 facade 侧向量用例）
// 的用例。

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/hostsession"
	"github.com/zhaoyswd/homeway/pkg/probe"
	"github.com/zhaoyswd/homeway/pkg/proto"
)

// demandTestID 测试主机 peerID（[32]byte 与其 64 hex 形式）。
func demandTestID() (id [32]byte, hexID string) {
	for i := range id {
		id[i] = byte(i*3 + 1)
	}
	return id, hex.EncodeToString(id[:])
}

// TestParseViewGrammar view 文法（D5：host=<id>[,host=<id>]*，只增不改）：合法
// 多台 / 空串 / 垃圾串保守忽略。
func TestParseViewGrammar(t *testing.T) {
	id1 := strings.Repeat("11", 32)
	id2 := strings.Repeat("22", 32)
	// 合法多台。
	got := ParseView("host=" + id1 + ",host=" + id2)
	if len(got) != 2 {
		t.Fatalf("合法双主机应解析 2 条：%d", len(got))
	}
	if string(got[0][:]) != strings.Repeat("\x11", 32) {
		t.Fatalf("第一条主机 id 不符：%x", got[0])
	}
	// 空串 = 空集（不参与需求合成，不报错）。
	if got = ParseView(""); got != nil {
		t.Fatalf("空串应空集：%v", got)
	}
	// 垃圾串：未知格式/短 hex/非 host= 前缀——保守忽略（逐条跳过，合法条仍收）。
	if got = ParseView("garbage,host=xyz,host=" + id1 + ",host=zz"); len(got) != 1 {
		t.Fatalf("垃圾串应只收合法 1 条：%v", got)
	}
	// 大小写/空白：条目两端空白容忍，host= 前缀大小写敏感（文法只增不改——不做
	// 宽松匹配）。
	if got = ParseView(" host=" + id1 + " "); len(got) != 1 {
		t.Fatalf("条目两端空白应容忍：%v", got)
	}
	if got = ParseView("HOST=" + id1); got != nil {
		t.Fatalf("前缀大小写敏感（未知格式保守忽略）：%v", got)
	}
}

// TestDemandSynthesisThreeSources 三源合成（§6.2 用例：三源单真 / 全假 / 退订后
// 贡献消失）。
func TestDemandSynthesisThreeSources(t *testing.T) {
	id, hexID := demandTestID()
	bus := NewBus(NewGeneration(), BusConfig{})
	h := &hostDemand{}

	// 首拍（无源）：false "无"。
	if a, why := h.evaluate(bus, id); a || why != "无" {
		t.Fatalf("全假应 (false,\"无\")，得 (%v,%q)", a, why)
	}
	// 源①拨号尝试：单真。
	h.dials.Add(1)
	if a, why := h.evaluate(bus, id); !a || why != "拨号尝试" {
		t.Fatalf("拨号尝试应单真，得 (%v,%q)", a, why)
	}
	// 计数被消费：再评估无此源。
	if a, why := h.evaluate(bus, id); a || why != "无" {
		t.Fatalf("拨号计数应单拍消费，得 (%v,%q)", a, why)
	}
	// 源②在场腿：单真。
	h.activeNx.Add(1)
	if a, why := h.evaluate(bus, id); !a || why != "在场腿" {
		t.Fatalf("在场腿应单真，得 (%v,%q)", a, why)
	}
	h.activeNx.Add(-1)
	// 源③订阅视图：单真（view 声明聚合到主机集合）。
	sub := bus.NewSubscriber()
	if err := bus.Subscribe(sub, []string{DomainSession}, nil, bus.Generation(), "host="+hexID); err != nil {
		t.Fatal(err)
	}
	if a, why := h.evaluate(bus, id); !a || why != "订阅视图" {
		t.Fatalf("订阅视图应单真，得 (%v,%q)", a, why)
	}
	// 退订后贡献消失（§7.1 场景的 facade 侧前置：全摘域 = 订阅者离开 b.subs）。
	bus.UnsubscribeDomains(sub, []string{DomainSession})
	if a, why := h.evaluate(bus, id); a || why != "无" {
		t.Fatalf("退订后需求贡献应消失，得 (%v,%q)", a, why)
	}
	// 断连入口（exec-r1 低-6）：wire 断开走 Bus.Unsubscribe(c.sub)（server.go
	// close() 段——与 UnsubscribeDomains 等价但非同一入口）；同入口下 view 聚合
	// 回落的直接断言（此前只有代码阅读证据）。
	if err := bus.Subscribe(sub, []string{DomainSession}, nil, bus.Generation(), "host="+hexID); err != nil {
		t.Fatal(err)
	}
	if a, _ := h.evaluate(bus, id); !a {
		t.Fatal("重订阅（view）后源③应单真")
	}
	bus.Unsubscribe(sub)
	if a, why := h.evaluate(bus, id); a || why != "无" {
		t.Fatalf("断连入口（Bus.Unsubscribe）后 view 聚合应回落，得 (%v,%q)", a, why)
	}
}

// TestDemandViewAtomicReplace 替换订阅时 view 随 domains 一并整体替换（新声明
// 生效、旧声明消失）。
func TestDemandViewAtomicReplace(t *testing.T) {
	id, hexID := demandTestID()
	other := strings.Repeat("cc", 32)
	bus := NewBus(NewGeneration(), BusConfig{})
	sub := bus.NewSubscriber()
	if err := bus.Subscribe(sub, []string{DomainSession}, nil, bus.Generation(), "host="+hexID); err != nil {
		t.Fatal(err)
	}
	if !bus.viewDemand(id) {
		t.Fatal("view 声明应参与聚合")
	}
	if err := bus.Subscribe(sub, []string{DomainLink}, nil, bus.Generation(), "host="+other); err != nil {
		t.Fatal(err)
	}
	if bus.viewDemand(id) {
		t.Fatal("替换订阅后旧 view 声明应消失")
	}
}

// TestFacadeWiresDemandDiagHooks 装配接线（§6.1/§6.3）：Attach 的表把
// sessionHooks 注入 hostsession Options（Demand/Diag 非 nil）；Diag 回调 =
// 发 session.diag 到进程级总线（端到端：注入缝驱动 → 总线事件，词表/载荷同源
// vocab.go）。
func TestFacadeWiresDemandDiagHooks(t *testing.T) {
	dir := t.TempDir()
	d := New(Options{
		StrictIdentity: true,
		Probe: func(ctx context.Context, token string) (*probe.ReachReport, error) {
			id, _ := demandTestID()
			return &probe.ReachReport{
				Peer:    hex.EncodeToString(id[:2]),
				Results: []probe.ReachResult{{EP: "203.0.113.9:41641", RTT: 9 * time.Millisecond}},
			}, nil
		},
	})
	t.Cleanup(d.Close)
	if err := d.Attach(dir); err != nil {
		t.Fatal(err)
	}
	// 注入 newSession：捕获 Options、返回错误（条目仍入表——「构造期失败」形态，
	// 不起生命周期；钩子接线与生命周期无关）。
	var captured []hostsession.Options
	oldNew := newSession
	newSession = func(cfg hostsession.Config, opts hostsession.Options) (*hostsession.Session, error) {
		captured = append(captured, opts)
		return nil, errors.New("注入：只捕钩子")
	}
	t.Cleanup(func() { newSession = oldNew })
	if _, err := d.AddHost(context.Background(), "钩子机", demandTestToken(t), false); err != nil {
		t.Fatal(err)
	}
	if len(captured) != 1 {
		t.Fatalf("应恰捕获一次 Options：%d", len(captured))
	}
	if captured[0].Demand == nil || captured[0].Diag == nil {
		t.Fatal("Attach 的表应注入 Demand/Diag 钩子（§6 接线断）")
	}

	// Diag 回调 → session.diag 总线事件（端到端）。
	briefs := d.HostBriefs()
	if len(briefs) != 1 {
		t.Fatalf("主机面应 1 台：%d", len(briefs))
	}
	hexID := briefs[0].ID
	sub := d.Bus().NewSubscriber()
	if err := d.Bus().Subscribe(sub, []string{DomainSession}, nil, d.Bus().Generation(), ""); err != nil {
		t.Fatal(err)
	}
	for _, reason := range []string{"gated", "budget", "probe_window"} {
		captured[0].Diag(reason)
	}
	deadline := time.After(3 * time.Second)
	want := map[string]bool{"gated": false, "budget": false, "probe_window": false}
	for {
		all := true
		for _, ok := range want {
			if !ok {
				all = false
			}
		}
		if all {
			break
		}
		select {
		case ev := <-sub.Events():
			if ev.Kind != KindSessionDiag || ev.Domain != DomainSession {
				t.Fatalf("应为 session 域 session.diag：%+v", ev)
			}
			var p SessionDiagPayload
			if err := json.Unmarshal(ev.Payload, &p); err != nil {
				t.Fatal(err)
			}
			if p.Host != hexID {
				t.Fatalf("载荷 host 应为主机 id：%q", p.Host)
			}
			if _, ok := want[p.Reason]; !ok {
				t.Fatalf("reason 值域外：%q", p.Reason)
			}
			want[p.Reason] = true
		case <-deadline:
			t.Fatalf("三 reason 未收齐：%v", want)
		}
	}

	// Demand 回调 → sticky 落 demand 观测面（Daemon.DemandStatus）。
	h := d.Host(mustPeerID(t, hexID))
	if h == nil {
		t.Fatal("Host 对象不在")
	}
	h.dm.dials.Add(1)
	if a, why := captured[0].Demand(); !a || why != "拨号尝试" {
		t.Fatalf("Demand 回调应合成拨号尝试，得 (%v,%q)", a, why)
	}
	brief := d.DemandStatus()
	if len(brief) != 1 || !brief[0].Active || brief[0].Reason != "拨号尝试" || brief[0].At == 0 {
		t.Fatalf("demand 观测面应 sticky 记录最近一拍：%+v", brief)
	}
}

// demandTestToken 一个语法合法的 token（AddHost 的 decode 入口需要；探测假缝
// 在 New 时注入——不触网）。
func demandTestToken(t *testing.T) string {
	t.Helper()
	id, _ := demandTestID()
	var secret [32]byte
	tok, err := proto.EncodeToken(proto.Token{
		PeerID:    id,
		Secret:    secret,
		Endpoints: []proto.Endpoint{{Addr: "203.0.113.9:41641"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestDemandTruthTableAlignment §6.4 真值表对齐审计的 **facade 侧向量用例**：
// 手机门与桌面门已收口到同一实现（hostsession.PatrolEvidenceGate，FIX-20），
// 五分支向量（成功拍清零 / localNoise 清零 / 无需求清零 / 窗口作废 / 正常计数）
// 在本层全量断言；cshared 面的序列级回归见 cmd/clientcore/demand_test.go 的
// TestPatrolEvidenceGateSuccessResets。
func TestDemandTruthTableAlignment(t *testing.T) {
	now := time.Now()
	errProbe := errors.New("probe fail")
	type vector struct {
		name        string
		noise       bool
		demand      bool
		streak      int
		lastCounted time.Time
		probeErr    error
		wantN       int
		wantCounted bool
	}
	vectors := []vector{
		{"成功拍清零", false, true, 2, now, nil, 0, false},
		{"localNoise 清零", true, true, 2, now, errProbe, 0, false},
		{"无需求清零", false, false, 2, now, errProbe, 0, false},
		{"窗口作废（>10 分钟从 1 重数）", false, true, 2, now.Add(-3 * time.Hour), errProbe, 1, true},
		{"窗内正常累加", false, true, 2, now.Add(-2 * time.Minute), errProbe, 3, true},
		{"正常计数（+1）", false, true, 1, now.Add(-time.Minute), errProbe, 2, true},
	}
	for _, v := range vectors {
		n, counted := hostsession.PatrolEvidenceGate(v.noise, v.demand, v.streak, v.lastCounted, now, v.probeErr)
		if n != v.wantN || counted != v.wantCounted {
			t.Errorf("【%s】桌面门得 (%d,%v)，期望 (%d,%v)——与手机门真值表对齐断", v.name, n, counted, v.wantN, v.wantCounted)
		}
	}
}

// TestDemandTrafficSourceUserConnOnly 源①字节口径（exec-r1 中-2 整改回归）：
// 需求字节源 = countedConn.Write 的**用户连接出站**——探针（PathProbe/punchTo 拨
// 出口 1 号端口）与 WG 握手/保活不经 Host.DialPort，无路径进入计数面 ⇒ 探针失败
// 期无用户流量时 demand=false（门控 !demand 分支可达）；用户写出 ⇒ true（出站包）；
// 连接关闭且无新字节 ⇒ 回落「无」。旧口径（StatsSnapshot.TxBytes 差分）把探针自身
// 出站重试也算作需求（后端死时恒真），已弃。
func TestDemandTrafficSourceUserConnOnly(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() { _, _ = io.Copy(io.Discard, c2) }() // pipe 同步写需要读者排空对端
	restore := injectDialPort(func(s *hostsession.Session, ctx context.Context, port uint16) (net.Conn, error) {
		return c1, nil
	})
	defer restore()

	id, _ := demandTestID()
	bus := NewBus(NewGeneration(), BusConfig{})
	dm := &hostDemand{}
	h := &Host{rec: HostRecord{ID: "probe-excluded"}, sess: &hostsession.Session{}, dm: dm}

	// 首拍采样：无任何用户面动作——探针流量（不经 Host.DialPort）不可能进入计数面。
	if a, why := dm.evaluate(bus, id); a || why != "无" {
		t.Fatalf("探针失败期无用户流量应 (false,\"无\")，得 (%v,%q)", a, why)
	}
	// 用户拨号：本拍拨号尝试（源①的拨号腿）。
	conn, err := h.DialPort(context.Background(), 7724)
	if err != nil {
		t.Fatal(err)
	}
	if a, why := dm.evaluate(bus, id); !a || why != "拨号尝试" {
		t.Fatalf("拨号拍应 (true,\"拨号尝试\")，得 (%v,%q)", a, why)
	}
	// 无新字节、连接在场：在场腿（源②）。
	if a, why := dm.evaluate(bus, id); !a || why != "在场腿" {
		t.Fatalf("在场无字节应 (true,\"在场腿\")，得 (%v,%q)", a, why)
	}
	// 用户写出：出站包（源①的字节腿——countedConn.Write 记账）。
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if a, why := dm.evaluate(bus, id); !a || why != "出站包" {
		t.Fatalf("用户写出应 (true,\"出站包\")，得 (%v,%q)", a, why)
	}
	// 连接关闭、无新字节：全源回落。
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if a, why := dm.evaluate(bus, id); a || why != "无" {
		t.Fatalf("关流后无新字节应 (false,\"无\")，得 (%v,%q)", a, why)
	}
}

// TestDemandRefreshKeepsSingleState exec-r1 中-1 整改回归：同 peerID 换 token
// 刷新后 demand 状态不分叉——会话侧钩子、观测面（Daemon.DemandStatus）、计数器
// 三面同一 hostDemand（刷新复用原表条目，新会话装回 e）。改前：刷新路径
// startEntryLocked 造新 entry，钩子绑孤儿 dm、观测面读旧 dm，demand 段对刷新
// 主机永久冻结在刷新前值。
func TestDemandRefreshKeepsSingleState(t *testing.T) {
	dir := t.TempDir()
	d := New(Options{
		StrictIdentity: true,
		Probe: func(ctx context.Context, token string) (*probe.ReachReport, error) {
			id, _ := demandTestID()
			return &probe.ReachReport{
				Peer:    hex.EncodeToString(id[:2]),
				Results: []probe.ReachResult{{EP: "203.0.113.9:41641", RTT: 9 * time.Millisecond}},
			}, nil
		},
	})
	t.Cleanup(d.Close)
	if err := d.Attach(dir); err != nil {
		t.Fatal(err)
	}
	// 注入 newSession：捕获 Options、返回错误（条目仍入表——不起生命周期；
	// 钩子接线与刷新路径的条目归属无关）。
	var captured []hostsession.Options
	oldNew := newSession
	newSession = func(cfg hostsession.Config, opts hostsession.Options) (*hostsession.Session, error) {
		captured = append(captured, opts)
		return nil, errors.New("注入：只捕钩子")
	}
	t.Cleanup(func() { newSession = oldNew })

	_, hexID := demandTestID()
	tok1, tok2 := refreshTestToken(t, 1), refreshTestToken(t, 2) // 同 peerID、不同 secret = 刷新
	if _, err := d.AddHost(context.Background(), "刷新机", tok1, false); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AddHost(context.Background(), "", tok2, false); err != nil {
		t.Fatalf("同 peerID 换 token 应走刷新：%v", err)
	}
	if len(captured) != 2 {
		t.Fatalf("应恰捕获两次 Options（入表 + 刷新），实得 %d", len(captured))
	}
	// view 需求为真 → 新会话的钩子判定（会话侧写）。
	sub := d.Bus().NewSubscriber()
	if err := d.Bus().Subscribe(sub, []string{DomainSession}, nil, d.Bus().Generation(), "host="+hexID); err != nil {
		t.Fatal(err)
	}
	if a, why := captured[1].Demand(); !a || why != "订阅视图" {
		t.Fatalf("刷新后钩子应判 (true,\"订阅视图\")，得 (%v,%q)", a, why)
	}
	// 观测面与钩子判定一致（改前这里读旧 dm：Active=false 冻结）。
	brief := d.DemandStatus()
	if len(brief) != 1 || brief[0].Host != hexID {
		t.Fatalf("demand 观测面应恰一条（%s）：%+v", hexID, brief)
	}
	if !brief[0].Active || brief[0].Reason != "订阅视图" || brief[0].At == 0 {
		t.Fatalf("观测面应与钩子判定一致（true/订阅视图），得 %+v——刷新后状态分叉", brief[0])
	}
	// 退订后两面同步回落（同一 dm 的 sticky 写点）。
	d.Bus().UnsubscribeDomains(sub, []string{DomainSession})
	if a, why := captured[1].Demand(); a || why != "无" {
		t.Fatalf("退订后钩子应回落 (false,\"无\")，得 (%v,%q)", a, why)
	}
	if brief = d.DemandStatus(); brief[0].Active || brief[0].Reason != "无" {
		t.Fatalf("退订后观测面应同步回落，得 %+v", brief[0])
	}
}

// refreshTestToken 同 peerID、不同 secret 的 token 对（刷新路径驱动件：同后端
// 重签发形态）。
func refreshTestToken(t *testing.T, secret byte) string {
	t.Helper()
	id, _ := demandTestID()
	var sec [32]byte
	sec[0] = secret
	tok, err := proto.EncodeToken(proto.Token{
		PeerID:    id,
		Secret:    sec,
		Endpoints: []proto.Endpoint{{Addr: "203.0.113.9:41641"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// mustPeerID 见 table_isolation_test.go（同包既有助手）。

// TestDemandFilesStreamPresenceLeg files-cli 2.3 用例（files 流腿的 DialPort 记账）：
// 经注入桩拨 DialPort(ctx, 7802)（files 服务端口）——桩收到 7802（kind→端口→DialPort
// 唯一路径的 facade 侧端点断言）且连接在途 = 需求源②在场腿 > 0（长传输期间巡检失败
// 照常计证据、不被「无需求期」门控压制）；连接关闭 → 在场腿归零。
func TestDemandFilesStreamPresenceLeg(t *testing.T) {
	var gotPort uint16
	portCh := make(chan uint16, 1)
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() { _, _ = io.Copy(io.Discard, c2) }() // pipe 同步写需要读者排空对端
	restore := injectDialPort(func(s *hostsession.Session, ctx context.Context, port uint16) (net.Conn, error) {
		gotPort = port
		select {
		case portCh <- port:
		default:
		}
		return c1, nil
	})
	defer restore()

	id, _ := demandTestID()
	bus := NewBus(NewGeneration(), BusConfig{})
	dm := &hostDemand{}
	h := &Host{rec: HostRecord{ID: "files-leg"}, sess: &hostsession.Session{}, dm: dm}

	// files 流腿拨号（7802 = filesServicePort 的核内约定值）。
	conn, err := h.DialPort(context.Background(), 7802)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-portCh:
		if p != 7802 {
			t.Fatalf("DialPort 应携带 files 端口 7802，得到 %d", p)
		}
	case <-time.After(time.Second):
		t.Fatalf("注入桩未收到端口（gotPort=%d）", gotPort)
	}
	// 拨号拍先落源①（单拍消费）；下一拍起连接在途 = 在场腿（源②）——files 长传输
	// 期间需求恒真。
	if a, why := dm.evaluate(bus, id); !a || why != "拨号尝试" {
		t.Fatalf("拨号拍应 (true,\"拨号尝试\")，得 (%v,%q)", a, why)
	}
	if a, why := dm.evaluate(bus, id); !a || why != "在场腿" {
		t.Fatalf("files 流在途应 (true,\"在场腿\")，得 (%v,%q)", a, why)
	}
	// 连接关闭 → 在场腿归零（全源回落）。
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	// countedConn 的关闭钩子同步执行（Close 里解注册）；给一个短窗口防调度抖动。
	deadline := time.Now().Add(2 * time.Second)
	for {
		if a, why := dm.evaluate(bus, id); !a && why == "无" {
			return
		} else if time.Now().After(deadline) {
			t.Fatalf("关流后在场腿应归零，得 (%v,%q)", a, why)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
