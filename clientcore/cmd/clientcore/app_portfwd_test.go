//go:build cshared

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
)

// errExitSession 拨号必败的假上游：探测性 TCP 连接万一真被 accept，也不许碰 nil。
type errExitSession struct{}

func (errExitSession) ServerTunnelIP() netip.Addr { return netip.MustParseAddr("100.64.255.1") }

func (errExitSession) DialTCPPort(ctx context.Context, port uint16) (net.Conn, error) {
	return nil, fmt.Errorf("pf-test: 不拨上游")
}
func (errExitSession) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return nil, fmt.Errorf("pf-test: 不拨上游")
}
func (errExitSession) PathProbe(ctx context.Context) error { return nil }
func (errExitSession) Close() error                        { return nil }

// newPfTestRunner 构造仅够 pf 子系统跑起来的最小 runner：pf 函数只碰 logf 与
// pf* 字段；上游用拨号必败的假会话顶住探测性连接。
func newPfTestRunner() *tunRunner {
	return &tunRunner{logf: func(format string, args ...any) {
		fmt.Printf("   [pf-test] "+format+"\n", args...)
	}, dialTimeout: 2 * time.Second, cl: errExitSession{}}
}

// pfPortClosed 只对「应已关闭」的口用：拨一下必须被拒。
// （开着听没听不能这么测——探测连接会真被 accept、触发上游拨号路径。）
func pfPortClosed(t *testing.T, port uint16) bool {
	t.Helper()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
	if err != nil {
		return true
	}
	_ = c.Close()
	return false
}

// pfStateOf 从状态表里取某端口的状态（空串 = 不在表里）。
func pfStateOf(tr *tunRunner, port uint16) string {
	for _, s := range tr.pfStatusJSON() {
		if u, ok := s["listen"].(uint16); ok && u == port {
			state, _ := s["state"].(string)
			return state
		}
	}
	return ""
}

// 热替换的核心合同：换表后旧监听口关闭、新监听口在听、状态表与配置一致。
func TestSetPortForwardsReconfigures(t *testing.T) {
	tr := newPfTestRunner()
	defer tr.stopPortForwards()

	ports := freeLocalPorts(t, 3)
	p1, p2, p3 := ports[0], ports[1], ports[2]
	tr.setPortForwards([]tunPortForward{{Listen: p1, TargetPort: 80}, {Listen: p2, TargetPort: 81}})
	if pfStateOf(tr, p1) != "listening" || pfStateOf(tr, p2) != "listening" {
		t.Fatalf("首启后两个监听口都该在听（%d %d）：%v", p1, p2, tr.pfStatusJSON())
	}

	// 换表：去掉 p1、保留 p2、新增 p3
	tr.setPortForwards([]tunPortForward{{Listen: p2, TargetPort: 81}, {Listen: p3, TargetPort: 82}})
	if !pfPortClosed(t, p1) {
		t.Fatalf("换表后旧口 %d 必须已关（否则端口泄漏/状态错乱）", p1)
	}
	if pfStateOf(tr, p2) != "listening" || pfStateOf(tr, p3) != "listening" {
		t.Fatalf("换表后保留口 %d 与新增口 %d 必须在听", p2, p3)
	}

	// 状态表与新配置一致（顺序、端口、listening）
	st := tr.pfStatusJSON()
	if len(st) != 2 {
		t.Fatalf("状态表长度 = %d，要 2", len(st))
	}
	if st[0]["listen"] != p2 || st[1]["listen"] != p3 {
		t.Fatalf("状态表端口顺序错：%v", st)
	}
	for _, s := range st {
		if s["state"] != "listening" {
			t.Fatalf("状态应为 listening：%v", s)
		}
	}

	// 清空 = 全停、状态清零
	tr.setPortForwards(nil)
	if !pfPortClosed(t, p2) || !pfPortClosed(t, p3) {
		t.Fatalf("清空后监听口必须全关")
	}
	if got := tr.pfStatusJSON(); len(got) != 0 {
		t.Fatalf("清空后状态表必须为空：%v", got)
	}
}

// 占用中的端口：该条记 failed、不阻断其余条目（软失败哲学），状态表仍覆盖全部条目。
func TestSetPortForwardsConflictMarksFailed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("预占端口失败：%v", err)
	}
	defer ln.Close()
	busy := uint16(ln.Addr().(*net.TCPAddr).Port)
	free := freeLocalPorts(t, 1)[0]

	tr := newPfTestRunner()
	defer tr.stopPortForwards()
	tr.setPortForwards([]tunPortForward{{Listen: busy, TargetPort: 80}, {Listen: free, TargetPort: 81}})

	st := tr.pfStatusJSON()
	if len(st) != 2 {
		t.Fatalf("两条都要有状态：%v", st)
	}
	if st[0]["state"] != "failed" || st[0]["listen"] != busy {
		t.Fatalf("被占口应记 failed：%v", st[0])
	}
	if st[1]["state"] != "listening" {
		t.Fatalf("另一条应正常 listening：%v", st[1])
	}
}

// NAPI 入口的返回码合同：无世代 -1（调用方稍后重试）、非法 JSON / 非法端口 -2。
func TestTunSetPortForwardsJSONReturnCodes(t *testing.T) {
	if got := tunSetPortForwardsJSON("{not json"); got != -2 {
		t.Fatalf("非法 JSON 应 -2，得 %d", got)
	}
	if got := tunSetPortForwardsJSON(`{"portForwards":[{"listen":0,"targetPort":80}]}`); got != -2 {
		t.Fatalf("listen=0 应 -2，得 %d", got)
	}
	if got := tunSetPortForwardsJSON(`{"portForwards":[{"listen":18080,"targetIp":"","targetPort":8080}]}`); got != -1 {
		// 测试进程里没有接管中的世代（currentTunRun 为 nil）
		t.Fatalf("无世代应 -1，得 %d", got)
	}
}

// 入参形状与 tunConfig 同名键兼容（扩展侧同一份拼装逻辑的两端必须对得上）。
func TestTunSetPortForwardsJSONShape(t *testing.T) {
	var v struct {
		PortForwards []tunPortForward `json:"portForwards"`
	}
	in := `{"portForwards":[{"listen":18080,"targetIp":"","targetPort":8080},{"listen":18443,"targetIp":"10.1.2.3","targetPort":443}]}`
	if err := json.Unmarshal([]byte(in), &v); err != nil {
		t.Fatalf("形状不兼容：%v", err)
	}
	if len(v.PortForwards) != 2 || v.PortForwards[0].Listen != 18080 || v.PortForwards[1].TargetIp != "10.1.2.3" {
		t.Fatalf("解析结果不对：%+v", v.PortForwards)
	}
}

// freeLocalPorts 拿 n 个当前空闲的 TCP 端口（先 listen 再关，窗口期内无人占用即可）。
func freeLocalPorts(t *testing.T, n int) []uint16 {
	t.Helper()
	ports := make([]uint16, 0, n)
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("拿空闲端口失败：%v", err)
		}
		ports = append(ports, uint16(ln.Addr().(*net.TCPAddr).Port))
		_ = ln.Close()
	}
	return ports
}

// 世代收工后的热更新必须被拒绝（review 复审：孤儿监听器）。
//
// 触发面很宽：任何"扩展进程活着、但世代已经收工"的时刻（GIVE_UP 冷却期、连接失败后、
// tunStop→prepare 之间）用户保存/删除映射都会命中。旧实现只看 currentTunRun() 是否为
// nil，而 tunNow 从不置空 ⇒ 监听器被装进死世代的 runner：返回 0 谎报成功、端口被永久
// 占住（之后同端口映射恒 EADDRINUSE）、状态面还显示"监听中"。
func TestTunSetPortForwardsRejectedAfterGenerationEnd(t *testing.T) {
	ports := freeLocalPorts(t, 1)
	port := ports[0]

	// 清理：本用例会动包级共享状态（probeRunning/阶段/tunNow），跑完必须复原，
	// 否则同包其它用例的"没有接管中的世代"前提会被破坏。
	defer func() {
		probeRunning.Store(0)
		setStage(stageIdle, "", "", false)
		tunMu.Lock()
		tunNow = nil
		tunMu.Unlock()
	}()

	// ① 正向对照：attached + probeRunning=1（在世代的形态）→ 应用成功、真的在监听。
	probeRunning.Store(1)
	setStage(stageAttached, "", "", true)
	r := beginTunRun()
	tr := newPfTestRunner()
	r.setRunner(tr)
	cfg := fmt.Sprintf(`{"portForwards":[{"listen":%d,"targetPort":80}]}`, port)
	if rc := tunSetPortForwardsJSON(cfg); rc != 0 {
		t.Fatalf("在世代的形态下热更新应返回 0，得 %d", rc)
	}
	if ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
		_ = ln.Close()
		t.Fatal("热更新返回 0 但端口没人监听（正向路径没生效）")
	}

	// ② 世代收工：done 关闭（probeRunning 随之清零）+ 世代退出时 defer 的 stopPortForwards
	//（真实收工顺序）→ 此后热更新必须 -1，且不得再装监听器。
	r.finish()
	tr.stopPortForwards()
	if rc := tunSetPortForwardsJSON(cfg); rc != -1 {
		t.Fatalf("已收工世代的热更新应返回 -1（无接管中的世代），得 %d", rc)
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("端口 %d 被孤儿监听器占住（%v）——热更新装进了死世代", port, err)
	}
	_ = ln.Close()
	tr.stopPortForwards()
}

// 同表内重复监听端口必须被拒（第二条注定 EADDRINUSE，界面会显示一条莫名其妙的"失败"）。
func TestTunSetPortForwardsRejectsDuplicateListen(t *testing.T) {
	ports := freeLocalPorts(t, 1)
	cfg := fmt.Sprintf(`{"portForwards":[{"listen":%d,"targetPort":80},{"listen":%d,"targetPort":81}]}`,
		ports[0], ports[0])
	if rc := tunSetPortForwardsJSON(cfg); rc != -2 {
		t.Fatalf("重复监听端口应返回 -2，得 %d", rc)
	}
}
