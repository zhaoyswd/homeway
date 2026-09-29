//go:build !cshared

package hostsession

// multihost_isolation_test.go — 注册表并发隔离（host-registry-daemon 5.2，HD
// 「多主机会话注册表」隔离判据）：两台后端一健康一持续失败，**真实会话**（真 WG +
// 回环上的真出口，同 TestServiceSessionRecoverLadder 的服务端形态）并发跑——
// 失败主机的恢复风暴（阶梯连续耗尽 → 整会话重建 → 限频）不得影响健康主机的
// 巡检/链路/恢复计数（按会话归属独立断言，D8）。
//
// 放在 hostsession 包的原因：fake-build 注入的假会话过不了 NewTransport 的类型
// 断言（recoverStaleSession 直接短路——阶梯根本不跑）；只有真会话才承载真实
// 阶梯/重建/recGate 路径，而三预算 var 是本包未导出、只有同包测试能缩到毫秒级
// 让风暴秒级跑完。注册表层面的并发/摘除隔离另见 internal/daemon 的用例（真
// Registry + 真回环出口）。

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/intercept"
	"github.com/zhaoyswd/homeway/pkg/proto"
	"github.com/zhaoyswd/homeway/pkg/servercore"
	"github.com/zhaoyswd/homeway/pkg/wgnet"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// isoFreeUDPPort 找一个空闲 UDP 端口并释放（返回后端口无人监听——「死端点」用）。
func isoFreeUDPPort(t *testing.T) uint16 {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

// isoStartExit 起一台回环上的真出口（服务端形态同 TestServiceSessionRecoverLadder），
// 返回（监听端口、设备表、后端公钥——token 的 PeerID 用它，握手指由此配对）。
func isoStartExit(t *testing.T, secret [32]byte) (uint16, *servercore.DeviceTable, [32]byte) {
	t.Helper()
	srvPort := isoFreeUDPPort(t)
	spriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	srvTun, srvNS, err := wgnet.CreateOpts([]netip.Addr{netip.MustParseAddr("100.64.254.1")}, 1280, wgnet.Opts{HandleLocal: false})
	if err != nil {
		t.Fatal(err)
	}
	sbind := &servercore.ServerBind{Build: "iso-test"}
	sdev := device.NewDevice(srvTun, sbind, device.NewLogger(device.LogLevelError, "iso"))
	t.Cleanup(func() { sdev.Close() })
	table := servercore.NewDeviceTable(servercore.NewIPCConfigurer(sdev), [][32]byte{secret},
		servercore.DeviceConfig{MaxDevices: 8, TTL: time.Minute})
	sbind.Table = table
	if err := sdev.IpcSet(fmt.Sprintf("private_key=%x\nlisten_port=%d\n", spriv[:], srvPort)); err != nil {
		t.Fatal(err)
	}
	if err := sdev.Up(); err != nil {
		t.Fatal(err)
	}
	inter, ierr := intercept.Attach(srvNS, intercept.Config{TunnelIP: netip.MustParseAddr("100.64.254.1")}, &intercept.Stats{})
	if ierr != nil {
		t.Fatal(ierr)
	}
	t.Cleanup(inter.Close)
	return srvPort, table, spriv.PublicKey()
}

// TestMultiHostSessionsIsolatedUnderRecoveryStorm HD 隔离判据：一健康 + 一持续失败。
func TestMultiHostSessionsIsolatedUnderRecoveryStorm(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		t.Skip("进程内全栈 WG 集成（同 TestServiceSessionRecoverLadder 的 CI 降级口径）：共享 runner 调度抖动下时序敏感，本地/真机跑")
	}
	// 阶梯预算缩到亚秒（本包 var，同包可写；结束恢复生产值）。
	oldPre, oldVerify, oldAct := recoverPreProbeTimeout, recoverVerifyTimeout, recoverActionTimeout
	recoverPreProbeTimeout, recoverVerifyTimeout, recoverActionTimeout = 200*time.Millisecond, 500*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() {
		recoverPreProbeTimeout, recoverVerifyTimeout, recoverActionTimeout = oldPre, oldVerify, oldAct
	})

	// 后端 A：真出口（健康）。
	secretA := [32]byte{21, 21, 21, 4}
	srvPort, table, backendPub := isoStartExit(t, secretA)
	tokA, err := proto.EncodeToken(proto.Token{
		PeerID:    backendPub,
		Secret:    secretA,
		Endpoints: []proto.Endpoint{{Addr: fmt.Sprintf("127.0.0.1:%d", srvPort)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// 后端 B：合法 token 指向死端点（持续失败——恢复风暴源）。
	deadPort := isoFreeUDPPort(t)
	bpriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	secretB := [32]byte{22, 22, 22, 5}
	tokB, err := proto.EncodeToken(proto.Token{
		PeerID:    bpriv.PublicKey(),
		Secret:    secretB,
		Endpoints: []proto.Endpoint{{Addr: fmt.Sprintf("127.0.0.1:%d", deadPort)}},
	})
	if err != nil {
		t.Fatal(err)
	}

	// 两会话 = Registry 每主机一条的形态：同 identityDir（master 共享、按后端公钥
	// 派生不同 WG 钥匙）、各自独立日志文件（按主机归属对拍恢复行）。
	dir := t.TempDir()
	mkCfg := func(tok, out string) Config {
		return Config{
			Token:            tok,
			IdentityDir:      filepath.Join(dir, "identity"), // 同一身份目录（D2：一份 master 按后端派生）
			EndpointCacheDir: filepath.Join(dir, "endpoints"),
			Out:              filepath.Join(dir, out),
		}
	}
	sA, err := NewSession(mkCfg(tokA, "host-a.log"), Options{StrictIdentity: true})
	if err != nil {
		t.Fatal(err)
	}
	sB, err := NewSession(mkCfg(tokB, "host-b.log"), Options{StrictIdentity: true})
	if err != nil {
		t.Fatal(err)
	}
	sA.Start()
	sB.Start()
	t.Cleanup(func() { sA.Stop(); sB.Stop() })

	// A 暖机就绪 + 真健康（ready 不保证健康——暖机软失败也到 ready，同
	// TestServiceSessionRecoverLadder 的①前置口径：用生产同款判据轮询到健康，
	// 并等传输层把采纳路径反映进 link）。
	waitHealthy := func(s *Session) {
		t.Helper()
		deadline := time.Now().Add(25 * time.Second)
		for time.Now().Before(deadline) {
			if sess := s.curSession(); sess != nil {
				pctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				perr := sess.PathProbe(pctx)
				cancel()
				snap := s.StatusSnapshot()
				if perr == nil && snap.Link != nil && snap.Link.Via == "direct" && snap.Link.Ep != "" {
					return
				}
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatalf("25s 内 A 未达健康+direct（当前 %+v）", sA.StatusSnapshot())
	}
	waitSnap := func(s *Session, want string) Snapshot {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			snap := s.StatusSnapshot()
			if snap.State == want {
				return snap
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("30s 内未到 %s（当前 %+v）", want, s.StatusSnapshot())
		return Snapshot{}
	}
	waitSnap(sA, svcStateReady)
	waitHealthy(sA)
	waitSnap(sB, svcStateReady) // 软失败形态（会话在、链路无）

	// ---- B 的恢复风暴：拨号失败驱动阶梯；连续耗尽 → 整会话重建 → 再耗尽被限频。----
	stormDial := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
		defer cancel()
		_, _ = sB.DialPort(ctx, 7724) // 失败属预期（死端点）；价值在内部恢复路径被驱动
	}
	stormDial() // 阶梯轮 1（走完仍失败）
	stormDial() // 阶梯轮 2 → 连续耗尽 → REBUILD 整会话重建（计数触发即归零）
	stormDial() // 新会话阶梯轮 3
	stormDial() // 阶梯轮 4 → 再耗尽 → 限频挡下（「被限频」行）

	// ---- 隔离判据（逐条，HD 场景「两主机会话并发互不干扰」） ----
	// ① A 仍是就绪会话、链路仍在（巡检/链路状态不受 B 风暴影响）。
	snapA2 := sA.StatusSnapshot()
	if snapA2.State != svcStateReady || snapA2.Link == nil || snapA2.Link.Via != "direct" {
		t.Fatalf("风暴后 A 应仍 ready+direct：%+v", snapA2)
	}
	// ② 恢复计数按会话归属：A 零耗尽、零重建；B 有重建时刻。
	if sA.ladderExhausted != 0 || !sA.rebuildAt.IsZero() {
		t.Fatalf("A 不应有恢复记账（exhausted=%d rebuildAt=%v）", sA.ladderExhausted, sA.rebuildAt)
	}
	if sB.rebuildAt.IsZero() {
		t.Fatal("B 应已触发整会话重建（rebuildAt 零值）")
	}
	// ③ 恢复闸按会话自持（无共享 gate）。
	if &sA.recGate == &sB.recGate {
		t.Fatal("两会话不应共享恢复闸")
	}
	// ④ 身份按后端派生：同 master、不同后端公钥 → 不同 WG 钥匙（devTag 是设备级
	// 共享——出口按 devTag 归并同一台设备，这是 D2 的派生模型，不比较 Dev）。
	snapB := sB.StatusSnapshot()
	if snapA2.Identity != nil && snapB.Identity != nil {
		if snapA2.Identity.Pub == snapB.Identity.Pub {
			t.Fatal("不同后端派生的 WG 公钥指纹不应相同")
		}
	}
	// ⑤ 恢复动作只发生在 B 的会话上：日志按主机归属对拍（A 的日志零恢复行）。
	logA, _ := os.ReadFile(filepath.Join(dir, "host-a.log"))
	logB, _ := os.ReadFile(filepath.Join(dir, "host-b.log"))
	for _, bad := range []string{"RECOVER", "REBUILD", "拨号失败"} {
		if strings.Contains(string(logA), bad) {
			t.Fatalf("A 的日志不应出现恢复动作 %q（串扰）", bad)
		}
	}
	for _, want := range []string{"拨号失败", "RECOVER 走完", "REBUILD 整会话重建（", "REBUILD 整会话重建被限频"} {
		if !strings.Contains(string(logB), want) {
			t.Fatalf("B 的日志缺风暴证据 %q", want)
		}
	}
	// ⑥ A 的后端真的收到过注册（A 的 WG 会话为活隧道的旁证）。
	if n := table.Len(); n < 1 {
		t.Fatalf("健康后端设备表应有 A 的记录（size=%d）", n)
	}
}
