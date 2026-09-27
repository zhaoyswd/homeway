//go:build cshared

// app_service_recover_test.go — 服务腿恢复阶梯的**进程内集成**（openspec recovery-ladder
// 评审二轮·四-2）：起一个真 serviceSession（真 WG 会话 + 回环上的真出口），验证
// recoverStaleSession 真的接上了统一阶梯——
//
//	① 会话健康：探测先行，零档位动作（不打 R1/R2/R3 行）；
//	② 出口设备记录被回收（= 出口重启形态）：R2 直入跑齐「补注册+丢会话+换源」，一个
//	   验证探测内恢复，设备表回到 1 条（同设备刷新）；
//	③ 出口死透：R1→R3 全档 -1（判据行「走完 R1→R3 仍未恢复」），不重建、不 panic。
//
// 阶梯预算缩到毫秒级让用例秒级跑完（生产值见 recover.go）；与隧道域互不等待是结构性
// 保证（两个独立 gate 对象，隧道域闸挂在 tunRun 上），单飞语义另由 TestRecoverMergeSingleFlight 钉住。
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/zhaoyswd/homeway/clientcore/internal/wtransport"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/intercept"
	"github.com/zhaoyswd/homeway/pkg/proto"
	"github.com/zhaoyswd/homeway/pkg/servercore"
	"github.com/zhaoyswd/homeway/pkg/wgnet"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// svcTestTunnelIP 出口侧隧道地址（服务腿测试自用；与 wgcore 测试同段不同值）。
const svcTestTunnelIP = "100.64.254.1"

func svcFreeUDPPort(t *testing.T) uint16 {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

// onceClose 让收工路径幂等（③ 里会提前关服务端，t.Cleanup 再来一次不能炸）。
func onceClose(close func()) func() {
	var once sync.Once
	return func() { once.Do(close) }
}

// svcTestBudgets 一轮阶梯的预算三元组（pre=起查探测 / verify=档位动作后验证 / action=本地动作）。
type svcTestBudgets struct {
	pre, verify, action time.Duration
}

func TestServiceSessionRecoverLadder(t *testing.T) {
	// CI 降级跳过（2026-09-28，core-homeway-merge 环节 2）：本用例是进程内全栈 WG 集成
	//（真实 UDP loopback 握手 + 隧道内探测），GitHub runner（2 核 VM）资源不足使握手/探测
	// 时序全面拉伸、三轮 dispatch 实测系统性红且失败点漂移（153/153/176 行）；本机与
	// docker golang:1.24 同命令全绿、cgroup 0.4 CPU 压测复现同族失败 ⇒ 判定环境不适配
	// 而非产品回归。恢复阶梯的档位决策由 wgcore recover_test 等单元面在 CI 继续守。
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		t.Skip("进程内全栈 WG 集成：CI runner 资源不足（时序系统性拉伸），本地/真机跑")
	}
	// 阶梯预算（包内 var；测试串行无并发改写——巡检 60s 一拍、本用例全程秒级），
	// 结束恢复生产值。按阶段设（exec-r4 后 CI 慢机整改：旧的全局 800ms/1.5s/0.5s
	// 在 GitHub 共享 runner 上不够——慢机上暖机后的一发隧道内往返被调度拖过 800ms，
	// ①「零档位动作」即假失败；且②的验证探测要容纳 WG 首发握手丢失后的 5s 重发
	// ——REG 重注册与握手 initiation 在出口侧跨 goroutine 竞争，慢机上首发被丢不罕见）：
	//	①健康路径用生产值（3s/10s/2s）——测试预算不该比生产更苛刻，语义才诚实；
	//	②③的死路径（起查探测必超时、③验证必超时）只等超时本身，维持毫秒级省墙钟；
	//	②的验证探测与①同宽（恢复真发生时远快于预算，预算只是兜底慢机）。
	oldPre, oldVerify, oldAct := recoverPreProbeTimeout, recoverVerifyTimeout, recoverActionTimeout
	setBudgets := func(b svcTestBudgets) {
		recoverPreProbeTimeout, recoverVerifyTimeout, recoverActionTimeout = b.pre, b.verify, b.action
	}
	t.Cleanup(func() {
		recoverPreProbeTimeout, recoverVerifyTimeout, recoverActionTimeout = oldPre, oldVerify, oldAct
	})

	// ---------- 服务端：生产同一份 ServerBind + DeviceTable（同 wgcore recover_test 形态） ----------
	secret := [32]byte{11, 11, 11, 3}
	srvPort := svcFreeUDPPort(t)
	spriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	srvTun, srvNS, err := wgnet.CreateOpts([]netip.Addr{netip.MustParseAddr(svcTestTunnelIP)}, 1280, wgnet.Opts{HandleLocal: false})
	if err != nil {
		t.Fatal(err)
	}
	sbind := &servercore.ServerBind{Build: "svc-recover-test"}
	sdev := device.NewDevice(srvTun, sbind, device.NewLogger(device.LogLevelError, "srv"))
	closeSrv := onceClose(func() { sdev.Close() })
	t.Cleanup(closeSrv)
	sbind.Table = servercore.NewDeviceTable(servercore.NewIPCConfigurer(sdev), [][32]byte{secret},
		servercore.DeviceConfig{MaxDevices: 8, TTL: time.Minute})
	if err := sdev.IpcSet(fmt.Sprintf("private_key=%x\nlisten_port=%d\n", spriv[:], srvPort)); err != nil {
		t.Fatal(err)
	}
	if err := sdev.Up(); err != nil {
		t.Fatal(err)
	}
	inter, ierr := intercept.Attach(srvNS, intercept.Config{TunnelIP: netip.MustParseAddr(svcTestTunnelIP)}, &intercept.Stats{})
	if ierr != nil {
		t.Fatal(ierr)
	}
	t.Cleanup(onceClose(inter.Close))

	// ---------- 客户端：真 serviceSession（token 驱动的生产启动路径） ----------
	tokStr, err := proto.EncodeToken(proto.Token{
		PeerID:    spriv.PublicKey(),
		Secret:    secret,
		Endpoints: []proto.Endpoint{{Addr: fmt.Sprintf("127.0.0.1:%d", srvPort)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "svc.log")
	cfgJSON, err := json.Marshal(tunConfig{
		Token:            tokStr,
		IdentityDir:      filepath.Join(dir, "id"),
		EndpointCacheDir: filepath.Join(dir, "ep"),
		Out:              logPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rc := serviceStartFromJSON(string(cfgJSON)); rc != 0 {
		t.Fatalf("serviceStartFromJSON rc=%d", rc)
	}
	t.Cleanup(func() { serviceStopInternal() })

	// 等 ready（暖机探测通过即 ready）。
	deadline := time.Now().Add(15 * time.Second)
	for {
		st, _, _ := serviceCur.snapshotState()
		if st == svcStateReady {
			break
		}
		if st == svcStateFailed || time.Now().After(deadline) {
			t.Fatalf("服务会话未就绪：state=%s", st)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if sbind.Table.Len() != 1 {
		t.Fatalf("就绪后设备表应 1 条：%d", sbind.Table.Len())
	}

	currentSess := func() exitSession {
		serviceCur.mu.Lock()
		defer serviceCur.mu.Unlock()
		return serviceCur.sess
	}
	logHas := func(needle string) bool {
		b, rerr := os.ReadFile(logPath)
		if rerr != nil {
			return false
		}
		return strings.Contains(string(b), needle)
	}

	// ①的前置：会话必须**真健康**再起查。ready 不保证这一点——暖机超时按软失败
	// 也会走到 ready（见 run()），此时会话可能还没握上手，①的「零档位动作」就成了
	// 对着病会话的空头断言（慢机上暖机软失败不罕见）。用生产同款判据（拨 1 号端口
	// 收 RST）轮询到健康为止；这发探测无副作用（健康会话上一个纯往返）。
	healthDeadline := time.Now().Add(15 * time.Second)
	for {
		pctx, pcancel := context.WithTimeout(context.Background(), 3*time.Second)
		perr := currentSess().PathProbe(pctx)
		pcancel()
		if perr == nil {
			break
		}
		if time.Now().After(healthDeadline) {
			t.Fatalf("①前置失败：会话 15s 内未达健康（暖机软失败后也未恢复；末次探测 %v）", perr)
		}
		time.Sleep(200 * time.Millisecond)
	}

	// ① 健康：探测先行，零档位动作。
	setBudgets(svcTestBudgets{pre: 3 * time.Second, verify: 10 * time.Second, action: 2 * time.Second})
	serviceCur.recoverStaleSession(currentSess(), "集成①")
	if !logHas("RECOVER 已恢复（R2 换源 起查，原因=集成①，零档位动作") {
		t.Fatal("①健康路径应零档位动作（探测先行命中）")
	}

	// ② 出口设备记录被回收（= 出口重启形态）：R2 直入跑齐动作并恢复，设备表同设备刷新。
	if out := sbind.Table.GC(time.Now().Add(2 * time.Minute)); len(out) != 1 {
		t.Fatalf("GC 应回收 1 条：%+v", out)
	}
	// ② 起查必超时（设备记录已回收、包发出去无应答）——起查预算短等超时本身即可；
	// 验证探测给生产宽度：RefreshReg 的 REG 与握手 initiation 在出口侧跨 goroutine
	// 竞争，首发被丢要等 WG 的 5s 重发（recover.go 生产注释同款考量）。
	setBudgets(svcTestBudgets{pre: 800 * time.Millisecond, verify: 10 * time.Second, action: 2 * time.Second})
	serviceCur.recoverStaleSession(currentSess(), "集成②")
	if !logHas("RECOVER 恢复于 R2 换源（原因=集成②") {
		t.Fatal("②设备回收后应由 R2 档恢复（补注册+丢会话+换源）")
	}
	if sbind.Table.Len() != 1 {
		t.Fatalf("②恢复后设备表应回到 1 条：%d", sbind.Table.Len())
	}

	// ③ 出口死透：R1→R3 全档失败（-1），判据行留痕，不重建不 panic。死路径上
	// 探测只会超时（收不到任何应答），预算短等超时本身即可，省墙钟。
	closeSrv()
	setBudgets(svcTestBudgets{pre: 800 * time.Millisecond, verify: 1500 * time.Millisecond, action: 2 * time.Second})
	serviceCur.recoverStaleSession(currentSess(), "集成③")
	if !logHas("RECOVER 走完 R1→R3 仍未恢复（起跑=R2 换源，原因=集成③") {
		t.Fatal("③出口死透应走完全档并报 -1")
	}
}

// TestRebuildSessionSwapsCoolsDownAndFailsClosed 整会话重建（2026-09-22 冻结唤醒死亡
// 的兜底）：阶梯连续耗尽后 rebuildSession 必须 ①Close 旧会话 ②换入新会话（桥不动、
// dial 走 curSession 动态取）；③冷却窗口内不重复拆建；④新会话建立失败按 failed 收工
// （s.sess 清空、状态机可再次 Start，不闩锁）。
func TestRebuildSessionSwapsCoolsDownAndFailsClosed(t *testing.T) {
	restore := withFakeServiceBuild(func(cfg tunConfig, logf Logf) (exitSession, *wtransport.EndpointCache, error) {
		return newFakeExitSession(), nil, nil
	})
	defer restore()

	s := &serviceSession{state: svcStateReady, since: time.Now(), logf: Discard, cfg: tunConfig{}}
	first := newFakeExitSession()
	s.sess = first

	s.rebuildSession("测试：阶梯耗尽")
	if first.closeAt.IsZero() {
		t.Fatal("旧会话未被 Close（重建必须全弃握手状态/socket）")
	}
	second := s.sess
	if second == nil || second == exitSession(first) {
		t.Fatalf("未换入新会话（%v）", second)
	}
	select {
	case <-first.closed:
	default:
		t.Fatal("旧会话 Close 未生效")
	}

	// 限频：冷却窗口内的第二次耗尽不拆建（保住 second 继续观察）
	s.rebuildSession("测试：再次耗尽（应限频）")
	if s.sess != second {
		t.Fatal("冷却窗口内不应重建")
	}

	// 重建失败 → failed 收工（不闩锁）
	s.mu.Lock()
	s.rebuildAt = time.Time{} // 解除限频
	s.mu.Unlock()
	restore()
	fail := withFakeServiceBuild(func(cfg tunConfig, logf Logf) (exitSession, *wtransport.EndpointCache, error) {
		return nil, nil, errFakeNotImpl
	})
	defer fail()
	s.rebuildSession("测试：重建失败")
	if st, _, _ := s.snapshotState(); st != svcStateFailed {
		t.Fatalf("重建失败应按 failed 收工，当前 %s", st)
	}
	if s.sess != nil {
		t.Fatal("failed 收工后 s.sess 应清空")
	}
}

// TestNoteLadderResultCountsAndRebuilds 阶梯耗尽计数的语义（2026-09-23：拨号触发与
// 巡检触发同权计数后）：①一次耗尽+一次健康 → 归零，不重建；②连续两次耗尽（无论
// 来自哪个入口——计数点在 run 回调、按轮记）→ 触发整会话重建；③健康拍也归零。
func TestNoteLadderResultCountsAndRebuilds(t *testing.T) {
	restore := withFakeServiceBuild(func(cfg tunConfig, logf Logf) (exitSession, *wtransport.EndpointCache, error) {
		return newFakeExitSession(), nil, nil
	})
	defer restore()

	s := &serviceSession{state: svcStateReady, since: time.Now(), logf: Discard, cfg: tunConfig{}}
	first := newFakeExitSession()
	s.sess = first

	// 一次耗尽 + 一次健康：不重建（每笔记数后照生产时序查一次阈值）
	s.noteLadderResult(-1)
	s.maybeRebuildIfExhausted()
	s.markLadderHealthy()
	s.noteLadderResult(-1)
	s.maybeRebuildIfExhausted()
	if s.sess != exitSession(first) {
		t.Fatal("1 次耗尽（中途归零后）不应触发重建")
	}

	// 再连续一次耗尽 → 重建换新
	s.noteLadderResult(-1)
	s.maybeRebuildIfExhausted()
	if s.sess == nil || s.sess == exitSession(first) {
		t.Fatal("连续 2 次耗尽应触发整会话重建")
	}
	if first.closeAt.IsZero() {
		t.Fatal("重建必须 Close 旧会话")
	}

	// 阶梯恢复（rc≥0）同样归零：下一轮耗尽后不立即重建
	// （评审⑤修正：second 必须在 noteLadderResult(-1) **之前**捕获——之后捕获的
	// 断言恒真，什么都没钉住；变异测试证实旧写法在"每次耗尽都重建"的实现下照样过）
	s.noteLadderResult(1)
	second := s.sess
	if second == nil || second == exitSession(first) {
		t.Fatal("前置校验失败：重建后的会话应在位")
	}
	s.noteLadderResult(-1)
	s.maybeRebuildIfExhausted() // 1 < 2：不重建
	if s.sess != second {
		t.Fatal("恢复归零后的单次耗尽不应再次重建")
	}
	// 重建触发即归零（评审③-2）：再补一记耗尽凑到阈值 → 重建，重建后单发耗尽不再重建
	s.mu.Lock()
	s.rebuildAt = time.Time{} // 解除限频（只测计数语义，不测冷却）
	s.mu.Unlock()
	s.noteLadderResult(-1) // 2 → 触发重建并归零
	s.maybeRebuildIfExhausted()
	third := s.sess
	if third == nil || third == second {
		t.Fatal("第二次重建应换入新会话")
	}
	s.noteLadderResult(-1) // 1 < 2：不重建
	s.maybeRebuildIfExhausted()
	if s.sess != third {
		t.Fatal("重建触发后计数应归零，单发耗尽不应再重建")
	}
}

// TestRecoverGateRunsOncePerRound 闸的单飞契约（noteLadderResult「每轮恰好记一次」
// 依赖它，评审④）：并发多入口 merge 到同一轮时，run 只执行一次、所有等待者共享同一
// 个 rc——不会对同一轮阶梯重复计数。
func TestRecoverGateRunsOncePerRound(t *testing.T) {
	var g recoverGate
	var runs atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan int, 1)
	go func() {
		firstDone <- g.merge(recoverR2, "first", func(from recoverLevel) int {
			runs.Add(1)
			close(started)
			<-release
			return -1
		})
	}()
	<-started
	lateDone := make(chan int, 1)
	go func() {
		lateDone <- g.merge(recoverR2, "late", func(from recoverLevel) int {
			runs.Add(1)
			return 99 // 不该被执行：等待者不另起 run
		})
	}()
	time.Sleep(150 * time.Millisecond) // 让 late 确实挂在等待上
	close(release)
	if rc := <-firstDone; rc != -1 {
		t.Fatalf("先到者 rc=%d，期望 -1", rc)
	}
	if rc := <-lateDone; rc != -1 {
		t.Fatalf("等待者应共享同轮 rc=-1，实际 %d", rc)
	}
	if n := runs.Load(); n != 1 {
		t.Fatalf("run 应恰好执行一次，实际 %d 次（同轮会重复计数）", n)
	}
}
