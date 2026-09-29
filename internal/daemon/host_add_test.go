package daemon

// host_add_test.go — host.add 服务端验证路径四路判据（host-cli 1.2，design D1/D3）：
// 直连/仅中继/全不可达/force 跳过——**真探测核**（生产路径 pkg/probe.Reach，不经
// 注入缝）+ 回环参照点应答器 + 真实 UDS/帧/JSON 全链（§3.8 Go 客户端）。零副作用
// 断言：探测为纯旁路，不碰注册表已有会话状态（HM「守护进程持有多台主机会话时
// 添加」场景——真 WG 回环出口 + 健康会话 A，添加 B 期间 A 无扰动）。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/internal/control"
	"github.com/zhaoyswd/homeway/pkg/intercept"
	"github.com/zhaoyswd/homeway/pkg/probe"
	"github.com/zhaoyswd/homeway/pkg/proto"
	"github.com/zhaoyswd/homeway/pkg/servercore"
	"github.com/zhaoyswd/homeway/pkg/wgnet"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// addFakeProber 回环参照点应答器（就绪即回，带构建标记；hits 计收到的探测请求）。
type addFakeProber struct {
	pc   *net.UDPConn
	hits atomic.Int64
}

func addStartProber(t *testing.T, build string) *addFakeProber {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	fp := &addFakeProber{pc: pc}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			n, src, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			fp.hits.Add(1)
			if resp := probe.Respond(buf[:n], src.AddrPort(), build, 0); resp != nil {
				_, _ = pc.WriteToUDP(resp, src)
			}
		}
	}()
	t.Cleanup(func() { _ = pc.Close(); <-done })
	return fp
}

func addDeadPort(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().String()
}

// TestHostAddFourPaths 直连/仅中继/全不可达/force 四路（真探测 + 真 UDS + 帧路径）。
func TestHostAddFourPaths(t *testing.T) {
	_, sock := startDaemonForTest(t)
	c := dialDaemon(t, sock)
	ctx := context.Background()

	direct := addStartProber(t, "exit-d")
	relay := addStartProber(t, "exit-r")
	dead := addDeadPort(t)

	// ① 直连可达：入表 + tier=direct + bestEp=实测直连端点 + rtt 有值。
	raw, err := c.Request(ctx, control.OpHostAdd, control.HostAddArgs{Name: "直连后端", Token: addToken(t, [32]byte{1}, proto.Endpoint{Addr: direct.pc.LocalAddr().String()})})
	if err != nil {
		t.Fatalf("直连 host.add：%v", err)
	}
	var r1 control.HostAddResult
	if err := json.Unmarshal(raw, &r1); err != nil {
		t.Fatal(err)
	}
	if r1.Reach == nil || r1.Reach.Tier != control.ReachTierDirect || r1.Reach.BestEp != direct.pc.LocalAddr().String() || r1.Reach.RttMs < 0 {
		t.Fatalf("直连结论不符：%+v", r1.Reach)
	}
	if len(r1.Reach.Tested) != 1 || r1.Reach.Tested[0].Relay {
		t.Fatalf("tested 应恰一条直连：%+v", r1.Reach.Tested)
	}

	// ② 仅中继：直连死 + 中继活 → 入表 + tier=relay + 提示面数据（relay 档场景
	// 证据——live 拓扑若两台均直连则以此为准，host-cli 1.7 同款）。
	raw, err = c.Request(ctx, control.OpHostAdd, control.HostAddArgs{Name: "中继后端", Token: addToken(t, [32]byte{2},
		proto.Endpoint{Addr: dead},
		proto.Endpoint{Addr: relay.pc.LocalAddr().String(), Relay: true},
	)})
	if err != nil {
		t.Fatalf("仅中继 host.add：%v", err)
	}
	var r2 control.HostAddResult
	if err := json.Unmarshal(raw, &r2); err != nil {
		t.Fatal(err)
	}
	if r2.Reach == nil || r2.Reach.Tier != control.ReachTierRelay || r2.Reach.BestEp != relay.pc.LocalAddr().String() {
		t.Fatalf("仅中继结论不符：%+v", r2.Reach)
	}

	// ③ 全不可达（未带 force）：host_unreachable、不入表、连接保持。
	tok3 := addToken(t, [32]byte{3},
		proto.Endpoint{Addr: dead},
		proto.Endpoint{Addr: "203.0.113.50:41641", Relay: true},
	)
	if _, err := c.Request(ctx, control.OpHostAdd, control.HostAddArgs{Name: "失联", Token: tok3}); !errors.Is(err, control.CodeError(control.CodeHostUnreachable)) {
		t.Fatalf("全不可达应 host_unreachable：%v", err)
	}
	if _, err := c.Request(ctx, control.OpHostList, nil); err != nil {
		t.Fatalf("host_unreachable 后连接应保持：%v", err)
	}
	rawList, err := c.Request(ctx, control.OpHostList, nil)
	if err != nil {
		t.Fatal(err)
	}
	var list control.HostListResult
	if err := json.Unmarshal(rawList, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Hosts) != 2 {
		t.Fatalf("全不可达不得入表：%+v", list.Hosts)
	}

	// ④ force 跳过：同 token 带 force → 入表成功、tier=skipped、tested 空。
	raw, err = c.Request(ctx, control.OpHostAdd, control.HostAddArgs{Name: "强制", Token: tok3, Force: true})
	if err != nil {
		t.Fatalf("force host.add：%v", err)
	}
	var r4 control.HostAddResult
	if err := json.Unmarshal(raw, &r4); err != nil {
		t.Fatal(err)
	}
	if r4.Reach == nil || r4.Reach.Tier != control.ReachTierSkipped || r4.Reach.BestEp != "" || len(r4.Reach.Tested) != 0 {
		t.Fatalf("force 结论应为 skipped（端点未实测）：%+v", r4.Reach)
	}

	// 清理（会话对回环探测应答器的暖机属异步预期，Remove 走完即可）。
	for _, id := range []string{r1.ID, r2.ID, r4.ID} {
		if _, err := c.Request(ctx, control.OpHostRemove, control.HostRemoveArgs{Host: id}); err != nil {
			t.Fatalf("清理 %s：%v", id, err)
		}
	}
}

// TestHostAddBadTokenNoProbe token 非法就地报错：不发起网络探测（HM「token 格式
// 错误不进入探测」——应答器零命中 + bad_token 不被 force 绕过）。
func TestHostAddBadTokenNoProbe(t *testing.T) {
	_, sock := startDaemonForTest(t)
	c := dialDaemon(t, sock)
	ctx := context.Background()
	fp := addStartProber(t, "exit-n")

	if _, err := c.Request(ctx, control.OpHostAdd, control.HostAddArgs{Token: "hmw1-not-a-token"}); !errors.Is(err, control.CodeError(control.CodeBadToken)) {
		t.Fatalf("坏 token 应 bad_token：%v", err)
	}
	if _, err := c.Request(ctx, control.OpHostAdd, control.HostAddArgs{Token: "hmw1-not-a-token", Force: true}); !errors.Is(err, control.CodeError(control.CodeBadToken)) {
		t.Fatalf("force 不得绕过 bad_token：%v", err)
	}
	if got := fp.hits.Load(); got != 0 {
		t.Fatalf("坏 token 触发了网络探测（命中 %d 次）", got)
	}
}

// TestHostAddProbeZeroSideEffect HM「守护进程持有多台主机会话时添加」：真 WG 回环
// 出口 + 健康会话 A（ready+direct）→ 添加 B（真探测）→ A 会话对象/链路/统计无
// 归因于验证的扰动。
func TestHostAddProbeZeroSideEffect(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		t.Skip("进程内全栈 WG 集成（回环真出口）：共享 runner 调度抖动下时序敏感，本地/真机跑（同 registry_isolation 口径）")
	}
	// 健康后端 A：回环真出口（registry_isolation_test 同款装配）。
	secret := [32]byte{41, 41, 41, 3}
	srvPort := isoDaemonFreeUDPPort(t)
	spriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	srvTun, srvNS, err := wgnet.CreateOpts([]netip.Addr{netip.MustParseAddr("100.64.254.1")}, 1280, wgnet.Opts{HandleLocal: false})
	if err != nil {
		t.Fatal(err)
	}
	sbind := &servercore.ServerBind{Build: "hm-add-iso"}
	sdev := device.NewDevice(srvTun, sbind, device.NewLogger(device.LogLevelError, "hmadd"))
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

	tokA, err := proto.EncodeToken(proto.Token{
		PeerID:    spriv.PublicKey(),
		Secret:    secret,
		Endpoints: []proto.Endpoint{{Addr: fmt.Sprintf("127.0.0.1:%d", srvPort)}},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, sock := startDaemonForTest(t)
	c := dialDaemon(t, sock)
	ctx := context.Background()

	// A 先入表并就绪（A 走 force：出口的探测应答器 = WG 端口本身会回参照点应答，
	// 但此处不依赖——force 保证入表不依赖探测结论，暖机握手才判健康）。
	raw, err := c.Request(ctx, control.OpHostAdd, control.HostAddArgs{Name: "健康A", Token: tokA, Force: true})
	if err != nil {
		t.Fatalf("A 入表：%v", err)
	}
	var recA control.HostAddResult
	if err := json.Unmarshal(raw, &recA); err != nil {
		t.Fatal(err)
	}
	hsA := itWaitHostReady(t, c, recA.ID)
	snapBefore := hsA

	// 添加 B（真探测：应答器活端点）——探测期间/之后 A 无扰动。
	bEp := addStartProber(t, "exit-b")
	raw, err = c.Request(ctx, control.OpHostAdd, control.HostAddArgs{Name: "后端B", Token: addToken(t, [32]byte{5}, proto.Endpoint{Addr: bEp.pc.LocalAddr().String()})})
	if err != nil {
		t.Fatalf("B host.add：%v", err)
	}
	var recB control.HostAddResult
	if err := json.Unmarshal(raw, &recB); err != nil {
		t.Fatal(err)
	}
	if recB.Reach == nil || recB.Reach.Tier != control.ReachTierDirect {
		t.Fatalf("B 结论应为 direct：%+v", recB.Reach)
	}

	// A 的会话对象与链路态不变（同一登记面快照路径核对）。
	var snapAfter control.HostState
	deadline := time.Now().Add(3 * time.Second)
	found := false
	for time.Now().Before(deadline) {
		rawS, err := c.Request(ctx, control.OpSnapshotGet, nil)
		if err == nil {
			var snap control.SnapshotResult
			if json.Unmarshal(rawS, &snap) == nil {
				for _, h := range snap.Hosts {
					if h.ID == recA.ID {
						snapAfter, found = h, true
					}
				}
			}
		}
		if found {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !found {
		t.Fatal("快照中找不到 A")
	}
	if snapAfter.State != "ready" || snapAfter.Link == nil || snapAfter.Link.Via != "direct" || snapAfter.Link.Ep != snapBefore.Link.Ep {
		t.Fatalf("B 的验证探测扰动了 A：before=%+v after=%+v", snapBefore, snapAfter)
	}
}

func addToken(t *testing.T, peerID [32]byte, eps ...proto.Endpoint) string {
	t.Helper()
	s, err := proto.EncodeToken(proto.Token{PeerID: peerID, Secret: [32]byte{7, 7, 7}, Endpoints: eps})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
