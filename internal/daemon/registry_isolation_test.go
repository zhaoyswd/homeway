package daemon

// registry_isolation_test.go — 5.2 注册表层隔离判据（HD「多主机会话注册表」）：
// 真 Registry + 回环上的真出口（健康后端）+ 死端点（持续失败后端）并发——健康
// 主机在注册表内就绪（真 WG 握手 + 链路 direct）、失败主机共存不干扰；摘除失败
// 主机不影响健康主机会话对象（每记录自持 teardown）。恢复风暴的按会话归属断言
// （阶梯/重建/限频计数互不串扰）在 hostsession 包 multihost_isolation_test.go
// （真会话 + 可缩预算——本包够不到那三个未导出 var）。

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/intercept"
	"github.com/zhaoyswd/homeway/pkg/proto"
	"github.com/zhaoyswd/homeway/pkg/servercore"
	"github.com/zhaoyswd/homeway/pkg/wgnet"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func isoDaemonFreeUDPPort(t *testing.T) uint16 {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

// TestRegistryIsolationHealthyAndFailing HD 场景「两主机会话并发互不干扰」的注册表面。
func TestRegistryIsolationHealthyAndFailing(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		t.Skip("进程内全栈 WG 集成（回环真出口）：共享 runner 调度抖动下时序敏感，本地/真机跑（同 hostsession multihost_isolation 口径）")
	}
	// 健康后端：回环上的真出口。
	secret := [32]byte{31, 31, 31, 6}
	srvPort := isoDaemonFreeUDPPort(t)
	spriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	srvTun, srvNS, err := wgnet.CreateOpts([]netip.Addr{netip.MustParseAddr("100.64.254.1")}, 1280, wgnet.Opts{HandleLocal: false})
	if err != nil {
		t.Fatal(err)
	}
	sbind := &servercore.ServerBind{Build: "reg-iso-test"}
	sdev := device.NewDevice(srvTun, sbind, device.NewLogger(device.LogLevelError, "regiso"))
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
	// 持续失败后端：合法 token 指向死端点。
	deadPort := isoDaemonFreeUDPPort(t)
	fpriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	secretB := [32]byte{32, 32, 32, 7}
	tokB, err := proto.EncodeToken(proto.Token{
		PeerID:    fpriv.PublicKey(),
		Secret:    secretB,
		Endpoints: []proto.Endpoint{{Addr: fmt.Sprintf("127.0.0.1:%d", deadPort)}},
	})
	if err != nil {
		t.Fatal(err)
	}

	dir := shortTempDirDaemon(t)
	reg, err := OpenRegistry(dir, RegistryOptions{StrictIdentity: true, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reg.Close)

	recA, err := reg.Add("健康后端", tokA)
	if err != nil {
		t.Fatal(err)
	}
	recB, err := reg.Add("失联后端", tokB)
	if err != nil {
		t.Fatal(err)
	}
	peerA := mustPeerID(t, recA.ID)
	peerB := mustPeerID(t, recB.ID)
	if peerA == peerB {
		t.Fatal("两后端不应同键")
	}

	// 健康主机：注册表内就绪 + 真 WG 握手（后端设备表见记录）+ 链路 direct。
	// （ready 不保证健康——暖机软失败也到 ready；用链路面与后端设备表共同判。）
	sessA := reg.Session(peerA)
	if sessA == nil {
		t.Fatal("A 会话未建")
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		snap := sessA.StatusSnapshot()
		// 等待条件必须并入 ready：链路采纳与状态机到 ready 之间有窗口
		//（exec-r1 整改发现：-race 时序下循环在 starting 期即 break，终断言
		// 误报——既有批 3 用例缺陷，非本批代码回归）。
		if snap.State == "ready" && snap.Link != nil && snap.Link.Via == "direct" && snap.Link.Ep != "" && table.Len() >= 1 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	snapA := sessA.StatusSnapshot()
	if snapA.State != "ready" || snapA.Link == nil || snapA.Link.Via != "direct" {
		t.Fatalf("健康主机应 ready+direct：%+v", snapA)
	}
	if table.Len() < 1 {
		t.Fatal("健康后端设备表应有 A 的记录（WG 会话未活）")
	}

	// 失败主机共存：会话在（暖机对死端点软失败/在途），链路无——不影响 A。
	if reg.Session(peerB) == nil {
		t.Fatal("B 会话未建")
	}
	if got := reg.Session(peerA); got != sessA {
		t.Fatalf("B 共存期间 A 会话对象不应被换（%p ≠ %p）", got, sessA)
	}

	// 摘除失败主机：A 的会话对象与状态不动（每记录自持 teardown）。
	if err := reg.Remove(peerB); err != nil {
		t.Fatal(err)
	}
	if got := reg.Session(peerA); got != sessA {
		t.Fatal("摘除 B 后 A 会话对象不应变化")
	}
	if snap := reg.Session(peerA).StatusSnapshot(); snap.State != "ready" || snap.Link == nil {
		t.Fatalf("摘除 B 后 A 应仍 ready+link：%+v", snap)
	}
	if reg.Session(peerB) != nil {
		t.Fatal("B 摘除后不应再有会话")
	}
}

// mustPeerID hosts 表 id（hex）→ [32]byte。
func mustPeerID(t *testing.T, id string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(id)
	if err != nil || len(b) != 32 {
		t.Fatalf("id 非法：%q（%v）", id, err)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}
