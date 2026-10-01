package wgcore

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/internal/wtransport"
	"github.com/zhaoyswd/homeway/pkg/intercept"
	"github.com/zhaoyswd/homeway/pkg/proto"
	"github.com/zhaoyswd/homeway/pkg/servercore"
	"github.com/zhaoyswd/homeway/pkg/wgnet"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// 出口重启 / 本设备记录被回收后的**快速恢复**（openspec device-identity-persist）：
// 设备记录被服务端回收 ⇒ 隧道必然不通 ⇒ 手机侧 `RefreshReg + forceRehandshake`
// ⇒ 下一发探测就重新登记并全新握手，恢复是秒级（而不是等客户端自己的 rekey 计时，最长 ~2 分钟）。
//
// 这条路径由核的巡检在「探测失败当拍」调用（tunmode.go），是出口重启这类
// 「本地无感、对端已丢失登记」故障的唯一恢复入口。
func TestRecoverAfterDeviceRecordReaped(t *testing.T) {
	secret := [32]byte{7, 7, 7, 7, 1}
	srvPort := freeUDPPort(t)
	spriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	// ---------- 后端：生产同一份 ServerBind + DeviceTable（短 TTL 便于模拟回收） ----------
	srvTun, srvNS, err := wgnet.CreateOpts([]netip.Addr{netip.MustParseAddr(srvTunnelIP)}, 1280, wgnet.Opts{HandleLocal: false})
	if err != nil {
		t.Fatal(err)
	}
	sbind := &servercore.ServerBind{Build: "wgcore-recover-test"}
	sdev := device.NewDevice(srvTun, sbind, device.NewLogger(device.LogLevelError, "srv"))
	t.Cleanup(func() { sdev.Close() })
	sbind.Table = servercore.NewDeviceTable(servercore.NewIPCConfigurer(sdev), [][32]byte{secret},
		servercore.DeviceConfig{MaxDevices: 8, TTL: time.Minute})
	if err := sdev.IpcSet(fmt.Sprintf("private_key=%x\nlisten_port=%d\n", spriv[:], srvPort)); err != nil {
		t.Fatal(err)
	}
	if err := sdev.Up(); err != nil {
		t.Fatal(err)
	}
	// 过境拦截层（l3-exit-intercept 形态）：DialTCPPort = 拨隧道 IP（豁免转投本机同端口）。
	inter, ierr := intercept.Attach(srvNS, intercept.Config{TunnelIP: netip.MustParseAddr(srvTunnelIP)}, &intercept.Stats{})
	if ierr != nil {
		t.Fatal(ierr)
	}
	t.Cleanup(inter.Close)

	// 出口主机上的一个回环 TCP 回声服务（目标）
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		for {
			c, aerr := echo.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	echoPort := uint16(echo.Addr().(*net.TCPAddr).Port)

	// ---------- 客户端：wgcore + Transport ----------
	id, err := wtransport.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	appTun, _, err := wgnet.Create([]netip.Addr{proto.DeriveTunIP(secret, id.PublicKey())}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	cand := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), srvPort)
	core, err := start(Config{
		TUN: appTun, PeerID: spriv.PublicKey(), Secret: secret, Identity: id,
		Candidates: []wtransport.Candidate{{Addr: cand}}, ServerTunnelIP: netip.MustParseAddr(srvTunnelIP),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(core.Close)
	tr, err := NewTransport(TransportConfig{
		Core:             core,
		StaticCandidates: []wtransport.Candidate{{Addr: cand}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tr.Close() })

	dial := func(budget time.Duration) error {
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		defer cancel()
		conn, derr := tr.DialTCPPort(ctx, echoPort)
		if derr != nil {
			return derr
		}
		_ = conn.Close()
		return nil
	}

	// ① 跑通一条流（顺带完成首轮注册：设备表 1 条）
	if err := dial(20 * time.Second); err != nil {
		t.Fatalf("基线拨号失败：%v", err)
	}
	if sbind.Table.Len() != 1 {
		t.Fatalf("首轮注册后设备表应 1 条：%d", sbind.Table.Len())
	}
	if _, ok := sbind.Table.TunnelIP(id.PublicKey()); !ok {
		t.Fatal("设备表里应有本设备的隧道地址")
	}

	// ② 模拟「出口重启 / 记录被回收」：TTL 回收把本设备删掉（连 device 侧 peer 一起）
	if out := sbind.Table.GC(time.Now().Add(2 * time.Minute)); len(out) != 1 {
		t.Fatalf("GC 应回收 1 条：%+v", out)
	}
	if sbind.Table.Len() != 0 {
		t.Fatalf("回收后设备表应为空：%d", sbind.Table.Len())
	}

	// ③ 此时隧道必然不通（短预算，避免测试等太久）
	if err := dial(2 * time.Second); err == nil {
		t.Fatal("记录被回收后不应还能拨通（本地会话还在，但对端已丢失）")
	}

	// ④ 恢复：补注册（裸 UDP，不依赖会话）+ 强制丢弃本地会话重新握手
	if !tr.RefreshReg() {
		t.Fatal("RefreshReg 应已发出（已采纳路径存在）")
	}
	tr.Rearm()
	if err := tr.ResetPeerSession(); err != nil {
		t.Fatalf("丢弃本地会话失败：%v", err)
	}
	if err := dial(20 * time.Second); err != nil {
		t.Fatalf("补注册 + 重新握手后仍拨不通：%v", err)
	}
	if sbind.Table.Len() != 1 {
		t.Fatalf("恢复后设备表应重新是 1 条：%d", sbind.Table.Len())
	}
	if _, ok := sbind.Table.TunnelIP(id.PublicKey()); !ok {
		t.Fatal("恢复后设备表应能按公钥查到同一设备（同 devTag 刷新/重登记）")
	}

	// ⑤ Rebind（服务会话「挂起唤醒」的陈旧恢复会先换本地 socket，再补注册 + 重新握手）：
	// 换 socket 后同一套恢复序列仍能拨通，且设备表仍是一条（同设备刷新、不新增）。
	if err := tr.Rebind(); err != nil {
		t.Fatalf("Rebind 失败：%v", err)
	}
	tr.RefreshReg()
	tr.Rearm()
	if err := tr.ResetPeerSession(); err != nil {
		t.Fatalf("丢弃本地会话失败：%v", err)
	}
	if err := dial(20 * time.Second); err != nil {
		t.Fatalf("Rebind + 补注册 + 重新握手后仍拨不通：%v", err)
	}
	if sbind.Table.Len() != 1 {
		t.Fatalf("Rebind 后设备表应仍是一条：%d", sbind.Table.Len())
	}

	// ⑥ 保采纳档（openspec recovery-ladder：R1/R2 的动作原语）：仅丢会话，采纳路径不动。
	addrBefore, relayBefore, okBefore := core.Bind().Adopted()
	if !okBefore || relayBefore || addrBefore != cand {
		t.Fatalf("前提失败：此时应有指向服务端的直连采纳（%v relay=%v valid=%v）", addrBefore, relayBefore, okBefore)
	}
	if err := tr.ResetPeerSession(); err != nil {
		t.Fatalf("ResetPeerSession 失败：%v", err)
	}
	addrAfter, _, okAfter := core.Bind().Adopted()
	if !okAfter || addrAfter != addrBefore {
		t.Fatalf("ResetPeerSession 不应清采纳：前=%v 后=%v（valid=%v）", addrBefore, addrAfter, okAfter)
	}
	// 丢会话后仍能拨通（下一发出站包全新握手）—— R1 的完整行为。
	if err := dial(20 * time.Second); err != nil {
		t.Fatalf("仅丢会话（保采纳）后仍拨不通：%v", err)
	}

	// ⑦ 清采纳档（Rearm = R3 的动作原语）：采纳被清，赛跑重启后重新采纳同一直连地址。
	// 观察式断言（慢机整改）：⑥ 的拨号刚关连接，FIN/RST 尾包可能恰好落在 Rearm 之后——
	// 收包路径按设计会立刻重新采纳活路径（bind.go 收包点置 valid=true，产品行为正确），
	// 慢机上 Rearm 与断言之间的窗口被调度拉宽后这个竞争肉眼可见。轮询窗口内捕捉到
	// 一次 valid=false 即证明 Rearm 确实清了采纳（尾包落地后下一轮必能观察到）。
	rearmed := false
	rearmDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(rearmDeadline) {
		tr.Rearm()
		if _, _, ok := core.Bind().Adopted(); !ok {
			rearmed = true
			break
		}
		time.Sleep(100 * time.Millisecond) // 等在途尾包落地后再试一轮
	}
	if !rearmed {
		t.Fatal("Rearm 应清采纳（5s 内未观察到 valid=false——每轮 Rearm 后立即被在途包重新采纳）")
	}
	if err := dial(20 * time.Second); err != nil {
		t.Fatalf("Rearm 后重赛跑应重新建立会话：%v", err)
	}
	addrRe, _, okRe := core.Bind().Adopted()
	if !okRe || addrRe != cand {
		t.Fatalf("重赛跑后应重新采纳同一直连候选：%v（valid=%v）", addrRe, okRe)
	}
}
