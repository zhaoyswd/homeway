package servercore

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
)

type fakeCfg struct {
	mu      sync.Mutex
	added   map[[32]byte]PeerConfig
	order   [][32]byte
	removed [][32]byte
}

func newFakeCfg() *fakeCfg { return &fakeCfg{added: map[[32]byte]PeerConfig{}} }

func (f *fakeCfg) AddPeer(pc PeerConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.added[pc.Pubkey]; !ok {
		f.order = append(f.order, pc.Pubkey)
	}
	f.added[pc.Pubkey] = pc
	return nil
}

func (f *fakeCfg) RemovePeer(pub [32]byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.added[pub]; ok {
		delete(f.added, pub)
		f.removed = append(f.removed, pub)
	}
	return nil
}

var testSecret = [32]byte{9, 9, 9}

func regFor(pub [32]byte, ts time.Time) []byte { return proto.EncodeReg(testSecret, pub, ts) }

func pubN(n byte) [32]byte {
	var k [32]byte
	k[0] = n
	return k
}

func TestPeerTableRegisterAndIdempotent(t *testing.T) {
	fc := newFakeCfg()
	tb := NewPeerTable(fc, [][32]byte{testSecret}, 4, time.Hour)
	now := time.Now()

	if _, err := tb.Register(regFor(pubN(1), now), now); err != nil {
		t.Fatal(err)
	}
	// 重放同一 reg：无错、表不膨胀（重放无害）
	if _, err := tb.Register(regFor(pubN(1), now), now); err != nil {
		t.Fatalf("重放应无害：%v", err)
	}
	if tb.Len() != 1 || len(fc.order) != 1 {
		t.Fatalf("表膨胀：len=%d added=%d", tb.Len(), len(fc.order))
	}
	ip, found := tb.TunnelIP(pubN(1))
	if !found || !ip.IsValid() {
		t.Fatalf("TunnelIP found=%v ip=%v", found, ip)
	}
	// 隧道地址 = 两端从临时公钥派生（tasks 3.7）：POST 的 allowed_ip 必须是它，
	// 否则客户端（用派生地址做流侧源）的包会被 allowed_ip 检查丢掉。
	if want := proto.DeriveTunnelIP(testSecret, pubN(1)); ip != want {
		t.Fatalf("TunnelIP 应为派生地址：got=%v want=%v", ip, want)
	}
	if fc.added[pubN(1)].TunnelIP != ip {
		t.Fatalf("AddPeer 的 allowed_ip 与表内地址不一致：%v vs %v", fc.added[pubN(1)].TunnelIP, ip)
	}
	// PSK 正确派生
	if fc.added[pubN(1)].PSK != proto.DerivePSK(testSecret) {
		t.Fatal("PSK 派生不匹配")
	}
}

func TestPeerTableUnknownSecretRejected(t *testing.T) {
	fc := newFakeCfg()
	tb := NewPeerTable(fc, [][32]byte{testSecret}, 4, time.Hour)
	var wrong [32]byte
	wrong[0] = 1
	reg := proto.EncodeReg(wrong, pubN(5), time.Now())
	if _, err := tb.Register(reg, time.Now()); err == nil {
		t.Fatal("未知 secret 的 reg 必须被拒")
	}
}

// 热加载：出口运行中新 `issue` 出来的 token（tokens.jsonl 追加）不改重启即可注册。
// 背景（2026-09-19 真机）：issue → 粘贴到手机 → REG 被拒「无匹配 token」，因为服务只在启动时读过台账。
func TestPeerTableReloadsSecretsOnMiss(t *testing.T) {
	fc := newFakeCfg()
	tb := NewPeerTable(fc, [][32]byte{testSecret}, 4, time.Hour)
	now := time.Now()

	var fresh [32]byte
	fresh[0] = 7
	reg := proto.EncodeReg(fresh, pubN(6), now)
	if _, err := tb.Register(reg, now); err == nil {
		t.Fatal("未经 reload 的新 secret 不应通过")
	}

	reloads := 0
	tb.SetSecretsReloader(func() ([][32]byte, error) {
		reloads++
		return [][32]byte{testSecret, fresh}, nil
	})
	if _, err := tb.Register(reg, now); err != nil {
		t.Fatalf("reload 后应通过：%v", err)
	}
	if reloads != 1 {
		t.Fatalf("reload 次数 = %d，want 1", reloads)
	}
	// 命中已加载的 secret 时不再触发 reload（热路径零开销）
	if _, err := tb.Register(regFor(pubN(7), now), now); err != nil {
		t.Fatal(err)
	}
	if reloads != 1 {
		t.Fatalf("命中路径不该 reload：%d", reloads)
	}
}

func TestPeerTableCapLRU(t *testing.T) {
	fc := newFakeCfg()
	tb := NewPeerTable(fc, [][32]byte{testSecret}, 2, time.Hour)
	now := time.Now()

	tb.Register(regFor(pubN(1), now), now)
	time.Sleep(time.Millisecond)
	tb.Register(regFor(pubN(2), now), now)
	time.Sleep(time.Millisecond)
	// 刷新 pubN(1)（成为最新）→ pubN(2) 变 LRU
	tb.Register(regFor(pubN(1), now), now)
	time.Sleep(time.Millisecond)
	// 第三个进来应淘汰 pubN(2)
	if _, err := tb.Register(regFor(pubN(3), now), now); err != nil {
		t.Fatal(err)
	}
	if len(fc.removed) != 1 || fc.removed[0] != pubN(2) {
		t.Fatalf("LRU 淘汰错误：%v", fc.removed)
	}
	if tb.Len() != 2 {
		t.Fatalf("len=%d", tb.Len())
	}
	if _, found := tb.TunnelIP(pubN(2)); found {
		t.Fatal("被淘汰的 peer 不应还能查到")
	}
}

func TestPeerTableTTLGC(t *testing.T) {
	fc := newFakeCfg()
	tb := NewPeerTable(fc, [][32]byte{testSecret}, 8, time.Hour)
	t0 := time.Now()
	tb.Register(regFor(pubN(1), t0), t0)
	tb.Register(regFor(pubN(2), t0), t0)

	// t0+2h：两个都过期
	if n := tb.GC(t0.Add(2 * time.Hour)); n != 2 {
		t.Fatalf("GC 清理数=%d", n)
	}
	if len(fc.removed) != 2 || tb.Len() != 0 {
		t.Fatalf("removed=%v len=%d", fc.removed, tb.Len())
	}
}

// netip 零值哨兵回归（lazyPeers 前科）：分配/回收全走显式标志，
// 「释放后的地址被复用」若被零值哨兵吞掉会静默 no-op。
func TestIPPoolZeroValueSentinelRegression(t *testing.T) {
	p := newIPPool(netip.MustParseAddr(tunnelBase))
	ip1 := p.Acquire()
	ip2 := p.Acquire()
	if !ip1.IsValid() || !ip2.IsValid() || ip1 == ip2 {
		t.Fatalf("分配非法：%v %v", ip1, ip2)
	}
	if !ip1.Is4() || ip1.String() != "100.64.0.1" {
		t.Fatalf("首个分配应为基址+1（网段地址 .0 不分配给主机）：%v", ip1)
	}
	p.Release(ip1)
	// 回收的地址应优先复用（而非继续顺序分配）
	if got := p.Acquire(); got != ip1 {
		t.Fatalf("回收地址未被复用：got=%v want=%v", got, ip1)
	}
	// 幂等释放不应污染池
	p.Release(ip1)
	p.Release(ip1)
	if got := p.Acquire(); got != ip1 {
		t.Fatalf("重复释放后池状态被污染：got=%v", got)
	}
}
