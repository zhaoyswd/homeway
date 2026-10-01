package servercore

import (
	"errors"
	"fmt"
	"github.com/zhaoyswd/homeway/pkg/proto"
	"strings"
	"sync"
	"testing"
	"time"
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

func (f *fakeCfg) has(pub [32]byte) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.added[pub]
	return ok
}

var testSecret = [32]byte{9, 9, 9}

func regFor(pub [32]byte, dev proto.DevTag, ts time.Time) []byte {
	return proto.EncodeReg(testSecret, pub, dev, ts)
}

func pubN(n byte) [32]byte {
	var k [32]byte
	k[0] = n
	return k
}

func devN(n byte) proto.DevTag {
	var d proto.DevTag
	d[0], d[1] = n, 0xA5
	return d
}

// captureLog 收集表打的日志（断言判据行）。
func captureLog(tb *DeviceTable) *[]string {
	lines := &[]string{}
	tb.SetLogger(func(format string, args ...any) {
		*lines = append(*lines, fmt.Sprintf(format, args...))
	})
	return lines
}

func TestDeviceTableAddRefreshRotate(t *testing.T) {
	fc := newFakeCfg()
	tb := NewDeviceTable(fc, [][32]byte{testSecret}, DeviceConfig{MaxDevices: 4})
	lines := captureLog(tb)
	now := time.Now()

	res, err := tb.Register(regFor(pubN(1), devN(1), now), now)
	if err != nil || res.Action != ActionAdded {
		t.Fatalf("首个注册：res=%+v err=%v", res, err)
	}
	if tb.Len() != 1 {
		t.Fatalf("Len=%d", tb.Len())
	}
	if want := proto.DeriveTunnelIP(testSecret, pubN(1)); res.TunnelIP != want {
		t.Fatalf("隧道地址 = %v，want %v", res.TunnelIP, want)
	}
	waitPendingDrained(t, tb)
	if !fc.has(pubN(1)) {
		t.Fatal("device 侧应写入 peer")
	}

	// 同设备同公钥：只刷新，不新增
	res, err = tb.Register(regFor(pubN(1), devN(1), now.Add(time.Second)), now.Add(time.Second))
	if err != nil || res.Action != ActionRefreshed || tb.Len() != 1 {
		t.Fatalf("刷新：res=%+v err=%v len=%d", res, err, tb.Len())
	}

	// 同设备换公钥：轮换替换（表内仍一条，旧 peer 被移除）
	res, err = tb.Register(regFor(pubN(2), devN(1), now.Add(2*time.Second)), now.Add(2*time.Second))
	if err != nil || res.Action != ActionRotated || tb.Len() != 1 {
		t.Fatalf("轮换：res=%+v err=%v len=%d", res, err, tb.Len())
	}
	waitPendingDrained(t, tb)
	if fc.has(pubN(1)) {
		t.Fatal("轮换后旧公钥应已从 device 移除")
	}
	if !fc.has(pubN(2)) {
		t.Fatal("轮换后新公钥应已写入 device")
	}
	if want := proto.DeriveTunnelIP(testSecret, pubN(2)); res.TunnelIP != want {
		t.Fatalf("轮换后隧道地址 = %v，want %v", res.TunnelIP, want)
	}
	if ip, found := tb.TunnelIP(pubN(2)); !found || ip != res.TunnelIP {
		t.Fatalf("TunnelIP 查询 = %v/%v", ip, found)
	}
	if len(*lines) < 3 {
		t.Fatalf("每个动作都应有一行日志：%v", *lines)
	}
}

func TestDeviceTableCapEvictsOnlyStale(t *testing.T) {
	fc := newFakeCfg()
	tb := NewDeviceTable(fc, [][32]byte{testSecret}, DeviceConfig{MaxDevices: 2, Grace: time.Minute})
	lines := captureLog(tb)
	t0 := time.Now()

	if _, err := tb.Register(regFor(pubN(1), devN(1), t0), t0); err != nil {
		t.Fatal(err)
	}
	// dev2 比 dev1 晚 30s 注册：同为失联时「最旧 = dev1」是确定的。
	//（同刻注册的两台在 map 迭代序下淘汰谁随机——曾让本用例在全包跑时偶发红。）
	t1 := t0.Add(30 * time.Second)
	if _, err := tb.Register(regFor(pubN(2), devN(2), t1), t1); err != nil {
		t.Fatal(err)
	}
	// 2 分钟后两台都超过 grace：第三个设备应淘汰最旧的（dev1），不拒绝
	later := t0.Add(2 * time.Minute)
	res, err := tb.Register(regFor(pubN(3), devN(3), later), later)
	if err != nil || res.Action != ActionAdded {
		t.Fatalf("表满但有失联设备时应登记新设备：res=%+v err=%v", res, err)
	}
	if tb.Len() != 2 {
		t.Fatalf("Len=%d", tb.Len())
	}
	waitPendingDrained(t, tb)
	if fc.has(pubN(1)) {
		t.Fatal("最旧的失联设备应被淘汰")
	}
	if !fc.has(pubN(3)) {
		t.Fatal("新设备应已写入")
	}
	if len(fc.removed) != 1 || fc.removed[0] != pubN(1) {
		t.Fatalf("移除记录 = %v", fc.removed)
	}
	found := false
	for _, l := range *lines {
		if strings.Contains(l, "reason=stale") {
			found = true
		}
	}
	if !found {
		t.Fatalf("淘汰应打 reason=stale 日志：%v", *lines)
	}
}

func TestDeviceTableFullRejectsWhenAllActive(t *testing.T) {
	fc := newFakeCfg()
	tb := NewDeviceTable(fc, [][32]byte{testSecret}, DeviceConfig{MaxDevices: 2, Grace: time.Minute})
	lines := captureLog(tb)
	t0 := time.Now()
	if _, err := tb.Register(regFor(pubN(1), devN(1), t0), t0); err != nil {
		t.Fatal(err)
	}
	// dev2 比 dev1 晚 30s 注册：同为失联时「最旧 = dev1」是确定的。
	//（同刻注册的两台在 map 迭代序下淘汰谁随机——曾让本用例在全包跑时偶发红。）
	t1 := t0.Add(30 * time.Second)
	if _, err := tb.Register(regFor(pubN(2), devN(2), t1), t1); err != nil {
		t.Fatal(err)
	}
	// 全部在宽限期内：拒绝新设备，绝不淘汰在线设备
	soon := t0.Add(10 * time.Second)
	_, err := tb.Register(regFor(pubN(3), devN(3), soon), soon)
	if !errors.Is(err, ErrTableFull) {
		t.Fatalf("err = %v, want ErrTableFull", err)
	}
	if tb.Len() != 2 || len(fc.removed) != 0 || fc.has(pubN(3)) {
		t.Fatalf("在线设备不得被淘汰：len=%d removed=%v", tb.Len(), fc.removed)
	}
	found := false
	for _, l := range *lines {
		if strings.Contains(l, "reason=table-full") {
			found = true
		}
	}
	if !found {
		t.Fatalf("拒绝应打 reason=table-full 日志：%v", *lines)
	}
}

// 核心回归：两台设备共用同一 token；A 长连不动、B 反复重连（同 devTag、每代换公钥），
// A 必须始终在线（旧实现：B 第 8 次新身份注册时 A 被 LRU 淘汰）。
func TestTwoDevicesSameTokenNoEviction(t *testing.T) {
	fc := newFakeCfg()
	tb := NewDeviceTable(fc, [][32]byte{testSecret}, DeviceConfig{MaxDevices: 8, Grace: time.Minute})
	t0 := time.Now()
	devA, devB := devN(0xA), devN(0xB)
	pubA := pubN(0x11)
	if _, err := tb.Register(regFor(pubA, devA, t0), t0); err != nil {
		t.Fatal(err)
	}
	for i := byte(1); i <= 10; i++ {
		ts := t0.Add(time.Duration(i) * 10 * time.Second)
		if _, err := tb.Register(regFor(pubN(0x40+i), devB, ts), ts); err != nil {
			t.Fatalf("B 第 %d 次重连：%v", i, err)
		}
	}
	if tb.Len() != 2 {
		t.Fatalf("表内应只有两台设备：Len=%d", tb.Len())
	}
	if !fc.has(pubA) {
		t.Fatal("A 的长连记录被挤掉了（回归）")
	}
	if _, found := tb.TunnelIP(pubA); !found {
		t.Fatal("A 的隧道地址应仍在表内")
	}
}

func TestDeviceTableTTLGC(t *testing.T) {
	fc := newFakeCfg()
	tb := NewDeviceTable(fc, [][32]byte{testSecret}, DeviceConfig{MaxDevices: 8, TTL: time.Hour})
	t0 := time.Now()
	if _, err := tb.Register(regFor(pubN(1), devN(1), t0), t0); err != nil {
		t.Fatal(err)
	}
	if _, err := tb.Register(regFor(pubN(2), devN(2), t0.Add(30*time.Minute)), t0.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	// t0+90m：dev1 空闲 90m（>1h，过期），dev2 空闲 60m（刚好等于 TTL，不算过期）
	out := tb.GC(t0.Add(90 * time.Minute))
	if len(out) != 1 || out[0].Action != ActionExpired || out[0].DevTag != devN(1) {
		t.Fatalf("GC 结果 = %+v", out)
	}
	if tb.Len() != 1 || fc.has(pubN(1)) {
		t.Fatalf("GC 后 len=%d，dev1 的 peer 应已移除", tb.Len())
	}
	// 幂等：同一时刻再扫一次无变化
	if again := tb.GC(t0.Add(90 * time.Minute)); len(again) != 0 {
		t.Fatalf("重复 GC = %+v", again)
	}
}

// 同一公钥挂在两个 devTag 上（克隆/迁移应用数据的签名）：允许但必须打告警。
func TestDevicePubConflictWarns(t *testing.T) {
	fc := newFakeCfg()
	tb := NewDeviceTable(fc, [][32]byte{testSecret}, DeviceConfig{MaxDevices: 8})
	lines := captureLog(tb)
	t0 := time.Now()
	pub := pubN(0x77)
	if _, err := tb.Register(regFor(pub, devN(1), t0), t0); err != nil {
		t.Fatal(err)
	}
	if _, err := tb.Register(regFor(pub, devN(2), t0.Add(time.Second)), t0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if tb.Len() != 2 {
		t.Fatalf("两条记录都应保留：Len=%d", tb.Len())
	}
	found := false
	for _, l := range *lines {
		if strings.Contains(l, "疑似同一身份") {
			found = true
		}
	}
	if !found {
		t.Fatalf("应打克隆告警：%v", *lines)
	}
}

func TestDeviceUnknownSecretRejected(t *testing.T) {
	fc := newFakeCfg()
	tb := NewDeviceTable(fc, [][32]byte{testSecret}, DeviceConfig{})
	var wrong [32]byte
	wrong[0] = 1
	reg := proto.EncodeReg(wrong, pubN(5), devN(5), time.Now())
	if _, err := tb.Register(reg, time.Now()); !errors.Is(err, ErrNoToken) {
		t.Fatalf("err = %v, want ErrNoToken", err)
	}
}

// 构造期 secrets 全集验证（secrets 单轨，host-registry-daemon D7：热重读分支已删——
// `Secrets()` 仅启动期调用、`IssueToken` 先于建表入集，签发永远先于建表；重签发的
// token 随出口重启进构造期集合）。全集里的每个 secret 都能注册，集合外的仍拒。
func TestDeviceTableVerifiesFullSecretSetAtConstruction(t *testing.T) {
	fc := newFakeCfg()
	var fresh [32]byte
	fresh[0] = 7
	// 构造期给全集（如出口重启后 tokens.jsonl 的全部 secret）。
	tb := NewDeviceTable(fc, [][32]byte{testSecret, fresh}, DeviceConfig{})
	now := time.Now()

	// 旧 secret：通过。
	if _, err := tb.Register(regFor(pubN(6), devN(6), now), now); err != nil {
		t.Fatalf("构造期集合内的旧 secret 应通过：%v", err)
	}
	// 新签发的 secret（已在构造期集合里）：同样通过。
	if _, err := tb.Register(proto.EncodeReg(fresh, pubN(7), devN(7), now), now); err != nil {
		t.Fatalf("构造期集合内的新 secret 应通过：%v", err)
	}
	// 集合外的 secret：拒绝（无热重读路径——未命中即 ErrNoToken）。
	var unknown [32]byte
	unknown[0] = 9
	if _, err := tb.Register(proto.EncodeReg(unknown, pubN(8), devN(8), now), now); !errors.Is(err, ErrNoToken) {
		t.Fatalf("集合外 secret 应 ErrNoToken：%v", err)
	}
}

// 并发注册（-race）：多设备并发注册不丢设备、不产生重复条目。
func TestDeviceTableConcurrentRegister(t *testing.T) {
	fc := newFakeCfg()
	tb := NewDeviceTable(fc, [][32]byte{testSecret}, DeviceConfig{MaxDevices: 64})
	now := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(n byte) {
			defer wg.Done()
			_, _ = tb.Register(regFor(pubN(n), devN(n), now), now)
		}(byte(i + 1))
	}
	wg.Wait()
	if tb.Len() != 16 {
		t.Fatalf("Len=%d，want 16", tb.Len())
	}
}

// #16：设备表必须同时跟踪两个派生 /32（隧道地址 + 应用面地址）——allowedips 是
// 全局前缀表，任一 /32 撞车都会错路由。占用判定（ipTakenLocked）必须并集生效，
// 冲突时 assignTunIPLocked 退池并打告警。
func TestTunIPOccupancyTracked(t *testing.T) {
	tb := NewDeviceTable(newFakeCfg(), [][32]byte{testSecret}, DeviceConfig{})
	now := time.Now()
	if _, err := tb.Register(regFor(pubN(1), devN(1), now), now); err != nil {
		t.Fatal(err)
	}
	tb.mu.Lock()
	e1 := tb.entries[devN(1)]
	tb.mu.Unlock()
	if !e1.tunIP.IsValid() {
		t.Fatal("dentry 没记 tunIP（#16：应用面地址不进占用集合）")
	}
	if e1.tunIP == e1.ip {
		t.Fatalf("同设备两地址相等：%v（proto 相等守卫失效）", e1.ip)
	}
	// 并集判定：两个地址都算占用。
	if !tb.ipTakenLocked(e1.ip) || !tb.ipTakenLocked(e1.tunIP) {
		t.Fatal("ipTakenLocked 不认双地址集合（#16 回归）")
	}
	// 第二台设备：AddPeer 落下去的 TunIP 不得与 dev1 的任何地址相同。
	if _, err := tb.Register(regFor(pubN(2), devN(2), now), now); err != nil {
		t.Fatal(err)
	}
	waitPendingDrained(t, tb)
	pc := tb.cfg.(*fakeCfg).added[pubN(2)]
	if pc.TunIP == e1.ip || pc.TunIP == e1.tunIP {
		t.Fatalf("dev2 的 TunIP %v 与 dev1 的地址撞车未被处置", pc.TunIP)
	}
}

// TestIPConflictRejectsRegistration（FIX-66）：派生地址撞车 ⇒ **显式拒绝注册**
// （ErrTunnelIPConflict），不再退池造一条「客户端永远不会用」的注定不通记录。
// 构造：先算出目标公钥的派生地址，塞一条占用它的条目（模拟撞车），再注册。
func TestIPConflictRejectsRegistration(t *testing.T) {
	tb := NewDeviceTable(newFakeCfg(), [][32]byte{testSecret}, DeviceConfig{})
	now := time.Now()
	pub3 := pubN(3)
	derived := proto.DeriveTunnelIP(testSecret, pub3) // 与 assignIPLocked 同函数
	// 占住该地址（伪装成另一台设备）。
	tb.mu.Lock()
	tb.entries[devN(99)] = &dentry{dev: devN(99), pub: pubN(99), ip: derived, tunIP: proto.DeriveTunIP(testSecret, pubN(99)), lastReg: now, createdAt: now}
	tb.mu.Unlock()

	if _, err := tb.Register(regFor(pub3, devN(3), now), now); !errors.Is(err, ErrTunnelIPConflict) {
		t.Fatalf("撞车应 ErrTunnelIPConflict（显式拒绝），got %v", err)
	}
	tb.mu.Lock()
	_, inTable := tb.entries[devN(3)]
	tb.mu.Unlock()
	if inTable {
		t.Fatal("被拒的注册不得入表（原实现会退池造一条注定不通的记录）")
	}
	// 撞车解除后可正常注册（拒绝不是闩锁）。
	tb.mu.Lock()
	delete(tb.entries, devN(99))
	tb.mu.Unlock()
	if _, err := tb.Register(regFor(pub3, devN(3), now), now); err != nil {
		t.Fatalf("撞车解除后应可注册：%v", err)
	}
}

// 设备配置操作的顺序契约（review 复审 a2）：提交顺序 = 执行顺序。
//
// 为什么必须锁死：轮换路径是"先 RemovePeer(旧) 再 AddPeer(新)"、淘汰+重登记也是
// "先摘旧再写新"。旧实现（每次操作起一个 goroutine 抢一把 mutex）在**超时后**
// 可能让后提交的操作抢到锁先执行，留下"设备表里已登记、device 里却没有该 peer"
// 的静默分歧（直到 TTL 才自愈）。现在单消费者 FIFO 队列从结构上排除抢跑。
func TestApplyDeviceOpKeepsSubmissionOrder(t *testing.T) {
	oldTimeout := devOpTimeout
	devOpTimeout = 40 * time.Millisecond
	defer func() { devOpTimeout = oldTimeout }()

	tb := NewDeviceTable(newFakeCfg(), [][32]byte{testSecret}, DeviceConfig{MaxDevices: 2})
	gate := make(chan struct{})
	var mu sync.Mutex
	var order []string
	rec := func(s string) {
		mu.Lock()
		order = append(order, s)
		mu.Unlock()
	}

	// 第一个操作卡住 → applyDeviceOp 超时返回，但它仍占着队列（尚未执行完）
	tb.applyDeviceOp(func() { <-gate; rec("first") })
	// 第二个操作在第一个还卡着时提交：它必须先于"第一个完成"之后执行
	tb.applyDeviceOp(func() { rec("second") })

	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	before := append([]string(nil), order...)
	mu.Unlock()
	if len(before) != 0 {
		t.Fatalf("卡住的操作未完成时后一个操作就跑了（顺序被破坏）：%v", before)
	}
	close(gate)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := append([]string(nil), order...)
		mu.Unlock()
		if len(got) == 2 {
			if got[0] != "first" || got[1] != "second" {
				t.Fatalf("执行顺序错乱：%v（want [first second]）", got)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	got := append([]string(nil), order...)
	mu.Unlock()
	t.Fatalf("操作未全部执行：%v", got)
}

// TestIPConflictSamePubCloneAllowed（FIX-66 的边界）：**同公钥**不同 devTag（克隆/
// 迁移应用数据）沿用同一派生地址、照常注册（这是既有场景，不算「注定不通」）；
// 只有**不同公钥**撞同一地址才拒（TestIPConflictRejectsRegistration）。
func TestIPConflictSamePubCloneAllowed(t *testing.T) {
	tb := NewDeviceTable(newFakeCfg(), [][32]byte{testSecret}, DeviceConfig{MaxDevices: 8})
	now := time.Now()
	pub := pubN(0x55)
	r1, err := tb.Register(regFor(pub, devN(1), now), now)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := tb.Register(regFor(pub, devN(2), now.Add(time.Second)), now.Add(time.Second))
	if err != nil {
		t.Fatalf("同公钥克隆应照常注册（沿用同址）：%v", err)
	}
	if r2.TunnelIP != r1.TunnelIP {
		t.Fatalf("克隆应沿用同一派生地址：%v vs %v", r2.TunnelIP, r1.TunnelIP)
	}
}

// waitPendingDrained 等设备写入队列排空（FIX-67 起注册路径异步落地——「应答已发、
// device 写入在飞」是正常形态，测试要观察 device 状态先等它）。
func waitPendingDrained(t *testing.T, tb *DeviceTable) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if tb.PendingOps() == 0 {
			// 队列空 ≠ 已执行完最后一条：pending 在执行体内才 -1 ⇒ 归零即已执行完。
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("设备写入队列未在 2s 内排空（pending=%d）", tb.PendingOps())
}

// TestRegisterReturnsBeforeDeviceWrite（FIX-67）：注册路径**不等** device 写入完成
// ——接收 goroutine（WG 收包）此前同步等 IpcSet 完成，devOpTimeout 的界意味着最坏
// 2s 的全局停包。判据：device 写入被阻塞时 Register 仍立刻返回（且在 flying 期
// PendingOps() > 0），放行后写入落地。
func TestRegisterReturnsBeforeDeviceWrite(t *testing.T) {
	fc := newBlockingCfg()
	tb := NewDeviceTable(fc, [][32]byte{testSecret}, DeviceConfig{MaxDevices: 8})
	now := time.Now()
	fc.block()
	start := time.Now()
	res, err := tb.Register(regFor(pubN(1), devN(1), now), now)
	took := time.Since(start)
	if err != nil {
		t.Fatalf("Register：%v", err)
	}
	if took > 500*time.Millisecond {
		t.Fatalf("注册不该等 device 写入（耗时 %v）", took)
	}
	if tb.PendingOps() == 0 {
		t.Fatal("device 写入在飞时 PendingOps 应 > 0（状态面）")
	}
	_ = res
	fc.release()
	waitPendingDrained(t, tb)
	if !fc.has(pubN(1)) {
		t.Fatal("放行后 device 写入应落地")
	}
}

// blockingCfg：可阻塞的配置面（模拟 device 锁竞争/收工窗口）：block 之后 AddPeer
// 一直挂到 release。
type blockingCfg struct {
	*fakeCfg
	mu   sync.Mutex
	hold chan struct{}
}

func newBlockingCfg() *blockingCfg { return &blockingCfg{fakeCfg: newFakeCfg()} }

func (b *blockingCfg) block() {
	b.mu.Lock()
	b.hold = make(chan struct{})
	b.mu.Unlock()
}

func (b *blockingCfg) release() {
	b.mu.Lock()
	if b.hold != nil {
		close(b.hold)
		b.hold = nil
	}
	b.mu.Unlock()
}

func (b *blockingCfg) AddPeer(pc PeerConfig) error {
	b.mu.Lock()
	h := b.hold
	b.mu.Unlock()
	if h != nil {
		<-h
	}
	return b.fakeCfg.AddPeer(pc)
}
