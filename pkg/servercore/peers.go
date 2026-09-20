package servercore

import (
	"context"
	"encoding/hex"
	"errors"
	"math/rand"
	"net/netip"
	"sync"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
)

// 设备表（2026-09-20 起，取代按 WG 公钥为键的动态 peer 表）。
//
// 为什么要换代：客户端身份从前是「每隧道世代一把临时密钥」，而旧表以公钥为键、按「上次注册时间」
// 做 LRU —— 于是每次重连都占一个新名额，表满后淘汰的永远是「注册最老」的那条，而它恰好可能是
// 一台长连、仍在线的设备（老 ≠ 死）。实测：A 长连 + B 重连 8 次 ⇒ A 被 RemovePeer，黑洞 2–4 分钟。
//
// 现在的语义（与 openspec/changes/device-identity-persist 的 spec 一一对应）：
//   - 键 = 注册报文里的设备标签 devTag（设备本地生成、跨连接稳定，见 pkg/proto/reg.go）；
//   - 同设备重复注册只刷新 lastReg；同 devTag 换公钥 = 身份轮换 ⇒ 原子替换 device 侧 peer 配置；
//   - 表满只淘汰**超过活跃宽限期（grace）未刷新**的设备中最旧的一条；全部活跃则拒绝新设备
//     （ErrTableFull，绝不淘汰在线设备）；
//   - TTL 周期回收长期不活跃设备（RunGC）；
//   - 登记/刷新/轮换/淘汰/拒绝/回收各打一行日志（dev/pub 短指纹 + 隧道地址 + n/cap + 原因）。
//
// 隧道地址仍由 (secret, pubkey) 两端各自派生（proto.DeriveTunnelIP）：身份稳定 ⇒ 地址稳定；
// 身份轮换时地址随新公钥变化，由替换路径处理。
type PeerConfig struct {
	Pubkey   [32]byte
	PSK      [32]byte
	TunnelIP netip.Addr // 100.64.0.0/16 内 /32
}

// Configurer 把表项落到 WG device（生产实现包 IpcSet；测试用 fake）。
type Configurer interface {
	AddPeer(pc PeerConfig) error
	RemovePeer(pubkey [32]byte) error
}

// Action 一次注册/回收对设备表造成的变化（测试断言与日志口径）。
type Action string

const (
	ActionAdded     Action = "add"
	ActionRefreshed Action = "refresh"
	ActionRotated   Action = "rotate"
	ActionExpired   Action = "expire"
)

// Result 一次登记/回收的结果快照。
type Result struct {
	DevTag   proto.DevTag
	Pubkey   [32]byte
	TunnelIP netip.Addr
	Action   Action
	// 轮换时填充（旧公钥/旧隧道地址），日志用。
	OldPubkey [32]byte
	OldIP     netip.Addr
	// Idle = 距上一次活跃（刷新/轮换/回收时填充）。
	Idle time.Duration
}

var (
	// ErrNoToken reg 报文没有任何已知 token secret 能验通。
	ErrNoToken = errors.New("peers: reg 验证失败（无匹配 token）")
	// ErrTableFull 表满且所有设备都在活跃宽限期内刷新过——拒绝新设备，绝不淘汰在线设备。
	ErrTableFull = errors.New("peers: 设备表已满且没有超过活跃宽限期的失联设备")
)

// DeviceConfig 设备表参数（零值走默认）。
type DeviceConfig struct {
	MaxDevices int           // <=0 = 32
	TTL        time.Duration // 0 = 7 天；<0 = 关闭 TTL 回收
	Grace      time.Duration // <=0 = 10 分钟（表满淘汰门槛）
}

const (
	defaultMaxDevices = 32
	defaultTTL        = 7 * 24 * time.Hour
	defaultGrace      = 10 * time.Minute
)

type dentry struct {
	dev       proto.DevTag
	pub       [32]byte
	psk       [32]byte
	ip        netip.Addr
	lastReg   time.Time
	createdAt time.Time
}

// DeviceTable 以设备标签为键的动态设备表（wg-native-stack tasks 3.2 的换代）。
type DeviceTable struct {
	mu      sync.Mutex
	cfg     Configurer
	secrets [][32]byte
	// reload 可选：reg 验证失败时重新读一次 token 台账（serve 重签 token 后免重启生效）。
	reload func() ([][32]byte, error)
	logf   func(format string, args ...any)

	max   int
	ttl   time.Duration
	grace time.Duration

	entries map[proto.DevTag]*dentry
	pool    *ipPool
}

// tunnelBase：冲突兜底地址池基址（/16，逐 /32 分配）。正常路径不用池，见 assignIPLocked。
const tunnelBase = "100.64.0.0"

// NewDeviceTable 建表（cfg 零值走默认：32 台 / 7 天 / 10 分钟宽限）。
func NewDeviceTable(cfg Configurer, secrets [][32]byte, opt DeviceConfig) *DeviceTable {
	if opt.MaxDevices <= 0 {
		opt.MaxDevices = defaultMaxDevices
	}
	if opt.TTL == 0 {
		opt.TTL = defaultTTL
	}
	if opt.Grace <= 0 {
		opt.Grace = defaultGrace
	}
	return &DeviceTable{
		cfg:     cfg,
		secrets: secrets,
		logf:    logf,
		max:     opt.MaxDevices,
		ttl:     opt.TTL,
		grace:   opt.Grace,
		entries: make(map[proto.DevTag]*dentry, opt.MaxDevices),
		pool:    newIPPool(netip.MustParseAddr(tunnelBase)),
	}
}

// SetLogger 注入正式日志（homewayd 装配）；不注入则用包内兜底。
func (t *DeviceTable) SetLogger(fn func(format string, args ...any)) {
	if fn == nil {
		return
	}
	t.mu.Lock()
	t.logf = fn
	t.mu.Unlock()
}

// SetSecretsReloader 注入「重读 token 台账」的回调（传 nil = 关闭热加载）。
func (t *DeviceTable) SetSecretsReloader(fn func() ([][32]byte, error)) {
	t.mu.Lock()
	t.reload = fn
	t.mu.Unlock()
}

func (t *DeviceTable) currentSecrets() [][32]byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.secrets
}

// verify 逐一试 token secret，返回 (公钥, 设备标签, 命中的 secret)。
func (t *DeviceTable) verify(reg []byte, now time.Time) (pubkey [32]byte, devTag proto.DevTag, secret [32]byte, err error) {
	try := func(secs [][32]byte) bool {
		for _, sec := range secs {
			if pk, dt, verr := proto.VerifyReg(sec, reg, now, 0); verr == nil {
				pubkey, devTag, secret = pk, dt, sec
				return true
			}
		}
		return false
	}
	if try(t.currentSecrets()) {
		return pubkey, devTag, secret, nil
	}
	t.mu.Lock()
	reload := t.reload
	t.mu.Unlock()
	if reload != nil {
		if secs, rerr := reload(); rerr == nil && len(secs) > 0 {
			t.mu.Lock()
			t.secrets = secs
			t.mu.Unlock()
			if try(secs) {
				return pubkey, devTag, secret, nil
			}
		}
	}
	return pubkey, devTag, secret, ErrNoToken
}

// Register 验证 reg 报文并按设备标签登记/刷新/轮换。返回本次动作快照（日志与测试用）。
func (t *DeviceTable) Register(reg []byte, now time.Time) (Result, error) {
	pubkey, devTag, secret, err := t.verify(reg, now)
	if err != nil {
		return Result{}, err
	}
	psk := proto.DerivePSK(secret)

	t.mu.Lock()
	defer t.mu.Unlock()

	if e, found := t.entries[devTag]; found {
		prev := e.lastReg
		if e.pub == pubkey {
			e.lastReg = now
			res := Result{DevTag: devTag, Pubkey: pubkey, TunnelIP: e.ip, Action: ActionRefreshed, Idle: now.Sub(prev)}
			t.logf("peer: ~ dev=%s refresh (idle=%s) n=%d/%d", devShort(devTag), roundDur(res.Idle), len(t.entries), t.max)
			return res, nil
		}
		// 身份轮换：先移除旧 peer 再写新的 —— 顺序固定，避免旧 allowed_ip 悬空。
		oldPub, oldIP := e.pub, e.ip
		if rerr := t.cfg.RemovePeer(oldPub); rerr != nil {
			t.logf("peer: ! dev=%s rotate 移除旧 peer（pub=%s）失败：%v", devShort(devTag), pubShort(oldPub), rerr)
		}
		t.pool.Release(oldIP)
		ip := t.assignIPLocked(secret, pubkey, devTag)
		e.pub, e.psk, e.ip, e.lastReg = pubkey, psk, ip, now
		if aerr := t.cfg.AddPeer(PeerConfig{Pubkey: pubkey, PSK: psk, TunnelIP: ip}); aerr != nil {
			t.logf("peer: ! dev=%s rotate 写入新 peer（pub=%s）失败：%v", devShort(devTag), pubShort(pubkey), aerr)
		}
		res := Result{DevTag: devTag, Pubkey: pubkey, TunnelIP: ip, Action: ActionRotated,
			OldPubkey: oldPub, OldIP: oldIP, Idle: now.Sub(prev)}
		t.logf("peer: ~ dev=%s rotate pub=%s→%s ip=%v→%v n=%d/%d",
			devShort(devTag), pubShort(oldPub), pubShort(pubkey), oldIP, ip, len(t.entries), t.max)
		return res, nil
	}

	if len(t.entries) >= t.max {
		if !t.evictStaleLocked(now) {
			t.logf("peer: ! dev=%s reject reason=table-full n=%d/%d", devShort(devTag), len(t.entries), t.max)
			return Result{}, ErrTableFull
		}
	}
	ip := t.assignIPLocked(secret, pubkey, devTag)
	e := &dentry{dev: devTag, pub: pubkey, psk: psk, ip: ip, lastReg: now, createdAt: now}
	t.entries[devTag] = e
	if aerr := t.cfg.AddPeer(PeerConfig{Pubkey: pubkey, PSK: psk, TunnelIP: ip}); aerr != nil {
		t.logf("peer: ! dev=%s 写入 peer（pub=%s）失败：%v", devShort(devTag), pubShort(pubkey), aerr)
	}
	if other, ok := t.findByPubLocked(pubkey, devTag); ok {
		t.logf("peer: ! pub=%s 同时登记在 dev=%s 与 dev=%s（疑似同一身份被两台设备使用：克隆/迁移过应用数据？）",
			pubShort(pubkey), devShort(other), devShort(devTag))
	}
	t.logf("peer: + dev=%s pub=%s ip=%v n=%d/%d", devShort(devTag), pubShort(pubkey), ip, len(t.entries), t.max)
	return Result{DevTag: devTag, Pubkey: pubkey, TunnelIP: ip, Action: ActionAdded}, nil
}

// GC 回收超过 TTL 未刷新的设备，返回被回收的条目（每个都打了日志）。
func (t *DeviceTable) GC(now time.Time) []Result {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ttl <= 0 {
		return nil
	}
	var victims []*dentry
	for _, e := range t.entries {
		if now.Sub(e.lastReg) > t.ttl {
			victims = append(victims, e)
		}
	}
	out := make([]Result, 0, len(victims))
	for _, e := range victims {
		res := Result{DevTag: e.dev, Pubkey: e.pub, TunnelIP: e.ip, Action: ActionExpired, Idle: now.Sub(e.lastReg)}
		t.removeLocked(e)
		t.logf("peer: - dev=%s reason=ttl (idle=%s) n=%d/%d", devShort(res.DevTag), roundDur(res.Idle), len(t.entries), t.max)
		out = append(out, res)
	}
	return out
}

// RunGC 周期回收（ctx 结束即退出）。every<=0 或 TTL 关闭时不做事。
// 节拍带 ±10% 抖动：多出口同时扫表时错开。
func (t *DeviceTable) RunGC(ctx context.Context, every time.Duration) {
	if every <= 0 || t.ttl <= 0 {
		return
	}
	for {
		wait := time.Duration(float64(every) * (0.9 + 0.2*rand.Float64()))
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		t.GC(time.Now())
	}
}

// evictStaleLocked 表满时淘汰：只在「超过 grace 未刷新」的设备里挑最旧的一条。
// 返回 false = 全部活跃（调用方应拒绝新设备，绝不淘汰在线设备）。
func (t *DeviceTable) evictStaleLocked(now time.Time) bool {
	var victim *dentry
	for _, e := range t.entries {
		if now.Sub(e.lastReg) <= t.grace {
			continue // 活跃宽限期内：不碰
		}
		if victim == nil || e.lastReg.Before(victim.lastReg) {
			victim = e
		}
	}
	if victim == nil {
		return false
	}
	idle := now.Sub(victim.lastReg)
	dev := victim.dev
	t.removeLocked(victim)
	t.logf("peer: - dev=%s reason=stale (idle=%s) n=%d/%d", devShort(dev), roundDur(idle), len(t.entries), t.max)
	return true
}

// assignIPLocked：隧道地址 = 两端各自从 (secret, 公钥) 派生（tasks 3.7）。
// 理论冲突（cap=32 时 ≈0.05%）退到池分配并大声告警 —— 注意身份持久化之后
// 重启不再换钥匙，消解冲突要靠用户「重置本机身份」。
func (t *DeviceTable) assignIPLocked(secret [32]byte, pub [32]byte, dev proto.DevTag) netip.Addr {
	ip := proto.DeriveTunnelIP(secret, pub)
	if !t.ipTakenLocked(ip) {
		return ip
	}
	for {
		fallback := t.pool.Acquire()
		if t.ipTakenLocked(fallback) {
			continue
		}
		t.logf("⚠️ 隧道地址冲突：dev=%s 的派生地址 %v 已被其他设备占用，本次退到池地址 %v（客户端仍用派生地址发包 ⇒ 该设备会不通；请在手机上「重置本机身份」后重连）",
			devShort(dev), ip, fallback)
		return fallback
	}
}

// ipTakenLocked 判断某地址是否已被表内其他设备占用（调用方持锁）。
func (t *DeviceTable) ipTakenLocked(ip netip.Addr) bool {
	for _, e := range t.entries {
		if e.ip == ip {
			return true
		}
	}
	return false
}

// findByPubLocked 找「同一公钥挂在别的 devTag 上」的条目（克隆检测，诊断用）。
func (t *DeviceTable) findByPubLocked(pub [32]byte, except proto.DevTag) (proto.DevTag, bool) {
	for dev, e := range t.entries {
		if dev != except && e.pub == pub {
			return dev, true
		}
	}
	return proto.DevTag{}, false
}

func (t *DeviceTable) removeLocked(e *dentry) {
	delete(t.entries, e.dev) // map 删除带显式 found 语义（下面 Release 幂等）
	t.pool.Release(e.ip)
	if err := t.cfg.RemovePeer(e.pub); err != nil {
		t.logf("peer: ! dev=%s 移除 peer（pub=%s）失败：%v", devShort(e.dev), pubShort(e.pub), err)
	}
}

// Len 当前设备数。
func (t *DeviceTable) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// Cap 容量。
func (t *DeviceTable) Cap() int { return t.max }

// Limits 返回 (cap, ttl, grace)，启动日志用。
func (t *DeviceTable) Limits() (int, time.Duration, time.Duration) { return t.max, t.ttl, t.grace }

// TunnelIP 查询某公钥的隧道地址（诊断）。found 显式返回——netip 零值不是哨兵。
func (t *DeviceTable) TunnelIP(pub [32]byte) (netip.Addr, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, e := range t.entries {
		if e.pub == pub {
			return e.ip, true
		}
	}
	return netip.Addr{}, false
}

// devShort / pubShort：日志用短指纹（4 字节 hex）。
func devShort(d proto.DevTag) string { return hex.EncodeToString(d[:4]) }
func pubShort(p [32]byte) string     { return hex.EncodeToString(p[:4]) }

func roundDur(d time.Duration) time.Duration { return d.Round(time.Second) }

// ipPool：顺序分配 + 释放回收（只服务隧道地址冲突的兜底路径）。
// 全部显式标志，零值地址不承担「未找到」语义。
type ipPool struct {
	base netip.Addr
	next uint32
	used map[netip.Addr]struct{}
	free []netip.Addr
}

func newIPPool(base netip.Addr) *ipPool {
	// next 从 1 起：base+0 是网段地址（100.64.0.0），不该分配给主机（FINDINGS/设计 §9-1）。
	return &ipPool{base: base, next: 1, used: make(map[netip.Addr]struct{})}
}

func (p *ipPool) Acquire() netip.Addr {
	if n := len(p.free); n > 0 {
		ip := p.free[n-1]
		p.free = p.free[:n-1]
		p.used[ip] = struct{}{}
		return ip
	}
	for {
		ip := netip.AddrFrom4([4]byte{p.base.As4()[0], p.base.As4()[1], byte(p.next >> 8), byte(p.next)})
		p.next++
		if _, taken := p.used[ip]; !taken {
			p.used[ip] = struct{}{}
			return ip
		}
	}
}

func (p *ipPool) Release(ip netip.Addr) {
	if _, ok := p.used[ip]; !ok {
		return // 幂等
	}
	delete(p.used, ip)
	p.free = append(p.free, ip)
}
