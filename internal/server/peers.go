package server

import (
	"container/list"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
)

// 动态 peer 表（wg-native-stack tasks 3.2）。
// lazyPeers 三条教训全带上：cap + LRU、TTL、显式 found 标志（netip 零值哨兵坑）。
//
// 表项由 reg 报文驱动：VerifyReg 过 → 不存在则登记（AddPeer + 隧道 IP 分配），
// 已存在则刷新 lastReg 并置 LRU 头。重放无害：旧公钥没有对应私钥，握手无法完成，
// 重复 reg 只刷新时间戳。TTL 过期由 GC（或下次 Register 惰性触发）清理。
type PeerConfig struct {
	Pubkey    [32]byte
	PSK       [32]byte
	TunnelIP  netip.Addr // 100.64.0.0/16 内 /32
	Keepalive int        // 秒；0 = 不配置
}

// Configurer 把表项落到 WG device（生产实现包 IpcSet；测试用 fake）。
type Configurer interface {
	AddPeer(pc PeerConfig) error
	RemovePeer(pubkey [32]byte) error
}

type pentry struct {
	pub     [32]byte
	psk     [32]byte
	ip      netip.Addr
	lastReg time.Time
	el      *list.Element // LRU 链表节点（front=最新）
}

type PeerTable struct {
	mu      sync.Mutex
	cfg     Configurer
	secrets [][32]byte
	cap     int
	ttl     time.Duration

	entries map[[32]byte]*pentry
	lru     *list.List
	pool    *ipPool
}

// DefaultTunnelBase：动态客户端的隧道 IP 池基址（/16，逐 /32 分配）。
const tunnelBase = "100.64.0.0"

func NewPeerTable(cfg Configurer, secrets [][32]byte, maxPeers int, ttl time.Duration) *PeerTable {
	if maxPeers <= 0 {
		maxPeers = 8
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &PeerTable{
		cfg:     cfg,
		secrets: secrets,
		cap:     maxPeers,
		ttl:     ttl,
		entries: make(map[[32]byte]*pentry, maxPeers),
		lru:     list.New(),
		pool:    newIPPool(netip.MustParseAddr(tunnelBase)),
	}
}

// Register 验证 reg 报文并确保 peer 在表内。返回登记的公钥。
func (t *PeerTable) Register(reg []byte, now time.Time) ([32]byte, error) {
	var pubkey [32]byte
	var secret [32]byte
	matched := false
	for _, sec := range t.secrets {
		if pk, err := proto.VerifyReg(sec, reg, now, 0); err == nil {
			pubkey, secret, matched = pk, sec, true
			break
		}
	}
	if !matched {
		return pubkey, fmt.Errorf("peers: reg 验证失败（无匹配 token）")
	}
	psk := proto.DerivePSK(secret)

	t.mu.Lock()
	defer t.mu.Unlock()
	if e, found := t.entries[pubkey]; found {
		e.lastReg = now // 重放/重连：仅刷新
		t.lru.MoveToFront(e.el)
		return pubkey, nil
	}
	if len(t.entries) >= t.cap {
		t.evictLRULocked()
	}
	ip := t.pool.Acquire()
	e := &pentry{pub: pubkey, psk: psk, ip: ip, lastReg: now}
	e.el = t.lru.PushFront(e)
	t.entries[pubkey] = e
	t.cfg.AddPeer(PeerConfig{Pubkey: pubkey, PSK: psk, TunnelIP: ip, Keepalive: 25})
	return pubkey, nil
}

// GC 清理 TTL 过期表项，返回清理数。
func (t *PeerTable) GC(now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for el := t.lru.Back(); el != nil; {
		prev := el.Prev()
		e := el.Value.(*pentry)
		if now.Sub(e.lastReg) > t.ttl {
			t.removeLocked(e)
			n++
		}
		el = prev
	}
	return n
}

func (t *PeerTable) evictLRULocked() {
	el := t.lru.Back()
	if el == nil {
		return
	}
	t.removeLocked(el.Value.(*pentry))
}

func (t *PeerTable) removeLocked(e *pentry) {
	t.lru.Remove(e.el)
	delete(t.entries, e.pub) // map 删除带显式 found 语义（下面 Release 幂等）
	t.pool.Release(e.ip)
	t.cfg.RemovePeer(e.pub)
}

func (t *PeerTable) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// TunnelIP 查询某公钥的隧道 IP（诊断）。found 显式返回——netip 零值不是哨兵。
func (t *PeerTable) TunnelIP(pub [32]byte) (ip netip.Addr, found bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[pub]
	if !ok {
		return netip.Addr{}, false
	}
	return e.ip, true
}

// ipPool：顺序分配 + 释放回收。全部显式标志，零值地址不承担「未找到」语义。
type ipPool struct {
	base netip.Addr
	next uint32
	used map[netip.Addr]struct{}
	free []netip.Addr
}

func newIPPool(base netip.Addr) *ipPool {
	return &ipPool{base: base, used: make(map[netip.Addr]struct{})}
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
