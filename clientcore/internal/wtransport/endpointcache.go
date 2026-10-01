// 端点学习缓存（wg-native-stack tasks 2.5；probe 来源与落盘合并 = endpoint-freshness）。
//
// 四种来源（design D3 与 spec「客户端地址学习」）：
//   - token  ：静态候选，每次从 token 来，不进缓存（Merge 时由调用方传入）；
//   - inband ：后端在隧道内自报的现址（认证、新鲜；生产者未实现，来源保留）；
//   - hint   ：中继观察到的地址（不可信、最新鲜；Bind 的 OnHint 回调喂进来）；
//   - probe  ：探测应答端点列表（**非认证**——公网明文路径、来源地址校验过的线索，
//     与 hint 同级信任；旧 IP 漂移后被他人占有时占有者可投喂，赛跑与 WG
//     认证是终审。绝不冒充 inband 的「认证」语义）。
//
// 每条记录带 source / learnedAt / verifiedAt：
//   - **verified 只在「该地址上真正跑通过一次认证握手或一次真实往返」后打**（由会话层调
//     MarkVerified，不要拿「采纳了来源地址」当验证——Bind 的采纳发生在 WG 认证之前）；
//   - 候选排序：verified 且新鲜优先，其次按学到的先后；
//   - TTL 7 天；无时间戳/过期一律无效。
//
// 落盘：<dir>/<peerID hex>.json（dir 约定 <filesDir>/endpoints），
// 原子写（tmp+rename），内容未变不写。**写前重读合并**（endpoint-freshness D8）：同一
// peerID 可能有两份缓存实例（隧道会话与服务会话）各持一份内存表，整文件覆盖会抹掉对方
// 在此期间学到的条目——Save 先把磁盘上自己没有的条目并入再写。
package wtransport

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// LearnedEndpointTTL：学习地址的有效期。
const LearnedEndpointTTL = 7 * 24 * time.Hour

// EndpointSource 学习来源（provenance）。
type EndpointSource string

const (
	SourceToken  EndpointSource = "token"  // 静态候选（一般只在 verified 记录里出现）
	SourceInband EndpointSource = "inband" // 后端隧道内自报（认证；生产者未实现，来源保留）
	SourceHint   EndpointSource = "hint"   // 中继观察（不可信）
	SourceProbe  EndpointSource = "probe"  // 探测应答端点列表（非认证、hint 级信任；endpoint-freshness）
)

// LearnedEndpoint 一条学习记录。
//
// 时间戳为 **Unix 毫秒**：同一秒内先学到 A、后学到 B 仍能定序
// （秒级时间戳下排序会退化成 map 迭代顺序，不确定）。
type LearnedEndpoint struct {
	Addr       netip.AddrPort `json:"-"`
	Endpoint   string         `json:"endpoint"`
	Source     EndpointSource `json:"source"`
	LearnedAt  int64          `json:"learnedAt"`
	VerifiedAt int64          `json:"verifiedAt,omitempty"`
}

// Verified 是否已验证过（一次成功的认证会话）。
func (e LearnedEndpoint) Verified() bool { return e.VerifiedAt > 0 }

// endpointFile 落盘形态。
type endpointFile struct {
	Peer    string            `json:"peer,omitempty"`
	Entries []LearnedEndpoint `json:"entries,omitempty"`
}

// EndpointCache 一个后端（peerID）一份缓存的读写器。零值不可用，用 OpenEndpointCache。
type EndpointCache struct {
	dir    string
	peerID [32]byte
	ttl    time.Duration
	logf   func(format string, args ...any)

	mu      sync.Mutex
	entries map[netip.AddrPort]LearnedEndpoint
	lastRaw string // 节流：上次写盘内容
}

// OpenEndpointCache 打开（不存在则空）某后端的端点缓存。dir 空 = 关闭缓存（所有写/读都空转）。
// 读盘失败一律安全降级为空缓存——缓存坏了不该影响建连。
func OpenEndpointCache(dir string, peerID [32]byte) *EndpointCache {
	c := &EndpointCache{
		dir:     dir,
		peerID:  peerID,
		ttl:     LearnedEndpointTTL,
		entries: map[netip.AddrPort]LearnedEndpoint{},
		logf:    func(string, ...any) {},
	}
	c.load()
	return c
}

// SetLogger 注入日志（与 Bind 同款）。
func (c *EndpointCache) SetLogger(logf func(string, ...any)) {
	if logf != nil {
		c.logf = logf
	}
}

// setTTL 覆盖有效期（测试/运维用）。
func (c *EndpointCache) setTTL(ttl time.Duration) { c.ttl = ttl }

// Path 缓存文件路径（dir 空时返回空串）。
func (c *EndpointCache) Path() string {
	if c.dir == "" {
		return ""
	}
	return filepath.Join(c.dir, hex.EncodeToString(c.peerID[:])+".json")
}

func (c *EndpointCache) load() {
	p := c.Path()
	if p == "" {
		return
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return // 文件缺失/不可读：空缓存
	}
	var f endpointFile
	if err := json.Unmarshal(raw, &f); err != nil {
		c.logf("ENDPOINTCACHE 读盘失败（忽略，用空缓存）：%v", err)
		return
	}
	for _, e := range f.Entries {
		ap, err := netip.ParseAddrPort(e.Endpoint)
		if err != nil || !ap.IsValid() {
			continue
		}
		e.Addr = ap
		c.entries[ap] = e
	}
}

// Entries 返回 TTL 内、未被失败剔除的记录（verified 且新鲜优先）。
func (c *EndpointCache) Entries(now time.Time) []LearnedEndpoint {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.validLocked(now)
}

func (c *EndpointCache) validLocked(now time.Time) []LearnedEndpoint {
	out := make([]LearnedEndpoint, 0, len(c.entries))
	for _, e := range c.entries {
		if !c.valid(e, now) {
			continue
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Verified() != out[j].Verified() {
			return out[i].Verified() // 已验证优先
		}
		// 新的优先：先看最近一次验证，再看最近一次学习；同分按地址定序（确定性）
		if out[i].VerifiedAt != out[j].VerifiedAt {
			return out[i].VerifiedAt > out[j].VerifiedAt
		}
		if out[i].LearnedAt != out[j].LearnedAt {
			return out[i].LearnedAt > out[j].LearnedAt
		}
		return out[i].Endpoint < out[j].Endpoint
	})
	return out
}

func (c *EndpointCache) valid(e LearnedEndpoint, now time.Time) bool {
	if !e.Addr.IsValid() || e.LearnedAt <= 0 {
		return false
	}
	// 新鲜度 = max(学习, 验证)（FIX-11）：持续被验证（每轮往返 MarkRoundTrip 复标
	// VerifiedAt）的长连端点在「学习时刻」满 TTL 时**不得**被静默删除——那删掉的
	// 正是出口漂移场景里唯一的救命记录（它还在被用着）。
	last := e.LearnedAt
	if e.VerifiedAt > last {
		last = e.VerifiedAt
	}
	return now.Sub(time.UnixMilli(last)) <= c.ttl
}

func markTS(t time.Time) int64 { return t.UnixMilli() }

// Observe 记录一条学习到的地址（hint/inband/token）。返回是否有变化。
// 同址重复观察：刷新时间、清失败计数；来源按强度升级（token < hint < inband）。
func (c *EndpointCache) Observe(addr netip.AddrPort, src EndpointSource, now time.Time) bool {
	if !addr.IsValid() {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[addr]
	if !ok {
		c.entries[addr] = LearnedEndpoint{
			Addr: addr, Endpoint: addr.String(), Source: src, LearnedAt: markTS(now),
		}
		return true
	}
	e.LearnedAt = markTS(now)
	if sourceStrength(src) > sourceStrength(e.Source) {
		e.Source = src
	}
	c.entries[addr] = e
	return true
}

// MarkVerified 标记「该地址上完成过一次成功认证会话」。缺记录时会补建。
func (c *EndpointCache) MarkVerified(addr netip.AddrPort, src EndpointSource, now time.Time) bool {
	if !addr.IsValid() {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[addr]
	if !ok {
		e = LearnedEndpoint{Addr: addr, Endpoint: addr.String(), Source: src, LearnedAt: markTS(now)}
	}
	e.VerifiedAt = markTS(now)
	if sourceStrength(src) > sourceStrength(e.Source) {
		e.Source = src
	}
	c.entries[addr] = e
	return true
}

// Merge 组装建连候选：学习到的地址在前（verified/新鲜优先），静态 token 候选去重后接上。
// 学习到的地址一律按 direct 处理（中继腿由 token/带内给）；**但**若同一地址在 static 里
// 是中继条目（出口与中继同机同口的退化形态），沿用 Relay 标记——按地址去重把类型位吃掉
// 正是 token relay 腿失效那类事故的同源形态（review 1.4，2026-09-23）。
func (c *EndpointCache) Merge(static []Candidate, now time.Time) []Candidate {
	learned := c.Entries(now)
	relayAddrs := make(map[netip.AddrPort]bool, len(static))
	for _, s := range static {
		if s.Relay && s.Addr.IsValid() {
			relayAddrs[s.Addr] = true
		}
	}
	out := make([]Candidate, 0, len(learned)+len(static))
	seen := map[netip.AddrPort]bool{}
	for _, e := range learned {
		if seen[e.Addr] {
			continue
		}
		seen[e.Addr] = true
		out = append(out, Candidate{Addr: e.Addr, Relay: relayAddrs[e.Addr]})
	}
	for _, s := range static {
		if s.Addr.IsValid() && !seen[s.Addr] {
			seen[s.Addr] = true
			out = append(out, s)
		}
	}
	return out
}

// Save 落盘（内容未变不写；原子写；**写前重读合并**）。dir 空或没有任何记录时不写文件。
//
// 合并语义（endpoint-freshness D8）：同一 peerID 的两份缓存实例（隧道会话与服务会话）各持
// 内存表，任一方整文件覆盖都会抹掉对方在此期间学到的条目——写前把磁盘上**本实例没有**的
// 条目并入（同址以内存为准：本实例的观察更新）。合并不救活 TTL 外/失败剔除的条目
// （validLocked 在落盘时统一过滤）。
func (c *EndpointCache) Save(now time.Time) error {
	if c.dir == "" {
		return nil
	}
	// 全程持锁（真机 2026-09-22：锁外 tmp+rename 的并发保存竞态——后到者 rename 报
	// ENOENT，失败路径的 os.Remove(tmp) 还会误删第三个并发者刚写的 tmp，连环失败每
	// 巡检拍刷 2-3 条「落盘失败」）。实例锁只护本实例；**跨实例**（隧道/服务两份缓存，
	// 或重建窗口新旧实例并存）由唯一 tmp 名兜底（FIX-12）：各自写各自 tmp、rename 原子、
	// 末写者胜（写前重读合并保证对方已知条目不丢），失败清理只删自己的 tmp。
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mergeDiskLocked()
	entries := c.validLocked(now)
	raw, err := json.Marshal(endpointFile{
		Peer:    hex.EncodeToString(c.peerID[:]),
		Entries: entries,
	})
	if err != nil {
		return err
	}
	if string(raw) == c.lastRaw {
		return nil
	}

	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return fmt.Errorf("wtransport: 建端点缓存目录失败: %w", err)
	}
	tmp := fmt.Sprintf("%s.tmp.%d.%d", c.Path(), os.Getpid(), time.Now().UnixNano())
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("wtransport: 写端点缓存失败: %w", err)
	}
	if err := os.Rename(tmp, c.Path()); err != nil {
		_ = os.Remove(tmp) // 只删自己写的 tmp（名字唯一，误删他人 tmp 的形态已消）
		return fmt.Errorf("wtransport: 端点缓存改名失败: %w", err)
	}
	c.lastRaw = string(raw)
	return nil
}

// mergeDiskLocked：把磁盘文件里本实例没有的条目并入内存（调用方持锁）。
// 读盘失败静默跳过——合并是保护性的，盘坏了按原行为落盘。
func (c *EndpointCache) mergeDiskLocked() {
	raw, err := os.ReadFile(c.Path())
	if err != nil {
		return
	}
	var f endpointFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return
	}
	for _, e := range f.Entries {
		ap, err := netip.ParseAddrPort(e.Endpoint)
		if err != nil || !ap.IsValid() {
			continue
		}
		e.Addr = ap
		if _, inMem := c.entries[ap]; !inMem {
			c.entries[ap] = e
		}
	}
}

// ObserveAndSave：便捷组合（hint 回调这类高频路径用）。
func (c *EndpointCache) ObserveAndSave(addr netip.AddrPort, src EndpointSource, now time.Time) {
	if c.Observe(addr, src, now) {
		if err := c.Save(now); err != nil {
			c.logf("ENDPOINTCACHE 落盘失败：%v", err)
		}
	}
}

// MarkVerifiedAndSave：会话成功后的便捷组合。
func (c *EndpointCache) MarkVerifiedAndSave(addr netip.AddrPort, src EndpointSource, now time.Time) {
	if c.MarkVerified(addr, src, now) {
		if err := c.Save(now); err != nil {
			c.logf("ENDPOINTCACHE 落盘失败：%v", err)
		}
	}
}

func sourceStrength(s EndpointSource) int {
	switch s {
	case SourceInband:
		return 3
	case SourceHint, SourceProbe: // probe = 非认证线索，与 hint 同级（endpoint-freshness）
		return 2
	case SourceToken:
		return 1
	default:
		return 0
	}
}
