// socksmgr.go — 按主机 SOCKS5 承载面管理器（forward-socks-speedtest 3e §2.4，D1/D3/D8）。
//
// 每主机至多一个 listener（多主机 = 多端口，浏览器按端口选出口）；{on,listen} 记忆
// 持久化于 <state>/socks.json（0600、原子读改写、损坏按空表重建 + 告警）。off 不抹
// 端口记忆（下次 on 缺省沿用）。域名远程解析 = DNS-over-TCP→5300（Host.DialPort(5300)
// → 出口豁免转投本机代答），**MUST NOT 本地解析**（结构保证：本文件无任何系统解析
// 调用）。缓存**每 listener 一份**（r1 中-2：缓存 key =（出口主机, 域名）——每主机一
// listener 的实现形态即天然隔离；有界 256、TTL 取应答钳制值、否定不缓存、逐出即弃）。
// 在世连接（r1 中-6）：off/级联 = 显式关（SetLinger(0) RST——「off」之后不得仍有
// 代理流量经隧道跑）。
package facade

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/zhaoyswd/homeway/pkg/dns"
	"github.com/zhaoyswd/homeway/pkg/socks"
)

// socksFileName 开关记忆持久化文件（0600）。
const socksFileName = "socks.json"

// socksDialPort 出口 DNS 代答端口（pkg/dns 默认监听 127.0.0.1:5300；经隧道的查询由
// 出口 intercept 豁免转投）。
const socksDNSPort = 5300

// socks 默认监听端口与缓存边界。
const (
	socksDefaultListen = 1080
	socksCacheMax      = 256
	// socksResolveBudget 单次解析总预算（拨 5300 + 查询；design D3：5s，超时归因、不缓存）。
	socksResolveBudget = 5 * time.Second
)

// SocksEntry 每主机开关记忆（持久化形态）。
type SocksEntry struct {
	Host   string `json:"host"` // peerID hex
	On     bool   `json:"on"`
	Listen uint16 `json:"listen"` // 记忆端口（off 也保留）
}

// SocksState status 面单条（链路态 via/rtt 由 CLI/绑定层 join——本面只管承载态）。
type SocksState struct {
	Host   string
	On     bool
	Listen uint16 // off 但记住的端口（status --json 暴露）
	Conns  int
	Err    string // 重建/开启失败时的如实呈现
}

// socksEntry 运行时。
type socksEntryRT struct {
	rec   SocksEntry
	ln    net.Listener
	srv   *socks.Server
	cache *dnsCache
	err   string
}

// SocksManager socks 承载面管理器（Carriers 持有；全局端口唯一性检查在 Carriers 层）。
type SocksManager struct {
	mu        sync.Mutex
	stateDir  string
	dial      carrierDial
	defListen uint16 // on 缺省端口（无记忆时的落点；生产 = 1080；测试可注入 0 = 取空闲端口）
	entries   []*socksEntryRT
	logf      func(format string, args ...any)
	warnf     func(format string, args ...any)
}

// openSocksManager 打开开关记忆：读 socks.json、按 on 条目重建监听（失败 = off 呈现 +
// 告警，不拒启）。defListen = on 缺省端口的落点：生产（openCarriers）恒传 1080；
// 测试经 openCarriersWithSocksDefault 注入 0 = 让内核选空闲端口（exec-r1 B4：门禁
// 与「在役 daemon 持 1080」解耦——「无记忆 → 1080」的纯面断言见 DefaultListen）。
func openSocksManager(stateDir string, dial carrierDial, defListen uint16, logf, warnf func(string, ...any)) (*SocksManager, error) {
	m := &SocksManager{stateDir: stateDir, dial: dial, defListen: defListen, logf: logf, warnf: warnf}
	if logf == nil {
		m.logf = func(string, ...any) {}
	}
	if warnf == nil {
		m.warnf = m.logf
	}
	recs, err := loadSocksEntries(filepath.Join(stateDir, socksFileName), m.warnf)
	if err != nil {
		return nil, err
	}
	for _, rec := range recs {
		e := &socksEntryRT{rec: rec}
		if rec.On {
			if err := m.startListener(e); err != nil {
				e.err = err.Error()
				m.warnf("socks: %s 监听重建失败（%v）——按 off 呈现，socks on 可重试", shortHost(rec.Host), err)
			}
		}
		m.entries = append(m.entries, e)
	}
	return m, nil
}

// On 开监听（listen 0 = 沿用记忆端口，无记忆则缺省——生产 1080、注入面见
// openSocksManager；exec-r1 B1：此前恒落 1080，把记忆静默改写）。同主机重复 on：
// 同端口 = 幂等成功；换端口 = 关旧开新。返回实际端口。
func (m *SocksManager) On(host string, listen uint16) (uint16, error) {
	if listen == 0 {
		listen = m.DefaultListen(host)
	}
	if listen != 0 && (listen < forwardMinPort || listen > forwardMaxPort) {
		return 0, fmt.Errorf("%w：%d", ErrPortRange, listen)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.entries {
		if e.rec.Host != host {
			// 其它主机的端口一律挡（含 off 但记住的——「全局唯一」按规则在册判，
			// 防 on 回来撞上别台已占/已记的端口）。
			if listen != 0 && e.rec.Listen == listen {
				return 0, fmt.Errorf("%w：%d 已被 %s 的 socks 监听占用（可用 --listen 另选）", ErrPortTaken, listen, shortHost(e.rec.Host))
			}
			continue
		}
		if e.ln != nil && listen != 0 && e.rec.Listen == listen {
			return listen, nil // 幂等：同端口已开
		}
		if e.ln != nil {
			m.stopListener(e) // 换端口：关旧（显式关在世连接）
		}
		e.rec.Listen = listen
		e.err = ""
		if err := m.startListener(e); err != nil {
			_ = m.saveLocked()
			return 0, fmt.Errorf("监听 127.0.0.1:%d 失败（%w）", listen, err)
		}
		port, err := m.settleListenPortLocked(e)
		if err != nil {
			return 0, err
		}
		m.logf("socks: %s on 127.0.0.1:%d", shortHost(host), port)
		return port, nil
	}
	e := &socksEntryRT{rec: SocksEntry{Host: host, On: true, Listen: listen}}
	if err := m.startListener(e); err != nil {
		return 0, fmt.Errorf("监听 127.0.0.1:%d 失败（%w）", listen, err)
	}
	// 先入表再落盘；落盘失败撤回——零副作用。
	m.entries = append(m.entries, e)
	if _, err := m.settleListenPortLocked(e); err != nil {
		m.entries = m.entries[:len(m.entries)-1]
		return 0, err
	}
	m.logf("socks: %s on 127.0.0.1:%d", shortHost(host), e.rec.Listen)
	return e.rec.Listen, nil
}

// DefaultListen on 缺省端口的解析面（纯查询、不绑端口）：该主机的记忆端口，
// 无记忆/记忆为 0 = 注入的缺省（生产 1080；测试注入 0 = 内核选空闲端口）。
// spec「on 的监听端口缺省 SHALL 沿用该主机上次使用的端口（无记忆则 1080）」的
// 唯一真源（exec-r1 B1）。
func (m *SocksManager) DefaultListen(host string) uint16 {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.entries {
		if e.rec.Host == host && e.rec.Listen != 0 {
			return e.rec.Listen
		}
	}
	return m.defListen
}

// settleListenPortLocked 落记忆并落盘；注入缺省 = 0（内核选空闲端口）时先把记忆
// 落成实际端口。失败路径统一收口监听（调用方只撤表）。调用方持锁。
func (m *SocksManager) settleListenPortLocked(e *socksEntryRT) (uint16, error) {
	if e.rec.Listen == 0 {
		e.rec.Listen = listenerPort(e.ln)
	}
	if e.rec.Listen == 0 {
		m.stopListener(e)
		return 0, errors.New("socks: 无法确定监听端口")
	}
	if err := m.saveLocked(); err != nil {
		m.stopListener(e)
		_ = m.saveLocked()
		return 0, err
	}
	return e.rec.Listen, nil
}

// listenerPort 从监听器读实际端口（测试注入缺省 0 的形态用；非 TCP 返回 0）。
func listenerPort(ln net.Listener) uint16 {
	if t, ok := ln.Addr().(*net.TCPAddr); ok {
		return uint16(t.Port)
	}
	return 0
}

// Off 关监听并**显式关在世连接**（RST 收口）；端口记忆保留（下次 on 缺省沿用）。
func (m *SocksManager) Off(host string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.entries {
		if e.rec.Host == host {
			if e.ln != nil {
				m.stopListener(e)
				m.logf("socks: %s off（在世连接已 RST 收口，端口 %d 记忆保留）", shortHost(host), e.rec.Listen)
			}
			return m.saveLocked()
		}
	}
	return fmt.Errorf("%w：socks %s", ErrNoForwardRule, shortHost(host))
}

// RemoveHost 级联（host.remove）：off 同款显式关 + 端口记忆随之消失。
func (m *SocksManager) RemoveHost(host string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.entries[:0]
	for _, e := range m.entries {
		if e.rec.Host == host {
			if e.ln != nil {
				m.stopListener(e)
			}
			m.logf("socks: %s off（主机删除级联；端口记忆消失）", shortHost(host))
			continue
		}
		kept = append(kept, e)
	}
	m.entries = kept
	if err := m.saveLocked(); err != nil {
		m.warnf("socks: 级联删除后落盘失败（%v）——内存为准，下次写回收敛", err)
	}
}

// Status 各主机承载态（按 host 排序稳定输出）。
func (m *SocksManager) Status() []SocksState {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]SocksState, 0, len(m.entries))
	for _, e := range m.entries {
		st := SocksState{Host: e.rec.Host, On: e.ln != nil, Listen: e.rec.Listen, Err: e.err}
		if e.srv != nil {
			st.Conns = e.srv.Conns()
		}
		out = append(out, st)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Host < out[j-1].Host; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// portOwner 端口占用查询（含 off 但记住的端口——全局唯一按「规则在册」判，防 on 回来
// 撞上别的主机已占的端口）。
func (m *SocksManager) portOwner(port uint16) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.entries {
		if e.rec.Listen == port {
			return shortHost(e.rec.Host) + " 的 socks 监听", true
		}
	}
	return "", false
}

// Close 收工：全部按 off 语义显式关（RST 在世连接）。
func (m *SocksManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.entries {
		if e.ln != nil {
			m.stopListener(e)
		}
	}
}

// startListener 起监听 + SOCKS 服务端（resolver/dialer 绑定该主机；每 listener 一份
// DNS 缓存——r1 中-2）。调用方持锁。
func (m *SocksManager) startListener(e *socksEntryRT) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", e.rec.Listen))
	if err != nil {
		return err
	}
	host := e.rec.Host
	cache := newDNSCache(socksCacheMax)
	srv := socks.New(socks.ServerConfig{
		Resolver: m.resolverFor(host, cache),
		Dialer: func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
			return m.dial.dial(ctx, host, dst) // 数据腿：任意目标缝
		},
		Logf:          m.logf,
		ResolveBudget: socksResolveBudget,
	})
	go func() {
		err := srv.Serve(ln)
		// L6（exec-r1）：非「监听器被关」的 Serve 退出（accept 瞬态错误烧尽退避——
		// 见 pkg/socks.Serve）= 无人再受理的僵尸监听——按 off 语义收口 + err 如实
		// 呈现（status 面 Err 字段），防「状态说在听、实际没人 accept」。
		if err != nil && !errors.Is(err, net.ErrClosed) {
			m.mu.Lock()
			if e.ln == ln { // 仍是在役监听（off/级联路径已自行收口）
				m.stopListener(e)
				e.err = fmt.Sprintf("监听 accept 失败（%v）——重试 socks on 可恢复", err)
				m.warnf("socks: %s 监听 accept 失败（%v）——按 off 收口", shortHost(e.rec.Host), err)
			}
			m.mu.Unlock()
		}
	}()
	e.ln, e.srv, e.cache = ln, srv, cache
	e.rec.On = true
	return nil
}

// stopListener 关监听 + 显式关在世连接（RST）。调用方持锁。
func (m *SocksManager) stopListener(e *socksEntryRT) {
	if e.ln != nil {
		_ = e.ln.Close()
	}
	if e.srv != nil {
		e.srv.Close() // SetLinger(0) RST 全部在世连接
	}
	e.ln, e.srv, e.cache = nil, nil, nil
	e.rec.On = false
}

// resolverFor 域名远程解析腿（socks 承载面的解析注入）：缓存（每 listener 一份 = 每
// 主机一份——key（出口主机, 域名）的隔离由「cache 实例随 listener」实现，r1 中-2）→
// 未命中经 Host.DialPort(5300) 拨出口代答 TCP 面发 DNS-over-TCP A 查询；否定/超时
// 不缓存。ctx 预算由 socks 服务端套（ResolveBudget）。
func (m *SocksManager) resolverFor(host string, cache *dnsCache) socks.Resolver {
	return func(ctx context.Context, name string) ([]netip.Addr, error) {
		if addrs, ok := cache.get(name, time.Now()); ok {
			return addrs, nil
		}
		conn, err := m.dial.dialPort(ctx, host, socksDNSPort)
		if err != nil {
			return nil, fmt.Errorf("解析腿拨号（出口 5300）失败：%w", err)
		}
		budget := socksResolveBudget
		if dl, ok := ctx.Deadline(); ok {
			if remain := time.Until(dl); remain > 0 {
				budget = remain
			}
		}
		res, err := dns.ResolveOverConn(conn, name, budget)
		_ = conn.Close() // 每查询一条新连接
		if err != nil {
			return nil, err // NXDOMAIN/无 A/超时——不缓存
		}
		cache.put(name, res.Addrs, time.Now().Add(time.Duration(res.TTL)*time.Second))
		return res.Addrs, nil
	}
}

// ---------- 持久化 ----------

func (m *SocksManager) saveLocked() error {
	path := filepath.Join(m.stateDir, socksFileName)
	if err := os.MkdirAll(m.stateDir, 0o700); err != nil {
		return err
	}
	recs := make([]SocksEntry, 0, len(m.entries))
	for _, e := range m.entries {
		recs = append(recs, e.rec)
	}
	b, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func loadSocksEntries(path string, warnf func(string, ...any)) ([]SocksEntry, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var recs []SocksEntry
	if err := json.Unmarshal(b, &recs); err != nil {
		backup := fmt.Sprintf("%s.corrupt-%d", path, time.Now().Unix())
		if rerr := os.Rename(path, backup); rerr != nil {
			return nil, fmt.Errorf("socks.json 损坏（%v）且备份失败：%w", err, rerr)
		}
		warnf("socks.json 损坏（%v）——已备份 %s，按空表重建", err, backup)
		return nil, nil
	}
	return recs, nil
}

// ---------- DNS 缓存（每 listener 一份） ----------

// dnsCache 域名 → 候选列表的有界 TTL 缓存（FIFO 逐出；否定不进缓存；逐出即弃不续期）。
type dnsCache struct {
	mu      sync.Mutex
	max     int
	entries map[string]dnsCacheEntry
	order   []string // 插入序（FIFO 逐出）
}

type dnsCacheEntry struct {
	addrs  []netip.Addr
	expiry time.Time
}

func newDNSCache(max int) *dnsCache {
	if max <= 0 {
		max = socksCacheMax
	}
	return &dnsCache{max: max, entries: map[string]dnsCacheEntry{}}
}

func (c *dnsCache) get(name string, now time.Time) ([]netip.Addr, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[name]
	if !ok {
		return nil, false
	}
	if !now.Before(e.expiry) {
		delete(c.entries, name) // 过期惰性清除
		return nil, false
	}
	return e.addrs, true
}

func (c *dnsCache) put(name string, addrs []netip.Addr, expiry time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[name]; !ok {
		if len(c.order) >= c.max { // FIFO 逐出最旧
			oldest := c.order[0]
			c.order = c.order[1:]
			delete(c.entries, oldest)
		}
		c.order = append(c.order, name)
	}
	c.entries[name] = dnsCacheEntry{addrs: addrs, expiry: expiry}
}

// size 缓存条数（测试观测面）。
func (c *dnsCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
