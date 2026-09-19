// Package relay：Homeway 中继（wg-native-stack tasks 6.1–6.5）。
//
// 定位：中继是**路径而不是参与方** —— 只见密文、零 WG 感知、零落盘状态（重启即清）。
// 安全由两件事构造性保证：
//   - 控制面：后端注册腿要证明持有 peerId 私钥（X25519 DH 挑战响应），否则拒绝；
//   - 数据面：转发的都是端到端加密的 WG 报文，中继改不了也读不了。
//
// 两条腿：
//
//	后端(NAT 后) ──出站注册腿──► 中继                       （NAT 友好：出站即可）
//	客户端       ──标签帧──────► 中继 ──per-client socket──► 后端注册腿源地址
//
// **per-client 分配 socket 是正确性要求**：后端 WG 靠**源地址**区分客户端 endpoint，
// 共用一条 socket 会让多客户端互踩（files 独立身份那次的教训）。
//
// hint（对端观察地址）在三个时机递送：客户端腿建立、后端注册腿源地址变化、客户端首包。
// hint 一律是不可信线索：只用于发起握手尝试，路径迁移以对端认证握手成功为前提。
package relay

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
	"golang.org/x/crypto/curve25519"
)

// 默认参数（可用 Config 覆盖）。
const (
	defaultIdleTimeout = 90 * time.Second  // 分配腿空闲回收
	defaultLegTimeout  = 90 * time.Second  // 注册腿过期（后端 keepalive 间隔的 3 倍）
	defaultMaxPerPeer  = 32                // 每个后端最多并发的客户端分配
	defaultRateLimit   = 200               // 每个源地址每秒允许的包数（准入限流）
	challengeTTL       = 15 * time.Second  // 挑战有效期
)

// Config 中继参数。
type Config struct {
	Addr        string        // 监听地址（如 :41641）
	IdleTimeout time.Duration // 分配腿空闲回收（0 = 默认 90s）
	LegTimeout  time.Duration // 注册腿过期（0 = 默认 90s）
	MaxPerPeer  int           // 每个后端的最大并发分配（0 = 默认 32）
	RateLimit   int           // 每源每秒包数上限（0 = 默认 200）
	Logf        func(format string, args ...any)
}

// Relay 中继实例。
type Relay struct {
	cfg Config
	pc  *net.UDPConn

	mu     sync.Mutex
	legs   map[[8]byte]*leg
	assocs map[assocKey]*assoc
	rates  map[netip.Addr]*rateBucket

	stats Stats
}

// Stats 中继计数（诊断/测试用）。
type Stats struct {
	Registered    uint64 // 成功注册的后端腿次数
	Forged        uint64 // 注册挑战/证明失败次数
	Assigned      uint64 // 新建的客户端分配数
	Reclaimed     uint64 // 回收的分配数
	Dropped       uint64 // 被丢弃的包（未知 peerId/超限/畸形）
	ForwardedUp   uint64 // 客户端 → 后端 转发包数
	ForwardedDown uint64 // 后端 → 客户端 转发包数
}

type assocKey struct {
	label  [8]byte
	client netip.AddrPort
}

type leg struct {
	label    [8]byte
	pubkey   [32]byte
	addr     netip.AddrPort // 注册腿源地址（后端公网映射，也是给客户端的 hint）
	last     time.Time
	ephPriv  [32]byte
	nonce    [16]byte
	challAt  time.Time
	verified bool
}

type assoc struct {
	key     assocKey
	backend netip.AddrPort // 注册腿地址（回程发给它）
	sock    *net.UDPConn   // 该客户端专属的上游 socket（后端看到的"客户端地址"）
	last    time.Time
}

type rateBucket struct {
	window time.Time
	count  int
}

// New 建中继（不监听）。
func New(cfg Config) *Relay {
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = defaultIdleTimeout
	}
	if cfg.LegTimeout <= 0 {
		cfg.LegTimeout = defaultLegTimeout
	}
	if cfg.MaxPerPeer <= 0 {
		cfg.MaxPerPeer = defaultMaxPerPeer
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = defaultRateLimit
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	return &Relay{
		cfg:    cfg,
		legs:   map[[8]byte]*leg{},
		assocs: map[assocKey]*assoc{},
		rates:  map[netip.Addr]*rateBucket{},
	}
}

// LocalAddr 监听地址（Run 之后可用；测试里取随机端口）。
func (r *Relay) LocalAddr() netip.AddrPort {
	if r.pc == nil {
		return netip.AddrPort{}
	}
	if ua, ok := r.pc.LocalAddr().(*net.UDPAddr); ok {
		return ua.AddrPort()
	}
	return netip.AddrPort{}
}

// Stats 读计数快照。
func (r *Relay) Stats() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stats
}

// Run 监听并服务直到 ctx 结束。
func (r *Relay) Run(ctx context.Context) error {
	pc, err := net.ListenUDP("udp", mustResolve(r.cfg.Addr))
	if err != nil {
		return err
	}
	r.pc = pc
	r.cfg.Logf("中继就绪：%v（分配回收 %v，注册腿过期 %v，每源限速 %d pps，每后端最多 %d 条分配）",
		pc.LocalAddr(), r.cfg.IdleTimeout, r.cfg.LegTimeout, r.cfg.RateLimit, r.cfg.MaxPerPeer)
	go r.reapLoop(ctx)
	go r.statsLoop(ctx)
	go func() {
		<-ctx.Done()
		_ = pc.Close()
		r.closeAll()
	}()
	r.readLoop(ctx)
	return nil
}

func mustResolve(addr string) *net.UDPAddr {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return &net.UDPAddr{}
	}
	return ua
}

// readLoop：listener 上的收包（客户端腿 + 后端注册腿共用同一个端口）。
func (r *Relay) readLoop(ctx context.Context) {
	buf := make([]byte, 65535)
	for {
		n, src, err := r.pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			return // ctx 结束或 socket 关闭
		}
		src = unmap(src)
		if !r.allow(src.Addr()) {
			r.bump(func(s *Stats) { s.Dropped++ })
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)
		r.handlePacket(ctx, src, pkt)
	}
}

// handlePacket：一条入包的分派。
func (r *Relay) handlePacket(_ context.Context, src netip.AddrPort, pkt []byte) {
	label, typ, payload, err := proto.DecodeTagged(pkt)
	if err != nil {
		// 不带标签的包（比如误发到中继端口的 WG）：直接丢
		r.bump(func(s *Stats) { s.Dropped++ })
		return
	}
	r.mu.Lock()
	lg := r.legs[label]
	r.mu.Unlock()

	if typ == proto.FrameTypeRelayReg {
		r.handleControl(src, label, lg, payload)
		return
	}
	if lg == nil || !lg.verified {
		// 准入：没有已注册的后端，谁也别想转发（蹭不到资源）
		r.bump(func(s *Stats) { s.Dropped++ })
		return
	}
	r.forwardUp(src, lg, typ, payload)
}

// handleControl：后端注册腿的控制消息（Hello/Proof/Keepalive）。
func (r *Relay) handleControl(src netip.AddrPort, label [8]byte, lg *leg, payload []byte) {
	sub, _ := proto.RelaySubtype(payload)
	switch sub {
	case proto.RelaySubHello:
		pubkey, err := proto.DecodeRelayHello(payload)
		if err != nil || proto.RelayID(pubkey) != label {
			r.bump(func(s *Stats) { s.Forged++ })
			return
		}
		// 出题：临时 X25519 密钥对 + 随机数
		var ephPriv [32]byte
		if _, err := rand.Read(ephPriv[:]); err != nil {
			return
		}
		ephPub, err := curve25519.X25519(ephPriv[:], curve25519.Basepoint)
		if err != nil {
			return
		}
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return
		}
		var pub [32]byte
		copy(pub[:], ephPub)
		r.mu.Lock()
		cur := r.legs[label]
		if cur == nil || !cur.verified {
			cur = &leg{label: label, pubkey: pubkey}
			r.legs[label] = cur
		}
		cur.ephPriv, cur.nonce, cur.challAt = ephPriv, nonce, time.Now()
		r.mu.Unlock()
		_, _ = r.pc.WriteToUDPAddrPort(proto.EncodeFrame(proto.FrameTypeRelayReg,
			proto.EncodeRelayChallenge(pub, nonce)), src)
	case proto.RelaySubProof:
		if lg == nil {
			r.bump(func(s *Stats) { s.Forged++ })
			return
		}
		gotNonce, mac, err := proto.DecodeRelayProof(payload)
		if err != nil {
			r.bump(func(s *Stats) { s.Forged++ })
			return
		}
		r.mu.Lock()
		if time.Since(lg.challAt) > challengeTTL || lg.nonce != gotNonce {
			r.mu.Unlock()
			r.bump(func(s *Stats) { s.Forged++ })
			return
		}
		dh, err := curve25519.X25519(lg.ephPriv[:], lg.pubkey[:])
		if err != nil {
			r.mu.Unlock()
			r.bump(func(s *Stats) { s.Forged++ })
			return
		}
		want := proto.RelayProofMAC(dh, lg.nonce, lg.pubkey)
		if subtle.ConstantTimeCompare(want, mac) != 1 {
			r.mu.Unlock()
			r.bump(func(s *Stats) { s.Forged++ })
			return
		}
		moved := lg.addr.IsValid() && lg.addr != src
		lg.verified, lg.addr, lg.last = true, src, time.Now()
		// 内存里的挑战私钥用完即弃
		lg.ephPriv = [32]byte{}
		var stale []assocKey
		if moved {
			// 后端换网/重映射：它的旧分配腿对端地址已变，全部作废重建
			for k, a := range r.assocs {
				if k.label == label {
					stale = append(stale, k)
					_ = a.sock.Close()
				}
			}
			for _, k := range stale {
				delete(r.assocs, k)
			}
		}
		r.stats.Registered++
		r.mu.Unlock()
		if moved {
			r.cfg.Logf("中继：后端 %x 注册腿地址变化 → %v（旧分配 %d 条已作废，等客户端重建）",
				label[:4], src, len(stale))
		} else {
			r.cfg.Logf("中继：后端 %x 注册成功（腿 %v）", label[:4], src)
		}
		_, _ = r.pc.WriteToUDPAddrPort(proto.EncodeFrame(proto.FrameTypeRelayReg, proto.EncodeRelayOK()), src)
	case proto.RelaySubKeepalive:
		if lg == nil || !lg.verified {
			// 腿不在了（中继刚重启/已过期）：明确让后端重注册 —— 否则它以为还在，只发保活，
			// 两边就永远对不上（实测踩过：中继重启后后端一直不重注册）。
			_, _ = r.pc.WriteToUDPAddrPort(proto.EncodeFrame(proto.FrameTypeRelayReg, proto.EncodeRelayAgain()), src)
			return
		}
		if lg.addr != src {
			// 换了地址的保活不算数：要求重新走一遍注册（防地址冒用）
			_, _ = r.pc.WriteToUDPAddrPort(proto.EncodeFrame(proto.FrameTypeRelayReg, proto.EncodeRelayAgain()), src)
			return
		}
		r.mu.Lock()
		lg.last = time.Now()
		r.mu.Unlock()
	default:
		r.bump(func(s *Stats) { s.Dropped++ })
	}
}

// forwardUp：客户端 → 后端（必要时新建分配 socket），并按需递送 hint。
func (r *Relay) forwardUp(client netip.AddrPort, lg *leg, typ byte, payload []byte) {
	key := assocKey{label: lg.label, client: client}
	r.mu.Lock()
	a := r.assocs[key]
	if a != nil && a.backend != lg.addr {
		// 后端注册腿换了地址（重映射）：老分配作废，重建
		_ = a.sock.Close()
		delete(r.assocs, key)
		a = nil
	}
	if a == nil {
		if r.countAssocsLocked(lg.label) >= r.cfg.MaxPerPeer {
			r.mu.Unlock()
			r.bump(func(s *Stats) { s.Dropped++ })
			r.cfg.Logf("中继：后端 %x 的分配腿已达上限 %d，丢弃新客户端 %v", lg.label[:4], r.cfg.MaxPerPeer, client)
			return
		}
		sock, err := net.ListenUDP("udp", nil)
		if err != nil {
			r.mu.Unlock()
			r.bump(func(s *Stats) { s.Dropped++ })
			return
		}
		a = &assoc{key: key, backend: lg.addr, sock: sock, last: time.Now()}
		r.assocs[key] = a
		r.stats.Assigned++
		r.mu.Unlock()
		go r.assocReadLoop(a)
		// 腿建立：两端各推一次对端观察地址（不可信线索）
		r.sendHintToClient(a, lg)
		r.sendHintToBackend(a, client)
		r.cfg.Logf("中继：客户端 %v 起一条分配腿 → 后端 %x（中继侧出口 %v）",
			client, lg.label[:4], a.sock.LocalAddr())
	} else {
		a.last = time.Now()
		r.mu.Unlock()
	}
	frame := proto.EncodeFrame(typ, payload)
	_, _ = a.sock.WriteToUDPAddrPort(frame, lg.addr)
	r.bump(func(s *Stats) { s.ForwardedUp++ })
}

// assocReadLoop：后端 → 客户端。后端回程是**裸 WG**（device 不知道帧），也可能带 hint 腿帧。
func (r *Relay) assocReadLoop(a *assoc) {
	buf := make([]byte, 65535)
	for {
		n, _, err := a.sock.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		pkt := buf[:n]
		frame := pkt
		if len(pkt) == 0 || pkt[0] != 0xBB {
			// 裸 WG：包成数据腿帧再发给客户端
			frame = proto.EncodeFrame(proto.FrameTypeData, pkt)
		}
		if _, err := r.pc.WriteToUDPAddrPort(frame, a.key.client); err != nil {
			return
		}
		r.mu.Lock()
		a.last = time.Now()
		r.mu.Unlock()
		r.bump(func(s *Stats) { s.ForwardedDown++ })
	}
}

// sendHintToClient：把**后端注册腿的源地址**告诉客户端（客户端据此打洞）。
func (r *Relay) sendHintToClient(a *assoc, lg *leg) {
	r.mu.Lock()
	addr := lg.addr
	r.mu.Unlock()
	if !addr.IsValid() {
		return
	}
	frame := proto.EncodeHint(addr.String())
	_, _ = r.pc.WriteToUDPAddrPort(frame, a.key.client)
}

// sendHintToBackend：把**客户端在中继眼里的源地址**告诉后端（后端据此盲打 + 学习）。
func (r *Relay) sendHintToBackend(a *assoc, client netip.AddrPort) {
	frame := proto.EncodeHint(client.String())
	_, _ = a.sock.WriteToUDPAddrPort(frame, a.backend)
}

// reapLoop：回收空闲分配腿 + 过期注册腿。
func (r *Relay) reapLoop(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now()
		var reclaim int
		r.mu.Lock()
		for k, a := range r.assocs {
			if now.Sub(a.last) > r.cfg.IdleTimeout {
				_ = a.sock.Close()
				delete(r.assocs, k)
				reclaim++
			}
		}
		r.stats.Reclaimed += uint64(reclaim)
		for label, lg := range r.legs {
			if lg.verified && now.Sub(lg.last) > r.cfg.LegTimeout {
				r.cfg.Logf("中继：后端 %x 注册腿过期（%v 无保活）—— 摘掉", label[:4], now.Sub(lg.last).Round(time.Second))
				for k, a := range r.assocs {
					if k.label == label {
						_ = a.sock.Close()
						delete(r.assocs, k)
					}
				}
				delete(r.legs, label)
			}
		}
		// 限流桶清理（窗口外的直接丢）
		for ip, b := range r.rates {
			if now.Sub(b.window) > 2*time.Second {
				delete(r.rates, ip)
			}
		}
		r.mu.Unlock()
		if reclaim > 0 {
			r.cfg.Logf("中继：回收 %d 条空闲分配腿（当前 %d 条）", reclaim, r.assocCount())
		}
	}
}

// statsLoop：分钟级统计一行（运维判据：转发量/分配数/丢弃数）。
func (r *Relay) statsLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		st := r.Stats()
		r.mu.Lock()
		legs, assocs := len(r.legs), len(r.assocs)
		r.mu.Unlock()
		r.cfg.Logf("中继统计：注册腿 %d（累计成功 %d，伪造 %d）｜分配腿 %d（累计 %d，回收 %d）｜转发 上 %d / 下 %d 包｜丢弃 %d",
			legs, st.Registered, st.Forged, assocs, st.Assigned, st.Reclaimed,
			st.ForwardedUp, st.ForwardedDown, st.Dropped)
	}
}

func (r *Relay) closeAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, a := range r.assocs {
		_ = a.sock.Close()
		delete(r.assocs, k)
	}
}

func (r *Relay) assocCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.assocs)
}

func (r *Relay) countAssocsLocked(label [8]byte) int {
	n := 0
	for k := range r.assocs {
		if k.label == label {
			n++
		}
	}
	return n
}

// allow：每源每秒包数限流（准入闸：防蹭转发资源/放大器）。
func (r *Relay) allow(ip netip.Addr) bool {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.rates[ip]
	if b == nil || now.Sub(b.window) >= time.Second {
		r.rates[ip] = &rateBucket{window: now, count: 1}
		return true
	}
	b.count++
	return b.count <= r.cfg.RateLimit
}

func (r *Relay) bump(f func(*Stats)) {
	r.mu.Lock()
	f(&r.stats)
	r.mu.Unlock()
}

func unmap(ap netip.AddrPort) netip.AddrPort {
	if ap.Addr().Is4In6() {
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return ap
}

// RegisterLeg：查一条注册腿是否在（测试/诊断）。
func (r *Relay) RegisterLeg(label [8]byte) (netip.AddrPort, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	lg := r.legs[label]
	if lg == nil || !lg.verified {
		return netip.AddrPort{}, false
	}
	return lg.addr, true
}
