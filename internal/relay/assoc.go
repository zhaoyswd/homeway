package relay

import (
	"crypto/rand"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
)

type assoc struct {
	key     assocKey
	backend netip.AddrPort // 注册腿地址（回程发给它；拨腿模式下 = 后端腿的实际源地址）
	sock    *net.UDPConn   // 该客户端专属的上游 socket（后端看到的"客户端地址"）
	last    time.Time      // 最近一次任一方向活动（空闲回收判据）
	// lastDown：最近一次**下行**（腿/后端方向到达）时刻。与 last 分开记：
	// 半死会话（上行活跃、下行恒零）光看 last 永远活着——DownSilent 用它判死。
	lastDown time.Time
	// 拨腿模式（relay-backend-dial）：等后端来拨。首包（LEGUP）到达前，
	// 客户端包缓冲在 pend（≤16）；到达后 backend = 腿源地址，缓冲放行。
	// dialed 是**持久**标志（本会话由拨腿承载——backend=腿源地址，与 lg.addr
	// 是两个概念，地址漂移检查不适用）；dialUp 只标「等待中」。
	// dialUpAt：等待开始时刻（DialWait 超时判据——后端拨腿失败不回报，
	// 中继侧必须自持看门狗，否则客户端上行会让会话悬挂到天荒地老）。
	sid      uint64
	dialed   bool
	dialUp   bool
	dialUpAt time.Time
	// 腿身份认证（review #3）：cookie 只经控制通道发给会话所属后端；拨腿首包必须
	// 回带 cookie+MAC，验过才认（authOK）。authSrc = 已认证的腿源（常态跟随它；
	// 换源必须重新出示合法认证——未知源不改变 backend、不放行 pend、不续命）。
	cookie  [16]byte
	authOK  bool
	authSrc netip.AddrPort
	pendMu  sync.Mutex
	pend    [][]byte
}

func (r *Relay) forwardUp(client netip.AddrPort, lg *leg, typ byte, payload []byte) {
	key := assocKey{label: lg.label, client: client}
	r.mu.Lock()
	a := r.assocs[key]
	if a != nil && !a.dialed && a.backend != lg.addr {
		// 后端注册腿换了地址（重映射）：老分配作废，重建。
		// 拨腿模式不适用：backend = 腿源地址（与 lg.addr 是两个概念，
		// 无 UDP 注册时 lg.addr 为零值，按它比对会恒不等 → 每包都拆会话重建。
		_ = a.sock.Close()
		delete(r.assocs, key)
		a = nil
	}
	if a == nil {
		// 无可达路径不建会话：既无 UDP 注册腿（lg.addr 无效）也无控制连接时，
		// 建了也只能指向零值地址（死会话，客户端首包竞态在控制面握手窗口里
		// 会踩中）——丢弃让客户端重试，等后端任一路径就绪。
		if !lg.addr.IsValid() && !r.hasControlLocked(lg) {
			r.mu.Unlock()
			r.bump(func(s *Stats) { s.Dropped++ })
			return
		}
		if r.countAssocsLocked(lg.label) >= r.cfg.MaxPerPeer {
			r.mu.Unlock()
			r.bump(func(s *Stats) { s.Dropped++ })
			r.cfg.Logf("中继：后端 %x 的分配腿已达上限 %d，丢弃新客户端 %v", lg.label[:], r.cfg.MaxPerPeer, client)
			return
		}
		sock, err := net.ListenUDP("udp", nil)
		if err != nil {
			r.mu.Unlock()
			r.bump(func(s *Stats) { s.Dropped++ })
			return
		}
		a = &assoc{key: key, backend: lg.addr, sock: sock, last: time.Now(), lastDown: time.Now()}
		// relay-backend-dial：有控制连接的后端走「通告 + 等拨腿」——
		// 不主动发往 lg.addr（严格 NAT 上恒不通），首包缓冲、等后端的认证 LEGUP。
		if r.hasControlLocked(lg) {
			r.nextSid++
			a.sid = r.nextSid
			a.dialUp = true
			a.dialed = true
			a.dialUpAt = time.Now()
			// 每会话随机 cookie（review #3）：只经控制通道发给该后端，
			// 拨腿首包必须回带 cookie+MAC 才被认作腿。
			if _, cerr := rand.Read(a.cookie[:]); cerr != nil {
				// 随机源失效（实践上不会发生）：**不**退化成全零 cookie 的"假认证"
				// （那会让 cookie 可预测、认证形同虚设）——拆掉本次会话让客户端
				// 重试，下一次多半能拿到正常随机数。会话尚未入表，直接关 socket。
				_ = sock.Close()
				r.mu.Unlock()
				r.bump(func(s *Stats) { s.Dropped++ })
				r.cfg.Logf("⚠️ 中继：会话随机数不可用（%v）——已放弃本次会话，客户端重试即可", cerr)
				return
			}
			a.authOK = false
		}
		r.assocs[key] = a
		r.stats.Assigned++
		sid, dialUp := a.sid, a.dialUp
		cookie := a.cookie
		r.mu.Unlock()
		go r.assocReadLoop(a)
		// 腿建立：两端各推一次对端观察地址（不可信线索）
		r.sendHintToClient(a, lg)
		r.sendHintToBackend(a, client)
		if dialUp {
			port := uint16(sock.LocalAddr().(*net.UDPAddr).Port)
			if r.announceSession(lg, proto.CtlSession{ID: sid, DataPort: port, Cookie: cookie}) {
				r.cfg.Logf("中继：客户端 %v 起会话 #%d（拨腿模式）→ 后端 %x（数据口 %v）",
					client, sid, lg.label[:], sock.LocalAddr())
			} else {
				// 通告失败（连接刚断）：这条会话没腿可等——回收掉，客户端重试会再触发
				_ = sock.Close()
				r.mu.Lock()
				delete(r.assocs, key)
				r.mu.Unlock()
				r.bump(func(s *Stats) { s.Dropped++ })
				return
			}
		} else {
			r.cfg.Logf("中继：客户端 %v 起一条分配腿 → 后端 %x（中继侧出口 %v）",
				client, lg.label[:], a.sock.LocalAddr())
		}
	} else {
		a.last = time.Now()
		r.mu.Unlock()
	}
	frame := proto.EncodeFrame(typ, payload)
	r.mu.Lock()
	if a.dialUp {
		// 等腿窗口：缓冲（上限外丢弃——QUIC 首包风暴也就 1-2 个包）
		a.pendMu.Lock()
		if len(a.pend) < ctlPendMax {
			a.pend = append(a.pend, frame)
			a.pendMu.Unlock()
			r.mu.Unlock()
			r.bump(func(s *Stats) { s.ForwardedUp++ })
			return
		}
		a.pendMu.Unlock()
		r.mu.Unlock()
		r.bump(func(s *Stats) { s.Dropped++ })
		return
	}
	dst := a.backend
	r.mu.Unlock()
	_, _ = a.sock.WriteToUDPAddrPort(frame, dst)
	r.bump(func(s *Stats) { s.ForwardedUp++ })
}

func (r *Relay) assocReadLoop(a *assoc) {
	buf := make([]byte, 65535)
	for {
		n, from, err := a.sock.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		pkt := buf[:n]
		from = unmap(from) // 与 readLoop 同款：4in6 映射形态统一成 v4，否则后续比较恒不等
		r.mu.Lock()
		now := time.Now()
		if a.sid != 0 {
			// ---- v2 拨腿会话：认证状态机 ----
			if a.authOK && a.authSrc == from {
				// 常态：已认证源的下行（数据腿帧或重发的 LEGUP 标记都算）。
				a.last, a.lastDown = now, now
				r.mu.Unlock()
			} else if c, isLegup := proto.LegupCookie(pkt); isLegup && c == a.cookie &&
				proto.VerifyLegupAuth(pkt, a.sid, a.cookie, r.legMACKey(a.cookie)) {
				// 合法认证：首拨（authOK=false，放行 pend）或已认证腿的重拨/换源
				//（控制重连重放后的再拨——源变了但 cookie 认得出来）。
				first := !a.authOK
				moved := a.authOK && a.authSrc != from
				a.authOK = true
				a.authSrc = from
				a.backend = from
				a.last, a.lastDown = now, now
				sid := a.sid // 锁内取值：replaySessions 会在 r.mu 下改写 a.sid（review 复审 b2）
				r.mu.Unlock()
				if first {
					r.mu.Lock()
					a.dialUp = false
					r.mu.Unlock()
					a.pendMu.Lock()
					pend := a.pend
					a.pend = nil
					a.pendMu.Unlock()
					for _, p := range pend {
						_, _ = a.sock.WriteToUDPAddrPort(p, from)
					}
				}
				if moved {
					r.cfg.Logf("中继：会话 #%d 的后端腿重拨 → %v（cookie 认证通过，跟随）", sid, from)
				}
			} else {
				// 未认证/未知源：丢弃并计数，不改变任何状态、不续命（#3）。
				r.stats.LegRejected++
				n := r.stats.LegRejected
				sid := a.sid // 同上：锁内取值
				rateOK := r.legRateOKLocked(from.Addr())
				r.mu.Unlock()
				if rateOK && legRejectLog(n) {
					r.cfg.Logf("中继：会话 #%d 收到未知源 %v 的包（%dB）—— 已拒绝（未认证不得成为腿；累计 %d 次）",
						sid, from, len(pkt), n)
				}
				continue
			}
		} else {
			// ---- v1 会话（sid==0，fallback：backend = lg.addr）----
			a.last, a.lastDown = now, now
			r.mu.Unlock()
		}
		// LEGUP 认证标记吞包（判定在分支外）：首腿、重拨腿与已认证源的重复标记
		// 都不外泄给对端（WG 层本也会丢弃，但别把标记泄出去）。
		if _, isLegup := proto.LegupCookie(pkt); isLegup {
			continue
		}
		// FIX-91：出口恒发腿帧（统一线格式）——中继不再做「裸 WG → 套帧」转换，
		// 原样转发（未知/畸形包由客户端侧按解码失败丢弃）。
		if _, err := r.pc.WriteToUDPAddrPort(pkt, a.key.client); err != nil {
			return
		}
		r.bump(func(s *Stats) { s.ForwardedDown++ })
	}
}

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

func (r *Relay) sendHintToBackend(a *assoc, client netip.AddrPort) {
	frame := proto.EncodeHint(client.String())
	// 持锁读 backend（review B5）：assocReadLoop 在锁内写它，裸读是数据竞争。
	r.mu.Lock()
	dst := a.backend
	r.mu.Unlock()
	if !dst.IsValid() {
		return // 拨腿等待中（无 backend 可发）
	}
	_, _ = a.sock.WriteToUDPAddrPort(frame, dst)
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
