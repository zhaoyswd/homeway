package relay

import (
	"crypto/rand"
	"crypto/subtle"
	"net/netip"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
	"golang.org/x/crypto/curve25519"
)

type leg struct {
	label    [8]byte
	pubkey   [32]byte
	addr     netip.AddrPort // 注册腿源地址（后端公网映射，也是给客户端的 hint）
	last     time.Time
	ephPriv  [32]byte
	nonce    [16]byte
	challAt  time.Time
	verified bool
	// ctlVerified：控制面（TCP 挑战）认证过。与 verified（UDP 注册挑战）是**两种
	// 证明**，转发准入与过期判定用「任一」——不再让控制面认证直接置 verified，
	// 否则孤儿清理的 !verified 恒假成死代码（review B4）。
	ctlVerified bool
	// ctl：控制通道（relay-backend-dial）。非 nil 时客户端到达走「通告+等后端拨腿」，
	// 而不是 per-client socket 主动发往 lg.addr（那条路在严格 NAT 上恒不通）。
	// FIX-89 起控制面恒为 v2（版本不符已在握手期拒绝）——不再有 ctlV2 判定。
	ctl *ctlConn
}

type assocKey struct {
	label  [8]byte
	client netip.AddrPort
}

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
		if cur == nil {
			if len(r.legs) >= r.cfg.MaxLegs {
				r.mu.Unlock()
				r.bump(func(s *Stats) { s.Denied++ })
				r.cfg.Logf("中继：注册腿总数已达上限 %d，拒绝新的 %x（防匿名洪水）", r.cfg.MaxLegs, label[:])
				return
			}
			cur = &leg{label: label, last: time.Now()} // last=now：未验证腿的注册窗口起点（见 reapLoop 的 legBootstrap 分支）
			r.legs[label] = cur
		}
		// **复用既有对象，绝不替换**（review #2，高危）：腿上可能挂着长生命周期子状态
		// （ctl 控制连接 / ctlVerified）。替换成新对象会让 ctl 指向脱离 map 的旧对象——
		// 通告与重放全走新对象（无 ctl ⇒ 拨腿模式静默退化回旧敲洞路径），而孤儿控制
		// 连接还在被回 KEEPALIVE、后端永不重连，两边日志全是"健康"的。中继重启后
		// （控制先连、UDP Hello 后到）近乎必然踩中。
		cur.pubkey = pubkey
		cur.ephPriv, cur.nonce, cur.challAt = ephPriv, nonce, time.Now()
		r.mu.Unlock()
		_, _ = r.pc.WriteToUDPAddrPort(proto.EncodeFrame(proto.FrameTypeRelayReg,
			proto.EncodeRelayChallenge(pub, nonce)), src)
	case proto.RelaySubProof:
		if lg == nil {
			r.bump(func(s *Stats) { s.Forged++ })
			return
		}
		gotNonce, macDH, macPSK, ver, err := proto.DecodeRelayProof(payload)
		if err != nil {
			r.bump(func(s *Stats) { s.Forged++ })
			return
		}
		// 协议版本门（FIX-89，v2-only）：UDP 注册腿与 TCP 控制面同版本判定，
		// 版本不符即拒（老后端/未来版本都不再被静默容纳）。
		if ver != proto.RelayCtlVer {
			r.bump(func(s *Stats) { s.Forged++ })
			r.cfg.Logf("中继：后端 %x 注册证明协议版本 %d 不符（需要 %d）—— 拒绝", label[:], ver, proto.RelayCtlVer)
			return
		}
		r.mu.Lock()
		if r.legs[label] != lg {
			// 挑战发出后腿被摘/被换（#2 的守卫）：旧对象上的证明不再作数。
			r.mu.Unlock()
			r.bump(func(s *Stats) { s.Forged++ })
			return
		}
		if time.Since(lg.challAt) > challengeTTL || lg.nonce != gotNonce {
			r.mu.Unlock()
			r.bump(func(s *Stats) { s.Forged++ })
			return
		}
		var dh []byte
		if r.cfg.Open {
			dh, err = curve25519.X25519(lg.ephPriv[:], lg.pubkey[:])
			if err != nil {
				r.mu.Unlock()
				r.bump(func(s *Stats) { s.Forged++ })
				return
			}
		}
		// token 模式只认鉴权 MAC（DH 谁都算得出来，不能当准入）；开放模式看 DH。
		if !r.cfg.Open {
			want := proto.RelayAuthMAC(r.cfg.Secret, lg.nonce, lg.pubkey)
			if len(macPSK) != 16 || subtle.ConstantTimeCompare(want, macPSK) != 1 {
				r.mu.Unlock()
				r.bump(func(s *Stats) { s.Forged++ })
				r.cfg.Logf("中继：后端 %x 的 token 校验不过（密钥不对/没带 token）—— 拒绝", label[:])
				return
			}
		} else {
			want := proto.RelayProofMAC(dh, lg.nonce, lg.pubkey)
			if subtle.ConstantTimeCompare(want, macDH) != 1 {
				r.mu.Unlock()
				r.bump(func(s *Stats) { s.Forged++ })
				return
			}
		}
		moved := lg.addr.IsValid() && lg.addr != src
		lg.verified, lg.addr, lg.last = true, src, time.Now()
		// 内存里的挑战私钥用完即弃
		lg.ephPriv = [32]byte{}
		var stale []assocKey
		var staleSids []uint64
		if moved {
			// 后端换网/重映射：它的旧分配腿对端地址已变，全部作废重建。
			// 拨腿会话补发 RELEASE（review B1）：后端侧的腿等它重拨/重放对账。
			for k, a := range r.assocs {
				if k.label == label {
					stale = append(stale, k)
					if a.sid != 0 {
						staleSids = append(staleSids, a.sid)
					}
					_ = a.sock.Close()
				}
			}
			for _, k := range stale {
				delete(r.assocs, k)
			}
		}
		r.stats.Registered++
		r.mu.Unlock()
		for _, sid := range staleSids {
			r.releaseSession(lg, sid)
		}
		if moved {
			r.cfg.Logf("中继：后端 %x 注册腿地址变化 → %v（旧分配 %d 条已作废，等客户端重建）",
				label[:], src, len(stale))
		} else {
			r.cfg.Logf("中继：后端 %x 注册成功（腿 %v）", label[:], src)
		}
		_, _ = r.pc.WriteToUDPAddrPort(proto.EncodeFrame(proto.FrameTypeRelayReg, proto.EncodeRelayOK()), src)
	case proto.RelaySubKeepalive:
		if lg == nil || !(lg.verified || lg.ctlVerified) {
			// 腿不在了（中继刚重启/已过期）：明确让后端重注册 —— 否则它以为还在，只发保活，
			// 两边就永远对不上（实测踩过：中继重启后后端一直不重注册）。
			_, _ = r.pc.WriteToUDPAddrPort(proto.EncodeFrame(proto.FrameTypeRelayReg, proto.EncodeRelayAgain()), src)
			return
		}
		if lg.addr.IsValid() && lg.addr != src {
			// 换了地址的保活不算数：要求重新走一遍注册（防地址冒用）。
			_, _ = r.pc.WriteToUDPAddrPort(proto.EncodeFrame(proto.FrameTypeRelayReg, proto.EncodeRelayAgain()), src)
			return
		}
		if !lg.addr.IsValid() {
			// 无 UDP 注册（纯控制腿）的保活（FIX-68）：addr 无从比对，但**不能**无条件
			// 续命——此前任何人知道 label 就能发一个「影子保活」把这条腿永久占住
			//（占腿额、还把真后端的注册用 Again 挡回）。判据：必须挂着控制连接，且保活
			// 源 IP 与控制连接同 IP（端口可不同：TCP/UDP 各自随机）。
			if lg.ctl == nil || !sameIPAsControl(lg.ctl, src) {
				_, _ = r.pc.WriteToUDPAddrPort(proto.EncodeFrame(proto.FrameTypeRelayReg, proto.EncodeRelayAgain()), src)
				return
			}
			// 有活控制连接且同 IP：静默续命（回 Again 只会让后端无意义地重注册刷屏，
			// review B7③ 的原意保留）。
		}
		r.mu.Lock()
		lg.last = time.Now()
		r.mu.Unlock()
	default:
		r.bump(func(s *Stats) { s.Dropped++ })
	}
}

func (r *Relay) hasControlLocked(lg *leg) bool {
	return lg != nil && lg.ctl != nil
}

func (r *Relay) legMACKey(cookie [16]byte) [32]byte {
	if !r.cfg.Open {
		return r.cfg.Secret
	}
	var k [32]byte
	copy(k[:16], cookie[:])
	return k
}

func legRejectLog(n uint64) bool {
	return n <= 3 || n%100 == 0
}

func (r *Relay) RegisterLeg(label [8]byte) (netip.AddrPort, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	lg := r.legs[label]
	if lg == nil || !(lg.verified || lg.ctlVerified) {
		return netip.AddrPort{}, false
	}
	return lg.addr, true
}

func sameIPAsControl(cc *ctlConn, src netip.AddrPort) bool {
	ra := cc.c.RemoteAddr()
	if ra == nil {
		return false
	}
	ap, err := netip.ParseAddrPort(ra.String())
	if err != nil {
		return false
	}
	return ap.Addr().Unmap() == src.Addr().Unmap()
}
