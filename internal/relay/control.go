package relay

// control.go — relay-backend-dial 的中继侧控制面。
//
// TCP 监听与 UDP 同号（一个端口号的 TCP/UDP 是两个独立端口空间 ⇒ 部署零新增、
// token 不变）。每个后端一条控制长连；鉴权与 UDP 注册腿**同一套** X25519 挑战
// （复用 proto.RelaySub* 与 RelayProofMAC）——控制通道必须证明持有 peerId 私钥，
// 否则拿到 rl1 token 的任何人都能冒领别人的 SESSION 通告（DoS 真后端）。
//
// 鉴权通过后：
//   - 控制连接挂到对应 leg（lg.ctl）；后端 KEEPALIVE 同时刷新 lg.last（腿不过期）；
//   - 客户端到达时 forwardUp 经 lg.ctl 发 SESSION 通告并缓冲首包，等后端拨腿；
//   - 分配回收时发 RELEASE。
// 同一后端的新控制连接**顶掉**旧连接（重连语义）；控制断开不清 leg（UDP 注册腿
// 可能还活着），只清 ctl——转发改回旧路径（若有 UDP 腿）或等重连。

import (
	"crypto/rand"
	"crypto/subtle"
	"net"
	"sync"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
	"golang.org/x/crypto/curve25519"
)

// ctlKeepaliveEvery：后端侧保活节拍（与 UDP 注册腿一致；中继 3 倍容错）。
const ctlKeepaliveEvery = 25 * time.Second

// ctlReadTimeout：控制连接的读超时 = 3× 保活（超时即断，等后端重连）。
const ctlReadTimeout = 3*ctlKeepaliveEvery + 15*time.Second

// ctlConn：一条已鉴权的控制连接（只允许串行写；读在专属协程）。
type ctlConn struct {
	c   net.Conn
	wmu sync.Mutex
}

func (cc *ctlConn) writeMsg(msg []byte) error {
	cc.wmu.Lock()
	defer cc.wmu.Unlock()
	return proto.CtlWriteMsg(cc.c, msg)
}

func (cc *ctlConn) close() {
	_ = cc.c.Close()
}

// ctlHandshakeMax：**握手中**的并发上限（review B7②：每个未完成握手占一个协程
// 最长 10s，公网中继防「慢握手洪水」）。
// review #7 勘误：旧实现把这个计数当成「连接数」——Add(-1) 挂在 controlConn 的
// defer 上、要到连接退出才释放 ⇒ 16 条空闲的已认证连接就把第 17 个后端的握手
// 挡在门外（且拒绝时一行日志都没有）。现在**握手完成即释放**，长连改由
// ctlEstablished（总数上限）约束。
const ctlHandshakeMax = 16

// serveControl：TCP 接入循环（每连接一个协程跑 handshake+readLoop）。
func (r *Relay) serveControl(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		if r.ctlHandshaking.Add(1) > ctlHandshakeMax {
			r.ctlHandshaking.Add(-1)
			_ = c.Close()
			r.bump(func(s *Stats) { s.Dropped++ })
			r.cfg.Logf("中继：并发握手上限 %d 已满，拒绝 %v（慢握手洪水防护）", ctlHandshakeMax, c.RemoteAddr())
			continue
		}
		go r.controlConn(c)
	}
}

// controlConn：一条控制连接的全生命周期。
func (r *Relay) controlConn(c net.Conn) {
	// #7：握手槽**只在握手中占用**——成功即释放（移出 defer 作用域），
	// 失败/断开由这里的 defer 兜底（用 handshaking 标志防双释放）。
	handshaking := true
	defer func() {
		if handshaking {
			r.ctlHandshaking.Add(-1)
		}
	}()
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second)) // 握手必须在 10s 内完成

	// ① HELLO（带公钥；形状与 v1 完全一致——版本不自报在这里，见 EncodeRelayProofV 注释）
	typ, payload, err := proto.CtlReadMsg(c)
	if err != nil || typ != proto.RelaySubHello {
		return
	}
	pub, err := proto.DecodeRelayHello(withSubtype(typ, payload))
	if err != nil {
		return
	}
	label := proto.RelayID(pub)

	// ② CHALLENGE（临时公钥 + nonce；与 UDP 注册同款）
	var ephPriv, ephPub [32]byte
	if _, err := rand.Read(ephPriv[:]); err != nil {
		return
	}
	curve25519.ScalarBaseMult(&ephPub, &ephPriv)
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return
	}
	if err := proto.CtlWriteMsg(c, proto.EncodeRelayChallenge(ephPub, nonce)); err != nil {
		return
	}

	// ③ PROOF（校验与 UDP 注册完全一致：DH MAC + token 模式的 PSK MAC）。
	// 末尾 1 字节 = 对端协议版本（50B = v2；49B/33B = v1，#25）。
	typ, payload, err = proto.CtlReadMsg(c)
	if err != nil || typ != proto.RelaySubProof {
		return
	}
	gotNonce, macDH, macPSK, ver, err := proto.DecodeRelayProof(withSubtype(typ, payload))
	if err != nil || gotNonce != nonce {
		return
	}
	dh, derr := curve25519.X25519(ephPriv[:], pub[:])
	if derr != nil {
		return
	}
	if subtle.ConstantTimeCompare(proto.RelayProofMAC(dh, nonce, pub), macDH) != 1 {
		r.bump(func(s *Stats) { s.Forged++ })
		r.cfg.Logf("中继：控制面 %v 的 DH 校验不过 —— 拒绝", c.RemoteAddr())
		return
	}
	if r.cfg.Secret != ([32]byte{}) {
		want := proto.RelayAuthMAC(r.cfg.Secret, nonce, pub)
		if len(macPSK) != 16 || subtle.ConstantTimeCompare(want, macPSK) != 1 {
			r.bump(func(s *Stats) { s.Forged++ })
			r.cfg.Logf("中继：控制面 %v 的 token 校验不过 —— 拒绝", c.RemoteAddr())
			return
		}
	}

	// ④ 已建立控制连接总数上限（#7/#18：认证长连各占一个读协程，要有总闸）。
	if r.ctlEstablished.Add(1) > int32(r.cfg.MaxCtlConns) {
		r.ctlEstablished.Add(-1)
		r.bump(func(s *Stats) { s.Dropped++ })
		r.cfg.Logf("中继：已建立控制连接达上限 %d，拒绝 %v（label %x）", r.cfg.MaxCtlConns, c.RemoteAddr(), label[:])
		return
	}
	estab := true
	defer func() {
		if estab {
			r.ctlEstablished.Add(-1)
		}
	}()

	// ⑤ OK + 挂到 leg（顶掉旧连接）。v2 后端 + token 模式：OK 带 MAC 让后端
	// 认证中继（#29——此前任何能截 TCP 的角色都能发 OK 再喂假 SESSION）。
	okMsg := proto.EncodeRelayOK()
	if ver >= proto.RelayCtlVer && r.cfg.Secret != ([32]byte{}) {
		okMsg = proto.EncodeRelayOKAuth(proto.RelayOKAuthMAC(r.cfg.Secret, nonce))
	}
	if err := proto.CtlWriteMsg(c, okMsg); err != nil {
		return
	}
	r.ctlHandshaking.Add(-1) // 握手完成：释放并发槽（#7）
	handshaking = false
	_ = c.SetDeadline(time.Time{}) // 清握手超时；后续用 readLoop 的滚动超时

	lg, ok := r.legForControl(label, pub)
	if !ok {
		// 腿数达上限（#18：控制路径此前不受 MaxLegs 闸）
		return
	}
	// 控制面过的是与 UDP 注册同一套 X25519 挑战 ⇒ 身份证明等价，但记在
	// ctlVerified（与 UDP 的 verified 分开——review B4：混用会让孤儿清理的
	// !verified 恒假，且两种证明语义不同）。
	r.mu.Lock()
	lg.ctlVerified = true
	lg.ctlV2 = ver >= proto.RelayCtlVer
	lg.last = time.Now()
	r.mu.Unlock()
	cc := &ctlConn{c: c}
	r.attachControl(lg, cc)
	// 重放对账（review B1）：重连 = 后端已 ClearLegs，中继把该 label 的全部活跃
	// 会话重新通告一遍，后端按重放重建腿——中继重启（表空 → 重放零条 = 后端清空）、
	// 控制连接抖动（表还在 → 原样重建）两条路径都靠它收敛。
	r.replaySessions(lg, cc)
	defer func() {
		r.detachControl(lg, cc)
		// 孤儿清理（review C2 收敛）：纯控制腿的尸体——既无 UDP 注册（verified=false
		// 且无 addr）也无新控制连接，**且没有任何活跃会话**——才立即删。有会话的腿
		// 留给 reapLoop 的 LegTimeout 路径（90s）：控制 TCP 瞬断时立刻删腿会让该
		// 后端全部会话的上行立刻被丢（下行还挂在 assoc 上），比留到超时更伤。
		r.mu.Lock()
		if lg.ctl == nil && !lg.verified && !lg.addr.IsValid() && r.countAssocsLocked(lg.label) == 0 {
			delete(r.legs, lg.label)
		}
		r.mu.Unlock()
	}()
	r.cfg.Logf("中继：后端 %x 控制面就绪（%v；SESSION 通告启用拨腿模式）", label[:], c.RemoteAddr())
	r.readControlLoop(lg, cc, c)
}

// readControlLoop：控制连接的读循环（KEEPALIVE 刷新腿；未知消息忽略——前向兼容）。
func (r *Relay) readControlLoop(lg *leg, cc *ctlConn, c net.Conn) {
	for {
		_ = c.SetReadDeadline(time.Now().Add(ctlReadTimeout))
		typ, _, err := proto.CtlReadMsg(c)
		if err != nil {
			return
		}
		switch typ {
		case proto.RelaySubKeepalive:
			r.mu.Lock()
			lg.last = time.Now()
			r.mu.Unlock()
			// 回发一个 KEEPALIVE（review B3）：后端读侧 deadline = 3×保活+15s，
			// 无会话事件时若中继永远静默，后端每 ~90s 空转重连一次（且每次重连
			// 叠加 B2 的泄漏）。被动回显模式——后端 25s 发、中继必答，链路双向
			// 始终有消息，无需中继自持 ticker。
			if err := cc.writeMsg(proto.EncodeRelayKeepalive()); err != nil {
				return
			}
		default:
			// 后端→中继方向目前没有其它消息；未知子类型按前向兼容忽略。
		}
	}
}

// legForControl：按 label 找（或建）leg。控制面建立的 leg 没有 UDP 地址，
// 仍允许 —— dataPort 拨腿模式不需要 lg.addr；hints/兼容路径照旧依赖 UDP 注册。
// last=now：未验证腿的注册窗口起点——reapLoop 的 legBootstrap 分支据此放行
// 握手期（TCP 挑战 deadline 10s；零值 last 会被 5s 一轮的 reap 立即摘掉）。
func (r *Relay) legForControl(label [8]byte, pub [32]byte) (*leg, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	lg := r.legs[label]
	if lg == nil {
		// #18：控制路径建腿也过 MaxLegs 闸（与 UDP Hello 同一道防线——
		// 否则持凭证者可经 TCP 把腿表灌爆，绕过匿名洪水防护的上限语义）。
		if len(r.legs) >= r.cfg.MaxLegs {
			r.stats.Denied++ // 持锁内直接计（bump 会再 Lock——当场死锁）
			r.cfg.Logf("中继：注册腿总数已达上限 %d，拒绝控制面新腿 %x", r.cfg.MaxLegs, label[:])
			return nil, false
		}
		lg = &leg{label: label, pubkey: pub, last: time.Now()}
		r.legs[label] = lg
	}
	return lg, true
}

// attachControl：挂控制连接（顶掉旧连接；新连接生效）。
func (r *Relay) attachControl(lg *leg, cc *ctlConn) {
	r.mu.Lock()
	old := lg.ctl
	lg.ctl = cc
	r.mu.Unlock()
	if old != nil {
		old.close() // 顶掉：旧连接的读循环会因关闭而退出，detach 只认现任
	}
}

// detachControl：仅在 cc 仍是现任时摘除（旧连接的延迟退出不误摘新连接）。
func (r *Relay) detachControl(lg *leg, cc *ctlConn) {
	r.mu.Lock()
	if lg.ctl == cc {
		lg.ctl = nil
	}
	r.mu.Unlock()
}

// announceSession：经控制通道通告新会话（调用方持有 assoc 上下文）。
func (r *Relay) announceSession(lg *leg, sess proto.CtlSession) bool {
	r.mu.Lock()
	cc := lg.ctl
	r.mu.Unlock()
	if cc == nil {
		return false
	}
	if err := cc.writeMsg(proto.EncodeCtlSession(sess)); err != nil {
		cc.close() // 写失败即断：等后端重连
		return false
	}
	return true
}

// replaySessions：向（新建立的）控制连接重放该后端的全部活跃会话。
//
// sid==0 的 fallback 会话（控制空窗期建立、走 lg.addr 旧敲洞路径）在这里被
// **提升**而非跳过（review D1）：分配全新 sid、切到拨腿模式（dialUp=true，后续
// 客户端包进等腿缓冲）并通告。这是唯一干净的收敛路径——否则严格 NAT 后端的
// fallback 会话在旧路径上恒不可达，而客户端持续重试让 a.last 一直新鲜，空闲
// 回收永不触发，要等手机侧巡检 3 连败自愈（分钟级）。公共出口（旧路径本来通）
// 的会话也被统一提升，短暂等腿（一轮通告+拨腿，几十 ms）后继续。
func (r *Relay) replaySessions(lg *leg, cc *ctlConn) {
	if !lg.ctlV2 {
		return // v1 控制连接：解不开 v2 SESSION，也没有拨腿会话要重放（#25）
	}
	r.mu.Lock()
	type pending struct {
		msg   []byte
		assoc *assoc
	}
	var out []pending
	for _, a := range r.assocs {
		if a.key.label != lg.label {
			continue
		}
		if a.sid == 0 {
			// 提升：拿全新会话号（不是 0——多条 id=0 会互相顶掉，且 RELEASE
			// 语义要求 sid!=0），切拨腿模式。通告成功与否在锁外验证，失败则
			// 回滚成 fallback（下次重连再试）。dialUpAt 从提升时刻起算——
			// 拨腿等待超时（DialWait）按它判。
			r.nextSid++
			a.sid = r.nextSid
			a.dialUp = true
			a.dialed = true
			a.dialUpAt = time.Now()
			// 提升会话换新 cookie（#3）：重放 = 后端已 ClearLegs，等它带新认证重拨。
			if _, cerr := rand.Read(a.cookie[:]); cerr == nil {
				a.authOK = false
			}
		}
		port := uint16(a.sock.LocalAddr().(*net.UDPAddr).Port)
		out = append(out, pending{msg: proto.EncodeCtlSession(proto.CtlSession{
			ID: a.sid, DataPort: port, Cookie: a.cookie, HasCookie: true}), assoc: a})
	}
	r.mu.Unlock()
	sent := 0
	for _, p := range out {
		if err := cc.writeMsg(p.msg); err != nil {
			cc.close()
			// 通告失败：**从失败那条起**回滚剩余的提升（已成功发出的算数——后端会拨腿，
			// assocReadLoop 的 LEGUP/认证分支会完成交接）。失败这条自己也没送达，
			// 不回滚的话它会停在「dialUp + 已提升」但后端从未收到通告的状态：
			// 客户端上行进 pend 缓冲、要等 DialWait 看门狗 15s 后才回收
			//（review 复审修正：此前是 out[sent+1:]，漏掉失败那条）。
			r.mu.Lock()
			for _, q := range out[sent:] {
				if q.assoc.dialUp && q.assoc.sid != 0 && q.assoc.key.label == lg.label {
					q.assoc.sid = 0
					q.assoc.dialUp = false
					q.assoc.dialed = false
				}
			}
			r.mu.Unlock()
			return
		}
		sent++
	}
	if len(out) > 0 {
		r.cfg.Logf("中继：后端 %x 控制面重放 %d 条活跃会话", lg.label[:], len(out))
	}
}

// releaseSession：通告会话回收。写失败即关连接（review #36，与 announceSession
// 对齐）：半死的 TCP 上 RELEASE 会一直丢，后端的腿只能等空闲回收；关掉逼后端
// 重连，重连后的重放对账把两边状态拉齐。
func (r *Relay) releaseSession(lg *leg, id uint64) {
	r.mu.Lock()
	cc := lg.ctl
	r.mu.Unlock()
	if cc != nil {
		if err := cc.writeMsg(proto.EncodeCtlRelease(id)); err != nil {
			cc.close()
		}
	}
}

// withSubtype：CtlReadMsg 的 payload 去掉了子类型字节，而 proto 的 RelaySub*
// 编解码以「子类型 + 载荷」整条为对象 —— 拼回去再解。
func withSubtype(typ byte, payload []byte) []byte {
	out := make([]byte, 0, 1+len(payload))
	out = append(out, typ)
	out = append(out, payload...)
	return out
}
