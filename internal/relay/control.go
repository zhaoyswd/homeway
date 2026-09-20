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
	"errors"
	"net"
	"sync"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
	"golang.org/x/crypto/curve25519"
)

// ctlKeepaliveEvery：后端侧保活节拍（与 UDP 注册腿一致；中继 3 倍容错）。
const ctlKeepaliveEvery = 25 * time.Second

// ctlReadTimeout：控制连接的读超时 = 3× 保活（超时即断，等后端重连）。
const ctlReadTimeout = 3 * ctlKeepaliveEvery + 15*time.Second

// ctlConn：一条已鉴权的控制连接（只允许串行写；读在专属协程）。
type ctlConn struct {
	c     net.Conn
	wmu   sync.Mutex
	label [8]byte
}

func (cc *ctlConn) writeMsg(msg []byte) error {
	cc.wmu.Lock()
	defer cc.wmu.Unlock()
	return proto.CtlWriteMsg(cc.c, msg)
}

func (cc *ctlConn) close() {
	_ = cc.c.Close()
}

// serveControl：TCP 接入循环（每连接一个协程跑 handshake+readLoop）。
func (r *Relay) serveControl(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go r.controlConn(c)
	}
}

// controlConn：一条控制连接的全生命周期。
func (r *Relay) controlConn(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second)) // 握手必须在 10s 内完成

	// ① HELLO（带公钥）
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

	// ③ PROOF（校验与 UDP 注册完全一致：DH MAC + token 模式的 PSK MAC）
	typ, payload, err = proto.CtlReadMsg(c)
	if err != nil || typ != proto.RelaySubProof {
		return
	}
	gotNonce, macDH, macPSK, err := proto.DecodeRelayProof(withSubtype(typ, payload))
	if err != nil || gotNonce != nonce {
		return
	}
	dh, derr := curve25519.X25519(ephPriv[:], pub[:])
	if derr != nil {
		return
	}
	if !hmacEqual(proto.RelayProofMAC(dh, nonce, pub), macDH) {
		r.bump(func(s *Stats) { s.Forged++ })
		r.cfg.Logf("中继：控制面 %v 的 DH 校验不过 —— 拒绝", c.RemoteAddr())
		return
	}
	if r.cfg.Secret != ([32]byte{}) {
		want := proto.RelayAuthMAC(r.cfg.Secret, nonce, pub)
		if len(macPSK) != 16 || !hmacEqual(want, macPSK) {
			r.bump(func(s *Stats) { s.Forged++ })
			r.cfg.Logf("中继：控制面 %v 的 token 校验不过 —— 拒绝", c.RemoteAddr())
			return
		}
	}

	// ④ OK + 挂到 leg（顶掉旧连接）
	if err := proto.CtlWriteMsg(c, proto.EncodeRelayOK()); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{}) // 清握手超时；后续用 readLoop 的滚动超时

	lg := r.legForControl(label, pub)
	// 控制面过的是与 UDP 注册同一套 X25519 挑战 ⇒ 身份证明等价，腿直接置 verified
	//（addr 仍空：hints/兼容转发照旧依赖 UDP 注册腿；数据走拨腿）。
	r.mu.Lock()
	lg.verified = true
	lg.last = time.Now()
	r.mu.Unlock()
	cc := &ctlConn{c: c, label: label}
	r.attachControl(lg, cc)
	defer func() {
		r.detachControl(lg, cc)
		// 孤儿清理：控制断开时腿若既无 UDP 注册（verified=false 且无 addr）也无新
		// 控制连接，就是纯控制 leg 的尸体——从表里摘掉，防泄漏。
		r.mu.Lock()
		if lg.ctl == nil && !lg.verified && !lg.addr.IsValid() {
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
		default:
			// 后端→中继方向目前没有其它消息；未知子类型按前向兼容忽略。
		}
	}
}

// legForControl：按 label 找（或建）leg。控制面建立的 leg 没有 UDP 地址，
// 仍允许 —— dataPort 拨腿模式不需要 lg.addr；hints/兼容路径照旧依赖 UDP 注册。
func (r *Relay) legForControl(label [8]byte, pub [32]byte) *leg {
	r.mu.Lock()
	defer r.mu.Unlock()
	lg := r.legs[label]
	if lg == nil {
		lg = &leg{label: label, pubkey: pub}
		r.legs[label] = lg
	}
	return lg
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

// releaseSession：通告会话回收（尽力而为；连接已断就跳过）。
func (r *Relay) releaseSession(lg *leg, id uint64) {
	r.mu.Lock()
	cc := lg.ctl
	r.mu.Unlock()
	if cc != nil {
		_ = cc.writeMsg(proto.EncodeCtlRelease(id))
	}
}

func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// ErrNoControlConn：无控制连接（兼容路径继续走 per-client 敲洞）。
var ErrNoControlConn = errors.New("relay: 后端无控制连接")

// withSubtype：CtlReadMsg 的 payload 去掉了子类型字节，而 proto 的 RelaySub*
// 编解码以「子类型 + 载荷」整条为对象 —— 拼回去再解。
func withSubtype(typ byte, payload []byte) []byte {
	out := make([]byte, 0, 1+len(payload))
	out = append(out, typ)
	out = append(out, payload...)
	return out
}
