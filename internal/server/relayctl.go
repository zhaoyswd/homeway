package server

// relayctl.go — relay-backend-dial 的出口侧控制客户端（任务 2.1）。
//
// 与中继的一条 TCP 长连：X25519 挑战（与 UDP 注册同一套 crypto/proto）、保活、
// 重连退避。收到 SESSION 通告 → 向中继数据口拨 connected UDP 腿（LEGUP）并注册进
// ServerBind 腿表；RELEASE → 拆腿。
//
// 失败语义：控制面全链路「尽力而为」——连不上/断了就退避重连，期间中继侧若无
// UDP 注册腿则新客户端不可达（老行为本来就是这样）；一切错误只记日志，绝不影响
// 出口主服务。

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
	"github.com/zhaoyswd/homeway/pkg/servercore"
	"golang.org/x/crypto/curve25519"
)

const (
	ctlDialTimeout    = 5 * time.Second
	ctlKeepaliveEvery = 25 * time.Second // 与中继侧 ctlReadTimeout（3×+15s）配套
	ctlReconnectMin   = 1 * time.Second
	ctlReconnectMax   = 30 * time.Second
)

// startControlClient：起控制面协程（非阻塞；随 ctx 收工）。
func startControlClient(ctx context.Context, bind *servercore.ServerBind, relay netip.AddrPort,
	priv [32]byte, pub [32]byte, relaySecret [32]byte, logf func(string, ...any)) {
	go func() {
		backoff := ctlReconnectMin
		for {
			if ctx.Err() != nil {
				return
			}
			err := runControlConn(ctx, bind, relay, priv, pub, relaySecret, logf)
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				logf("中继控制面断开（%v）—— %v 后重连", err, backoff)
			} else {
				logf("中继控制面退出 —— %v 后重连", backoff)
			}
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			backoff *= 2
			if backoff > ctlReconnectMax {
				backoff = ctlReconnectMax
			}
		}
	}()
}

// runControlClient 的一次完整连接生命周期（返回 = 连接结束）。
func runControlConn(ctx context.Context, bind *servercore.ServerBind, relay netip.AddrPort,
	priv [32]byte, pub [32]byte, relaySecret [32]byte, logf func(string, ...any)) error {

	d := net.Dialer{Timeout: ctlDialTimeout}
	conn, err := d.DialContext(ctx, "tcp", relay.String())
	if err != nil {
		return fmt.Errorf("拨控制通道: %w", err)
	}
	defer conn.Close()

	// ① HELLO
	if err := proto.CtlWriteMsg(conn, proto.EncodeRelayHello(pub)); err != nil {
		return fmt.Errorf("发 HELLO: %w", err)
	}
	// ② CHALLENGE → ③ PROOF
	typ, payload, err := proto.CtlReadMsg(conn)
	if err != nil {
		return fmt.Errorf("读 CHALLENGE: %w", err)
	}
	if typ != proto.RelaySubChallenge {
		return errors.New("控制面握手不是 CHALLENGE")
	}
	ephPub, nonce, cerr := proto.DecodeRelayChallenge(withSubtype(typ, payload))
	if cerr != nil {
		return fmt.Errorf("解析 CHALLENGE: %w", cerr)
	}
	dh, derr := curve25519.X25519(priv[:], ephPub[:])
	if derr != nil {
		return fmt.Errorf("算 DH: %w", derr)
	}
	var macPSK []byte
	if relaySecret != ([32]byte{}) {
		macPSK = proto.RelayAuthMAC(relaySecret, nonce, pub)
	}
	if err := proto.CtlWriteMsg(conn, proto.EncodeRelayProof(nonce, dh, pub, macPSK)); err != nil {
		return fmt.Errorf("发 PROOF: %w", err)
	}
	// ④ OK
	typ, payload, err = proto.CtlReadMsg(conn)
	if err != nil {
		return fmt.Errorf("读 OK: %w", err)
	}
	if typ != proto.RelaySubOK {
		return fmt.Errorf("控制面握手被拒（type=0x%02x）", typ)
	}
	logf("中继控制面已连（%v）—— SESSION 通告/拨腿模式启用", relay)

	// 保活 + 读循环（SESSION/RELEASE）。中继侧读超时 = 3×保活+15s，留足容错。
	keep := time.NewTicker(ctlKeepaliveEvery)
	defer keep.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-keep.C:
			}
			if err := proto.CtlWriteMsg(conn, proto.EncodeRelayKeepalive()); err != nil {
				_ = conn.Close() // 写失败：主循环读侧随之退出
				return
			}
		}
	}()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_ = conn.SetReadDeadline(time.Now().Add(3*ctlKeepaliveEvery + 15*time.Second))
		typ, payload, err := proto.CtlReadMsg(conn)
		if err != nil {
			return fmt.Errorf("控制面读: %w", err)
		}
		switch typ {
		case proto.RelayCtlSession:
			sess, serr := proto.DecodeCtlSession(withSubtype(typ, payload))
			if serr != nil {
				logf("中继控制面：SESSION 通告畸形（%v）—— 忽略", serr)
				continue
			}
			remote := netip.AddrPortFrom(relay.Addr().Unmap(), sess.DataPort)
			if rerr := bind.RegisterLeg(sess.ID, remote); rerr != nil {
				logf("中继控制面：会话 #%d 拨腿失败（→ %v）：%v", sess.ID, remote, rerr)
				continue
			}
			logf("中继控制面：会话 #%d 已拨腿 → %v", sess.ID, remote)
		case proto.RelayCtlRelease:
			id, rerr := proto.DecodeCtlRelease(withSubtype(typ, payload))
			if rerr != nil {
				continue
			}
			bind.RemoveLeg(id)
			logf("中继控制面：会话 #%d 已拆腿（RELEASE）", id)
		case proto.RelaySubKeepalive:
			// 中继方向的保活：无需处理（TCP 本身就是活性的证明）
		default:
			// 未知子类型：前向兼容忽略
		}
	}
}

// withSubtype：同 internal/relay（CtlReadMsg 的 payload 不含子类型字节）。
func withSubtype(typ byte, payload []byte) []byte {
	out := make([]byte, 0, 1+len(payload))
	out = append(out, typ)
	out = append(out, payload...)
	return out
}
