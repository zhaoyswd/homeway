package wtransport

// wg-native-stack tasks 2.3 集成测试：三场景（direct 可达 / 仅 relay 可达 / 全哑退避→恢复），
// 真 wireguard-go device 双端 + 真 UDP。测试内自带最小服务端/中继 harness
// （与 homeway internal/server 同语义：reg 验证→动态 AddPeer→数据透传），不跨模块引 internal。

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/files"
	"github.com/zhaoyswd/homeway/pkg/intercept"
	"github.com/zhaoyswd/homeway/pkg/probe"
	"github.com/zhaoyswd/homeway/pkg/proto"
	"github.com/zhaoyswd/homeway/pkg/term"
	"github.com/zhaoyswd/homeway/pkg/wgnet"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	srvTunnelIP = "100.64.255.1" // 后端隧道 IP（名义值，客户端 allowed_ip 用）
	cliTunnelIP = "100.64.0.1"   // 服务端给客户端分配的隧道 IP
)

// ---------- 最小服务端 harness ----------

type srvHarness struct {
	dev    *device.Device
	tun    *tuntest.ChannelTUN
	bind   *srvBind
	priv   wgtypes.Key
	secret [32]byte
	psk    [32]byte
	cliPub [32]byte
	// cliPubMu：cliPub / allowIP 的同步（harness 竞态：客户端栈起来后 REG 可能已到、
	// 注册 Once 在接收 goroutine 里读，而测试主 goroutine 这时才写这两个字段——
	// allowIP 同因纳入本锁，CI -race 首跑实拍）。
	cliPubMu sync.Mutex
	allowIP  netip.Addr // 登记给客户端的 allowed_ip；零值 = 用固定 cliTunnelIP（场景①–③）
	once     sync.Once
}

func newSrvHarness(t *testing.T, secret [32]byte, port uint16) *srvHarness {
	t.Helper()
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return newSrvHarnessWithKey(t, priv, secret, port)
}

// newSrvHarnessWithKey：用指定静态身份起服务端——「后端换址不换身份」的场景用（tasks 2.5）。
func newSrvHarnessWithKey(t *testing.T, priv wgtypes.Key, secret [32]byte, port uint16) *srvHarness {
	t.Helper()
	h := &srvHarness{priv: priv, secret: secret, psk: proto.DerivePSK(secret)}
	h.tun = tuntest.NewChannelTUN()
	h.bind = &srvBind{h: h}
	h.dev = device.NewDevice(h.tun.TUN(), h.bind, device.NewLogger(device.LogLevelError, "srv"))
	t.Cleanup(func() { h.dev.Close() })
	if err := h.dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", hex.EncodeToString(priv[:]), port)); err != nil {
		t.Fatal(err)
	}
	if err := h.dev.Up(); err != nil {
		t.Fatal(err)
	}
	return h
}

// reg 到达时动态登记客户端 peer（幂等 once——同公钥重复 reg 只刷时间戳的等价简化）。
// allowed_ip 用**两端各自派生**的隧道地址（tasks 3.7）——与 homeway internal/server 的
// PeerTable.Register 同语义：客户端拿自己的临时公钥算、后端从 reg 学到的公钥算。
func (h *srvHarness) setClientPub(k wgtypes.Key) {
	h.cliPubMu.Lock()
	copy(h.cliPub[:], k[:])
	h.cliPubMu.Unlock()
}

func (h *srvHarness) clientPubSlice() []byte {
	h.cliPubMu.Lock()
	defer h.cliPubMu.Unlock()
	return append([]byte(nil), h.cliPub[:]...)
}

// setAllowIP：写 allowIP（与接收 goroutine 的读同锁，见 cliPubMu 注释）。
func (h *srvHarness) setAllowIP(ip netip.Addr) {
	h.cliPubMu.Lock()
	h.allowIP = ip
	h.cliPubMu.Unlock()
}

// allowIPSnapshot：读 allowIP（锁内取）。
func (h *srvHarness) allowIPSnapshot() netip.Addr {
	h.cliPubMu.Lock()
	defer h.cliPubMu.Unlock()
	return h.allowIP
}

func (h *srvHarness) registerClient() {
	h.once.Do(func() {
		ip := h.allowIPSnapshot()
		if !ip.IsValid() {
			ip = netip.MustParseAddr(cliTunnelIP)
		}
		_ = h.dev.IpcSet(fmt.Sprintf(
			"public_key=%s\npreshared_key=%s\nallowed_ip=%s/32\n",
			hex.EncodeToString(h.clientPubSlice()), hex.EncodeToString(h.psk[:]), ip))
	})
}

type srvBind struct {
	h *srvHarness
	c *net.UDPConn
}

type srvEP struct{ ap netip.AddrPort }

func (e srvEP) ClearSrc()           {}
func (e srvEP) SrcToString() string { return "unset" }
func (e srvEP) DstToString() string { return e.ap.String() }
func (e srvEP) DstToBytes() []byte {
	b, _ := e.ap.Addr().MarshalBinary()
	p := uint16(e.ap.Port())
	return append(b, byte(p), byte(p>>8))
}
func (e srvEP) DstIP() netip.Addr { return e.ap.Addr() }
func (e srvEP) SrcIP() netip.Addr { return netip.Addr{} }

func (b *srvBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	b.c = c
	actual := uint16(c.LocalAddr().(*net.UDPAddr).Port)
	fn := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			n, src, err := c.ReadFromUDPAddrPort(packets[0])
			if err != nil {
				return 0, err
			}
			if src.Addr().Is4In6() {
				src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
			}
			buf := packets[0][:n]

			// 参照点探测（tasks 3.6）：与生产 ServerBind 同语义——明文一问一答，不进数据面。
			if resp := probe.Respond(buf, "tier-test", 0x01); resp != nil { // flags bit0：模拟"默认路径能承载 UDP"
				_, _ = c.WriteToUDPAddrPort(resp, src)
				continue
			}

			if len(buf) > 0 && buf[0] == 0xBB {
				typ, payload, err := proto.DecodeFrame(buf)
				if err != nil {
					continue
				}
				switch typ {
				case proto.FrameTypeData:
					sizes[0] = len(payload)
					copy(packets[0], payload)
					eps[0] = srvEP{src}
					return 1, nil
				case proto.FrameTypeReg:
					if _, _, err := proto.VerifyReg(b.h.secret, payload, time.Now(), time.Minute); err == nil {
						b.h.registerClient()
					}
					continue
				case proto.FrameTypeBatch:
					// FIX-91 搭车容器：按序 [reg][data]（先登记后投递）。
					msgs, berr := proto.DecodeBatch(payload)
					if berr != nil {
						continue
					}
					var data []byte
					for _, m := range msgs {
						switch m.Type {
						case proto.FrameTypeReg:
							if _, _, err := proto.VerifyReg(b.h.secret, m.Payload, time.Now(), time.Minute); err == nil {
								b.h.registerClient()
							}
						case proto.FrameTypeData:
							if data == nil {
								data = m.Payload
							}
						}
					}
					if data == nil {
						continue
					}
					sizes[0] = len(data)
					copy(packets[0], data)
					eps[0] = srvEP{src}
					return 1, nil
				default:
					continue
				}
			}
			// FIX-91 统一线格式：非帧包不是腿（旧对端/垃圾）——丢弃。
			continue
		}
	}
	return []conn.ReceiveFunc{fn}, actual, nil
}

func (b *srvBind) Close() error {
	if b.c == nil {
		return nil // BindUpdate 在首次 Open 前会先 Close 旧 bind
	}
	return b.c.Close()
}
func (b *srvBind) SetMark(uint32) error { return nil }
func (b *srvBind) BatchSize() int       { return 1 }

func (b *srvBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(srvEP)
	if !ok {
		return fmt.Errorf("srvBind: 未知 endpoint %T", ep)
	}
	for _, buf := range bufs {
		// FIX-91 统一线格式：出口恒发数据腿帧。
		if _, err := b.c.WriteToUDPAddrPort(proto.EncodeFrame(proto.FrameTypeData, buf), e.ap); err != nil {
			return err
		}
	}
	return nil
}

func (b *srvBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return srvEP{ap}, nil
}

// ---------- 最小中继 harness（分配式转发，tagged/腿帧格式） ----------

type testRelay struct {
	ln      *net.UDPConn
	backend netip.AddrPort
	mu      sync.Mutex
	allocs  map[string]*net.UDPConn
}

func newTestRelay(t *testing.T, backend netip.AddrPort) (*testRelay, uint16) {
	t.Helper()
	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	r := &testRelay{ln: ln, backend: backend, allocs: map[string]*net.UDPConn{}}
	t.Cleanup(func() { ln.Close() })
	go r.run()
	return r, uint16(ln.LocalAddr().(*net.UDPAddr).Port)
}

func (r *testRelay) port() uint16 { return uint16(r.ln.LocalAddr().(*net.UDPAddr).Port) }

func (r *testRelay) run() {
	buf := make([]byte, 65535)
	for {
		n, src, err := r.ln.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		if n < 11 || buf[0] != 0xAA {
			continue
		}
		key := src.String()
		r.mu.Lock()
		alloc := r.allocs[key]
		if alloc == nil {
			alloc, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				r.mu.Unlock()
				continue
			}
			r.allocs[key] = alloc
			go r.pump(alloc, src)
		}
		r.mu.Unlock()
		alloc.WriteToUDPAddrPort(buf[9:n], r.backend) // 剥 9B 路由头 → 腿帧直转后端
	}
}

func (r *testRelay) pump(alloc *net.UDPConn, client netip.AddrPort) {
	buf := make([]byte, 65535)
	for {
		n, _, err := alloc.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		// FIX-91：后端回程已是腿帧（出口恒套帧）——原样转发（与生产中继同语义）
		r.ln.WriteToUDPAddrPort(buf[:n], client)
	}
}

// ---------- 客户端栈 ----------

type clientStack struct {
	bind *Bind
	tun  *tuntest.ChannelTUN
	dev  *device.Device
	id   *Identity
}

func newClientStack(t *testing.T, token proto.Token, cands []Candidate) *clientStack {
	t.Helper()
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bind := NewBind(Config{
		PeerID:     token.PeerID,
		Secret:     token.Secret,
		Identity:   id,
		Candidates: cands,
	})
	tun := tuntest.NewChannelTUN()
	dev := device.NewDevice(tun.TUN(), bind, device.NewLogger(device.LogLevelError, "cli"))
	t.Cleanup(func() { dev.Close() })
	idPriv := id.PrivateKey()
	psk := proto.DerivePSK(token.Secret)
	conf := fmt.Sprintf("private_key=%s\npublic_key=%s\npreshared_key=%s\nendpoint=race\nallowed_ip=%s/32\n",
		hex.EncodeToString(idPriv[:]),
		hex.EncodeToString(token.PeerID[:]),
		hex.EncodeToString(psk[:]),
		srvTunnelIP)
	if err := dev.IpcSet(conf); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	return &clientStack{bind: bind, tun: tun, dev: dev, id: id}
}

// ---------- 数据包工具 ----------

func udp4Pkt(src, dst string, sport, dport uint16, payload string) []byte {
	s := netip.MustParseAddr(src)
	d := netip.MustParseAddr(dst)
	total := 20 + 8 + len(payload)
	pkt := make([]byte, total)
	pkt[0] = 0x45
	pkt[2] = byte(total >> 8)
	pkt[3] = byte(total)
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], s.AsSlice())
	copy(pkt[16:20], d.AsSlice())
	u := 20
	pkt[u] = byte(sport >> 8)
	pkt[u+1] = byte(sport)
	pkt[u+2] = byte(dport >> 8)
	pkt[u+3] = byte(dport)
	copy(pkt[u+8:], payload)
	return pkt
}

func recvTun(ch chan []byte, d time.Duration) []byte {
	select {
	case p := <-ch:
		return p
	case <-time.After(d):
		return nil
	}
}

func randSecret() [32]byte {
	var s [32]byte
	for i := range s {
		s[i] = byte(i*7 + 1)
	}
	return s
}

func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	p := uint16(c.LocalAddr().(*net.UDPAddr).Port)
	c.Close()
	return p
}

// 场景①：direct 可达 → via=direct，数据往返
func TestIntegrationDirectReachable(t *testing.T) {
	secret := randSecret()
	srvPort := freeUDPPort(t)
	h := newSrvHarness(t, secret, srvPort)

	var token proto.Token
	pub := h.priv.PublicKey()
	copy(token.PeerID[:], pub[:])
	token.Secret = secret
	cand := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", srvPort))
	token.Endpoints = []proto.Endpoint{{Addr: cand.String()}}

	cs := newClientStack(t, token, []Candidate{{Addr: cand}})
	h.setClientPub(cs.id.PublicKey())

	cs.tun.Outbound <- udp4Pkt(cliTunnelIP, srvTunnelIP, 40000, 5678, "ping-d")
	p := recvTun(h.tun.Inbound, 5*time.Second)
	if p == nil || string(p[28:]) != "ping-d" {
		t.Fatal("场景①失败：服务端未收到 ping-d")
	}
	if addr, relay, valid := cs.bind.Adopted(); !valid || relay || addr.Port() != srvPort {
		t.Fatalf("场景① via 判定错误：addr=%v relay=%v", addr, relay)
	}
	h.tun.Outbound <- udp4Pkt(srvTunnelIP, cliTunnelIP, 5678, 40000, "pong-d")
	if g := recvTun(cs.tun.Inbound, 5*time.Second); g == nil || string(g[28:]) != "pong-d" {
		t.Fatal("场景①回程失败")
	}
}

// 场景②：直连候选全死、仅中继可达 → via=relay，数据经中继往返
func TestIntegrationRelayOnly(t *testing.T) {
	secret := randSecret()
	srvPort := freeUDPPort(t)
	h := newSrvHarness(t, secret, srvPort)

	rl, relayPort := newTestRelay(t, netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", srvPort)))
	_ = rl

	var token proto.Token
	pub := h.priv.PublicKey()
	copy(token.PeerID[:], pub[:])
	token.Secret = secret
	token.Endpoints = []proto.Endpoint{
		{Addr: "127.0.0.1:1"},
		{Addr: fmt.Sprintf("127.0.0.1:%d", relayPort), Relay: true},
	}
	cs := newClientStack(t, token, []Candidate{
		{Addr: netip.MustParseAddrPort("127.0.0.1:1")},
		{Addr: netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", relayPort)), Relay: true},
	})
	h.setClientPub(cs.id.PublicKey())

	cs.tun.Outbound <- udp4Pkt(cliTunnelIP, srvTunnelIP, 40000, 5678, "ping-r")
	p := recvTun(h.tun.Inbound, 5*time.Second)
	if p == nil || string(p[28:]) != "ping-r" {
		t.Fatal("场景②失败：服务端经中继未收到 ping-r")
	}
	if addr, relay, valid := cs.bind.Adopted(); !valid || !relay || addr.Port() != relayPort {
		t.Fatalf("场景② via 判定错误：addr=%v relay=%v", addr, relay)
	}
	h.tun.Outbound <- udp4Pkt(srvTunnelIP, cliTunnelIP, 5678, 40000, "pong-r")
	if g := recvTun(cs.tun.Inbound, 5*time.Second); g == nil || string(g[28:]) != "pong-r" {
		t.Fatal("场景②回程失败")
	}
}

// 场景③：候选全死 → 无采纳、镜像持续；SetCandidates+Rearm → 恢复。
// 后端先建（公钥已知——token 烤的是它），但客户端候选指向死端口（后端「不可达」）。
func TestIntegrationAllDeadThenRecover(t *testing.T) {
	secret := randSecret()
	srvPort := freeUDPPort(t)
	h := newSrvHarness(t, secret, srvPort)

	var token proto.Token
	hPub := h.priv.PublicKey()
	copy(token.PeerID[:], hPub[:])
	token.Secret = secret
	token.Endpoints = []proto.Endpoint{{Addr: "127.0.0.1:1"}}

	cs := newClientStack(t, token, []Candidate{{Addr: netip.MustParseAddrPort("127.0.0.1:1")}})
	cs.tun.Outbound <- udp4Pkt(cliTunnelIP, srvTunnelIP, 40000, 5678, "ping-x")
	time.Sleep(400 * time.Millisecond)
	if _, _, valid := cs.bind.Adopted(); valid {
		t.Fatal("全哑场景不应有采纳")
	}
	if cs.bind.Status().Mirrored < 1 {
		t.Fatal("镜像应有计数")
	}

	h.setClientPub(cs.id.PublicKey())
	cs.bind.SetCandidates([]Candidate{{Addr: netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", srvPort))}})
	cs.bind.Rearm()
	cs.tun.Outbound <- udp4Pkt(cliTunnelIP, srvTunnelIP, 40001, 5678, "ping-y")
	got := map[string]bool{}
	for i := 0; i < 4; i++ {
		p := recvTun(h.tun.Inbound, 10*time.Second)
		if p == nil {
			break
		}
		got[string(p[28:])] = true
		if got["ping-y"] {
			break
		}
	}
	if !got["ping-y"] {
		t.Fatalf("恢复场景失败：服务端收到 %v", got)
	}
}

// 场景④（flows-compat-remove 后改写为生产过境模型）：L3 直通端到端——客户端 netstack
// 直拨**非隧道 IP 目标**（过境语义）走真 WG 隧道，服务端由 intercept 拦截层终结重拨：
//   - TCP：拨宿主机回声 → 9B 往返；死端口 → 裸 RST（connection refused——flows 时代的
//     结构化 ERR 已随协议退役，与 cmd/tailcat/session.go 的口径注释一致）；
//   - UDP：五元组长会话，同会话两条数据报全部回投（QUIC 语义）——wgnet 的 UDP 路径全覆盖；
//   - 判据：intercept.Stats 的 dialok/dialfail 与 UDP 会话归宿计数（replied——udpcap
//     的「实测 N 条有回包」就靠它），与 homewayd 生产装配一致。
//
// 注意：
//   - 过境目的地用 TEST-NET-2 段的 198.51.100.7（≠隧道 IP）：gVisor 的 IP 层把
//     回环目的地址当 martian 包丢（与 HandleLocal 无关），127.0.0.1 不能当过境 dst；
//     生产里过境 dst 也从不是回环。服务端拦截层注入 Dial 把该段映射到本机同端口
//     回声/死端口（顺带覆盖 Dial 注入缝，生产=系统默认路由）；
//   - 客户端 peer allowed_ip=0.0.0.0/0（生产手机形态）：过境目的地不在隧道子网内；
//   - 两端 netstack 必须用 homeway/pkg/wgnet（逐端点关 Nagle）——gVisor 对开栈的
//     小段死锁见 FINDINGS #10；
//   - 小段回声必须按实际长度 io.ReadFull（"ping-flow" = 9B）：读多一个字节会
//     等一个永远不来的字节，表现形式与「数据不到」完全一样（本测试初版踩过）。
func TestIntegrationTransitE2E(t *testing.T) {
	secret := randSecret()
	srvPort := freeUDPPort(t)

	spriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	nsTun, ns, err := wgnet.CreateOpts([]netip.Addr{netip.MustParseAddr(srvTunnelIP)}, 1280, wgnet.Opts{HandleLocal: false})
	if err != nil {
		t.Fatal(err)
	}
	h := &srvHarness{priv: spriv, secret: secret, psk: proto.DerivePSK(secret)}
	h.bind = &srvBind{h: h}
	h.dev = device.NewDevice(nsTun, h.bind, device.NewLogger(device.LogLevelError, "srv"))
	t.Cleanup(func() { h.dev.Close() })
	if err := h.dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", hex.EncodeToString(spriv[:]), srvPort)); err != nil {
		t.Fatal(err)
	}
	// 服务端拦截层（过境终结+重拨；豁免同端口转投）。UDP 空闲收短：会话归宿计数
	// （replied/noReply）要等会话关闭才上报。Dial 注入：把 TEST-NET-2 目的地映射到
	// 本机同端口（gVisor martian 拒回环 dst，见函数头注；生产这里走系统默认路由）。
	st := &intercept.Stats{}
	mapToLocal := func(ctx context.Context, network, address string) (net.Conn, error) {
		ap, perr := netip.ParseAddrPort(address)
		if perr != nil {
			return nil, perr
		}
		// 拦截层必须按原始过境目的地址重拨（评审整改：若实现改写成别的地址，
		// 只映射端口会让这条断言静默通过）。TEST-NET-2 = 函数头注的过境语义目的地。
		if want := netip.MustParseAddr("198.51.100.7"); ap.Addr() != want {
			return nil, fmt.Errorf("重拨目的被改写：want %v got %v", want, ap.Addr())
		}
		d := net.Dialer{Timeout: 5 * time.Second}
		return d.DialContext(ctx, network, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), ap.Port()).String())
	}
	inter, ierr := intercept.Attach(ns, intercept.Config{
		TunnelIP: netip.MustParseAddr(srvTunnelIP),
		UDPIdle:  300 * time.Millisecond,
		Dial:     mapToLocal,
	}, st)
	if ierr != nil {
		t.Fatal(ierr)
	}
	t.Cleanup(inter.Close)

	// 宿主机 UDP 回声（模拟 DNS/QUIC 对端）
	udpEcho, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udpEcho.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := udpEcho.ReadFromUDP(buf)
			if err != nil {
				return
			}
			udpEcho.WriteToUDP(buf[:n], from)
		}
	}()

	// 宿主机 TCP 回声
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	echoPort := uint16(echo.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					c.Write(buf[:n])
				}
			}()
		}
	}()

	if err := h.dev.Up(); err != nil {
		t.Fatal(err)
	}

	spub := spriv.PublicKey()
	var token proto.Token
	copy(token.PeerID[:], spub[:])
	token.Secret = secret
	cand := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", srvPort))
	token.Endpoints = []proto.Endpoint{{Addr: cand.String()}}

	id, _ := NewIdentity()
	bind := NewBind(Config{PeerID: token.PeerID, Secret: token.Secret, Identity: id, Candidates: []Candidate{{Addr: cand}}})
	// 客户端隧道地址 = 自己从临时公钥派生；后端在 reg 到达后用同一公式算出同一个
	// 值写 allowed_ip（tasks 3.7）。
	cliIP := proto.DeriveTunnelIP(secret, id.PublicKey())
	if !netip.MustParsePrefix("100.64.0.0/16").Contains(cliIP) {
		t.Fatalf("派生隧道地址越界：%v", cliIP)
	}
	h.setAllowIP(cliIP)
	// 客户端栈用 wgnet.Create（= 生产手机形态：HandleLocal:true——评审整改
	// 2026-09-22：此前抄了出口侧的 CreateOpts(false)，注释还自称同构；本栈在测试里
	// 扮演手机客户端，HandleLocal 只影响回环目的地的本地短路，对过境场景无影响）。
	cliTun, cliNS, err := wgnet.Create([]netip.Addr{cliIP}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	cdev := device.NewDevice(cliTun, bind, device.NewLogger(device.LogLevelError, "cli"))
	t.Cleanup(func() { cdev.Close() })
	idPriv := id.PrivateKey()
	psk := proto.DerivePSK(token.Secret)
	// allowed_ip=0.0.0.0/0（生产手机形态）：过境目的地不在隧道子网内。
	conf := fmt.Sprintf("private_key=%s\npublic_key=%s\npreshared_key=%s\nendpoint=race\nallowed_ip=0.0.0.0/0\n",
		hex.EncodeToString(idPriv[:]), hex.EncodeToString(token.PeerID[:]), hex.EncodeToString(psk[:]))
	if err := cdev.IpcSet(conf); err != nil {
		t.Fatal(err)
	}
	if err := cdev.Up(); err != nil {
		t.Fatal(err)
	}
	h.setClientPub(id.PublicKey())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	transitDst := netip.MustParseAddr("198.51.100.7") // TEST-NET-2：过境语义的目的地（≠隧道 IP）

	// TCP 过境成功路径（9B 小段——Nagle 关闭后才可靠）
	conn, err := cliNS.DialTCPAddrPortCtx(ctx, netip.AddrPortFrom(transitDst, echoPort))
	if err != nil {
		t.Fatalf("过境 TCP 拨号失败：%v", err)
	}
	if _, err := conn.Write([]byte("ping-flow")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("ping-flow"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("回声未达：%v", err)
	}
	if string(got) != "ping-flow" {
		t.Fatalf("回声=%q", got)
	}
	conn.Close()

	// TCP 过境失败路径：死端口 → 出口重拨被拒回 RST，客户端拿到裸 connection refused
	// （flows 时代的结构化 ERR 语义已退役——见 session.go 口径注释）。
	// refused 类错误是恢复阶梯归因的依据（R1 探测按它区分「对端死」与「本地挂起」）：
	// 只断言 err!=nil 会放过「退化成超时」的实现回归，这里钉住错误类别。
	_, derr := cliNS.DialTCPAddrPortCtx(ctx, netip.AddrPortFrom(transitDst, 1))
	if derr == nil {
		t.Fatal("死端口应拒绝")
	}
	if !errors.Is(derr, wgnet.ErrRefused) && !strings.Contains(derr.Error(), "connection refused") {
		t.Fatalf("死端口应回 connection refused（RST），got：%v", derr)
	}

	// UDP 过境：长会话（客户端 netstack UDP → WG → 服务端拦截会话 → 宿主机回声），
	// 同一五元组两条数据报全部回投。
	upc, err := cliNS.ListenUDPAddrPort(netip.AddrPortFrom(cliIP, 0))
	if err != nil {
		t.Fatalf("ListenUDP 失败：%v", err)
	}
	// UDP 的过境目的地 = TEST-NET-2:回声端口（包的 dst 就是它；回包由服务端拦截会话回投）。
	udpDst := netip.AddrPortFrom(transitDst, uint16(udpEcho.LocalAddr().(*net.UDPAddr).Port))
	if _, err := upc.WriteTo([]byte("ping-dgram"), net.UDPAddrFromAddrPort(udpDst)); err != nil {
		t.Fatalf("数据报写失败：%v", err)
	}
	ubuf := make([]byte, 512)
	_ = upc.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := upc.ReadFrom(ubuf)
	if err != nil {
		t.Fatalf("数据报读失败：%v（服务端计数 %v）", err, st.Snapshot())
	}
	if string(ubuf[:n]) != "ping-dgram" {
		t.Fatalf("数据报往返异常：%q", ubuf[:n])
	}
	if _, err := upc.WriteTo([]byte("ping-2"), net.UDPAddrFromAddrPort(udpDst)); err != nil {
		t.Fatalf("数据报二次写失败：%v", err)
	}
	_ = upc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, _, err := upc.ReadFrom(ubuf); err != nil || string(ubuf[:n]) != "ping-2" {
		t.Fatalf("数据报二次往返失败：n=%d err=%v payload=%q", n, err, ubuf[:n])
	}
	upc.Close()

	// 等会话空闲关闭（UDPIdle=300ms）→ 会话归宿计数上报：同五元组两条数据报
	// 只算一条 replied 会话（长会话复用，不是一次一拨）。
	// 轮询等会话空闲关闭（UDPIdle=300ms）后归宿计数到位（评审整改：固定 Sleep
	// 在重载机器上可能闪断，同文件 settle() 的轮询风格更稳）。
	waitUDPSessions := func() (uint64, uint64) {
		deadline := time.Now().Add(3 * time.Second)
		for {
			r, n := st.UDPSessions()
			if (r >= 1 && n >= 0) || time.Now().After(deadline) {
				return r, n
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	replied, noReply := waitUDPSessions()
	if replied != 1 || noReply != 0 {
		t.Fatalf("UDP 会话归宿不符：replied=%d noReply=%d", replied, noReply)
	}
	snap := st.Snapshot()
	if snap["dialok"] != 1 || snap["dialfail"] != 1 {
		t.Fatalf("计数契约不符：%v", snap)
	}
}

// 场景⑤（tasks 2.5 判据）：端点学习缓存——学习 → 后端换址 → 重连命中新址。
//
//  1. 后端身份固定（spriv），在 A 地址起服务；客户端用 token 静态候选建连并跑通一次认证会话
//     （数据往返）⇒ A 记「已验证」；
//  2. 后端换址到 B（同一静态身份、同一 token）——A 关掉；
//  3. 一条 hint 经 Bind.OnHint 的真实接线进缓存：B 未验证、最新鲜（生产里来自中继/带内观察）；
//  4. **重连**（新进程语义：新临时身份 + 新 device），候选 = cache.Merge(静态 token 候选)
//     ⇒ 镜像握手同时打 A（死）与 B，回包来自 B ⇒ 采纳 B；数据在新址上真的往返成功；
//  5. B 标 verified 落盘，重读缓存仍在且排最前（下次冷启动直接命中新址）。
func TestIntegrationLearnedEndpointSurvivesMove(t *testing.T) {
	secret := randSecret()
	dir := t.TempDir()
	spriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	spub := spriv.PublicKey()
	var token proto.Token
	copy(token.PeerID[:], spub[:])
	token.Secret = secret

	candA := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", freeUDPPort(t)))
	candB := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", freeUDPPort(t)))
	token.Endpoints = []proto.Endpoint{{Addr: candA.String()}}

	cache := OpenEndpointCache(dir, spub)

	srvA := newSrvHarnessWithKey(t, spriv, secret, candA.Port())
	cs1 := newClientStack(t, token, []Candidate{{Addr: candA}})
	srvA.setClientPub(cs1.id.PublicKey())
	// hint → 缓存：生产里核心也是这么接线（中继腿控制帧/带内通告 → OnHint → Observe(SourceHint)）
	cs1.bind.SetOnHint(func(addr string) {
		if ap, err := netip.ParseAddrPort(addr); err == nil {
			cache.ObserveAndSave(ap, SourceHint, time.Now())
		}
	})

	// 1) A 上跑通一次认证会话
	cs1.tun.Outbound <- udp4Pkt(cliTunnelIP, srvTunnelIP, 40000, 5678, "ping-a")
	if p := recvTun(srvA.tun.Inbound, 5*time.Second); p == nil || string(p[28:]) != "ping-a" {
		t.Fatal("场景⑤阶段1失败：A 地址会话未建立")
	}
	adoptedA, relayA, okA := cs1.bind.Adopted()
	if !okA || relayA || adoptedA != candA {
		t.Fatalf("场景⑤阶段1采纳不符：addr=%v relay=%v", adoptedA, relayA)
	}
	cache.MarkVerifiedAndSave(adoptedA, SourceInband, time.Now())

	// 2) 后端换址：A 关掉，同身份在 B 起来
	srvA.dev.Close()
	srvB := newSrvHarnessWithKey(t, spriv, secret, candB.Port())

	// 3) hint 送达（等价于中继腿递来一条 hint）
	cs1.bind.deliverHint(candB.String())
	if es := cache.Entries(time.Now()); len(es) != 2 {
		t.Fatalf("场景⑤阶段3失败：缓存应有 A/B 两条：%+v", es)
	}

	// 4) 重连：新临时身份 + 新 device（进程重启语义），候选 = 学习缓存 + token 静态
	cs2 := newClientStack(t, token, cache.Merge([]Candidate{{Addr: candA}}, time.Now()))
	srvB.setClientPub(cs2.id.PublicKey())
	cs2.tun.Outbound <- udp4Pkt(cliTunnelIP, srvTunnelIP, 40001, 5678, "ping-b")
	if p := recvTun(srvB.tun.Inbound, 10*time.Second); p == nil || string(p[28:]) != "ping-b" {
		t.Fatal("场景⑤阶段4失败：换址后重连未命中新址")
	}
	srvB.tun.Outbound <- udp4Pkt(srvTunnelIP, cliTunnelIP, 5678, 40001, "pong-b")
	if g := recvTun(cs2.tun.Inbound, 10*time.Second); g == nil || string(g[28:]) != "pong-b" {
		t.Fatal("场景⑤阶段4回程失败")
	}
	adoptedB, relayB, okB := cs2.bind.Adopted()
	if !okB || relayB || adoptedB != candB {
		t.Fatalf("场景⑤阶段4应采纳学习到的新址：addr=%v relay=%v（期望 %v）", adoptedB, relayB, candB)
	}

	// 5) 新址会话verified + 落盘重读（冷启动路径）
	cache.MarkVerifiedAndSave(candB, SourceHint, time.Now())
	c2 := OpenEndpointCache(dir, spub)
	es := c2.Entries(time.Now())
	if len(es) == 0 || es[0].Addr != candB || !es[0].Verified() {
		t.Fatalf("场景⑤阶段5失败：重读缓存应把新址排在最前且已验证：%+v", es)
	}
	if got := c2.Merge(nil, time.Now()); len(got) == 0 || got[0].Addr != candB {
		t.Fatalf("场景⑤阶段5失败：Merge 应把新址放最前：%+v", got)
	}
}

// 场景⑥（tasks 3.4 组合验证）：files 原生协议过真隧道（生产模型，flows-compat-remove 改写）——
// 客户端 netstack 直拨 隧道IP:<filesPort> → WG → 服务端拦截层豁免转投 127.0.0.1:<filesPort>
// → 后端 files 服务。判据：问候帧 root、list/stat/mkdir/read/upload/download 全通 + 错误码透传。
func TestIntegrationFilesOverTunnel(t *testing.T) {
	secret := randSecret()
	srvPort := freeUDPPort(t)

	spriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	nsTun, ns, err := wgnet.CreateOpts([]netip.Addr{netip.MustParseAddr(srvTunnelIP)}, 1280, wgnet.Opts{HandleLocal: false})
	if err != nil {
		t.Fatal(err)
	}
	h := &srvHarness{priv: spriv, secret: secret, psk: proto.DerivePSK(secret)}
	h.bind = &srvBind{h: h}
	h.dev = device.NewDevice(nsTun, h.bind, device.NewLogger(device.LogLevelError, "srv"))
	t.Cleanup(func() { h.dev.Close() })
	if err := h.dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", hex.EncodeToString(spriv[:]), srvPort)); err != nil {
		t.Fatal(err)
	}
	// 服务端拦截层：豁免规则把 隧道IP:<filesPort> 转投本机同端口（files 监听在下面起）。
	st := &intercept.Stats{}
	inter, ierr := intercept.Attach(ns, intercept.Config{TunnelIP: netip.MustParseAddr(srvTunnelIP)}, st)
	if ierr != nil {
		t.Fatal(ierr)
	}
	t.Cleanup(inter.Close)
	if err := h.dev.Up(); err != nil {
		t.Fatal(err)
	}

	// 后端 side：files 服务（根 = 临时目录）+ 本机回环监听
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hi-there"), 0o644); err != nil {
		t.Fatal(err)
	}
	fsrv, err := files.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fsrv.Close() })
	fln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fln.Close() })
	go fsrv.Serve(fln)
	filesPort := uint16(fln.Addr().(*net.TCPAddr).Port)

	// 客户端 side：WG 客户端装配（拨号在 fileCli.Dial 里直拨隧道 IP）
	spub := spriv.PublicKey()
	var token proto.Token
	copy(token.PeerID[:], spub[:])
	token.Secret = secret
	cand := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", srvPort))
	token.Endpoints = []proto.Endpoint{{Addr: cand.String()}}

	id, _ := NewIdentity()
	bind := NewBind(Config{PeerID: token.PeerID, Secret: token.Secret, Identity: id, Candidates: []Candidate{{Addr: cand}}})
	cliIP := proto.DeriveTunnelIP(secret, id.PublicKey())
	h.setAllowIP(cliIP)
	cliTun, cliNS, err := wgnet.Create([]netip.Addr{cliIP}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	cdev := device.NewDevice(cliTun, bind, device.NewLogger(device.LogLevelError, "cli"))
	t.Cleanup(func() { cdev.Close() })
	idPriv := id.PrivateKey()
	psk := proto.DerivePSK(secret)
	conf := fmt.Sprintf("private_key=%s\npublic_key=%s\npreshared_key=%s\nendpoint=race\nallowed_ip=%s/32\n",
		hex.EncodeToString(idPriv[:]), hex.EncodeToString(token.PeerID[:]),
		hex.EncodeToString(psk[:]), srvTunnelIP)
	if err := cdev.IpcSet(conf); err != nil {
		t.Fatal(err)
	}
	if err := cdev.Up(); err != nil {
		t.Fatal(err)
	}
	h.setClientPub(id.PublicKey())

	// 客户端 side：WG 客户端 + 栈 B 直拨隧道 IP（出口豁免转投本机 files 端口）
	fileCli := &files.Client{Dial: func(ctx context.Context) (net.Conn, error) {
		return cliNS.DialTCPAddrPortCtx(ctx, netip.AddrPortFrom(netip.MustParseAddr(srvTunnelIP), filesPort))
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// 问候帧（root 判据）+ list
	sess, err := fileCli.Open(ctx)
	if err != nil {
		t.Fatalf("files 问候失败：%v", err)
	}
	if sess.Root != root || sess.Ver != files.Version {
		t.Fatalf("问候字段不符：root=%q ver=%d", sess.Root, sess.Ver)
	}
	sess.Close()
	ents, err := fileCli.List(ctx, ".")
	if err != nil || len(ents) != 1 || ents[0].Name != "hello.txt" || ents[0].Size != 8 {
		t.Fatalf("list 不符：err=%v ents=%+v", err, ents)
	}
	if e, err := fileCli.Stat(ctx, "hello.txt"); err != nil || e.Size != 8 {
		t.Fatalf("stat 不符：err=%v entry=%+v", err, e)
	}
	if err := fileCli.Mkdir(ctx, "docs"); err != nil {
		t.Fatalf("mkdir 失败：%v", err)
	}
	if resp, err := fileCli.Read(ctx, "hello.txt", "", 0); err != nil || resp.Text != "hi-there" {
		t.Fatalf("read 不符：err=%v resp=%+v", err, resp)
	}

	// 上传（跨帧）→ 回读 → 落盘校验
	payload := bytes.Repeat([]byte("tier-files-"), 40000) // 440KB：跨多帧
	if n, err := fileCli.Upload(ctx, "docs/big.bin", bytes.NewReader(payload), int64(len(payload)), nil); err != nil || n != int64(len(payload)) {
		t.Fatalf("upload 失败：n=%d err=%v", n, err)
	}
	var got bytes.Buffer
	if n, err := fileCli.Download(ctx, "docs/big.bin", &got); err != nil || n != int64(len(payload)) {
		t.Fatalf("download 失败：n=%d err=%v", n, err)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatal("download 内容与上传不一致")
	}
	onDisk, err := os.ReadFile(filepath.Join(root, "docs", "big.bin"))
	if err != nil || !bytes.Equal(onDisk, payload) {
		t.Fatalf("落盘内容不符：err=%v len=%d", err, len(onDisk))
	}

	// 错误码透传（NAPI 层直接消费）
	if _, err := fileCli.Stat(ctx, "nope"); err == nil {
		t.Fatal("缺文件应报错")
	} else {
		var fe *files.Error
		if !errors.As(err, &fe) || fe.Code != "not_found" {
			t.Fatalf("错误码应为 not_found：%v", err)
		}
	}
	if snap := st.Snapshot(); snap["dialok"] < 7 || snap["dialfail"] != 0 {
		t.Fatalf("流计数不符（每次 files 命令一条流）：%v", snap)
	}

	// 收尾：等所有内部流都收工再让 cleanup 拆设备。
	// 客户端关流只是把 FIN 交给自己的 netstack/WG 设备**异步**发出；cleanup 里客户端设备
	// 先于 stopFlow 关闭，FIN 还没出门就会丢 ⇒ 服务端 handler 永远等不到 EOF，表现为
	// 「流泄漏」的假象（真机不存在：设备与隧道同生共死，FIN 总会发出）。
	settle := time.Now().Add(10 * time.Second)
	for {
		if st.Snapshot()["flows"] == 0 {
			break
		}
		if time.Now().After(settle) {
			t.Fatalf("仍有内部流未收工：%v", st.Snapshot())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ---------- 真隧道夹具（场景⑦⑧共用） ----------

type tunnelFixture struct {
	cliNS *wgnet.Net // 客户端栈 B（豁免腿：拨隧道 IP 走这里）
	st    *intercept.Stats
	srv   *srvHarness
}

// newTunnelFixture：服务端（wgnet HandleLocal:false + 拦截层豁免转投）+ 客户端（wgnet
// 直拨隧道 IP）。覆盖的是「未映射端口的豁免回环 TCP 兜底」分支（评审整改 2026-09-22
// 的口径修正：生产 files/term 自 exit-service-uds 起走 <state>/*.sock 的 LocalServices
// 映射形态，由 homeway 仓 TestExemptTCPViaUnixSocket 承担；两仓有意分工）。
func newTunnelFixture(t *testing.T) *tunnelFixture {
	t.Helper()
	secret := randSecret()
	srvPort := freeUDPPort(t)
	spriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	nsTun, ns, err := wgnet.CreateOpts([]netip.Addr{netip.MustParseAddr(srvTunnelIP)}, 1280, wgnet.Opts{HandleLocal: false})
	if err != nil {
		t.Fatal(err)
	}
	h := &srvHarness{priv: spriv, secret: secret, psk: proto.DerivePSK(secret)}
	h.bind = &srvBind{h: h}
	h.dev = device.NewDevice(nsTun, h.bind, device.NewLogger(device.LogLevelError, "srv"))
	t.Cleanup(func() { h.dev.Close() })
	if err := h.dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", hex.EncodeToString(spriv[:]), srvPort)); err != nil {
		t.Fatal(err)
	}
	st := &intercept.Stats{}
	inter, ierr := intercept.Attach(ns, intercept.Config{TunnelIP: netip.MustParseAddr(srvTunnelIP)}, st)
	if ierr != nil {
		t.Fatal(ierr)
	}
	t.Cleanup(inter.Close)
	if err := h.dev.Up(); err != nil {
		t.Fatal(err)
	}

	spub := spriv.PublicKey()
	var token proto.Token
	copy(token.PeerID[:], spub[:])
	token.Secret = secret
	cand := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", srvPort))
	token.Endpoints = []proto.Endpoint{{Addr: cand.String()}}

	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bind := NewBind(Config{PeerID: token.PeerID, Secret: token.Secret, Identity: id, Candidates: []Candidate{{Addr: cand}}})
	cliIP := proto.DeriveTunnelIP(secret, id.PublicKey())
	h.setAllowIP(cliIP)
	cliTun, cliNS, err := wgnet.Create([]netip.Addr{cliIP}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	cdev := device.NewDevice(cliTun, bind, device.NewLogger(device.LogLevelError, "cli"))
	t.Cleanup(func() { cdev.Close() })
	idPriv := id.PrivateKey()
	psks := proto.DerivePSK(secret)
	conf := fmt.Sprintf("private_key=%s\npublic_key=%s\npreshared_key=%s\nendpoint=race\nallowed_ip=%s/32\n",
		hex.EncodeToString(idPriv[:]), hex.EncodeToString(token.PeerID[:]), hex.EncodeToString(psks[:]), srvTunnelIP)
	if err := cdev.IpcSet(conf); err != nil {
		t.Fatal(err)
	}
	if err := cdev.Up(); err != nil {
		t.Fatal(err)
	}
	h.setClientPub(id.PublicKey())
	return &tunnelFixture{cliNS: cliNS, st: st, srv: h}
}

// settle 等内部流全部收工（理由见场景⑥收尾注释）。
func (f *tunnelFixture) settle(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if f.st.Snapshot()["flows"] == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("仍有内部流未收工：%v", f.st.Snapshot())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// 场景⑦（tasks 3.5）：终端会话过真隧道——pty 建会话、写命令、读到回显、会话结束。
func TestIntegrationTermOverTunnel(t *testing.T) {
	fx := newTunnelFixture(t)

	// 后端侧终端服务（homewayd 生产装配：127.0.0.1:<TermPort>）
	// stateDir 传空 ⇒ 只用内置 agent manifest（本用例只验会话与回显，不涉及 <state>/agent-detection 覆盖目录）。
	logf := func(format string, args ...any) { fmt.Fprintf(os.Stderr, "[term] "+format+"\n", args...) }
	tsrv := term.New(logf, "")
	t.Cleanup(tsrv.Close)
	tln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tln.Close() })
	go func() {
		for {
			c, aerr := tln.Accept()
			if aerr != nil {
				return
			}
			go tsrv.ServeConn(c)
		}
	}()
	termPort := uint16(tln.Addr().(*net.TCPAddr).Port)

	tcli := &term.Client{Dial: func(ctx context.Context) (net.Conn, error) {
		return fx.cliNS.DialTCPAddrPortCtx(ctx, netip.AddrPortFrom(netip.MustParseAddr(srvTunnelIP), termPort))
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	conn, err := tcli.Attach(ctx, "tier-e2e", 100, 30, true)
	if err != nil {
		t.Fatalf("attach 失败：%v", err)
	}
	if conn.Ver != 1 || conn.Features == 0 {
		t.Fatalf("GREETING 字段不符：ver=%d features=%#x", conn.Ver, conn.Features)
	}

	// 读命令回显：写入一个唯一标记，等它出现在 DATA 里
	const marker = "TIER_TERM_E2E_OK"
	if err := conn.SendData([]byte("echo " + marker + "\n")); err != nil {
		t.Fatalf("发命令失败：%v", err)
	}
	var out bytes.Buffer
	deadline := time.Now().Add(15 * time.Second)
	for !strings.Contains(out.String(), marker) {
		if time.Now().After(deadline) {
			t.Fatalf("等不到命令回显（已收 %dB）：%q", out.Len(), out.String())
		}
		_ = conn.NetConn().SetReadDeadline(time.Now().Add(3 * time.Second))
		f, ferr := conn.ReadFrame()
		if ferr != nil {
			if ne, ok := ferr.(net.Error); ok && ne.Timeout() {
				continue
			}
			t.Fatalf("读帧失败：%v（已收 %q）", ferr, out.String())
		}
		switch f.Op {
		case term.OpData:
			out.Write(f.Payload)
		case term.OpError:
			t.Fatalf("服务端报错：%q", f.Payload)
		}
	}

	// exit → 会话结束（ENDED 帧）+ 列表里应查不到（会话被回收）
	if err := conn.SendData([]byte("exit\n")); err != nil {
		t.Fatal(err)
	}
	ended := false
	endDeadline := time.Now().Add(10 * time.Second)
	for !ended && time.Now().Before(endDeadline) {
		_ = conn.NetConn().SetReadDeadline(time.Now().Add(3 * time.Second))
		f, ferr := conn.ReadFrame()
		if ferr != nil {
			if ne, ok := ferr.(net.Error); ok && ne.Timeout() {
				continue
			}
			break
		}
		if f.Op == term.OpEnded {
			ended = true
		}
	}
	if !ended {
		t.Fatal("exit 后未收到 ENDED")
	}
	conn.Close()

	if raw, err := tcli.List(ctx); err != nil {
		t.Fatalf("list 失败：%v", err)
	} else if strings.Contains(string(raw), "tier-e2e") {
		t.Fatalf("会话应已回收，但 list 里仍在：%s", raw)
	}
	fx.settle(t)
}

// 场景⑧（tasks 3.5）：端口转发回环可达——客户端本地监听 → 每条连接经内部流拨后端目标。
func TestIntegrationPortForwardLoopback(t *testing.T) {
	fx := newTunnelFixture(t)

	// 后端主机上的目标服务（模拟「家里那台机器上的端口」）
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { targetLn.Close() })
	go func() {
		for {
			c, aerr := targetLn.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, rerr := c.Read(buf)
					if n > 0 {
						c.Write(buf[:n])
					}
					if rerr != nil {
						return
					}
				}
			}()
		}
	}()
	targetPort := uint16(targetLn.Addr().(*net.TCPAddr).Port)

	// 客户端侧端口转发（与手机核 app_portfwd 同构：本地监听 + 每连接一条内部流 + 双向管道）
	localLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { localLn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	go func() {
		for {
			local, aerr := localLn.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer local.Close()
				up, cerr := fx.cliNS.DialTCPAddrPortCtx(ctx, netip.AddrPortFrom(netip.MustParseAddr(srvTunnelIP), targetPort))
				if cerr != nil {
					return
				}
				defer up.Close()
				go func() { _, _ = io.Copy(up, local); up.Close() }()
				_, _ = io.Copy(local, up)
			}()
		}
	}()

	// 客户端本地连接 → 应经隧道到达后端目标并拿到回显
	c, err := net.DialTimeout("tcp", localLn.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("连本地监听失败：%v", err)
	}
	defer c.Close()
	payload := []byte("pf-loopback-ok")
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("回显未达：%v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("回显=%q", got)
	}
	c.Close()
	localLn.Close()
	fx.settle(t)
}

// 场景⑨（tasks 3.6）：参照点探测——不依赖任何隧道/会话状态，握手之前就能拿到
// 「该地址 UDP 可达（RTT）+ 后端构建标记 + 后端看到的我是哪个地址」；
// 同时验证非探测包不产生任何响应（不扰动数据面）。
func TestIntegrationProbeReferencePoint(t *testing.T) {
	secret := randSecret()
	srvPort := freeUDPPort(t)
	_ = newSrvHarness(t, secret, srvPort) // 起服务端（srvBind 含生产同款探测应答）
	target := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", srvPort))

	cli, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 直连探测应答：可达性 + RTT + 构建标记 + 出口能力位
	rtt, build, flags, err := probe.Ping(ctx, cli, target, "")
	if err != nil {
		t.Fatalf("ping 失败：%v", err)
	}
	if build != "tier-test" {
		t.Fatalf("构建标记=%q 期望 tier-test", build)
	}
	if rtt <= 0 || rtt > 2*time.Second {
		t.Fatalf("RTT 异常：%v", rtt)
	}
	_ = flags // 能力位由出口决定（测试夹具不回 flags ⇒ 0）

	// 非探测包（垃圾/裸 WG 形态）不应有任何响应：数据面不受探测通道影响
	if _, err := cli.WriteToUDP([]byte("not-a-probe-payload"), net.UDPAddrFromAddrPort(target)); err != nil {
		t.Fatal(err)
	}
	_ = cli.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	buf := make([]byte, 256)
	if n, _, err := cli.ReadFromUDP(buf); err == nil {
		t.Fatalf("非探测包不应被应答（收到 %dB）", n)
	}
}
