package relay

// relay-backend-dial 探索验证（openspec change relay-backend-dial 的 spike）。
//
// 验证目标（不依赖现有 relay 内部实现，纯 net 标准库自包含）：
//  1. 控制通道机制：后端发起 TCP 控制长连，收到「客户端到达 + 数据口」通告；
//  2. 数据腿机制：后端**主动拨** UDP 到中继数据口，双向数据经该腿流动
//     （模拟 WG device 的回声消费方：收到即原路回 ACK）；
//  3. 多客户端隔离：两个客户端各得一条腿，内容互不串；
//  4. 建立时延：客户端首包 → 后端收到（含控制通告 + 拨腿一整轮）；
//  5. 中继重启恢复：控制断开后重连，新客户端会话照常（状态天然清零）。
//
// NAT 属性不在本地模拟（构造性成立）：数据腿由后端先发起（connected UDP 的五元组
// 精确匹配），端口受限/对称 NAT 均放行回程——这正是本设计要替换「per-client socket
// 主动敲洞」的理由（那套在严格 NAT 上恒不通，且故障对中继不可见）。
//
// 生产化时的对应关系（见 design.md）：spikeCtrl* → internal/server/relayclient.go 的
// 控制客户端；spikeRelay 的通告/数据口分配 → internal/relay 的腿分配；后端回声消费方
// → ServerBind 的多腿收发 + WG device。

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------- 中继侧（spike 最小实现） ----------

type spikeSession struct {
	id     int64
	legPC  *net.UDPConn // per-client 数据口（等后端来拨）
	legUp  atomic.Bool  // 后端拨过了（legPC 见到它的首包）
	legDst atomic.Pointer[netip.AddrPort]
	client atomic.Pointer[netip.AddrPort]
	pendMu sync.Mutex
	pend   [][]byte // 拨腿前的客户端包缓冲
}

type spikeRelay struct {
	ctrlLn   net.Listener // TCP 控制面
	clientPC *net.UDPConn // 客户端面（UDP）
	nextID   atomic.Int64

	mu       sync.Mutex
	ctrl     net.Conn // 当前的控制连接（spike 只服务一个后端）
	ctrlUp   chan struct{}
	sessions map[int64]*spikeSession
	byClient map[netip.AddrPort]int64
}

func startSpikeRelay(t *testing.T) *spikeRelay {
	t.Helper()
	r := &spikeRelay{sessions: map[int64]*spikeSession{}, byClient: map[netip.AddrPort]int64{}, ctrlUp: make(chan struct{})}
	var err error
	r.ctrlLn, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r.clientPC, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.ctrlLn.Close(); r.clientPC.Close() })

	// 控制面：接受后端的 TCP 长连（spike 单后端：后来的顶掉先来的）
	go func() {
		for {
			c, err := r.ctrlLn.Accept()
			if err != nil {
				return
			}
			r.mu.Lock()
			if r.ctrl != nil {
				r.ctrl.Close()
			}
			r.ctrl = c
			r.mu.Unlock()
			select {
			case <-r.ctrlUp:
			default:
				close(r.ctrlUp)
			}
			go r.readHello(c)
		}
	}()

	// 客户端面：按源地址认会话，首包触发「分配数据口 + 控制通道通告」
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := r.clientPC.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			pkt := append([]byte(nil), buf[:n]...)
			r.mu.Lock()
			id, ok := r.byClient[from]
			if !ok {
				id = r.nextID.Add(1)
				r.byClient[from] = id
			}
			sess := r.sessions[id]
			if sess == nil {
				sess = r.newSessionLocked(id, from)
			}
			r.mu.Unlock()
			sess.client.Store(&from)
			if sess.legUp.Load() {
				if dst := sess.legDst.Load(); dst != nil {
					_, _ = sess.legPC.WriteToUDPAddrPort(pkt, *dst)
				}
			} else {
				sess.pendMu.Lock()
				if len(sess.pend) < 16 {
					sess.pend = append(sess.pend, pkt)
				}
				sess.pendMu.Unlock()
			}
		}
	}()
	return r
}

func (r *spikeRelay) readHello(c net.Conn) {
	// HELLO 之后**保持连接**：SESSION 通告走同一条连接（spike 里后端侧的
	// scanner 会一直读）。这里只排水（生产版本会处理命令面错误/保活）。
	sc := bufio.NewScanner(c)
	for sc.Scan() {
	}
	_ = c.Close()
}

// newSessionLocked：分配 per-client 数据口 + 起腿泵 + 经控制通道通告后端。
func (r *spikeRelay) newSessionLocked(id int64, client netip.AddrPort) *spikeSession {
	legPC, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil
	}
	sess := &spikeSession{id: id, legPC: legPC}
	r.sessions[id] = sess
	// 腿泵：后端拨来（首包）→ 记录来源 + 放缓冲 → 之后双向转发
	go func() {
		buf := make([]byte, 65536)
		first := true
		for {
			n, from, err := legPC.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			pkt := append([]byte(nil), buf[:n]...)
			if first {
				first = false
				sess.legDst.Store(&from)
				sess.legUp.Store(true)
				sess.pendMu.Lock()
				pend := sess.pend
				sess.pend = nil
				sess.pendMu.Unlock()
				for _, p := range pend {
					_, _ = legPC.WriteToUDPAddrPort(p, from)
				}
				if string(pkt) == "LEGUP" {
					continue // 拨腿标记，不是数据
				}
			}
			if c := sess.client.Load(); c != nil {
				_, _ = r.clientPC.WriteToUDPAddrPort(pkt, *c)
			}
		}
	}()
	// 控制通告："SESSION <id> <port>\n"（spike 直接写文本行；生产走 pkg/proto 帧）
	legPort := uint16(legPC.LocalAddr().(*net.UDPAddr).Port)
	if r.ctrl != nil {
		fmt.Fprintf(r.ctrl, "SESSION %d %d\n", id, legPort)
	}
	return sess
}

// ---------- 后端侧（spike 最小实现：控制客户端 + 拨腿 + 回声消费方） ----------

// spikeBackend 连上中继，收到 SESSION 通告就拨腿；腿上的包交给 onPacket（模拟 WG device
// 的接收路径），onPacket 的返回值作为回程发出去（模拟 device 的 Send）。
func spikeBackend(t *testing.T, relayCtrl string, relayUDP netip.AddrPort, onPacket func(pkt []byte) []byte) {
	t.Helper()
	conn, err := net.Dial("tcp", relayCtrl)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("HELLO spike\n")); err != nil {
		t.Fatal(err)
	}
	go func() {
		sc := bufio.NewScanner(conn)
		for sc.Scan() {
			var id int64
			var port uint16
			if _, err := fmt.Sscanf(sc.Text(), "SESSION %d %d", &id, &port); err != nil {
				continue
			}
			leg, derr := net.DialUDP("udp4", nil, &net.UDPAddr{
				IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
			if derr != nil {
				continue
			}
			// connected socket：五元组精确匹配（这就是「后端先发起」的 NAT 穿透语义）
			if _, err := leg.Write([]byte("LEGUP")); err != nil {
				leg.Close()
				continue
			}
			go func(leg *net.UDPConn) {
				buf := make([]byte, 65536)
				for {
					n, rerr := leg.Read(buf)
					if rerr != nil {
						return
					}
					if n == 5 && string(buf[:n]) == "LEGUP" {
						continue // 自己的拨腿握手回声（不会发生，防御）
					}
					if resp := onPacket(buf[:n]); resp != nil {
						_, _ = leg.Write(resp)
					}
				}
			}(leg)
			t.Cleanup(func() { leg.Close() })
		}
	}()
	_ = relayUDP
}

// ---------- 验证用例 ----------

func TestSpikeBackendDialRoundtrip(t *testing.T) {
	r := startSpikeRelay(t)
	relayUDP := netip.MustParseAddrPort(r.clientPC.LocalAddr().String())

	// 模拟 WG device：收到 X 回 "ACK:<X>"
	spikeBackend(t, r.ctrlLn.Addr().String(), relayUDP, func(pkt []byte) []byte {
		return append(append([]byte("ACK:"), pkt...), '\n')
	})
	select {
	case <-r.ctrlUp:
	case <-time.After(2 * time.Second):
		t.Fatal("控制通道未就绪")
	}

	// 客户端：发一条、收一条（含完整的「通告+拨腿」建立轮）
	cli, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(relayUDP))
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	t0 := time.Now()
	if _, err := cli.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, err := cli.Read(buf)
	if err != nil {
		t.Fatalf("客户端未收到应答（通告+拨腿链路不通）：%v", err)
	}
	setup := time.Since(t0)
	if got := string(buf[:n]); got != "ACK:ping\n" {
		t.Fatalf("应答 = %q（want ACK:ping\\n）", got)
	}
	t.Logf("建立+首包往返 = %v（含控制通告 + 后端拨腿一整轮）", setup)
	if setup > 500*time.Millisecond {
		t.Fatalf("建立时延 %v 超过 500ms 上界", setup)
	}

	// 第二条起：腿已建，纯数据往返
	t1 := time.Now()
	if _, err := cli.Write([]byte("fast")); err != nil {
		t.Fatal(err)
	}
	cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err = cli.Read(buf)
	if err != nil || string(buf[:n]) != "ACK:fast\n" {
		t.Fatalf("稳态往返失败：n=%d err=%v data=%q", n, err, buf[:n])
	}
	t.Logf("稳态往返 = %v", time.Since(t1))
}

func TestSpikeBackendDialMultiClient(t *testing.T) {
	r := startSpikeRelay(t)
	relayUDP := netip.MustParseAddrPort(r.clientPC.LocalAddr().String())
	spikeBackend(t, r.ctrlLn.Addr().String(), relayUDP, func(pkt []byte) []byte {
		return append(append([]byte("ACK:"), pkt...), '\n')
	})
	select {
	case <-r.ctrlUp:
	case <-time.After(2 * time.Second):
		t.Fatal("控制通道未就绪")
	}

	mk := func(name string) {
		t.Helper()
		cli, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(relayUDP))
		if err != nil {
			t.Fatal(err)
		}
		defer cli.Close()
		msg := "hi-" + name
		if _, err := cli.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		cli.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 1024)
		n, rerr := cli.Read(buf)
		if rerr != nil {
			t.Fatalf("%s 未收到应答：%v", name, rerr)
		}
		if got := string(buf[:n]); got != "ACK:"+msg+"\n" {
			t.Fatalf("%s 串流！应答 = %q（want %q）—— per-client 腿隔离被破坏", name, got, "ACK:"+msg+"\n")
		}
	}
	mk("alice")
	mk("bob") // 第二个客户端 = 另一条腿；内容若串了立刻抓到

	// 会话数 = 2（两个客户端两条腿）
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.sessions) != 2 {
		t.Fatalf("会话数 = %d（want 2：每客户端一条腿）", len(r.sessions))
	}
}

func TestSpikeBackendDialRelayRestart(t *testing.T) {
	r := startSpikeRelay(t)
	relayUDP := netip.MustParseAddrPort(r.clientPC.LocalAddr().String())
	spikeBackend(t, r.ctrlLn.Addr().String(), relayUDP, func(pkt []byte) []byte {
		return append(append([]byte("ACK:"), pkt...), '\n')
	})

	// 模拟中继重启：旧的停掉、原地起一个新的（监听同口太麻烦——客户端面换新口重拨）
	oldCtrl := r.ctrlLn.Addr().String()
	r.ctrlLn.Close()
	r.clientPC.Close()
	time.Sleep(50 * time.Millisecond)
	r2 := startSpikeRelay(t)
	defer func() { _ = oldCtrl }()

	relayUDP2 := netip.MustParseAddrPort(r2.clientPC.LocalAddr().String())
	// 后端重连控制通道（生产里由控制客户端的重连逻辑负责；spike 直接再挂一个）
	spikeBackend(t, r2.ctrlLn.Addr().String(), relayUDP2, func(pkt []byte) []byte {
		return append(append([]byte("ACK2:"), pkt...), '\n')
	})
	select {
	case <-r2.ctrlUp:
	case <-time.After(2 * time.Second):
		t.Fatal("重启后控制通道未就绪")
	}

	cli, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(relayUDP2))
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if _, err := cli.Write([]byte("after-restart")); err != nil {
		t.Fatal(err)
	}
	cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, rerr := cli.Read(buf)
	if rerr != nil {
		t.Fatalf("中继重启后未恢复：%v", rerr)
	}
	if got := string(buf[:n]); got != "ACK2:after-restart\n" {
		t.Fatalf("重启后应答 = %q", got)
	}
}
