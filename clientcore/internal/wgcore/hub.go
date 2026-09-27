package wgcore

// hub.go — WG device 的 tun 侧多路复用器（l3-exit-intercept D1）。
//
// 结构：
//
//	真 TUN fd（应用 transit，Attach 后注册）─┐
//	                                        ├─► hub(tun.Device) ─► WG device ─► wtransport
//	隧道侧 netstack B（核心自连的出站包）  ─┘
//
//	Read（出站明文包）= 合并两源；Write（入站明文包）= 按目的地址分流：
//	dst == B 的本地地址（派生隧道 IP）→ B（核心自连的回程），其余 → 真 TUN fd（内核投给应用）。
//
//	prepare/attach 兼容：hub 常驻——Prepare 时只有 B 一个源（与服务会话同构），
//	Attach 注册 TUN 源；WG device 全程不重建，会话不断。
//
import (
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
)

var (
	errAlreadyAttached = errors.New("wgcore: hub 已经 Attach 过 TUN")
	errHubClosed       = errors.New("wgcore: hub 已关闭")
)

type hub struct {
	b        *bSource // 隧道侧 B（wgnet 包装：tun.Device 读循环）
	mtu      uint32
	tunnelIP [16]byte // B 的本地地址（分流键；4in6 不需要——按 4 字节比较）
	is4      bool

	mu      sync.Mutex
	appTun  tun.Device // Attach 注册的真 TUN（nil = 未接管）
	appDead chan struct{}
	onError func(err error) // 应用 TUN 读写失败回调（tunmode 挂 markUnhealthy）

	// fd 字节计数（与应用侧 vpn-tun 行对表：fdRead=上行 / fdWrite=下行）
	readBytes  atomic.Int64
	writeBytes atomic.Int64

	// 需求信号（demand-driven-recovery D1）：**App TUN 源**的出站包计数与最近出站时刻。
	// 只在 appReadLoop 刷新——栈 B（核心自连：files/终端/探测）不算需求，巡检/探测自身
	// 的流量也不算（它们从 B 或 Bind 直发）。计数按巡检拍「取走清零」消费（自上一拍以来
	// 是否有过出站 = 需求），不做时间窗（拍粒度与证据天然对齐）。
	outPkts        atomic.Int64
	lastOutboundAt atomic.Int64 // unix nano；0 = 本世代从未有过应用出站

	closeOnce sync.Once
	dead      chan struct{}
	events    chan tun.Event

	// 出站包合并通道（两源的读者各把自己的包递进来）
	outbound chan outPkt
}

type outPkt struct {
	data []byte
}

const hubQueue = 512

func newHub(b tun.Device, tunnelIP tcpip.Address, mtu uint32) *hub {
	h := &hub{
		mtu:      mtu,
		dead:     make(chan struct{}),
		appDead:  make(chan struct{}),
		events:   make(chan tun.Event, 4),
		outbound: make(chan outPkt, hubQueue),
	}
	h.events <- tun.EventUp
	copy(h.tunnelIP[:], tunnelIP.AsSlice())
	h.is4 = len(tunnelIP.AsSlice()) == 4
	h.b = startBSource(b, h)
	return h
}

// AttachTUN 注册应用 TUN 源（两阶段启动的第二阶段；只允许一次）。
func (h *hub) AttachTUN(dev tun.Device) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.appTun != nil {
		return errAlreadyAttached
	}
	h.appTun = dev
	go h.appReadLoop(dev)
	return nil
}

// SetOnError 设置应用 TUN 读写失败回调（fd 失效 → tunmode 标记不健康）。
func (h *hub) SetOnError(f func(err error)) {
	h.mu.Lock()
	h.onError = f
	h.mu.Unlock()
}

// FdStats 应用 TUN 的累计字节数（读=上行 / 写=下行）。
func (h *hub) FdStats() (read, write int64) {
	return h.readBytes.Load(), h.writeBytes.Load()
}

// SwapOutboundPackets 取走并清零「自上次调用以来的 App 出站包数」（巡检拍消费：
// >0 = 本拍存在真实流量需求）。挂起期读循环同样冻结，取走值只反映醒着的窗口。
func (h *hub) SwapOutboundPackets() int64 {
	return h.outPkts.Swap(0)
}

// LastOutboundAt 最近一次 App 出站包的时刻（零值 = 从未）。待发包下推器与诊断共用。
func (h *hub) LastOutboundAt() time.Time {
	ns := h.lastOutboundAt.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// ---------- tun.Device（给 wireguard-go 的 NewDevice） ----------

func (h *hub) Name() (string, error)    { return "hub", nil }
func (h *hub) File() *os.File           { return nil }
func (h *hub) Events() <-chan tun.Event { return h.events }

func (h *hub) MTU() (int, error) { return int(h.mtu), nil }

func (h *hub) BatchSize() int { return 1 }

func (h *hub) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case p := <-h.outbound:
		n := copy(bufs[0][offset:], p.data)
		sizes[0] = n
		return 1, nil
	case <-h.dead:
		return 0, errHubClosed
	}
}

// Write：把 WG 解密出的入站明文包分流（tun.Device 语义：返回值 = **写入的包数**，
// 不是字节数——review #40 把混用的计数收敛成显式的 packets++）。
func (h *hub) Write(bufs [][]byte, offset int) (int, error) {
	h.mu.Lock()
	app := h.appTun
	h.mu.Unlock()
	written := 0
	for _, b := range bufs {
		pkt := b[offset:]
		if len(pkt) == 0 {
			continue
		}
		if h.isForB(pkt) {
			if h.b.writeIn(pkt) > 0 {
				written++
			}
			continue
		}
		if app == nil {
			// 未 Attach：transit 回包不该出现（还没有应用流量）；丢弃。
			continue
		}
		if _, err := app.Write([][]byte{pkt}, 0); err != nil {
			h.mu.Lock()
			cb := h.onError
			h.mu.Unlock()
			if cb != nil {
				cb(err)
			}
			return written, err
		}
		written++
		h.writeBytes.Add(int64(len(pkt)))
	}
	return written, nil
}

func (h *hub) Close() error {
	h.closeOnce.Do(func() {
		close(h.dead)
		h.b.close()
		// 关闭隧道侧 B（wgnet.Net）：l3 前 device.Close() 会链式关掉它（tun.Device
		// 就是 wgnet 本体），hub 包装后这条链断了——不补这行，每世代/每服务会话
		// 泄漏一整张 gVisor 栈 + 一个卡在 <-incoming 的读 goroutine（坑 49 同类，
		// 2026-09-20 review A1）。顺序：Core.Close 先 dev.Close()（device 停写）再
		// 走到这里，栈被拆时不会再有写入。
		if h.b != nil && h.b.dev != nil {
			_ = h.b.dev.Close()
		}
		h.mu.Lock()
		app := h.appTun
		h.appTun = nil
		h.mu.Unlock()
		if app != nil {
			// 只关 appDead 信号（读循环的 push 分支会退）。**不关 app 设备本身**：
			// hub 不是它的主人（外部 Attach 进来的可能是 gVisor 栈整张——hub.Close
			// 关它会当场拆掉调用方还在用的栈，实测 panic；#15 的读循环收口由
			// **创建方**（Core.AttachFD 造的 fdTUN）在 Core.Close 里补 Close——
			// fdTUN.Close 只关事件通道，fd 仍归扩展，所有权不变）。
			close(h.appDead)
		}
		// Events 必须关闭：device 的 RoutineTUNEventReader 阻塞在 range Events()
		// ——不关它，每世代泄漏一个 event reader（wgnet.Close 同款语义）。
		close(h.events)
	})
	return nil
}

// isForB：dst == B 的本地地址（核心自连的回程）。内层只承载 IPv4（平台不下发
// v6 路由，D4）——v6 分支是死代码已删（review A5③）。
func (h *hub) isForB(pkt []byte) bool {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return false
	}
	return string(pkt[16:20]) == string(h.tunnelIP[:4])
}

// appReadLoop：真 TUN 读循环（应用 transit 出站方向，原样送 outbound）。
func (h *hub) appReadLoop(dev tun.Device) {
	defer func() {
		// panic 兜底（review #19）：读循环死了应用流量就黑洞，
		// 但比杀进程好得多——markUnhealthy 让扩展重建世代。
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "hub: TUN 读循环 panic（已恢复，交由健康巡检重建）：%v\n", r)
			h.mu.Lock()
			cb := h.onError
			h.mu.Unlock()
			if cb != nil {
				cb(fmt.Errorf("TUN 读循环 panic：%v", r))
			}
		}
	}()
	bufs := [][]byte{make([]byte, 65535)}
	sizes := make([]int, 1)
	for {
		n, err := dev.Read(bufs, sizes, 0)
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}
			h.mu.Lock()
			cb := h.onError
			h.mu.Unlock()
			if cb != nil {
				cb(err)
			}
			return
		}
		if n == 0 {
			continue
		}
		for i := 0; i < n; i++ {
			pkt := make([]byte, sizes[i])
			copy(pkt, bufs[i][:sizes[i]])
			if len(pkt) == 0 {
				continue
			}
			h.readBytes.Add(int64(len(pkt)))
			// 需求信号：App 出站包到达（demand-driven-recovery D1）。
			h.outPkts.Add(1)
			h.lastOutboundAt.Store(time.Now().UnixNano())
			select {
			case h.outbound <- outPkt{data: pkt}:
			case <-h.dead:
				return
			case <-h.appDead:
				return
			}
		}
	}
}

// bSource：把 B（wgnet.Net 即 tun.Device）的读循环包装成包源。
type bSource struct {
	dev  tun.Device
	dead chan struct{}
	once sync.Once

	mu  sync.Mutex
	hub *hub
}

func startBSource(dev tun.Device, h *hub) *bSource {
	bs := &bSource{dev: dev, dead: make(chan struct{})}
	bs.mu.Lock()
	bs.hub = h
	bs.mu.Unlock()
	go bs.readLoop()
	return bs
}

func (bs *bSource) readLoop() {
	bufs := [][]byte{make([]byte, 65535)}
	sizes := make([]int, 1)
	for {
		n, err := bs.dev.Read(bufs, sizes, 0)
		if err != nil || n == 0 {
			return
		}
		for i := 0; i < n; i++ {
			pkt := make([]byte, sizes[i])
			copy(pkt, bufs[i][:sizes[i]])
			select {
			case bs.hub.outbound <- outPkt{data: pkt}:
			case <-bs.dead:
				return
			case <-bs.hub.dead:
				return
			}
		}
	}
}

// writeIn：WG 解密出的「dst = B 本地地址」包投给 B（即 wgnet.Net.Write → InjectInbound）。
func (bs *bSource) writeIn(pkt []byte) int {
	if _, err := bs.dev.Write([][]byte{pkt}, 0); err != nil {
		return 0
	}
	return 1
}

func (bs *bSource) close() {
	bs.once.Do(func() { close(bs.dead) })
}
