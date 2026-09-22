package servercore

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zhaoyswd/homeway/pkg/probe"
	"github.com/zhaoyswd/homeway/pkg/proto"
	"golang.zx2c4.com/wireguard/conn"
)

// nowTime 可注入时钟（测试用）。
var nowTime = time.Now

// ServerBind：homewayd 的 conn.Bind。与客户端 wtransport 对称但无赛跑逻辑：
// 监听固定端口，收包按首字节无歧义判别三种形态——
//
//	[0xBB]…      腿帧（来自中继分配 socket）：0=数据入 device / 1=hint 回调 / 2=reg / 未知=忽略
//	"HR"…‖WG     直连 reg 搭车（SplitDirectReg 拆分，先登记后投递）
//	其余          直连裸 WG
//
// Send 恒裸发（对端 endpoint 是中继分配地址或客户端直连地址，两者都收裸 WG；
// 中继负责把回程包包装成腿帧发回客户端）。
type ServerBind struct {
	Port  uint16
	Table *DeviceTable
	Build string // 探测应答里回报的构建标记（就绪行/排障用）
	// Caps：探测应答里回报的能力位（bit0 = 出口默认路径可承载 UDP；nil 或未探过 = 0）。
	// 用函数而不是值：UDP 能力是**周期性探测**的结论，运行期会变（换网/代理开关）。
	Caps func() byte
	// ProbeEndpoints：探测应答端点列表段的来源（endpoint-freshness；nil = 不带列表）。
	// 回调钩子（与 Caps 同款——servercore 不能反向 import internal/server）：返回当前可公布
	// 的公网端点（v4 外口 + stun6 验证过的 v6），与 token 打印同源。应答侧自带防放大约束
	//（请求 pad 够才附列表），这里只管给数据。
	ProbeEndpoints func() []netip.AddrPort
	// OnLegFrame：腿上帧的**额外**分派钩子（中继控制帧走这里；返回 true = 已消费，不进 device）。
	// 已有的固定处理（data/reg/control-hint）在内，钩子只收 type ≥ 3 的帧与显式未处理的分支。
	OnLegFrame func(typ byte, payload []byte, src netip.AddrPort) bool
	// OnHint：中继观察到的客户端公网地址（打洞用）。带包源地址——接线方必须校验
	// src 属中继（#23：hint 是「向任意地址盲打」的触发器，不能让未知源注入）。
	OnHint func(addr string, src netip.AddrPort)
	Logf   func(format string, args ...any)
	// LogfD：细节级日志（入站新源/reg 拒绝这类排查行；nil 时回落 Logf）。
	// 摘要/细节分流见 internal/server/logging.go（2026-09-20 用户口径：终端只看关键信息）。
	LogfD func(format string, args ...any)
	// BindAddr 非零时把 UDP socket 绑到这张网卡的地址上：
	// ① 出站走该接口（绕开 TUN 型代理抢默认路由，旧栈的 `--bind-interface=physical`）；
	// ② STUN 观测到的才是**这个 socket** 在路由器上的真实映射。
	BindAddr netip.Addr
	// BindIface 非空时**双栈**监听并整条 socket 钉在该网卡上（v4+v6 一起）：
	// 这就是出口同时服务 IPv4/IPv6 客户端的形态；比只绑一个地址更通用（v6 地址会轮换）。
	BindIface *net.Interface

	// c：主 WG socket。**原子访问**（review #9）：Open 写一次，但 SendRawTo/LocalPort/
	// STUNQuery/Send/RepinTo 可能从别的 goroutine 在 Open 完成前后读（启动顺序里
	// 中继注册先于 dev.Up() 的年代就靠「读了 nil 报错」混过去）——裸字段在 -race 下
	// 是真竞争。
	c        atomic.Pointer[net.UDPConn]
	stunMu   sync.Mutex
	stunWait *stunPending

	// relay-backend-dial 的数据腿表：远端（中继:P_x）→ connected socket。
	// 收：每腿一个读协程推 legCh，聚合 ReceiveFunc 消费；发：Send 按端点选腿。
	legMu   sync.RWMutex
	legByR  map[netip.AddrPort]*relayLeg
	legByID map[uint64]*relayLeg
	legCh   chan relayLegPkt
	legOnce sync.Once
	// dead_：腿侧收工信号。**每次 Close 关闭、每次 Open 重建**（deadMu 保护）——
	// wireguard-go 的 BindUpdate 契约就是「Close 旧 bind → Open 新 bind」循环，
	// Close 若只执行一次（sync.Once），第二轮 Close 变 no-op：socket 不关、接收
	// goroutine 永远退不出（review #8 要的幂等是「不 panic/可重复」，不是「只许一次」）。
	deadMu sync.Mutex
	dead_  chan struct{}
	// legRecent：最近被摘除的腿远端地址（TTL 内用于 Send 的「不回落主 socket」判定
	// 与日志归因，review #17）。
	legRecent map[netip.AddrPort]time.Time
	// legPorts：**曾经当过一次腿的远端地址**（中继主机 + 数据口）。Send 见到"曾是腿、
	// 但已不是现任腿"的 endpoint 时一律丢弃，且**不受 legRecent 那 5 分钟窗口限制**：
	// 中继的 per-client 数据口是临时端口，被系统回收后可能分给**另一个客户端的会话**，
	// 从主 socket 发过去就落进别人的会话（review 复审 #17/R2 的残留路径；端口复用可能
	// 发生在几小时后，5 分钟窗口盖不住）。
	// 判据精确到端口（不是整个中继主机）：中继主机上的**其它**端口仍可正常直发，
	// 不会把"回不到腿"扩大成"谁都发不出去"。容量有上限，满了清表重记（同 srcSeen）。
	legPorts   map[netip.AddrPort]bool
	legDropped atomic.Uint64 // Send 因「曾是腿地址但腿已摘」而丢弃的包数（#17 观测面）
	pinMu      sync.Mutex
	pinned     *net.Interface // 当前实际钉住的网卡（Open 时设置，Repin 时更新）

	// srcSeen：入站**新源**首包的排障记录。
	// 背景（2026-09-20 排查「直连时好时坏」）：出口对陌生/解不开的包零记录，
	// 「包没到出口」「到了但回程被手机 NAT 过滤」「到了但没回」三个断点一个都看不到。
	// 每个新来源只记一行首包（含 WG 消息类型），正常流量零噪音；
	// 手机换 NAT 映射后的第一发直连握手必落一行 —— 直连路径到达性从此有据可查。
	// ⚠️ **必须持锁**（review #1，致命）：Open 返回两条 ReceiveFunc（主 socket + 腿聚合），
	// wireguard-go 为每条各起一个读 goroutine，两条路径都会走到这里 —— 注释里旧的
	// 「单读 goroutine 无需锁」在 relay-backend-dial 合入当天就失效了，无锁时
	// -race 报 DATA RACE、高并发直接 `fatal error: concurrent map writes` 把整个
	// homewayd 进程带走。容量上限防公网口上的无界增长（满则整表清空并记一行）。
	srcMu   sync.Mutex
	srcSeen map[netip.AddrPort]bool
}

// legPortsMax：「曾当过腿的远端地址」表的容量上限（超过就清表重记——它只是 Send 的
// 兜底判据与日志归因，不是 correctness 状态；真丢了也只是回到"可能发到被复用的数据口"
// 的老行为）。
const legPortsMax = 4096

// srcSeenMax：新源记录表的容量上限。正常多客户端场景不过几百；满了说明在被扫描/
// 洪泛，清表重来（这个表只是排障日志的去重，丢历史无 correctness 影响）。
const srcSeenMax = 4096

// Repin 按**名字**重新解析网卡并把它重新钉到当前 socket 上（换网/接口索引变化后调用）。
// 没配 BindIface 时是 no-op（返回 nil, nil）。
//
// 为什么按名字重解析：接口索引会变（Wi-Fi 关开、换网），老的 index 会让 socket 钉在一个
// 不存在的网卡上 —— 表现是"隧道还在、包发不出去"。名字是稳定的。
func (b *ServerBind) Repin() (*net.Interface, error) {
	cfg := b.BindIface
	if cfg == nil {
		return nil, nil
	}
	ifi, err := net.InterfaceByName(cfg.Name)
	if err != nil {
		return nil, fmt.Errorf("server: 网卡 %s 当前不可用: %w", cfg.Name, err)
	}
	return b.RepinTo(ifi)
}

// RepinTo 把当前 socket 钉到**指定的**网卡上（自动挑卡/换网切换时用；传 nil = 不绑）。
func (b *ServerBind) RepinTo(ifi *net.Interface) (*net.Interface, error) {
	c := b.c.Load()
	if c == nil {
		return nil, fmt.Errorf("server: socket 还没打开")
	}
	b.pinMu.Lock()
	defer b.pinMu.Unlock()
	if ifi == nil {
		b.pinned = nil
		return nil, nil
	}
	if err := PinSocketToIface(c, ifi); err != nil {
		return nil, err
	}
	b.pinned = ifi
	return ifi, nil
}

// relayLeg：一条到中继数据口的 connected UDP 腿（relay-backend-dial）。
type relayLeg struct {
	id     uint64 // 中继侧会话号（RELEASE 关联）
	remote netip.AddrPort
	sock   *net.UDPConn
	last   atomic.Int64 // 最近活动（unix ms）——空闲回收的判据
}

// relayLegPkt：腿上读到的（包， 源=腿远端）。
type relayLegPkt struct {
	pkt []byte
	src netip.AddrPort
}

// 腿上限与空闲回收（review B1：中继侧 closeAll/moved/RELEASE 丢失都会让腿变孤儿，
// 后端必须自持兜底——回收窗对齐中继 IdleTimeout 的 3 倍）。
// legSweepEvery / legIdleAfter / legRecentAfter：回收节拍、空闲阈值与「最近摘除」
// 窗口。**var 而非 const**：单测要把它们压缩到毫秒级（回收循环的启停是 a1 的回归点，
// 不压缩就得等 30s/5min，没法测）。
var (
	legSweepEvery  = relayLegSweep
	legIdleAfter   = relayLegIdle
	legRecentAfter = legRecentTTL
)

const (
	relayLegMax   = 64
	relayLegIdle  = 3 * time.Minute
	relayLegSweep = 30 * time.Second
	// legRecentTTL：「最近摘除的腿地址」的保留窗口（#17）。窗口内对该地址的发送
	// 被判为「腿已摘、不回落主 socket」直接丢弃；窗口过后按普通未知地址处理
	// （回落主 socket —— 那可能是合法的新对端）。
	legRecentTTL = 5 * time.Minute
)

// legInit：腿表/通道（一次）。**不在这里起回收循环**：回收循环按世代启停
// （review 复审 a1——legOnce 起一次的写法在第一次 Close→Open 之后永久死掉：
// 循环看到旧世代的 dead 已关就 return，而 Open 换了新信号却没人再起它 ⇒
// 空闲腿永不回收、legRecent 永不过期，攒到 64 条后新会话再也拿不到腿）。
func (b *ServerBind) legInit() {
	b.legOnce.Do(func() {
		b.legByR = make(map[netip.AddrPort]*relayLeg)
		b.legByID = make(map[uint64]*relayLeg)
		b.legCh = make(chan relayLegPkt, 128)
		b.legRecent = make(map[netip.AddrPort]time.Time)
		b.legPorts = make(map[netip.AddrPort]bool)
	})
}

// deadCh：当前世代的收工信号（惰性创建；deadMu 保护——Open 会整体换新）。
func (b *ServerBind) deadCh() chan struct{} {
	b.deadMu.Lock()
	defer b.deadMu.Unlock()
	if b.dead_ == nil {
		b.dead_ = make(chan struct{})
	}
	return b.dead_
}

// closeDead：关掉当前世代信号（幂等）。
func (b *ServerBind) closeDead() {
	b.deadMu.Lock()
	defer b.deadMu.Unlock()
	if b.dead_ == nil {
		return
	}
	select {
	case <-b.dead_:
	default:
		close(b.dead_)
	}
}

// legDead：Bind 当前世代是否已收工。收工后 RegisterLeg/RemoveLeg/ClearLegs
// 一律 no-op（review #38：否则能在已收工的 Bind 上挂出永不回收的新腿与读协程）。
func (b *ServerBind) legDead() bool {
	select {
	case <-b.deadCh():
		return true
	default:
		return false
	}
}

// legReapLoop：腿空闲回收（review B1）。RELEASE 是主路径，这里是兜底——
// 中继重启不发 RELEASE（closeAll 尽力而为）、控制连接断开丢通告等场景下，
// 无流量超过 relayLegIdle 的腿自动拆掉（socket + 读协程 + 64KB 缓冲全释放）。
// dead = 本世代的收工信号（Open 启动、Close 关闭；换代后由新的 Open 再起一条）。
func (b *ServerBind) legReapLoop(dead chan struct{}) {
	t := time.NewTicker(legSweepEvery)
	defer t.Stop()
	for {
		select {
		case <-dead:
			return
		case <-t.C:
		}
		now := time.Now().UnixMilli()
		b.legMu.Lock()
		for _, lg := range b.legByID {
			if now-lg.last.Load() > legIdleAfter.Milliseconds() {
				b.logf("腿（会话 #%d → %v）空闲超 %v，回收", lg.id, lg.remote, legIdleAfter)
				b.removeLegLocked(lg)
			}
		}
		// 「最近摘除的腿地址」过期清理（#17 的判定窗口）。
		for ap, at := range b.legRecent {
			if now-at.UnixMilli() > legRecentAfter.Milliseconds() {
				delete(b.legRecent, ap)
			}
		}
		b.legMu.Unlock()
	}
}

// RegisterLeg：向中继数据口拨一条腿（connected），发认证标记并开始接收。
// marker = 拨腿首包载荷：v2 会话是 LEGUP‖cookie‖MAC（腿身份认证，#3），
// v1 是纯 "LEGUP"。同 id 或同远端重复注册 = 先拆旧再建（中继侧会话重建的语义）。
// Bind 已收工（dead 已关）时 no-op（#38）。
func (b *ServerBind) RegisterLeg(id uint64, remote netip.AddrPort, marker []byte) error {
	b.legInit()
	if b.legDead() {
		return fmt.Errorf("server: bind 已收工，拒绝注册腿 #%d", id)
	}
	if len(marker) == 0 {
		marker = []byte("LEGUP")
	}
	// 按目标族选 socket 网络（review B6：写死 udp4 会让 v6 中继端点恒失败）。
	network := "udp4"
	if remote.Addr().Is6() {
		network = "udp6"
	}
	sock, err := net.DialUDP(network, nil, &net.UDPAddr{IP: remote.Addr().AsSlice(), Port: int(remote.Port())})
	if err != nil {
		return err
	}
	if _, err := sock.Write(marker); err != nil {
		_ = sock.Close()
		return err
	}
	lg := &relayLeg{id: id, remote: remote, sock: sock}
	lg.last.Store(time.Now().UnixMilli())
	b.legMu.Lock()
	// 上限只拦「新 id」（review C3）：对已有 id 的重放/重建是替换语义，满员时
	// 若先拦后换，中继 replay 会把活跃会话的腿拒之门外。
	if _, exists := b.legByID[id]; !exists && len(b.legByID) >= relayLegMax {
		b.legMu.Unlock()
		_ = sock.Close()
		return fmt.Errorf("腿数已达上限 %d", relayLegMax)
	}
	if old := b.legByID[id]; old != nil {
		b.removeLegLocked(old)
	}
	if old := b.legByR[remote]; old != nil {
		b.removeLegLocked(old)
	}
	b.legByID[id] = lg
	b.legByR[remote] = lg
	if b.legPorts != nil {
		if len(b.legPorts) >= legPortsMax {
			b.legPorts = make(map[netip.AddrPort]bool) // 满表清空（排障级记忆，丢了只影响归因）
		}
		b.legPorts[remote] = true // 记住"这个端口当过腿"（Send 的兜底丢弃判据）
	}
	// 同地址重拨成功：撤掉「最近摘除」标记（这个远端又有腿了，Send 正常走腿）。
	delete(b.legRecent, remote)
	b.legMu.Unlock()
	go b.legReadLoop(lg, sock, b.deadCh())
	return nil
}

// ClearLegs：拆掉全部腿（控制面重连对账——中继在 OK 后会重放全量 SESSION，
// 后端先清再按重放重建；review B1 的「重启清孤儿」主路径）。收工后 no-op（#38）。
func (b *ServerBind) ClearLegs() {
	b.legInit()
	if b.legDead() {
		return
	}
	b.legMu.Lock()
	defer b.legMu.Unlock()
	for _, lg := range b.legByID {
		b.removeLegLocked(lg)
	}
}

// RemoveLeg：按会话号拆腿（RELEASE / 收工）。不存在 = no-op；收工后 no-op（#38）。
func (b *ServerBind) RemoveLeg(id uint64) {
	b.legInit()
	if b.legDead() {
		return
	}
	b.legMu.Lock()
	defer b.legMu.Unlock()
	if lg := b.legByID[id]; lg != nil {
		b.removeLegLocked(lg)
	}
}

// removeLegLocked：关 socket + 双表摘除（调用方持锁）。socket 关闭让读协程退出；
// 「同远端新腿不串旧流」由 socket 生命周期保证（旧 socket 已关，不可能再投递）。
// 摘除的远端进 legRecent（#17：Send 在 TTL 内对它丢弃、不回落主 socket）。
func (b *ServerBind) removeLegLocked(lg *relayLeg) {
	_ = lg.sock.Close()
	if b.legByID[lg.id] == lg {
		delete(b.legByID, lg.id)
	}
	if b.legByR[lg.remote] == lg {
		delete(b.legByR, lg.remote)
	}
	if b.legRecent != nil {
		b.legRecent[lg.remote] = time.Now()
	}
}

// legReadLoop：一条腿的读循环（connected socket 的 Read；源恒为腿远端）。
// 读循环退出（socket 关闭/ICMP 拒绝等）即摘腿（review #8）：Send 会刷新 last，
// 死腿靠空闲扫描永远扫不掉 —— 不在这里摘，WG 会一直往死 socket 写。
func (b *ServerBind) legReadLoop(lg *relayLeg, sock *net.UDPConn, dead chan struct{}) {
	defer func() {
		b.legMu.Lock()
		// 只摘「仍是本人」的表项（期间可能已被 RegisterLeg 替换成新腿）。
		if b.legByID[lg.id] == lg || b.legByR[lg.remote] == lg {
			b.logf("腿（会话 #%d → %v）读循环退出，摘除", lg.id, lg.remote)
			if b.legByID[lg.id] == lg {
				delete(b.legByID, lg.id)
			}
			if b.legByR[lg.remote] == lg {
				delete(b.legByR, lg.remote)
			}
			if b.legRecent != nil {
				b.legRecent[lg.remote] = time.Now()
			}
		}
		b.legMu.Unlock()
	}()
	buf := make([]byte, 65535)
	for {
		n, err := sock.Read(buf)
		if err != nil {
			return
		}
		if n == 5 && string(buf[:n]) == "LEGUP" {
			continue // 防御：中继侧已吞，正常到不了这里
		}
		if n == 37 && string(buf[:5]) == "LEGUP" {
			continue // 防御：认证 marker 的回显（同上）
		}
		lg.last.Store(time.Now().UnixMilli())
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		select {
		case b.legCh <- relayLegPkt{pkt: pkt, src: lg.remote}:
		case <-dead:
			return
		}
	}
}

// legReceiveFunc：聚合的腿接收函数（Open 时追加到 ReceiveFunc 列表）。
// dead 参数 = Open 时刻的收工信号（Close→Open 换代后，旧接收函数随旧信号退出）。
func (b *ServerBind) legReceiveFunc(dead chan struct{}) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			var lp relayLegPkt
			select {
			case lp = <-b.legCh:
			case <-dead:
				// 收工信号：阻塞读退出（device 关 Bind 时会停；这里返回错误让循环结束）
				return 0, net.ErrClosed
			}
			// 腿上的包与主 socket 同构（中继按 0xBB 帧封装后转发）——走同一条解析。
			n, err := b.processPacket(packets, sizes, eps, lp.pkt, lp.src)
			if err != nil {
				return 0, err
			}
			if n > 0 {
				return n, nil
			}
			// 被内部消费（腿帧/探测/STUN）的包：继续读下一条
		}
	}
}

// SendRawTo：从**同一个 WG socket** 直接发给 addr（中继注册/保活/盲打都用它 ——
// 注册腿必须与数据面同端口，NAT 映射才会一致，见 design D4）。
func (b *ServerBind) SendRawTo(addr netip.AddrPort, payload []byte) error {
	c := b.c.Load()
	if c == nil {
		return fmt.Errorf("server: socket 还没打开")
	}
	_, err := c.WriteToUDPAddrPort(payload, addr)
	return err
}

// SendTo：与 Send 同款路由（endpoint 命中腿表走腿、否则主 socket、腿已摘则丢弃），
// 供非 WG 调用方（测试/e2e）按「数据面真实路径」发包。注册/保活/盲打仍用 SendRawTo
// （那条路刻意钉主 socket：注册腿必须与数据面同端口，NAT 映射才一致）。
func (b *ServerBind) SendTo(addr netip.AddrPort, buf []byte) error {
	return b.Send([][]byte{buf}, srvEP{addr})
}

// PinnedIface 当前钉住的网卡（没绑卡时 nil）。
func (b *ServerBind) PinnedIface() *net.Interface {
	b.pinMu.Lock()
	defer b.pinMu.Unlock()
	return b.pinned
}

// listenWithFallback：监听口被占用时的退让顺序 —— +1…+9，最后随机。
// 返回已监听的 socket；全失败返回最后的错误。
func listenWithFallback(network string, laddr *net.UDPAddr, port uint16) (*net.UDPConn, error) {
	var lastErr error
	for p := int(port) + 1; p <= int(port)+9; p++ {
		la := *laddr
		la.Port = p
		c, err := net.ListenUDP(network, &la)
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	la := *laddr
	la.Port = 0
	c, err := net.ListenUDP(network, &la)
	if err == nil {
		return c, nil
	}
	if err != nil {
		lastErr = err
	}
	return nil, lastErr
}

// stunPending 一次在飞的 STUN 查询（接收路径匹配事务 ID 后把结果投给它）。
type stunPending struct {
	txid [12]byte
	ch   chan netip.AddrPort
}

// srvEP：服务端视角的真实地址端点（device 的 SetEndpointFromPacket 原生语义即可用）。
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

func (b *ServerBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	// 网络族：默认**双栈**（v4 + v6），这样出口既能被 IPv4 客户端连，也能被 IPv6 客户端连，
	// 且同一个 socket 上做 STUN 观测对两族都成立。显式绑地址时按该地址的族走单栈。
	network := "udp"
	laddr := &net.UDPAddr{Port: int(port)}
	if b.BindAddr.IsValid() {
		laddr.IP = b.BindAddr.AsSlice()
		if b.BindAddr.Is4() {
			network = "udp4"
		} else {
			network = "udp6"
		}
	}
	c, err := net.ListenUDP(network, laddr)
	if err != nil {
		// 端口被占用**不能**让出口起不来（旧实例没退干净、别的服务抢先、快速重启撞 TIME_WAIT…）。
		// 按 监听口 → +1…+9 → 随机 的顺序退让，并把实际端口打出来（UPnP/STUN/公布/token 全按实际端口走）。
		if port != 0 {
			if alt, aerr := listenWithFallback(network, laddr, port); aerr == nil {
				altPort := uint16(0)
				if ua, ok := alt.LocalAddr().(*net.UDPAddr); ok {
					altPort = uint16(ua.Port)
				}
				b.logf("⚠️ 监听端口 %d 被占用（%v）—— 改用 %d；token 里的端口以公布/签发为准", port, err, altPort)
				c, err = alt, nil
			}
		}
		if err != nil {
			return nil, 0, err
		}
	}
	if b.BindIface != nil {
		if err := PinSocketToIface(c, b.BindIface); err != nil {
			// 钉不上卡**不致命**：继续按未绑卡运行，并把后果说清楚（公网端点公布会自动变保守：
			// 只有 PinnedIface()!=nil 时才允许"外口≠监听口"的拼法）。
			b.logf("⚠️ 钉网卡 %s 失败（%v）—— 继续以未绑卡运行：STUN 观测可能被 TUN 型代理污染，"+
				"公网端点公布会因此变保守", b.BindIface.Name, err)
		} else {
			b.pinMu.Lock()
			b.pinned = b.BindIface
			b.pinMu.Unlock()
		}
	} else if laddr.IP != nil {
		// 绑了源地址还要把 socket 钉在该网卡上（见 PinSocketToIface 的注释）：
		// 否则默认路由被 TUN 型代理抢走时，STUN 观测到的是代理的映射而不是路由器上的真实映射。
		if ip, ok := netip.AddrFromSlice(laddr.IP); ok {
			if ifi := ifaceForAddr(ip.Unmap()); ifi != nil {
				if err := PinSocketToIface(c, ifi); err != nil {
					b.logf("⚠️ 钉网卡 %s 失败（%v）—— 继续以未绑卡运行（公网端点公布变保守）", ifi.Name, err)
				} else {
					b.pinMu.Lock()
					b.pinned = ifi
					b.pinMu.Unlock()
				}
			}
		}
	}
	b.c.Store(c)
	actual := uint16(c.LocalAddr().(*net.UDPAddr).Port)
	b.legInit()
	// 换代收工信号：上一世代的腿侧读循环/聚合接收随旧信号退出（BindUpdate 的
	// Close→Open 循环语义；此前 dead 由 legInit 建一次，Once 化的 Close 会让
	// 第二轮 Close 变 no-op——socket 不关、接收 goroutine 卡死，实测踩过）。
	b.closeDead()
	b.deadMu.Lock()
	b.dead_ = make(chan struct{})
	dead := b.dead_
	b.deadMu.Unlock()
	go b.legReapLoop(dead) // 每世代一条（a1）：Close 关信号即退出，重新 Open 再起
	fn := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, src, err := c.ReadFromUDPAddrPort(packets[0])
		if err != nil {
			return 0, err
		}
		if src.Addr().Is4In6() {
			src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		}
		buf := make([]byte, n)
		copy(buf, packets[0][:n])
		return b.processPacket(packets, sizes, eps, buf, src)
	}
	return []conn.ReceiveFunc{fn, b.legReceiveFunc(dead)}, actual, nil
}

// processPacket：一个入站 UDP 包的完整解析（主 socket 与中继数据腿共用）。
// 返回 >0 = 交给 device 的包数；0 = 内部消费；err = 读路径终止。
func (b *ServerBind) processPacket(packets [][]byte, sizes []int, eps []conn.Endpoint, buf []byte, src netip.AddrPort) (int, error) {
	// STUN 观测：只认事务 ID 匹配的应答，消耗掉不进 device（见 STUNQuery）。
	if stunLooksLikeResponse(buf) {
		if b.deliverSTUN(buf) {
			b.noteNewSrc(src, "STUN应答", len(buf))
			return 0, nil
		}
	}

	// 参照点探测（tasks 3.6）：明文一问一答，不进 WG、不登记 peer、不碰会话状态。
	// 客户端在「全部候选失败」时用它做三档归因（本机 / 链路 / 后端）。
	// 端点列表段（endpoint-freshness）：请求 pad 够的探测顺带拿到出口当前公网端点——
	// 手机侧旁路探测由此持续保鲜学习缓存；老请求方拿不到列表（RespondEx 内的 pad 契约）。
	caps := byte(0)
	if b.Caps != nil {
		caps = b.Caps()
	}
	var probeEps []netip.AddrPort
	if b.ProbeEndpoints != nil {
		probeEps = b.ProbeEndpoints()
	}
	if resp := probe.RespondEx(buf, src, b.Build, caps, probeEps); resp != nil {
		b.noteNewSrc(src, "参照点探测", len(buf))
		if c := b.c.Load(); c != nil {
			_, _ = c.WriteToUDPAddrPort(resp, src)
		}
		return 0, nil
	}

	if len(buf) > 0 && buf[0] == 0xBB {
		typ, payload, err := proto.DecodeFrame(buf)
		if err != nil {
			b.noteNewSrc(src, "畸形腿帧", len(buf))
			return 0, nil // 畸形腿帧：丢弃不中断（fn 返回 0 会继续被调用）
		}
		switch typ {
		case proto.FrameTypeData:
			b.noteNewSrc(src, "腿帧数据", len(buf))
			sizes[0] = len(payload)
			copy(packets[0], payload)
			eps[0] = srvEP{src}
			return 1, nil
		case proto.FrameTypeReg:
			b.noteNewSrc(src, "腿帧注册", len(buf))
			if _, err := b.Table.Register(payload, nowTime()); err != nil {
				b.logfD("reg 腿帧被拒（来源 %v）：%v", src, err)
			}
			return 0, nil
		case proto.FrameTypeControl:
			b.noteNewSrc(src, "腿帧控制", len(buf))
			if b.OnHint != nil {
				if addr, err := proto.DecodeHintPayload(payload); err == nil {
					b.OnHint(addr, src)
				}
			}
			return 0, nil
		default:
			// 中继控制帧（type≥3）等留给钩子；没钩子就按前向兼容忽略。
			b.noteNewSrc(src, fmt.Sprintf("腿帧type=%d", typ), len(buf))
			if b.OnLegFrame != nil && b.OnLegFrame(typ, payload, src) {
				return 0, nil
			}
			return 0, nil
		}
	}

	if reg, rest, ok := proto.SplitDirectReg(buf); ok {
		shape := "直连reg搭车"
		if len(rest) > 0 {
			shape += "+" + wgMsgName(rest[0])
		}
		b.noteNewSrc(src, shape, len(buf))
		if _, err := b.Table.Register(reg, nowTime()); err != nil {
			b.logfD("reg 搭车被拒（来源 %v）：%v", src, err)
			return 0, nil
		}
		sizes[0] = len(rest)
		copy(packets[0], rest)
		eps[0] = srvEP{src}
		return 1, nil
	}

	// 直连裸 WG
	shape := "直连裸WG"
	if len(buf) > 0 {
		shape = "直连裸" + wgMsgName(buf[0])
	}
	b.noteNewSrc(src, shape, len(buf))
	sizes[0] = len(buf)
	copy(packets[0], buf)
	eps[0] = srvEP{src}
	return 1, nil
}

// wgMsgName：WG 报文类型码 → 可读名（首包日志用；type 见 wireguard 规范）。
func wgMsgName(b byte) string {
	switch b {
	case 1:
		return "WG握手发起"
	case 2:
		return "WG握手应答"
	case 3:
		return "WG cookie"
	case 4:
		return "WG传输数据"
	}
	return "非WG"
}

// noteNewSrc：入站新源的首包一行（每个来源只记一次）。shape 描述这包的形态。
// 收到「WG握手发起」却迟迟不形成会话 = 出口侧密钥/注册问题；一个新源都没有 =
// 包死在半路（手机网络/运营商/路由器映射）——这两类从此一眼可分。
// 持锁 + 容量上限（review #1，致命）：Open 返回两条 ReceiveFunc，wireguard-go 为
// 各起一条读 goroutine，两条路径并发到这里 —— 无锁时 -race 报 DATA RACE、
// 高并发直接 `fatal error: concurrent map writes` 带走整个 homewayd 进程。
func (b *ServerBind) noteNewSrc(src netip.AddrPort, shape string, n int) {
	b.srcMu.Lock()
	if b.srcSeen == nil {
		b.srcSeen = make(map[netip.AddrPort]bool)
	}
	if b.srcSeen[src] {
		b.srcMu.Unlock()
		return
	}
	if len(b.srcSeen) >= srcSeenMax {
		// 满表：大概率在被扫描/洪泛。整表清空（排障去重表，不是 correctness 状态）。
		b.srcSeen = make(map[netip.AddrPort]bool)
		b.logfD("入站新源表满（%d 条），清表重记", srcSeenMax)
	}
	b.srcSeen[src] = true
	b.srcMu.Unlock()
	b.logfD("入站新源：%v（%s，%d 字节）", src, shape, n)
}

// logfD 细节级（未接线时回落摘要级，别丢线索）。
func (b *ServerBind) logfD(format string, args ...any) {
	if b.LogfD != nil {
		b.LogfD(format, args...)
		return
	}
	b.logf(format, args...)
}

// Close 收工。**可重复、可重开**（wireguard-go 的 BindUpdate 就是 Close→Open 循环，
// review #8 的幂等 = 并发/重复调用不 panic、不漏关；不是「只执行一次」）：
// 关当前世代的收工信号（腿侧读循环退出）+ 全部腿 + 主 socket。Open 会重建信号。
func (b *ServerBind) Close() error {
	b.closeDead()
	b.legMu.Lock()
	for _, lg := range b.legByID {
		_ = lg.sock.Close()
	}
	b.legByID = map[uint64]*relayLeg{}
	b.legByR = map[netip.AddrPort]*relayLeg{}
	b.legMu.Unlock()
	if c := b.c.Load(); c != nil {
		_ = c.Close()
	}
	return nil
}

// deliverSTUN 把 STUN 应答交给等待者（事务 ID 匹配才认）。返回 true = 已被消耗。
func (b *ServerBind) deliverSTUN(pkt []byte) bool {
	b.stunMu.Lock()
	w := b.stunWait
	if w == nil {
		b.stunMu.Unlock()
		return false
	}
	ap, ok := stunParseBindingResponse(pkt, w.txid)
	if !ok {
		b.stunMu.Unlock()
		return false // 事务 ID 不匹配：不是我们要的应答，照常交给 device（不会有害）
	}
	b.stunWait = nil
	b.stunMu.Unlock()
	select {
	case w.ch <- ap:
	default:
	}
	return true
}

// LocalPort 返回实际监听的 UDP 端口（Open 之后有效；0 = 还没开）。
func (b *ServerBind) LocalPort() uint16 {
	c := b.c.Load()
	if c == nil {
		return 0
	}
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

// STUNQuery 在**本 Bind 的 UDP socket** 上问一次 STUN 服务器「你看到的我是什么地址」（IPv4 路径）。
// 拿到的是「监听端口这个 socket」的 NAT 映射（同一 socket 收发，端口不受源端口改写影响）。
func (b *ServerBind) STUNQuery(ctx context.Context, server string) (netip.AddrPort, error) {
	return b.stunQuery(ctx, server, false)
}

// STUNQueryV6 同 STUNQuery，但走 IPv6：用来确认「双栈 socket 的 v6 路径可用」，
// 并拿到服务器看到的 v6 地址（v6 无 NAT，应当等于本机全局地址）。
func (b *ServerBind) STUNQueryV6(ctx context.Context, server string) (netip.AddrPort, error) {
	return b.stunQuery(ctx, server, true)
}

func (b *ServerBind) stunQuery(ctx context.Context, server string, want6 bool) (netip.AddrPort, error) {
	c := b.c.Load()
	if c == nil {
		return netip.AddrPort{}, fmt.Errorf("server: bind 尚未 Open")
	}
	host, portStr, err := net.SplitHostPort(server)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("解析 STUN 服务器 %q: %w", server, err)
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("STUN 服务器端口 %q: %w", portStr, err)
	}
	network := "ip4"
	if want6 {
		network = "ip6"
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, network, host)
	if err != nil || len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("解析 STUN 服务器 %q 的 %s: %w", server, network, err)
	}
	rap := ips[0]
	if want6 {
		if !rap.Is6() || rap.Is4In6() {
			return netip.AddrPort{}, fmt.Errorf("STUN 服务器 %q 没有可用的 IPv6 地址", server)
		}
	} else {
		if rap = rap.Unmap(); !rap.Is4() {
			return netip.AddrPort{}, fmt.Errorf("STUN 服务器 %q 没有可用的 IPv4 地址", server)
		}
	}
	target := netip.AddrPortFrom(rap, uint16(port))

	var txid [12]byte
	if _, err := rand.Read(txid[:]); err != nil {
		return netip.AddrPort{}, err
	}
	w := &stunPending{txid: txid, ch: make(chan netip.AddrPort, 1)}
	b.stunMu.Lock()
	b.stunWait = w // 同一时刻只允许一次查询（轮询周期都是分钟级）
	b.stunMu.Unlock()
	defer func() {
		b.stunMu.Lock()
		if b.stunWait == w {
			b.stunWait = nil
		}
		b.stunMu.Unlock()
	}()

	if _, err := c.WriteToUDPAddrPort(stunBindingRequest(txid), target); err != nil {
		return netip.AddrPort{}, fmt.Errorf("发 STUN 请求: %w", err)
	}
	select {
	case ap := <-w.ch:
		return ap, nil
	case <-ctx.Done():
		return netip.AddrPort{}, fmt.Errorf("等 STUN 应答: %w", ctx.Err())
	}
}

func (b *ServerBind) SetMark(mark uint32) error { return nil }

func (b *ServerBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(srvEP)
	if !ok {
		return fmt.Errorf("server: 未知 endpoint 类型 %T", ep)
	}
	// relay-backend-dial：endpoint 命中腿表时走该腿的 connected socket——
	// 回程必须与「后端拨出去的映射」同五元组（严格 NAT 的构造性穿透）。
	b.legMu.RLock()
	lg := b.legByR[e.ap]
	recent := false
	everLeg := false
	if lg == nil {
		if b.legRecent != nil {
			_, recent = b.legRecent[e.ap]
		}
		if b.legPorts != nil {
			everLeg = b.legPorts[e.ap]
		}
	}
	b.legMu.RUnlock()
	if lg != nil {
		lg.last.Store(time.Now().UnixMilli())
		for _, buf := range bufs {
			if _, err := lg.sock.Write(buf); err != nil {
				return err
			}
		}
		return nil
	}
	if recent || everLeg {
		// #17：该 endpoint 是「中继主机上的数据口」。腿不在了（RELEASE 丢失/控制空窗回收/
		// 重连对账中/端口已被回收给别人）却从**主 socket** 发，会打到中继主口或被复用的
		// 数据口 —— 要么被中继当未知源丢弃，要么污染别的会话。丢弃 + 计数；等控制重连的
		// SESSION 重放重建腿（或下一个入站包重学 endpoint）后自愈。
		// legHost 判据不受 5 分钟窗口限制（端口复用可能发生在很久以后）。
		if n := b.legDropped.Add(1); n <= 3 || n%1000 == 0 {
			b.logfD("腿已摘或非现任（%v）丢弃出站 %d 包（等控制面重放重建腿）", e.ap, len(bufs))
		}
		return nil
	}
	c := b.c.Load()
	if c == nil {
		return fmt.Errorf("server: socket 还没打开")
	}
	for _, buf := range bufs {
		if _, err := c.WriteToUDPAddrPort(buf, e.ap); err != nil {
			return err
		}
	}
	return nil
}

func (b *ServerBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return srvEP{ap}, nil
}

func (b *ServerBind) BatchSize() int { return 1 }

func (b *ServerBind) logf(format string, args ...any) {
	if b.Logf != nil {
		b.Logf(format, args...)
	}
}
