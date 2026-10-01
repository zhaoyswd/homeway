package wgcore

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/internal/wtransport"
	"github.com/zhaoyswd/homeway/pkg/proto"
	"github.com/zhaoyswd/homeway/pkg/wgnet"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// Config 数据面装配参数。
type Config struct {
	// TUN App 流量 TUN（生产 = VpnExtension 的 fd；测试 = 内存 TUN）。
	// 两阶段启动时可以留空：先 Prepare（暖机：隧道侧 + WG，**不碰 TUN**），
	// 扩展把 fd 递进来后再 Attach（建 TUN 侧栈与转发器）。
	TUN tun.Device
	MTU int

	// 隧道侧（WG 客户端）
	PeerID         [32]byte // 后端静态公钥
	Secret         [32]byte // token 凭证种子
	Identity       *wtransport.Identity
	Candidates     []wtransport.Candidate
	ServerTunnelIP netip.Addr // 后端隧道 IP（allowed_ip）

	// DirectFirst：直连优先窗口（中继只作后备）。0 = 默认 2s；<0 = 关（所有候选同时打）。
	DirectFirst time.Duration

	// 隧道侧本地地址（空 = 从 Secret+临时公钥派生，tasks 3.7）
	ClientTunnelIP netip.Addr

	Logf func(format string, args ...any)
}

// Core：一套可用的数据面（hub + 隧道侧 netstack B + WG 客户端）。
//
// l3-exit-intercept 形态：应用 transit 包经 hub 直通 WG（手机侧不终结）；
// 核心自连（files/终端/探测/端口转发/DoH）经 B 以普通 TCP/UDP 拨隧道 IP 目标。
type Core struct {
	cfg  Config
	logf func(format string, args ...any)
	// peerIPC 是服务端 peer 的 UAPI 配置原文：ResetPeerSession 用它把 peer
	// 「移除再写回」以强制丢弃本地会话（下一次出站包立即发起全新握手）。
	peerIPC string
	hub     *hub
	wgNet   *wgnet.Net
	bind    *wtransport.Bind
	dev     *device.Device

	// appDev：AttachFD 自己造的 fdTUN 包装（Close 时关——#15 读循环收口信号）。
	appDev    tun.Device
	closeOnce sync.Once
}

// start 装配并启动（非阻塞）。调用方负责在退出时 Close。
// = Prepare + Attach(cfg.TUN)，等价于单阶段启动（测试与不需要两阶段的场景用）。
func start(cfg Config) (*Core, error) {
	c, err := Prepare(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.TUN == nil {
		c.Close()
		return nil, errors.New("wgcore: Start 需要 Config.TUN（两阶段请用 Prepare + Attach）")
	}
	if err := c.Attach(cfg.TUN); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// Prepare 第一阶段：建隧道侧（netstack + WG device）并起握手。
// 此时**没有** TUN：应用流量还不存在，但会话已经可以预热（首个握手/注册搭车在首个
// 出站包时发生；核心自连的拨号等 Attach 后再用）。
func Prepare(cfg Config) (*Core, error) {
	if cfg.MTU <= 0 {
		cfg.MTU = 1280
	}
	if cfg.ServerTunnelIP.IsValid() == false {
		cfg.ServerTunnelIP = defaultServerTunnelIP()
	}
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	c := &Core{cfg: cfg, logf: logf}

	// ---- 隧道侧：netstack（内部流承载）+ WG device ----
	// Identity 恒必填（FIX-17）：UAPI 私钥（peerIPCString）与地址派生都要它——旧校验
	// 允许「显式 ClientTunnelIP + Identity=nil」通过，随后在 :131 解引用 nil panic
	// （.so 内 panic 会带走宿主进程；导出 API 陷阱）。
	if cfg.Identity == nil {
		return nil, errors.New("wgcore: Identity 必填（隧道侧地址派生与 UAPI 私钥都需要；不能省略）")
	}
	cliIP := cfg.ClientTunnelIP
	if !cliIP.IsValid() {
		cliIP = proto.DeriveTunnelIP(cfg.Secret, cfg.Identity.PublicKey())
	}
	wgTun, wgNet, err := wgnet.Create([]netip.Addr{cliIP}, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("wgcore: 隧道侧 netstack: %w", err)
	}
	c.wgNet = wgNet
	// hub：WG device 的 tun 侧多路复用（B 源常在；TUN 源 Attach 时注册）。
	c.hub = newHub(wgTun, tcpip.AddrFromSlice(cliIP.AsSlice()), uint32(cfg.MTU))
	wgTun = c.hub
	directFirst := cfg.DirectFirst
	if directFirst == 0 {
		directFirst = 2 * time.Second // 默认：直连先试 2s，没响应才解锁中继
	}
	if directFirst < 0 {
		directFirst = 0 // 显式关：全部候选同时打（旧行为）
	}
	bind := wtransport.NewBind(wtransport.Config{
		PeerID:      cfg.PeerID,
		Secret:      cfg.Secret,
		Identity:    cfg.Identity,
		Candidates:  cfg.Candidates,
		DirectFirst: directFirst,
		Logf:        logf,
	})
	c.bind = bind
	c.dev = device.NewDevice(wgTun, bind, device.NewLogger(device.LogLevelError, "wgcore"))
	c.peerIPC = peerIPCString(cfg)
	if err := c.dev.IpcSet(c.peerIPC); err != nil {
		c.Close()
		return nil, fmt.Errorf("wgcore: device 配置: %w", err)
	}
	if err := c.dev.Up(); err != nil {
		c.Close()
		return nil, fmt.Errorf("wgcore: device Up: %w", err)
	}
	logf("wgcore: 隧道侧就绪（L3 直通；隧道地址 %v，后端隧道 IP %v，核心自连经 B 拨隧道 IP）",
		cliIP, cfg.ServerTunnelIP)
	return c, nil
}

// Attach 第二阶段：把 App 流量 TUN 注册进 hub（transit 直通 WG）。
// 可重复调用（重复时返回错误，避免两个源抢同一个 TUN）。
func (c *Core) Attach(dev tun.Device) error {
	if dev == nil {
		return errors.New("wgcore: Attach 需要 tun.Device")
	}
	if err := c.hub.AttachTUN(dev); err != nil {
		return err
	}
	c.logf("wgcore: 应用面就绪（TUN 已接上，transit 直通，MTU %d）", c.cfg.MTU)
	return nil
}

// AttachFD 两阶段启动第二阶段（生产入口）：裸 fd 造 tun.Device 并注册进 hub。
// 造出来的 fdTUN 包装由 Core 记住并在 Close 时关（review #15：fdTUN.Close 只关
// 事件通道——fd 仍归扩展——但它是 fdTUN.Read 的 poll 循环退出判据；不关的话
// hub 收工后 appReadLoop 要等扩展 destroy 让 fd 报错才退）。
func (c *Core) AttachFD(fd, mtu int) error {
	dev, err := NewTunFromFD(fd, mtu)
	if err != nil {
		return err
	}
	if err := c.Attach(dev); err != nil {
		return err
	}
	c.appDev = dev
	return nil
}

// SetOnTunError 应用 TUN 读写失败回调（fd 失效 → 调用方标记不健康）。
func (c *Core) SetOnTunError(f func(err error)) { c.hub.SetOnError(f) }

// FdStats 应用 TUN 累计字节数（读=上行 / 写=下行；供 stats 行与状态 JSON）。
func (c *Core) FdStats() (read, write int64) { return c.hub.FdStats() }

// SwapTunOutboundPackets / LastTunOutboundAt：App TUN 出站的需求信号透出
// （demand-driven-recovery D1——巡检拍与待发包下推器的消费入口）。
func (c *Core) SwapTunOutboundPackets() int64 { return c.hub.SwapOutboundPackets() }
func (c *Core) LastTunOutboundAt() time.Time  { return c.hub.LastOutboundAt() }

// ClientTunnelIP 隧道侧本地地址（派生或显式指定）。
func (c *Core) ClientTunnelIP() netip.Addr {
	if c.cfg.ClientTunnelIP.IsValid() {
		return c.cfg.ClientTunnelIP
	}
	return proto.DeriveTunnelIP(c.cfg.Secret, c.cfg.Identity.PublicKey())
}

// DialTCPTunnel 经栈 B 拨隧道内目标的 TCP（核心自连：files/终端/探测/端口转发）。
// 「拨隧道 IP = 拨后端 localhost」由出口的豁免规则实现（l3-exit-intercept D5）。
func (c *Core) DialTCPTunnel(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
	return c.wgNet.DialTCPAddrPortCtx(ctx, ap)
}

// defaultServerTunnelIP 出口隧道 IP 的兜底常量（dns-host-resolver 起为两端契约：
// 手机 VpnConfig 的 dnsAddresses 声明它，出口 intercept 只对它豁免——漂移即静默失效）。
func defaultServerTunnelIP() netip.Addr { return netip.MustParseAddr("100.64.255.1") }

// ServerTunnelIP 后端隧道 IP（Transport 拨「后端 localhost」的语义地址）。
func (c *Core) ServerTunnelIP() netip.Addr { return c.cfg.ServerTunnelIP }

// TunIP 应用面（VpnConfig/TUN）地址：与隧道 IP 同源派生、标签不同的「第二地址」。
// hub 按「dst==隧道IP→B 栈，其余→TUN」分流，两者不可同名（否则应用回程被 B 吃掉）。
func (c *Core) TunIP() netip.Addr {
	return proto.DeriveTunIP(c.cfg.Secret, c.cfg.Identity.PublicKey())
}

// Bind 传输层 Bind（状态快照/重建候选用）。
func (c *Core) Bind() *wtransport.Bind { return c.bind }

// Identity 本核的设备身份（只暴露短指纹给状态面/诊断；私钥不外出）。
func (c *Core) Identity() *wtransport.Identity { return c.cfg.Identity }

// peerIPCString：服务端 peer 的 UAPI 配置（Prepare 与 ResetPeerSession 共用一份，避免漂移）。
func peerIPCString(cfg Config) string {
	return fmt.Sprintf(
		"private_key=%s\npublic_key=%s\npreshared_key=%s\nendpoint=race\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n",
		hexKey(cfg.Identity.PrivateKey()), hexKey(cfg.PeerID), hexKey(proto.DerivePSK(cfg.Secret)))
}

// ResetPeerSession 强制丢弃与服务端 peer 的本地会话：把 peer 移除再按原配置写回。
// 之后**下一次出站包**会立即发起全新握手（wireguard-go 在无 keypair 时就是这条路径）。
//
// 为什么需要它：出口重启/设备记录被回收后，本地会话在客户端看来仍然"有效"（≤120s 才 rekey、
// ≤180s 才拒绝发送），期间所有数据包都被对端丢弃且无人握手 —— 只补注册的话，恢复要等客户端
// 自己的 rekey 计时（最长 ~2 分钟）。主动丢会话 + 补注册 + 补一发探测，恢复就是秒级。
func (c *Core) ResetPeerSession() error {
	if c.dev == nil || c.peerIPC == "" {
		return errors.New("wgcore: device 未就绪")
	}
	if err := c.dev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", hexKey(c.cfg.PeerID))); err != nil {
		return fmt.Errorf("wgcore: 移除 peer 失败: %w", err)
	}
	if err := c.dev.IpcSet(c.peerIPC); err != nil {
		return fmt.Errorf("wgcore: 回写 peer 失败: %w", err)
	}
	c.logf("wgcore: 已丢弃本地会话（peer 移除并写回）—— 下一发出站包将全新握手")
	return nil
}

// Close 收工（幂等）。
func (c *Core) Close() {
	c.closeOnce.Do(func() {
		if c.dev != nil {
			c.dev.Close()
		}
		if c.hub != nil {
			c.hub.Close()
		}
		if c.appDev != nil {
			_ = c.appDev.Close() // 自己造的 fdTUN 包装（#15：读循环收口的信号）
		}
	})
}

// Status 传输层状态（映射进 tunStatusJSON 的 link 段，tasks 2.6）。
func (c *Core) status() wtransport.Status { return c.bind.Status() }

func hexKey(k [32]byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range k {
		out[i*2] = hexdigits[b>>4]
		out[i*2+1] = hexdigits[b&0x0f]
	}
	return string(out)
}
