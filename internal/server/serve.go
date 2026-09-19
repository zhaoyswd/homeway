package server

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/zhaoyswd/homeway/pkg/egress"
	"github.com/zhaoyswd/homeway/pkg/files"
	"github.com/zhaoyswd/homeway/pkg/flows"
	"github.com/zhaoyswd/homeway/pkg/servercore"
	"github.com/zhaoyswd/homeway/pkg/term"
	"github.com/zhaoyswd/homeway/pkg/wgnet"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// 默认内部地址（隧道内，客户端 token/配置与之配套）。
const (
	DefaultTunnelIP   = "100.64.255.1"
	DefaultFlowPort   = uint16(7800) // TCP CONNECT 流
	DefaultUDPFlowPrt = uint16(7801) // UDP 数据报（DNS 等）
	DefaultFilesPort  = uint16(7802) // files 原生协议（后端本机 127.0.0.1）
	DefaultTermPort   = uint16(7724) // 终端会话 / agent gateway（与旧栈 tunnel 内虚拟端口同号）
)

// EgressMode：某类转发流量走哪条路。
//
//	bind：钉在 --bind-interface 的物理网卡上（不经 TUN 型代理）；
//	default：走系统默认路由 —— TUN 型代理（Surge 等）按自己的规则处理。
type EgressMode string

const (
	EgressBind    EgressMode = "bind"
	EgressDefault EgressMode = "default"
	// EgressAuto：按机器当前状态自动判定（默认值，见 resolveEgressPolicy）。
	EgressAuto EgressMode = "auto"
)

// ForwardEgress：TCP/UDP 各自的去向。两者可以不同 —— 实测（2026-09-19）：
// TUN 型代理会按规则处理 TCP（境外走代理能通），但**不中继 UDP**（QUIC 有去无回），
// 所以 Mac 出口最合适的配置常是 `tcp=default,udp=bind`：TCP 交给代理策略，UDP 直出物理网卡。
type ForwardEgress struct {
	TCP EgressMode
	UDP EgressMode
}

// BindMode：WG socket（打洞/STUN）钉哪张物理网卡。
//
//	BindAuto（默认）：候选物理网卡逐个探针，挑最快探通的那张（见 pkg/egress.SelectBest）；
//	                  挑不到就不绑（退回系统默认路由）并打日志，绝不因此拒绝启动。
//	BindExplicit：--bind-interface <网卡名>，只按名字重解析（换网/索引变化时跟上）。
//	BindOff：不绑（--bind-interface none）。TUN 型代理抢默认路由的机器上**不要用**：
//	         STUN 观测到的会是代理的映射，打洞与端点公布都不成立。
type BindMode string

const (
	BindAuto     BindMode = "auto"
	BindExplicit BindMode = "explicit"
	BindOff      BindMode = "off"
)

// ParseForwardEgress 解析 --forward-egress：
//
//	auto（默认）/ bind / default —— 同时作用于 TCP 与 UDP（auto 的判据见 resolveEgressPolicy）
//	tcp=default,udp=bind        —— 分开指定（可只写一项，另一项默认 auto）
//	（空 = auto）
func ParseForwardEgress(v string) (ForwardEgress, error) {
	out := ForwardEgress{TCP: EgressAuto, UDP: EgressAuto}
	v = strings.TrimSpace(v)
	if v == "" {
		return out, nil
	}
	if !strings.Contains(v, "=") {
		m, err := parseEgressMode(v)
		if err != nil {
			return out, err
		}
		out.TCP, out.UDP = m, m
		return out, nil
	}
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, val, ok := strings.Cut(part, "=")
		if !ok {
			return out, fmt.Errorf("--forward-egress %q：%q 应为 tcp=… 或 udp=…", v, part)
		}
		m, err := parseEgressMode(val)
		if err != nil {
			return out, err
		}
		switch strings.TrimSpace(key) {
		case "tcp":
			out.TCP = m
		case "udp":
			out.UDP = m
		default:
			return out, fmt.Errorf("--forward-egress %q：只认 tcp / udp（收到 %q）", v, key)
		}
	}
	return out, nil
}

func parseEgressMode(v string) (EgressMode, error) {
	switch strings.TrimSpace(v) {
	case string(EgressAuto):
		return EgressAuto, nil
	case string(EgressBind):
		return EgressBind, nil
	case string(EgressDefault):
		return EgressDefault, nil
	default:
		return "", fmt.Errorf("--forward-egress %q：只支持 auto、bind、default", v)
	}
}

// resolveEgressPolicy：把 auto 落成具体模式（纯函数，便于单测）。
//
// 判据只有一条：**默认路由那张卡是不是隧道型网卡**（utun/bridge/wg… 见 egress.IsVirtualIface）。
//
//	是 → 有 TUN 型代理（Surge 等）在抢默认路由：
//	     TCP 交给它（用户跑这个代理就是要它的规则：境内直连、境外走代理）；
//	     UDP 钉物理网卡（实测这类代理不中继 UDP：同会话"上行 5 包、下行 0 包"，钉卡直出才通）。
//	否 → 默认路由本来就是物理网卡：两块都钉该卡（与走默认路由等价，但更确定；
//	     也防"以后又冒出个代理"时不声不响地改道）。
func resolveEgressPolicy(cfg ForwardEgress, prefer *net.Interface) (tcp, udp EgressMode) {
	tcp, udp = cfg.TCP, cfg.UDP
	tunProxy := prefer != nil && egress.IsVirtualIface(prefer.Name)
	apply := func(m EgressMode) EgressMode {
		if m != EgressAuto {
			return m
		}
		if tunProxy {
			return EgressDefault
		}
		return EgressBind
	}
	tcp = apply(tcp)
	if udp == EgressAuto {
		if tunProxy {
			udp = EgressBind // UDP 一律不交给 TUN 型代理
		} else {
			udp = EgressBind
		}
	}
	return tcp, udp
}

type ServeConfig struct {
	StateDir     string
	ListenPort   uint16
	TunnelIP     netip.Addr
	FlowPort     uint16
	UDPFlowPort  uint16
	FilesPort    uint16        // files 服务在本机的监听端口（客户端经流协议 CONNECT 到它）
	FilesRoot    string        // files 根（空 = 用户主目录；协议恒读写）
	TermPort     uint16        // 终端会话 / agent gateway 在本机的监听端口
	FlowMaxConns int           // 内部流并发上限（0 = 默认 64）
	FlowIdle     time.Duration // 内部流空闲回收（0 = 默认 30 分钟；终端会话腿也走这里，别设太短）
	BuildTag     string        // 探测应答里回报的构建标记（空 = 用内置默认）
	BindAddr     netip.Addr    // 非零 = 把 WG UDP socket 绑到该地址（该网卡出站；STUN 观测同 socket）
	BindIface    *net.Interface // 非空 = 双栈监听并整条 socket 钉在该网卡（同时支持 v4/v6 客户端）
	BindMode     BindMode       // WG socket 钉哪张卡：auto（默认，自动挑）/explicit（用 BindIface）/off（不绑）
	ForwardEgress ForwardEgress // 转发出站走哪条路（TCP/UDP 可分开）：bind（默认，钉网卡）/ default（系统默认路由 = TUN 型代理）
	UPnP         bool          // 启动后向路由器申请 UDP 端口映射并 30 分钟续期
	STUN         string        // 非空 = 在监听 socket 上向该 STUN 服务器观测公网映射（如 stun.miwifi.com:3478）
	STUN6        string        // 非空 = 用该服务器做 **IPv6** 路径校验（要有 AAAA，如 stun.cloudflare.com:3478）
	Verbose      bool
}

func (c *ServeConfig) fill() {
	if c.ListenPort == 0 {
		c.ListenPort = 41641
	}
	if !c.TunnelIP.IsValid() {
		c.TunnelIP = netip.MustParseAddr(DefaultTunnelIP)
	}
	if c.FlowPort == 0 {
		c.FlowPort = DefaultFlowPort
	}
	if c.UDPFlowPort == 0 {
		c.UDPFlowPort = DefaultUDPFlowPrt
	}
	if c.FilesPort == 0 {
		c.FilesPort = DefaultFilesPort
	}
	if c.TermPort == 0 {
		c.TermPort = DefaultTermPort
	}
	if c.FlowMaxConns <= 0 {
		c.FlowMaxConns = 64
	}
	if c.FlowIdle <= 0 {
		c.FlowIdle = 30 * time.Minute
	}
}

// Server：homewayd 的完整数据面装配（netstack + WG device + ServerBind + PeerTable + flows）。
type Server struct {
	cfg   ServeConfig
	Stats *flows.Stats // dialok / dialfail / flows（状态面 3.6 消费）
	Table *servercore.PeerTable

	dev     *device.Device
	bind    *servercore.ServerBind
	bindIface *net.Interface     // 本轮实际钉住的网卡（auto 挑出来的或显式给的；nil = 不绑）
	fwdTCP    *egress.Binder     // 转发 TCP 用的绑定器（跟着换卡走）
	fwdUDP    *egress.Binder     // 转发 UDP 用的绑定器（跟着换卡走）
	fwdEgress ForwardEgress      // --forward-egress 原始取值（auto 需要周期重算）
	stopTCP func()
	stopUDP func()
	pubKick chan struct{} // 公网端点探测的"立即重测"信号（换网事件踢）
	filesLn net.Listener
	files   *files.Server
	termLn  net.Listener
	termSrv *term.TermService
}

// Start 装配并启动（非阻塞）。
func Start(cfg ServeConfig) (*Server, error) {
	cfg.fill()
	st, err := OpenState(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	priv, err := st.PrivateKey()
	if err != nil {
		return nil, err
	}
	secrets, err := st.Secrets()
	if err != nil {
		return nil, err
	}

	tunDev, ns, err := wgnet.Create([]netip.Addr{cfg.TunnelIP}, 1280)
	if err != nil {
		return nil, err
	}
	// WG socket 钉哪张卡：auto 先探针挑一张（挑不到就不绑，绝不因此拒绝启动）。
	resolvedIf := cfg.BindIface
	switch cfg.BindMode {
	case BindOff:
		resolvedIf = nil
	case BindAuto:
		selCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		best, serr := egress.SelectBest(selCtx, egress.PhysicalCandidates(), nil, 2*time.Second, logf)
		cancel()
		if serr != nil {
			logf("绑卡：自动挑卡失败（%v）—— 本轮不绑，走系统默认路由（TUN 型代理机器上请用 --bind-interface <网卡>）", serr)
			resolvedIf = nil
		} else {
			resolvedIf = best
			logf("绑卡：自动挑到 %s（%s）", best.Name, stateOf(best))
		}
	}
	s := &Server{cfg: cfg, Stats: &flows.Stats{}}
	s.bindIface = resolvedIf
	level := device.LogLevelError
	if cfg.Verbose {
		level = device.LogLevelVerbose
	}
	buildTag := cfg.BuildTag
	if buildTag == "" {
		buildTag = "homewayd-dev"
	}
	sbind := &servercore.ServerBind{Logf: logf, Build: buildTag, BindAddr: cfg.BindAddr, BindIface: resolvedIf}
	s.bind = sbind
	s.dev = device.NewDevice(tunDev, sbind, device.NewLogger(level, "homewayd"))
	s.Table = servercore.NewPeerTable(servercore.NewIPCConfigurer(s.dev), secrets, 8, 0)
	// token 台账热加载：`homewayd issue` 之后不需要重启出口（见 PeerTable.reload 的注释）。
	s.Table.SetSecretsReloader(st.Secrets)
	sbind.Table = s.Table

	if err := s.dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", hex.EncodeToString(priv[:]), cfg.ListenPort)); err != nil {
		s.dev.Close()
		return nil, err
	}

	// 公网端点自动公布（UPnP 映射 + 同 socket STUN 观测；两条证据一致才写 public_endpoint.txt）。
	// 必须放在 IpcSet 之后：device 到这一刻才打开 Bind（socket 有了端口，STUN 才有意义）。
	s.StartPublicEndpoint(context.Background(), PublicOpts{
		StateDir: cfg.StateDir, UPnP: cfg.UPnP, STUN: cfg.STUN, STUN6: cfg.STUN6, Bind: sbind,
		Pinned: cfg.BindAddr.IsValid() || resolvedIf != nil, Logf: logf,
	})

	tcpLn, err := ns.ListenTCPAddrPort(netip.AddrPortFrom(cfg.TunnelIP, cfg.FlowPort))
	if err != nil {
		s.dev.Close()
		return nil, err
	}
	// 转发出站流量怎么出去，三选一（优先级见下）：经上游代理 → 钉物理网卡 → 系统默认路由。
	//
	//   - 钉物理网卡（--forward-egress=bind，默认）：不经 TUN 型代理（Surge 等）；
	//   - 系统默认路由（--forward-egress=default）：让 TUN 型代理按它自己的规则处理；
	//   - **两者可以分开**（--forward-egress=tcp=default,udp=bind）：实测 TUN 型代理会按规则
	//     处理 TCP（境外能通），但不中继 UDP（QUIC 有去无回）—— 这类机器上这就是最优解。
	// 无论怎么选，**WG socket（打洞/STUN）始终钉在物理网卡上**：NAT 映射必须是我们自己的那个。
	// 回环目标自动豁免（出口自己的 files/终端就在 127.0.0.1）。
	tcpMode, udpMode := resolveEgressPolicy(cfg.ForwardEgress, egress.PreferredIface())
	eg := egress.FromInterface(ifaceForMode(tcpMode, resolvedIf))
	egUDP := egress.FromInterface(ifaceForMode(udpMode, resolvedIf))
	s.fwdTCP, s.fwdUDP = eg, egUDP
	s.fwdEgress = cfg.ForwardEgress // auto 时看护会周期性重算
	logf("Egress：转发的 TCP %s / UDP %s（--forward-egress=%s/%s ⇒ %s/%s）",
		egressPathName(tcpMode), egressPathName(udpMode),
		dash(cfg.ForwardEgress.TCP), dash(cfg.ForwardEgress.UDP), tcpMode, udpMode)
	// TCP 走哪条路由 dialer 自己判（绑定器 Enabled() 是动态的：auto 模式会在运行期切换）。
	dial := eg.DialContext
	if resolvedIf != nil {
		logf("Egress：WG socket（端口 %d）钉在 %s 上（打洞/STUN 的映射必须是我们自己的）",
			cfg.ListenPort, resolvedIf.Name)
	}
	s.stopTCP, err = flows.ServeTCP(tcpLn, dial, s.Stats,
		flows.WithMaxConns(cfg.FlowMaxConns), flows.WithIdleTimeout(cfg.FlowIdle))
	if err != nil {
		s.dev.Close()
		return nil, err
	}
	udpPC, err := ns.ListenUDPAddrPort(netip.AddrPortFrom(cfg.TunnelIP, cfg.UDPFlowPort))
	if err != nil {
		s.stopTCP()
		s.dev.Close()
		return nil, err
	}
	// UDP 中继：长会话（QUIC/游戏）+ 会话级日志（建立/关闭各一行，含双向包数——
	// 真机判断「QUIC 到底通没通」就靠这一行，逐包细节不在这里）。
	udpOpts := []flows.UDPOption{flows.WithUDPLog(logf),
		// 工厂常驻：auto 模式会在运行期把"走默认路由/钉网卡"来回切（见 EgressWatch）。
		flows.WithUDPSocket(func(dst netip.AddrPort) (flows.UDPConn, error) {
			if egUDP.Enabled() {
				return egUDP.ListenUDPFor(dst)
			}
			return net.ListenUDP(egress.NetworkFor(dst), nil)
		})}
	s.stopUDP, _ = flows.ServeUDP(udpPC, s.Stats, udpOpts...)

	// files 原生协议服务：只监听本机回环（客户端经内部流的 CONNECT 让后端按本机网络重拨到这里）。
	// 根 = 用户主目录、恒读写（协议无参数）；启动打一行根目录判据。
	fsrv, err := files.Open(cfg.FilesRoot)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("files 根目录不可用：%w", err)
	}
	fsrv.SetLogger(logf)
	fln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.FilesPort))
	if err != nil {
		fsrv.Close()
		s.Close()
		return nil, fmt.Errorf("files 监听 %d 失败：%w", cfg.FilesPort, err)
	}
	s.filesLn, s.files = fln, fsrv
	go func() {
		if err := fsrv.Serve(fln); err != nil {
			logf("files 服务收工：%v", err)
		}
	}()
	rootDir := fsrv.RootDir()
	logf("files 就绪：root=%s (rw) listen=127.0.0.1:%d", rootDir, cfg.FilesPort)

	// 终端会话 / agent gateway：只监听本机回环，客户端经内部流 CONNECT 到 127.0.0.1:<TermPort>。
	// 会话由后端持有（客户端断开只摘泵，不杀进程）；开关 HOMEWAY_TERM=off，调参 HOMEWAY_TERM_*。
	if term.Disabled() {
		logf("term 服务被 HOMEWAY_TERM=off 关闭")
	} else {
		tsrv := term.New(logf)
		tln, terr := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.TermPort))
		if terr != nil {
			s.Close()
			return nil, fmt.Errorf("term 监听 %d 失败：%w", cfg.TermPort, terr)
		}
		s.termLn, s.termSrv = tln, tsrv
		go func() {
			for {
				conn, aerr := tln.Accept()
				if aerr != nil {
					return
				}
				go tsrv.ServeConn(conn)
			}
		}()
		// 就绪行（判据）：终端会话端口 + shell + 历史窗口 + 能力位
		logf("# Serving terminal sessions on port %d (shell=%s, history=%s, features=%s)",
			cfg.TermPort, tsrv.ShellText(), tsrv.HistoryText(), term.FeaturesText())
	}

	if err := s.dev.Up(); err != nil { // FINDINGS 0.1-1
		s.Close()
		return nil, err
	}
	pub := priv.PublicKey()
	logf("serve 就绪：wg=:%d tunnel=%v flow=tcp:%d,udp:%d tokens=%d key=%x…",
		cfg.ListenPort, cfg.TunnelIP, cfg.FlowPort, cfg.UDPFlowPort, len(secrets), pub[:6])
	return s, nil
}

// Close 收工（幂等性由各层保证；stop 函数可重复调用部分由调用方保证单次）。
func (s *Server) Close() {
	if s.stopUDP != nil {
		s.stopUDP()
	}
	if s.stopTCP != nil {
		s.stopTCP()
	}
	if s.dev != nil {
		s.dev.Close()
	}
	if s.filesLn != nil {
		s.filesLn.Close()
	}
	if s.files != nil {
		s.files.Close()
	}
	if s.termLn != nil {
		s.termLn.Close()
	}
	if s.termSrv != nil {
		s.termSrv.Close()
	}
}

// Run 阻塞直到 ctx 结束。
func Run(ctx context.Context, cfg ServeConfig) error {
	s, err := Start(cfg)
	if err != nil {
		return err
	}
	// 换网自愈：绑了物理网卡时，网卡索引/地址变化后重钉 socket 并立刻重测公网端点
	// （否则接口索引一变，socket 就钉在一个不存在的网卡上；端点也会 stale 到下一轮 10 分钟）。
	// --forward-egress=auto：默认路由变成/变回隧道型网卡时跟着切（30s 一次，开销一次 UDP dial）。
	watchEgressPolicy(ctx, cfg.ForwardEgress, egressRecheck, logf,
		func() (EgressMode, EgressMode) { return resolveEgressPolicy(cfg.ForwardEgress, egress.PreferredIface()) },
		func(tcp, udp EgressMode) {
			s.fwdTCP.SetIface(ifaceForMode(tcp, s.bindIface))
			s.fwdUDP.SetIface(ifaceForMode(udp, s.bindIface))
		})
	if s.bindIface != nil && cfg.BindAddr.IsValid() == false {
		WatchBind(ctx, BindWatchOpts{
			Explicit: cfg.BindIface, // auto 模式传 nil（每次重新挑）
			Repin: func(ifi *net.Interface) error {
				if _, err := s.bind.RepinTo(ifi); err != nil {
					return err
				}
				s.bindIface = ifi
				s.applyForwardEgress() // 换卡后转发路径跟着走（auto 的 default 侧仍保持不绑）
				return nil
			},
			OnChange: s.KickPublicEndpoint,
			Logf:     logf,
		})
	}
	<-ctx.Done()
	// 退出时把映射**租期缩短**（而不是删除）：路由器表就是我们"上次用的外口"的记忆 ——
	// 快速重启（升级/换二进制）能沿用同一个公网端口；出口真退休了，5 分钟后映射自动消失，
	// 不会像旧栈那样在路由器里留一堆永久的。异常退出（kill -9）保持原租期（≤1 小时）后过期。
	if cfg.UPnP {
		ctx2, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		if g, local, err := FindIGD(ctx2); err == nil {
			if ext, internal, ok := g.FindOurMapping(ctx2, upnpMapDesc, local, cfg.ListenPort); ok {
				if err := g.ReAddShortLease(ctx2, ext, local, internal, 300); err == nil {
					logf("UPnP：退出前把映射 外部 %d 的租期缩到 5 分钟（快速重启仍会沿用这个端口）", ext)
				}
			}
		}
		cancel()
	}
	s.Close()
	return nil
}

// ipcConfigurer：PeerTable 表项 → device IpcSet。
func logf(format string, args ...any) {
	fmt.Printf("[homewayd] "+format+"\n", args...)
}

var _ = wgtypes.Key{} // 保留引用


// applyForwardEgress：把当前 --forward-egress 策略应用到两个绑定器上（换卡/重算时调用）。
func (s *Server) applyForwardEgress() {
	tcp, udp := resolveEgressPolicy(s.fwdEgress, egress.PreferredIface())
	if s.fwdTCP != nil {
		s.fwdTCP.SetIface(ifaceForMode(tcp, s.bindIface))
	}
	if s.fwdUDP != nil {
		s.fwdUDP.SetIface(ifaceForMode(udp, s.bindIface))
	}
}

func egressPathName(m EgressMode) string {
	if m == EgressDefault {
		return "走系统默认路由（TUN 型代理按自己的规则处理）"
	}
	return "钉物理网卡"
}

func dash(m EgressMode) string {
	if m == "" {
		return "auto"
	}
	return string(m)
}
