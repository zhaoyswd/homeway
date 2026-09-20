package server

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"strings"
	"time"

	"github.com/zhaoyswd/homeway/pkg/egress"
	"github.com/zhaoyswd/homeway/pkg/files"
	"github.com/zhaoyswd/homeway/pkg/flows"
	"github.com/zhaoyswd/homeway/pkg/proto"
	"github.com/zhaoyswd/homeway/pkg/servercore"
	"github.com/zhaoyswd/homeway/pkg/term"
	"golang.org/x/crypto/curve25519"
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
	MaxDevices   int           // 设备表容量（0 = 32）
	PeerTTL      time.Duration // 长期不活跃设备的回收期限（0 = 7 天；<0 = 关闭 TTL 回收）
	BuildTag     string        // 探测应答里回报的构建标记（空 = 用内置默认）
	BindAddr     netip.Addr    // 非零 = 把 WG UDP socket 绑到该地址（该网卡出站；STUN 观测同 socket）
	BindIface    *net.Interface // 非空 = 双栈监听并整条 socket 钉在该网卡（同时支持 v4/v6 客户端）
	BindMode     BindMode       // WG socket 钉哪张卡：auto（默认，自动挑）/explicit（用 BindIface）/off（不绑）
	UPnP         bool          // 启动后向路由器申请 UDP 端口映射并 30 分钟续期
	STUN         string        // 非空 = 在监听 socket 上向该 STUN 服务器观测公网映射（如 stun.miwifi.com:3478）
	STUN6        string        // 非空 = 用该服务器做 **IPv6** 路径校验（要有 AAAA，如 stun.cloudflare.com:3478）
	Relay        string        // 非空 = 向该中继注册一条反向注册腿（host:port），NAT 后的出口由此可被客户端到达
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
	if c.MaxDevices <= 0 {
		c.MaxDevices = 32
	}
	if c.PeerTTL == 0 {
		c.PeerTTL = 7 * 24 * time.Hour
	}
}

// Server：homewayd 的完整数据面装配（netstack + WG device + ServerBind + PeerTable + flows）。
type Server struct {
	cfg   ServeConfig
	Stats *flows.Stats // dialok / dialfail / flows（状态面 3.6 消费）
	Table *servercore.DeviceTable

	dev     *device.Device
	bind    *servercore.ServerBind
	bindIface *net.Interface     // 本轮实际钉住的网卡（auto 挑出来的或显式给的；nil = 不绑）
	priv      [32]byte           // WG 静态私钥（中继注册腿要用它做挑战响应）
	secret    [32]byte           // token 凭证种子（打客户端 token 用）
	relayEp   proto.Endpoint     // serve --relay 给的中继端点（打客户端 token 时带上）
	tokMu     sync.Mutex
	lastToken string             // 上次打印过的客户端 token（变了才重打）
	udpCap    *udpCapState       // 默认路径的 UDP 能力（周期探测；探测应答里回报）
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
	s.priv = priv
	if len(secrets) > 0 {
		s.secret = secrets[0] // 与 `issue` 同一份凭证种子（见 state.Secrets）
	}
	level := device.LogLevelError
	if cfg.Verbose {
		level = device.LogLevelVerbose
	}
	buildTag := cfg.BuildTag
	if buildTag == "" {
		buildTag = "homewayd-dev"
	}
	sbind := &servercore.ServerBind{Logf: logf, Build: buildTag, BindAddr: cfg.BindAddr, BindIface: resolvedIf,
		Caps: func() byte { return s.UDPCapFlags() }}
	s.bind = sbind
	s.dev = device.NewDevice(tunDev, sbind, device.NewLogger(level, "homewayd"))
	s.Table = servercore.NewDeviceTable(servercore.NewIPCConfigurer(s.dev), secrets, servercore.DeviceConfig{
		MaxDevices: cfg.MaxDevices,
		TTL:        cfg.PeerTTL,
	})
	s.Table.SetLogger(logf)
	peerCap, peerTTL, peerGrace := s.Table.Limits()
	logf("peer 表：设备表就绪（cap=%d，ttl=%v，grace=%v；按 devTag 记账/刷新/轮换）", peerCap, peerTTL, peerGrace)
	// token 台账热加载：serve 自己重签 token（端点变化时）后，新 secret 立刻可用，
	// 不需要重启出口（见 PeerTable.reload 的注释）。
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
	// 转发出站流量**一律走系统默认路由**（2026-09-19 定稿）：
	// 出口机器上装了什么代理/网关就由它按自己的规则处理，我们不做路径判断 ——
	// 但要**把"这条路能不能承载 UDP"测出来暴露**（见 udpcap.go）：
	// 这类 TUN 型代理通常不中继 UDP（实测同会话"上行 5 包、下行 0 包"），
	// 所以转发出去的 UDP（QUIC 等）能不能通是这条路的属性，而不是我们能选的。
	// 回环目标不受影响（出口自己的 files/终端就在 127.0.0.1）。
	dial := flows.DialFunc(flows.DefaultDial)
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
	udpOpts := []flows.UDPOption{flows.WithUDPLog(logf)}
	s.stopUDP, _ = flows.ServeUDP(udpPC, s.Stats, udpOpts...)

	// files 原生协议服务：只监听本机回环（客户端经内部流的 CONNECT 让后端按本机网络重拨到这里）。
	// 根 = 用户主目录、恒读写（协议无参数）；启动打一行根目录判据。
	// ⚠️ 可选服务失败**不致命**：端口被别的程序占用（或同机跑了第二个实例）时，
	// 隧道/转发照常工作，只把这条服务摘掉并说清后果 —— 整机因为 7802 起不来是最糟的取舍。
	fsrv, err := files.Open(cfg.FilesRoot)
	if err != nil {
		logf("⚠️ files 根目录不可用（%v）—— 文件管理会报错，其余功能不受影响", err)
	} else {
		fsrv.SetLogger(logf)
		fln, lerr := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.FilesPort))
		if lerr != nil {
			fsrv.Close()
			logf("⚠️ files 监听 127.0.0.1:%d 失败（%v）—— 文件管理会报错（别的程序占用或同机跑了第二个实例），"+
				"其余功能不受影响", cfg.FilesPort, lerr)
		} else {
			s.filesLn, s.files = fln, fsrv
			go func() {
				if serr := fsrv.Serve(fln); serr != nil {
					logf("files 服务收工：%v", serr)
				}
			}()
			logf("files 就绪：root=%s (rw) listen=127.0.0.1:%d", fsrv.RootDir(), cfg.FilesPort)
		}
	}

	// 终端会话 / agent gateway：只监听本机回环，客户端经内部流 CONNECT 到 127.0.0.1:<TermPort>。
	// 会话由后端持有（客户端断开只摘泵，不杀进程）；开关 HOMEWAY_TERM=off，调参 HOMEWAY_TERM_*。
	if term.Disabled() {
		logf("term 服务被 HOMEWAY_TERM=off 关闭")
	} else {
		tsrv := term.New(logf)
		tln, terr := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.TermPort))
		if terr != nil {
			// 与 files 同一取舍：可选服务起不来不影响隧道/转发。
			logf("⚠️ term 监听 127.0.0.1:%d 失败（%v）—— 终端功能会报错，其余功能不受影响", cfg.TermPort, terr)
			tsrv.Close()
		} else {
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
	}

	if err := s.dev.Up(); err != nil { // FINDINGS 0.1-1
		s.Close()
		return nil, err
	}
	pub := priv.PublicKey()
	// 注意：这里是**配置端口**；端口被占用会自动退让，实际端口在下面异步落盘时打（见 listen_port.txt）。
	logf("serve 就绪：wg=:%d（配置端口；被占用会自动退让）tunnel=%v flow=tcp:%d,udp:%d tokens=%d key=%x…",
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
	// 把**实际**监听端口落盘：端口冲突会自动退让（见 ServerBind.Open），`issue` 需要知道真实端口
	// 才能把 LAN 端点写对（不写这个文件的话，回退端口后 token 里的端口就是错的）。
	go func() {
		p := waitLocalPort(context.Background(), s.bind, 30*time.Second)
		if p == 0 {
			return
		}
		if p != cfg.ListenPort {
			logf("⚠️ 实际监听端口 %d（配置的 %d 被占用，已自动退让）—— token 里的端口以公布/签发为准", p, cfg.ListenPort)
		}
		if werr := os.WriteFile(ListenPortPath(cfg.StateDir), []byte(strconv.Itoa(int(p))+"\n"), 0o600); werr != nil {
			logf("监听端口落盘失败（%v）—— 只是少了给人看的记录，不影响隧道", werr)
		}
	}()
	// 身份标签：中继日志里的「后端 <label> 注册成功」就是它（排障时对得上号）。
	label := BackendLabel(s.priv)
	pub6 := PubFromPriv(s.priv)
	logf("后端身份：标签 %x ｜公钥 %x…", label, pub6[:6])

	// 中继注册腿（--relay）：从 WG socket 出站注册，NAT 后的出口由此可被客户端到达。
	// 参数可以是 **中继 token（rl1…，含地址 + 鉴权密钥）** 或裸 host:port（开放模式）。
	if cfg.Relay != "" {
		relayAddr, relaySecret, rerr := ParseRelayArg(cfg.Relay)
		if rerr == nil {
			s.relayEp = proto.Endpoint{Addr: relayAddr.String(), Relay: true}
			startRelayLeg(ctx, s.bind, relayAddr, s.priv, wgPub(s.priv), relaySecret, logf)
		} else {
			logf("⚠️ --relay 解析失败（%v）—— 跳过中继注册", rerr)
		}
	}
	// 默认路径能不能承载 UDP：周期探测 + 探测应答里回报（转发流量一律走默认路由，这是它的属性）。
	s.startUDPCapProbe(ctx, logf)
	// 设备表周期回收：只清「超过 TTL 没有成功注册」的失联设备（在线设备被客户端周期注册刷新，
	// 不会误收）。10 分钟一拍、±10% 抖动；TTL<=0 时这个 goroutine 直接返回。
	go s.Table.RunGC(ctx, 10*time.Minute)
	// 换网自愈：绑了物理网卡时，网卡索引/地址变化后重钉 socket 并立刻重测公网端点
	// （否则接口索引一变，socket 就钉在一个不存在的网卡上；端点也会 stale 到下一轮 10 分钟）。
	if s.bindIface != nil && cfg.BindAddr.IsValid() == false {
		WatchBind(ctx, BindWatchOpts{
			Explicit: cfg.BindIface, // auto 模式传 nil（每次重新挑）
			Repin: func(ifi *net.Interface) error {
				if _, err := s.bind.RepinTo(ifi); err != nil {
					return err
				}
				s.bindIface = ifi
				return nil
			},
			OnChange: func() {
				s.KickPublicEndpoint() // 端点要重测（可能换网/换 IP）
				s.KickUDPCapProbe()    // UDP 能力也要重测（换了条路）
			},
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
// ParseRelayArg：`--relay` 的取值 —— 中继 token（rl1…，地址 + 鉴权密钥）或裸 host:port（开放模式）。
func ParseRelayArg(v string) (netip.AddrPort, [32]byte, error) {
	var secret [32]byte
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "rl1") {
		tok, err := proto.DecodeRelayToken(v)
		if err != nil {
			return netip.AddrPort{}, secret, fmt.Errorf("中继 token 解析失败: %w", err)
		}
		eps := tok.DirectEndpoints()
		if len(eps) == 0 {
			eps = tok.Endpoints
		}
		if len(eps) == 0 {
			return netip.AddrPort{}, secret, fmt.Errorf("中继 token 里没有端点")
		}
		ap, err := netip.ParseAddrPort(eps[0].Addr)
		if err != nil {
			return netip.AddrPort{}, secret, fmt.Errorf("中继 token 端点 %q 不是 IP:port（先用带 IP 的 token）: %w", eps[0].Addr, err)
		}
		return ap, tok.Secret, nil
	}
	ap, err := netip.ParseAddrPort(v)
	if err != nil {
		return netip.AddrPort{}, secret, fmt.Errorf("%q 既不是 host:port 也不是 rl1 token（%v）", v, err)
	}
	return ap, secret, nil
}

// PubFromPriv：从 WG 私钥导出公钥（Curve25519 basepoint 乘法）。
func PubFromPriv(priv [32]byte) [32]byte { return wgPub(priv) }

// BackendLabel：出口的**中继标签** = SHA-256(静态公钥)[:8]（16 位 hex）。
// 中继日志 `中继：后端 <label> 注册成功` 用的就是它。
func BackendLabel(priv [32]byte) [8]byte { return proto.RelayID(PubFromPriv(priv)) }

// BackendLabelFromState：从 state 目录里的身份密钥算标签（`homewayd id` 用）。
func BackendLabelFromState(stateDir string) ([8]byte, [32]byte, error) {
	st, err := OpenState(stateDir)
	if err != nil {
		return [8]byte{}, [32]byte{}, err
	}
	priv, err := st.PrivateKey()
	if err != nil {
		return [8]byte{}, [32]byte{}, err
	}
	pub := PubFromPriv(priv)
	return proto.RelayID(pub), pub, nil
}

// wgPub：从 WG 私钥导出公钥（Curve25519 basepoint 乘法）；中继注册要用它作 peerId。
func wgPub(priv [32]byte) [32]byte {
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	var out [32]byte
	if err != nil {
		return out
	}
	copy(out[:], pub)
	return out
}

func logf(format string, args ...any) {
	fmt.Printf("[homewayd] "+format+"\n", args...)
}

var _ = wgtypes.Key{} // 保留引用
