package server

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"time"

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
	UPnP         bool          // 启动后向路由器申请 UDP 端口映射并 30 分钟续期
	STUN         string        // 非空 = 在监听 socket 上向该 STUN 服务器观测公网映射（如 stun.miwifi.com:3478）
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
	stopTCP func()
	stopUDP func()
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
	s := &Server{cfg: cfg, Stats: &flows.Stats{}}
	level := device.LogLevelError
	if cfg.Verbose {
		level = device.LogLevelVerbose
	}
	buildTag := cfg.BuildTag
	if buildTag == "" {
		buildTag = "homewayd-dev"
	}
	sbind := &servercore.ServerBind{Logf: logf, Build: buildTag, BindAddr: cfg.BindAddr}
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
		StateDir: cfg.StateDir, UPnP: cfg.UPnP, STUN: cfg.STUN, Bind: sbind,
		Pinned: cfg.BindAddr.IsValid(), Logf: logf,
	})

	tcpLn, err := ns.ListenTCPAddrPort(netip.AddrPortFrom(cfg.TunnelIP, cfg.FlowPort))
	if err != nil {
		s.dev.Close()
		return nil, err
	}
	s.stopTCP, err = flows.ServeTCP(tcpLn, flows.DefaultDial, s.Stats,
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
	s.stopUDP, _ = flows.ServeUDP(udpPC, s.Stats)

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
	<-ctx.Done()
	// 退出时把自己建的 UPnP 映射删掉（尽力而为）：路由器上的映射是持久状态，
	// 出口不在了就不该继续占着公网端口。异常退出（kill -9）删不掉，靠租期自动过期兜底。
	if cfg.UPnP {
		ctx2, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		if g, _, err := FindIGD(ctx2); err == nil {
			if n, _, err := g.CleanMappings(ctx2, upnpMapDesc, 0); err == nil && n > 0 {
				logf("UPnP：退出前已删除 %d 条自己的映射", n)
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
