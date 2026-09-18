package server

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"

	"github.com/zhaoyswd/homeway/pkg/files"
	"github.com/zhaoyswd/homeway/pkg/flows"
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
)

type ServeConfig struct {
	StateDir    string
	ListenPort  uint16
	TunnelIP    netip.Addr
	FlowPort    uint16
	UDPFlowPort uint16
	FilesPort   uint16 // files 服务在本机的监听端口（客户端经流协议 CONNECT 到它）
	FilesRoot   string // files 根（空 = 用户主目录；协议恒读写）
	Verbose     bool
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
}

// Server：homewayd 的完整数据面装配（netstack + WG device + ServerBind + PeerTable + flows）。
type Server struct {
	cfg   ServeConfig
	Stats *flows.Stats // dialok / dialfail / flows（状态面 3.6 消费）
	Table *PeerTable

	dev     *device.Device
	stopTCP func()
	stopUDP func()
	filesLn net.Listener
	files   *files.Server
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
	sbind := &ServerBind{Logf: logf}
	s.dev = device.NewDevice(tunDev, sbind, device.NewLogger(level, "homewayd"))
	s.Table = NewPeerTable(&ipcConfigurer{dev: s.dev}, secrets, 8, 0)
	sbind.Table = s.Table

	if err := s.dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", hex.EncodeToString(priv[:]), cfg.ListenPort)); err != nil {
		s.dev.Close()
		return nil, err
	}

	tcpLn, err := ns.ListenTCPAddrPort(netip.AddrPortFrom(cfg.TunnelIP, cfg.FlowPort))
	if err != nil {
		s.dev.Close()
		return nil, err
	}
	s.stopTCP, err = flows.ServeTCP(tcpLn, flows.DefaultDial, s.Stats)
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
}

// Run 阻塞直到 ctx 结束。
func Run(ctx context.Context, cfg ServeConfig) error {
	s, err := Start(cfg)
	if err != nil {
		return err
	}
	<-ctx.Done()
	s.Close()
	return nil
}

// ipcConfigurer：PeerTable 表项 → device IpcSet。
type ipcConfigurer struct{ dev *device.Device }

func (d *ipcConfigurer) AddPeer(pc PeerConfig) error {
	return d.dev.IpcSet(fmt.Sprintf(
		"public_key=%s\npreshared_key=%s\nallowed_ip=%s/32\n",
		hex.EncodeToString(pc.Pubkey[:]), hex.EncodeToString(pc.PSK[:]), pc.TunnelIP))
}

func (d *ipcConfigurer) RemovePeer(pub [32]byte) error {
	return d.dev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", hex.EncodeToString(pub[:])))
}

func logf(format string, args ...any) {
	fmt.Printf("[homewayd] "+format+"\n", args...)
}

var _ = wgtypes.Key{} // 保留引用
