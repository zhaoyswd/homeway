package server

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/zhaoyswd/homeway/pkg/dns"
	"github.com/zhaoyswd/homeway/pkg/egress"
	"github.com/zhaoyswd/homeway/pkg/files"
	"github.com/zhaoyswd/homeway/pkg/intercept"
	"github.com/zhaoyswd/homeway/pkg/proto"
	"github.com/zhaoyswd/homeway/pkg/servercore"
	"github.com/zhaoyswd/homeway/pkg/term"
	"github.com/zhaoyswd/homeway/pkg/wgnet"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// 默认内部地址（隧道内，客户端 token/配置与之配套）。
const (
	DefaultTunnelIP  = "100.64.255.1"
	DefaultFilesPort = uint16(7802) // files 原生协议（后端本机 127.0.0.1）
	DefaultTermPort  = uint16(7724) // 终端会话 / agent gateway（与旧栈 tunnel 内虚拟端口同号）
	DefaultDNSPort   = uint16(5300) // DNS 代答（任意目的 :53 改写到这里；不用 53——macOS 非 root 绑不上回环特权端口）
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
	StateDir   string
	ListenPort uint16
	TunnelIP   netip.Addr
	FilesPort  uint16         // files 服务在本机的监听端口（客户端经隧道 IP 豁免转投到它）
	FilesRoot  string         // files 根（空 = 用户主目录；协议恒读写）
	TermPort   uint16         // 终端会话 / agent gateway 在本机的监听端口
	DNSPort    uint16         // DNS 代答监听端口（0 = 禁用：:53 按原目标过境重拨；cli 默认 DefaultDNSPort）
	MaxDevices int            // 设备表容量（0 = 32）
	PeerTTL    time.Duration  // 长期不活跃设备的回收期限（0 = 7 天；<0 = 关闭 TTL 回收）
	BuildTag   string         // 探测应答里回报的构建标记（空 = 用内置默认）
	BindAddr   netip.Addr     // 非零 = 把 WG UDP socket 绑到该地址（该网卡出站；STUN 观测同 socket）
	BindIface  *net.Interface // 非空 = 双栈监听并整条 socket 钉在该网卡（同时支持 v4/v6 客户端）
	BindMode   BindMode       // WG socket 钉哪张卡：auto（默认，自动挑）/explicit（用 BindIface）/off（不绑）
	UPnP       bool           // 启动后向路由器申请 UDP 端口映射并 30 分钟续期
	STUN       string         // 非空 = 在监听 socket 上向该 STUN 服务器观测公网映射（如 stun.miwifi.com:3478）
	STUN6      string         // 非空 = 用该服务器做 **IPv6** 路径校验（要有 AAAA，如 stun.cloudflare.com:3478）
	Relay      string         // 非空 = 向该中继注册一条反向注册腿（host:port），NAT 后的出口由此可被客户端到达
	Verbose    bool
}

func (c *ServeConfig) fill() {
	if c.ListenPort == 0 {
		c.ListenPort = 41641
	}
	if !c.TunnelIP.IsValid() {
		c.TunnelIP = netip.MustParseAddr(DefaultTunnelIP)
	}
	if c.FilesPort == 0 {
		c.FilesPort = DefaultFilesPort
	}
	if c.TermPort == 0 {
		c.TermPort = DefaultTermPort
	}
	if c.MaxDevices <= 0 {
		c.MaxDevices = 32
	}
	if c.PeerTTL == 0 {
		c.PeerTTL = 7 * 24 * time.Hour
	}
}

// Server：homewayd 的完整数据面装配（netstack + WG device + ServerBind + PeerTable + 拦截层）。
type Server struct {
	cfg   ServeConfig
	Stats *intercept.Stats // dialok / dialfail / flows 计数（拦截层唯一写入方；udpcap 读 UDP 实测位）
	Table *servercore.DeviceTable

	dev           *device.Device
	bind          *servercore.ServerBind
	bindIface     *net.Interface // 本轮实际钉住的网卡（auto 挑出来的或显式给的；nil = 不绑）
	priv          [32]byte       // WG 静态私钥（中继注册腿要用它做挑战响应）
	secret        [32]byte       // token 凭证种子（打客户端 token 用）
	relayEp       proto.Endpoint // serve --relay 给的中继端点（打客户端 token 时带上）
	relayWanted   bool           // --relay 解析成功：token 未并入中继端点前不打印（只打最终形态）
	tokMu         sync.Mutex
	lastToken     string       // 上次已写出的客户端 token（去重：没变就不再写；终端只认首轮）
	lastPublished []string     // 最近一轮已公布的公网端点（Run 的终端兜底带上它，别打残缺版）
	udpCap        *udpCapState // 默认路径的 UDP 能力（周期探测；探测应答里回报）
	// dnsSrv：DNS 代答（dns-host-resolver）；nil = 未启用（监听失败降级或配置关闭）。
	dnsSrv *dns.Server
	// stopIntercept：过境拦截层收工（关会话通知；栈随 tunDev 生命周期回收）。
	stopIntercept func()
	pubKick       chan struct{} // 公网端点探测的"立即重测"信号（换网事件踢）
	firstProbe    chan struct{} // 第一次端点探测结束（Run 的 token 兜底在等它；nil=探测被关）
	filesLn       net.Listener
	filesSock     string      // files 的 UDS 路径（Close 时清 socket 文件；空 = 未起）
	filesOwn      os.FileInfo // bind 出的文件身份（removeSockOwn 只删自己的）
	files         *files.Server
	termLn        net.Listener
	termSock      string      // term 的 UDS 路径（同上）
	termOwn       os.FileInfo // 同 filesOwn
	termSrv       *term.TermService
	// relayCtx：中继注册腿 + 控制客户端的生命周期（review #8：此前给的是
	// context.Background()，Close 之后这两组协程与拨号循环永不退出——进程级
	// 无所谓，但测试里每次都泄漏 goroutine）。
	relayCtx    context.Context
	relayCancel context.CancelFunc
	relayStart  func() // dev.Up() 之后执行（socket 已开，#9）
}

// Start 装配并启动（非阻塞）。
func Start(cfg ServeConfig) (*Server, error) {
	cfg.fill()
	st, err := OpenState(cfg.StateDir) // MkdirAll：debug.log 依赖目录先存在
	if err != nil {
		return nil, err
	}
	// 文件日志立起来（CLI 已按同目录初始化过时这里幂等跳过）：摘要 events.log + 细节 debug.log。
	initLogs(cfg.StateDir, cfg.Verbose)
	priv, err := st.PrivateKey()
	if err != nil {
		return nil, err
	}
	secrets, err := st.Secrets()
	if err != nil {
		return nil, err
	}
	if len(secrets) == 0 {
		// 零参首启（全新 state 目录、没有 tokens.jsonl）：先签发一条凭证并落台账。
		// 不然启动时打印的客户端 token 会带**全零 Secret**（出口自己的 reg 验证
		// 也不认它——台账里根本没这条），生来无效（2026-09-20 实测踩中：裸启动
		// 新目录后打出的 token 手机无法连接）。台账里的 endpoints 字段仅信息性，
		// 实际验证只读 secrets；真正的客户端 token 由 printClientToken 用实时
		// 端点 + 这把 secret 铸出。
		if _, ierr := st.IssueToken(nil); ierr != nil {
			return nil, fmt.Errorf("state: 初始凭证签发失败: %w", ierr)
		}
		if secrets, err = st.Secrets(); err != nil || len(secrets) == 0 {
			return nil, fmt.Errorf("state: 初始凭证签发后仍读不到（%v）", err)
		}
	}

	// 过境拦截栈（l3-exit-intercept）：HandleLocal 必须关（混杂+spoofing 的前提，
	// 见 pkg/intercept 包注释）。
	tunDev, ns, err := wgnet.CreateOpts([]netip.Addr{cfg.TunnelIP}, 1280, wgnet.Opts{HandleLocal: false})
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
		best, serr := egress.SelectBest(selCtx, egress.PhysicalCandidates(), nil, 2*time.Second, dlogf)
		cancel()
		if serr != nil {
			logf("绑卡：自动挑卡失败（%v）—— 本轮不绑，走系统默认路由（TUN 型代理机器上请用 --bind-interface <网卡>）", serr)
			resolvedIf = nil
		} else {
			resolvedIf = best
			logf("绑卡：自动挑到 %s（%s）", best.Name, stateOf(best))
		}
	}
	s := &Server{cfg: cfg, Stats: &intercept.Stats{}}
	// DNS 代答（dns-host-resolver）：任意目的 :53 的隧道查询改写进本机代答，
	// 上游 = 主机系统解析（resolv.conf 跟随；启动时暂无上游不致命——空表周期
	// 重试，期间查询落兜底，review M6）。可选服务（与 files/term 同取舍），但
	// 降级后果如实写：监听失败（被占）时 DNSPort 传 0（禁改写）——手机声明的
	// DNS 是隧道 IP，豁免落到 127.0.0.1:53 无人监听 ⇒ **手机系统解析全断**
	// （只有应用写死公共 DNS 的查询还有明文过境）。这是硬依赖：靠启动自验证
	// 的告警行发现，靠进程重启恢复（KeepAlive/launchd 兜）。
	var dnsPort uint16
	if cfg.DNSPort != 0 {
		dsrv, derr := dns.Listen(dns.Config{
			Addr:  fmt.Sprintf("127.0.0.1:%d", cfg.DNSPort),
			Logf:  logf,
			DLogf: dlogf,
		})
		if derr != nil {
			logf("⚠️ dns 代答监听失败（%v）——隧道侧 DNS 将全断（隧道IP:53 豁免无人应答），其余功能不受影响；请检查端口占用并重启", derr)
		} else {
			// 自验证先于就绪行（review M2）：经监听器真发一条查询，失败=告警
			// 可达（老实现的失败分支是死代码）。失败不禁用改写——上游会跟随
			// 主机恢复，翻转改写会让 DNS 在两种模式间抖动。
			if serr := dsrv.SelfCheck(); serr != nil {
				logf("⚠️ dns 代答自验证未通过（%v）——上游此刻不可达（会跟随主机恢复/空表周期重试），期间查询按 SERVFAIL/兜底处理", serr)
			}
			s.dnsSrv = dsrv
			dnsPort = cfg.DNSPort
			logf("dns 代答就绪：listen=127.0.0.1:%d upstream=%s", cfg.DNSPort, dsrv.UpstreamsText())
		}
	}
	// 过境拦截层（l3-exit-intercept）。转发出站流量**一律走系统默认路由**（2026-09-19 定稿）：
	// 出口机器上装了什么代理/网关就由它按自己的规则处理，我们不做路径判断——但要把
	// 「这条路能不能承载 UDP」测出来暴露（见 udpcap.go）；TUN 型代理通常不中继 UDP
	// （实测同会话"上行 5 包、下行 0 包"），转发出去的 UDP（QUIC 等）能不能通是这条路的
	// 属性，而不是我们能选的。回环目标不受影响（出口自己的 files/终端就在 127.0.0.1）。
	//
	// 并发/空闲两个值 = l3 上线起的生产值（原 flows 时代 ServeConfig 字段随兼容监听退役）：
	// 64 连接自 l3-exit-intercept 上线即此值并经真机全量测试；30min 空闲是给豁免腿上的
	// 终端会话留的（拨隧道IP:7724 的长连接，别设太短）。
	// 本机服务承载映射（exit-service-uds）：files/term 的豁免端口改投 UDS。
	// 静态路径、建后不改——服务监听失败时条目保留，socket 文件不存在、拨号 ENOENT
	// 快速失败回 RST（与端口没人听不可区分）。
	var localSvcs map[uint16]string
	if cfg.StateDir != "" {
		localSvcs = map[uint16]string{
			cfg.FilesPort: filepath.Join(cfg.StateDir, "files.sock"),
			cfg.TermPort:  filepath.Join(cfg.StateDir, "term.sock"),
		}
	}
	inter, ierr := intercept.Attach(ns, intercept.Config{
		TunnelIP:      cfg.TunnelIP,
		DNSPort:       dnsPort,
		MaxConns:      64,
		TCPIdle:       30 * time.Minute,
		LocalServices: localSvcs,
		Logf:          dlogf,
	}, s.Stats)
	if ierr != nil {
		if s.dnsSrv != nil { // review F4：代答先于 Attach 起在此路径上要一起收
			s.dnsSrv.Close()
		}
		tunDev.Close()
		return nil, ierr
	}
	s.stopIntercept = inter.Close
	s.bindIface = resolvedIf
	s.priv = priv
	if len(secrets) > 0 {
		s.secret = secrets[0] // 与 `issue` 同一份凭证种子（见 state.Secrets）
	}
	buildTag := cfg.BuildTag
	if buildTag == "" {
		buildTag = "homewayd-dev"
	}
	sbind := &servercore.ServerBind{Logf: logf, LogfD: dlogf, Build: buildTag, BindAddr: cfg.BindAddr, BindIface: resolvedIf,
		Caps: func() byte { return s.UDPCapFlags() }}
	s.bind = sbind
	// wireguard-go 的日志也进文件：device.NewLogger 直写 stdout（2026-09-21 前会刷终端）。
	// ERROR 级进摘要文件；VERBOSE 只在 --verbose 时进细节文件。
	// ⚠️ Verbosef 必须非 nil：这版 wireguard-go 的 RoutineEncryption 无条件调
	// device.log.Verbosef（与 Logger「nil=silent」的注释矛盾），nil 会当场 panic。
	wgLog := &device.Logger{
		Errorf:   func(f string, a ...any) { logf("wg: "+f, a...) },
		Verbosef: device.DiscardLogf,
	}
	if cfg.Verbose {
		wgLog.Verbosef = func(f string, a ...any) { dlogf("wg: "+f, a...) }
	}
	s.dev = device.NewDevice(tunDev, sbind, wgLog)
	s.Table = servercore.NewDeviceTable(servercore.NewIPCConfigurer(s.dev), secrets, servercore.DeviceConfig{
		MaxDevices: cfg.MaxDevices,
		TTL:        cfg.PeerTTL,
	})
	s.Table.SetLogger(dlogf)
	peerCap, peerTTL, peerGrace := s.Table.Limits()
	dlogf("peer 表：设备表就绪（cap=%d，ttl=%v，grace=%v；按 devTag 记账/刷新/轮换）", peerCap, peerTTL, peerGrace)
	// token 台账热加载：serve 自己重签 token（端点变化时）后，新 secret 立刻可用，
	// 不需要重启出口（见 PeerTable.reload 的注释）。
	s.Table.SetSecretsReloader(st.Secrets)
	sbind.Table = s.Table

	if err := s.dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", hex.EncodeToString(priv[:]), cfg.ListenPort)); err != nil {
		s.dev.Close()
		return nil, err
	}

	// 中继注册腿（--relay）：从 WG socket 出站注册，NAT 后的出口由此可被客户端到达。
	// 参数可以是 **中继 token（rl1…，含地址 + 鉴权密钥）** 或裸 host:port（开放模式）。
	// ⚠️ 必须在 StartPublicEndpoint 的结果落地前把 relayEp 配好（2026-09-20 用户口径：
	// 指定了 --relay 就不该先打一个**不带中继端点**的 token）——此前这段排在后面，
	// STUN 快时 token 会先打一版无中继的、再重打一版带中继的。
	if cfg.Relay != "" {
		relayAddr, relaySecret, rerr := ParseRelayArg(cfg.Relay)
		if rerr == nil {
			s.relayEp = proto.Endpoint{Addr: relayAddr.String(), Relay: true}
			s.relayWanted = true
			// ⚠️ 只在这里**记下端点**，两个 start 挪到 dev.Up() 之后（review #9）：
			// 此前注册腿在 Up 前开跑，SendRawTo 读到 nil 的 socket，启动日志第一行
			// 就是假的「注册 Hello 发送失败」。token 打印顺序依赖 relayEp 先配好，
			// 所以赋值留在原处、启动延后。
			s.relayStart = func() {
				startRelayLeg(s.relayCtx, s.bind, relayAddr, s.priv, wgPub(s.priv), relaySecret, logf)
				// relay-backend-dial：控制通道（TCP，同号）+ SESSION 通告/拨腿。
				// 失败只退避重连，不影响主服务（见 relayctl.go 头注释）。
				startControlClient(s.relayCtx, s.bind, relayAddr, s.priv, wgPub(s.priv), relaySecret, logf)
			}
		} else {
			logf("⚠️ --relay 解析失败（%v）—— 跳过中继注册", rerr)
		}
	}

	// 公网端点自动公布（UPnP 映射 + 同 socket STUN 观测；两条证据一致才写 public_endpoint.txt）。
	// 必须放在 IpcSet 之后：device 到这一刻才打开 Bind（socket 有了端口，STUN 才有意义）。
	s.StartPublicEndpoint(context.Background(), PublicOpts{
		StateDir: cfg.StateDir, UPnP: cfg.UPnP, STUN: cfg.STUN, STUN6: cfg.STUN6, Bind: sbind,
		Pinned: cfg.BindAddr.IsValid() || resolvedIf != nil, Logf: logf,
	})

	// files 原生协议服务（exit-service-uds：UDS 承载，<state>/files.sock）。
	// 客户端拨 隧道IP:<FilesPort>，拦截层按 LocalServices 映射转投到这里——主机本地
	// 零端口占用、其它本地进程不可达；手机侧零改动（承载对它不可见）。
	// 根 = 用户主目录、恒读写（协议无参数）；启动打一行根目录判据。
	// ⚠️ 可选服务失败**不致命**（state 目录不可写等）：隧道/转发照常工作，只把这条
	// 服务摘掉并说清后果 —— 整机因为 files 起不来是最糟的取舍。
	fsrv, err := files.Open(cfg.FilesRoot)
	if err != nil {
		logf("⚠️ files 根目录不可用（%v）—— 文件管理会报错，其余功能不受影响", err)
	} else {
		fsrv.SetLogger(dlogf)
		fsock, fln, fown, lerr := listenLocalService(cfg.StateDir, "files.sock")
		if lerr != nil {
			fsrv.Close()
			logf("⚠️ files 监听 %s 失败（%v）—— 文件管理会报错（state 目录异常/被其它实例占用），其余功能不受影响", fsock, lerr)
		} else {
			s.filesLn, s.filesSock, s.filesOwn, s.files = fln, fsock, fown, fsrv
			go func() {
				serr := fsrv.Serve(fln)
				// Serve 返回 = Accept 循环退出（EMFILE 等）：摘监听，让后续拨号
				// ECONNREFUSED 快速失败，而不是握手进 backlog 后无人 Accept 挂住。
				fln.Close()
				if serr != nil {
					logf("files 服务收工：%v", serr)
				}
			}()
			logf("files 就绪：root=%s (rw) sock=%s（隧道IP:%d 经拦截层转投）", fsrv.RootDir(), fsock, cfg.FilesPort)
		}
	}

	// 终端会话 / agent gateway（exit-service-uds：UDS 承载 <state>/term.sock）。客户端拨隧道 IP:<TermPort>，
	// 拦截层按 LocalServices 映射转投；会话由后端持有（客户端断开只摘泵，不杀进程）；
	// 开关 HOMEWAY_TERM=off，调参 HOMEWAY_TERM_*。
	if term.Disabled() {
		logf("term 服务被 HOMEWAY_TERM=off 关闭")
	} else {
		tsrv := term.New(dlogf)
		tsock, tln, town, terr := listenLocalService(cfg.StateDir, "term.sock")
		if terr != nil {
			// 与 files 同一取舍：可选服务起不来不影响隧道/转发。
			logf("⚠️ term 监听 %s 失败（%v）—— 终端功能会报错（state 目录异常/被其它实例占用），其余功能不受影响", tsock, terr)
			tsrv.Close()
		} else {
			s.termLn, s.termSock, s.termOwn, s.termSrv = tln, tsock, town, tsrv
			go func() {
				for {
					conn, aerr := tln.Accept()
					if aerr != nil {
						// Accept 退出（同 files：别留一个「文件在、无人收」的监听点）。
						tln.Close()
						return
					}
					go tsrv.ServeConn(conn)
				}
			}()
			// 就绪行（判据）：终端会话 socket + shell + 历史窗口 + 能力位
			logf("# Serving terminal sessions on sock=%s (shell=%s, history=%s, features=%s)",
				tsock, tsrv.ShellText(), tsrv.HistoryText(), term.FeaturesText())
		}
	}

	// 生命周期 ctx 在装配起点建（收工由 Close 取消，#8）。
	s.relayCtx, s.relayCancel = context.WithCancel(context.Background())
	if err := s.dev.Up(); err != nil { // FINDINGS 0.1-1
		s.Close()
		return nil, err
	}
	// 中继注册腿/控制客户端此刻才开跑（#9）：dev.Up() 内部打开 Bind（socket 就绪），
	// SendRawTo 不再撞「socket 还没打开」。
	if s.relayStart != nil {
		s.relayStart()
	}
	pub := priv.PublicKey()
	// 注意：这里是**配置端口**；端口被占用会自动退让，实际端口在下面异步落盘时打（见 listen_port.txt）。
	logf("serve 就绪：wg=:%d（配置端口；被占用会自动退让）tunnel=%v files=%d term=%d dns=%d tokens=%d key=%x…",
		cfg.ListenPort, cfg.TunnelIP, cfg.FilesPort, cfg.TermPort, dnsPort, len(secrets), pub[:6])
	return s, nil
}

// listenLocalService：本机服务的 UDS 监听（exit-service-uds）。
// 残留处理按「死/活」区分（评审整改 2026-09-22）：先拨一下现有路径——拨得通 =
// 另一个活实例占着同一路径（同 state 双实例），报占用让调用方按可选服务失败
// 摘除（先到先得，与旧 TCP 端口被占的行为一致）；拨不通（ECONNREFUSED/ENOENT）
// 才是异常退出留下的死残留，删掉重绑。判活挡住了「新实例无条件抢走路径」；
// 返回的 own（bind 出的文件身份）配合 removeSockOwn 再挡住「退出时删掉后来
// 接管者的 socket」。
// 注：Go 的 UnixListener.Close 默认会按路径 unlink（unlinkOnClose=true）——本函数
// 在 listen 成功后关掉这个默认，删除统一走身份比对路径（见 removeSockOwn）。
// 路径超过 sockaddr_un 上限时直接报错（重试无意义）。
func listenLocalService(stateDir, name string) (string, net.Listener, os.FileInfo, error) {
	sock := filepath.Join(stateDir, name)
	if len(sock) >= 100 { // sockaddr_un.sun_path 保守上限（darwin 104 / linux 108）
		return sock, nil, nil, fmt.Errorf("路径超长（%d 字节 ≥ 100，sun_path 上限）", len(sock))
	}
	if c, derr := net.DialTimeout("unix", sock, 200*time.Millisecond); derr == nil {
		_ = c.Close()
		return sock, nil, nil, errors.New("socket 已被另一个活实例占用（同 state 双实例？）")
	} else if !errors.Is(derr, syscall.ENOENT) && !errors.Is(derr, syscall.ECONNREFUSED) {
		// ENOENT=文件不在；ECONNREFUSED=监听者已死只剩文件（都是可清的死残留）。
		// 其余（超时等模糊结果）按「有人占着」处理：不删状态不明的东西。
		return sock, nil, nil, fmt.Errorf("socket 占用状态不明（%v），不接管", derr)
	}
	if err := os.Remove(sock); err != nil && !os.IsNotExist(err) {
		return sock, nil, nil, fmt.Errorf("清残留 socket 失败：%w", err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return sock, nil, nil, err
	}
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false) // 删除走 removeSockOwn 的身份比对，防误删接管者
	}
	own, serr := os.Stat(sock)
	if serr != nil {
		ln.Close()
		return sock, nil, nil, serr
	}
	return sock, ln, own, nil
}

// removeSockOwn：只删「还是自己 bind 出来的那个文件」。路径已被别的实例接管
// （SameFile 不匹配）时不动它——旧实现按路径无条件删，会在双实例场景把后来
// 接管者的活 socket 摘掉，让它在无任何报错的情况下永久不可达。
func removeSockOwn(path string, own os.FileInfo) {
	if own == nil {
		_ = os.Remove(path) // 没拿到身份（防御）：退回按路径删
		return
	}
	cur, err := os.Stat(path)
	if err != nil {
		return // 已不在（含 Go listener Close 摘过等）
	}
	if os.SameFile(own, cur) {
		_ = os.Remove(path)
	}
}

// Close 收工（幂等性由各层保证；stop 函数可重复调用部分由调用方保证单次）。
func (s *Server) Close() {
	if s.relayCancel != nil {
		s.relayCancel() // 中继注册腿 + 控制客户端随服务收工（#8）
	}
	if s.stopIntercept != nil {
		s.stopIntercept()
	}
	if s.dnsSrv != nil {
		s.dnsSrv.Close()
	}
	if s.dev != nil {
		s.dev.Close()
	}
	if s.filesLn != nil {
		s.filesLn.Close()
		removeSockOwn(s.filesSock, s.filesOwn)
	}
	if s.files != nil {
		s.files.Close()
	}
	if s.termLn != nil {
		s.termLn.Close()
		removeSockOwn(s.termSock, s.termOwn)
	}
	if s.termSrv != nil {
		s.termSrv.Close()
	}
	closeLogs()
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
			// 端口变了 = token 里的端口跟着变：按用户口径这属于「IP/端口变化」，走终端。
			ulogf("⚠️ 实际监听端口 %d（配置的 %d 被占用，已自动退让）—— token 里的端口以公布/签发为准", p, cfg.ListenPort)
		}
		if werr := os.WriteFile(ListenPortPath(cfg.StateDir), []byte(strconv.Itoa(int(p))+"\n"), 0o600); werr != nil {
			logf("监听端口落盘失败（%v）—— 只是少了给人看的记录，不影响隧道", werr)
		}
	}()
	// 身份标签：中继日志里的「后端 <label> 注册成功」就是它（排障时对得上号）。
	label := BackendLabel(s.priv)
	pub6 := PubFromPriv(s.priv)
	logf("后端身份：标签 %x ｜公钥 %x…", label, pub6[:6])

	// 终端兜底：终端一辈子只打一轮 token（2026-09-21 用户口径），所以这一轮必须打
	// 「此刻能拿到的最好版本」——等第一轮公网探测结束（成不成都算）再决定；探测被关
	// （--upnp=false --stun=''，firstProbe==nil）时 15s 后兜底。打印仍被 relay 闸/端口闸
	// 拦下的话每秒重试一小会儿（中继注册腿偶尔慢于探测轮，别急着放弃）。
	go func() {
		if s.firstProbe != nil {
			select {
			case <-s.firstProbe:
			case <-ctx.Done():
				return
			}
		} else {
			select {
			case <-ctx.Done():
				return
			case <-time.After(15 * time.Second):
			}
		}
		for i := 0; i < 10; i++ {
			s.tokMu.Lock()
			printed := s.lastToken != ""
			pub := s.lastPublished
			s.tokMu.Unlock()
			if printed {
				return
			}
			s.printClientToken(pub)
			s.tokMu.Lock()
			printed = s.lastToken != ""
			s.tokMu.Unlock()
			if printed {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(1 * time.Second):
			}
		}
	}()

	// 默认路径能不能承载 UDP：周期探测 + 探测应答里回报（转发流量一律走默认路由，这是它的属性）。
	s.startUDPCapProbe(ctx, dlogf)
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
			Logf: logf,
		})
	}
	<-ctx.Done()
	// 退出时把映射**租期缩短**（而不是删除）：路由器表就是我们"上次用的外口"的记忆 ——
	// 快速重启（升级/换二进制）能沿用同一个公网端口；出口真退休了，5 分钟后映射自动消失，
	// 不会像旧栈那样在路由器里留一堆永久的。异常退出（kill -9）保持原租期（≤1 小时）后过期。
	if cfg.UPnP {
		ctx2, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		if g, local, err := FindIGD(ctx2); err == nil {
			// 认领用**实际监听口**（映射的内网口是按实际口申请的——监听口被占会 +1…+9 退让）。
			// 传配置口时自己的映射会撞上 InternalPort≠listenPort + portInUse(实际口)=自己
			// ⇒ 判 ownerLiveSibling 认领失败 ⇒ 缩租期静默跳过（评审整改 2026-09-22）。
			port := s.bind.LocalPort()
			if port == 0 {
				port = cfg.ListenPort // socket 从没开起来的极端形态：退回配置口（多半也认领不到）
			}
			if ext, internal, ok := g.FindOurMapping(ctx2, upnpMapDesc, local, port); ok {
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

var _ = wgtypes.Key{} // 保留引用
