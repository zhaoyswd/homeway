package daemon

// unified.go — 统一进程装配（role-management tasks 2.3，design D1/D3/D9/HD delta）。
//
// 装配序（D1）：取锁（统一进程与前台单角色共用 <state>/lock——角色名归一）→
// OpenNodeState（三层布局 + 同根自动迁移 + config 缺失生成默认）→ 读 config
// （fail-fast）→ client/control 角色**恒开**（期望态 roles.json 已退役——控制面宿主
// 与注册表是 daemon 本职，无开关无配置节）→ serve/relay 按期望态（config enabled）
// 挂 supervisor → 等信号收工（全停进程常驻不退出，D9——client/control 仍开）。
//
// 路径注入（D3 拆分表）：serve L2=<state>/serve、relay L2=<state>/relay、client
// L2=<state>/client；L3（日志/端口文件/端点缓存）=<state>/cache；瞬态 socket=<state>。
// cache/events.log 与 debug.log 的写权：NodeState 只在启动期写迁移摘要，随后关句柄
// 交还 serve 角色（append-only 续写，两写者不同时在世）；守护侧自有日志走
// cache/daemon-{events,debug}.log（迁移映射的防撞落名）。

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/zhaoyswd/homeway/clientcore/facade"
	"github.com/zhaoyswd/homeway/internal/nodeconfig"
	"github.com/zhaoyswd/homeway/internal/nodestate"
	"github.com/zhaoyswd/homeway/internal/relay"
	"github.com/zhaoyswd/homeway/internal/server"
	"github.com/zhaoyswd/homeway/pkg/probe"
)

// RunUnified 统一进程前台入口（`homeway` 零参 / 首参全局 flag；cmd/homeway 分发）。
// 只认全局 flag（--state/--verbose——r1 中-1）；角色 flag 打在统一进程形态 =
// 可行动错误（提示走 config 或前台单角色形态）。
func RunUnified(version string, args []string) error {
	// r1 中-1：统一进程拒收角色 flag（--listen 在 serve/relay 同名不同型、--relay 与
	// relay 角色名词根同源——拒收即消灭歧义，且与「config 是意图层」一致）。**先于
	// flag 解析**扫描：未知 flag 交给 flag 集只会得到「provided but not defined」的
	// 语法错，可行动提示（走 config 或前台形态）必须在这里给。
	// 只扫 flag 形态的 token：--state 的**值**（下一位）跳过，--state=DIR 归并。
	stateDirHint := DefaultStateDir()
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			continue // 位置参数由下方 NArg 分支拒绝
		}
		name := strings.TrimLeft(a, "-")
		if strings.HasPrefix(name, "state") && !strings.Contains(name, "=") {
			if i+1 < len(args) {
				stateDirHint = args[i+1]
			}
			i++ // --state 的值位
			continue
		}
		if j := strings.IndexByte(name, '='); j >= 0 {
			if name[:j] == "state" {
				stateDirHint = name[j+1:]
			}
			name = name[:j]
		}
		switch name {
		case "state", "verbose", "help", "h":
		default:
			return fmt.Errorf("统一进程只认 --state/--verbose（%q 是角色 flag）——角色参数请写 %s 的 config.toml，或用 `homeway serve` / `homeway relay` 前台单角色形态",
				a, stateDirHint)
		}
	}
	fs := flag.NewFlagSet("homeway", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	stateDir := fs.String("state", DefaultStateDir(), "统一 state 根（三层布局 + config.toml）")
	verbose := fs.Bool("verbose", false, "摘要+细节日志同时回显终端")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("统一进程不接受位置参数 %q（角色命令见 `homeway serve` / `homeway relay` / 客户端域命令）", fs.Args())
	}
	return RunUnifiedState(version, *stateDir, *verbose)
}

// RunUnifiedState 按 state 目录起统一进程（e2e/测试缝：跳过 flag 解析）。
func RunUnifiedState(version, stateDir string, verbose bool) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proc, err := assembleUnified(ctx, version, stateDir, verbose)
	if err != nil {
		return err
	}
	// 唯一信号入口（D3：serve/relay 角色的信号处理已随角色化移出）。
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	got := <-sig
	fmt.Printf("homeway: 收到 %v，收工\n", got)
	cancel()
	return proc.Close() // 取消 → 等角色循环退出 → 收日志/锁
}

// unifiedProc 统一进程装配句柄（测试缝：坏 config 拒启/期望态装配矩阵/动态启停
// 判据不依赖信号）。
type unifiedProc struct {
	ctx     context.Context // 进程级（assembleUnified 自建派生）
	cancel  context.CancelFunc
	sup     *supervisor
	d       *facade.Daemon
	dl      *DaemonState
	cfg     *nodeconfig.Config
	release func() // 单实例锁释放
}

// Close 立即收工：取消进程级 ctx → 等角色循环全部退出 → 守护日志/facade/锁。
func (p *unifiedProc) Close() error {
	p.cancel()
	p.sup.Close()
	p.dl.Close()
	p.d.Close()
	p.release()
	return nil
}

// assembleUnified 装配全部角色（非阻塞）：锁 → 三层 state/迁移 → config → 恒开
// client/control → serve/relay 按期望态。返回句柄持有进程级 ctx（派生自调用方
// ctx，任一收工即全收）。
func assembleUnified(parent context.Context, version, stateDir string, verbose bool) (*unifiedProc, error) {
	ctx, cancel := context.WithCancel(parent)
	proc := &unifiedProc{ctx: ctx, cancel: cancel}

	// ① 单实例锁（与前台单角色共用 <state>/lock；角色名归一为 homeway——锁内
	// 持有者信息不再区分形态）。
	lock, err := nodestate.AcquireInstanceLock(stateDir, "homeway")
	if err != nil {
		cancel()
		return nil, err
	}
	proc.release = lock.Release

	// ② 三层 state + 同根自动迁移 + config 缺失生成默认（迁移摘要进 cache/events.log）。
	nst, err := nodestate.OpenNodeState(stateDir)
	if err != nil {
		cancel()
		lock.Release()
		return nil, fmt.Errorf("打开 state %s：%w", stateDir, err)
	}
	// ③ 读 config（fail-fast：非法 = 可行动错误拒启，不静默按默认——D2）。
	cfg, err := nodeconfig.Load(nodeconfig.Path(stateDir))
	if err != nil {
		nst.Close()
		cancel()
		lock.Release()
		return nil, err
	}
	// 守护侧自有日志立起来后，NodeState 的 events.log 句柄交还 serve 角色
	// （cache/events.log|debug.log 由 serve 独占；守护侧写 daemon-events.log）。
	dl := OpenDaemonLogs(stateDir, nst.CacheDir())
	cacheDir := nst.CacheDir()
	nst.Close()

	// ④ 进程级 facade（总线/代际进程唯一——动态启停不换不换代际）+ supervisor。
	d := facade.New(facade.Options{
		StrictIdentity:   true, // 统一进程 = 严格身份（D2/N2）
		Logf:             dl.Debugf,
		Eventf:           dl.Eventf,
		Probe:            probe.Reach,
		EndpointCacheDir: filepath.Join(cacheDir, "endpoints"), // client L3 注入（D3 表）
		Out:              filepath.Join(cacheDir, "client.log"),
	})
	sup := newSupervisor(ctx, dl.Eventf, dl.Debugf)
	proc.d, proc.dl, proc.sup, proc.cfg = d, dl, sup, cfg

	// ⑤ client 角色恒开（HD delta：期望态并入 config，client/control 无开关）。
	sup.Start("client", func() Role { return newClientRole(filepath.Join(stateDir, "client"), dl, d) }, nil)

	// ⑥ control 角色恒开（首启 Listen fail-fast：监听失败 = 报错退出——控制面是
	// 统一进程的用户面，静默缺失无从排查）。
	if err := startControlPlane(ctx, version, stateDir, sup, d, dl.Eventf); err != nil {
		proc.Close()
		return nil, err
	}

	// ⑦ serve/relay 按期望态（config enabled；重启机器照此恢复）。
	if cfg.Serve.Enabled {
		sup.StartRole("serve", makeServeRole(stateDir, cacheDir, cfg, version, verbose), nil)
	} else {
		dl.Eventf("serve: 期望停用（config serve.enabled=false）——不装配")
	}
	if cfg.Relay.Enabled {
		sup.StartRole("relay", makeRelayRole(stateDir, cacheDir, cfg, version), nil)
	} else {
		dl.Eventf("relay: 期望停用（config relay.enabled=false）——不装配")
	}

	dl.Eventf("homeway: 统一进程就绪（state=%s，serve=%v relay=%v，client/control 恒开，version=%s）",
		stateDir, cfg.Serve.Enabled, cfg.Relay.Enabled, version)
	// 全停 = client/control 仍在、进程常驻不退出（D9）——收工由句柄 Close/信号驱动。
	return proc, nil
}

// makeServeRole serve 角色工厂（D3 拆分表注入；每次重建重新构造——角色对象不跨重建复用）。
func makeServeRole(stateDir, cacheDir string, cfg *nodeconfig.Config, version string, verbose bool) func() Role {
	return func() Role {
		sc := &cfg.Serve
		bindAddr, bindIf, bindMode, err := server.ResolveBind(sc.BindInterface)
		if err != nil {
			// resolve 失败按角色失败处理（退避重建）。
			return failedRole{name: "serve", err: err}
		}
		return server.NewRole(server.ServeConfig{
			StateDir:    filepath.Join(stateDir, "serve"), // L2
			LogDir:      cacheDir,                         // L3（events/debug 日志）
			PortFileDir: cacheDir,                         // L3（listen_port/public_endpoint）
			SockDir:     stateDir,                         // 瞬态（files/term/speedtest.sock）
			ListenPort:  sc.Listen,
			BindAddr:    bindAddr,
			BindIface:   bindIf,
			BindMode:    bindMode,
			UPnP:        sc.UPnP,
			STUN:        sc.STUN,
			STUN6:       sc.STUN6,
			DDNS:        sc.DDNS,
			Relay:       sc.Relay,
			MaxDevices:  sc.MaxPeers,
			PeerTTL:     sc.PeerTTL,
			DNSPort:     sc.DNSPort,
			FilesRoot:   sc.FilesRoot,
			BuildTag:    version,
			Verbose:     verbose,
		})
	}
}

// makeRelayRole relay 角色工厂（同表注入）。
func makeRelayRole(stateDir, cacheDir string, cfg *nodeconfig.Config, version string) func() Role {
	return func() Role {
		return relay.NewRole(relay.RoleConfig{
			Addr:      cfg.Relay.Listen,
			Advertise: cfg.Relay.Advertise,
			StateDir:  filepath.Join(stateDir, "relay"), // L2（relay.key）
			LogDir:    cacheDir,                         // L3（relay.log）
			Build:     version,
		})
	}
}

// failedRole 构造期失败的角色包装（Run 恒返回该错误——交 supervisor 退避重建，
// 与运行期失败同一条路径）。
type failedRole struct {
	name string
	err  error
}

func (f failedRole) Name() string              { return f.name }
func (f failedRole) Run(context.Context) error { return f.err }
