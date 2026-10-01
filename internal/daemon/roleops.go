package daemon

// roleops.go — serve/relay 角色管理 op 的宿主绑定（role-management tasks 4.2，CP
// delta「绑定层只字段映射」）：控制面 serve.*/relay.* 十 op 的语义落点。语义真源 =
// internal/server 与 internal/relay 的角色接口（快照/token/生命周期）+ internal/
// nodeconfig（期望态）——本文件只做「角色接口 ↔ wire 体」的字段映射与启停编排。
//
// 期望态读写 = 每次 Load/Update config.toml（**不持有进程内副本**）：`serve relay
// set` 类纯文件写命令在进程在跑时直改文件（不热更基线），restart/动态启停经本面
// 重新 Load 才能吃到手编值——工厂（makeServeFactory/makeRelayFactory）每轮重建时
// 也重新 Load，文件即单一真源（D3「期望态读取时点」的推论）。
//
// 角色句柄：工厂每次构造新角色对象（supervisor 重建纪律——对象不跨轮复用），构造
// 时注册进 roleOps——控制面的 status/token 数据源取「当前轮」。

import (
	"errors"
	"fmt"
	"github.com/zhaoyswd/homeway/internal/control"
	"github.com/zhaoyswd/homeway/internal/nodeconfig"
	"github.com/zhaoyswd/homeway/internal/nodestate"
	"github.com/zhaoyswd/homeway/internal/relay"
	"github.com/zhaoyswd/homeway/internal/server"
	"path/filepath"
	"sync"
)

// roleOps serve/relay 角色管理面（assembleUnified 装配；controlBackend 持有）。
type roleOps struct {
	stateDir string
	cacheDir string
	version  string
	verbose  bool
	sup      *supervisor

	mu    sync.Mutex
	serve *server.Role // 当前轮句柄（工厂注册；nil = 从未装配）
	relay *relay.Role
}

// setServe/setRelay 工厂注册当前轮句柄。
func (ro *roleOps) setServe(r *server.Role) {
	ro.mu.Lock()
	ro.serve = r
	ro.mu.Unlock()
}

func (ro *roleOps) setRelay(r *relay.Role) {
	ro.mu.Lock()
	ro.relay = r
	ro.mu.Unlock()
}

func (ro *roleOps) serveRole() *server.Role {
	ro.mu.Lock()
	defer ro.mu.Unlock()
	return ro.serve
}

func (ro *roleOps) relayRole() *relay.Role {
	ro.mu.Lock()
	defer ro.mu.Unlock()
	return ro.relay
}

// makeServeFactory serve 角色工厂（每轮重建重新 Load config——手编/`serve relay set`
// 的值在 restart/重建轮生效；D3 路径注入表不变）。
func (ro *roleOps) makeServeFactory() func() Role {
	return func() Role {
		cfg, err := nodeconfig.Load(nodeconfig.Path(ro.stateDir))
		if err != nil {
			return failedRole{name: "serve", err: fmt.Errorf("读 config 失败：%w", err)}
		}
		sc, err := serveConfigOf(ro.stateDir, ro.cacheDir, cfg, ro.version, ro.verbose)
		if err != nil {
			return failedRole{name: "serve", err: err} // ResolveBind 失败 = 角色失败（退避重建）
		}
		r := server.NewRole(sc)
		ro.setServe(r)
		return r
	}
}

// makeRelayFactory relay 角色工厂（同款）。
func (ro *roleOps) makeRelayFactory() func() Role {
	return func() Role {
		cfg, err := nodeconfig.Load(nodeconfig.Path(ro.stateDir))
		if err != nil {
			return failedRole{name: "relay", err: fmt.Errorf("读 config 失败：%w", err)}
		}
		r := relay.NewRole(relayConfigOf(ro.stateDir, ro.cacheDir, cfg, ro.version))
		ro.setRelay(r)
		return r
	}
}

// serveConfigOf D3 拆分表的 serve 注入映射（unified.go 原装配代码收拢于此）。
func serveConfigOf(stateDir, cacheDir string, cfg *nodeconfig.Config, version string, verbose bool) (server.ServeConfig, error) {
	sc := &cfg.Serve
	bindAddr, bindIf, bindMode, err := server.ResolveBind(sc.BindInterface)
	if err != nil {
		return server.ServeConfig{}, fmt.Errorf("bind_interface 解析失败：%w", err)
	}
	return server.ServeConfig{
		StateDir:    nodestate.ServeDir(stateDir), // L2
		LogDir:      cacheDir,                     // L3（events/debug 日志）
		PortFileDir: cacheDir,                     // L3（listen_port/public_endpoint）
		SockDir:     stateDir,                     // 瞬态（files/term/speedtest.sock）
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
	}, nil
}

// relayConfigOf 同表 relay 注入映射。
func relayConfigOf(stateDir, cacheDir string, cfg *nodeconfig.Config, version string) relay.RoleConfig {
	return relay.RoleConfig{
		Addr:      cfg.Relay.Listen,
		Advertise: cfg.Relay.Advertise,
		StateDir:  nodestate.RelayDir(stateDir), // L2（relay.key）
		LogDir:    cacheDir,                     // L3（relay.log）
		Build:     version,
	}
}

// ---- 角色状态面（supervisor stats → 五态语义） ----

// roleStateOf supervisor 状态 → serve.status/relay.status 的运行态字段。五态：
// running/stopping/stopped/failed/absent（未装配——从未 start 或 stop 收尾后；
// 与 stopped 的语义差别由 Enabled 期望态分开呈现，r2 新-4 的 failed 不落降级列）。
func (ro *roleOps) roleStateOf(name string) (state, reason string) {
	for _, st := range ro.sup.Statuses() {
		if st.Name == name {
			return st.State, st.LastError
		}
	}
	return "absent", ""
}

// desiredOf 期望态直读（文件；坏 config = 错误——状态面如实报）。
func (ro *roleOps) desiredOf() (*nodeconfig.Config, error) {
	return nodeconfig.Load(nodeconfig.Path(ro.stateDir))
}

// ---- 启停编排（幂等语义在成功载荷呈现） ----

// lifecycleStart enabled=true 写 config + 确保角色装配（幂等；stopping 中 = 等旧轮
// 收尾完再启——supervisor 串行化，r1 中-4）。
func (ro *roleOps) lifecycleStart(name string, setEnabled func(*nodeconfig.Config, bool), factory func() Role) (control.RoleActionResult, error) {
	before, _ := ro.roleStateOf(name)
	if err := nodeconfig.Update(nodeconfig.Path(ro.stateDir), func(c *nodeconfig.Config) error {
		setEnabled(c, true)
		return nil
	}); err != nil {
		return control.RoleActionResult{}, err
	}
	if before == roleStateRunning || before == roleStateStopping || before == roleStateFailed {
		// running = 幂等无动作；stopping = StartRole 内部等收尾后装配（动作语义 =
		// 无动作——期望态本就 true）；failed = 期望态 true 的退避重建中（幂等成功）。
		ro.sup.StartRole(name, factory, nil)
		return control.RoleActionResult{Action: "already"}, nil
	}
	ro.sup.StartRole(name, factory, nil)
	return control.RoleActionResult{Action: "started"}, nil
}

// lifecycleStop enabled=false 写 config + 取消角色 ctx 立即应答（收尾异步——D5/r1 中-4）。
func (ro *roleOps) lifecycleStop(name string, setEnabled func(*nodeconfig.Config, bool)) (control.RoleActionResult, error) {
	before, _ := ro.roleStateOf(name)
	if err := nodeconfig.Update(nodeconfig.Path(ro.stateDir), func(c *nodeconfig.Config) error {
		setEnabled(c, false)
		return nil
	}); err != nil {
		return control.RoleActionResult{}, err
	}
	ro.sup.StopRole(name) // 未装配/已停/停中 = 幂等无动作
	if before == roleStateStopped || before == "absent" {
		return control.RoleActionResult{Action: "already"}, nil
	}
	return control.RoleActionResult{Action: "stopped"}, nil
}

// lifecycleRestart 角色进程内重建（期望态不变）。running = 常规重建；failed = 跳过剩余
// 退避立即重建（supervisor.RestartRole 同面语义）；stopped/absent = 可行动错误哨兵
// （CLI 预检兜住「先 serve start」提示，wire 理论不可达）。
func (ro *roleOps) lifecycleRestart(name string) (control.RoleActionResult, error) {
	state, _ := ro.roleStateOf(name)
	if state != roleStateRunning && state != roleStateFailed {
		return control.RoleActionResult{}, control.ErrBackendRoleStopped
	}
	if err := ro.sup.RestartRole(name); err != nil {
		return control.RoleActionResult{}, err
	}
	return control.RoleActionResult{Action: "restarted"}, nil
}

// ---- Backend 十方法的字段映射 ----

func (ro *roleOps) ServeStart() (control.RoleActionResult, error) {
	return ro.lifecycleStart("serve", func(c *nodeconfig.Config, v bool) { c.Serve.Enabled = v }, ro.makeServeFactory())
}

func (ro *roleOps) ServeStop() (control.RoleActionResult, error) {
	return ro.lifecycleStop("serve", func(c *nodeconfig.Config, v bool) { c.Serve.Enabled = v })
}

func (ro *roleOps) ServeRestart() (control.RoleActionResult, error) {
	return ro.lifecycleRestart("serve")
}

func (ro *roleOps) ServeStatus() control.ServeStatusResult {
	out := control.ServeStatusResult{Peers: []control.ServePeerBrief{}, Intercept: control.ServeInterceptBits{}}
	if cfg, err := ro.desiredOf(); err == nil {
		out.Enabled = cfg.Serve.Enabled
	} else {
		out.Reason = err.Error() // 期望态读失败如实呈现（手编坏 config 的运行中边界）
	}
	out.State, _ = ro.roleStateOf("serve")
	if role := ro.serveRole(); role != nil {
		if cur := role.Current(); cur != nil {
			snap := cur.Snapshot()
			out.ListenPort = snap.ListenPort
			out.Published = snap.Published
			out.TokenMask = snap.TokenMask
			out.Endpoints = snap.Endpoints
			for _, p := range snap.Peers {
				out.Peers = append(out.Peers, control.ServePeerBrief{
					Dev: p.Dev, TunnelIP: p.TunnelIP,
					LastReg: p.LastReg.UnixMilli(), IdleMs: p.Idle.Milliseconds(),
				})
			}
			for _, d := range snap.DDNS {
				out.DDNS = append(out.DDNS, control.ServeDDNSBrief{
					Domain: d.Domain, LagStreak: d.LagStreak,
					WarnedLag: d.WarnedLag, WarnedAAAA: d.WarnedAAAA,
				})
			}
			out.Intercept = control.ServeInterceptBits{
				DialOK: snap.Intercept.DialOK, DialFail: snap.Intercept.DialFail,
				Reject: snap.Intercept.Reject, Flows: snap.Intercept.Flows,
			}
		}
	}
	// 角色未装配/未铸出时掩码降级 = 台账末行（reveal 纪律：status 一律掩码、以末行为准）。
	if out.TokenMask == "" {
		if tok, _, ok, _ := server.RevealLastToken(nodestate.ServeDir(ro.stateDir)); ok {
			out.TokenMask = server.MaskToken(tok)
		}
	}
	return out
}

func (ro *roleOps) ServeToken() (control.ServeTokenResult, error) {
	// 运行态真源优先；未铸出（探测未完成窗口）或角色未装配 → 台账末行（写入纪律下
	// 末行 = 最近在用 token——两源同源，spec 场景「token 双路径一致」）。
	// 来源细分（exec-r1 低-5）：ledger-early = 角色已装配、本轮 token 未铸出（启动
	// 早期窗口）；ledger = 进程在跑但角色未装配（如 serve stop 后）或未跑直读——
	// 前者的台账末行可能是 endpoints=null 预热行，CLI 侧据此给可行动提示。
	roleAssembled := false
	if role := ro.serveRole(); role != nil {
		if cur := role.Current(); cur != nil {
			roleAssembled = true
			if tok := cur.CurrentToken(); tok != "" {
				// exec-r2 N1：runtime 分支同样回填端点（快照与铸出 token 同源——
				// lastPublished+监听口；铸出前提 eps 非空）。不填则 CLI 侧
				// warnNoEndpoints 在在跑稳态误报「该 token 无端点」（与事实相反）。
				return control.ServeTokenResult{Token: tok, Source: "runtime", Eps: cur.Snapshot().Endpoints}, nil
			}
		}
	}
	tok, eps, ok, err := server.RevealLastToken(nodestate.ServeDir(ro.stateDir))
	if err != nil {
		return control.ServeTokenResult{}, err
	}
	if !ok {
		return control.ServeTokenResult{}, errors.New("serve 角色未铸出 token 且台账为空（等首轮端点探测后重试，或先 homeway serve start）")
	}
	src := "ledger"
	if roleAssembled {
		src = "ledger-early"
	}
	return control.ServeTokenResult{Token: tok, Source: src, Eps: eps}, nil
}

func (ro *roleOps) RelayStart() (control.RoleActionResult, error) {
	return ro.lifecycleStart("relay", func(c *nodeconfig.Config, v bool) { c.Relay.Enabled = v }, ro.makeRelayFactory())
}

func (ro *roleOps) RelayStop() (control.RoleActionResult, error) {
	return ro.lifecycleStop("relay", func(c *nodeconfig.Config, v bool) { c.Relay.Enabled = v })
}

func (ro *roleOps) RelayRestart() (control.RoleActionResult, error) {
	return ro.lifecycleRestart("relay")
}

func (ro *roleOps) RelayStatus() control.RelayStatusResult {
	out := control.RelayStatusResult{Backends: []control.RelayBackendBrief{}}
	if cfg, err := ro.desiredOf(); err == nil {
		out.Enabled = cfg.Relay.Enabled
		out.Advertise = cfg.Relay.Advertise
	} else {
		out.Reason = err.Error()
	}
	out.State, _ = ro.roleStateOf("relay")
	if role := ro.relayRole(); role != nil {
		snap := role.Snapshot()
		out.Listen = snap.Listen
		out.Open = snap.Open
		out.Assocs = snap.Assocs
		for _, b := range snap.Backends {
			out.Backends = append(out.Backends, control.RelayBackendBrief{
				Label: b.Label, Addr: b.Addr, LastActive: b.LastActive.UnixMilli(),
				Verified: b.Verified, CtlVerified: b.CtlVerified, HasCtl: b.HasCtl,
			})
		}
		// relay 无台账：掩码 = 在跑轮最近铸出（未铸出 = 空——relay 侧无 APP 维度的
		// 事实约束下，空掩码只意味着「本轮还没铸出」）。
		if tok, _ := role.LastToken(); tok != "" {
			out.TokenMask = relay.MaskToken(tok)
		}
	}
	return out
}

func (ro *roleOps) RelayToken() (control.RelayTokenResult, error) {
	if role := ro.relayRole(); role != nil {
		if cur := role.Current(); cur != nil {
			if tok, eps := role.LastToken(); tok != "" {
				return control.RelayTokenResult{Token: tok, Source: "runtime", Eps: eps}, nil
			}
		}
	}
	// 降级 = D8a 离线推算（relay.key + config listen/advertise——推算值与本机网络
	// 状态绑定，与在跑值不一致以控制面为准）。
	tok, eps, err := ro.deriveRelayToken()
	if err != nil {
		return control.RelayTokenResult{}, err
	}
	return control.RelayTokenResult{Token: tok, Source: "derived", Eps: eps}, nil
}

// deriveRelayToken D8a 离线推算：relay/relay.key 的 secret + config 的
// relay.listen 端口 + advertise（空 = 复刻公网地址探测——BuildToken 内置同规则）。
func (ro *roleOps) deriveRelayToken() (string, []string, error) {
	cfg, err := ro.desiredOf()
	if err != nil {
		return "", nil, err
	}
	port, err := relay.ListenPortOf(cfg.Relay.Listen)
	if err != nil {
		return "", nil, fmt.Errorf("config relay.listen %q 无端口可推算：%w", cfg.Relay.Listen, err)
	}
	secret, ok, err := relay.ReadSecret(filepath.Join(ro.stateDir, "relay"))
	if err != nil {
		return "", nil, err
	}
	if !ok {
		return "", nil, errors.New("relay/relay.key 不存在——中继从未启动过则无钥可推算（先 homeway relay start）")
	}
	return relay.BuildToken(secret, cfg.Relay.Advertise, port)
}
