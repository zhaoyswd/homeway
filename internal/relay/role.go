package relay

// role.go — relay 角色（role-management tasks 2.2，design D3）：RunWithReady 的启动/
// 收尾归角色——可挂 supervisor 重建（角色对象不跨重建复用）；onReady token 回调保留
// （token 打印/入账走它）。StateDir 指 <state>/relay/（relay.key 落点）；LogDir 注入
// （relay.log 落 <state>/cache/，空 = StateDir 现状缺省——r1 高-2）。

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
)

// RoleConfig relay 角色装配项（daemon 装配层与前台单角色 CLI 按同表注入）。
type RoleConfig struct {
	Addr      string // 监听地址（":41741"）
	Advertise string // token 里公布的中继地址（逗号分隔；空 = 运行时探测）
	StateDir  string // L2：<state>/relay/（relay.key）
	LogDir    string // L3：relay.log 落点（空 = StateDir——现状单旋钮缺省）
	Build     string // 探测应答的构建标记
}

// Role relay 角色（可重建）。
type Role struct {
	cfg RoleConfig

	mu      sync.Mutex
	running bool
	cur     *Relay // 当前运行轮（Snapshot 数据源；未跑 = nil）

	tokMu     sync.Mutex
	lastToken string   // 最近一次铸出的 rl1 token 全文（relay.token 运行态真源；未铸出 = 空）
	lastEps   []string // 该枚 token 的端点
}

// NewRole 建角色（未启动）。
func NewRole(cfg RoleConfig) *Role { return &Role{cfg: cfg} }

// Name 角色名（supervisor 状态面）。
func (r *Role) Name() string { return "relay" }

// Current 当前运行轮的 Relay（nil = 未在跑）。
func (r *Role) Current() *Relay {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cur
}

// Run 起角色并阻塞到收工：ctx 取消 = 正常收工；监听失败（端口全退让失败）= 角色失败。
func (r *Role) Run(ctx context.Context) error {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return errors.New("relay 角色已在运行（重复启动被拒）")
	}
	r.running = true
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.running = false
		r.cur = nil
		r.mu.Unlock()
	}()

	// 文件日志先立起来（loadSecret 的提示也有地方落）：注入目录，空 = StateDir。
	logDir := r.cfg.LogDir
	if logDir == "" {
		logDir = r.cfg.StateDir
	}
	initRelayLog(logDir)
	secret, created, err := loadSecret(r.cfg.StateDir)
	if err != nil {
		return err
	}
	if created {
		logf("已生成中继鉴权密钥（%s/relay.key，0600）—— 重启不变，token 因此稳定", r.cfg.StateDir)
	}
	// 启动时带一行日志落点（只此一次；终端不再输出其它信息）。
	if p := relayLogPath(); p != "" {
		ulogf("日志：%s —— 终端只出 token 与端点变化", p)
	}
	rl := New(Config{
		Addr:   r.cfg.Addr,
		Secret: secret,
		Build:  r.cfg.Build,
		Logf:   logf,
	})
	r.mu.Lock()
	r.cur = rl
	r.mu.Unlock()
	advertise := r.cfg.Advertise
	return rl.RunWithReady(ctx, func(actual netip.AddrPort) {
		token, eps, terr := BuildToken(secret, advertise, actual.Port())
		if terr != nil {
			logf("⚠️ token 生成失败（%v）—— 后端可用裸地址走开放模式", terr)
			return
		}
		ulogf("中继 token：%s", token)
		ulogf("端点：%s", strings.Join(eps, "、"))
		r.tokMu.Lock()
		r.lastToken, r.lastEps = token, append([]string(nil), eps...)
		r.tokMu.Unlock()
		if allPrivate(eps) {
			ulogf("⚠️ 公布的地址都在内网：公网中继请加 --advertise <公网IP:端口>")
		}
		// 用法提示进文件（终端不再输出）：token 里已含全部端点与密钥。
		logf("后端这样用：homeway serve --relay '%s'", token)
	})
}

// LastToken 最近一次铸出的 token 全文与端点（role-management 3.3：relay.token
// 控制面路径的运行态真源；空 = 本轮 onReady 未发生——调用方回落离线推算）。
func (r *Role) LastToken() (string, []string) {
	r.tokMu.Lock()
	defer r.tokMu.Unlock()
	return r.lastToken, append([]string(nil), r.lastEps...)
}

// Snapshot 当前运行轮的状态快照（未跑 = Open=false 的空面）。
func (r *Role) Snapshot() StatusSnapshot {
	if cur := r.Current(); cur != nil {
		return cur.Snapshot()
	}
	return StatusSnapshot{}
}
