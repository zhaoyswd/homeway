package server

// role.go — serve 角色（role-management tasks 2.1，design D3）：Run 生命周期 = Start
// 装配（非阻塞）→ 尾部观测面（端口落盘/token 兜底/UDP 能力探测/表回收/换网自愈）→
// <-ctx → Shutdown（D5 收尾序，宽限 10s）。角色对象不跨重建复用（supervisor 重建 =
// 重新 NewRole）；「行为一条不丢」——本文件的主体是原 Run 的装配后逻辑原样搬入，
// 信号处理留在外层调用方（前台单角色 = CLI 的 signal ctx；统一进程 = 唯一信号入口）。

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// tokenFallbackWait：探测被关（--upnp=false --stun=”）时 token 兜底的等待窗。
// 原子读写（CI -race 首跑实拍：测试 Cleanup 的复位与兜底 goroutine 的读构成竞态）；
// 生产 = 15s，测试经此缝缩短（同 devOpTimeout/ddnsLogf 先例）。
var tokenFallbackWait atomic.Int64

func init() { tokenFallbackWait.Store(int64(15 * time.Second)) }

// StopGrace：serve stop 的过境 TCP 存量连接有界宽限（design D5 开放项⑦定稿：
// 10s 内继续承载、到期 RST；「停了还能通最多 10s」由 status 的 stopping 相位如实呈现）。
const StopGrace = 10 * time.Second

// Role serve 角色：可重建（每次 Run 重新装配一套数据面；peer 表按 L2 身份重建）。
type Role struct {
	cfg ServeConfig

	mu      sync.Mutex
	running bool
	cur     *Server // 当前运行轮的 Server（Status 数据源；未跑 = nil）
}

// NewRole 建角色（未启动；Run 才装配）。
func NewRole(cfg ServeConfig) *Role { return &Role{cfg: cfg} }

// Name 角色名（supervisor 状态面）。
func (r *Role) Name() string { return "serve" }

// Current 当前运行轮的 Server（nil = 未在跑——装配层的状态快照数据源）。
func (r *Role) Current() *Server {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cur
}

func (r *Role) setCurrent(s *Server) {
	r.mu.Lock()
	r.cur = s
	r.mu.Unlock()
}

// Run 起角色并阻塞到收工：ctx 取消 = 正常收工（返回 nil）；装配失败 = 角色失败
// （supervisor 退避重建）。重复 Run（未收先再启）= 错误（角色对象一次生命周期）。
func (r *Role) Run(ctx context.Context) error {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return errors.New("serve 角色已在运行（重复启动被拒）")
	}
	r.running = true
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.running = false
		r.mu.Unlock()
	}()

	s, err := Start(ctx, r.cfg)
	if err != nil {
		return err
	}
	r.setCurrent(s)
	defer r.setCurrent(nil)
	cfg := r.cfg

	// 把**实际**监听端口落盘：端口冲突会自动退让（见 ServerBind.Open），`issue` 需要知道真实端口
	// 才能把 LAN 端点写对（不写这个文件的话，回退端口后 token 里的端口就是错的）。
	go func() {
		p := waitLocalPort(ctx, s.bind, 30*time.Second)
		if p == 0 {
			return
		}
		if p != cfg.ListenPort {
			// 端口变了 = token 里的端口跟着变：按用户口径这属于「IP/端口变化」，走终端。
			ulogf("⚠️ 实际监听端口 %d（配置的 %d 被占用，已自动退让）—— token 里的端口以公布/签发为准", p, cfg.ListenPort)
		}
		if werr := os.WriteFile(ListenPortPath(cfg.portDir()), []byte(strconv.Itoa(int(p))+"\n"), 0o600); werr != nil {
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
			case <-time.After(time.Duration(tokenFallbackWait.Load())):
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
	if s.bindIface != nil && !cfg.BindAddr.IsValid() {
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
	// D5 收尾序（宽限 = StopGrace；supervisor 的 stop/restart 经取消本 ctx 走到这里）。
	s.Shutdown(StopGrace)
	return nil
}
