// carriers.go — 承载面管理器束（forward-socks-speedtest 3e §2.4，D1/D6/D8）。
//
// forward / socks / speedtest 三个管理器的装配点与协调面：随 Daemon.Attach/Detach
// 生命周期（角色级，stateDir 单一来源）；「监听端口全局唯一」（跨 forward 规则与
// socks 监听——多主机会话并发在世、共享同一回环命名空间）的检查在本层做（两管理器
// 各自只查名下端口）；host.remove 级联清理经本层分发（forward = delete 语义不强关、
// socks = off 语义显式关、speedtest = cancel）。拨号一律经 Host 的拨号缝
// （DialPort/Dial 家族——同记账同重建感知），无旁路直拨。
package facade

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"sync"
)

// carrierDial 承载面统一拨号缝（Daemon 装配 = Host.DialPort/Dial；测试注入桩）。
// host = peerID hex。
type carrierDial struct {
	dialPort func(ctx context.Context, host string, port uint16) (net.Conn, error)        // 出口本机端口
	dial     func(ctx context.Context, host string, dst netip.AddrPort) (net.Conn, error) // 任意目标
}

// Carriers 承载面管理器束（Daemon 持有；未 attach = nil）。
type Carriers struct {
	stateDir string
	dial     carrierDial
	logf     func(format string, args ...any)
	warnf    func(format string, args ...any)

	Fwd *ForwardManager
	Sks *SocksManager
	Spd *SpeedtestManager

	// addMu 「全局端口检查 + 落地」的串行化（forward.add 与 socks.on 两入口共享
	// 同一回环命名空间，check-then-act 必须原子）；**成员检查也在其内**（FIX-05：
	// host.remove 的「删条目 → 级联」与本层并发时，检查落在临界区外可造出
	// 「控制面再也删不掉」的孤儿监听——级联同持 addMu，双向互斥）。
	addMu sync.Mutex
	// hostExists 主机表成员谓词（Attach 时注入；nil = 不校验——直接构造的测试形态）。
	hostExists func(id [32]byte) bool
}

// peerIDFromHex Host 字段（peerID hex）→ id；坏 hex = 不在表。
func peerIDFromHex(s string) ([32]byte, bool) {
	var id [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return id, false
	}
	copy(id[:], b)
	return id, true
}

// openCarriers 打开三个管理器（读各自持久化文件、按表重建监听/运行面）。
func openCarriers(stateDir string, dial carrierDial, logf, warnf func(string, ...any)) (*Carriers, error) {
	return openCarriersWithSocksDefault(stateDir, dial, socksDefaultListen, logf, warnf)
}

// openCarriersWithSocksDefault 同 openCarriers，但注入 socks on 的缺省端口
// （exec-r1 B4：测试注入 0 = 内核选空闲端口，让门禁与「在役 daemon 持 1080」解耦；
// 生产一律走 openCarriers = 1080）。
func openCarriersWithSocksDefault(stateDir string, dial carrierDial, socksDefListen uint16, logf, warnf func(string, ...any)) (*Carriers, error) {
	c := &Carriers{stateDir: stateDir, dial: dial, logf: logf, warnf: warnf}
	if logf == nil {
		c.logf = func(string, ...any) {}
	}
	if warnf == nil {
		c.warnf = c.logf
	}
	fwd, err := openForwardManager(stateDir, dial, logf, warnf)
	if err != nil {
		return nil, err
	}
	sks, err := openSocksManager(stateDir, dial, socksDefListen, logf, warnf)
	if err != nil {
		fwd.Close()
		return nil, err
	}
	c.Fwd, c.Sks = fwd, sks
	c.Spd = newSpeedtestManager(dial, logf)
	return c, nil
}

// AddForward 建转发规则（全局端口检查 + 委托 ForwardManager.Add——当场监听失败 =
// 错误返回、不入表）。
func (c *Carriers) AddForward(rule ForwardRule) error {
	c.addMu.Lock()
	defer c.addMu.Unlock()
	if c.hostExists != nil { // 成员检查在临界区内（FIX-05；见 addMu 注释）
		if id, ok := peerIDFromHex(rule.Host); !ok || !c.hostExists(id) {
			return ErrNoHost
		}
	}
	if owner, taken := c.Fwd.portOwner(rule.Listen); taken {
		return fmt.Errorf("%w：%d 已被 %s 占用", ErrPortTaken, rule.Listen, owner)
	}
	if owner, taken := c.Sks.portOwner(rule.Listen); taken {
		return fmt.Errorf("%w：%d 已被 %s 占用（可用 --listen 另选）", ErrPortTaken, rule.Listen, owner)
	}
	return c.Fwd.Add(rule)
}

// RemoveForward 删规则（不强关在世连接）。
func (c *Carriers) RemoveForward(host string, listen uint16) error {
	return c.Fwd.Remove(host, listen)
}

// ForwardStates 规则表快照（host 空 = 全部）。
func (c *Carriers) ForwardStates(host string) []ForwardState { return c.Fwd.List(host) }

// SocksOn 开 SOCKS 监听（listen 0 = 沿用记忆/缺省）；全局端口检查后委托。返回实际端口。
func (c *Carriers) SocksOn(host string, listen uint16) (uint16, error) {
	c.addMu.Lock()
	defer c.addMu.Unlock()
	if c.hostExists != nil { // 成员检查在临界区内（FIX-05）
		if id, ok := peerIDFromHex(host); !ok || !c.hostExists(id) {
			return 0, ErrNoHost
		}
	}
	// socks×socks 的跨主机冲突（含记忆端口、文案含另选提示）由 SocksManager.On
	// 自带；这里只补 forward 侧的占用检查——按**解析后的端口**判（exec-r1 B1：
	// 此前 listen==0 时整个跳过，靠 On 恒落 1080 的〔错误〕假设兜着）。
	port := listen
	if port == 0 {
		port = c.Sks.DefaultListen(host)
	}
	if port != 0 {
		if owner, taken := c.Fwd.portOwner(port); taken {
			return 0, fmt.Errorf("%w：%d 已被 %s 占用（可用 --listen 另选）", ErrPortTaken, port, owner)
		}
	}
	return c.Sks.On(host, listen)
}

// SocksOff 关监听（显式关在世连接；端口记忆保留）。
func (c *Carriers) SocksOff(host string) error { return c.Sks.Off(host) }

// SocksStates socks 承载态快照。
func (c *Carriers) SocksStates() []SocksState { return c.Sks.Status() }

// SpeedtestStart / Status / Cancel：守护侧测速运行面（per-host 单飞）。
func (c *Carriers) SpeedtestStart(host string, p SpeedtestStart) SpeedtestStartAck {
	return c.Spd.Start(host, p)
}

func (c *Carriers) SpeedtestStatus(host string) *SpeedtestStatus { return c.Spd.Status(host) }

func (c *Carriers) SpeedtestCancel(host string) { c.Spd.Cancel(host) }

// RemoveHost host.remove 级联：forward 规则（delete 语义，不强关）、socks 监听
// （off 语义，显式 RST + 记忆消失）、speedtest（cancel）。持 addMu（FIX-05）：
// 与 AddForward/SocksOn 的成员检查互斥——级联要么看到规则并删掉，要么规则因
// 成员检查失败而根本落不了地。
func (c *Carriers) RemoveHost(id [32]byte) {
	c.addMu.Lock()
	defer c.addMu.Unlock()
	host := hex.EncodeToString(id[:])
	c.Fwd.RemoveHost(host)
	c.Sks.RemoveHost(host)
	c.Spd.RemoveHost(host)
}

// Close 收工（Detach 路径）：forward 只关监听、socks 显式关在世连接、speedtest 取消。
func (c *Carriers) Close() {
	c.Fwd.Close()
	c.Sks.Close()
	c.Spd.Close()
}

// ---------- Daemon 装配（拨号缝 = Host 面） ----------

// carrierDialOf 从 Daemon 装配承载面拨号缝：Host 查表 + DialPort/Dial（同记账同
// 重建感知；表外主机 = ErrNoHost——绑定层沿 no_host 族映射）。
func carrierDialOf(d *Daemon) carrierDial {
	return carrierDial{
		dialPort: func(ctx context.Context, host string, port uint16) (net.Conn, error) {
			h := d.hostByHex(host)
			if h == nil {
				return nil, ErrNoHost
			}
			return h.DialPort(ctx, port)
		},
		dial: func(ctx context.Context, host string, dst netip.AddrPort) (net.Conn, error) {
			h := d.hostByHex(host)
			if h == nil {
				return nil, ErrNoHost
			}
			return h.Dial(ctx, dst)
		},
	}
}

// hostByHex peerID hex → Host（表外/未 attach = nil）。
func (d *Daemon) hostByHex(host string) *Host {
	var id [32]byte
	b, err := hex.DecodeString(host)
	if err != nil || len(b) != 32 {
		return nil
	}
	copy(id[:], b)
	return d.Host(id)
}
