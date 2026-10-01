// forward.go — 桌面端口转发规则管理器（forward-socks-speedtest 3e §2.4，D1/D2/D8）。
//
// daemon 侧承载面：规则持久化于 <state>/forwards.json（0600、原子读改写、损坏按空表
// 重建 + 告警）；监听器在本进程跑（127.0.0.1、仅回环、会话无关长活——规则 add 即起、
// delete/重启重建随表）；入站连接经拨号缝到目标（target 空 = 出口自己同端口、
// target IP = 任意目标缝）。**与手机 portfwd 面（App UI + ClientCoreTunSetPortForwards）
// 零耦合**：两套规则表、两套监听宿主互不相干。
//
// 在世连接语义（r1 中-6）：delete/级联 = **不强关**已建立连接（Go Listener.Close 不
// 影响已 accept 的连接，pipeBoth 自然收口——手机面同款实质）；上游拨号失败 = 本地
// RST 收口（SetLinger(0)，app_portfwd 同款教训：优雅 FIN 会让客户端静默挂住）。
package facade

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zhaoyswd/homeway/pkg/netpipe"
	"github.com/zhaoyswd/homeway/pkg/portfwd"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// forwardsFileName 规则持久化文件（0600）。
const forwardsFileName = "forwards.json"

// forward 校验边界（镜像手机 spec + 桌面全局唯一差异，D1）。
const (
	// 值域真源在 pkg/portfwd（FIX-43：四处重写已漂移，统一到共享包）。
	forwardMinPort    = portfwd.MinPort
	forwardMaxPort    = portfwd.MaxPort
	forwardMaxPerHost = 8
	// forwardMaxConns 每监听并发连接上限（exec-r1 B3-b：spec「每监听 SHALL 有并发
	// 连接上限（超限拒绝并计数）」——与 pkg/socks 的 MaxConns 同值 256；无上限时
	// 任一本机进程可打满 daemon 的 goroutine/fd）。
	forwardMaxConns = 256
	// accept 瞬态错误的有界线性退避（exec-r1 L6：一次瞬态错误即退 = 无人受理的
	// 僵尸监听）。
	forwardAcceptRetryMax  = 8
	forwardAcceptRetryStep = 50 * time.Millisecond
)

// 管理器哨兵（绑定层映射 bad_request / no_host 族；§3 接线）。
var (
	// ErrPortRange 监听端口值域外（= portfwd.ErrRange，同一哨兵）。
	ErrPortRange = portfwd.ErrRange
	// ErrPortTaken 监听端口全局占用（含占用方说明的包装形态）。
	ErrPortTaken = errors.New("监听端口已被占用（全局唯一）")
	// ErrTooManyRules 每主机规则上限。
	ErrTooManyRules = errors.New("每主机 forward 规则上限 8 条")
	// ErrBadTarget 目标形态非法。
	ErrBadTarget = errors.New("目标须为空（出口自己）或 IPv4 字面量")
	// ErrNoForwardRule 规则不存在。
	ErrNoForwardRule = errors.New("forward 规则不存在")
)

// ForwardRule 一条转发规则（持久化形态）。TargetIP 空 = 出口自己；TargetPort 0 =
// 同监听端口（「:<port>」形态——出口自己的指定端口）。
type ForwardRule struct {
	Host       string `json:"host"`                 // peerID hex
	Listen     uint16 `json:"listen"`               // 本机回环监听端口
	TargetIP   string `json:"targetIp,omitempty"`   // 空 = 出口自己；IPv4 字面量
	TargetPort uint16 `json:"targetPort,omitempty"` // 0 = 同监听端口
}

// ForwardState 规则运行态（forward list 面）。
type ForwardState struct {
	Rule     ForwardRule
	State    string // listening | failed
	Err      string
	Conns    int
	Rejected int // 超并发上限被拒的连接计数（exec-r1 B3-b）
}

// forwardEntry 一条规则的运行时。
type forwardEntry struct {
	rule     ForwardRule
	state    string
	err      string
	ln       net.Listener
	conns    atomic.Int32
	rejected atomic.Int32
}

// ForwardManager forward 规则管理器（Carriers 持有；全局端口唯一性检查在 Carriers
// 层做——本管理器只管自己名下的端口）。
type ForwardManager struct {
	mu       sync.Mutex
	stateDir string
	dial     carrierDial
	rules    []*forwardEntry
	logf     func(format string, args ...any)
	warnf    func(format string, args ...any)
}

// openForwardManager 打开规则表：读 forwards.json（缺失 = 空表；损坏 = 备份后空表 +
// 告警不拒启）、按表重建监听器（端口被占 = 该条 failed 如实呈现，不阻断其余——
// 手机「软失败不回滚」哲学）。
func openForwardManager(stateDir string, dial carrierDial, logf, warnf func(string, ...any)) (*ForwardManager, error) {
	m := &ForwardManager{stateDir: stateDir, dial: dial, logf: logf, warnf: warnf}
	if logf == nil {
		m.logf = func(string, ...any) {}
	}
	if warnf == nil {
		m.warnf = m.logf
	}
	recs, err := loadForwardRules(filepath.Join(stateDir, forwardsFileName), m.warnf)
	if err != nil {
		return nil, err
	}
	for _, r := range recs {
		e := &forwardEntry{rule: r}
		if err := m.startListener(e); err != nil {
			e.state, e.err = "failed", err.Error()
			m.warnf("forward: 规则 %s:%d 重建监听失败（%v）——按 failed 呈现，其余规则不受影响", shortHost(r.Host), r.Listen, err)
		}
		m.rules = append(m.rules, e)
	}
	return m, nil
}

// Add 建规则并起监听：校验（值域/每主机上限/本管理器内端口唯一）→ **当场监听**
// （失败 = 错误返回、不入表——「failed 软状态」只留重启重建路径，r1 低-7）→ 落盘 →
// 入表。调用方（Carriers）已做跨 socks 的全局端口检查。
func (m *ForwardManager) Add(rule ForwardRule) error {
	if err := portfwd.ValidateListen(rule.Listen); err != nil {
		return err
	}
	if rule.TargetIP != "" {
		ip, err := netip.ParseAddr(rule.TargetIP)
		if err != nil || !ip.Is4() {
			return fmt.Errorf("%w：%s", ErrBadTarget, rule.TargetIP)
		}
	}
	if err := portfwd.ValidateTarget(rule.TargetIP, rule.TargetPort); err != nil {
		return err
	}
	// 目标端口不限下界（spec 的「配置校验」只约束监听端口；目标端口是出口去拨的，
	// 不做 bind——转发到出口自己的 :22/:80 合法，FIX-43 起与 App 同口径）。
	m.mu.Lock()
	defer m.mu.Unlock()
	perHost := 0
	for _, e := range m.rules {
		if e.rule.Host == rule.Host {
			perHost++
		}
		if e.rule.Listen == rule.Listen {
			return fmt.Errorf("%w：%d 已被 %s 的 forward 规则占用", ErrPortTaken, rule.Listen, shortHost(e.rule.Host))
		}
	}
	if perHost >= forwardMaxPerHost {
		return fmt.Errorf("%w（%s 已 %d 条）", ErrTooManyRules, shortHost(rule.Host), perHost)
	}
	e := &forwardEntry{rule: rule}
	if err := m.startListener(e); err != nil {
		return fmt.Errorf("监听 127.0.0.1:%d 失败（%w）——规则不入表", rule.Listen, err)
	}
	// 先入表再落盘（落盘内容 = 内存表快照）；落盘失败撤回——零副作用。
	m.rules = append(m.rules, e)
	if err := m.saveLocked(); err != nil {
		_ = e.ln.Close()
		m.rules = m.rules[:len(m.rules)-1]
		return err
	}
	m.logf("forward: + %s 127.0.0.1:%d → %s", shortHost(rule.Host), rule.Listen, describeTarget(rule))
	return nil
}

// Remove 删规则并关监听（**不强关**在世连接——自然收口；conns 可观察此过程）。
func (m *ForwardManager) Remove(host string, listen uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, e := range m.rules {
		if e.rule.Host == host && e.rule.Listen == listen {
			if e.ln != nil {
				_ = e.ln.Close() // 只关监听：已 accept 的连接由 pipeBoth 自然收口
			}
			m.rules = append(m.rules[:i], m.rules[i+1:]...)
			if err := m.saveLocked(); err != nil {
				return err
			}
			m.logf("forward: - %s 127.0.0.1:%d（在世连接不强关）", shortHost(host), listen)
			return nil
		}
	}
	return fmt.Errorf("%w：%s/%d", ErrNoForwardRule, shortHost(host), listen)
}

// RemoveHost 级联删该主机全部规则（host.remove；同 delete 语义——不强关在世连接）。
func (m *ForwardManager) RemoveHost(host string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.rules[:0]
	for _, e := range m.rules {
		if e.rule.Host == host {
			if e.ln != nil {
				_ = e.ln.Close()
			}
			m.logf("forward: - %s 127.0.0.1:%d（主机删除级联；在世连接不强关）", shortHost(host), e.rule.Listen)
			continue
		}
		kept = append(kept, e)
	}
	m.rules = kept
	if err := m.saveLocked(); err != nil {
		m.warnf("forward: 级联删除后落盘失败（%v）——内存为准，下次写回收敛", err)
	}
}

// List 规则表快照（host 空 = 全部；按 host/listen 稳定排序）。
func (m *ForwardManager) List(host string) []ForwardState {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ForwardState, 0, len(m.rules))
	for _, e := range m.rules {
		if host != "" && e.rule.Host != host {
			continue
		}
		st := ForwardState{Rule: e.rule, State: e.state, Err: e.err, Conns: int(e.conns.Load()), Rejected: int(e.rejected.Load())}
		out = append(out, st)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0; j-- {
			if out[j].Rule.Host < out[j-1].Rule.Host ||
				(out[j].Rule.Host == out[j-1].Rule.Host && out[j].Rule.Listen < out[j-1].Rule.Listen) {
				out[j], out[j-1] = out[j-1], out[j]
			}
		}
	}
	return out
}

// portOwner 端口占用查询（全局唯一检查用）：占用返回占用方描述。
func (m *ForwardManager) portOwner(port uint16) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.rules {
		if e.rule.Listen == port {
			return shortHost(e.rule.Host) + " 的 forward 规则", true
		}
	}
	return "", false
}

// Close 收工：关全部监听（在世连接不强关；随进程/角色收口）。
func (m *ForwardManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.rules {
		if e.ln != nil {
			_ = e.ln.Close()
		}
	}
}

// startListener 起 127.0.0.1 回环监听 + accept 循环（调用方持锁或装配期）。
func (m *ForwardManager) startListener(e *forwardEntry) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", e.rule.Listen))
	if err != nil {
		return err
	}
	e.ln = ln
	e.state, e.err = "listening", ""
	go m.acceptLoop(e)
	return nil
}

func (m *ForwardManager) acceptLoop(e *forwardEntry) {
	backoff := 0
	for {
		conn, err := e.ln.Accept()
		if err == nil {
			backoff = 0
			// exec-r1 B3-b：每监听并发上限（256，与 socks MaxConns 同值）——超限
			// 拒绝并计数（单 accept goroutine 串行判-增，不会超上限）。
			if int(e.conns.Load()) >= forwardMaxConns {
				e.rejected.Add(1)
				m.logf("forward: %s:%d 连接拒绝（并发上限 %d）", shortHost(e.rule.Host), e.rule.Listen, forwardMaxConns)
				_ = conn.Close()
				continue
			}
			e.conns.Add(1)
			go m.serveConn(e, conn)
			continue
		}
		if errors.Is(err, net.ErrClosed) {
			return // 监听器被关（delete/级联/收工）——正常收口
		}
		// L6/exec-r1：瞬态错误（EMFILE 等）有界线性退避；烧尽 = 置 failed+原因
		//（与重启重建的 failed 软状态同款），防「状态说在听、实际没人 accept」。
		if backoff >= forwardAcceptRetryMax {
			m.mu.Lock()
			if e.ln != nil {
				_ = e.ln.Close()
				e.state, e.err = "failed", fmt.Sprintf("accept 连续失败（%d 次）：%v", backoff+1, err)
			}
			m.mu.Unlock()
			m.warnf("forward: %s:%d %s", shortHost(e.rule.Host), e.rule.Listen, e.err)
			return
		}
		backoff++
		time.Sleep(time.Duration(backoff) * forwardAcceptRetryStep)
	}
}

// serveConn 单条转发：拨号 → 双向透传。上游失败 = RST 收口（MUST NOT 优雅 FIN
// 静默挂住客户端）。
func (m *ForwardManager) serveConn(e *forwardEntry, conn net.Conn) {
	defer func() {
		e.conns.Add(-1)
		_ = conn.Close()
	}()
	r := e.rule
	port := r.TargetPort
	if port == 0 {
		port = r.Listen
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var upstream net.Conn
	var err error
	if r.TargetIP == "" {
		upstream, err = m.dial.dialPort(ctx, r.Host, port) // 出口自己
	} else {
		ip := netip.MustParseAddr(r.TargetIP)
		upstream, err = m.dial.dial(ctx, r.Host, netip.AddrPortFrom(ip, port)) // 任意目标
	}
	if err != nil {
		m.logf("forward: %s:%d 拨上游失败（RST 收口）：%v", shortHost(r.Host), r.Listen, err)
		rstCloseConn(conn)
		return
	}
	defer upstream.Close()
	// 半关闭透传（FIX-35）：任一向 EOF 只收该向写端，不再双向收口——原实现把
	// 「客户端关写等响应」的响应当场截断（与手机面 pipeBoth 语义相悖）。
	netpipe.Both(m.logf, conn, upstream)
}

// ---------- 持久化 ----------

// saveLocked 落盘规则表（tmp+rename 原子替换，0600；调用方持锁）。
func (m *ForwardManager) saveLocked() error {
	path := filepath.Join(m.stateDir, forwardsFileName)
	if err := os.MkdirAll(m.stateDir, 0o700); err != nil {
		return err
	}
	recs := make([]ForwardRule, 0, len(m.rules))
	for _, e := range m.rules {
		recs = append(recs, e.rule)
	}
	b, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// loadForwardRules 读规则表（hosts.json 同口径：缺失 = 空表；损坏 = 备份后空表 +
// 告警不拒启）。
func loadForwardRules(path string, warnf func(string, ...any)) ([]ForwardRule, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var recs []ForwardRule
	if err := json.Unmarshal(b, &recs); err != nil {
		backup := fmt.Sprintf("%s.corrupt-%d", path, time.Now().Unix())
		if rerr := os.Rename(path, backup); rerr != nil {
			return nil, fmt.Errorf("forwards.json 损坏（%v）且备份失败：%w", err, rerr)
		}
		warnf("forwards.json 损坏（%v）——已备份 %s，按空表重建（原件保留，可修复后重启恢复）", err, backup)
		return nil, nil
	}
	return recs, nil
}

// DescribeForwardTarget 转发目标的**呈现文案**（出口自己 / 出口自己:N / ip:N；
// port 0 = 同监听端口 ⇒ 落成 listen）。语义唯一源（FIX-46）：CLI 表格、日志与
// 手机 status 面此前各写一遍，手机面把 0 原样呈现成「1.2.3.4:0」（用户看不出
// 到底转发到哪）；以后新增呈现面一律走这里。
func DescribeForwardTarget(ip string, port, listen uint16) string {
	return portfwd.DescribeTarget(ip, port, listen)
}

// describeTarget 规则目标的日志文案。
func describeTarget(r ForwardRule) string {
	if r.TargetIP == "" {
		if r.TargetPort == 0 {
			return "出口自己（同端口）"
		}
		return fmt.Sprintf("出口自己:%d", r.TargetPort)
	}
	return fmt.Sprintf("%s:%d", r.TargetIP, r.TargetPort)
}

// shortHost peerID hex 的短形态（日志/错误文案用）。
func shortHost(host string) string {
	if len(host) > 8 {
		return host[:8] + "…"
	}
	return host
}

// rstCloseConn RST 收口（尽力而为——按接口断言：非 TCP 形态〔含包装连接〕静默忽略）。
func rstCloseConn(c net.Conn) {
	if l, ok := c.(interface{ SetLinger(int) error }); ok {
		_ = l.SetLinger(0)
	}
}
