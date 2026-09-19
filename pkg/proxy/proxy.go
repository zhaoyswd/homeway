// Package proxy：出口侧「被转发的用户流量经上游代理」。
//
// 为什么需要它：出口自身必须让**打洞/STUN socket 直连**（一旦经 TUN 型代理，包会被代理用
// 自己的 socket 重发 ⇒ 对端拿到的映射不属于我们 ⇒ 打洞失败），但被转发的用户流量通常希望
// 经代理出网（境内直连、境外走代理）。同一台机器上这两件事只能显式分开：出口自己的 socket
// 直连/绑卡，转发流量走 --forward-via-proxy。
//
// 语义（与旧栈 tailcat 的 --forward-via-proxy/--forward-udp 对齐）：
//
//	--forward-via-proxy=socks5://host:port   被转发的 TCP 与 UDP 经它拨出
//	--forward-udp=auto|on|off                 UDP 是否也经代理（默认 auto）
//	  off ：只代理 TCP，UDP 直出
//	  auto：探测代理能不能承载 UDP（UDP ASSOCIATE + STUN 探针）；能就经代理，不能就直出并说明原因
//	  on  ：必须经代理，探测不通过就明确失败（不静默直出）
//
// 只用 SOCKS5（含 socks5h 别名）：UDP ASSOCIATE 是它独有的能力，HTTP 代理承载不了 UDP，
// 混在一起只会让"看着配了、其实 UDP 直出"这种坑重现。
package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sync"
	"time"
)

// UDPMode 是 --forward-udp 的取值。
type UDPMode string

const (
	UDPAuto UDPMode = "auto" // 默认：探测后决定
	UDPOn   UDPMode = "on"   // 必须经代理
	UDPOff  UDPMode = "off"  // UDP 不经代理
)

// ParseUDPMode 解析 --forward-udp（纯函数，便于单测）。
func ParseUDPMode(v string) (UDPMode, error) {
	switch v {
	case "", string(UDPAuto):
		return UDPAuto, nil
	case string(UDPOn):
		return UDPOn, nil
	case string(UDPOff):
		return UDPOff, nil
	default:
		return "", fmt.Errorf("--forward-udp %q：只支持 auto、on、off", v)
	}
}

// 默认 STUN 探针目标（**字面 IP**：规则型代理会把域名变成 fake-IP，域名探针测不出真东西）。
var defaultProbeTargets = []netip.AddrPort{
	netip.MustParseAddrPort("162.159.207.1:3478"),  // Cloudflare
	netip.MustParseAddrPort("74.125.250.129:19302"), // Google
}

// Client 一条 SOCKS5 上游。零值不可用，用 New 构造；nil 表示没有代理。
type Client struct {
	raw      string
	host     string
	user     string
	pass     string
	timeout  time.Duration
	mode     UDPMode
	targets  []netip.AddrPort

	mu       sync.Mutex
	verdict  *UDPVerdict
	inflight chan struct{}
	fails    int
	ttl      time.Duration
}

// UDPVerdict 是 UDP 能力探测的结论。
type UDPVerdict struct {
	Supported bool
	Detail    string
	At        time.Time
}

// New 解析 --forward-via-proxy（空 = 没有代理，返回 nil）。
func New(raw string, mode UDPMode, targets []netip.AddrPort, timeout time.Duration) (*Client, error) {
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("--forward-via-proxy %q: %w", raw, err)
	}
	if u.Scheme != "socks5" && u.Scheme != "socks5h" {
		return nil, fmt.Errorf("--forward-via-proxy %q：只支持 socks5:// 与 socks5h://（UDP 要 SOCKS5 的 UDP ASSOCIATE）", raw)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("--forward-via-proxy %q：缺少主机:端口", raw)
	}
	c := &Client{raw: raw, host: u.Host, timeout: timeout, mode: mode, targets: targets}
	c.ttl = defaultVerdictTTL
	if c.timeout <= 0 {
		c.timeout = 10 * time.Second
	}
	if len(c.targets) == 0 {
		c.targets = defaultProbeTargets
	}
	if u.User != nil {
		c.user = u.User.Username()
		c.pass, _ = u.User.Password()
	}
	return c, nil
}

// defaultVerdictTTL：探测结论的有效期。到期重探 —— 代理可能后起（出口先启动、代理后上），
// 缓存一个"不支持"就必须能自愈，否则要重启出口才能用上 UDP 代理。
const defaultVerdictTTL = 5 * time.Minute

// SetVerdictTTL 覆盖结论有效期（测试用；<=0 用默认）。
func (c *Client) SetVerdictTTL(d time.Duration) {
	if c == nil {
		return
	}
	if d <= 0 {
		d = defaultVerdictTTL
	}
	c.mu.Lock()
	c.ttl = d
	c.mu.Unlock()
}

// Host 代理地址（日志用）。
func (c *Client) Host() string {
	if c == nil {
		return ""
	}
	return c.host
}

// Mode UDP 模式。
func (c *Client) Mode() UDPMode {
	if c == nil {
		return UDPOff
	}
	return c.mode
}

// dialControl 连代理本身（**不绑卡、不走代理**：代理地址是运维显式配置的）。
func (c *Client) dialControl(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	if dl, ok := ctx.Deadline(); ok {
		d.Deadline = dl
	} else {
		d.Timeout = c.timeout
	}
	return d.DialContext(ctx, "tcp", c.host)
}

// DialContext 经代理拨 TCP（flows.DialFunc 形状）。没有代理时行为等同直拨。
func (c *Client) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if c == nil {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(c.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	conn, err := c.dialControl(ctx)
	if err != nil {
		return nil, fmt.Errorf("proxy: 连代理 %s 失败: %w", c.host, err)
	}
	if err := handshake(conn, c.user, c.pass, deadline); err != nil {
		conn.Close()
		return nil, err
	}
	dst, err := encodeAddr(host, uint16(port))
	if err != nil {
		conn.Close()
		return nil, err
	}
	_, rep, err := request(conn, cmdConnect, dst, deadline)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if rep != repSuccess {
		conn.Close()
		return nil, &ReplyError{Rep: rep}
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// UDPDecision：一次"这条 UDP 会话怎么走"的裁决（进日志，也让测试能断言）。
type UDPDecision struct {
	Via        string // "proxy" / "direct"
	Reason     string
	Verdict    *UDPVerdict
	Err        error // mode=on 且探测不通过时的硬错误
}

// DecideUDP 按模式与探测结论裁决一条 UDP 会话的走向。
func (c *Client) DecideUDP(ctx context.Context) UDPDecision {
	if c == nil {
		return UDPDecision{Via: "direct", Reason: "未配置 --forward-via-proxy"}
	}
	if c.mode == UDPOff {
		return UDPDecision{Via: "direct", Reason: "--forward-udp=off"}
	}
	v := c.UDPVerdict(ctx)
	if v.Supported {
		return UDPDecision{Via: "proxy", Reason: v.Detail, Verdict: v}
	}
	if c.mode == UDPOn {
		return UDPDecision{Via: "direct", Reason: v.Detail, Verdict: v,
			Err: fmt.Errorf("--forward-udp=on 但代理 %s 不能承载 UDP：%s", c.host, v.Detail)}
	}
	return UDPDecision{Via: "direct", Reason: "代理不能承载 UDP（" + v.Detail + "），回落直出", Verdict: v}
}

// NoteUDPFailure 记一次"按结论该走代理、但失败"。连续失败到阈值就把结论作废，下次重探
// （代理重启/换后端能自愈）。
func (c *Client) NoteUDPFailure(logf func(string, ...any)) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.fails++
	reset := c.fails >= 3
	if reset {
		c.verdict = nil
	}
	fails := c.fails
	c.mu.Unlock()
	if reset && logf != nil {
		logf("forward-udp: 连续 %d 次经代理转发 UDP 失败，丢弃探测结论（下次重新探测）", fails)
	}
}

// UDPVerdict 返回缓存的探测结论；没有就同步探一次（并发调用共享同一次探测）。
func (c *Client) UDPVerdict(ctx context.Context) *UDPVerdict {
	if c == nil {
		return &UDPVerdict{Supported: false, Detail: "没有配置代理", At: time.Now()}
	}
	for {
		c.mu.Lock()
		if c.verdict != nil {
			ttl := c.ttl
			if ttl <= 0 {
				ttl = defaultVerdictTTL
			}
			if time.Since(c.verdict.At) < ttl {
				v := c.verdict
				c.mu.Unlock()
				return v
			}
			c.verdict = nil // 过期：丢掉重探（并发调用共享下面这次探测）
		}
		wait := c.inflight
		if wait != nil {
			c.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return &UDPVerdict{Supported: false, Detail: "等待代理探测结果超时", At: time.Now()}
			}
		}
		done := make(chan struct{})
		c.inflight = done
		c.mu.Unlock()

		v := c.probeUDP(ctx)

		c.mu.Lock()
		c.verdict = v
		c.fails = 0
		c.inflight = nil
		c.mu.Unlock()
		close(done)
		return v
	}
}

// probeUDP 探测：UDP ASSOCIATE（看 REP）+ STUN 探针（校验事务 ID）。
func (c *Client) probeUDP(ctx context.Context) *UDPVerdict {
	pctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	conn, err := c.OpenUDPConn(pctx, netip.AddrPort{})
	if err != nil {
		var re *ReplyError
		if errors.As(err, &re) {
			return &UDPVerdict{Supported: false, Detail: "UDP ASSOCIATE 被拒：" + repString(re.Rep), At: time.Now()}
		}
		return &UDPVerdict{Supported: false, Detail: "UDP ASSOCIATE 失败：" + err.Error(), At: time.Now()}
	}
	defer conn.Close()

	var lastErr error
	for _, target := range c.targets {
		mapped, err := stunProbe(pctx, conn, target)
		if err == nil {
			return &UDPVerdict{Supported: true,
				Detail: fmt.Sprintf("探针 %v 收到可校验应答（映射 %v）", target, mapped), At: time.Now()}
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("没有可用的探针目标")
	}
	return &UDPVerdict{Supported: false, Detail: "中继已建立但没有有效应答：" + lastErr.Error(), At: time.Now()}
}

// stunProbe 经一条 UDP 通道向 target 发 STUN 并校验应答。
func stunProbe(ctx context.Context, conn *UDPConn, target netip.AddrPort) (netip.AddrPort, error) {
	txID := NewTxID()
	if _, err := conn.WriteToUDPAddrPort(StunRequest(txID, "homewayd"), target); err != nil {
		return netip.AddrPort{}, err
	}
	deadline := time.Now().Add(3 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetReadDeadline(deadline)
	defer conn.SetReadDeadline(time.Time{})
	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return netip.AddrPort{}, err
		}
		gotTx, mapped, err := ParseStunResponse(buf[:n])
		if err != nil {
			continue // 不是 STUN 应答（可能是并发会话的数据）⇒ 继续等
		}
		if gotTx != txID {
			continue // 事务 ID 对不上 ⇒ 不是我们这条请求的应答
		}
		return mapped, nil
	}
}
