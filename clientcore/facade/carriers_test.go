// carriers_test.go — 承载面管理器三件（3e §2.4，任务 2.4 验证）：规则校验矩阵、
// 全局端口冲突、级联删除、重启重建、损坏重建、在世连接两分面、socks 缓存（TTL/
// 逐出/跨出口隔离/否定不缓存）、speedtest runner（单飞/waiting 到期/取消归因/
// 拨号被拒 → not_supported）。拨号缝全部假注入，不碰真隧道。
package facade

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/speedtest"
	"github.com/zhaoyswd/homeway/pkg/wgnet"
)

// ---------- 测试基建 ----------

// fakeDial 可观测的拨号缝桩。
type fakeDial struct {
	mu        sync.Mutex
	dialPortF func(ctx context.Context, host string, port uint16) (net.Conn, error)
	dialF     func(ctx context.Context, host string, dst netip.AddrPort) (net.Conn, error)
	portCalls []string // "host:port" 记账（5300 查询计数用）
	addrCalls []string // "host:ip:port" 记账
}

func (f *fakeDial) dialPort(ctx context.Context, host string, port uint16) (net.Conn, error) {
	f.mu.Lock()
	f.portCalls = append(f.portCalls, fmt.Sprintf("%s:%d", host, port))
	fn := f.dialPortF
	f.mu.Unlock()
	if fn == nil {
		return nil, errors.New("fake: dialPort 未配置")
	}
	return fn(ctx, host, port)
}

func (f *fakeDial) dial(ctx context.Context, host string, dst netip.AddrPort) (net.Conn, error) {
	f.mu.Lock()
	f.addrCalls = append(f.addrCalls, fmt.Sprintf("%s:%s", host, dst))
	fn := f.dialF
	f.mu.Unlock()
	if fn == nil {
		return nil, errors.New("fake: dial 未配置")
	}
	return fn(ctx, host, dst)
}

func (f *fakeDial) snapshot() (ports []string, addrs []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.portCalls...), append([]string{}, f.addrCalls...)
}

func discardLogf(string, ...any) {}

// openTestCarriers 假拨号缝的 Carriers。
func openTestCarriers(t *testing.T, fd *fakeDial) *Carriers {
	t.Helper()
	c, err := openCarriers(t.TempDir(), carrierDial{dialPort: fd.dialPort, dial: fd.dial}, discardLogf, discardLogf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

// echoUpstream 起 TCP 回显上游。
func echoUpstream(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

// ---------- forward 管理器 ----------

// TestForwardRuleValidation 规则校验矩阵：端口值域、目标 IPv4 字面量、每主机 ≤8、
// 端口全局唯一、成功路径入表落盘。
func TestForwardRuleValidation(t *testing.T) {
	c := openTestCarriers(t, &fakeDial{})
	hostA, hostB := strings.Repeat("aa", 32), strings.Repeat("bb", 32)

	cases := []struct {
		name string
		rule ForwardRule
		want error
	}{
		{"端口过小", ForwardRule{Host: hostA, Listen: 80}, ErrPortRange},
		{"端口保留段", ForwardRule{Host: hostA, Listen: 1023}, ErrPortRange},
		{"目标非 IPv4", ForwardRule{Host: hostA, Listen: 2000, TargetIP: "example.com"}, ErrBadTarget},
		{"目标是 v6", ForwardRule{Host: hostA, Listen: 2000, TargetIP: "::1"}, ErrBadTarget},
		{"目标端口越界", ForwardRule{Host: hostA, Listen: 2000, TargetPort: 80}, ErrPortRange},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := c.AddForward(tc.rule); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v，期望 %v", err, tc.want)
			}
		})
	}
	// 每主机 8 条上限。
	for i := 0; i < 8; i++ {
		if err := c.AddForward(ForwardRule{Host: hostA, Listen: uint16(3000 + i)}); err != nil {
			t.Fatalf("第 %d 条应成功：%v", i+1, err)
		}
	}
	if err := c.AddForward(ForwardRule{Host: hostA, Listen: 4000}); !errors.Is(err, ErrTooManyRules) {
		t.Fatalf("第 9 条应 ErrTooManyRules，got %v", err)
	}
	// 跨主机端口冲突（全局唯一）。
	if err := c.AddForward(ForwardRule{Host: hostB, Listen: 3000}); !errors.Is(err, ErrPortTaken) {
		t.Fatalf("跨主机同端口应 ErrPortTaken，got %v", err)
	}
	if got := len(c.ForwardStates(hostA)); got != 8 {
		t.Fatalf("hostA 应 8 条，实得 %d", got)
	}
	// 落盘核对。
	b, err := os.ReadFile(filepath.Join(c.stateDir, forwardsFileName))
	if err != nil || !strings.Contains(string(b), "\"listen\": 3000") {
		t.Fatalf("forwards.json 落盘异常：%v", err)
	}
}

// TestForwardAddEaddrinuseNotInTable add 当场监听失败（端口被守护外进程占用）→
// 错误返回、规则不入表（r1 低-7——failed 软状态只留重启重建路径）。
func TestForwardAddEaddrinuseNotInTable(t *testing.T) {
	ext, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ext.Close()
	port := netip.MustParseAddrPort(ext.Addr().String()).Port()

	c := openTestCarriers(t, &fakeDial{})
	err = c.AddForward(ForwardRule{Host: strings.Repeat("aa", 32), Listen: port})
	if err == nil || !strings.Contains(err.Error(), "监听") {
		t.Fatalf("应报监听失败，got %v", err)
	}
	if got := c.ForwardStates(""); got != nil && len(got) != 0 {
		t.Fatalf("规则不应入表，实得 %v", got)
	}
	if _, rerr := os.Stat(filepath.Join(c.stateDir, forwardsFileName)); !errors.Is(rerr, os.ErrNotExist) {
		t.Fatalf("规则不入表则不应落盘：%v", rerr)
	}
}

// freePort 取一个当前空闲且**可重绑**的回环端口（listen :0 → 记下 → 关 → 复验
// 可再绑；防拿到刚进 TIME_WAIT 的连接端口——:0 分配不避开它们）。
func freePort(t *testing.T) uint16 {
	t.Helper()
	for i := 0; i < 50; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		ln.Close()
		verify, err := net.Listen("tcp", addr)
		if err != nil {
			continue // TIME_WAIT 类占用——换一个
		}
		verify.Close()
		return netip.MustParseAddrPort(addr).Port()
	}
	t.Fatal("找不到可重绑的空闲端口")
	return 0
}

// dialUp 把拨号缝实现为「拨真实 TCP 目标」。
func dialUp() (func(context.Context, string, uint16) (net.Conn, error), func(context.Context, string, netip.AddrPort) (net.Conn, error)) {
	d := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var nd net.Dialer
		return nd.DialContext(ctx, network, addr)
	}
	return func(ctx context.Context, host string, port uint16) (net.Conn, error) {
			return d(ctx, "tcp", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port).String())
		}, func(ctx context.Context, host string, dst netip.AddrPort) (net.Conn, error) {
			return d(ctx, "tcp", dst.String())
		}
}

// TestForwardDataPath 数据路径两形态：目标空 = 拨出口同端口（dialPort 缝，host 透传）；
// 目标 IP = 任意目标缝（dial，ip:port 透传）。
func TestForwardDataPath(t *testing.T) {
	up := echoUpstream(t)
	var hosts, dsts sync.Map
	fd := &fakeDial{}
	fd.dialPortF = func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		hosts.Store("port:"+host, port)
		var nd net.Dialer
		return nd.DialContext(ctx, "tcp", netip.AddrPortFrom(up.Addr(), port).String())
	}
	fd.dialF = func(ctx context.Context, host string, dst netip.AddrPort) (net.Conn, error) {
		dsts.Store("dst:"+host, dst)
		var nd net.Dialer
		return nd.DialContext(ctx, "tcp", dst.String())
	}
	c := openTestCarriers(t, fd)
	hostA := strings.Repeat("aa", 32)
	// 两个监听口都在建立任何连接**之前**取好（测试连接的 TIME_WAIT 会污染 :0 分配）。
	listenA, listenB := freePort(t), freePort(t)

	// 目标空：拨出口同端口（出口自己 = TargetPort）。
	if err := c.AddForward(ForwardRule{Host: hostA, Listen: listenA, TargetPort: up.Port()}); err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listenA), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("回显不符：%q %v", buf, err)
	}
	conn.Close()
	if v, ok := hosts.Load("port:" + hostA); !ok || v.(uint16) != up.Port() {
		t.Fatalf("dialPort 缝应收到出口同端口：%v %v", v, ok)
	}

	// 目标 IP：任意目标缝。
	if err := c.AddForward(ForwardRule{Host: hostA, Listen: listenB, TargetIP: "127.0.0.1", TargetPort: up.Port()}); err != nil {
		t.Fatal(err)
	}
	conn2, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listenB), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn2.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn2.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	buf2 := make([]byte, 4)
	if _, err := io.ReadFull(conn2, buf2); err != nil || string(buf2) != "pong" {
		t.Fatalf("回显不符：%q %v", buf2, err)
	}
	conn2.Close()
	if v, ok := dsts.Load("dst:" + hostA); !ok || v.(netip.AddrPort).Port() != up.Port() {
		t.Fatalf("dial 缝应收到目标 ip:port：%v %v", v, ok)
	}
}

// TestForwardDeleteNotForceClose 在世连接两分面之一：delete 关监听但不强关已建立
// 连接（自然收口）；conns 计数可观察。
func TestForwardDeleteNotForceClose(t *testing.T) {
	up := echoUpstream(t)
	dp, dd := dialUp()
	fd := &fakeDial{dialPortF: dp, dialF: dd}
	c := openTestCarriers(t, fd)
	host := strings.Repeat("aa", 32)
	listen := freePort(t)
	if err := c.AddForward(ForwardRule{Host: host, Listen: listen, TargetPort: up.Port()}); err != nil {
		t.Fatal(err)
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listen), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	waitFor(t, time.Second, func() bool {
		for _, st := range c.ForwardStates(host) {
			if st.Conns >= 1 {
				return true
			}
		}
		return false
	}, "在世连接应可观察")

	// 删除规则：监听关（新连接被拒）、已建立连接继续透传。
	if err := c.RemoveForward(host, listen); err != nil {
		t.Fatal(err)
	}
	if _, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listen), 300*time.Millisecond); err == nil {
		t.Fatal("删除后监听应已关（新连接被拒）")
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("still-alive")); err != nil {
		t.Fatalf("在世连接不应被强关：%v", err)
	}
	buf := make([]byte, 11)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "still-alive" {
		t.Fatalf("在世连接透传不符：%q %v", buf, err)
	}
}

// TestForwardRebuild 重启重建：关掉重开（同 stateDir）→ 监听按表重建；端口被占的
// 那条 failed 如实呈现、其余不受影响。
func TestForwardRebuild(t *testing.T) {
	dir := t.TempDir()
	up := echoUpstream(t)
	dp, dd := dialUp()
	fd := &fakeDial{dialPortF: dp, dialF: dd}
	c1, err := openCarriers(dir, carrierDial{dialPort: fd.dialPort, dial: fd.dial}, discardLogf, discardLogf)
	if err != nil {
		t.Fatal(err)
	}
	host := strings.Repeat("aa", 32)
	listen1, listen2 := freePort(t), freePort(t)
	if err := c1.AddForward(ForwardRule{Host: host, Listen: listen1, TargetPort: up.Port()}); err != nil {
		t.Fatal(err)
	}
	if err := c1.AddForward(ForwardRule{Host: host, Listen: listen2, TargetIP: "127.0.0.1", TargetPort: up.Port()}); err != nil {
		t.Fatal(err)
	}
	c1.Close()

	// 占掉第二条的端口后重开：第二条 failed、第一条照常。
	occ, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", listen2))
	if err != nil {
		t.Fatal(err)
	}
	defer occ.Close()
	c2, err := openCarriers(dir, carrierDial{dialPort: fd.dialPort, dial: fd.dial}, discardLogf, discardLogf)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	states := c2.ForwardStates(host)
	if len(states) != 2 {
		t.Fatalf("重建后应 2 条，实得 %d", len(states))
	}
	for _, st := range states {
		if st.Rule.Listen == listen1 && st.State != "listening" {
			t.Fatalf("未被占的规则应 listening：%+v", st)
		}
		if st.Rule.Listen == listen2 {
			if st.State != "failed" || st.Err == "" {
				t.Fatalf("被占的规则应 failed+原因：%+v", st)
			}
		}
	}
	// 第一条数据面仍通。
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listen1), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
}

// TestForwardCorruptRebuild forwards.json 损坏 → 备份 + 空表重建 + 告警不拒启。
func TestForwardCorruptRebuild(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, forwardsFileName), []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	warned := atomic.Bool{}
	c, err := openCarriers(dir, carrierDial{}, discardLogf, func(format string, args ...any) { warned.Store(true) })
	if err != nil {
		t.Fatalf("损坏应按空表重建不拒启：%v", err)
	}
	defer c.Close()
	if got := c.ForwardStates(""); len(got) != 0 {
		t.Fatalf("空表重建，实得 %d 条", len(got))
	}
	if !warned.Load() {
		t.Fatal("应产生告警")
	}
	matches, _ := filepath.Glob(filepath.Join(dir, forwardsFileName+".corrupt-*"))
	if len(matches) != 1 {
		t.Fatalf("应留备份：%v", matches)
	}
}

// TestSocksCorruptRebuild socks.json 损坏同口径。
func TestSocksCorruptRebuild(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, socksFileName), []byte("[not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := openCarriers(dir, carrierDial{}, discardLogf, discardLogf)
	if err != nil {
		t.Fatalf("损坏应按空表重建不拒启：%v", err)
	}
	defer c.Close()
	if got := c.SocksStates(); len(got) != 0 {
		t.Fatalf("空表重建，实得 %d 条", len(got))
	}
}

// waitFor 轮询等待条件成立。
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("等待超时：%s", what)
}

// ---------- socks 管理器 ----------

// miniSocksClient 测试用 SOCKS5 客户端（协商 + 域名 CONNECT；返回可用连接）。
func miniSocksClient(t *testing.T, addr string, domain string, port uint16) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(conn, sel); err != nil || sel[1] != 0 {
		t.Fatalf("协商失败：%v %v", sel, err)
	}
	req := []byte{5, 1, 0, 3, byte(len(domain))}
	req = append(req, []byte(domain)...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if resp[1] != 0 {
		return nil // 调用方按 rep 断言
	}
	return conn
}

// fakeDNSResponder 造一条 A 应答（回显 question、追加一条 A 记录，TTL 60）。
func fakeDNSResponse(q []byte, ip netip.Addr) []byte {
	resp := append([]byte(nil), q...)
	resp[2] = 0x80 | (q[2] & 0x01)
	resp[3] = 0
	a := ip.As4()
	rec := []byte{0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, a[0], a[1], a[2], a[3]}
	resp = append(resp, rec...)
	binary.BigEndian.PutUint16(resp[6:8], 1)
	return resp
}

// serveDNSOverPipe 在 pipe 另一端应答 A 查询（ipFor 决定答案；nil = NXDOMAIN）。
func serveDNSOverPipe(serverEnd net.Conn, ipFor func(hostKey string) netip.Addr, key string) {
	defer serverEnd.Close()
	br := bufio.NewReader(serverEnd)
	var lb [2]byte
	if _, err := io.ReadFull(br, lb[:]); err != nil {
		return
	}
	q := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(br, q); err != nil {
		return
	}
	var out []byte
	if ip := ipFor(key); ip.IsValid() {
		out = fakeDNSResponse(q, ip)
	} else {
		out = append([]byte(nil), q...)
		out[2] = 0x80 | (q[2] & 0x01)
		out[3] = 3 // NXDOMAIN
	}
	framed := make([]byte, 2+len(out))
	binary.BigEndian.PutUint16(framed[0:2], uint16(len(out)))
	copy(framed[2:], out)
	_, _ = serverEnd.Write(framed)
}

// TestSocksOnOffStatus 开关与状态：默认端口、off 记忆保留、再次 on 沿用、同端口幂等。
func TestSocksOnOffStatus(t *testing.T) {
	c := openTestCarriers(t, &fakeDial{})
	hostA, hostB := strings.Repeat("aa", 32), strings.Repeat("bb", 32)

	port, err := c.SocksOn(hostA, 0)
	if err != nil || port != socksDefaultListen {
		t.Fatalf("默认端口应 %d，got %d %v", socksDefaultListen, port, err)
	}
	if _, err := c.SocksOn(hostA, 0); err != nil { // 同端口幂等
		t.Fatalf("同端口重复 on 应幂等：%v", err)
	}
	st := c.SocksStates()
	if len(st) != 1 || !st[0].On || st[0].Listen != socksDefaultListen {
		t.Fatalf("status 形态：%v", st)
	}
	if err := c.SocksOff(hostA); err != nil {
		t.Fatal(err)
	}
	st = c.SocksStates()
	if st[0].On || st[0].Listen != socksDefaultListen {
		t.Fatalf("off 后应保留端口记忆：%v", st)
	}
	port, err = c.SocksOn(hostA, 0) // 沿用记忆
	if err != nil || port != socksDefaultListen {
		t.Fatalf("on 应沿用记忆端口：%d %v", port, err)
	}
	// 端口值域。
	if _, err := c.SocksOn(hostB, 80); !errors.Is(err, ErrPortRange) {
		t.Fatalf("端口值域外应 ErrPortRange，got %v", err)
	}
}

// TestGlobalPortConflicts 全局端口冲突矩阵：socks×socks 跨主机、socks×forward、
// forward×socks（r1 低-12 同款文案口径——含占用方与另选提示）。
func TestGlobalPortConflicts(t *testing.T) {
	c := openTestCarriers(t, &fakeDial{})
	hostA, hostB := strings.Repeat("aa", 32), strings.Repeat("bb", 32)

	if _, err := c.SocksOn(hostA, 1080); err != nil {
		t.Fatal(err)
	}
	// socks × socks。
	_, err := c.SocksOn(hostB, 1080)
	if !errors.Is(err, ErrPortTaken) || !strings.Contains(err.Error(), "另选") {
		t.Fatalf("socks 跨主机冲突文案不符：%v", err)
	}
	// forward × socks（在监听的）。
	if err := c.AddForward(ForwardRule{Host: hostB, Listen: 1080}); !errors.Is(err, ErrPortTaken) {
		t.Fatalf("forward 撞 socks 应 ErrPortTaken，got %v", err)
	}
	// socks × forward。
	if err := c.AddForward(ForwardRule{Host: hostB, Listen: 1090}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SocksOn(hostA, 1090); !errors.Is(err, ErrPortTaken) {
		t.Fatalf("socks 撞 forward 应 ErrPortTaken，got %v", err)
	}
	// 另选端口成功。
	if p, err := c.SocksOn(hostB, 1081); err != nil || p != 1081 {
		t.Fatalf("另选端口应成功：%d %v", p, err)
	}
}

// TestSocksOffRSTLiveConns 在世连接两分面之二：off 显式关（RST 收口）——off 后
// 在世连接读侧立即收错、不再有代理流量。
func TestSocksOffRSTLiveConns(t *testing.T) {
	up := echoUpstream(t)
	fd := &fakeDial{}
	fd.dialF = func(ctx context.Context, host string, dst netip.AddrPort) (net.Conn, error) {
		var nd net.Dialer
		return nd.DialContext(ctx, "tcp", dst.String())
	}
	fd.dialPortF = func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		if port == socksDNSPort { // 解析腿：直接回 pipe 上的假应答
			clientEnd, serverEnd := net.Pipe()
			go serveDNSOverPipe(serverEnd, func(string) netip.Addr { return up.Addr() }, host)
			return clientEnd, nil
		}
		return nil, errors.New("不应拨其它端口")
	}
	c := openTestCarriers(t, fd)
	host := strings.Repeat("aa", 32)
	if _, err := c.SocksOn(host, 0); err != nil {
		t.Fatal(err)
	}
	conn := miniSocksClient(t, "127.0.0.1:1080", "echo.example", up.Port())
	if conn == nil {
		t.Fatal("CONNECT 应成功")
	}
	waitFor(t, time.Second, func() bool { return c.SocksStates()[0].Conns >= 1 }, "在世连接可观察")

	if err := c.SocksOff(host); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("x")); err == nil {
		buf := make([]byte, 4)
		if _, rerr := conn.Read(buf); rerr == nil {
			t.Fatal("off 后在世连接应被 RST 收口（仍可读写 = 泄漏）")
		}
	}
	_ = conn.Close()
}

// TestSocksCacheIsolationAndTTL 跨出口缓存隔离（r1 中-2）+ TTL 命中免查 + 否定不缓存：
// 两台主机各自首次 CONNECT 同域名 ⇒ 各一次 5300 查询、各用各的应答；同主机 TTL 内
// 二次 CONNECT 免查；NXDOMAIN 不缓存（每次都查）。
func TestSocksCacheIsolationAndTTL(t *testing.T) {
	up := echoUpstream(t)
	ipA := netip.MustParseAddr("203.0.113.101")  // A 出口对该域名的答案
	ipB := netip.MustParseAddr("198.51.100.202") // B 出口的答案（不同——geo/split-horizon）
	var dnsQueries atomic.Int64
	var dialTargets sync.Map
	fd := &fakeDial{}
	fd.dialPortF = func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		if port != socksDNSPort {
			return nil, errors.New("不应拨其它端口")
		}
		dnsQueries.Add(1)
		clientEnd, serverEnd := net.Pipe()
		go serveDNSOverPipe(serverEnd, func(key string) netip.Addr {
			if key == strings.Repeat("aa", 32) {
				return ipA
			}
			return ipB
		}, host)
		return clientEnd, nil
	}
	fd.dialF = func(ctx context.Context, host string, dst netip.AddrPort) (net.Conn, error) {
		dialTargets.Store(host, dst.Addr())
		var nd net.Dialer
		return nd.DialContext(ctx, "tcp", netip.AddrPortFrom(up.Addr(), up.Port()).String()) // 都拨到回显上游（断言解析产物即可）
	}
	c := openTestCarriers(t, fd)
	hostA, hostB := strings.Repeat("aa", 32), strings.Repeat("bb", 32)
	if _, err := c.SocksOn(hostA, 1080); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SocksOn(hostB, 1081); err != nil {
		t.Fatal(err)
	}

	// 各自首次 CONNECT 同域名。
	if miniSocksClient(t, "127.0.0.1:1080", "same.example", up.Port()) == nil {
		t.Fatal("A 应连通")
	}
	if miniSocksClient(t, "127.0.0.1:1081", "same.example", up.Port()) == nil {
		t.Fatal("B 应连通")
	}
	if n := dnsQueries.Load(); n != 2 {
		t.Fatalf("两台各自首次 CONNECT 应各查一次（共 2），实得 %d", n)
	}
	// 各用各的应答（A 连接用 ipA、B 用 ipB——跨出口不串）。
	if v, ok := dialTargets.Load(hostA); !ok || v.(netip.Addr) != ipA {
		t.Fatalf("A 的连接应用 A 出口答案 %v：%v %v", ipA, v, ok)
	}
	if v, ok := dialTargets.Load(hostB); !ok || v.(netip.Addr) != ipB {
		t.Fatalf("B 的连接应用 B 出口答案 %v：%v %v", ipB, v, ok)
	}

	// TTL 内同主机二次 CONNECT：免查（缓存命中）。
	if miniSocksClient(t, "127.0.0.1:1080", "same.example", up.Port()) == nil {
		t.Fatal("缓存命中应连通")
	}
	if n := dnsQueries.Load(); n != 2 {
		t.Fatalf("TTL 内二次 CONNECT 应免查，实得 %d 次查询", n)
	}

	// 否定不缓存：NXDOMAIN 域名两次 CONNECT ⇒ 两次查询。
	fd.dialPortF = func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		dnsQueries.Add(1)
		clientEnd, serverEnd := net.Pipe()
		go serveDNSOverPipe(serverEnd, func(string) netip.Addr { return netip.Addr{} }, host) // 空 = NXDOMAIN
		return clientEnd, nil
	}
	if conn := miniSocksClient(t, "127.0.0.1:1080", "nx.example", up.Port()); conn != nil {
		t.Fatal("NXDOMAIN 应 CONNECT 失败")
	}
	if conn := miniSocksClient(t, "127.0.0.1:1080", "nx.example", up.Port()); conn != nil {
		t.Fatal("NXDOMAIN 应 CONNECT 失败")
	}
	if n := dnsQueries.Load(); n != 4 {
		t.Fatalf("否定不缓存：两次 CONNECT 应两次查询，实得 %d", n)
	}
}

// TestDNSCacheUnit dnsCache 单元：TTL 过期、FIFO 逐出（有界）。
func TestDNSCacheUnit(t *testing.T) {
	c := newDNSCache(2)
	a := []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	c.put("a", a, time.Now().Add(time.Minute))
	c.put("b", a, time.Now().Add(time.Minute))
	if got, ok := c.get("a", time.Now()); !ok || got == nil {
		t.Fatal("a 应命中")
	}
	c.put("c", a, time.Now().Add(time.Minute)) // 逐出最旧 a
	if c.size() != 2 {
		t.Fatalf("有界 2，实得 %d", c.size())
	}
	if _, ok := c.get("a", time.Now()); ok {
		t.Fatal("a 应被 FIFO 逐出")
	}
	if _, ok := c.get("b", time.Now()); !ok {
		t.Fatal("b 应命中")
	}
	// TTL 过期。
	c.put("d", a, time.Now().Add(-time.Second))
	if _, ok := c.get("d", time.Now()); ok {
		t.Fatal("过期条目不应命中")
	}
}

// ---------- speedtest runner ----------

// TestSpeedRunnerRefusedNotWaiting 拨号被拒（refused-like）→ not_supported 且
// MUST NOT 落等待支（r1 高-1①）：waitMs 给足 30s 也必须立即收场。
func TestSpeedRunnerRefusedNotWaiting(t *testing.T) {
	fd := &fakeDial{}
	fd.dialPortF = func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		return nil, fmt.Errorf("wgnet: connect: %w", wgnet.ErrRefused)
	}
	c := openTestCarriers(t, fd)
	host := strings.Repeat("aa", 32)
	ack := c.SpeedtestStart(host, SpeedtestStart{Down: time.Second, Up: time.Second, Warmup: 100 * time.Millisecond, Streams: 1, WaitMs: 30000})
	if ack.Phase != "waiting" {
		t.Fatalf("start 应立即返回 waiting，got %+v", ack)
	}
	t0 := time.Now()
	waitFor(t, 3*time.Second, func() bool {
		st := c.SpeedtestStatus(host)
		return st != nil && !st.Waiting && st.Snap.Reason == speedtest.ReasonNotSupported
	}, "refused-like 应立即 not_supported 收场")
	if el := time.Since(t0); el > 2*time.Second {
		t.Fatalf("refused-like %v 才收场——落进了等待支", el)
	}
}

// TestSpeedRunnerWaitingExpiry link_down 在 waitMs 预算内保持 waiting，到点收场
// link_down（r1 中-3）。
func TestSpeedRunnerWaitingExpiry(t *testing.T) {
	fd := &fakeDial{}
	fd.dialPortF = func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		return nil, ErrSessionNotCurrent // 会话不在/重建窗口
	}
	c := openTestCarriers(t, fd)
	host := strings.Repeat("aa", 32)
	ack := c.SpeedtestStart(host, SpeedtestStart{Down: time.Second, Up: time.Second, WaitMs: 600})
	if ack.Phase != "waiting" {
		t.Fatalf("start 应返回 waiting：%+v", ack)
	}
	waitFor(t, time.Second, func() bool {
		st := c.SpeedtestStatus(host)
		return st != nil && st.Waiting
	}, "预算内应保持 waiting")
	waitFor(t, 3*time.Second, func() bool {
		st := c.SpeedtestStatus(host)
		return st != nil && !st.Waiting && st.Snap.Reason == speedtest.ReasonLinkDown
	}, "到点应 link_down 收场")
}

// TestSpeedRunnerCancelDuringWaiting 取消落在等待期 → cancelled 秒级收场。
func TestSpeedRunnerCancelDuringWaiting(t *testing.T) {
	fd := &fakeDial{}
	fd.dialPortF = func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		<-ctx.Done() // 阻塞到取消
		return nil, ctx.Err()
	}
	c := openTestCarriers(t, fd)
	host := strings.Repeat("aa", 32)
	c.SpeedtestStart(host, SpeedtestStart{Down: time.Second, Up: time.Second, WaitMs: 60000})
	waitFor(t, time.Second, func() bool {
		st := c.SpeedtestStatus(host)
		return st != nil && st.Waiting
	}, "应进入 waiting")
	t0 := time.Now()
	c.SpeedtestCancel(host)
	waitFor(t, 3*time.Second, func() bool {
		st := c.SpeedtestStatus(host)
		return st != nil && !st.Waiting && st.Snap.Reason == speedtest.ReasonCancelled
	}, "取消应 cancelled 收场")
	if el := time.Since(t0); el > 2*time.Second {
		t.Fatalf("取消 %v 才收场，应秒级", el)
	}
}

// TestSpeedRunnerFullAndSingleFlight 真引擎全轮（真 speedtest 服务）+ per-host 单飞。
func TestSpeedRunnerFullAndSingleFlight(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	srv := speedtest.NewServer(nil)
	srv.SetLimits(speedtest.Limits{ConnTimeout: 20 * time.Second})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })
	fd := &fakeDial{}
	fd.dialPortF = func(ctx context.Context, host string, p uint16) (net.Conn, error) {
		if p != speedtestServicePort {
			return nil, fmt.Errorf("测速只拨 %d，got %d", speedtestServicePort, p)
		}
		var nd net.Dialer
		return nd.DialContext(ctx, "tcp", ln.Addr().String())
	}
	c := openTestCarriers(t, fd)
	host := strings.Repeat("aa", 32)
	ack := c.SpeedtestStart(host, SpeedtestStart{Down: 3 * time.Second, Up: 2 * time.Second, Warmup: 100 * time.Millisecond, Streams: 1, WaitMs: 0})
	if ack.Phase != "waiting" {
		t.Fatalf("start 应返回 waiting：%+v", ack)
	}
	// 引擎开跑（离开 waiting、进入 down 相位）后：running 中再 start = busy（成功载荷
	// reason，不占错误码）。
	waitFor(t, 3*time.Second, func() bool {
		st := c.SpeedtestStatus(host)
		return st != nil && !st.Waiting && (st.Snap.Phase == string(speedtest.PhaseDown) || st.Snap.Phase == string(speedtest.PhaseConnecting))
	}, "应进入引擎运行相位")
	if ack := c.SpeedtestStart(host, SpeedtestStart{WaitMs: 0}); ack.Phase != "busy" {
		t.Fatalf("running 中再 start 应 busy：%+v", ack)
	}
	c.SpeedtestCancel(host)
	waitFor(t, 3*time.Second, func() bool {
		st := c.SpeedtestStatus(host)
		return st != nil && !st.Waiting && st.Snap.Phase == string(speedtest.PhaseCancelled)
	}, "取消应 cancelled 收场")
	// 终态让位后可再跑（不 busy）。cancelled 相位先于 running=false 落面——轮询让位。
	var relaunch SpeedtestStartAck
	waitFor(t, 3*time.Second, func() bool {
		relaunch = c.SpeedtestStart(host, SpeedtestStart{WaitMs: 0})
		return relaunch.Phase == "waiting"
	}, "终态让位后应可再跑")
	c.SpeedtestCancel(host)
}

// ---------- 级联删除 ----------

// TestRemoveHostCascade host.remove 级联：forward 规则消失（磁盘+内存）、socks 记忆
// 消失、监听关闭；重新打开不复活。
func TestRemoveHostCascade(t *testing.T) {
	dir := t.TempDir()
	up := echoUpstream(t)
	dp, dd := dialUp()
	fd := &fakeDial{dialPortF: dp, dialF: dd}
	c, err := openCarriers(dir, carrierDial{dialPort: fd.dialPort, dial: fd.dial}, discardLogf, discardLogf)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	hostA, hostB := strings.Repeat("aa", 32), strings.Repeat("bb", 32)
	listenA, listenB := freePort(t), freePort(t)
	if err := c.AddForward(ForwardRule{Host: hostA, Listen: listenA, TargetPort: up.Port()}); err != nil {
		t.Fatal(err)
	}
	if err := c.AddForward(ForwardRule{Host: hostB, Listen: listenB, TargetPort: up.Port()}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SocksOn(hostA, 1080); err != nil {
		t.Fatal(err)
	}

	var id [32]byte
	if b, derr := hex.DecodeString(hostA); derr != nil || len(b) != 32 {
		t.Fatalf("hostA 应为 64 位 hex：%v", derr)
	} else {
		copy(id[:], b)
	}
	c.RemoveHost(id)

	if got := c.ForwardStates(hostA); len(got) != 0 {
		t.Fatalf("hostA forward 应级联清空：%v", got)
	}
	if got := c.ForwardStates(hostB); len(got) != 1 {
		t.Fatalf("hostB 不受波及：%v", got)
	}
	for _, st := range c.SocksStates() {
		if st.Host == hostA {
			t.Fatal("hostA socks 记忆应级联消失")
		}
	}
	// 监听关闭：连不上。
	if _, err := net.DialTimeout("tcp", "127.0.0.1:1080", 300*time.Millisecond); err == nil {
		t.Fatal("socks 监听应已关")
	}
	// 磁盘同步：hostA 的 forward 规则不在 forwards.json。
	b, _ := os.ReadFile(filepath.Join(dir, forwardsFileName))
	if strings.Contains(string(b), hostA) {
		t.Fatal("forwards.json 不应再含 hostA")
	}
	if !strings.Contains(string(b), hostB) {
		t.Fatal("forwards.json 应保留 hostB")
	}
	// 重新打开不复活。
	c.Close()
	c2, err := openCarriers(dir, carrierDial{dialPort: fd.dialPort, dial: fd.dial}, discardLogf, discardLogf)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if got := c2.ForwardStates(""); len(got) != 1 || got[0].Rule.Host != hostB {
		t.Fatalf("重开应只剩 hostB：%v", got)
	}
}

// TestSocksPersistenceRebuild socks.json 重启重建：on 条目恢复监听、off 条目保持 off。
func TestSocksPersistenceRebuild(t *testing.T) {
	dir := t.TempDir()
	up := echoUpstream(t)
	fd := &fakeDial{}
	fd.dialF = func(ctx context.Context, host string, dst netip.AddrPort) (net.Conn, error) {
		var nd net.Dialer
		return nd.DialContext(ctx, "tcp", dst.String())
	}
	fd.dialPortF = func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		clientEnd, serverEnd := net.Pipe()
		go serveDNSOverPipe(serverEnd, func(string) netip.Addr { return up.Addr() }, host)
		return clientEnd, nil
	}
	mk := func() *Carriers {
		c, err := openCarriers(dir, carrierDial{dialPort: fd.dialPort, dial: fd.dial}, discardLogf, discardLogf)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	hostA, hostB := strings.Repeat("aa", 32), strings.Repeat("bb", 32)
	c1 := mk()
	if _, err := c1.SocksOn(hostA, 1080); err != nil {
		t.Fatal(err)
	}
	if _, err := c1.SocksOn(hostB, 1081); err != nil {
		t.Fatal(err)
	}
	if err := c1.SocksOff(hostB); err != nil { // B off（记忆 1081）
		t.Fatal(err)
	}
	c1.Close()

	c2 := mk()
	defer c2.Close()
	st := c2.SocksStates()
	if len(st) != 2 {
		t.Fatalf("重建应 2 条：%v", st)
	}
	for _, e := range st {
		if e.Host == hostA && (!e.On || e.Listen != 1080) {
			t.Fatalf("A 应恢复监听：%v", e)
		}
		if e.Host == hostB && (e.On || e.Listen != 1081) {
			t.Fatalf("B 应保持 off 且记忆端口：%v", e)
		}
	}
	// A 的监听真实可用。
	if miniSocksClient(t, "127.0.0.1:1080", "echo.example", up.Port()) == nil {
		t.Fatal("重建后 A 的 socks 应可用")
	}
	// 重建后 json 内容自洽（不含测试残留字段以外的内容）。
	b, _ := os.ReadFile(filepath.Join(dir, socksFileName))
	var recs []SocksEntry
	if err := json.Unmarshal(b, &recs); err != nil || len(recs) != 2 {
		t.Fatalf("socks.json 形态：%v %s", err, b)
	}
}
