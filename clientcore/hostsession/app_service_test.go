//go:build !cshared

// app_service_test.go — 服务会话状态机（openspec app-service-session 任务 2.2）：
// 起停生命周期、starting 中取消（同钥匙不双发的关键路径）、失败终态与幂等。
// （随迁自 cshared package main，host-registry-daemon D8 账本·重接线 10 之一；
// 接线变化（r3 订正口径——断言集合/语义逐条不变）：入口 serviceStartFromJSON/
// StatusJSON/StopInternal → 包内 Default() API；bridgeAuth/reason/waitServiceState
// 改读 StatusSnapshot；桥断言改由注入的假桥工厂供给等价值。）
package hostsession

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/internal/wtransport"
)

// fakeExitSession 可编排的假会话：probe 行为可注入，Close 被记录。
type fakeExitSession struct {
	probe   func(ctx context.Context) error
	dialTCP func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) // 3e §2.1：DialAddr 用例注入
	closed  chan struct{}
	closeAt time.Time
}

func newFakeExitSession() *fakeExitSession {
	return &fakeExitSession{closed: make(chan struct{})}
}

func (f *fakeExitSession) DialTCPPort(ctx context.Context, port uint16) (net.Conn, error) {
	c1, c2 := net.Pipe()
	go func() {
		buf := make([]byte, 256)
		for {
			if _, err := c2.Read(buf); err != nil {
				return
			}
		}
	}()
	return c1, nil
}

func (f *fakeExitSession) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if f.dialTCP != nil {
		return f.dialTCP(ctx, dst)
	}
	return f.DialTCPPort(ctx, 1)
}

func (f *fakeExitSession) PathProbe(ctx context.Context) error {
	if f.probe == nil {
		return nil
	}
	return f.probe(ctx)
}

func (f *fakeExitSession) ServerTunnelIP() netip.Addr {
	return netip.MustParseAddr("100.64.255.1") // 常量契约（与 wgcore 兜底一致）
}

func (f *fakeExitSession) Close() error {
	f.closeAt = time.Now()
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return nil
}

var errFakeNotImpl = errors.New("fake: not implemented")

// withFakeServiceBuild 注入假 builder（并返回恢复函数）。
func withFakeServiceBuild(b sessionBuilder) func() {
	old := sessionBuild
	sessionBuild = b
	return func() { sessionBuild = old }
}

// fakeBridge 假回环桥（重接线：桥断言改由注入的假桥工厂供给等价值——96 hex 的
// 鉴权 blob 与三座 sock 路径，形状与真桥一致）。
type fakeBridge struct {
	started bool
	stopped bool
}

func (b *fakeBridge) Start() { b.started = true }
func (b *fakeBridge) Stop()  { b.stopped = true }
func (b *fakeBridge) AuthHex() string {
	// 16B 魔数 + 32B 令牌 = 48B → 96 hex 字符（真桥同长度）。
	return fmt.Sprintf("%032x%064x", 1, 2)
}
func (b *fakeBridge) SockJSON() (string, string, string) {
	return "files.sock", "term.sock", "speed.sock"
}

// resetService 测试收尾：停掉全局实例，回到干净状态。
func resetService(t *testing.T) {
	t.Helper()
	if rc := Default().Stop(); rc != 0 {
		t.Logf("收尾 stop 返回 %d（重试一次）", rc)
		_ = Default().Stop()
	}
	Default().reset()
}

// waitServiceState 轮询等状态（上限 3s）——改读 StatusSnapshot（r3：断言语义不变）。
func waitServiceState(t *testing.T, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if Default().Snapshot().State == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("3s 内未到状态 %q（当前 %s）", want, Default().Snapshot().State)
}

func serviceTestConfig(t *testing.T) Config {
	t.Helper()
	// identityDir：桥目录由其父目录推得（app-bridge-uds）——测试给短目录，
	// 避免 macOS 临时路径叠测试名顶过 sun_path 上限（源定义留守 cshared
	// app_bridge_test.go；本包测试保留同款副本，r4 口径）。
	return Config{Token: "hmw1-test", IdentityDir: filepath.Join(shortBridgeDir(t), "identity")}
}

// shortBridgeDir 每用例独立的桥目录：名字刻意短——macOS 的 t.TempDir() 路径带着
// 长测试名，叠上 /bridge/xxx.sock 后会顶过 sun_path 的 104 字节上限（bind 报
// invalid argument），2026-09-22 踩过。源定义留守 cshared（桥 11 例仍用），
// 本包测试保留同款副本（r4：源定义留守 + hostsession 测试包同款副本）。
func shortBridgeDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "br")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// 起停生命周期：start → ready（bridgeAuth 可见）→ stop → idle，会话被关。
func TestServiceLifecycle(t *testing.T) {
	fb := &fakeBridge{}
	restore := withFakeServiceBuild(func(cfg Config, logf Logf) (ExitSession, *wtransport.EndpointCache, error) {
		return newFakeExitSession(), nil, nil
	})
	defer restore()
	defer resetService(t)

	if rc := Default().Start(serviceTestConfig(t), Options{BridgeFactory: func(cfg Config, logf Logf, dial func(ctx context.Context, port uint16) (net.Conn, error), dialTimeout time.Duration) Bridge {
		return fb
	}}); rc != 0 {
		t.Fatalf("start rc=%d", rc)
	}
	waitServiceState(t, svcStateReady)
	if !fb.started {
		t.Fatal("假桥未被 Start（工厂注入未生效）")
	}

	// 状态面（改读 StatusSnapshot，r3）：bridgeAuth 存在且 96 hex 字符；
	// identity/link 缺省（假会话不是 newSession）。
	st := Default().Snapshot()
	if len(st.BridgeAuth) != 96 {
		t.Fatalf("bridgeAuth 长度 %d ≠ 96", len(st.BridgeAuth))
	}
	if st.BridgeFilesSock == "" || st.BridgeTermSock == "" || st.BridgeSpeedSock == "" {
		t.Fatalf("三座桥 sock 缺省：%+v", st)
	}
	if st.Link != nil || st.Identity != nil || st.Stats != nil {
		t.Fatalf("假会话不应有 link/identity/stats：%+v", st)
	}

	if rc := Default().Stop(); rc != 0 {
		t.Fatalf("stop rc=%d", rc)
	}
	waitServiceState(t, svcStateIdle)
	if !fb.stopped {
		t.Fatal("收工后假桥未被 Stop")
	}
}

// starting 中 stop：探测挂起直到取消；stop 快速收工、会话被关（同钥匙不双发的关键路径）。
func TestServiceStopDuringStarting(t *testing.T) {
	fake := newFakeExitSession()
	fake.probe = func(ctx context.Context) error {
		<-ctx.Done() // 挂起等取消（模拟探测在途收到停止请求）
		return ctx.Err()
	}
	restore := withFakeServiceBuild(func(cfg Config, logf Logf) (ExitSession, *wtransport.EndpointCache, error) {
		return fake, nil, nil
	})
	defer restore()
	defer resetService(t)

	if rc := Default().Start(serviceTestConfig(t), Options{}); rc != 0 {
		t.Fatalf("start rc=%d", rc)
	}
	begin := time.Now()
	if rc := Default().Stop(); rc != 0 {
		t.Fatalf("stop rc=%d", rc)
	}
	if d := time.Since(begin); d > serviceStopWait {
		t.Fatalf("stop 用时 %v 超预算", d)
	}
	waitServiceState(t, svcStateIdle)
	select {
	case <-fake.closed:
	default:
		t.Fatal("stop 后假会话未被 Close")
	}
}

// 构造失败：state=failed、reason 非空、可被 stop 归位。
func TestServiceBuildFailure(t *testing.T) {
	restore := withFakeServiceBuild(func(cfg Config, logf Logf) (ExitSession, *wtransport.EndpointCache, error) {
		return nil, nil, errFakeNotImpl
	})
	defer restore()
	defer resetService(t)

	if rc := Default().Start(serviceTestConfig(t), Options{}); rc != 0 {
		t.Fatalf("start rc=%d", rc)
	}
	waitServiceState(t, svcStateFailed)
	if st := Default().Snapshot(); st.Reason == "" {
		t.Fatal("failed 态缺 reason")
	}
	if rc := Default().Stop(); rc != 0 {
		t.Fatalf("stop rc=%d", rc)
	}
	// failed 实例 stop 后仍是 failed（保留归因）；再次 start 可替换重试（见下一测试）。
}

// failed 后重试成功（Start 可替换失败实例）。
func TestServiceRetryAfterFailure(t *testing.T) {
	fail := true
	restore := withFakeServiceBuild(func(cfg Config, logf Logf) (ExitSession, *wtransport.EndpointCache, error) {
		if fail {
			fail = false
			return nil, nil, errFakeNotImpl
		}
		return newFakeExitSession(), nil, nil
	})
	defer restore()
	defer resetService(t)

	if rc := Default().Start(serviceTestConfig(t), Options{}); rc != 0 {
		t.Fatalf("start rc=%d", rc)
	}
	waitServiceState(t, svcStateFailed)
	_ = Default().Stop()
	time.Sleep(50 * time.Millisecond) // 等 done 关闭（failed 后 goroutine 即将退出）
	if rc := Default().Start(serviceTestConfig(t), Options{}); rc != 0 {
		t.Fatalf("重试 start rc=%d", rc)
	}
	waitServiceState(t, svcStateReady)
}

// 幂等：ready 下重复 start 返回 0 且不换实例。
func TestServiceStartIdempotent(t *testing.T) {
	restore := withFakeServiceBuild(func(cfg Config, logf Logf) (ExitSession, *wtransport.EndpointCache, error) {
		return newFakeExitSession(), nil, nil
	})
	defer restore()
	defer resetService(t)

	if rc := Default().Start(serviceTestConfig(t), Options{}); rc != 0 {
		t.Fatalf("start rc=%d", rc)
	}
	waitServiceState(t, svcStateReady)
	if rc := Default().Start(serviceTestConfig(t), Options{}); rc != 0 {
		t.Fatalf("重复 start rc=%d（应幂等 0）", rc)
	}
	waitServiceState(t, svcStateReady)
}

// 收工落盘（任务 2.4 判据）：Observe/NoteFailure 只改内存，finish 必须把未保存变更
// Save 出去 —— 否则隧道会话接手时读到的是半新半旧的缓存。
func TestServiceFinishSavesCache(t *testing.T) {
	dir := t.TempDir()
	var peerID [32]byte
	for i := range peerID {
		peerID[i] = byte(i)
	}
	cache := wtransport.OpenEndpointCache(dir, peerID)
	cache.SetLogger(Discard)
	ap := netip.MustParseAddrPort("127.0.0.1:41641")
	cache.Observe(ap, wtransport.SourceHint, time.Now())

	s := &Session{
		state:  svcStateReady,
		since:  time.Now(),
		stopCh: make(chan struct{}),
		done:   make(chan struct{}),
		logf:   Discard,
		cache:  cache,
	}
	s.finish(svcStateIdle, "已收工")

	// 重新打开缓存：Observe 的变更必须在盘上。
	cache2 := wtransport.OpenEndpointCache(dir, peerID)
	entries := cache2.Entries(time.Now())
	found := false
	for _, e := range entries {
		if e.Addr == ap {
			found = true
		}
	}
	if !found {
		t.Fatalf("finish 后缓存未落盘（目录 %s，条目 %v）", dir, entries)
	}
}

// TestSessionDialAddr（3e §2.1）：任意目标拨号缝——dst 原样透传到当代会话的
// DialTCP；会话不在（收工/重建窗口）= ErrSessionNotCurrent（与 DialPort 同语义）。
func TestSessionDialAddr(t *testing.T) {
	dst := netip.MustParseAddrPort("192.168.3.5:5000")
	var gotDst netip.AddrPort
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	f := newFakeExitSession()
	f.dialTCP = func(ctx context.Context, d netip.AddrPort) (net.Conn, error) {
		gotDst = d
		return c1, nil
	}
	s := &Session{state: svcStateReady, since: time.Now(), stopCh: make(chan struct{}), done: make(chan struct{}), logf: Discard}
	s.mu.Lock()
	s.sess = f
	s.mu.Unlock()
	conn, err := s.DialAddr(context.Background(), dst)
	if err != nil {
		t.Fatalf("DialAddr: %v", err)
	}
	if conn != c1 {
		t.Fatal("应返回会话拨号产物")
	}
	if gotDst != dst {
		t.Fatalf("dst 应原样透传，实得 %v", gotDst)
	}

	// 会话不在：ErrSessionNotCurrent。
	s2 := &Session{state: svcStateReady, since: time.Now(), stopCh: make(chan struct{}), done: make(chan struct{}), logf: Discard}
	if _, err := s2.DialAddr(context.Background(), dst); !errors.Is(err, ErrSessionNotCurrent) {
		t.Fatalf("会话不在应 ErrSessionNotCurrent，实得 %v", err)
	}
}
