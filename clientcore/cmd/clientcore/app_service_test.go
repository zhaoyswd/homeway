//go:build cshared

// app_service_test.go — 服务会话状态机（openspec app-service-session 任务 2.2）：
// 起停生命周期、starting 中取消（同钥匙不双发的关键路径）、失败终态与幂等。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/internal/wtransport"
	"path/filepath"
)

// fakeExitSession 可编排的假会话：probe 行为可注入，Close 被记录。
type fakeExitSession struct {
	probe   func(ctx context.Context) error
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
func withFakeServiceBuild(b serviceBuilder) func() {
	old := serviceBuild
	serviceBuild = b
	return func() { serviceBuild = old }
}

// resetService 测试收尾：停掉全局实例，回到干净状态。
func resetService(t *testing.T) {
	t.Helper()
	if rc := serviceStopInternal(); rc != 0 {
		t.Logf("收尾 stop 返回 %d（重试一次）", rc)
		_ = serviceStopInternal()
	}
	serviceMu.Lock()
	serviceCur = nil
	serviceMu.Unlock()
}

// waitServiceState 轮询等状态（上限 3s）。
func waitServiceState(t *testing.T, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var st struct {
			State string `json:"state"`
		}
		if err := json.Unmarshal([]byte(serviceStatusJSON()), &st); err == nil && st.State == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("3s 内未到状态 %q（当前 %s）", want, serviceStatusJSON())
}

func serviceTestConfig(t *testing.T) string {
	t.Helper()
	// identityDir：桥目录由其父目录推得（app-bridge-uds）——测试给短目录，
	// 避免 macOS 临时路径叠测试名顶过 sun_path 上限（见 app_bridge_test.go 注）。
	return fmt.Sprintf(`{"token":"hmw1-test","out":"","identityDir":%q}`, filepath.Join(shortBridgeDir(t), "identity"))
}

// 起停生命周期：start → ready（bridgeAuth 可见）→ stop → idle，会话被关。
func TestServiceLifecycle(t *testing.T) {
	restore := withFakeServiceBuild(func(cfg tunConfig, logf Logf) (exitSession, *wtransport.EndpointCache, error) {
		return newFakeExitSession(), nil, nil
	})
	defer restore()
	defer resetService(t)

	if rc := serviceStartFromJSON(serviceTestConfig(t)); rc != 0 {
		t.Fatalf("start rc=%d", rc)
	}
	waitServiceState(t, svcStateReady)

	// 状态面：bridgeAuth 存在且 96 hex 字符；identity/link 缺省（假会话不是 newSession）。
	var st struct {
		BridgeAuth string `json:"bridgeAuth"`
	}
	if err := json.Unmarshal([]byte(serviceStatusJSON()), &st); err != nil {
		t.Fatalf("status JSON 解析失败：%v", err)
	}
	if len(st.BridgeAuth) != 96 {
		t.Fatalf("bridgeAuth 长度 %d ≠ 96", len(st.BridgeAuth))
	}

	if rc := serviceStopInternal(); rc != 0 {
		t.Fatalf("stop rc=%d", rc)
	}
	waitServiceState(t, svcStateIdle)
}

// starting 中 stop：探测挂起直到取消；stop 快速收工、会话被关（同钥匙不双发的关键路径）。
func TestServiceStopDuringStarting(t *testing.T) {
	fake := newFakeExitSession()
	fake.probe = func(ctx context.Context) error {
		<-ctx.Done() // 挂起等取消（模拟探测在途收到停止请求）
		return ctx.Err()
	}
	restore := withFakeServiceBuild(func(cfg tunConfig, logf Logf) (exitSession, *wtransport.EndpointCache, error) {
		return fake, nil, nil
	})
	defer restore()
	defer resetService(t)

	if rc := serviceStartFromJSON(serviceTestConfig(t)); rc != 0 {
		t.Fatalf("start rc=%d", rc)
	}
	begin := time.Now()
	if rc := serviceStopInternal(); rc != 0 {
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
	restore := withFakeServiceBuild(func(cfg tunConfig, logf Logf) (exitSession, *wtransport.EndpointCache, error) {
		return nil, nil, errFakeNotImpl
	})
	defer restore()
	defer resetService(t)

	if rc := serviceStartFromJSON(serviceTestConfig(t)); rc != 0 {
		t.Fatalf("start rc=%d", rc)
	}
	waitServiceState(t, svcStateFailed)
	var st struct {
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal([]byte(serviceStatusJSON()), &st)
	if st.Reason == "" {
		t.Fatal("failed 态缺 reason")
	}
	if rc := serviceStopInternal(); rc != 0 {
		t.Fatalf("stop rc=%d", rc)
	}
	// failed 实例 stop 后仍是 failed（保留归因）；再次 start 可替换重试（见下一测试）。
}

// failed 后重试成功（Start 可替换失败实例）。
func TestServiceRetryAfterFailure(t *testing.T) {
	fail := true
	restore := withFakeServiceBuild(func(cfg tunConfig, logf Logf) (exitSession, *wtransport.EndpointCache, error) {
		if fail {
			fail = false
			return nil, nil, errFakeNotImpl
		}
		return newFakeExitSession(), nil, nil
	})
	defer restore()
	defer resetService(t)

	if rc := serviceStartFromJSON(serviceTestConfig(t)); rc != 0 {
		t.Fatalf("start rc=%d", rc)
	}
	waitServiceState(t, svcStateFailed)
	_ = serviceStopInternal()
	time.Sleep(50 * time.Millisecond) // 等 done 关闭（failed 后 goroutine 即将退出）
	if rc := serviceStartFromJSON(serviceTestConfig(t)); rc != 0 {
		t.Fatalf("重试 start rc=%d", rc)
	}
	waitServiceState(t, svcStateReady)
}

// 幂等：ready 下重复 start 返回 0 且不换实例。
func TestServiceStartIdempotent(t *testing.T) {
	restore := withFakeServiceBuild(func(cfg tunConfig, logf Logf) (exitSession, *wtransport.EndpointCache, error) {
		return newFakeExitSession(), nil, nil
	})
	defer restore()
	defer resetService(t)

	if rc := serviceStartFromJSON(serviceTestConfig(t)); rc != 0 {
		t.Fatalf("start rc=%d", rc)
	}
	waitServiceState(t, svcStateReady)
	if rc := serviceStartFromJSON(serviceTestConfig(t)); rc != 0 {
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

	s := &serviceSession{
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
