package control

// server_test.go — §3.2/§3.3 服务器层单测（Go 客户端驱动 = 真实消费者路径；
// 握手场景另做原始字节断言）。fakeBackend 假宿主 + 假 term 后端（TCP listener）。

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zhaoyswd/homeway/clientcore/facade"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeBackend 假宿主（§3 测试用）。
type fakeBackend struct {
	mu       sync.Mutex
	notReady bool
	briefs   []HostBrief
	states   []HostState
	roles    []RoleBrief
	added    map[string]string // id -> token
	dialErr  map[string]error
	dialAddr string // DialTerm 实际拨的地址（假 term 后端）
	dials    int
	// L2 用例的慢请求注入（4a §5.1）：blockAddEntered 非 nil 时 AddHost 进入即
	// 向其发信号并阻塞到 blockAddRelease 关闭（假 Backend 的 entered 同步点）。
	blockAddEntered chan struct{}
	blockAddRelease chan struct{}
	// L2 用例的慢拨号注入（4a §5.1 r2 新-6）：dialEntered 非 nil 时 DialTerm
	// 进入即发信号并阻塞到 dialRelease 关闭（stream.open 独立执行体判据）。
	dialEntered chan struct{}
	dialRelease chan struct{}
	// pipe 模式的对端持有（从不读；防 GC 关闭 pipe 使写立即失败）。
	pipePeers []net.Conn
	// pipe 模式的对端慢排空节拍（>0 = 对端按此间隔慢慢读——「慢读但活着」形态；
	// 0 = 永不读）。pipeDrained = 慢排空累计收到的字节数（「数据完整到达后端」判据）。
	pipeDrainEvery time.Duration
	pipeDrained    atomic.Int64
	// demand 段注入（4a §6.2 用例）。
	demand []HostDemandBrief
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{added: map[string]string{}, dialErr: map[string]error{}}
}

// pipeDialAddr 特殊 dialAddr：DialTerm 返回无缓冲 net.Pipe（对端存 pipePeers、
// 从不读——「后端不读」形态的**确定性**载体，规避 TCP 内核缓冲/自调优在 localhost
// 上仍快速排空的不确定窗口，4a §5.3 用例）。
const pipeDialAddr = "\x00pipe"

// blockAdd 注入 AddHost 阻塞（entered 同步点 + release 放行）。
func (f *fakeBackend) blockAdd() (entered, release chan struct{}) {
	entered = make(chan struct{}, 64)
	release = make(chan struct{})
	f.mu.Lock()
	f.blockAddEntered, f.blockAddRelease = entered, release
	f.mu.Unlock()
	return
}

// blockDial 注入 DialTerm 阻塞（entered 同步点 + release 放行）。
func (f *fakeBackend) blockDial() (entered, release chan struct{}) {
	entered = make(chan struct{}, 64)
	release = make(chan struct{})
	f.mu.Lock()
	f.dialEntered, f.dialRelease = entered, release
	f.mu.Unlock()
	return
}

func (f *fakeBackend) ServerVersion() string { return "test-1.0" }
func (f *fakeBackend) RolesStatus() []RoleBrief {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.roles
}
func (f *fakeBackend) HostBriefs() []HostBrief {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]HostBrief(nil), f.briefs...)
}
func (f *fakeBackend) AddHost(name, token string, force bool) (HostAddResult, error) {
	f.mu.Lock()
	entered, release := f.blockAddEntered, f.blockAddRelease
	f.mu.Unlock()
	if entered != nil {
		entered <- struct{}{}
		<-release
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.HasPrefix(token, "BAD") {
		return HostAddResult{}, ErrBackendBadToken
	}
	if strings.HasPrefix(token, "DEAD") && !force {
		return HostAddResult{}, ErrBackendHostUnreachable // host-cli 3b：全不可达（force 不触发）
	}
	id := fmt.Sprintf("%064x", len(f.added)+1)
	if _, ok := f.added[id]; ok || token == "DUP" {
		return HostAddResult{}, ErrBackendHostExists
	}
	f.added[id] = token
	b := HostBrief{ID: id, Name: name, AddedAt: 1700000000}
	f.briefs = append(f.briefs, b)
	res := HostAddResult{ID: id, Name: name, AddedAt: 1700000000}
	if force {
		res.Reach = &HostReach{Tier: facade.ReachTierSkipped, Tested: []ReachTested{}}
	} else {
		res.Reach = &HostReach{Tier: facade.ReachTierDirect, BestEp: "203.0.113.1:41641", RttMs: 12, Tested: []ReachTested{{Ep: "203.0.113.1:41641", RttMs: 12}}}
	}
	return res, nil
}
func (f *fakeBackend) RemoveHost(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.added[id]; !ok {
		return ErrBackendNoHost
	}
	delete(f.added, id)
	for i, b := range f.briefs {
		if b.ID == id {
			f.briefs = append(f.briefs[:i], f.briefs[i+1:]...)
			break
		}
	}
	return nil
}
func (f *fakeBackend) HostStates() []HostState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]HostState(nil), f.states...)
}
func (f *fakeBackend) DialTerm(ctx context.Context, host string) (net.Conn, error) {
	f.mu.Lock()
	f.dials++
	err := f.dialErr[host]
	addr := f.dialAddr
	entered, release := f.dialEntered, f.dialRelease
	f.mu.Unlock()
	if entered != nil {
		entered <- struct{}{}
		<-release
	}
	if err != nil {
		return nil, err
	}
	if addr == pipeDialAddr {
		c1, c2 := net.Pipe()
		f.mu.Lock()
		f.pipePeers = append(f.pipePeers, c2)
		every := f.pipeDrainEvery
		f.mu.Unlock()
		if every > 0 {
			go func() { // 慢排空：按节拍读（读到的字节即「已到达后端」；EOF 即止）
				buf := make([]byte, 64<<10)
				for {
					n, err := c2.Read(buf)
					if n > 0 {
						f.pipeDrained.Add(int64(n))
					}
					if err != nil {
						return
					}
					time.Sleep(every)
				}
			}()
		}
		return c1, nil
	}
	if addr == "" {
		return nil, ErrBackendNoSession
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}
func (f *fakeBackend) NotReady() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.notReady
}

func (f *fakeBackend) DemandStatus() []HostDemandBrief {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]HostDemandBrief(nil), f.demand...)
}

// testServer 一套装配好的服务器（临时 state + bus + backend + 假 term 后端）。
type testServer struct {
	dir     string
	sock    string
	bus     *facade.Bus
	backend *fakeBackend
	srv     *Server
	termLn  net.Listener
	t       *testing.T
}

// shortTempDir 短路径临时目录（t.TempDir() 在 macOS 的 /var/folders 路径会超
// sockaddr_un 上限）。
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ctl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func startTestServer(t *testing.T, busCfg facade.BusConfig) *testServer {
	t.Helper()
	dir := shortTempDir(t)
	bus := facade.NewBus(facade.NewGeneration(), busCfg)
	backend := newFakeBackend()
	// 假 term 后端：一条 TCP listener（echo 模式由各测试自定）。
	termLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	backend.dialAddr = termLn.Addr().String()
	srv := NewServer(ServerConfig{ServerVersion: "test-1.0", Bus: bus, Backend: backend, Logf: t.Logf})
	sock, ln, err := ListenControl(dir)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	ts := &testServer{dir: dir, sock: sock, bus: bus, backend: backend, srv: srv, termLn: termLn, t: t}
	t.Cleanup(func() {
		srv.Close()
		_ = termLn.Close()
	})
	return ts
}

func dialTest(t *testing.T, ts *testServer) (*Client, *WelcomeBody) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, w, err := Dial(ctx, ts.sock, FrontendInfo{Kind: "cli", Name: "test", Version: "0"})
	if err != nil {
		t.Fatalf("客户端握手失败：%v", err)
	}
	t.Cleanup(c.Close)
	return c, w
}

// ---------- §3.2 握手（原始字节断言） ----------

// readFrameRaw 原始读一帧（字节断言用）。
func readFrameRaw(t *testing.T, r *bufio.Reader) (byte, []byte) {
	t.Helper()
	head := make([]byte, 5)
	if _, err := io.ReadFull(r, head); err != nil {
		t.Fatalf("读帧头失败：%v", err)
	}
	n := int(head[1])<<24 | int(head[2])<<16 | int(head[3])<<8 | int(head[4])
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		t.Fatalf("读 body 失败：%v", err)
	}
	return head[0], body
}

func TestHandshakeWelcomeBytes(t *testing.T) {
	ts := startTestServer(t, facade.BusConfig{})
	nc, err := net.Dial("unix", ts.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	// hello：手拼 JSON（字节级控制）。
	hello := `{"protoVersion":1,"frontend":{"kind":"cli","name":"raw","version":"9.9"}}`
	if _, err := nc.Write(EncodeFrame(OpHello, []byte(hello))); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(nc)
	op, body := readFrameRaw(t, r)
	if op != OpWelcome {
		t.Fatalf("首帧应为 welcome(0x02)，得到 0x%02x", op)
	}
	var w WelcomeBody
	if err := json.Unmarshal(body, &w); err != nil {
		t.Fatalf("welcome JSON：%v（%s）", err, body)
	}
	if w.ServerVersion != "test-1.0" {
		t.Fatalf("serverVersion=%s", w.ServerVersion)
	}
	if _, err := hex.DecodeString(w.Generation); err != nil || len(w.Generation) != 32 {
		t.Fatalf("generation 应为 16 字节 hex：%q", w.Generation)
	}
	if w.Generation != ts.bus.Generation() {
		t.Fatalf("welcome.generation 应等于总线代际")
	}
}

func TestHandshakeProtoMismatchReloadThenClose(t *testing.T) {
	ts := startTestServer(t, facade.BusConfig{})
	nc, err := net.Dial("unix", ts.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	hello := `{"protoVersion":2,"frontend":{"kind":"cli","name":"raw","version":"0"}}`
	if _, err := nc.Write(EncodeFrame(OpHello, []byte(hello))); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(nc)
	op, body := readFrameRaw(t, r)
	if op != OpReload {
		t.Fatalf("版本不匹配应回 reload，得到 0x%02x", op)
	}
	var rl ReloadBody
	if err := json.Unmarshal(body, &rl); err != nil || rl.Reason != ReloadProtoMismatch {
		t.Fatalf("reload 原因应为 proto_mismatch：%v（%s）", err, body)
	}
	// reload 后连接被关闭：读到 EOF。
	if _, err := r.ReadByte(); err != io.EOF {
		t.Fatalf("reload 后应关闭连接，读到 %v", err)
	}
}

func TestHandshakeGenerationCursorStale(t *testing.T) {
	// 代际失配三场景之三：握手成功（新代际）但订阅带旧代际游标 → cursor_stale。
	ts := startTestServer(t, facade.BusConfig{})
	c, _ := dialTest(t, ts)
	if _, err := c.Subscribe(context.Background(), []string{facade.DomainSession}, nil, "", "gen-old"); !errors.Is(err, CodeError(facade.CodeCursorStale)) {
		t.Fatalf("旧代际订阅应 cursor_stale，得到 %v", err)
	}
	// 连接仍可用（不断连）。
	if _, err := c.Request(context.Background(), facade.OpHostList, nil); err != nil {
		t.Fatalf("cursor_stale 后连接应仍可用：%v", err)
	}
}

func TestHandshakeBadJSONAndBadFrameDisconnect(t *testing.T) {
	ts := startTestServer(t, facade.BusConfig{})
	// hello 帧坏 JSON → goodbye(bad_json) + 断连。
	nc, err := net.Dial("unix", ts.sock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nc.Write(EncodeFrame(OpHello, []byte("{oops"))); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(nc)
	op, body := readFrameRaw(t, r)
	if op != OpGoodbye {
		t.Fatalf("坏 JSON 应 goodbye，得到 0x%02x", op)
	}
	var g GoodbyeBody
	_ = json.Unmarshal(body, &g)
	if g.Reason != facade.CodeBadJSON {
		t.Fatalf("goodbye 原因应为 bad_json：%q", g.Reason)
	}
	if _, err := r.ReadByte(); err != io.EOF {
		t.Fatalf("bad_json 后应断连：%v", err)
	}
	nc.Close()

	// 声明超限 → goodbye(bad_frame) + 断连（读 body 前拒绝）。
	nc2, err := net.Dial("unix", ts.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer nc2.Close()
	head := []byte{OpReq, 0x10, 0x00, 0x00, 0x00} // len = 0x10000000 = 256MiB > 1MiB
	if _, err := nc2.Write(head); err != nil {
		t.Fatal(err)
	}
	r2 := bufio.NewReader(nc2)
	op, body = readFrameRaw(t, r2)
	if op != OpGoodbye {
		t.Fatalf("超限应 goodbye，得到 0x%02x", op)
	}
	_ = json.Unmarshal(body, &g)
	if g.Reason != facade.CodeBadFrame {
		t.Fatalf("goodbye 原因应为 bad_frame：%q", g.Reason)
	}
	// body（未声明的那部分）留在流里：连接直接被关。
	if _, err := r2.ReadByte(); err != io.EOF {
		t.Fatalf("bad_frame 后应断连：%v", err)
	}

	// 非法 op（预留段 0x05）→ bad_frame 断连。
	nc3, err := net.Dial("unix", ts.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer nc3.Close()
	if _, err := nc3.Write(EncodeFrame(0x05, []byte("{}"))); err != nil {
		t.Fatal(err)
	}
	r3 := bufio.NewReader(nc3)
	op, body = readFrameRaw(t, r3)
	_ = json.Unmarshal(body, &g)
	if op != OpGoodbye || g.Reason != facade.CodeBadFrame {
		t.Fatalf("非法 op 应 goodbye(bad_frame)：op=0x%02x reason=%q", op, g.Reason)
	}
}

// ---------- §3.3 逐操作 + 错误码映射逐行负例 ----------

func TestOpsHappyPath(t *testing.T) {
	ts := startTestServer(t, facade.BusConfig{})
	ts.backend.mu.Lock()
	ts.backend.states = []HostState{{
		ID: "aa", Name: "mbp", State: "ready",
		Link:  &HostLink{Via: "direct", Ep: "1.2.3.4:41641", RttMs: 12, At: 1690000000000},
		Stats: &HostRxTx{RxBytes: 100, TxBytes: 5},
	}}
	ts.backend.roles = []RoleBrief{{Name: "client", State: "running"}}
	ts.backend.mu.Unlock()
	c, _ := dialTest(t, ts)

	// daemon.status。
	raw, err := c.Request(context.Background(), facade.OpDaemonStatus, nil)
	if err != nil {
		t.Fatal(err)
	}
	var st DaemonStatusResult
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	if st.ServerVersion != "test-1.0" || st.Generation == "" || len(st.Roles) != 1 || len(st.Hosts) != 1 || st.Hosts[0].Link.RttMs != 12 {
		t.Fatalf("daemon.status 载荷形状：%+v", st)
	}
	// host.add（host-cli 3b：响应类型 = HostAddResult，reach 结论字段上 wire）。
	raw, err = c.Request(context.Background(), facade.OpHostAdd, HostAddArgs{Name: "mbp", Token: "hmw1good"})
	if err != nil {
		t.Fatal(err)
	}
	var add HostAddResult
	if err := json.Unmarshal(raw, &add); err != nil || add.ID == "" || add.AddedAt == 0 {
		t.Fatalf("host.add 载荷：%v（%s）", err, raw)
	}
	if add.Reach == nil || add.Reach.Tier != facade.ReachTierDirect || add.Reach.BestEp == "" || len(add.Reach.Tested) == 0 {
		t.Fatalf("host.add reach 结论缺失：%+v", add.Reach)
	}
	// host.list。
	raw, err = c.Request(context.Background(), facade.OpHostList, nil)
	if err != nil {
		t.Fatal(err)
	}
	var list HostListResult
	if err := json.Unmarshal(raw, &list); err != nil || len(list.Hosts) != 1 || list.Hosts[0].ID != add.ID {
		t.Fatalf("host.list：%v %+v", err, list)
	}
	// snapshot.get（seq 与 bus 一致）。
	raw, err = c.Request(context.Background(), facade.OpSnapshotGet, nil)
	if err != nil {
		t.Fatal(err)
	}
	var snap SnapshotResult
	if err := json.Unmarshal(raw, &snap); err != nil || snap.Seq != ts.bus.CurrentSeq() || snap.Hosts[0].Stats.RxBytes != 100 {
		t.Fatalf("snapshot.get：%v %+v", err, snap)
	}
	// host.remove。
	if _, err := c.Request(context.Background(), facade.OpHostRemove, HostRemoveArgs{Host: add.ID}); err != nil {
		t.Fatalf("host.remove：%v", err)
	}
}

func TestErrorCodeMappingNegativeCases(t *testing.T) {
	ts := startTestServer(t, facade.BusConfig{})
	c, _ := dialTest(t, ts)
	ctx := context.Background()

	// unknown_op：不断连（后续请求照常）。
	if _, err := c.Request(ctx, "nonsense.op", nil); !errors.Is(err, CodeError(facade.CodeUnknownOp)) {
		t.Fatalf("未知操作应 unknown_op：%v", err)
	}
	if _, err := c.Request(ctx, facade.OpHostList, nil); err != nil {
		t.Fatalf("unknown_op 后连接应不断：%v", err)
	}
	// bad_token。
	if _, err := c.Request(ctx, facade.OpHostAdd, HostAddArgs{Token: "BADxxx"}); !errors.Is(err, CodeError(facade.CodeBadToken)) {
		t.Fatalf("坏 token 应 bad_token：%v", err)
	}
	// bad_request：字段缺失/类型不符/值域外。
	if _, err := c.Request(ctx, facade.OpHostAdd, HostAddArgs{Token: ""}); !errors.Is(err, CodeError(facade.CodeBadRequest)) {
		t.Fatalf("空 token 应 bad_request：%v", err)
	}
	if _, err := c.Request(ctx, facade.OpHostAdd, map[string]any{"token": 123}); !errors.Is(err, CodeError(facade.CodeBadRequest)) {
		t.Fatalf("类型不符应 bad_request：%v", err)
	}
	if _, err := c.Request(ctx, facade.OpStreamOpen, StreamOpenArgs{Kind: "files", Host: "aa"}); !errors.Is(err, CodeError(facade.CodeBadRequest)) {
		t.Fatalf("kind 值域外应 bad_request：%v", err)
	}
	// host_exists。
	if _, err := c.Request(ctx, facade.OpHostAdd, HostAddArgs{Token: "T1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Request(ctx, facade.OpHostAdd, HostAddArgs{Token: "DUP"}); !errors.Is(err, CodeError(facade.CodeHostExists)) {
		t.Fatalf("同后端重复添加应 host_exists：%v", err)
	}
	// host_unreachable（host-cli 3b 只增错误码）：全不可达且未带 force → 不入表、
	// 不断连（后续请求照常）；带 force → 添加成功（tier=skipped）。
	if _, err := c.Request(ctx, facade.OpHostAdd, HostAddArgs{Token: "DEADx"}); !errors.Is(err, CodeError(facade.CodeHostUnreachable)) {
		t.Fatalf("全不可达应 host_unreachable：%v", err)
	}
	if _, err := c.Request(ctx, facade.OpHostList, nil); err != nil {
		t.Fatalf("host_unreachable 后连接应不断：%v", err)
	}
	raw, err := c.Request(ctx, facade.OpHostAdd, HostAddArgs{Token: "DEADx", Force: true})
	if err != nil {
		t.Fatalf("force 应添加成功：%v", err)
	}
	var forced HostAddResult
	if err := json.Unmarshal(raw, &forced); err != nil || forced.Reach == nil || forced.Reach.Tier != facade.ReachTierSkipped || forced.Reach.Tested == nil || len(forced.Reach.Tested) != 0 {
		t.Fatalf("force 载荷应为 skipped（端点未实测）：%s", raw)
	}
	if _, err := c.Request(ctx, facade.OpHostRemove, HostRemoveArgs{Host: forced.ID}); err != nil {
		t.Fatalf("清理 force 添加的主机：%v", err)
	}
	// no_host。
	if _, err := c.Request(ctx, facade.OpHostRemove, HostRemoveArgs{Host: "ff"}); !errors.Is(err, CodeError(facade.CodeNoHost)) {
		t.Fatalf("主机不存在应 no_host：%v", err)
	}
	// 订阅：词表外域 bad_request；同域重复订阅幂等成功；退订未订阅域幂等成功。
	if _, err := c.Subscribe(ctx, []string{"nope"}, nil, "", ""); !errors.Is(err, CodeError(facade.CodeBadRequest)) {
		t.Fatalf("词表外域应 bad_request：%v", err)
	}
	if _, err := c.Subscribe(ctx, []string{facade.DomainSession}, nil, "", ""); err != nil {
		t.Fatalf("订阅失败：%v", err)
	}
	if _, err := c.Subscribe(ctx, []string{facade.DomainSession}, nil, "", ""); err != nil {
		t.Fatalf("同域重复订阅应幂等成功：%v", err)
	}
	if err := c.Unsubscribe(ctx, []string{facade.DomainLog}); err != nil {
		t.Fatalf("退订未订阅域应幂等成功：%v", err)
	}
	// 游标超前 bad_request；连接仍在（映射类错误全部不断连）。
	future := uint64(999)
	if _, err := c.Subscribe(ctx, []string{facade.DomainSession}, &future, "", ""); !errors.Is(err, CodeError(facade.CodeBadRequest)) {
		t.Fatalf("超前游标应 bad_request：%v", err)
	}
	if _, err := c.Request(ctx, facade.OpHostList, nil); err != nil {
		t.Fatalf("映射错误后连接应不断：%v", err)
	}
	// not_ready（放在最后：置位后宿主面不可用）。
	ts.backend.mu.Lock()
	ts.backend.notReady = true
	ts.backend.mu.Unlock()
	if _, err := c.Request(ctx, facade.OpHostList, nil); !errors.Is(err, CodeError(facade.CodeNotReady)) {
		t.Fatalf("未就绪应 not_ready：%v", err)
	}
}

func TestBadJSONRequestDisconnects(t *testing.T) {
	// 控制类 body 非法 JSON → bad_json 断连（req 帧）。
	ts := startTestServer(t, facade.BusConfig{})
	nc, err := net.Dial("unix", ts.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	if _, err := nc.Write(EncodeFrame(OpHello, []byte(`{"protoVersion":1,"frontend":{"kind":"cli","name":"x","version":"0"}}`))); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(nc)
	readFrameRaw(t, r) // welcome
	if _, err := nc.Write(EncodeFrame(OpReq, []byte(`{"corr":1,"op":"`))); err != nil {
		t.Fatal(err)
	}
	op, body := readFrameRaw(t, r)
	var g GoodbyeBody
	_ = json.Unmarshal(body, &g)
	if op != OpGoodbye || g.Reason != facade.CodeBadJSON {
		t.Fatalf("req 坏 JSON 应 goodbye(bad_json)：0x%02x %q", op, g.Reason)
	}
}

// ---------- 事件推送/回放/overrun（经客户端的端到端） ----------

func TestServerEventSubscribeReplayAndLive(t *testing.T) {
	ts := startTestServer(t, facade.BusConfig{})
	for i := 0; i < 3; i++ {
		if _, err := ts.bus.Publish(facade.DomainSession, facade.KindSessionStateChanged, facade.SessionStateChangedPayload{Host: "aa", State: fmt.Sprintf("s%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	c, _ := dialTest(t, ts)
	cur := uint64(0)
	if _, err := c.Subscribe(context.Background(), []string{facade.DomainSession}, &cur, "view-main", ""); err != nil {
		t.Fatal(err)
	}
	// 回放 3 条 + 在线 1 条。
	for want := uint64(1); want <= 3; want++ {
		select {
		case ev := <-c.Events():
			if ev.Seq != want || ev.Kind != facade.KindSessionStateChanged {
				t.Fatalf("回放事件 %d：%+v", want, ev)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("回放事件 %d 未到达", want)
		}
	}
	if _, err := ts.bus.Publish(facade.DomainSession, facade.KindSessionRemoved, facade.SessionRemovedPayload{Host: "aa", Reason: "user"}); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-c.Events():
		if ev.Seq != 4 || ev.Kind != facade.KindSessionRemoved {
			t.Fatalf("在线事件：%+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("在线事件未到达")
	}
}

func TestServerOverrunGoodbyeDisconnect(t *testing.T) {
	// 慢消费者：订阅队列 2、客户端不读事件 → goodbye(overrun) + 断连。
	ts := startTestServer(t, facade.BusConfig{SubQueue: 2})
	c, _ := dialTest(t, ts)
	if _, err := c.Subscribe(context.Background(), []string{facade.DomainSession}, nil, "", ""); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		if _, err := ts.bus.Publish(facade.DomainSession, facade.KindSessionStateChanged, facade.SessionStateChangedPayload{Host: "aa", State: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case g := <-c.Goodbye():
		if g.Reason != GoodbyeOverrun {
			t.Fatalf("告别原因应为 overrun：%q", g.Reason)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("慢消费者未被 goodbye(overrun) 断连")
	}
	select {
	case <-c.Closed():
	case <-time.After(time.Second):
		t.Fatal("连接应已断")
	}
}

func TestServerCloseSendsGoodbyeShuttingDown(t *testing.T) {
	ts := startTestServer(t, facade.BusConfig{})
	c, _ := dialTest(t, ts)
	go func() {
		time.Sleep(100 * time.Millisecond)
		ts.srv.Close()
	}()
	select {
	case g := <-c.Goodbye():
		if g.Reason != facade.CodeShuttingDown {
			t.Fatalf("收工告别原因应为 shutting_down：%q", g.Reason)
		}
	case <-c.Closed():
		// 告别帧与关闭竞态：连接断开也算通过（goodbye 尽力而为）。
	case <-time.After(3 * time.Second):
		t.Fatal("服务器收工未断开连接")
	}
}

// ---------- exec-r1 整改回归 ----------

// TestClientDisconnectReleasesConnAndGoroutines 客户端正常断开（不发 goodbye——
// CLI 形态）后连接必须收尾：conn 条目与 reader/writer 两 goroutine 全部回落
// （exec-r1 B1：此前 run() 在 reader 返回后先等 writerDone 再走 defer close，
// writer 永远等不到 closed ⇒ 每次断开泄漏 1 conn + 2 goroutine + 1 fd，监控脚本
// 几小时打爆 fd 上限）。
func TestClientDisconnectReleasesConnAndGoroutines(t *testing.T) {
	ts := startTestServer(t, facade.BusConfig{})
	before := runtime.NumGoroutine()
	for i := 0; i < 10; i++ {
		c, _ := dialTest(t, ts)
		if _, err := c.Request(context.Background(), facade.OpDaemonStatus, nil); err != nil {
			t.Fatalf("第 %d 条连接 status 失败：%v", i, err)
		}
		c.Close() // 直接关 socket（CLI 正常断开形态）
	}
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		ts.srv.mu.Lock()
		n := len(ts.srv.conns)
		ts.srv.mu.Unlock()
		if n == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	ts.srv.mu.Lock()
	n := len(ts.srv.conns)
	ts.srv.mu.Unlock()
	if n != 0 {
		t.Fatalf("10 条正常断开的连接应收尾干净（conns=%d）——连接泄漏回归", n)
	}
	grace := time.Now().Add(time.Second) // goroutine 回落容差窗（测试运行期后台噪声）
	for time.Now().Before(grace) && runtime.NumGoroutine() > before+2 {
		time.Sleep(50 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > before+2 {
		t.Fatalf("连接 goroutine 未回落（before=%d now=%d）——泄漏回归", before, got)
	}
}

// TestConnCloseBoundedWhenHighQueueFull highC 满 + 帧级错误下 close 必须有界返回
// （exec-r1 M1：此前 close(reason) 先走阻塞 sendHigh，唯一逃生口 closed 又在本
// 函数更后面才关——互等挂死，Server.Close()（daemon 收工路径）收不了尾）。
func TestConnCloseBoundedWhenHighQueueFull(t *testing.T) {
	bus := facade.NewBus(facade.NewGeneration(), facade.BusConfig{})
	srv := NewServer(ServerConfig{Bus: bus, Backend: newFakeBackend()})
	a, _ := net.Pipe()
	c := newConn(srv, a)
	for i := 0; i < highQueue; i++ { // 灌满控制帧队列（前端不读的病态）
		c.highC <- highItem{frame: []byte("x")}
	}
	done := make(chan struct{})
	go func() {
		c.fatal(facade.CodeBadFrame) // 帧级错误路径 = close(bad_frame) 携带告别帧
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("highC 满 + 帧级错误下 close 挂死（互等回归）")
	}
	select {
	case <-c.closed:
	default:
		t.Fatal("close 返回后 closed 应已关闭")
	}
	_ = a.Close()
}

// TestServerRejectsOversizedStreamDataOnReadPath 服务器读路径对流 DATA 帧执行
// 256KiB 上限（exec-r1 B2：此前读循环一律按控制上限 1MiB 读——512KiB 的
// stream.data 被完整读下、只回 no_stream 不断连，spec「帧长上限」对流帧名存实亡）。
// 只写 5 字节帧头（body 不发）同时证明「超限在读 body 前拒绝」。
func TestServerRejectsOversizedStreamDataOnReadPath(t *testing.T) {
	ts := startTestServer(t, facade.BusConfig{})
	nc, err := net.Dial("unix", ts.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	if _, err := nc.Write(EncodeFrame(OpHello, []byte(`{"protoVersion":1,"frontend":{"kind":"cli","name":"raw","version":"0"}}`))); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(nc)
	readFrameRaw(t, r) // welcome
	var head [5]byte   // 512KiB：超流上限（256KiB+1 即超）、未超控制上限（1MiB）
	head[0] = OpStreamData
	binary.BigEndian.PutUint32(head[1:5], uint32(512<<10))
	// 读超时兜底：按旧实现（一律控制上限）服务器会去等 512KiB 的 body——本测试
	// 只发帧头，变异/回归形态将以读超时失败，而不是永久挂起。
	_ = nc.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := nc.Write(head[:]); err != nil {
		t.Fatal(err)
	}
	op, body := readFrameRaw(t, r)
	var g GoodbyeBody
	_ = json.Unmarshal(body, &g)
	if op != OpGoodbye || g.Reason != facade.CodeBadFrame {
		t.Fatalf("超流上限应 goodbye(bad_frame)：op=0x%02x reason=%q", op, g.Reason)
	}
	if _, err := r.ReadByte(); err != io.EOF {
		t.Fatalf("bad_frame 后应断连：%v", err)
	}
}

// ---------- §3.6 监听（权限位 + 残留 socket 两分支） ----------

func TestListenControlPermissions(t *testing.T) {
	dir := shortTempDir(t)
	sock, ln, err := ListenControl(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("control.sock 权限应为 0600（凭证 = socket 属主），得到 %o", fi.Mode().Perm())
	}
	dfi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dfi.Mode().Perm() != 0o700 {
		t.Fatalf("state 目录应为 0700（第二层防御），得到 %o", dfi.Mode().Perm())
	}
	// 宽松目录（模拟异常）也只影响第二层：socket 自身仍收紧。
	dir2 := shortTempDir(t)
	_ = os.Chmod(dir2, 0o755)
	sock2, ln2, err := ListenControl(dir2)
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()
	fi2, _ := os.Stat(sock2)
	if fi2.Mode().Perm() != 0o600 {
		t.Fatalf("宽松目录下 socket 仍应 0600：%o", fi2.Mode().Perm())
	}
}

func TestListenControlResidue(t *testing.T) {
	dir := shortTempDir(t)
	sock := filepath.Join(dir, ControlSockName)

	// 分支一：活实例占用（connect 探测连通）→ 报错、不接管。
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ListenControl(dir); err == nil || !strings.Contains(err.Error(), "占用") {
		t.Fatalf("活实例占用应报错：%v", err)
	}
	// 占用者退场：模拟「监听者已死只剩 socket 文件」的死残留——Go 默认 close 会
	// unlink，先关掉该行为让文件留下（serve.go listenLocalService 同款模拟法）。
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	ln.Close()
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("死残留 socket 文件应在：%v", err)
	}
	// 分支二：死残留（connect 得 ECONNREFUSED）→ 清除后接管成功。
	sock2, ln2, err := ListenControl(dir)
	if err != nil {
		t.Fatalf("死残留应被清除接管：%v", err)
	}
	defer ln2.Close()
	if sock2 != sock {
		t.Fatalf("socket 路径应不变")
	}
	// 接管后可正常 connect（活监听点）。
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("接管后应可连接：%v", err)
	}
	c.Close()
}

// TestServerConcurrentUnsubscribeVsPublish 生产形态的并发「退订 × 发布」（经真实
// 连接的 events.subscribe/unsubscribe × 总线 Publish——exec-r1 H1 竞态的真实现场：
// 此前 opUnsubscribe 在 subMu 下裸 delete(sub.domains)，与 publish 在 b.mu 下经
// matches 读同一张 map 构成 fatal 级竞态）。`-race` 下旧实现必报
// concurrent map read and map write；修复 = 域增删收敛进总线锁
// （facade.Bus.UnsubscribeDomains，server 只调）。
func TestServerConcurrentUnsubscribeVsPublish(t *testing.T) {
	ts := startTestServer(t, facade.BusConfig{SubQueue: 1024})
	c, _ := dialTest(t, ts)
	ctx := context.Background()
	if _, err := c.Subscribe(ctx, []string{facade.DomainSession}, nil, "", ""); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // 并发发布（publish 在 b.mu 下读 sub.domains）
		defer wg.Done()
		for i := 0; i < 500; i++ {
			_, _ = ts.bus.Publish(facade.DomainSession, facade.KindSessionStateChanged, facade.SessionStateChangedPayload{Host: "aa", State: "x"})
		}
	}()
	go func() { // 并发退订/再订阅（写 sub.domains——只在 b.mu 内）
		defer wg.Done()
		for i := 0; i < 100; i++ {
			if err := c.Unsubscribe(ctx, []string{facade.DomainSession}); err != nil {
				return // 连接被断（overrun 等）：停（竞态窗口已开过）
			}
			if _, err := c.Subscribe(ctx, []string{facade.DomainSession}, nil, "", ""); err != nil {
				return
			}
		}
	}()
	wg.Wait()
}
