package server

// role_test.go — serve 角色生命周期与路径注入（role-management tasks 2.1 验证面）：
// 全装配 Start→ctx 取消→收尾（socket 摘除）；重复 Run 拒；nil 注入 = 现状单旋钮
// 落点；注入 = D3 拆分表三落点；台账写入纪律的服务器级端到端（启动首轮 + 端点变化轮）。
//
// 安全注意：测试全装配用随机空闲 UDP 端口、DNS 代答关（dns_port=0）、UPnP/STUN 关
// （零路由器/外网探测副作用）；udpcap 探测为普通出站 UDP（与既有测试同款）。

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"github.com/zhaoyswd/homeway/pkg/dns"
	"github.com/zhaoyswd/homeway/pkg/intercept"
	"github.com/zhaoyswd/homeway/pkg/proto"
	"github.com/zhaoyswd/homeway/pkg/servercore"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// freeUDPPort 抓一个空闲 UDP 端口（听完即关——串行测试下可用）。
func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return uint16(pc.LocalAddr().(*net.UDPAddr).Port)
}

// safeServeCfg 测试安全缺省（外网探测全关 + 随机端口），mutate 可覆盖。
func safeServeCfg(t *testing.T, stateDir string, mutate func(*ServeConfig)) ServeConfig {
	t.Helper()
	// 兜底窗缩到亚秒（生产 15s；同款 var 测试缝，见 role.go）。
	old := tokenFallbackWait.Load()
	tokenFallbackWait.Store(int64(200 * time.Millisecond))
	t.Cleanup(func() { tokenFallbackWait.Store(old) })
	cfg := ServeConfig{
		StateDir:   stateDir,
		ListenPort: freeUDPPort(t),
		BindMode:   BindOff, // 不探针挑卡（避免真实网卡探测的时延与噪声）
		UPnP:       false,
		// STUN 关：token 走兜底窗（测试经 tokenFallbackWait 缩到亚秒）；零外网探测。
		STUN:      "",
		STUN6:     "",
		DNSPort:   0, // 关代答（不碰 5300——本机可能有在役出口）
		PeerTTL:   time.Hour,
		FilesRoot: stateDir,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	return cfg
}

// shortStateDir：短路径（sun_path 上限）。
func shortStateDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "sv")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// runRoleUntilReady 起角色、等 token 台账出现首条追加（= 首轮铸出已发生），返回
// 停止函数（取消 ctx 并等 Run 返回）。
func runRoleUntilReady(t *testing.T, cfg ServeConfig) (*Role, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	role := NewRole(cfg)
	done := make(chan error, 1)
	go func() { done <- role.Run(ctx) }()
	st := &State{dir: cfg.StateDir}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		last, err := st.lastRecord()
		// 就绪判据 = 首轮**铸出**的台账行（endpoints 非空）——不能只看台账存在：全新
		// state 的预热行（IssueToken，endpoints=null）在启动即落，不代表 token 已铸。
		if err == nil && last != nil && len(last.Endpoints) > 0 {
			return role, func() {
				cancel()
				select {
				case err := <-done:
					if err != nil && err != context.Canceled {
						t.Errorf("角色收工应 nil（ctx 取消族）：%v", err)
					}
				case <-time.After(20 * time.Second):
					t.Error("角色 Run 未在 20s 内收工")
				}
			}
		}
		select {
		case err := <-done:
			t.Fatalf("角色提前退工：%v", err)
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	t.Fatal("20s 内未见首轮 token 台账追加")
	return nil, nil
}

// 生命周期：start → ctx 取消 → 收尾（UDS 摘除、Run 返回 nil）+ 重复 Run 拒。
func TestServeRoleLifecycleAndDoubleRun(t *testing.T) {
	dir := shortStateDir(t)
	cfg := safeServeCfg(t, dir, nil)
	role, stop := runRoleUntilReady(t, cfg)
	sock := filepath.Join(dir, "files.sock")
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("运行中 files.sock 应在 %s：%v", sock, err)
	}
	// 运行中重复 Run 拒（角色对象一次生命周期；重建 = 重新 NewRole——supervisor 语义；
	// 收工后的同一对象再 Run = 新一轮装配，属合法形态）。
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	if err := role.Run(ctx2); err == nil || !strings.Contains(err.Error(), "重复启动") {
		t.Fatalf("运行中再 Run 应报重复启动错误，got %v", err)
	}
	// 收尾：socket 文件摘除 + Run 返回 nil。
	stop()
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("收尾后 files.sock 应摘除：%v", err)
	}
}

// nil 注入 = 现状单旋钮落点：key/tokens/日志/socket 全在 StateDir（旧行为零变化）。
func TestServeRoleNilInjectionLegacyPaths(t *testing.T) {
	dir := shortStateDir(t)
	cfg := safeServeCfg(t, dir, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	role := NewRole(cfg)
	done := make(chan error, 1)
	go func() { done <- role.Run(ctx) }()
	waitFile(t, filepath.Join(dir, "key.bin"), 20*time.Second)
	waitFile(t, filepath.Join(dir, "tokens.jsonl"), 20*time.Second)
	waitFile(t, filepath.Join(dir, "events.log"), 20*time.Second)
	waitFile(t, filepath.Join(dir, "files.sock"), 20*time.Second)
	waitFile(t, filepath.Join(dir, "term.sock"), 20*time.Second)
	waitFile(t, filepath.Join(dir, "speedtest.sock"), 20*time.Second)
	cancel()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("角色未收工")
	}
}

// 注入 = D3 拆分表三落点：L2=<D>/serve、L3=<D>/cache、瞬态=<D>（与统一进程装配同表）。
func TestServeRoleInjectedPaths(t *testing.T) {
	dir := shortStateDir(t)
	cfg := safeServeCfg(t, dir, func(c *ServeConfig) {
		c.StateDir = filepath.Join(dir, "serve")
		c.LogDir = filepath.Join(dir, "cache")
		c.PortFileDir = filepath.Join(dir, "cache")
		c.SockDir = dir
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	role := NewRole(cfg)
	done := make(chan error, 1)
	go func() { done <- role.Run(ctx) }()
	waitFile(t, filepath.Join(dir, "serve", "key.bin"), 20*time.Second)
	waitFile(t, filepath.Join(dir, "serve", "tokens.jsonl"), 20*time.Second)
	waitFile(t, filepath.Join(dir, "cache", "events.log"), 20*time.Second)
	waitFile(t, filepath.Join(dir, "files.sock"), 20*time.Second)
	waitFile(t, filepath.Join(dir, "term.sock"), 20*time.Second)
	waitFile(t, filepath.Join(dir, "speedtest.sock"), 20*time.Second)
	cancel()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("角色未收工")
	}
}

// 台账写入纪律（2.4 服务器级端到端）：启动首轮即追加、末行 = 在跑 token；端点变化
// 轮再追加一条（secret 不变）；无变化不追加（进程内 lastToken 去重 + AppendToken 去重）。
func TestServeRoleAppendTokenLedger(t *testing.T) {
	dir := shortStateDir(t)
	cfg := safeServeCfg(t, dir, nil)
	role, stop := runRoleUntilReady(t, cfg)
	defer stop()
	s := role.Current()
	if s == nil {
		t.Fatal("角色运行中应能取到 Server")
	}
	st := &State{dir: cfg.StateDir}

	first, err := st.lastRecord()
	if err != nil || first == nil {
		t.Fatalf("首轮台账末行缺失：%v", err)
	}
	// 末行 secret = 在用 secret（secrets[0]——AppendToken 纪律）。
	secrets, err := st.Secrets()
	if err != nil || len(secrets) == 0 {
		t.Fatalf("读 secrets：%v", err)
	}
	var firstSecret [32]byte
	if raw, derr := decodeB64(first.Secret); derr == nil && len(raw) == 32 {
		copy(firstSecret[:], raw)
	}
	if firstSecret != secrets[0] {
		t.Fatal("台账末行 secret 应 = 在用 secret（secrets[0]）")
	}
	// 末行端点可解（启动首轮的实时端点——LAN 段非空）。
	if len(first.Endpoints) == 0 {
		t.Fatal("首轮台账行应带实时端点")
	}

	// 端点变化轮：直接驱动 printClientToken（生产同一条铸出路径）。
	s.tokMu.Lock()
	inUse := s.lastToken
	s.tokMu.Unlock()
	if inUse == "" {
		t.Fatal("运行中 lastToken 为空（首轮未铸出）")
	}
	s.printClientToken([]string{"203.0.113.7:41641"})
	second, err := st.lastRecord()
	if err != nil || second == nil {
		t.Fatalf("端点变化后台账末行缺失：%v", err)
	}
	if second.Secret != first.Secret {
		t.Fatal("端点变化轮的追加不得换 secret（复用在用 secret）")
	}
	found := false
	for _, e := range second.Endpoints {
		if e.Addr == "203.0.113.7:41641" {
			found = true
		}
	}
	if !found {
		t.Fatalf("变化轮末行应带新端点：%+v", second.Endpoints)
	}

	// 无变化不追加：同一清单再铸一轮，末行保持不变。
	before := ledgerLines(t, cfg.StateDir)
	s.printClientToken([]string{"203.0.113.7:41641"})
	time.Sleep(200 * time.Millisecond)
	if after := ledgerLines(t, cfg.StateDir); after != before {
		t.Fatalf("无变化轮不得追加（%d → %d）", before, after)
	}

	// 台账末行 = 在跑 token 的同源断言：末行 (secret, endpoints) 铸出的 token 与内存
	// lastToken 一致（Decode→重 Encode 对拍）。
	last, _ := st.lastRecord()
	var sec [32]byte
	raw, _ := decodeB64(last.Secret)
	copy(sec[:], raw)
	pub := PubFromPriv(s.priv)
	tokStr, err := proto.EncodeToken(proto.Token{PeerID: pub, Secret: sec, Endpoints: last.Endpoints})
	if err != nil {
		t.Fatal(err)
	}
	s.tokMu.Lock()
	cur := s.lastToken
	s.tokMu.Unlock()
	if tokStr != cur {
		t.Fatalf("台账末行重铸 token ≠ 在跑 token（末行滞后？）\nledger=%s\nrunning=%s", tokStr, cur)
	}
}

// ledgerLines 台账行数（非空行）。
func ledgerLines(t *testing.T, dir string) int {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, "tokens.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			n++
		}
	}
	return n
}

// decodeB64：台账 secret 的 RawURL base64。
func decodeB64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// waitFile 等文件出现（角色装配是异步的）。
func waitFile(t *testing.T, path string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		select {
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatalf("%s 在 %v 内未出现", path, d)
}

// 快照接口冒烟（D10 数据源）：字段可取、token 只见掩码。
func TestServeSnapshotMasksToken(t *testing.T) {
	s := &Server{priv: [32]byte{1}, secret: [32]byte{2}}
	b := &servercore.ServerBind{Logf: func(string, ...any) {}}
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	s.bind = b
	s.tokMu.Lock()
	s.lastToken = strings.Repeat("x", 80)
	s.tokMu.Unlock()
	snap := s.Snapshot()
	if !strings.HasPrefix(snap.TokenMask, "xxxx") || strings.Contains(snap.TokenMask, strings.Repeat("x", 40)) {
		t.Fatalf("token 掩码形态不对：%q", snap.TokenMask)
	}
	if snap.ListenPort != b.LocalPort() {
		t.Fatalf("快照监听口 %d ≠ 实际 %d", snap.ListenPort, b.LocalPort())
	}
}

// TestPeerTTLZeroMeansOff（FIX-62）：0 = **关闭** TTL 回收（三处口径统一）。
// 原实现 fill() 把 0 改写成 7 天——「--peer-ttl 0」/config `peer_ttl="0s"` 都
// 无法真正关掉回收（口径写「0 = 关」，行为是「0 = 缺省」）。
func TestPeerTTLZeroMeansOff(t *testing.T) {
	var c ServeConfig
	c.fill()
	if c.PeerTTL != 0 {
		t.Fatalf("fill 不得改写 PeerTTL（0 = 关），got %v", c.PeerTTL)
	}
	// 设备表：TTL=0 ⇒ 不回收（peers.go 的 ttl<=0 分支；构造器不再把 0 改写成 7 天）。
	tbl := servercore.NewDeviceTable(nil, nil, servercore.DeviceConfig{MaxDevices: 4})
	if _, ttl, _ := tbl.Limits(); ttl != 0 {
		t.Fatalf("表限额应原样携带 0（0 = 关）：%v", ttl)
	}
}

// TestCloseCleansPartialAssembly（FIX-65）：装配半途失败后统一走 Close——对**部分
// 装配**的 Server（只有 dnsSrv + 生命周期 ctx，bind/dev/intercept 都还没建）调 Close
// 不得 panic，且必须：取消 relayCtx（观测面/中继腿随之收）与关掉 DNS 代答（含它
// 接管的注入 listener——FIX-60 起代答自己没有监听面，生命周期全看注入）。
// 原实现的失败路径各自手写清理（只关 dev / 只关 dns+tunDev），漏一处就是一串泄漏。
func TestCloseCleansPartialAssembly(t *testing.T) {
	dsrv := dns.New(dns.Config{Logf: func(string, ...any) {}})
	pc, lerr := net.ListenPacket("udp", "127.0.0.1:0")
	if lerr != nil {
		t.Fatal(lerr)
	}
	ln, lerr := net.Listen("tcp", pc.LocalAddr().String())
	if lerr != nil {
		pc.Close()
		t.Fatal(lerr)
	}
	dsrv.ServePacketConn(pc)
	dsrv.ServeListener(ln)
	addr := pc.LocalAddr().String()
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		cfg:         ServeConfig{DNSPort: uint16(pc.LocalAddr().(*net.UDPAddr).Port), UPnP: false},
		Stats:       &intercept.Stats{},
		dnsSrv:      dsrv,
		relayCtx:    ctx,
		relayCancel: cancel,
	}
	s.Close() // 不得 panic（bind/dev/intercept/files 全 nil）
	select {
	case <-ctx.Done():
	default:
		t.Fatal("Close 应取消生命周期 ctx（观测面/中继腿随之收）")
	}
	// 注入的监听已随代答收工：同端口可再绑。
	pc2, lerr2 := net.ListenPacket("udp", addr)
	if lerr2 != nil {
		t.Fatalf("DNS 代答未收（注入的 listener 仍占着）：%v", lerr2)
	}
	_ = pc2.Close()
}

// TestManualPublicEndpointIsPublished（FIX-61）：--public-endpoint = 配置覆盖最高优先
// ——跳过 UPnP/STUN 推断，端点文件与 lastPublished 直接就是配置值（推断在不能枚举/观测
// 的环境里无解：macOS launchd 形态的 SSDP 被本地网络隐私静默拒即一例）。
func TestManualPublicEndpointIsPublished(t *testing.T) {
	dir := t.TempDir()
	cfg := ServeConfig{
		StateDir:       dir,
		UPnP:           false,
		STUN:           "",
		PublicEndpoint: "203.0.113.9:41641,[2001:db8::1]:41641",
	}
	s, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Start：%v", err)
	}
	defer s.Close()
	// 手动分支是同步写（refreshPublicEndpoint 的第一段）：直接读文件。
	b, rerr := os.ReadFile(PublicEndpointPath(dir))
	if rerr != nil {
		t.Fatalf("端点文件应已写出：%v", rerr)
	}
	got := strings.TrimSpace(string(b))
	if got != "203.0.113.9:41641\n[2001:db8::1]:41641" {
		t.Fatalf("端点文件应逐行等于配置值，got %q", got)
	}
	// 非法值：fill 阶段即被拒（按未配置处理，不阻断启动但也不信）。
	var bad ServeConfig
	bad.PublicEndpoint = "not-an-endpoint"
	bad.fill()
	if bad.PublicEndpoint != "" {
		t.Fatal("非法 --public-endpoint 应被清空（按未配置处理）")
	}
}

// TestStartMintsNewCredentialWhenAllRevoked（FIX-64）：凭证全被吊销后启动——启动
// 路径铸出新凭证（旧 token 彻底作废），并如实打台账规模与铸新行。
func TestStartMintsNewCredentialWhenAllRevoked(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenState(dir)
	if err != nil {
		t.Fatal(err)
	}
	old, err := st.IssueToken(nil)
	if err != nil {
		t.Fatal(err)
	}
	// 台账里已有第二轮（同凭证、新端点）——吊销后两行都应失效。
	if aerr := st.AppendToken(old.Secret, []proto.Endpoint{{Addr: "192.0.2.9:41641"}}); aerr != nil {
		t.Fatal(aerr)
	}
	if _, rerr := st.Revoke(old.Secret, "test"); rerr != nil {
		t.Fatal(rerr)
	}
	if secs, _ := st.Secrets(); len(secs) != 0 {
		t.Fatalf("吊销后验证集应为空，got %d", len(secs))
	}
	s, err := Start(context.Background(), ServeConfig{StateDir: dir, UPnP: false, DNSPort: 0})
	if err != nil {
		t.Fatalf("Start：%v", err)
	}
	defer s.Close()
	secs, err := st.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	if len(secs) != 1 || secs[0] == old.Secret {
		t.Fatalf("应铸出一枚新凭证（≠被吊销的旧凭证），got %d 枚", len(secs))
	}
	// 摘要日志：台账规模行 + 铸新行（判据可 grep）。
	b, rerr := os.ReadFile(filepath.Join(dir, eventsLogName))
	if rerr != nil {
		t.Fatalf("读 events.log：%v", rerr)
	}
	logs := string(b)
	if !strings.Contains(logs, "凭证台账：") || !strings.Contains(logs, "已吊销") {
		t.Fatalf("events.log 应有台账规模行（含已吊销计数）：\n%s", logs)
	}
	if !strings.Contains(logs, "已铸出新凭证") {
		t.Fatalf("全吊销启动应有铸新行：\n%s", logs)
	}
}

// TestStartWiresRevokedHook（FIX-64 接线判据）：装配层把吊销跟随读接进设备表——
// 同一凭证在吊销前后分别注册，前放行后拒（ErrTokenRevoked），全程无需重启。
func TestStartWiresRevokedHook(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenState(dir)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := st.IssueToken(nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Start(context.Background(), ServeConfig{StateDir: dir, UPnP: false, DNSPort: 0})
	if err != nil {
		t.Fatalf("Start：%v", err)
	}
	defer s.Close()
	pub := [32]byte{0x42}
	dev := proto.DevTag{1, 2, 3, 4, 5, 6, 7, 8}
	reg := proto.EncodeReg(tok.Secret, pub, dev, time.Now())
	if _, rerr := s.Table.Register(reg, time.Now()); rerr != nil {
		t.Fatalf("吊销前应放行：%v", rerr)
	}
	if _, rerr := st.Revoke(tok.Secret, "wired"); rerr != nil {
		t.Fatal(rerr)
	}
	// 拨过节流窗（等价于等过 1s；测试里直接重置检查时间）。
	s.revoked.mu.Lock()
	s.revoked.lastCheck = time.Time{}
	s.revoked.mu.Unlock()
	// 换个设备标签（同凭证）：验证面必然被吊销表挡下。
	dev2 := proto.DevTag{9, 9, 9, 9, 1, 2, 3, 4}
	if _, rerr := s.Table.Register(proto.EncodeReg(tok.Secret, pub, dev2, time.Now()), time.Now()); !errors.Is(rerr, servercore.ErrTokenRevoked) {
		t.Fatalf("吊销后必须 ErrTokenRevoked，got %v", rerr)
	}
}
