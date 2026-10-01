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
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
	"github.com/zhaoyswd/homeway/pkg/servercore"
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
	old := tokenFallbackWait
	tokenFallbackWait = 200 * time.Millisecond
	t.Cleanup(func() { tokenFallbackWait = old })
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
