//go:build cshared

// app_bridge_test.go — 桥鉴权与宿主行为（openspec app-service-session 任务 1.2）。
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/speedtest"
	"github.com/zhaoyswd/homeway/pkg/wgnet"
)

// fakeDialPort 拨出口虚拟端口的假实现：回一条管道连接，记录被拨的端口。
func fakeDialPort(dialed *[]uint16) func(ctx context.Context, port uint16) (net.Conn, error) {
	return func(ctx context.Context, port uint16) (net.Conn, error) {
		*dialed = append(*dialed, port)
		c1, c2 := net.Pipe()
		go func() {
			// 出口侧占位：只消费字节，保持连接开着。
			buf := make([]byte, 256)
			for {
				if _, err := c2.Read(buf); err != nil {
					return
				}
			}
		}()
		return c1, nil
	}
}

// waitSocket 等桥 socket 真正可连（token 生成先于 listen 完成，不能用 authHex 当就绪判据）。
func waitSocket(t *testing.T, sock string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("unix", sock, 200*time.Millisecond); err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("socket %s 3s 内未就绪", sock)
}

// shortBridgeDir 每用例独立的桥目录：名字刻意短——macOS 的 t.TempDir() 路径带着
// 长测试名，叠上 /bridge/xxx.sock 后会顶过 sun_path 的 104 字节上限（bind 报
// invalid argument），2026-09-22 踩过。生产路径（设备 <filesDir> ≈56B）无线内问题。
func shortBridgeDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "br")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// startTestHost 每用例独立桥目录（shortBridgeDir 充当 filesDir）。
func startTestHost(t *testing.T) (*bridgeHost, string) {
	t.Helper()
	var dialed []uint16
	h := newBridgeHost("测试桥", shortBridgeDir(t), Discard, fakeDialPort(&dialed), 2*time.Second)
	h.start()
	waitSocket(t, bridgeSocketPath(h.dir, "files"))
	t.Cleanup(func() { h.stop() })
	return h, h.authHex()
}

// 鉴权通过的流：客户端发 auth + 协议字节 → 桥透传到出口侧。
// 用回环 listener 模拟出口侧（dialPort 返回的连接由 fake 写入测试管道）。
// 这里只验证「合法令牌不被断」：连上 files 桥、发完整 auth blob，随后仍可读写。
func TestBridgeAuthAccepted(t *testing.T) {
	h, authHex := startTestHost(t)
	_ = h
	c, err := net.DialTimeout("unix", bridgeSocketPath(h.dir, "files"), time.Second)
	if err != nil {
		t.Fatalf("连 files 桥失败：%v", err)
	}
	defer c.Close()
	if err := bridgeWriteAuth(c, authHex); err != nil {
		t.Fatalf("发鉴权首包失败：%v", err)
	}
	// 鉴权通过后连接应保持可用（未被服务端断开）：写一笔协议字节，读不报错即算过
	//（fake 出口侧只读不回，这里验证连接在鉴权后短期内未被关闭）。
	_ = c.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := c.Write([]byte("POST-AUTH-BYTES")); err != nil {
		t.Fatalf("鉴权后写失败：%v", err)
	}
}

// 错误令牌：连接被断，且出口侧（dialPort）从未被调用。
func TestBridgeAuthWrongTokenRejected(t *testing.T) {
	var dialed []uint16
	h := newBridgeHost("测试桥", shortBridgeDir(t), Discard, fakeDialPort(&dialed), 2*time.Second)
	h.start()
	t.Cleanup(func() { h.stop() })
	waitSocket(t, bridgeSocketPath(h.dir, "term"))
	good := h.authHex()
	if good == "" {
		t.Fatal("桥未就绪")
	}
	bad := good[:len(good)-2] + "ff" // 改最后字节 ⇒ 令牌错误

	c, err := net.DialTimeout("unix", bridgeSocketPath(h.dir, "term"), time.Second)
	if err != nil {
		t.Fatalf("连 term 桥失败：%v", err)
	}
	defer c.Close()
	if err := bridgeWriteAuth(c, bad); err != nil {
		t.Fatalf("发（错误）鉴权首包失败：%v", err)
	}
	// 服务端应断开：读到 EOF 或错误。
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("错误令牌的连接未被断开")
	}
	// 出口侧未被拨：稍等异步路径完成。
	time.Sleep(200 * time.Millisecond)
	if len(dialed) != 0 {
		t.Fatalf("鉴权失败却拨了出口：%v", dialed)
	}
}

// 无鉴权直接说协议（其它应用的探测形态）：连接被断。
func TestBridgeAuthNoAuthRejected(t *testing.T) {
	var dialed []uint16
	h := newBridgeHost("测试桥", shortBridgeDir(t), Discard, fakeDialPort(&dialed), 2*time.Second)
	h.start()
	t.Cleanup(func() { h.stop() })
	waitSocket(t, bridgeSocketPath(h.dir, "files"))
	c, err := net.DialTimeout("unix", bridgeSocketPath(h.dir, "files"), time.Second)
	if err != nil {
		t.Fatalf("连 files 桥失败：%v", err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")) // 什么都不懂协议的探测
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("无鉴权连接未被断开")
	}
	time.Sleep(200 * time.Millisecond)
	if len(dialed) != 0 {
		t.Fatalf("无鉴权却拨了出口：%v", dialed)
	}
}

// 桥间的换轨：宿主 A stop 后宿主 B 能在同一路径 listen（bind 重试路径）。
// 顺带验证残留清理：A 的 stop 清掉自己的 socket 文件；异常残留（没来得及 stop）
// 由 B 的 listen 前 os.Remove 兜住。
func TestBridgeHandoff(t *testing.T) {
	dir := shortBridgeDir(t)
	var dialedA, dialedB []uint16
	sock := bridgeSocketPath(dir, "files")
	a := newBridgeHost("宿主A", dir, Discard, fakeDialPort(&dialedA), time.Second)
	a.start()
	waitSocket(t, sock)
	a.stop()
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("stop 后 socket 文件应被清理：%v", err)
	}

	b := newBridgeHost("宿主B", dir, Discard, fakeDialPort(&dialedB), time.Second)
	b.start()
	t.Cleanup(func() { b.stop() })
	// 宿主B 要经重试拿到路径（A 刚关，重试上限内必然成功）。
	var lastErr error
	for i := 0; i < 100; i++ { // ≤ ~5s
		c, err := net.DialTimeout("unix", sock, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return // B 已接管
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("宿主B 5s 内未接管 %s：%v", sock, lastErr)
}

// 异常残留（宿主崩溃没 stop）：下一个宿主 listen 前清掉死文件、正常起桥。
func TestBridgeStaleSocketCleaned(t *testing.T) {
	dir := shortBridgeDir(t)
	if err := os.MkdirAll(filepath.Join(dir, bridgeDirName), 0o700); err != nil {
		t.Fatal(err)
	}
	sock := bridgeSocketPath(dir, "term")
	if err := os.WriteFile(sock, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	var dialed []uint16
	h := newBridgeHost("测试桥", dir, Discard, fakeDialPort(&dialed), time.Second)
	h.start()
	t.Cleanup(func() { h.stop() })
	waitSocket(t, bridgeSocketPath(h.dir, "term"))
}

// bridgeWriteAuth 的参数校验（缺失/畸形 blob 不放行）。
func TestBridgeWriteAuthValidation(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	if err := bridgeWriteAuth(c1, ""); err == nil {
		t.Fatal("空 blob 应报错")
	}
	if err := bridgeWriteAuth(c1, "zz-not-hex"); err == nil {
		t.Fatal("非 hex 应报错")
	}
	short := "abcd"
	if err := bridgeWriteAuth(c1, short); err == nil {
		t.Fatal("短 blob 应报错")
	}
}

// obsConn 包装一条连接、记录 Close（net.Pipe 本身不记录）。
type obsConn struct {
	net.Conn
	closed *atomic.Bool
}

func (o *obsConn) Close() error {
	o.closed.Store(true)
	return o.Conn.Close()
}

// 桥闸的满员自愈：客户端泄漏连接占满上限后，新连接挤掉最老的一条（而不是被拒）。
// 复盘口径（真机 2026-09-20）：connect 的问候流泄漏 → 8 次进出打满闸 → 之后全拒、
// 「刷新也没用」。修复后：根修（问候流用完即关）+ 满员挤最老（任何来源的泄漏自愈）。
func TestBridgeLimiterEvictsOldest(t *testing.T) {
	lim := &bridgeConns{}
	mk := func() *obsConn {
		var closed atomic.Bool
		a, _ := net.Pipe()
		return &obsConn{Conn: a, closed: &closed}
	}
	c1, c2, c3 := mk(), mk(), mk()
	lim.admit(c1, Discard, "test-bridge", 2)
	lim.admit(c2, Discard, "test-bridge", 2)
	lim.admit(c3, Discard, "test-bridge", 2) // 满员：应挤掉 c1
	if !c1.closed.Load() {
		t.Fatal("满员后最老的连接未被挤掉")
	}
	if c2.closed.Load() || c3.closed.Load() {
		t.Fatal("不该动新连接")
	}
	// 被挤连接的泵 goroutine 随 Close 退出、调 leave 释放计数（测试模拟这一拍）：
	// 释放前瞬时计数 3、释放后回 2 —— 生产里这发生在毫秒级内。
	lim.leave(c1)
	if lim.n.Load() != 2 {
		t.Fatalf("计数 %d ≠ 2", lim.n.Load())
	}
	lim.leave(c3)
	lim.leave(c2)
	if lim.n.Load() != 0 {
		t.Fatalf("清空后计数 %d ≠ 0", lim.n.Load())
	}
}

// 静态断言：魔数长度与鉴权首包总长（协议常量漂移在测试期直接失败）。
func TestBridgeAuthConstants(t *testing.T) {
	if len(bridgeMagicForTest()) != 16 {
		t.Fatalf("魔数长度 %d ≠ 16", len(bridgeMagicForTest()))
	}
	if bridgeAuthLen != 16+32 {
		t.Fatalf("鉴权首包总长 %d ≠ 48", bridgeAuthLen)
	}
}

// ---- 评审整改 2026-09-22：活宿主让位与接管者保护 ----

// 活宿主占用：B 不得抢 A 的路径（此前盲删 + bind 会把 A 的监听器变孤儿，
// A 退场时又把 B 的 socket 删掉——换轨窗口双向破坏）。
func TestBridgeLiveOccupantNotClobbered(t *testing.T) {
	// 退避表经宿主字段注入（不动包级变量——与本包其它用例仍在退避睡眠里的
	// listenLoop goroutine 并发读写包级变量会被 -race 抓住）。
	shortBackoff := []time.Duration{10 * time.Millisecond}

	dir := shortBridgeDir(t)
	sock := bridgeSocketPath(dir, "files")
	var dialedA, dialedB []uint16
	a := newBridgeHost("宿主A", dir, Discard, fakeDialPort(&dialedA), time.Second)
	a.start()
	t.Cleanup(func() { a.stop() })
	waitSocket(t, sock)

	b := newBridgeHost("宿主B", dir, Discard, fakeDialPort(&dialedB), time.Second)
	b.backoff = shortBackoff
	b.start()
	t.Cleanup(func() { b.stop() })

	// B 的 listenLoop 走退避（不删 A 的文件、bind 撞 in use）——A 的桥必须原样活着。
	time.Sleep(300 * time.Millisecond)
	if c, err := net.DialTimeout("unix", sock, 200*time.Millisecond); err != nil {
		t.Fatalf("A 的活 socket 不应被 B 抢走/破坏：%v", err)
	} else {
		_ = c.Close()
	}
	if fi, err := os.Stat(sock); err != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("A 的 socket 文件应仍在且仍是 socket：%v", err)
	}
}

// 接管者保护：A 活着时路径被外力删掉、B 抢先 bind；A 晚到的 stop 不得删 B 的 socket。
func TestBridgeStopNotDeleteSuccessor(t *testing.T) {
	shortBackoff := []time.Duration{10 * time.Millisecond}

	dir := shortBridgeDir(t)
	sock := bridgeSocketPath(dir, "files")
	var dialedA, dialedB []uint16
	a := newBridgeHost("宿主A", dir, Discard, fakeDialPort(&dialedA), time.Second)
	a.start()
	waitSocket(t, sock)
	// 外力删除 A 的 socket 文件（A 的监听器仍活、路径已空——接管窗口的构造形态）。
	if err := os.Remove(sock); err != nil {
		t.Fatal(err)
	}
	b := newBridgeHost("宿主B", dir, Discard, fakeDialPort(&dialedB), time.Second)
	b.backoff = shortBackoff
	b.start()
	t.Cleanup(func() { b.stop() })
	waitSocket(t, sock) // B 拿到路径

	a.stop() // A 的收线：身份不匹配，不得动 B 的文件
	if c, err := net.DialTimeout("unix", sock, 200*time.Millisecond); err != nil {
		t.Fatalf("A 的 stop 把 B 的 socket 删掉了：%v", err)
	} else {
		_ = c.Close()
	}
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("B 的 socket 文件应仍在：%v", err)
	}
}

// TestSpeedBridgeHostBehavior：宿主侧第三座桥的护栏测试（评审 r2-N13——引擎单测的
// 仿桥绕开了宿主 acceptLoop，N2 正是从这条缝隙漏出去的）。用**真 bridgeHost** +
// 注入三种拨号结局，钉住「refused ⇒ 无帧 EOF（not_supported 路径）/ 其它错误 ⇒
// report{link_down}（先读掉请求帧再回帧）/ 成功 ⇒ 请求-应答全轮可用」的分流契约
// （3e 去问候帧后客户端先写请求、再读首帧）。
func TestSpeedBridgeHostBehavior(t *testing.T) {
	// 真出口：本地 speedtest 服务（线协议全真）。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := speedtest.NewServer(nil)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close(); ln.Close() })

	cases := []struct {
		name         string
		dialErr      error // nil = 拨真出口成功
		wantLinkDown bool  // true = 期望首帧 report{link_down}
		isSuccess    bool  // true = 期望完整收一轮
	}{
		{"refused ⇒ 无帧 EOF（出口无测速服务 not_supported 路径）", wgnet.ErrRefused, false, false},
		{"其它错误 ⇒ link_down 帧（恢复期）", errors.New("boom（会话未就绪）"), true, false},
		{"成功 ⇒ 请求-应答全轮", nil, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := shortBridgeDir(t)
			h := newBridgeHost("测试桥", dir, Discard,
				func(ctx context.Context, port uint16) (net.Conn, error) {
					if tc.dialErr != nil {
						return nil, tc.dialErr
					}
					return net.DialTimeout("tcp", ln.Addr().String(), time.Second)
				}, 2*time.Second)
			h.start()
			t.Cleanup(func() { h.stop() })
			sock := bridgeSocketPath(dir, "speedtest")
			waitSocket(t, sock)
			// 桥未起或 token 未生成时 authHex 为空：轮询等它就绪
			var authHex string
			for i := 0; i < 20; i++ {
				authHex = h.authHex()
				if authHex != "" {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if authHex == "" {
				t.Fatalf("桥令牌未就绪")
			}

			c, err := net.DialTimeout("unix", sock, time.Second)
			if err != nil {
				t.Fatalf("连 speed 桥失败：%v", err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			if err := bridgeWriteAuth(c, authHex); err != nil {
				t.Fatalf("发鉴权失败：%v", err)
			}
			bw := bufio.NewWriter(c)
			// 客户端先写请求（去问候帧后的协议序）；refused 路径桥会先关连接，
			// 写可能 EPIPE——忽略写错、以读端为准。
			_ = speedtest.WriteRequest(bw, speedtest.RoleRecv, 100*time.Millisecond, 150*time.Millisecond)
			_ = bw.Flush()
			br := bufio.NewReader(c)
			_ = c.SetDeadline(time.Time{})

			// 首帧分流：report{link_down}（恢复期）/ data→report（成功）/ EOF（refused）。
			ctrl := make([]byte, 1024)
			sawLinkDown := false
			for {
				tt, _, n, payload, rerr := speedtest.ReadFrameLoose(br, ctrl)
				if rerr != nil {
					break // EOF/读错收场（refused 路径的唯一出口）
				}
				if tt == speedtest.TypeData {
					if derr := speedtest.DiscardPayload(br, n); derr != nil {
						t.Fatalf("读载荷：%v", derr)
					}
					continue
				}
				if tt == speedtest.TypeReport {
					var rep speedtest.Report
					if jerr := json.Unmarshal(payload, &rep); jerr != nil {
						t.Fatalf("report 解析：%v", jerr)
					}
					if rep.Error == "link_down" {
						sawLinkDown = true
						break
					}
					if rep.Error != "" {
						t.Fatalf("意外错误 report：%+v", rep)
					}
					if !tc.isSuccess {
						t.Fatalf("该用例不应成功收轮：%+v", rep)
					}
					if rep.Bytes <= 0 {
						t.Fatalf("report 异常：%+v", rep)
					}
					return // 成功：完整收一轮（协议在真实宿主透传下可用）
				}
			}
			if tc.wantLinkDown && !sawLinkDown {
				t.Fatal("期望 link_down report，未读到")
			}
			// refused：必须无 link_down 帧（EOF 都行，就是不能是 link_down——
			// 否则出口无服务会被误判成恢复期）。
			if !tc.wantLinkDown && sawLinkDown {
				t.Fatalf("该用例不应回 link_down")
			}
			if tc.isSuccess {
				t.Fatal("成功用例必须收到 report 收轮")
			}
		})
	}
}
