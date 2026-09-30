package daemon

// live_integration_test.go — 5.3 流底座端到端集成（真环境窗口用例）：daemon +
// 真实 Mac 出口——控制面 stream.open(term) 经 hostsession 隧道拨 7724 往返
//（GREETING → LIST → LIST-REPLY，多流并发）。
//
// token 纪律：真实 token 经环境变量现场注入（HOMEWAY_IT_TOKEN），**不进仓库/
// 日志/报告**；未设置即 skip（CI 不依赖真实后端）。5.4 的「一次性 host.add 入表」
// 同样走这里（HOMEWAY_LIVE_SOCK + HOMEWAY_LIVE_TOKENS——对已在跑的 daemon 操作）。

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"github.com/zhaoyswd/homeway/clientcore/facade"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/internal/control"
)

// term 帧常量（pkg/term 的 wire 协议；此处只取最小消费面——完整协议归 pkg/term）。
const (
	itTermOpList     byte = 0x04
	itTermOpGreeting byte = 0x0C
)

// itReadTermFrame 从流的下一块数据里读一帧 term 协议（[op:1][len:2 LE][payload]）。
func itReadTermFrame(t *testing.T, recv <-chan []byte) (byte, []byte) {
	t.Helper()
	select {
	case b := <-recv:
		if len(b) < 3 {
			t.Fatalf("term 帧过短：%d 字节", len(b))
		}
		n := int(binary.LittleEndian.Uint16(b[1:3]))
		if len(b) < 3+n {
			t.Fatalf("term 帧载荷截断：%d < %d", len(b), 3+n)
		}
		return b[0], b[3 : 3+n]
	case <-time.After(10 * time.Second):
		t.Fatal("10s 内未收到 term 帧")
		return 0, nil
	}
}

// itWaitHostReady 等 host 就绪且链路确立（ready 不保证健康——暖机软失败也到 ready；
// 链路 direct/relay + ep 才是真握手完成的判据，同 multihost_isolation 口径）。
func itWaitHostReady(t *testing.T, c *control.Client, host string) control.HostState {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := c.Request(context.Background(), facade.OpSnapshotGet, nil)
		if err == nil {
			var snap control.SnapshotResult
			if json.Unmarshal(raw, &snap) == nil {
				for _, h := range snap.Hosts {
					if h.ID == host && h.Link != nil && h.Link.Ep != "" && (h.Link.Via == "direct" || h.Link.Via == "relay") {
						return h
					}
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("45s 内主机 %s 未就绪（链路未确立）", shortHostID(host))
	return control.HostState{}
}

// TestLiveStreamTermEndToEnd 真实后端 7724 端到端：daemon 内真 hostsession 隧道 +
// 控制面流腿 + 出口 term 服务三段全通。
func TestLiveStreamTermEndToEnd(t *testing.T) {
	token := os.Getenv("HOMEWAY_IT_TOKEN")
	if token == "" {
		t.Skip("未设置 HOMEWAY_IT_TOKEN（真实出口 token 现场注入；不进仓库/日志/报告）")
	}
	_, sock := startDaemonForTest(t)
	c := dialDaemon(t, sock)
	ctx := context.Background()

	// 入表（§3.8 Go 客户端的 host.add——一次性，token 只经内存与环境变量）。
	raw, err := c.Request(ctx, facade.OpHostAdd, control.HostAddArgs{Name: "live-it", Token: token})
	if err != nil {
		t.Fatalf("host.add：%v", err)
	}
	var added control.HostBrief
	if err := json.Unmarshal(raw, &added); err != nil {
		t.Fatal(err)
	}
	host := itWaitHostReady(t, c, added.ID)

	// 多流并发：两条 term 流各自 GREETING → LIST → LIST-REPLY（term 协议最小往返）。
	termRoundTrip := func(tag string) {
		st, err := c.OpenStream(ctx, added.ID)
		if err != nil {
			t.Fatalf("[%s] stream.open：%v", tag, err)
		}
		op, greeting := itReadTermFrame(t, st.Recv())
		if op != itTermOpGreeting || len(greeting) < 5 {
			t.Fatalf("[%s] 首帧应为 GREETING：op=0x%02x payload=%d 字节", tag, op, len(greeting))
		}
		if err := st.Send([]byte{itTermOpList, 0x00, 0x00}); err != nil { // LIST（空载荷）
			t.Fatalf("[%s] 发送 LIST：%v", tag, err)
		}
		for {
			op, payload := itReadTermFrame(t, st.Recv())
			if op != itTermOpList {
				continue // 其它 S→C 帧（如 STATE）跳过，等 LIST-REPLY
			}
			var listReply struct {
				Sessions []map[string]any `json:"sessions"`
			}
			if err := json.Unmarshal(payload, &listReply); err != nil {
				t.Fatalf("[%s] LIST-REPLY 载荷应 JSON：%v（%q）", tag, err, payload)
			}
			if err := st.Close(ctx); err != nil {
				// term 服务的一锤子命令腿（LIST）回完就收线：服务端先关时流已
				// end(closed) 出表，这里再关 = no_stream——属正常次序，不算失败。
				if code, ok := err.(control.CodeError); !ok || string(code) != facade.CodeNoStream {
					t.Fatalf("[%s] stream.close：%v", tag, err)
				}
			}
			return
		}
	}
	done1 := make(chan struct{})
	go func() { defer close(done1); termRoundTrip("流1") }()
	done2 := make(chan struct{})
	go func() { defer close(done2); termRoundTrip("流2") }()
	<-done1
	<-done2

	// 流开着的同时控制面仍应答（三类流量同连接并存的最小实证；深度背压归单测）。
	if _, err := c.Request(ctx, facade.OpDaemonStatus, nil); err != nil {
		t.Fatalf("流并发期间 daemon.status：%v", err)
	}
	t.Logf("真后端端到端通过（link via=%s ep=%s）", host.Link.Via, host.Link.Ep)
}

// TestLiveHostAddAgainstRunningDaemon 5.4 前置工具：对已在跑的 daemon（如 launchd
// 拉起的）经控制面一次性 host.add 入表。HOMEWAY_LIVE_SOCK = control.sock 路径；
// HOMEWAY_LIVE_TOKENS = 多行「名字<TAB>token」（名字可空）。skip unless both set。
func TestLiveHostAddAgainstRunningDaemon(t *testing.T) {
	sock := os.Getenv("HOMEWAY_LIVE_SOCK")
	tokens := os.Getenv("HOMEWAY_LIVE_TOKENS")
	if sock == "" || tokens == "" {
		t.Skip("未设置 HOMEWAY_LIVE_SOCK/HOMEWAY_LIVE_TOKENS（真环境窗口现场注入）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, _, err := control.Dial(ctx, sock, control.FrontendInfo{Kind: "cli", Name: "live-hostadd", Version: "0"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i, line := range strings.Split(strings.TrimSpace(tokens), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, tok := "", line
		if parts := strings.SplitN(line, "\t", 2); len(parts) == 2 {
			name, tok = strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		}
		raw, err := c.Request(ctx, facade.OpHostAdd, control.HostAddArgs{Name: name, Token: tok})
		if err != nil {
			if code, ok := err.(control.CodeError); ok && string(code) == facade.CodeHostExists {
				t.Logf("第 %d 台已在表（幂等跳过）", i+1)
				continue
			}
			t.Fatalf("host.add 第 %d 台：%v", i+1, err)
		}
		var added control.HostBrief
		if err := json.Unmarshal(raw, &added); err != nil {
			t.Fatal(err)
		}
		// 只打主机 id（token 不进日志）。
		t.Logf("已入表：%s", shortHostID(added.ID))
	}
}
