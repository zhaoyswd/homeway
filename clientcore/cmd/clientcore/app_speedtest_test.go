//go:build cshared

// app_speedtest_test.go — 测速引擎的 darwin 单测：真实 pkg/speedtest 服务 + 仿桥宿主
// （鉴权 → 拨本地服务 → 双向泵），全链路在进程内闭环；不碰真机/隧道。
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/speedtest"
)

func newBufioWriter(c net.Conn) *bufio.Writer { return bufio.NewWriter(c) }

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// fakeBridge：起一个仿桥宿主——unix listener，accept 后走真实 bridgeServerAuth，
// 再把连接双向泵到本地的 speedtest 服务（模拟「桥那头经会话拨出口 7803」）。
// mode：
//   - "ok"              正常泵；
//   - "close-after-auth" 鉴权通过就立刻关连接（模拟老出口：出口没有 7803 服务）；
//   - "link-down"       鉴权通过后回 report{link_down} 再关（模拟桥宿主拨出口失败）；
//   - "delay-greeting"  鉴权通过后静默 15s（模拟拨出口慢——取消竞态的靶子）。
func fakeBridge(t *testing.T, target string, mode string) (sockPath, authHex string) {
	t.Helper()
	// 目录名刻意短（同 shortBridgeDir 的做法）：macOS t.TempDir() 路径带长随机段，
	// 会顶穿 sockaddr_un 的 sun_path 上限（app_bridge.go 同款坑）。
	dir, err := os.MkdirTemp("", "sp")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.MkdirAll(filepath.Join(dir, bridgeDirName), 0o700); err != nil {
		t.Fatalf("mkdir bridge: %v", err)
	}
	path := bridgeSocketPath(dir, "speedtest")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	token := make([]byte, 32)
	for i := range token {
		token[i] = byte(i)
	}
	blob := append(append([]byte{}, bridgeAuthMagic...), token...)
	authHex = hex.EncodeToString(blob)

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if err := bridgeServerAuth(c, token); err != nil {
					_ = c.Close()
					return
				}
				switch mode {
				case "close-after-auth":
					_ = c.Close()
					return
				case "link-down":
					bw := newBufioWriter(c)
					_ = speedtest.WriteControl(bw, speedtest.TypeReport, []byte(`{"error":"link_down"}`))
					_ = bw.Flush()
					_ = c.Close()
					return
				case "delay-greeting":
					time.Sleep(15 * time.Second)
					_ = c.Close()
					return
				}
				remote, err := net.Dial("tcp", target)
				if err != nil {
					_ = c.Close()
					return
				}
				go func() { _, _ = io.Copy(remote, c) }()
				_, _ = io.Copy(c, remote)
				_ = remote.Close()
				_ = c.Close()
			}(c)
		}
	}()
	return path, authHex
}

func startSpeedServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	srv := speedtest.NewServer(nil)
	srv.SetLimits(speedtest.Limits{ConnTimeout: 20 * time.Second})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

func resetEngine(t *testing.T) {
	t.Helper()
	speed.mu.Lock()
	speed.phase = spIdle
	speed.running = false
	speed.mu.Unlock()
	speed.cancelActive()
	speed.mu.Lock()
	speed.phase = spIdle
	speed.running = false
	speed.mu.Unlock()
}

// TestSpeedEngineFullRun：全流程（下行 700ms + 上行 500ms，2 流）——两端数字对账，
// 且轮中能观察到 dir=down（评审 F1：相位必须真实流转）。
func TestSpeedEngineFullRun(t *testing.T) {
	target := startSpeedServer(t)
	sock, auth := fakeBridge(t, target, "ok")
	resetEngine(t)

	done := make(chan map[string]any, 1)
	go func() {
		done <- speedStart(mustJSON(t, speedParams{
			Auth: auth, Sock: sock,
			DownMs: 1500, UpMs: 700, WarmupMs: 150, Streams: 2,
		}))
	}()

	// 轮中观察 dir（评审 F1）：拨号+预热 ~0.5s 后应进入 down 窗。
	sawDown, sawUp := false, false
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) && !sawUp {
		snap := speed.snapshot()
		if d, _ := snap["dir"].(string); d == "down" {
			sawDown = true
		}
		if d, _ := snap["dir"].(string); d == "up" {
			sawUp = true
		}
		time.Sleep(60 * time.Millisecond)
	}
	if !sawDown {
		t.Fatalf("轮中从未观察到 dir=down")
	}
	if !sawUp {
		t.Fatalf("轮中从未观察到 dir=up")
	}

	res := <-done
	if res == nil {
		t.Fatalf("speedStart 返回 nil")
	}
	if res["ok"] != true {
		t.Fatalf("期望成功终态，got %v", res)
	}
	if res["downBps"].(float64) <= 0 || res["upBps"].(float64) <= 0 {
		t.Fatalf("两向速率应为正：down=%v up=%v", res["downBps"], res["upBps"])
	}
	if res["usageDown"].(int64) <= 0 || res["usageUp"].(int64) <= 0 {
		t.Fatalf("两向用量应为正：down=%v up=%v", res["usageDown"], res["usageUp"])
	}
	// 单飞后状态落 done；再 Start 应可重跑（终态让位）。
	if speed.snapshot()["phase"] != string(spDone) {
		t.Fatalf("终态相位 = %v，期望 done", speed.snapshot()["phase"])
	}
	t.Logf("down=%.1fMB/s up=%.1fMB/s usageDown=%d usageUp=%d wall=%v",
		res["downBps"].(float64)/1e6, res["upBps"].(float64)/1e6,
		res["usageDown"], res["usageUp"], time.Duration(res["wallMs"].(int64))*time.Millisecond)
}

// TestSpeedEngineNotSupported：鉴权后桥直接关连接（老出口）⇒ not_supported。
func TestSpeedEngineNotSupported(t *testing.T) {
	target := startSpeedServer(t)
	sock, auth := fakeBridge(t, target, "close-after-auth")
	resetEngine(t)

	res := speedStart(mustJSON(t, speedParams{Auth: auth, Sock: sock, DownMs: 300, UpMs: 200, WarmupMs: 100, Streams: 1}))
	if res["reason"] != "not_supported" {
		t.Fatalf("reason = %v，期望 not_supported", res["reason"])
	}
}

// TestSpeedEngineLinkDown：桥回 report{link_down}（桥宿主拨出口失败/恢复期）⇒ link_down，
// 不得误报 not_supported（评审 F4/F5）。
func TestSpeedEngineLinkDown(t *testing.T) {
	target := startSpeedServer(t)
	sock, auth := fakeBridge(t, target, "link-down")
	resetEngine(t)

	res := speedStart(mustJSON(t, speedParams{Auth: auth, Sock: sock, DownMs: 300, UpMs: 200, WarmupMs: 100, Streams: 1}))
	if res["reason"] != "link_down" {
		t.Fatalf("reason = %v，期望 link_down", res["reason"])
	}
}

// TestSpeedEngineBridgeDown：socket 不存在 ⇒ bridge_down（链路不在）。
func TestSpeedEngineBridgeDown(t *testing.T) {
	resetEngine(t)

	res := speedStart(mustJSON(t, speedParams{
		Auth: hex.EncodeToString(append(append([]byte{}, bridgeAuthMagic...), make([]byte, 32)...)),
		Sock: "/nonexistent/speedtest.sock", DownMs: 300, UpMs: 200, WarmupMs: 100, Streams: 1,
	}))
	if res["reason"] != "bridge_down" {
		t.Fatalf("reason = %v，期望 bridge_down", res["reason"])
	}
}

// TestSpeedEngineInvalid：参数越界（信封统一后走 ok:false，评审补③）。
func TestSpeedEngineInvalid(t *testing.T) {
	resetEngine(t)

	cases := []struct {
		name   string
		params string
		reason string
	}{
		{"流数越界", mustJSON(t, speedParams{Auth: "a", Sock: "/x", Streams: 99}), "invalid_arg"},
		{"窗口越界", mustJSON(t, speedParams{Auth: "a", Sock: "/x", DownMs: 60000}), "invalid_arg"},
		{"坏 JSON", `not-json`, "invalid_arg"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := speedStart(tc.params)
			if res["reason"] != tc.reason {
				t.Fatalf("reason = %v，期望 %s", res["reason"], tc.reason)
			}
		})
	}
}

// TestSpeedEngineCancel：下行窗中取消 ⇒ 终态 cancelled。
func TestSpeedEngineCancel(t *testing.T) {
	target := startSpeedServer(t)
	sock, auth := fakeBridge(t, target, "ok")
	resetEngine(t)

	done := make(chan map[string]any, 1)
	go func() {
		done <- speedStart(mustJSON(t, speedParams{Auth: auth, Sock: sock, DownMs: 5000, UpMs: 5000, WarmupMs: 300, Streams: 2}))
	}()
	time.Sleep(800 * time.Millisecond) // 等进入下行窗口（拨桥+预热 300ms + 余量）
	speed.cancelActive()
	select {
	case res := <-done:
		if res == nil || res["reason"] != "cancelled" {
			t.Fatalf("reason = %v，期望 cancelled", res)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("取消后引擎未收场")
	}
}

// TestSpeedEngineCancelDuringDial：取消落在**拨号/问候期**（连接尚未进窗）⇒
// 也必须秒级收场且归 cancelled（评审 F2-1：旧实现此处丢取消、跑满整轮还写结果）。
func TestSpeedEngineCancelDuringDial(t *testing.T) {
	sock, auth := fakeBridge(t, "127.0.0.1:1", "delay-greeting")
	resetEngine(t)

	done := make(chan map[string]any, 1)
	go func() {
		done <- speedStart(mustJSON(t, speedParams{Auth: auth, Sock: sock, DownMs: 3000, UpMs: 3000, WarmupMs: 200, Streams: 1}))
	}()
	time.Sleep(400 * time.Millisecond) // 已进 greeting 等待期
	t0 := time.Now()
	speed.cancelActive()
	select {
	case res := <-done:
		if res == nil || res["reason"] != "cancelled" {
			t.Fatalf("reason = %v，期望 cancelled；res=%v", res, res)
		}
		if el := time.Since(t0); el > 3*time.Second {
			t.Fatalf("取消后 %v 才收场，应秒级（greeting 期限 20s 没被取消打断）", el)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("取消后引擎未收场")
	}
}
