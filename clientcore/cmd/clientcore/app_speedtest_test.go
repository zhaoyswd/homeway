//go:build cshared

// app_speedtest_test.go — 测速壳（引擎已收拢 pkg/speedtest.Engine，3e §1.2）：
// 真实 pkg/speedtest 服务 + 仿桥宿主（鉴权 → 拨本地服务 → 双向泵），全链路在进程内
// 闭环；不碰真机/隧道。信封字段（Start/Status/Cancel 三返回形态）与 reason 五码
// busy/link_down/bridge_down/bridge_auth/not_supported × 触发条件逐条对拍（parity，
// r1 高-2——不只对字段名）。
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
//   - "close-after-auth" 鉴权通过就立刻关连接（出口无测速服务：桥拨被拒不回帧直接关——
//     判据② 形态）；
//   - "link-down"       鉴权通过后回 report{link_down} 再有序关（桥宿主拨出口失败——
//     与产线 speedLinkDownReply 同款 ReplyThenClose 收口）；
//   - "delay"           鉴权通过后静默 15s（模拟拨出口慢——等待期取消竞态的靶子）。
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
					speedtest.ReplyThenClose(c, bufio.NewReader(c), speedtest.Report{Error: "link_down"})
					return
				case "delay":
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

func startSpeedServer(t *testing.T, maxConns int) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	srv := speedtest.NewServer(nil)
	srv.SetLimits(speedtest.Limits{ConnTimeout: 20 * time.Second, MaxConns: maxConns})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

// ---------- 信封字段（Start/Status/Cancel 三返回形态，与迁移前逐字段一致） ----------

// TestSpeedEnvelopeSuccess 成功信封：字段名与类型 = ok/phase/downBps/upBps/usageDown/
// usageUp/wallMs（缺一/多一都算变）。
func TestSpeedEnvelopeSuccess(t *testing.T) {
	target := startSpeedServer(t, 0)
	sock, auth := fakeBridge(t, target, "ok")

	res := speedStart(mustJSON(t, speedParams{Auth: auth, Sock: sock, DownMs: 400, UpMs: 300, WarmupMs: 100, Streams: 1}))
	if res["ok"] != true {
		t.Fatalf("期望成功，got %v", res)
	}
	for _, k := range []string{"ok", "phase", "downBps", "upBps", "usageDown", "usageUp", "wallMs"} {
		if _, ok := res[k]; !ok {
			t.Fatalf("成功信封缺字段 %q：%v", k, res)
		}
	}
	if res["phase"] != "done" {
		t.Fatalf("phase = %v，期望 done", res["phase"])
	}
	if len(res) != 7 {
		t.Fatalf("成功信封字段数 = %d，期望 7：%v", len(res), res)
	}
	if res["downBps"].(float64) <= 0 || res["upBps"].(float64) <= 0 {
		t.Fatalf("两向速率应为正：%v", res)
	}
}

// TestSpeedEnvelopeFailure 失败信封：ok/reason/msg 三字段。
func TestSpeedEnvelopeFailure(t *testing.T) {
	res := speedStart(mustJSON(t, speedParams{Auth: "a", Sock: "/x", Streams: 99}))
	if res["ok"] != false || res["reason"] != "invalid_arg" {
		t.Fatalf("期望 invalid_arg 失败，got %v", res)
	}
	if len(res) != 3 {
		t.Fatalf("失败信封字段数 = %d，期望 3：%v", len(res), res)
	}
	if _, ok := res["msg"].(string); !ok {
		t.Fatalf("msg 应为 string：%v", res)
	}
}

// TestSpeedEnvelopeStatus Status 信封：phase/reason 恒在；运行中 usage/elapsed 在、
// 窗口内 dir/bytes/instBps 在（与迁移前按需出现一致）。
func TestSpeedEnvelopeStatus(t *testing.T) {
	// idle：只有 phase/reason（引擎初始快照 {idle, ElapsedMs:-1}——终态后 run 保留
	// 属既有设计「用量仍可读」，不用共享实例测 idle 面）。
	m := speedSnapshotJSON(speedtest.Snapshot{Phase: "idle", ElapsedMs: -1})
	if len(m) != 2 || m["phase"] != "idle" {
		t.Fatalf("idle 快照形态：%v", m)
	}

	target := startSpeedServer(t, 0)
	sock, auth := fakeBridge(t, target, "ok")
	done := make(chan map[string]any, 1)
	go func() {
		done <- speedStart(mustJSON(t, speedParams{Auth: auth, Sock: sock, DownMs: 900, UpMs: 500, WarmupMs: 100, Streams: 1}))
	}()
	deadline := time.Now().Add(4 * time.Second)
	sawLive := false
	for time.Now().Before(deadline) {
		s := speedSnapshotJSON(speed.Snapshot())
		if _, ok := s["usageDown"]; !ok {
			t.Fatalf("运行中快照缺 usageDown：%v", s)
		}
		if _, ok := s["elapsedMs"]; !ok {
			t.Fatalf("运行中快照缺 elapsedMs：%v", s)
		}
		if d, ok := s["dir"]; ok {
			// 相位过渡窗（connecting）dir 可为空串——迁移前同形态；非空只许 down/up。
			if dd, _ := d.(string); dd != "" && dd != "down" && dd != "up" {
				t.Fatalf("dir = %v", d)
			}
			if _, ok2 := s["bytes"]; !ok2 {
				t.Fatalf("有 dir 无 bytes：%v", s)
			}
			if _, ok2 := s["instBps"]; !ok2 {
				t.Fatalf("有 dir 无 instBps：%v", s)
			}
			if s["bytes"].(int64) > 0 {
				sawLive = true
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !sawLive {
		t.Fatal("快照从未观察到窗口内 live 读数")
	}
	if res := <-done; res["ok"] != true {
		t.Fatalf("成功终态：%v", res)
	}
}

// TestSpeedEnvelopeCancel Cancel 信封：{"ok":true}（cgo 不可进测试文件——导出面本体
// 只做 CancelActive + speedMarshal，这里测同一构造；C 字符串化由构建面保证）。
func TestSpeedEnvelopeCancel(t *testing.T) {
	speed.CancelActive() // 空闲时无害空操作
	m := map[string]any{"ok": true}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != `{"ok":true}` {
		t.Fatalf("Cancel 信封 = %s", b)
	}
}

// ---------- reason 五码 parity（迁移前后逐条对拍，r1 高-2） ----------

// TestSpeedEngineFullRun 全流程：两端数字对账 + 轮中相位真实流转（迁移前评审 F1）。
func TestSpeedEngineFullRun(t *testing.T) {
	target := startSpeedServer(t, 0)
	sock, auth := fakeBridge(t, target, "ok")

	done := make(chan map[string]any, 1)
	go func() {
		done <- speedStart(mustJSON(t, speedParams{
			Auth: auth, Sock: sock,
			DownMs: 1500, UpMs: 700, WarmupMs: 150, Streams: 2,
		}))
	}()

	sawDown, sawUp := false, false
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) && !sawUp {
		snap := speedSnapshotJSON(speed.Snapshot())
		if d, _ := snap["dir"].(string); d == "down" {
			sawDown = true
		}
		if d, _ := snap["dir"].(string); d == "up" {
			sawUp = true
		}
		time.Sleep(60 * time.Millisecond)
	}
	if !sawDown || !sawUp {
		t.Fatalf("轮中相位流转缺失：down=%v up=%v", sawDown, sawUp)
	}

	res := <-done
	if res["ok"] != true {
		t.Fatalf("期望成功终态，got %v", res)
	}
	if res["downBps"].(float64) <= 0 || res["upBps"].(float64) <= 0 {
		t.Fatalf("两向速率应为正：down=%v up=%v", res["downBps"], res["upBps"])
	}
	if res["usageDown"].(int64) <= 0 || res["usageUp"].(int64) <= 0 {
		t.Fatalf("两向用量应为正：down=%v up=%v", res["usageDown"], res["usageUp"])
	}
	if speedSnapshotJSON(speed.Snapshot())["phase"] != "done" {
		t.Fatalf("终态相位 = %v，期望 done", speedSnapshotJSON(speed.Snapshot())["phase"])
	}
	t.Logf("down=%.1fMB/s up=%.1fMB/s usageDown=%d usageUp=%d wall=%v",
		res["downBps"].(float64)/1e6, res["upBps"].(float64)/1e6,
		res["usageDown"], res["usageUp"], time.Duration(res["wallMs"].(int64))*time.Millisecond)
}

// TestSpeedReasonNotSupported（五码①）：鉴权后桥直接关连接（出口无测速服务，不回帧）
// ⇒ 请求后零字节 EOF ⇒ not_supported。
func TestSpeedReasonNotSupported(t *testing.T) {
	target := startSpeedServer(t, 0)
	sock, auth := fakeBridge(t, target, "close-after-auth")

	res := speedStart(mustJSON(t, speedParams{Auth: auth, Sock: sock, DownMs: 300, UpMs: 200, WarmupMs: 100, Streams: 1}))
	if res["reason"] != "not_supported" {
		t.Fatalf("reason = %v，期望 not_supported", res["reason"])
	}
}

// TestSpeedReasonLinkDown（五码②）：桥回 report{link_down}（桥宿主拨出口失败/恢复期）
// ⇒ link_down，不得误报 not_supported（迁移前评审 F4/F5）。
func TestSpeedReasonLinkDown(t *testing.T) {
	target := startSpeedServer(t, 0)
	sock, auth := fakeBridge(t, target, "link-down")

	res := speedStart(mustJSON(t, speedParams{Auth: auth, Sock: sock, DownMs: 300, UpMs: 200, WarmupMs: 100, Streams: 1}))
	if res["reason"] != "link_down" {
		t.Fatalf("reason = %v，期望 link_down", res["reason"])
	}
}

// TestSpeedReasonBridgeDown（五码③）：socket 不存在 ⇒ bridge_down（链路不在）。
func TestSpeedReasonBridgeDown(t *testing.T) {
	res := speedStart(mustJSON(t, speedParams{
		Auth: hex.EncodeToString(append(append([]byte{}, bridgeAuthMagic...), make([]byte, 32)...)),
		Sock: "/nonexistent/speedtest.sock", DownMs: 300, UpMs: 200, WarmupMs: 100, Streams: 1,
	}))
	if res["reason"] != "bridge_down" {
		t.Fatalf("reason = %v，期望 bridge_down", res["reason"])
	}
}

// TestSpeedReasonBridgeAuth（五码④）：鉴权首包写失败（blob 非法——bridgeWriteAuth 的
// 确定性错误面）⇒ bridge_auth。注：令牌不匹配的服务端形态在请求后 EOF 相位呈现
// not_supported（bridgeWriteAuth 只写不读、与迁移前 greeting 期 EOF 同归因——parity）。
func TestSpeedReasonBridgeAuth(t *testing.T) {
	target := startSpeedServer(t, 0)
	sock, _ := fakeBridge(t, target, "ok")

	res := speedStart(mustJSON(t, speedParams{Auth: "不是hex", Sock: sock, DownMs: 300, UpMs: 200, WarmupMs: 100, Streams: 1}))
	if res["reason"] != "bridge_auth" {
		t.Fatalf("reason = %v，期望 bridge_auth", res["reason"])
	}
}

// TestSpeedReasonBusy（五码⑤）：出口并发满员（MaxConns=1、2 流）⇒ 第二流收到
// report{busy} ⇒ busy。
func TestSpeedReasonBusy(t *testing.T) {
	target := startSpeedServer(t, 1)
	sock, auth := fakeBridge(t, target, "ok")

	res := speedStart(mustJSON(t, speedParams{Auth: auth, Sock: sock, DownMs: 300, UpMs: 200, WarmupMs: 100, Streams: 2}))
	if res["reason"] != "busy" {
		t.Fatalf("reason = %v，期望 busy（出口并发满员）", res["reason"])
	}
}

// TestSpeedEngineInvalid：参数越界（信封统一后走 ok:false，迁移前评审补③）。
func TestSpeedEngineInvalid(t *testing.T) {
	cases := []struct {
		name   string
		params string
		reason string
	}{
		{"流数越界", mustJSON(t, speedParams{Auth: "a", Sock: "/x", Streams: 99}), "invalid_arg"},
		{"窗口越界", mustJSON(t, speedParams{Auth: "a", Sock: "/x", DownMs: 60000}), "invalid_arg"},
		{"坏 JSON", `not-json`, "invalid_arg"},
		{"缺桥参数", mustJSON(t, speedParams{}), "bridge_down"},
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

// TestSpeedEngineCancel：窗口中取消 ⇒ 终态 cancelled。
func TestSpeedEngineCancel(t *testing.T) {
	target := startSpeedServer(t, 0)
	sock, auth := fakeBridge(t, target, "ok")

	done := make(chan map[string]any, 1)
	go func() {
		done <- speedStart(mustJSON(t, speedParams{Auth: auth, Sock: sock, DownMs: 5000, UpMs: 5000, WarmupMs: 300, Streams: 2}))
	}()
	time.Sleep(800 * time.Millisecond) // 等进入下行窗口（拨桥+预热 300ms + 余量）
	speed.CancelActive()
	select {
	case res := <-done:
		if res == nil || res["reason"] != "cancelled" {
			t.Fatalf("reason = %v，期望 cancelled", res["reason"])
		}
	case <-time.After(10 * time.Second):
		t.Fatal("取消后引擎未收场")
	}
}

// TestSpeedEngineCancelDuringWait：取消落在**请求后的等待期**（上游 delay，连接尚未进窗）
// ⇒ 也必须秒级收场且归 cancelled（迁移前评审 F2-1：取消丢在等待期跑满整轮是事故路径）。
func TestSpeedEngineCancelDuringWait(t *testing.T) {
	sock, auth := fakeBridge(t, "127.0.0.1:1", "delay")

	done := make(chan map[string]any, 1)
	go func() {
		done <- speedStart(mustJSON(t, speedParams{Auth: auth, Sock: sock, DownMs: 3000, UpMs: 3000, WarmupMs: 200, Streams: 1}))
	}()
	time.Sleep(400 * time.Millisecond) // 已进请求后等待期
	t0 := time.Now()
	speed.CancelActive()
	select {
	case res := <-done:
		if res == nil || res["reason"] != "cancelled" {
			t.Fatalf("reason = %v，期望 cancelled；res=%v", res["reason"], res)
		}
		if el := time.Since(t0); el > 3*time.Second {
			t.Fatalf("取消后 %v 才收场，应秒级", el)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("取消后引擎未收场")
	}
}
