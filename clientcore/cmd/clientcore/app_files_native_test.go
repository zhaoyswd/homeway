//go:build cshared

// app_files_native_test.go — files 客户端路径的读边界。
package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/files"
)

// 冻结对端（listen 但永不 accept）+ 短 ctx：nativeFilesDial 必须把 ctx 期限落到
// conn deadline——读在期限内超时返回，而不是无限挂死。钉住「退后台回前台后文件页
// 永远连接中」的根因修复（pkg/files 的 Open/call 读侧不吃 ctx，conn deadline 是
// 唯一有效边界点）。
func TestNativeFilesDialDeadlineBoundsSilentPeer(t *testing.T) {
	dir := shortBridgeDir(t) // t.TempDir 路径长，叠上 .sock 会顶过 sun_path 上限（见其注释）
	sock := filepath.Join(dir, "files.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() // 永不 Accept：UDS 拨号由内核 backlog 代答 = 冻结宿主的形态

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	// 96 个 hex 字符 = 48 字节首包（bridgeWriteAuth 只验长度；服务端没人读）。
	conn, err := nativeFilesDial(ctx, strings.Repeat("ab", 48), sock)
	if err != nil {
		t.Fatalf("dial（应成功——内核代答）: %v", err)
	}
	defer conn.Close()

	type readRes struct {
		err error
	}
	ch := make(chan readRes, 1)
	go func() {
		buf := make([]byte, 64)
		_, rerr := conn.Read(buf)
		ch <- readRes{err: rerr}
	}()
	select {
	case r := <-ch:
		if r.err == nil {
			t.Fatal("冻结对端不该有应答（读到数据）")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("读未被 ctx deadline 界定（2s 仍在挂）——SetDeadline 路径回归")
	}
}

// 操作路径的流开场失败归一（openspec bridge-call-layer）：
// 出口不可达时，op 级失败原本以 op_failed 露出「操作失败：读问候帧失败：EOF」，
// App 侧认不出这是通道不可达（它的域码表里通道码是 bridge_down）⇒ 翻目录会立刻落错误面。
// 2026-09-26 起判据从「三条文案前缀」改为**稳定码** `stream_open`（homeway pkg/files 的
// files.CodeStreamOpen）：文案改一句就静默失效的脆弱做法退役。三条边界：
//
//	① 开场失败（stream_open，任意文案）→ bridge_down；
//	② op_failed 一律不归一（出口侧真实失败 / 响应丢失 / 甚至连旧问候文案都不特判）；
//	③ 其它稳定码与 nil 原样透传。
func TestNormalizeOpStreamErr(t *testing.T) {
	cases := []struct {
		name string
		in   *filesError
		want string
	}{
		{"开场·读问候失败", filesErrf("stream_open", "读问候帧失败：EOF"), "bridge_down"},
		{"开场·问候不是 JSON", filesErrf("stream_open", "问候帧不是 JSON：unexpected end"), "bridge_down"},
		{"开场·问候失败", filesErrf("stream_open", "问候帧失败"), "bridge_down"},
		// 文案变化不影响判定（这正是换码的理由）：随便什么 msg 都算开场
		{"开场·未来改过的文案", filesErrf("stream_open", "greeting read failed: i/o timeout"), "bridge_down"},
		// ①'：旧做法认的三条文案，若码是 op_failed 则**不再**特判（码才是契约）
		{"op_failed·旧问候文案不再特判", filesErrf("op_failed", "读问候帧失败：EOF"), "op_failed"},
		// 出口侧真实的操作失败（server.go 也是 op_failed）：改判会把「出口拒绝该操作」谎报成
		// 通道不可用，还会触发 App 侧自动重放。
		{"出口侧 op_failed", filesErrf("op_failed", "open /root/x: permission denied"), "op_failed"},
		// call 阶段（可能已送达、响应丢了）不得改判：App 会对 bridge_down 自动重放。
		{"call·发请求失败", filesErrf("op_failed", "发请求失败：broken pipe"), "op_failed"},
		{"call·读响应失败", filesErrf("op_failed", "读响应失败：EOF"), "op_failed"},
		{"稳定码透传·permission", filesErrf("permission", "只读根"), "permission"},
		{"稳定码透传·bridge_auth", filesErrf("bridge_auth", "鉴权失败"), "bridge_auth"},
		{"稳定码透传·no_session", filesErrf("no_session", "会话不存在"), "no_session"},
	}
	for _, c := range cases {
		got := normalizeOpStreamErr(c.in)
		if got == nil {
			t.Fatalf("%s: 归一化不该返回 nil", c.name)
		}
		if got.Code != c.want {
			t.Errorf("%s: 码 = %q，期望 %q", c.name, got.Code, c.want)
		}
	}
	if normalizeOpStreamErr(nil) != nil {
		t.Error("nil 必须原样返回（调用方按 nil 判无错）")
	}
}

// 传输开场警戒（2026-09-26，b 案）：传输流的开场（拨号+问候+请求响应）超过
// transferOpenBudget 还没有第一个正文字节时，警戒把连接读期限拨到「立刻」，
// 卡在无 deadline 读上的传输 goroutine 带错退出（done=true）——否则它永久占着
// 会话传输表（再点下载报 busy）与桥连接坑位。两条边界：
//
//	① 对端冻结（不说话）→ 预算到点收口，错误带 stream_open（问候阶段失败）；
//	② 正文开始流动 → 警戒解除，跨越预算总时长的慢传输必须完整跑完（传输体不受限）。
func TestTransferOpenGuardBreaksStuckOpen(t *testing.T) {
	old := transferOpenBudget
	transferOpenBudget = 80 * time.Millisecond
	t.Cleanup(func() { transferOpenBudget = old })

	dir := shortBridgeDir(t)
	sock := filepath.Join(dir, "files.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() // 永不 Accept：内核 backlog 代答 = 对端不说话的形态

	s := &nativeFilesSession{
		id: 1, cli: &files.Client{Dial: func(ctx context.Context) (net.Conn, error) {
			return net.Dial("unix", sock)
		}},
		txs: map[int]*filesTransfer{},
	}
	res, ferr := s.startNativeTransfer("download", "x.bin", filepath.Join(t.TempDir(), "out.bin"))
	if ferr != nil {
		t.Fatalf("startNativeTransfer: %v", ferr)
	}
	id := int(res["transferId"].(int))
	waitTransferDone(t, s, id, 2*time.Second, func(errText string, bytes int64) {
		if !strings.Contains(errText, "stream_open") {
			t.Fatalf("开场超时应以 stream_open 露出（问候阶段失败），实际 = %q", errText)
		}
	})
}

func TestTransferOpenGuardDisarmedOnceBodyFlows(t *testing.T) {
	old := transferOpenBudget
	transferOpenBudget = 80 * time.Millisecond
	t.Cleanup(func() { transferOpenBudget = old })

	dir := shortBridgeDir(t)
	sock := filepath.Join(dir, "files.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	// 假服务端：问候 → 收请求 → ok 响应 → 4 帧 × 60ms（总时长 240ms，跨越 80ms 预算）
	// → 终止帧。正文慢但持续流动：警戒必须在第一帧后解除，传输必须完整跑完。
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		fmt.Fprintf(c, `{"ok":true,"root":"/tmp","ver":1,"rw":true}`+"\n")
		br := bufio.NewReader(c)
		_, _ = br.ReadBytes('\n') // download 请求行
		fmt.Fprintf(c, `{"ok":true,"size":20}`+"\n")
		for i := 0; i < 4; i++ {
			time.Sleep(60 * time.Millisecond)
			var hdr [4]byte
			binary.BigEndian.PutUint32(hdr[:], 5)
			if _, err := c.Write(hdr[:]); err != nil {
				return
			}
			if _, err := c.Write([]byte("12345")); err != nil {
				return
			}
		}
		var term [4]byte // len=0 终止帧
		_, _ = c.Write(term[:])
	}()

	s := &nativeFilesSession{
		id: 1, cli: &files.Client{Dial: func(ctx context.Context) (net.Conn, error) {
			return net.Dial("unix", sock)
		}},
		txs: map[int]*filesTransfer{},
	}
	res, ferr := s.startNativeTransfer("download", "x.bin", filepath.Join(t.TempDir(), "out.bin"))
	if ferr != nil {
		t.Fatalf("startNativeTransfer: %v", ferr)
	}
	id := int(res["transferId"].(int))
	waitTransferDone(t, s, id, 3*time.Second, func(errText string, bytes int64) {
		if errText != "" {
			t.Fatalf("正文流动后不该被开场警戒打断，实际 = %q", errText)
		}
		if bytes != 20 {
			t.Fatalf("字节数 = %d，期望 20", bytes)
		}
	})
}

// waitTransferDone 轮询到传输落定（done=true）后调 check（在测试 goroutine 上断言）。
func waitTransferDone(t *testing.T, s *nativeFilesSession, id int, within time.Duration, check func(errText string, bytes int64)) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		s.txMu.Lock()
		tx := s.txs[id]
		done, errText, bytes := false, "", int64(0)
		if tx != nil {
			done, errText, bytes = tx.done, tx.err, tx.bytes
		}
		s.txMu.Unlock()
		if done {
			check(errText, bytes)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("传输 %d 在 %v 内没有落定（开场警戒未生效？）", id, within)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestNativeFilesDialHonorsCanceledCtx（FIX-39）：ctx 已取消时拨号必须**当场拒绝**，
// 而不是照常连上去（内核 backlog 会替冻结宿主代答，只看墙钟的实现分辨不出来）。
// 变异自证：把 DialContext 换回 net.DialTimeout ⇒ 本用例会拿到可用连接而红。
func TestNativeFilesDialHonorsCanceledCtx(t *testing.T) {
	dir := shortBridgeDir(t)
	sock := filepath.Join(dir, "files.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn, derr := nativeFilesDial(ctx, strings.Repeat("ab", 48), sock)
	if derr == nil {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatal("ctx 已取消仍拨通了——取消在途拨号的契约在生产拨号缝上不成立")
	}
	// 平台文案不统一（"context canceled" / "operation was canceled"）——按 cancel 判。
	if !strings.Contains(strings.ToLower(derr.Error()), "cancel") {
		t.Fatalf("应归因到 ctx 取消，实际 %v", derr)
	}
}

// stallAfterResponseDial 假桥：完成问候 + 读请求 + 回响应行（声明 size），随后**卡住
// 不发正文**——把客户端钉在「阻塞于 ReadFrame」的状态上，用来验取消/收工能否打断 I/O。
func stallAfterResponseDial(t *testing.T, declared int64) (files.StreamDial, chan struct{}) {
	t.Helper()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	dial := func(ctx context.Context) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go func() {
			defer c2.Close()
			if err := files.WriteLine(c2, files.Greeting{Ok: true, Root: "/fake", Ver: files.Version}); err != nil {
				return
			}
			br := bufio.NewReader(c2)
			if _, err := files.ReadRequest(br); err != nil {
				return
			}
			if err := files.WriteLine(c2, files.Response{Ok: true, Size: declared}); err != nil {
				return
			}
			<-release // 卡住：正文永不到来（客户端将长期阻塞在 Read）
		}()
		return c1, nil
	}
	return dial, release
}

// TestTransferCancelCutsBlockedIO（FIX-42）：传输正文阻塞中取消，必须**当场**打断
// 阻塞在读上的 I/O 并把传输落定（done=true / canceled）——只 close(cancel) 时
// Download 的读不吃 ctx，传输会永远卡在非 done 态（后续传输全被 busy 挡住）。
// 变异自证：去掉 cutBlockedIO 调用 ⇒ 本用例等满窗口仍不 done 而红。
func TestTransferCancelCutsBlockedIO(t *testing.T) {
	dial, _ := stallAfterResponseDial(t, 1<<20)
	s := &nativeFilesSession{id: 1, cli: &files.Client{Dial: dial}, txs: map[int]*filesTransfer{}}
	res, ferr := s.startNativeTransfer("download", "big.bin", filepath.Join(t.TempDir(), "out.bin"))
	if ferr != nil {
		t.Fatalf("startNativeTransfer: %v", ferr)
	}
	id := res["transferId"].(int)

	// 等它进入「已收响应行、卡在正文读」的稳态（首字节没来，bytes 仍为 0）。
	time.Sleep(150 * time.Millisecond)
	s.txMu.Lock()
	st := s.txs[id]
	s.txMu.Unlock()
	if st == nil || st.done {
		t.Fatalf("传输应还在跑（未 done）：%+v", st)
	}
	s.nativeCancel(id)
	waitTransferDone(t, s, id, 2*time.Second, func(errText string, bytes int64) {
		if !strings.Contains(errText, "canceled") && !strings.Contains(errText, "已取消") {
			t.Fatalf("取消后应落 canceled 归因，实际 = %q", errText)
		}
	})
}

// TestSessionShutdownCutsBlockedIO（FIX-42）：会话收工 / 表满淘汰走的是同一个
// shutdown()——同样要打断在途 I/O（淘汰路径此前只从会话表摘名，传输成孤儿）。
func TestSessionShutdownCutsBlockedIO(t *testing.T) {
	dial, _ := stallAfterResponseDial(t, 1<<20)
	s := &nativeFilesSession{id: 2, cli: &files.Client{Dial: dial}, txs: map[int]*filesTransfer{}}
	res, ferr := s.startNativeTransfer("download", "big.bin", filepath.Join(t.TempDir(), "out.bin"))
	if ferr != nil {
		t.Fatalf("startNativeTransfer: %v", ferr)
	}
	id := res["transferId"].(int)
	time.Sleep(150 * time.Millisecond)
	// shutdown 会把传输表清空——先拿住指针，直接观察它落定（表里查不到了是设计使然）。
	s.txMu.Lock()
	st := s.txs[id]
	s.txMu.Unlock()
	s.shutdown()
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.txMu.Lock()
		done, errText := st.done, st.err
		s.txMu.Unlock()
		if done {
			if !strings.Contains(errText, "canceled") && !strings.Contains(errText, "已取消") {
				t.Fatalf("收工后应落 canceled 归因，实际 = %q", errText)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("shutdown 后传输仍在阻塞（I/O 未被收口）")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
