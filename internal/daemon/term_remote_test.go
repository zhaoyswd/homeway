package daemon

// term_remote_test.go — RemoteTerm 缝的 daemon 侧单测（term-remote 1.1–1.3）：
// 真 control 服务器（control.sock）+ 假 Backend（两台主机入表）+ 假目标主机 term
// 服务（TCP，最小帧协议）——寻址统一（名称/全长/短前缀）、错误面三层逐态、
// streamConn 适配器（Recv 跨帧读/End 后 EOF/Write 透传/Close 逃生口红绿）、
// 远程 attach 的分离键逃生口（PTY 全链：灌满下行 + 停读 + 分离键 → 有限时间退出）。

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/zhaoyswd/homeway/internal/control"
	"github.com/zhaoyswd/homeway/pkg/term"
)

// ---- 假宿主（control.Backend 最小实现：两台主机 + DialTerm 记账）----

type remoteTestBackend struct {
	mu       sync.Mutex
	hosts    []control.HostState
	dialAddr string           // DialTerm 实际拨的假 term 后端
	dialErr  map[string]error // host -> 拨号错误
	dialed   []string         // DialTerm 收到的 host
	notReady bool
}

func (b *remoteTestBackend) ServerVersion() string { return "test-1.0" }
func (b *remoteTestBackend) RolesStatus() []control.RoleBrief {
	return nil
}
func (b *remoteTestBackend) HostBriefs() []control.HostBrief {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]control.HostBrief, 0, len(b.hosts))
	for _, h := range b.hosts {
		out = append(out, control.HostBrief{ID: h.ID, Name: h.Name, AddedAt: h.AddedAt})
	}
	return out
}
func (b *remoteTestBackend) AddHost(name, token string, force bool) (control.HostAddResult, error) {
	return control.HostAddResult{}, errors.New("未实现")
}
func (b *remoteTestBackend) RemoveHost(id string) error { return errors.New("未实现") }
func (b *remoteTestBackend) HostStates() []control.HostState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]control.HostState(nil), b.hosts...)
}
func (b *remoteTestBackend) DialTerm(ctx context.Context, host string) (net.Conn, error) {
	b.mu.Lock()
	b.dialed = append(b.dialed, host)
	err := b.dialErr[host]
	addr := b.dialAddr
	known := false
	for _, h := range b.hosts {
		if h.ID == host {
			known = true
			break
		}
	}
	b.mu.Unlock()
	if !known {
		return nil, control.ErrBackendNoHost // 与真 controlBackend 同径：表外/非法 id → no_host
	}
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}
func (b *remoteTestBackend) NotReady() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.notReady
}

// ---- term 帧最小编解码（pkg/term 帧格式：[op:1][len:2 LE][payload]）----

func encTermFrame(op byte, payload []byte) []byte {
	out := make([]byte, 3+len(payload))
	out[0] = op
	binary.LittleEndian.PutUint16(out[1:3], uint16(len(payload)))
	copy(out[3:], payload)
	return out
}

func readTermFrameRaw(r io.Reader) (byte, []byte, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.LittleEndian.Uint16(hdr[1:3]))
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return 0, nil, err
	}
	return hdr[0], p, nil
}

// term op（与 pkg/term/frames.go 同值；测试自带最小副本避免引未导出符号）。
const (
	tOpHello    = 0x00
	tOpData     = 0x01
	tOpList     = 0x04
	tOpAttached = 0x09
	tOpGreeting = 0x0C
)

// 假目标主机 term 服务：GREETING → HELLO 回 ATTACHED。模式：
//
//	echo=true   DATA 原样回显（透传/重组断言）
//	flood=true  接入后持续狂吐 DATA（灌满服务端队列 + socket + 客户端 recv）
//	noread=true 接入后**一个字节都不再读**（驱动上行背压收流；上行计数停在 HELLO）
type fakeTermHost struct {
	ln     net.Listener
	echo   bool
	flood  bool
	noread bool

	mu      sync.Mutex
	written int // 后端累计收到的上行字节数（写计数断言）
	conns   map[net.Conn]struct{}
}

func startFakeTermHost(t *testing.T, echo, flood, noread bool) *fakeTermHost {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := &fakeTermHost{ln: ln, echo: echo, flood: flood, noread: noread, conns: map[net.Conn]struct{}{}}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			h.mu.Lock()
			h.conns[c] = struct{}{}
			h.mu.Unlock()
			go h.serve(c)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		h.mu.Lock()
		for c := range h.conns {
			_ = c.Close()
		}
		h.mu.Unlock()
	})
	return h
}

func (h *fakeTermHost) serve(c net.Conn) {
	defer func() {
		h.mu.Lock()
		delete(h.conns, c)
		h.mu.Unlock()
		_ = c.Close()
	}()
	// GREETING（CLI 只查 op，载荷不解析）。
	if _, err := c.Write(encTermFrame(tOpGreeting, make([]byte, 5))); err != nil {
		return
	}
	writeData := func(payload []byte) bool {
		_, err := c.Write(encTermFrame(tOpData, payload))
		return err == nil
	}
	for {
		op, p, err := readTermFrameRaw(c)
		if err != nil {
			return
		}
		h.mu.Lock()
		h.written += len(p)
		h.mu.Unlock()
		switch op {
		case tOpHello:
			if _, err := c.Write(encTermFrame(tOpAttached, nil)); err != nil {
				return
			}
			if h.flood {
				// 狂吐：块大块写（不等读端），把服务端队列 + socket + 客户端 recv 全灌满。
				chunk := make([]byte, 8<<10)
				go func() {
					for i := 0; i < 512; i++ { // 4MiB，足够灌满全链缓冲
						if !writeData(chunk) {
							return
						}
					}
				}()
			}
			if h.noread {
				// 不再读上行：socket 缓冲 + 服务端 upC 灌满 → 服务端按背压收流
				//（finish(gone)）；挂到 conn 被关（defer 收尾）。
				block := make(chan struct{})
				<-block
			}
		case tOpData:
			if h.echo {
				if _, err := c.Write(encTermFrame(tOpData, p)); err != nil {
					return
				}
			}
		}
	}
}

func (h *fakeTermHost) writtenBytes() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.written
}

// ---- 装配：control 服务器 + 两台主机入表 ----

type remoteTestRig struct {
	dir     string // daemon state（control.sock 所在）
	backend *remoteTestBackend
	srv     *control.Server
	host    *fakeTermHost
	macID   string // 主机 mac 的全长 hex id
	aliID   string
}

const (
	rtMacID = "aa11223344556677889900aabbccddeeff00112233445566778899aabbccddee"
	rtAliID = "bb11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff"
)

func startRemoteTestRig(t *testing.T, echo, flood, noread bool) *remoteTestRig {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "termremote-") // 短路径（sun_path 上限）
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	host := startFakeTermHost(t, echo, flood, noread)
	backend := &remoteTestBackend{
		dialAddr: host.ln.Addr().String(),
		dialErr:  map[string]error{},
		hosts: []control.HostState{
			{ID: rtMacID, Name: "mac", State: "ready"},
			{ID: rtAliID, Name: "ali", State: "ready"},
		},
	}
	srv := control.NewServer(control.ServerConfig{
		ServerVersion: "test-1.0",
		Bus:           control.NewBus(control.NewGeneration(), control.BusConfig{}),
		Backend:       backend,
		Logf:          t.Logf,
	})
	sock, ln, err := control.ListenControl(dir)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Close)
	_ = sock
	return &remoteTestRig{dir: dir, backend: backend, srv: srv, host: host, macID: rtMacID, aliID: rtAliID}
}

func rtCtx(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), 10*time.Second)
}

// ---- 1.2 寻址统一：名称/全长/短前缀 + 歧义/不存在/非法/空串逐态 ----

func TestTermRemoteResolveAddressing(t *testing.T) {
	rig := startRemoteTestRig(t, true, false, false)
	r := TermRemote("test")

	// 名称精确 / 全长 hex / 无歧义短前缀 三种 ref 均达对应主机。
	for _, c := range []struct{ ref, wantID, wantName string }{
		{"mac", rtMacID, "mac"},
		{"ali", rtAliID, "ali"},
		{rtMacID, rtMacID, "mac"},
		{"bb11223344556677889900", rtAliID, "ali"}, // 无歧义前缀（bb… 唯一）
	} {
		ctx, cancel := rtCtx(t)
		id, name, err := r.ResolveHostRef(ctx, rig.dir, c.ref)
		cancel()
		if err != nil || id != c.wantID || name != c.wantName {
			t.Fatalf("ref %q 解析 = (%q,%q,%v)，期望 (%q,%q,nil)", c.ref, id, name, err, c.wantID, c.wantName)
		}
	}

	// 歧义前缀：列候选（与 host delete 同一文案源 resolveHostTarget）——第三台主机
	// 与 mac 共享 "aa11" 前缀。
	rig.backend.mu.Lock()
	rig.backend.hosts = append(rig.backend.hosts, control.HostState{ID: "aa11" + strings.Repeat("9", 60), Name: "mac2", State: "ready"})
	rig.backend.mu.Unlock()
	ctx, cancel := rtCtx(t)
	_, _, err := r.ResolveHostRef(ctx, rig.dir, "aa11")
	cancel()
	if err == nil || !strings.Contains(err.Error(), "歧义") || !strings.Contains(err.Error(), "候选") {
		t.Fatalf("歧义前缀应报错列候选：%v", err)
	}

	// 不存在。
	ctx, cancel = rtCtx(t)
	_, _, err = r.ResolveHostRef(ctx, rig.dir, "nope")
	cancel()
	if err == nil || !strings.Contains(err.Error(), "不存在") {
		t.Fatalf("不存在应报错：%v", err)
	}

	// 空串：term 面文案（不出现 host delete）。
	ctx, cancel = rtCtx(t)
	_, _, err = r.ResolveHostRef(ctx, rig.dir, "")
	cancel()
	if err == nil || !strings.Contains(err.Error(), "--host 需要") {
		t.Fatalf("空串应报 term 面文案：%v", err)
	}
	if strings.Contains(fmt.Sprint(err), "host delete") {
		t.Fatalf("term 面不出现 host delete 文案：%v", err)
	}

	// stateDir 空串 = 默认 daemon state（对无 daemon 的环境报连接层错误，不 panic）。
	ctx, cancel = rtCtx(t)
	_, _, err = r.ResolveHostRef(ctx, "", "mac")
	cancel()
	if err == nil {
		t.Fatal("默认 state 无 daemon 应报错")
	}
}

// ---- 1.1/1.2 端到端：DialTerm 经控制面到假主机（GREETING/LIST 往返 + hexID 断言）----

func TestTermRemoteDialEndToEnd(t *testing.T) {
	rig := startRemoteTestRig(t, true, false, false)
	r := TermRemote("test")

	ctx, cancel := rtCtx(t)
	defer cancel()
	conn, err := r.DialTerm(ctx, rig.dir, rig.macID)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	rig.backend.mu.Lock()
	dialed := append([]string{}, rig.backend.dialed...)
	rig.backend.mu.Unlock()
	if len(dialed) != 1 || dialed[0] != rig.macID {
		t.Fatalf("DialTerm 应带 hexID 到达 Backend：%v", dialed)
	}
	// GREETING 经缝可读（CLI 的统一拨号路径读的就是它）。
	op, _, err := readTermFrameRaw(conn)
	if err != nil || op != tOpGreeting {
		t.Fatalf("经缝首帧应为 GREETING：op=0x%02x err=%v", op, err)
	}
	// Write（term DATA 帧）→ 假主机回显 → Read（适配器跨帧重组：流上承载的是
	// term 协议字节，回显的是整帧）。
	payload := []byte("hello-through-tunnel")
	if _, err := conn.Write(encTermFrame(tOpData, payload)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 0, 3+len(payload))
	deadline := time.After(5 * time.Second)
	buf := make([]byte, 7) // 小读缓冲：强制跨帧重组
	for len(got) < 3+len(payload) {
		type res struct {
			n   int
			err error
		}
		ch := make(chan res, 1)
		go func() {
			n, err := conn.Read(buf)
			ch <- res{n, err}
		}()
		select {
		case rr := <-ch:
			if rr.err != nil {
				t.Fatalf("Read：%v", rr.err)
			}
			got = append(got, buf[:rr.n]...)
		case <-deadline:
			t.Fatalf("echo 未回齐：%q", got)
		}
	}
	op, echoed, err := readTermFrameRaw(bytes.NewReader(got))
	if err != nil || op != tOpData || string(echoed) != string(payload) {
		t.Fatalf("透传字节不符：op=0x%02x payload=%q err=%v", op, echoed, err)
	}
}

// ---- 1.1 适配器单测：End 后 EOF（排干余量）与连接级断开 ----

func TestStreamConnEndThenEOF(t *testing.T) {
	rig := startRemoteTestRig(t, true, false, false)
	r := TermRemote("test")
	ctx, cancel := rtCtx(t)
	defer cancel()
	conn, err := r.DialTerm(ctx, rig.dir, rig.macID)
	if err != nil {
		t.Fatal(err)
	}

	// 服务端收工 → 连接级断开（无 end）：Read 排干余量后以 RemoteEndError{conn}
	// 终结（errors.Is io.EOF 成立）。
	rig.srv.Close()
	deadline := time.After(5 * time.Second)
	for {
		buf := make([]byte, 256)
		type res struct {
			n   int
			err error
		}
		ch := make(chan res, 1)
		go func() { n, err := conn.Read(buf); ch <- res{n, err} }()
		select {
		case rr := <-ch:
			if rr.err == nil {
				continue // 余量排干
			}
			var re *term.RemoteEndError
			if !errors.As(rr.err, &re) || re.Reason != term.RemoteEndConn {
				t.Fatalf("连接级断开应终结为 RemoteEndError{conn}：%v", rr.err)
			}
			if !errors.Is(rr.err, io.EOF) {
				t.Fatalf("终结错误应 errors.Is io.EOF：%v", rr.err)
			}
			return
		case <-deadline:
			t.Fatal("连接断开后 Read 未在有限时间内终结")
		}
	}
}

// TestStreamConnCloseEscapeHatch Close 逃生口红绿（1.1/1.3 判据，r1 P0-2）：假主机
// 持续狂吐（flood）→ 服务端队列 + socket + 客户端 recv（64 槽）全满、消费方停读
// （不调 Read）→ reader 阻塞在 recv<- → 触发 Close —— 必须在有限时间内返回
// （先 Client.Close()：closed 信号解阻塞 reader；不依赖 reader 前进）。反序
// （先 stream.Close 等 rsp）在该场景恒挂死——rsp 由被阻塞的 reader 投递。
func TestStreamConnCloseEscapeHatch(t *testing.T) {
	rig := startRemoteTestRig(t, true, true, false) // flood
	r := TermRemote("test")
	ctx, cancel := rtCtx(t)
	defer cancel()
	conn, err := r.DialTerm(ctx, rig.dir, rig.macID)
	if err != nil {
		t.Fatal(err)
	}
	// 停读窗口：等 flood 灌满全链（客户端 recv 64 槽 + 服务端 16 条 + TCP）。
	time.Sleep(1200 * time.Millisecond)

	done := make(chan error, 1)
	go func() { done <- conn.Close() }()
	select {
	case <-done:
		// 绿：有限时间内返回。
	case <-time.After(8 * time.Second):
		t.Fatal("Close 未在有限时间内返回（逃生口失效——检查 Client.Close 先行的定序）")
	}
	// Close 后 Read 立即终结（连接断开路径），不再挂等 reader。
	go func() {
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
	}()
}

// ---- 1.3 错误面三层逐态（层① controlDialErr / 层② streamOpenErr 纯函数）----

func TestControlDialErrStates(t *testing.T) {
	sock := "/tmp/fake-state/control.sock"
	cases := []struct {
		name string
		err  error
		want []string
	}{
		{"ENOENT", &fs.PathError{Op: "dial", Path: sock, Err: syscall.ENOENT},
			[]string{"daemon 未在运行", "--state 指守护进程 state", "homeway daemon --state"}},
		{"ECONNREFUSED", &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)},
			[]string{"残留 socket"}},
		{"EACCES", &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.EACCES)},
			[]string{"无权连接", "同一用户"}},
		{"其它", errors.New("boom"), []string{"连不上 daemon 控制面", sock}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := controlDialErr("/tmp/fake-state", sock, c.err)
			for _, w := range c.want {
				if !strings.Contains(got.Error(), w) {
					t.Fatalf("缺 %q：%v", w, got)
				}
			}
		})
	}
	// ENOENT + 目录里有 term.sock（像是误指出口 state）：点名提示。
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "term.sock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	got := controlDialErr(dir, filepath.Join(dir, "control.sock"), &fs.PathError{Op: "dial", Err: syscall.ENOENT})
	if !strings.Contains(got.Error(), "出口 state") {
		t.Fatalf("误指出口 state 应点名：%v", got)
	}
}

func TestStreamOpenErrStates(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want []string
	}{
		{"no_host", control.CodeError(control.CodeNoHost), []string{"不在守护进程表中", "host list"}},
		{"not_ready", control.CodeError(control.CodeNotReady), []string{"未就绪", "稍后重试"}},
		{"stream_refused", control.CodeError(control.CodeStreamRefused), []string{"主机离线", "host status"}},
		{"超预算", context.DeadlineExceeded, []string{"超预算", "--timeout"}},
		{"其它", errors.New("boom"), []string{"stream.open 失败"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := streamOpenErr(c.err)
			for _, w := range c.want {
				if !strings.Contains(got.Error(), w) {
					t.Fatalf("缺 %q：%v", w, got)
				}
			}
		})
	}
}

// ---- 1.3 层② 实路径：DialTerm 对 stream.open 错误码的翻文案 ----

func TestTermRemoteDialOpenErrors(t *testing.T) {
	rig := startRemoteTestRig(t, true, false, false)
	r := TermRemote("test")

	// not_ready。
	rig.backend.mu.Lock()
	rig.backend.notReady = true
	rig.backend.mu.Unlock()
	ctx, cancel := rtCtx(t)
	_, err := r.DialTerm(ctx, rig.dir, rig.macID)
	cancel()
	if err == nil || !strings.Contains(err.Error(), "未就绪") {
		t.Fatalf("not_ready 文案：%v", err)
	}

	// stream_refused（会话不在/隧道拨号失败——主机离线主文案面）。
	rig.backend.mu.Lock()
	rig.backend.notReady = false
	rig.backend.dialErr[rig.macID] = control.ErrBackendNoSession
	rig.backend.mu.Unlock()
	ctx, cancel = rtCtx(t)
	_, err = r.DialTerm(ctx, rig.dir, rig.macID)
	cancel()
	if err == nil || !strings.Contains(err.Error(), "stream_refused") || !strings.Contains(err.Error(), "主机离线") {
		t.Fatalf("stream_refused 文案：%v", err)
	}

	// no_host（寻址通过但表里没有/非法 hex）。
	ctx, cancel = rtCtx(t)
	_, err = r.DialTerm(ctx, rig.dir, strings.Repeat("cc", 32))
	cancel()
	if err == nil || !strings.Contains(err.Error(), "不在守护进程表中") {
		t.Fatalf("no_host 文案：%v", err)
	}

	// 层①：daemon 未运行（无 control.sock 的目录；短路径——t.TempDir() 的
	// /var/folders 路径超 sun_path 上限会变成 invalid argument 而非 ENOENT）。
	nodir, mkerr := os.MkdirTemp("/tmp", "termremote-nod-")
	if mkerr != nil {
		t.Fatal(mkerr)
	}
	t.Cleanup(func() { os.RemoveAll(nodir) })
	ctx, cancel = rtCtx(t)
	_, err = r.DialTerm(ctx, nodir, rig.macID)
	cancel()
	if err == nil || !strings.Contains(err.Error(), "daemon 未在运行") || !strings.Contains(err.Error(), "--state 指守护进程 state") {
		t.Fatalf("连接层文案（含 --state 指代提示）：%v", err)
	}
}

// ---- 1.3 attach 中途流死早退（写计数）+ 分离键逃生口（PTY 全链）----

// TestRemoteAttachDetachUnderFlood 远程 attach 全链（term.CLI + 真控制面 + 假主机
// flood）：假主机狂吐 + 无人读 master（pty 输出缓冲满 → CLI 主循环停在 out.Write →
// 停读 → recv 64 槽满 → 客户端 reader 阻塞在 recv<-）→ 敲分离键 Ctrl-b d（输入
// 路径与被阻塞的输出路径独立）→ exitCleanly → streamConn.Close（先 Client.Close）
// → reader 解阻塞 → 恢复排 master → 主循环读失败走 detachCh → CLI 干净退出
// （nil）。模拟 Ctrl-S 冻结输出后按分离键再 Ctrl-Q 的真实序列。
func TestRemoteAttachDetachUnderFlood(t *testing.T) {
	rig := startRemoteTestRig(t, true, true, false) // flood
	remote := TermRemote("test")

	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = slave, slave
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut }()

	done := make(chan error, 1)
	go func() {
		done <- term.CLI([]string{"attach", "s1", "--host", "mac", "--state", rig.dir, "--detach-key", "^b"}, remote)
	}()
	// 停读窗口：不排 master，等 flood 灌满全链（pty 缓冲 → CLI 主循环 out.Write
	// 阻塞 → recv 64 槽满 → reader 阻塞投递）。
	time.Sleep(2 * time.Second)
	// 分离键：master → slave（输入路径独立于被阻塞的输出路径）。
	if _, err := master.Write([]byte{0x02, 'd'}); err != nil {
		t.Fatal(err)
	}
	// 恢复排 master（Ctrl-Q）：主循环的 out.Write 解除阻塞、读端随即撞上已关的流
	// → detachCh → return nil。
	go func() { _, _ = io.Copy(io.Discard, master) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("分离应干净退出（nil）：%v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("分离键未在有限时间内退出（逃生口失效——检查 Close 定序/输入循环）")
	}
}

// TestRemoteAttachEarlyExitOnDeadStream attach 中途流死早退（1.3 判据：灌 1MiB
// 中途收流 → 未把余量推进死流）：假主机 HELLO 后不再读（noread）→ 客户端上行
// 1MiB 分片连发 → 服务端 upC（8 槽）+ socket 缓冲满 → finish(gone) → 流收尾后
// streamConn.Write 报错 → 写计数（假主机实际收到的上行字节）远小于 1MiB。
func TestRemoteAttachEarlyExitOnDeadStream(t *testing.T) {
	rig := startRemoteTestRig(t, false, false, true) // 不回显、HELLO 后不读上行
	r := TermRemote("test")
	ctx, cancel := rtCtx(t)
	defer cancel()
	conn, err := r.DialTerm(ctx, rig.dir, rig.macID)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if op, _, err := readTermFrameRaw(conn); err != nil || op != tOpGreeting {
		t.Fatalf("GREETING：op=0x%02x err=%v", op, err)
	}
	// HELLO → ATTACHED（触发假主机进入不读模式；与 CLI attach 的拨号序列同形）。
	if _, err := conn.Write(encTermFrame(tOpHello, nil)); err != nil {
		t.Fatal(err)
	}
	if op, _, err := readTermFrameRaw(conn); err != nil || op != tOpAttached {
		t.Fatalf("ATTACHED：op=0x%02x err=%v", op, err)
	}

	// 灌 1MiB（connSendData 同款分片语义：16KiB/帧）。socket 缓冲会先吸收一段，
	// 预算内持续连发直到 Write 报错（流已被背压收流）。
	chunk := make([]byte, 16<<10)
	sent, failed := 0, 0
	deadline := time.After(15 * time.Second)
	for i := 0; i < 128 && failed == 0; i++ { // 2MiB 上限：> upC 8×16KiB + 双侧 socket
		if _, err := conn.Write(chunk); err != nil {
			failed = i + 1
			if !strings.Contains(err.Error(), "流已终结") {
				t.Fatalf("死流 Write 应报 ErrStreamEnded 族错误：%v", err)
			}
			break
		}
		sent += len(chunk)
		select {
		case <-deadline:
			t.Fatalf("流未收尾（128 帧内无 gone）：%d 帧已发", i)
		default:
			time.Sleep(30 * time.Millisecond) // 给服务端 upC 满 → finish(gone) 的窗口
		}
	}
	if failed == 0 {
		t.Fatal("对端不读 + 背靠背连发：流应被背压收流（后续 Write 报错）")
	}
	// 写计数：假主机真收到的上行字节远小于发送量（余量没推进死流）。
	time.Sleep(200 * time.Millisecond)
	got := rig.host.writtenBytes()
	if int64(got) > int64(sent)/2 {
		t.Fatalf("死流余量被推进（假主机收到 %d 字节 > 已接受 %d 的一半）", got, sent)
	}
	t.Logf("流死于第 %d 帧；假主机实收 %d 字节 / 已接受 %d 字节", failed, got, sent)
}
