package daemon

// files_remote_test.go — RemoteFiles 缝的 daemon 侧单测（files-cli 2.1–2.3）：
// 真 control 服务器（control.sock）+ 假 Backend（两台主机入表、kind=files 路由到
// 真 files.Server 的 TCP 监听）——寻址三 ref 形态与歧义/空串文案、files.CLI 经控制面
// 到真 files 服务端到端（list/get/put）、kind 到达 Backend 断言、streamConn 写路径
// 终结翻译（streamend.Error + 「流已终结」文案——term_remote_test 既有断言的同款
// 判据在 files 面）。term 面既有用例（term_remote_test.go）零改、随批回归。

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/internal/control"
	"github.com/zhaoyswd/homeway/pkg/files"
	"github.com/zhaoyswd/homeway/pkg/streamend"
)

// startFilesRig 在 term rig 上挂一个真 files.Server 的 TCP 监听（kind=files 的路由
// 目标）——files 协议端到端原样承载（协议零改动经控制面流）。
func startFilesRig(t *testing.T) (*remoteTestRig, *files.Server, string) {
	t.Helper()
	rig := startRemoteTestRig(t, true, false, false)
	root := filesRoot(t)
	srv, err := files.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })
	rig.backend.mu.Lock()
	rig.backend.filesDialAddr = ln.Addr().String()
	rig.backend.mu.Unlock()
	return rig, srv, root
}

func filesRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "filesrig-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello-files"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// rwNetConn：io.ReadWriteCloser → net.Conn 的最小适配（deadline 族不支持——CLI 面
// 的适配壳同款语义；本测试只用作 files.Client 的 StreamDial 返回值）。
type rwNetConn struct{ c io.ReadWriteCloser }

func (w rwNetConn) Read(p []byte) (int, error)       { return w.c.Read(p) }
func (w rwNetConn) Write(p []byte) (int, error)      { return w.c.Write(p) }
func (w rwNetConn) Close() error                     { return w.c.Close() }
func (w rwNetConn) LocalAddr() net.Addr              { return dummyRigAddr{} }
func (w rwNetConn) RemoteAddr() net.Addr             { return dummyRigAddr{} }
func (w rwNetConn) SetDeadline(time.Time) error      { return errRigNoDeadline }
func (w rwNetConn) SetReadDeadline(time.Time) error  { return errRigNoDeadline }
func (w rwNetConn) SetWriteDeadline(time.Time) error { return errRigNoDeadline }

var errRigNoDeadline = errors.New("测试适配不支持 deadline")

type dummyRigAddr struct{}

func (dummyRigAddr) Network() string { return "rig" }
func (dummyRigAddr) String() string  { return "rig" }

// filesClientOnRig 构造一条经 RemoteFiles 缝的 files.Client。
func filesClientOnRig(t *testing.T, r files.RemoteFiles, rig *remoteTestRig) *files.Client {
	return &files.Client{Dial: func(ctx context.Context) (net.Conn, error) {
		rw, err := r.DialFiles(ctx, rig.dir, rig.macID)
		if err != nil {
			return nil, err
		}
		return rwNetConn{rw}, nil
	}}
}

// ---- 2.2 Resolve：三 ref 形态与歧义/不存在/空串（files 面参数化文案）----

func TestFilesRemoteResolveAddressing(t *testing.T) {
	rig, _, _ := startFilesRig(t)
	r := FilesRemote("test")

	for _, c := range []struct{ ref, wantID, wantName string }{
		{"mac", rtMacID, "mac"},
		{"ali", rtAliID, "ali"},
		{rtMacID, rtMacID, "mac"},
		{"bb11223344556677889900", rtAliID, "ali"}, // 无歧义前缀
	} {
		ctx, cancel := rtCtx(t)
		id, name, err := r.ResolveHostRef(ctx, rig.dir, c.ref)
		cancel()
		if err != nil || id != c.wantID || name != c.wantName {
			t.Fatalf("ref %q 解析 = (%q,%q,%v)，期望 (%q,%q,nil)", c.ref, id, name, err, c.wantID, c.wantName)
		}
	}

	// 歧义前缀：列候选（同一 resolveHostTarget 文案源）。
	rig.backend.mu.Lock()
	rig.backend.hosts = append(rig.backend.hosts, control.HostState{ID: "aa11" + strings.Repeat("9", 60), Name: "mac2", State: "ready"})
	rig.backend.mu.Unlock()
	ctx, cancel := rtCtx(t)
	_, _, err := r.ResolveHostRef(ctx, rig.dir, "aa11")
	cancel()
	if err == nil || !strings.Contains(err.Error(), "歧义") || !strings.Contains(err.Error(), "候选") {
		t.Fatalf("歧义前缀应报错列候选：%v", err)
	}

	// 空串：files 面文案（不出现 host delete）。
	ctx, cancel = rtCtx(t)
	_, _, err = r.ResolveHostRef(ctx, rig.dir, "")
	cancel()
	if err == nil || !strings.Contains(err.Error(), "--host 需要") || !strings.Contains(err.Error(), "homeway files") {
		t.Fatalf("空串应报 files 面文案：%v", err)
	}
	if strings.Contains(fmt.Sprint(err), "host delete") {
		t.Fatalf("files 面不出现 host delete 文案：%v", err)
	}
}

// ---- 2.2 Dial 经控制面到真 files 服务端到端（list/get/put 三命令够面）----

func TestFilesRemoteDialEndToEnd(t *testing.T) {
	rig, _, root := startFilesRig(t)
	r := FilesRemote("test")
	cli := filesClientOnRig(t, r, rig)
	ctx, cancel := rtCtx(t)
	defer cancel()

	// list。
	ents, err := cli.List(ctx, ".")
	if err != nil || len(ents) != 2 {
		t.Fatalf("list：err=%v ents=%v", err, ents)
	}

	// kind=files 到达 Backend（端口映射断言在 kind→port 单测 + facade 注入桩）。
	rig.backend.mu.Lock()
	kinds := append([]string{}, rig.backend.dialKinds...)
	rig.backend.mu.Unlock()
	if len(kinds) == 0 || kinds[len(kinds)-1] != "files" {
		t.Fatalf("Backend 应收到 kind=files：%v", kinds)
	}

	// get（下载到内存）。
	var buf bytes.Buffer
	n, err := cli.Download(ctx, "hello.txt", &buf)
	if err != nil || n != int64(len("hello-files")) || buf.String() != "hello-files" {
		t.Fatalf("download：err=%v n=%d %q", err, n, buf.String())
	}

	// put（上传 → 远端原子替换）。
	payload := bytes.Repeat([]byte("0123456789"), 2000) // 20KB 跨帧
	if _, err := cli.Upload(ctx, "sub/up.bin", bytes.NewReader(payload), int64(len(payload)), nil); err != nil {
		t.Fatalf("upload：%v", err)
	}
	got, err := os.ReadFile(filepath.Join(root, "sub", "up.bin"))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("上传内容不符：err=%v len=%d", err, len(got))
	}
}

// files CLI 全链（files.CLI --host → FilesRemote → control.sock → stream.open{kind:files}
// → 真 files 服务）：list/get/put 三命令的退出码与产物。
func TestFilesRemoteCLIThroughControlPlane(t *testing.T) {
	rig, _, root := startFilesRig(t)
	r := FilesRemote("test")
	dir, err := os.MkdirTemp("/tmp", "filescli-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	if err := files.CLI([]string{"list", "--host", "mac", "--state", rig.dir, "--json"}, r); err != nil {
		t.Fatalf("list --host 应成功：%v", err)
	}
	target := filepath.Join(dir, "hello.txt")
	if err := files.CLI([]string{"get", "hello.txt", "-o", target, "--host", "mac", "--state", rig.dir, "--quiet"}, r); err != nil {
		t.Fatalf("get --host 应成功：%v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "hello-files" {
		t.Fatalf("get 内容不符：%v %q", err, got)
	}
	if err := os.Mkdir(filepath.Join(root, "put"), 0o755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "up.bin")
	if err := os.WriteFile(src, []byte("via-control-plane"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := files.CLI([]string{"put", src, "put/cli.bin", "--host", "mac", "--state", rig.dir, "--quiet"}, r); err != nil {
		t.Fatalf("put --host 应成功：%v", err)
	}
	got, err = os.ReadFile(filepath.Join(root, "put", "cli.bin"))
	if err != nil || string(got) != "via-control-plane" {
		t.Fatalf("put 内容不符：%v %q", err, got)
	}
}

// ---- 2.2 streamConn 写路径终结翻译：Send 终结 → streamend.Error（put 方向与读
// 方向同判型；「流已终结」文案约束 = term_remote_test 既有断言的同款判据）----

func TestFilesStreamConnWriteEndTranslation(t *testing.T) {
	// 假 files 后端：问候后不读上行（服务端 upC + 工位灌满 → finish(gone) → Send
	// 报终结 → streamConn.Write 翻译 streamend.Error{gone}——put 方向终结归因的
	// daemon 侧真路径驱动）。
	rig := startFilesNoReadRig(t)
	r := FilesRemote("test")
	ctx, cancel := rtCtx(t)
	defer cancel()
	rw, err := r.DialFiles(ctx, rig.dir, rig.macID)
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Close()

	// files 协议开场（问候帧可读 = 流已就绪）。
	br := make([]byte, 128)
	n, err := rw.Read(br)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(br[:n], []byte(`"ok":true`)) {
		t.Fatalf("应读到 files 问候帧：%q", br[:n])
	}
	// 灌写（16KiB 分片连发）直到 Write 报终结（背靠背 > 40 帧窗口 + socket 吸收）。
	chunk := make([]byte, 16<<10)
	var werr error
	deadline := time.After(15 * time.Second)
	for i := 0; i < 768 && werr == nil; i++ {
		if _, werr = rw.Write(chunk); werr != nil {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("流未收尾（768 帧内无 gone）：%d 帧已发", i)
		default:
			time.Sleep(2 * time.Millisecond)
		}
	}
	if werr == nil {
		t.Fatal("对端不读 + 背靠背连发：流应被背压收流（Write 报终结）")
	}
	// 写路径终结 = streamend.Error（类型化归因）+ 「流已终结」文案。终结原因二态皆
	// 可达（CI -race 首跑实拍 closed）：出口侧先撞上行/工位界 = gone，先撞对端关闭/
	// EOF = closed（调度差异决定谁先观测）——本用例钉 daemon 侧「翻译」契约（类型 +
	// 文案 + Unwrap 链），出口侧的 gone 分类由 internal/control 的背压用例钉住
	// （TestStreamSendErrorsAfterEnd / l2_upstream，含钉接收缓冲的 CI 适配）。
	var se *streamend.Error
	if !errors.As(werr, &se) || (se.Reason != streamend.Gone && se.Reason != streamend.Closed) {
		t.Fatalf("Write 终结应翻译 streamend.Error{gone|closed}：%v", werr)
	}
	if !strings.Contains(werr.Error(), "流已终结") {
		t.Fatalf("终结文案应含「流已终结」（与 term_remote_test 既有断言同款约束）：%v", werr)
	}
	// errors.Is io.EOF 同样成立（Unwrap 链）。
	if !errors.Is(werr, io.EOF) {
		t.Fatalf("streamend.Error 应 errors.Is io.EOF：%v", werr)
	}
}

// startFilesNoReadRig：files rig 的不读形态（kind=files 后端 accept 后不读上行）。
func startFilesNoReadRig(t *testing.T) *remoteTestRig {
	rig := startRemoteTestRig(t, false, false, false)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// 问候后不读（钉小接收缓冲——背压确定触发，同 fakeTermHost noread 口径）。
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetReadBuffer(16 << 10)
			}
			go func() {
				_, _ = c.Write([]byte(`{"ok":true,"root":"/","ver":1,"rw":true}` + "\n"))
				block := make(chan struct{})
				<-block
			}()
		}
	}()
	rig.backend.mu.Lock()
	rig.backend.filesDialAddr = ln.Addr().String()
	rig.backend.mu.Unlock()
	return rig
}

// ---- 2.3 kind→端口映射（DialPort 唯一路径的映射处单测）----

func TestStreamServicePortMapping(t *testing.T) {
	for _, c := range []struct {
		kind string
		port uint16
	}{
		{"term", 7724},
		{"files", 7802},
	} {
		got, err := streamServicePort(c.kind)
		if err != nil || got != c.port {
			t.Fatalf("kind=%s 应映射端口 %d，得到 %d（err=%v）", c.kind, c.port, got, err)
		}
	}
	if _, err := streamServicePort("unknown"); err == nil {
		t.Fatal("值域外 kind 应报错（控制面层回 bad_request 的映射处防御）")
	}
}
