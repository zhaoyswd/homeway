package files

// files_cli_test.go — `homeway files` CLI 面单测（files-cli §1）：假 RemoteFiles 注入 +
// 真 files.Server（server_test 件复用）——参数解析、双面拨号路径选择、--state 指代
// 切换、--timeout 三段预算（含 r3 新-10 看门用例）、适配壳 deadline 族、六子命令
// 语义（get/put 的取消与原子落盘）、错误面三层与流终结三态（errors.As 读写两方向）、
// 令牌桶节拍/配额与 --rate-limit 解析。daemon 控制面侧（真 control 服务器 + streamConn）
// 的端到端在 internal/daemon/files_remote_test.go。

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/streamend"
)

// ---- 假远程缝 ----

type fakeRemoteFiles struct {
	mu          sync.Mutex
	resolveSeen []string // Resolve 收到的 ref
	stateSeen   []string // Resolve/Dial 收到的 stateDir
	dialed      []string // Dial 收到的 hexID
	ids         map[string]string
	resolveErr  error
	dialErr     error
	dialFn      func(ctx context.Context) (io.ReadWriteCloser, error) // 缺省 = 拨真 Server 管道
	resolveFn   func(ctx context.Context) error                       // 解析段行为注入（阻塞/报错）
	dialBudgets []time.Duration
	srv         *Server // 缺省 dial 的目标
}

func (f *fakeRemoteFiles) ResolveHostRef(ctx context.Context, stateDir, ref string) (string, string, error) {
	f.mu.Lock()
	f.stateSeen = append(f.stateSeen, stateDir)
	f.resolveSeen = append(f.resolveSeen, ref)
	f.mu.Unlock()
	if f.resolveFn != nil {
		if err := f.resolveFn(ctx); err != nil {
			return "", "", err
		}
	}
	if f.resolveErr != nil {
		return "", "", f.resolveErr
	}
	id := ref
	if f.ids != nil {
		if v, ok := f.ids[ref]; ok {
			id = v
		}
	}
	return id, ref, nil
}

func (f *fakeRemoteFiles) DialFiles(ctx context.Context, stateDir, hexID string) (io.ReadWriteCloser, error) {
	f.mu.Lock()
	f.stateSeen = append(f.stateSeen, stateDir)
	f.dialed = append(f.dialed, hexID)
	if dl, ok := ctx.Deadline(); ok {
		f.dialBudgets = append(f.dialBudgets, time.Until(dl))
	}
	f.mu.Unlock()
	if f.dialErr != nil {
		return nil, f.dialErr
	}
	if f.dialFn != nil {
		return f.dialFn(ctx)
	}
	c1, c2 := net.Pipe()
	go f.srv.ServeConn(c2)
	return c1, nil
}

// newFakeRemote 连到真 Server（协议零改动经缝原样承载的最小可测代理）。
func newFakeRemote(t *testing.T) (*fakeRemoteFiles, string) {
	t.Helper()
	root := newRoot(t)
	f := &fakeRemoteFiles{ids: map[string]string{"mac": "aa"}, srv: newServer(t, root)}
	return f, root
}

// ---- 输出捕获 ----

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	_ = w.Close()
	os.Stdout = old
	return <-done
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	_ = w.Close()
	os.Stderr = old
	return <-done
}

// ---- 错误注入 conn（读方向：指定时机把 Read 替换为注入错误；写方向：累计写出超
// writeAfter 后 Write 报终结错误——daemon 适配层归一后的终结经缝到达的形态）----

type errInjRW struct {
	c          io.ReadWriteCloser
	readErr    atomic.Pointer[error] // 置位后 Read 恒返回该错误
	injectedCh chan struct{}         // 随 readErr 关闭：打断在途的底层 Read
	writeOver  int64                 // >0：累计写出超过该字节数后 Write 报终结（gone）
	written    int64
}

func newErrInjRW(c io.ReadWriteCloser) *errInjRW {
	return &errInjRW{c: c, injectedCh: make(chan struct{})}
}

// setReadErr 注入读终结错误（关 injectedCh 打断在途 Read——注入时调用方可能正
// 阻塞在底层 conn 读上，必须能被唤醒）。
func (w *errInjRW) setReadErr(e error) {
	w.readErr.Store(&e)
	close(w.injectedCh)
}

func (w *errInjRW) Read(p []byte) (int, error) {
	if e := w.readErr.Load(); e != nil {
		return 0, *e
	}
	type res struct {
		n   int
		err error
	}
	ch := make(chan res, 1)
	go func() {
		n, err := w.c.Read(p)
		ch <- res{n, err}
	}()
	select {
	case r := <-ch:
		return r.n, r.err
	case <-w.injectedCh:
		e := w.readErr.Load()
		return 0, *e
	}
}

func (w *errInjRW) Write(p []byte) (int, error) {
	if w.writeOver > 0 && w.written+int64(len(p)) > w.writeOver {
		return 0, &streamend.Error{Reason: streamend.Gone}
	}
	n, err := w.c.Write(p)
	w.written += int64(n)
	return n, err
}

func (w *errInjRW) Close() error { return w.c.Close() }

// ---- 1.1 参数解析与拨号路径选择 ----

func TestFilesCLIParseErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"未知子命令", []string{"frobnicate"}, "不认识的子命令"},
		{"list 未知 flag", []string{"list", "--zzz"}, "不认识的参数"},
		{"list 双路径", []string{"list", "a", "b"}, "只能给一个路径"},
		{"stat 缺路径", []string{"stat"}, "stat 需要路径"},
		{"mkdir 缺路径", []string{"mkdir"}, "mkdir 需要路径"},
		{"read 缺路径", []string{"read"}, "read 需要路径"},
		{"read 非法 max", []string{"read", "a", "--max", "abc"}, "不是合法正整数"},
		{"get 缺路径", []string{"get"}, "get 需要远端路径"},
		{"put 缺路径", []string{"put", "only-one"}, "put 需要两个路径"},
		{"put 三路径", []string{"put", "a", "b", "c"}, "只能给本地与远端两个路径"},
		{"--host 空值", []string{"list", "--host", " "}, "--host 需要主机名"},
		{"--timeout 非法", []string{"list", "--host", "mac", "--timeout", "soon"}, "不是合法时长"},
		{"--rate-limit 负值", []string{"put", "a", "b", "--rate-limit", "-5"}, "不是合法的非负整数"},
		{"--rate-limit 非整数", []string{"put", "a", "b", "--rate-limit", "fast"}, "不是合法的非负整数"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := CLI(c.args, nil)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("期望报错含 %q，得到 %v", c.want, err)
			}
		})
	}
}

// 拨号路径选择 + --state 指代切换：远程模式透传（显式值/空串=实现侧默认），本地面
// 补默认并连 <state>/files.sock。
func TestFilesCLIDialPathAndStateSemantics(t *testing.T) {
	f, _ := newFakeRemote(t)

	// 远程模式：显式 --state 透传。
	if err := CLI([]string{"list", "--host", "mac", "--state", "/tmp/daemon-state", "--json"}, f); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	gotState := f.stateSeen[len(f.stateSeen)-1]
	gotDial := f.dialed[len(f.dialed)-1]
	f.mu.Unlock()
	if gotState != "/tmp/daemon-state" {
		t.Fatalf("远程模式 --state 应透传，得到 %q", gotState)
	}
	if gotDial != "aa" {
		t.Fatalf("解析结果应到 Dial（hexID=%q）", gotDial)
	}

	// 远程模式：不给 --state = 空串透传（实现侧默认 daemon state）。
	if err := CLI([]string{"list", "--host", "mac"}, f); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	gotState = f.stateSeen[len(f.stateSeen)-1]
	f.mu.Unlock()
	if gotState != "" {
		t.Fatalf("远程缺省 --state 应透传空串，得到 %q", gotState)
	}

	// 本地面：连 <state>/files.sock（真 UDS listener），无 --host（短路径——macOS
	// sun_path 上限）。
	dir := shortTestDir(t)
	srv2 := newServer(t, newRoot(t))
	ln, err := net.Listen("unix", filepath.Join(dir, "files.sock"))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv2.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })
	out := captureStdout(t, func() {
		if err := CLI([]string{"list", "--state", dir}, nil); err != nil {
			t.Error(err)
		}
	})
	if !strings.Contains(out, "a.txt") {
		t.Fatalf("本地面 list 应含 a.txt：%q", out)
	}

	// 本地面 files.sock 不存在：出口 state 指代提示（层①）。
	err = CLI([]string{"list", "--state", filepath.Join(shortTestDir(t), "nope")}, nil)
	if err == nil || !strings.Contains(err.Error(), "不是出口 state 目录") {
		t.Fatalf("本地面 files.sock 不存在应报出口 state 提示：%v", err)
	}
}

// --timeout 三段之①：解析段独立预算（假 Resolve 阻塞 → 到点报错退出）。
func TestFilesCLITimeoutResolveSegment(t *testing.T) {
	f, _ := newFakeRemote(t)
	f.resolveFn = func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}
	start := time.Now()
	err := CLI([]string{"list", "--host", "mac", "--timeout", "300ms"}, f)
	if err == nil {
		t.Fatal("解析段烧尽应报错")
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("应在预算附近退出，耗时 %v", el)
	}
}

// --timeout 三段之③：对端接受连接但不回问候 → 看门在预算内 Close、CLI 报错退出
// （r2 新-3 用例 + r3 新-10 归因：文案含「问候帧」而非 conn 态连接断开）。
func TestFilesCLITimeoutFirstResponseWatchdog(t *testing.T) {
	f, _ := newFakeRemote(t)
	// 对端接受连接、永不写问候帧。
	c1, c2 := net.Pipe()
	defer c2.Close()
	go func() { // 排空上行、永不写
		buf := make([]byte, 4096)
		for {
			if _, err := c2.Read(buf); err != nil {
				return
			}
		}
	}()
	f.dialFn = func(ctx context.Context) (io.ReadWriteCloser, error) { return c1, nil }

	start := time.Now()
	err := CLI([]string{"list", "--host", "mac", "--timeout", "400ms"}, f)
	if err == nil {
		t.Fatal("无问候帧应在预算内报错")
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("应在预算附近退出（看门 Close 打断阻塞读），耗时 %v", el)
	}
	if !strings.Contains(err.Error(), "问候帧") || !strings.Contains(err.Error(), "首响应") {
		t.Fatalf("错误应归因首响应（问候帧）超预算：%v", err)
	}
	if strings.Contains(err.Error(), "连接断开") {
		t.Fatalf("超预算不应误归因 conn 态：%v", err)
	}
}

// 传输跨过首响应预算不被看门误杀（r3 新-10 核心判据）：问候帧后慢速传输总时长 >
// --timeout，看门已切到命令级 ctx——不 Close、传输完整完成。
func TestFilesCLIWatchdogNoOverrunBeyondFirstResponse(t *testing.T) {
	f, _ := newFakeRemote(t)
	payload := bytes.Repeat([]byte("x"), 3*MaxChunk) // 3 帧
	// 脚本化慢后端：问候 → 请求 → 响应行 → 每帧间隔 200ms（3 帧 ≈ 600ms > 预算 300ms）。
	f.dialFn = func(ctx context.Context) (io.ReadWriteCloser, error) {
		c1, c2 := net.Pipe()
		go func() {
			defer c2.Close()
			_ = WriteLine(c2, Greeting{Ok: true, Root: "/", Ver: Version})
			line, err := readTestLine(c2)
			if err != nil {
				return
			}
			var req Request
			if unmarshalLine(line, &req) != nil {
				return
			}
			if req.Op != "download" {
				_ = WriteLine(c2, Response{Ok: false, Code: "invalid_arg", Msg: "test 只服务 download"})
				return
			}
			_ = WriteLine(c2, Response{Ok: true, Size: int64(len(payload))})
			for off := 0; off < len(payload); off += MaxChunk {
				end := off + MaxChunk
				if end > len(payload) {
					end = len(payload)
				}
				time.Sleep(200 * time.Millisecond) // 慢腿：跨过首响应预算
				if err := WriteFrame(c2, payload[off:end]); err != nil {
					return
				}
			}
			_ = WriteFrame(c2, nil)
		}()
		return c1, nil
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "slow.bin")
	start := time.Now()
	if err := CLI([]string{"get", "slow.bin", "-o", target, "--host", "mac", "--timeout", "300ms", "--quiet"}, f); err != nil {
		t.Fatalf("跨预算传输不应被看门误杀：%v", err)
	}
	if el := time.Since(start); el < 500*time.Millisecond {
		t.Fatalf("传输应确实跨过预算（耗时 %v）", el)
	}
	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("内容应逐字节一致：err=%v len=%d", err, len(got))
	}
}

// 适配壳：deadline 族三方法返回「不支持」。
func TestFilesCLIAdapterDeadlineUnsupported(t *testing.T) {
	a := &streamAdapter{c: nopRW{}, phase: newDialPhase()}
	for _, err := range []error{
		a.SetDeadline(time.Now()),
		a.SetReadDeadline(time.Now()),
		a.SetWriteDeadline(time.Now()),
	} {
		if err == nil || !strings.Contains(err.Error(), "不支持 deadline") {
			t.Fatalf("deadline 族应报不支持：%v", err)
		}
	}
}

type nopRW struct{}

func (nopRW) Read(p []byte) (int, error)  { return 0, io.EOF }
func (nopRW) Write(p []byte) (int, error) { return len(p), nil }
func (nopRW) Close() error                { return nil }

// ---- 1.2 六子命令语义（真 Server 经远程缝；本地/远程同一条 Client 路径）----

func TestFilesCLISixCommands(t *testing.T) {
	f, root := newFakeRemote(t)

	// list：表格 + --json 单行。
	out := captureStdout(t, func() {
		if err := CLI([]string{"list", "--host", "mac"}, f); err != nil {
			t.Error(err)
		}
	})
	if !strings.Contains(out, "a.txt") || !strings.Contains(out, "sub") || !strings.Contains(out, "dir") {
		t.Fatalf("表格应含条目与类型：%q", out)
	}
	out = captureStdout(t, func() {
		if err := CLI([]string{"list", "--host", "mac", "--json"}, f); err != nil {
			t.Error(err)
		}
	})
	if strings.Count(out, "\n") != 1 || !strings.Contains(out, `"name":"a.txt"`) || !strings.Contains(out, `"isDir":false`) {
		t.Fatalf("--json 应为单行数组：%q", out)
	}

	// stat：--json 单条目。
	out = captureStdout(t, func() {
		if err := CLI([]string{"stat", "a.txt", "--host", "mac", "--json"}, f); err != nil {
			t.Error(err)
		}
	})
	if !strings.Contains(out, `"size":5`) || !strings.Contains(out, `"mtimeMs"`) {
		t.Fatalf("stat --json 字段不符：%q", out)
	}

	// mkdir：成功 + already_exists。
	if err := CLI([]string{"mkdir", "newdir", "--host", "mac"}, f); err != nil {
		t.Fatal(err)
	}
	if err := CLI([]string{"mkdir", "newdir", "--host", "mac"}, f); err == nil || !strings.Contains(err.Error(), "同名条目已存在") {
		t.Fatalf("重复 mkdir 应 already_exists 文案：%v", err)
	}

	// read：默认 + --max 截断（提示走 stderr、stdout 只有正文）+ 超内联上限报错。
	var se string
	so := captureStdout(t, func() {
		se = captureStderr(t, func() {
			if err := CLI([]string{"read", "a.txt", "--host", "mac"}, f); err != nil {
				t.Error(err)
			}
		})
	})
	if so != "hello" || se != "" {
		t.Fatalf("read 正文进 stdout、无截断提示：stdout=%q stderr=%q", so, se)
	}
	if err := os.WriteFile(filepath.Join(root, "big.txt"), bytes.Repeat([]byte("y"), 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	so = captureStdout(t, func() {
		se = captureStderr(t, func() {
			if err := CLI([]string{"read", "big.txt", "--max", "1024", "--host", "mac"}, f); err != nil {
				t.Error(err)
			}
		})
	})
	if len(so) != 1024 || !strings.Contains(se, "截断") {
		t.Fatalf("截断预览不符：len(stdout)=%d stderr=%q", len(so), se)
	}
	if err := CLI([]string{"read", "big.txt", "--max", "99999999", "--host", "mac"}, f); err == nil ||
		!strings.Contains(err.Error(), "超过协议内联读取上限") {
		t.Fatalf("--max 超内联上限应就地报错非静默截断：%v", err)
	}

	// get：进度走 stderr、stdout 不污染；-o 落盘。
	dir := t.TempDir()
	target := filepath.Join(dir, "a.txt")
	so = captureStdout(t, func() {
		se = captureStderr(t, func() {
			if err := CLI([]string{"get", "a.txt", "-o", target, "--host", "mac"}, f); err != nil {
				t.Error(err)
			}
		})
	})
	if so != "" {
		t.Fatalf("get 不应污染 stdout：%q", so)
	}
	if !strings.Contains(se, "下载") {
		t.Fatalf("进度/完成行应走 stderr：%q", se)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "hello" {
		t.Fatalf("get 内容不符：%v %q", err, got)
	}

	// put：上传往返（真 Server 端到端）。
	src := filepath.Join(dir, "up.bin")
	payload := bytes.Repeat([]byte("0123456789"), 3000) // 30KB 跨帧
	if err := os.WriteFile(src, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CLI([]string{"put", src, "sub/up.bin", "--host", "mac", "--quiet"}, f); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(filepath.Join(root, "sub", "up.bin"))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("put 往返内容不符：err=%v len=%d", err, len(got))
	}
}

// get 覆盖防护：已存在默认拒（本地文件原样）+ --force 覆盖。
func TestFilesCLIGetRefuseAndForce(t *testing.T) {
	f, _ := newFakeRemote(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CLI([]string{"get", "a.txt", "-o", target, "--host", "mac"}, f); err == nil ||
		!strings.Contains(err.Error(), "已存在") || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("已存在应默认拒并提示 --force：%v", err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != "original" {
		t.Fatalf("拒绝路径本地文件应原样：%q", got)
	}
	if err := CLI([]string{"get", "a.txt", "-o", target, "--host", "mac", "--force", "--quiet"}, f); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(target)
	if string(got) != "hello" {
		t.Fatalf("--force 应覆盖：%q", got)
	}
}

// get 中断（流死）→ 本地无 .tierpart 残留、既有文件原样、可直接重试（「已存在默认
// 拒」不被残留触发）。
func TestFilesCLIGetInterruptNoResidue(t *testing.T) {
	f, _ := newFakeRemote(t)
	payload := bytes.Repeat([]byte("z"), 2*MaxChunk)
	f.dialFn = func(ctx context.Context) (io.ReadWriteCloser, error) {
		c1, c2 := net.Pipe()
		go func() {
			defer c2.Close() // 只发一帧即关（EOF 未带终止帧 = 中途断流）
			_ = WriteLine(c2, Greeting{Ok: true, Root: "/", Ver: Version})
			line, err := readTestLine(c2)
			if err != nil {
				return
			}
			var req Request
			if unmarshalLine(line, &req) != nil {
				return
			}
			_ = WriteLine(c2, Response{Ok: true, Size: int64(len(payload))})
			_ = WriteFrame(c2, payload[:MaxChunk])
		}()
		return c1, nil
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "half.bin")
	if err := os.WriteFile(target, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := CLI([]string{"get", "half.bin", "-o", target, "--host", "mac", "--force", "--quiet"}, f)
	if err == nil {
		t.Fatal("中途断流应报错")
	}
	got, rerr := os.ReadFile(target)
	if rerr != nil || string(got) != "old" {
		t.Fatalf("中断后目标应保持原样：%v %q", rerr, got)
	}
	if parts := cliLocalParts(target); len(parts) != 0 {
		t.Fatalf("中断后不应残留 .tierpart：%v", parts)
	}
	// 重试走默认拒路径：目标在、与残留无关（残留被删——默认拒不被残留顶撞）。
	if err := CLI([]string{"get", "half.bin", "-o", target, "--host", "mac", "--quiet"}, f); err == nil ||
		!strings.Contains(err.Error(), "已存在") {
		t.Fatalf("重试默认拒（目标在、非残留触发）：%v", err)
	}
}

// put 取消（ctx 取消即关流不发终止帧）：真 Server 端清理 .tierpart、目标不变 +
// 「已取消、远端未收完整」文案。慢排空后端保证取消落在传输中段。
func TestFilesCLIPutCancelCleansRemote(t *testing.T) {
	f, root := newFakeRemote(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "big.bin")
	if err := os.WriteFile(src, bytes.Repeat([]byte("q"), 4<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "keep.bin"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 慢排空：ready 后每 50ms 读 16KiB（4MiB ≈ 13s ≫ 取消点），取消必落传输中段。
	f.dialFn = func(ctx context.Context) (io.ReadWriteCloser, error) {
		c1, c2 := net.Pipe()
		go func() {
			defer c2.Close()
			_ = WriteLine(c2, Greeting{Ok: true, Root: "/", Ver: Version})
			line, err := readTestLine(c2)
			if err != nil {
				return
			}
			var req Request
			if unmarshalLine(line, &req) != nil {
				return
			}
			_ = WriteLine(c2, Response{Ok: true})
			buf := make([]byte, 16<<10)
			for {
				if _, err := c2.Read(buf); err != nil {
					return
				}
				time.Sleep(50 * time.Millisecond)
			}
		}()
		return c1, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel() // Ctrl-C 等价（signal ctx 的 cancel）
	}()
	err := cliFilesPut(ctx, []string{src, "keep.bin", "--host", "mac", "--quiet"}, f)
	if err == nil || !strings.Contains(err.Error(), "已取消") || !strings.Contains(err.Error(), "远端未收完整") {
		t.Fatalf("取消应报已取消文案：%v", err)
	}
	cancel()
	// 服务端清理是异步的（客户端关流 → 服务端读 EOF → 清理）：短轮询窗口。
	deadline := time.Now().Add(3 * time.Second)
	for {
		if parts := cliRemoteParts(root, "keep.bin"); len(parts) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("取消后远端不应残留 .tierpart（未发终止帧 ⇒ 服务端按取消清理）")
		}
		time.Sleep(20 * time.Millisecond)
	}
	got, rerr := os.ReadFile(filepath.Join(root, "keep.bin"))
	if rerr != nil || string(got) != "keep" {
		t.Fatalf("取消后远端目标应保持原样：%v %q", rerr, got)
	}
}

// ---- 1.3 错误面：流终结三态（errors.As 读写两方向各一）+ 逐码文案 ----

// 读方向：终结错误从 Client 读循环冒出、经 Errw/Unwrap 链可达 streamend.Error。
func TestFilesCLIStreamEndReadDirection(t *testing.T) {
	f, _ := newFakeRemote(t)
	payload := bytes.Repeat([]byte("r"), 2*MaxChunk)
	f.dialFn = func(ctx context.Context) (io.ReadWriteCloser, error) {
		c1, c2 := net.Pipe()
		w := newErrInjRW(c1)
		go func() {
			defer c2.Close()
			_ = WriteLine(c2, Greeting{Ok: true, Root: "/", Ver: Version})
			line, err := readTestLine(c2)
			if err != nil {
				return
			}
			var req Request
			if unmarshalLine(line, &req) != nil {
				return
			}
			_ = WriteLine(c2, Response{Ok: true, Size: int64(len(payload))})
			_ = WriteFrame(c2, payload[:MaxChunk])
			// 第二帧前终结（gone）：读端注入终结错误（daemon 适配层 Read 终结的
			// 形态）。注入后持住连接（读到客户端关流为止）——客户端看到的终结错误
			// 只能是注入的这个，不是 EOF。
			w.setReadErr(&streamend.Error{Reason: streamend.Gone})
			buf := make([]byte, 1)
			_, _ = c2.Read(buf)
		}()
		return w, nil
	}
	// 链断言（r2 新-1/新-2 验证升级）：经 Client 读循环冒出的错误 errors.As 命中。
	e := (&filesCommon{hostRef: "mac"}).env(context.Background(), f)
	_, err := e.client().DownloadTo(context.Background(), "x", io.Discard, nil)
	var se *streamend.Error
	if !errors.As(err, &se) || se.Reason != streamend.Gone {
		t.Fatalf("读方向 errors.As(streamend) 应命中 gone：%v", err)
	}
	// CLI 文案：三态归因 + 已收字节 + 可重试 + 本地无残留。
	dir := t.TempDir()
	target := filepath.Join(dir, "x")
	cerr := CLI([]string{"get", "x", "-o", target, "--host", "mac", "--quiet"}, f)
	if cerr == nil || !strings.Contains(cerr.Error(), "收流") || !strings.Contains(cerr.Error(), "可直接重试") {
		t.Fatalf("get 中途 gone 文案应含收流/可重试：%v", cerr)
	}
	// 已收字节数进文案（「已收 NB」恒在；具体值 = 已交付帧的字节，与服务端注入
	// 终结的时序相关〔pipe 写返回 ≠ 客户端已落盘〕——不钉具体值）。
	if !strings.Contains(cerr.Error(), "已收 ") || !strings.Contains(cerr.Error(), "B") {
		t.Fatalf("已收字节应进文案：%v", cerr)
	}
	if parts := cliLocalParts(target); len(parts) != 0 {
		t.Fatalf("get 中途本地无残留：%v", parts)
	}
}

// 写方向：daemon 适配层已把 Send 终结归一 streamend.Error——注入 conn 的 Write 在
// 累计写出超阈后报终结，经 Errw 链 CLI 同一 errors.As 命中（写路径翻译的客户端面）。
func TestFilesCLIStreamEndWriteDirection(t *testing.T) {
	f, _ := newFakeRemote(t)
	payload := bytes.Repeat([]byte("w"), 2*MaxChunk)
	f.dialFn = func(ctx context.Context) (io.ReadWriteCloser, error) {
		c1, c2 := net.Pipe()
		go func() {
			defer c2.Close()
			_ = WriteLine(c2, Greeting{Ok: true, Root: "/", Ver: Version})
			line, err := readTestLine(c2)
			if err != nil {
				return
			}
			var req Request
			if unmarshalLine(line, &req) != nil {
				return
			}
			_ = WriteLine(c2, Response{Ok: true}) // write ready
			buf := make([]byte, 64<<10)
			for { // 排空上行（帧继续被消费；终结由注入层报）
				if _, err := c2.Read(buf); err != nil {
					return
				}
			}
		}()
		// 累计写出 > 300KiB（首帧 256KiB 过、第二帧中段）后 Write 报终结（gone）。
		w := newErrInjRW(c1)
		w.writeOver = 300 << 10
		return w, nil
	}
	// 链断言：Upload 冒出的错误 errors.As 命中（与读方向同一类型）。
	e := (&filesCommon{hostRef: "mac"}).env(context.Background(), f)
	_, err := e.client().Upload(context.Background(), "y", bytes.NewReader(payload), int64(len(payload)), nil)
	var se *streamend.Error
	if !errors.As(err, &se) || se.Reason != streamend.Gone {
		t.Fatalf("写方向 errors.As(streamend) 应命中 gone：%v", err)
	}
	// CLI put 文案：收流/上行过快语义 + 远端按取消清理、不再推进余量。
	dir := t.TempDir()
	src := filepath.Join(dir, "y")
	if err := os.WriteFile(src, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	cerr := CLI([]string{"put", src, "y", "--host", "mac", "--quiet"}, f)
	if cerr == nil || !strings.Contains(cerr.Error(), "收流") || !strings.Contains(cerr.Error(), "上行") {
		t.Fatalf("put 中途 gone 文案应含收流/上行过快语义：%v", cerr)
	}
	if !strings.Contains(cerr.Error(), "取消") || !strings.Contains(cerr.Error(), "清理") {
		t.Fatalf("put 中途 gone 应提示远端按取消清理：%v", cerr)
	}
}

// 协议错误码逐码文案（真 Server 自然产生 not_found/is_dir/invalid_arg）。
func TestFilesCLIErrorCodes(t *testing.T) {
	f, _ := newFakeRemote(t)
	dir := t.TempDir()
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"not_found", []string{"stat", "nope", "--host", "mac"}, "不存在或不允许访问"},
		{"is_dir get", []string{"get", "sub", "-o", filepath.Join(dir, "sub"), "--host", "mac"}, "是目录"},
		{"invalid_arg（.. 段）", []string{"stat", "../escape", "--host", "mac"}, "路径不合法"},
		{"is_dir read", []string{"read", "sub", "--host", "mac"}, "是目录"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := CLI(c.args, f)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("期望文案含 %q：%v", c.want, err)
			}
		})
	}

	// stream_open（问候帧非 JSON）经脚本后端。
	f2, _ := newFakeRemote(t)
	f2.dialFn = func(ctx context.Context) (io.ReadWriteCloser, error) {
		c1, c2 := net.Pipe()
		go func() {
			defer c2.Close()
			_, _ = c2.Write([]byte("not-json\n"))
		}()
		return c1, nil
	}
	err := CLI([]string{"list", "--host", "mac"}, f2)
	if err == nil || !strings.Contains(err.Error(), "files 服务不可达") {
		t.Fatalf("流开场失败应归因 files 服务不可达：%v", err)
	}
}

// ---- 1.4 令牌桶 ----

// --rate-limit 解析含 0（0 = 不限，不构造桶）。
func TestFilesCLIRateLimitParse(t *testing.T) {
	if tb := newTokenBucket(0); tb != nil {
		t.Fatal("--rate-limit 0 应 = 不限（nil 桶）")
	}
	if tb := newTokenBucket(-1); tb != nil {
		t.Fatal("负值同样按不限处理（CLI 层已拒绝，防御）")
	}
	if tb := newTokenBucket(1024); tb == nil {
		t.Fatal("正值应构造桶")
	}
}

// 令牌桶节拍与配额：rate=1MiB/s、**空桶起步（纯节拍）**——3MiB 总量按速率匀速至少
// ~3s（无回压下的盲节流语义；v0.12.1 起 burst 语义废除——满桶突刺会击穿守护进程
// 640KiB 每流窗口，见 newTokenBucket 注释）。
func TestFilesCLITokenBucketPacing(t *testing.T) {
	if testing.Short() {
		t.Skip("节拍用例需要真实时间")
	}
	const rate = 1 << 20
	tb := newTokenBucket(rate)
	start := time.Now()
	total := 3 * rate
	for n := total; n > 0; {
		chunk := 256 * 1024
		if chunk > n {
			chunk = n
		}
		if err := tb.Await(context.Background(), chunk); err != nil {
			t.Fatalf("无取消 ctx 下 Await 不应报错：%v", err)
		}
		n -= chunk
	}
	el := time.Since(start)
	// 空桶起步：3MiB @1MiB/s ≈ 3s；下界 2.9s（留调度余量）、上界 8s。
	if el < 2900*time.Millisecond {
		t.Fatalf("限速失守（3MiB @1MiB/s 仅 %v）——盲节流义务", el)
	}
	if el > 8*time.Second {
		t.Fatalf("节拍过慢（%v）——桶补充逻辑异常", el)
	}
}

// 空桶起步回归（v0.12.1 修正的判据面）：构造即取配额**不得**直通——首帧也要等
// 攒够令牌。首版满桶起步（tokens=rate）在慢腿上 0.04s 内突刺 2MiB 击穿 640KiB
// 窗口被收流（真机实测形态），空桶起步把首帧延迟压到 16KiB/rate（默认 8ms）。
func TestFilesCLITokenBucketNoInitialBurst(t *testing.T) {
	if testing.Short() {
		t.Skip("节拍用例需要真实时间")
	}
	const rate = 2 << 20 // DefaultRateLimit
	tb := newTokenBucket(rate)
	start := time.Now()
	if err := tb.Await(context.Background(), 16*1024); err != nil {
		t.Fatalf("无取消 ctx 下 Await 不应报错：%v", err)
	} // 第一帧（16KiB = 协议帧宽）
	el := time.Since(start)
	if el < 4*time.Millisecond {
		t.Fatalf("首帧直通 = 满桶突刺复燃（应在 ~16KiB/rate≈8ms 处等待，实际 %v）", el)
	}
	// 令牌已花掉：紧接着的第二帧还要再等（连续两帧不应比两帧配额时间快）。
	if err := tb.Await(context.Background(), 16*1024); err != nil {
		t.Fatalf("无取消 ctx 下 Await 不应报错：%v", err)
	}
	if time.Since(start) < 12*time.Millisecond {
		t.Fatalf("第二帧仍在吃初始配额——桶初始令牌非零（%v 内两帧直通）", time.Since(start))
	}
}

// 停顿后补充上限 = burstCap（exec-r1 F2 用例）：>0.3s 停顿（本地盘/慢 stderr/调度
// 都会造成）后，桶内可立即灌入的增量必须 ≤ min(rate, 256KiB)——旧口径「上限 =
// rate」会在停顿后重新攒出 >640KiB 窗口的突刺（v0.12.1 修掉的失效模式的复活路径）。
// 判据走桶内状态（确定性，不依赖时钟精度）：把 last 拨回 1s 前（Await 只在调用时
// 按 elapsed 补充），触发一次补充后断言余额不超上限。
func TestFilesCLITokenBucketBurstCapAfterPause(t *testing.T) {
	// 常量关系：burstCap 必须压在守护进程窗口 640KiB 的一半以下。
	if tokenBurstCap >= 320<<10 {
		t.Fatalf("tokenBurstCap=%d 必须小于每流窗口 640KiB 的一半", tokenBurstCap)
	}
	for _, rate := range []int64{4 << 20, 128 << 10} { // rate > burstCap 与 rate < burstCap 两支
		tb := newTokenBucket(rate).(*tokenBucket)
		tb.mu.Lock()
		tb.last = time.Now().Add(-time.Second) // 模拟 1s 停顿（>0.3s 即足以击穿窗口）
		tb.mu.Unlock()
		if err := tb.Await(context.Background(), 1); err != nil {
			t.Fatalf("无取消 ctx 下 Await 不应报错：%v", err)
		}
		tb.mu.Lock()
		tokens := tb.tokens
		tb.mu.Unlock()
		want := rate
		if want > tokenBurstCap {
			want = tokenBurstCap
		}
		if tokens > float64(want) {
			t.Fatalf("rate=%d：停顿 1s 后桶余额 %v 超过补充上限 %d——停顿后突刺未削峰（可立即灌入增量超 640KiB 窗口余量）",
				rate, tokens, want)
		}
	}
}

// Await 吃 ctx（exec-r1 F5 用例）：小速率下单块等待可达秒级乃至分钟级（真实配额
// 单位 = 本地读块 ≤ MaxChunk = 256KiB，--rate-limit 1024 下满读块 = 256s；本例以
// 16KiB 配额缩短等待窗口），ctx 取消必须即时打断等待并返回 ctx.Err()——退出时间
// 有界，不被拖到「一块/速率」烧尽。n=16KiB > burst=1024 ⇒ 走 N1 整块配额分支
// （等待 = n/rate = 16s，取消在 ~150ms 打断）。
func TestFilesCLITokenBucketAwaitCancelBounded(t *testing.T) {
	tb := newTokenBucket(1024) // --rate-limit 1024（合法值域下界附近）
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	err := tb.Await(ctx, 16*1024) // 需 ~16s 的等待（16KiB @1024B/s）——取消应 ~150ms 内打断
	el := time.Since(start)
	if err == nil {
		t.Fatal("取消后 Await 必须返回错误（ctx.Err）")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("应返回 ctx 的取消错误，得到 %v", err)
	}
	if el > 3*time.Second {
		t.Fatalf("取消后退出被拖到 %v——sleep 不可打断（F5 未生效，应 ~150ms）", el)
	}
}

// 小速率有界等待（exec-r2 N1 用例，随 3e 发版窗口修）：配额单位 = 本地读块
// （≤ MaxChunk = 256KiB，client.go 上传循环按读块取配额），不是 16KiB 线帧。
// 0 < rate < n 时 burst = min(rate, 256KiB) < n，旧实现 tokens 恒被高水位截在
// burst 以下 ⇒ 永攒不够一块、Await 无界不返回（exec-r2 探针实测：131072/262143
// 5s 未返回——合法 flag 值下 put 永久挂死；262144 起 1s）。修复后单块配额不受
// 高水位约束，一律按 n/rate 节拍有界返回（边界 rate=n 走正常路径，节拍不变）。
// 131072 档连取两块：第二块仍按整块节拍等待（积累作废，不得凭上一块等待期间的
// 积累立刻放行）。
func TestFilesCLITokenBucketSmallRateBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("节拍用例需要真实时间")
	}
	for _, tc := range []struct {
		name  string
		rate  int64
		calls int
		was   string // 旧实现行为（exec-r2 探针留档）
	}{
		{name: "rate=131072（旧实现挂死）", rate: 131072, calls: 2, was: "5s 未返回"},
		{name: "rate=262143（旧实现挂死）", rate: 262143, calls: 1, was: "5s 未返回"},
		{name: "rate=262144（边界 = MaxChunk，正常路径）", rate: MaxChunk, calls: 1, was: "1s 返回"},
		{name: "rate=524288（正常路径）", rate: 512 << 10, calls: 1, was: "500ms 返回"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tb := newTokenBucket(tc.rate)
			want := time.Duration(float64(MaxChunk) / float64(tc.rate) * float64(time.Second))
			for call := 1; call <= tc.calls; call++ {
				start := time.Now()
				if err := tb.Await(context.Background(), MaxChunk); err != nil {
					t.Fatalf("无取消 ctx 下 Await 不应报错：%v", err)
				}
				el := time.Since(start)
				if el < want*9/10 {
					t.Fatalf("第 %d 块节拍失守：256KiB @%dB/s 用时 %v（期望 ≥%v 的 90%%）——空桶起步应按 n/rate 等待",
						call, tc.rate, el, want)
				}
				if el > want*3+2*time.Second {
					t.Fatalf("第 %d 块等待过长：用时 %v 超期望 %v 的 3 倍——小速率下仍近无界（旧实现：%s）",
						call, el, want, tc.was)
				}
			}
		})
	}
}

// put 缺省走 DefaultRateLimit（发送端速率义务缺省路径）：--rate-limit 未给 = 保守
// 默认；显式 0 = 不限；正值原样。
func TestFilesCLIPutDefaultRateApplied(t *testing.T) {
	if DefaultRateLimit != 2<<20 {
		t.Fatalf("缺省限速 = 保守值 2MiB/s（D5），得到 %d", DefaultRateLimit)
	}
	for _, c := range []struct {
		flag int64
		want int64
	}{
		{-1, DefaultRateLimit}, // 缺省（未给 --rate-limit）
		{0, 0},                 // 显式 0 = 不限（风险自担）
		{12345, 12345},         // 正值原样
	} {
		if got := resolveRateLimit(c.flag); got != c.want {
			t.Fatalf("resolveRateLimit(%d) = %d，期望 %d", c.flag, got, c.want)
		}
	}
}

// ---- 小工具 ----

// shortTestDir 短路径临时目录（macOS 的 t.TempDir() 在 /var/folders 下会超
// sockaddr_un 的 sun_path 上限——UDS 用例专用）。
func shortTestDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "filescli-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// readTestLine 读一行（到 \n）。
func readTestLine(r io.Reader) ([]byte, error) {
	var buf []byte
	b := make([]byte, 1)
	for {
		n, err := r.Read(b)
		if n > 0 {
			buf = append(buf, b[0])
			if b[0] == '\n' {
				return buf, nil
			}
		}
		if err != nil {
			return buf, err
		}
	}
}

// cliLocalParts / cliRemoteParts：临时残留按**前缀**找（FIX-37 起临时名带随机后缀，
// 固定名断言会恒真 = 失去判据）。
func cliLocalParts(target string) []string {
	ents, err := os.ReadDir(filepath.Dir(target))
	if err != nil {
		return nil
	}
	base := filepath.Base(target)
	var out []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), base+uploadPartSuffix) {
			out = append(out, e.Name())
		}
	}
	return out
}

func cliRemoteParts(root, name string) []string {
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), name+uploadPartSuffix) {
			out = append(out, e.Name())
		}
	}
	return out
}
