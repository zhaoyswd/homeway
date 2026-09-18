package files

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// ---------- 测试客户端（真客户端在手机核里，见 tasks 4.2） ----------

type testClient struct {
	t    *testing.T
	conn net.Conn
	br   *bufio.Reader
	root string
}

// dial 起一条流：读问候帧并校验，返回可直接发命令的客户端。
func dial(t *testing.T, srv *Server) (*testClient, chan struct{}) {
	t.Helper()
	c1, c2 := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.ServeConn(c2)
	}()
	br := bufio.NewReader(c1)
	var g Greeting
	readJSONLine(t, br, &g)
	if !g.Ok || g.Ver != Version || !g.RW {
		t.Fatalf("问候帧不符：%+v", g)
	}
	if g.Root != srv.RootDir() {
		t.Fatalf("问候帧 root=%q 期望 %q", g.Root, srv.RootDir())
	}
	t.Cleanup(func() { c1.Close() })
	return &testClient{t: t, conn: c1, br: br, root: g.Root}, done
}

func readJSONLine(t *testing.T, br *bufio.Reader, v any) {
	t.Helper()
	line, err := br.ReadBytes('\n')
	if err != nil {
		t.Fatalf("读响应行失败：%v", err)
	}
	if err := json.Unmarshal(trimEOL(line), v); err != nil {
		t.Fatalf("响应行不是 JSON：%v（%s）", err, line)
	}
}

func (c *testClient) req(r Request) Response {
	c.t.Helper()
	if err := WriteLine(c.conn, r); err != nil {
		c.t.Fatalf("发请求失败：%v", err)
	}
	var resp Response
	readJSONLine(c.t, c.br, &resp)
	return resp
}

func (c *testClient) download(path string) ([]byte, int64) {
	c.t.Helper()
	if err := WriteLine(c.conn, Request{Op: "download", Path: path}); err != nil {
		c.t.Fatal(err)
	}
	var resp Response
	readJSONLine(c.t, c.br, &resp)
	if !resp.Ok {
		c.t.Fatalf("download 失败：%+v", resp)
	}
	var out []byte
	buf := make([]byte, MaxChunk)
	for {
		n, err := ReadFrame(c.br, buf)
		if err != nil {
			c.t.Fatalf("读数据帧失败：%v", err)
		}
		if n == 0 {
			break
		}
		out = append(out, buf[:n]...)
	}
	return out, resp.Size
}

// upload 走完一次上传：请求 → 等 ready → 发帧 →（可选）终止帧 → 读结果行。
// commit=false 时返回前不发送终止帧（模拟取消；调用方随后关流）。
func (c *testClient) upload(path string, data []byte, commit bool) Response {
	c.t.Helper()
	if err := WriteLine(c.conn, Request{Op: "write", Path: path, Size: int64(len(data))}); err != nil {
		c.t.Fatal(err)
	}
	var ready Response
	readJSONLine(c.t, c.br, &ready)
	if !ready.Ok {
		return ready
	}
	if len(data) > 0 {
		if err := WriteFrame(c.conn, data); err != nil {
			c.t.Fatal(err)
		}
	}
	if !commit {
		return ready
	}
	if err := WriteFrame(c.conn, nil); err != nil {
		c.t.Fatal(err)
	}
	var resp Response
	readJSONLine(c.t, c.br, &resp)
	return resp
}

// call 起一条新流、跑一条命令、返回响应（每命令一条流 = 契约）。
func call(t *testing.T, srv *Server, r Request) Response {
	t.Helper()
	c, _ := dial(t, srv)
	return c.req(r)
}

// downloadOnce 起一条新流做一次下载。
func downloadOnce(t *testing.T, srv *Server, path string) ([]byte, int64) {
	t.Helper()
	c, _ := dial(t, srv)
	return c.download(path)
}

// ---------- 夹具 ----------

func newRoot(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func newServer(t *testing.T, root string) *Server {
	t.Helper()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// ---------- 用例 ----------

// 判据①：六动词往返 + 问候帧 + 列表/stat 字段
func TestRoundTripVerbs(t *testing.T) {
	root := newRoot(t)
	srv := newServer(t, root)

	resp := call(t, srv, Request{Op: "list", Path: "."})
	if !resp.Ok || len(resp.Entries) != 2 {
		t.Fatalf("list 根失败：%+v", resp)
	}
	byName := map[string]Entry{}
	for _, e := range resp.Entries {
		byName[e.Name] = e
	}
	if e := byName["a.txt"]; e.IsDir || e.Size != 5 || e.MtimeMs == 0 || e.Mode == 0 {
		t.Fatalf("a.txt 条目字段不符：%+v", e)
	}
	if e := byName["sub"]; !e.IsDir {
		t.Fatalf("sub 应为目录：%+v", e)
	}

	resp = call(t, srv, Request{Op: "stat", Path: "a.txt"})
	if !resp.Ok || resp.Entry == nil || resp.Entry.Name != "a.txt" || resp.Entry.Size != 5 {
		t.Fatalf("stat 失败：%+v", resp)
	}

	resp = call(t, srv, Request{Op: "read", Path: "a.txt"})
	if !resp.Ok || resp.Text != "hello" || resp.Size != 5 || resp.Truncated {
		t.Fatalf("read 失败：%+v", resp)
	}

	resp = call(t, srv, Request{Op: "read", Path: "a.txt", Mode: "image"})
	if !resp.Ok {
		t.Fatalf("read image 失败：%+v", resp)
	}
	if raw, err := base64.StdEncoding.DecodeString(resp.Base64); err != nil || string(raw) != "hello" {
		t.Fatalf("base64 载荷不符：%q err=%v", resp.Base64, err)
	}

	if resp = call(t, srv, Request{Op: "mkdir", Path: "sub/newdir"}); !resp.Ok {
		t.Fatalf("mkdir 失败：%+v", resp)
	}
	if fi, err := os.Stat(filepath.Join(root, "sub", "newdir")); err != nil || !fi.IsDir() {
		t.Fatalf("mkdir 未落盘：%v", err)
	}

	payload := []byte("uploaded-content")
	uc, _ := dial(t, srv)
	if resp = uc.upload("sub/newdir/u.bin", payload, true); !resp.Ok || resp.Size != int64(len(payload)) {
		t.Fatalf("upload 失败：%+v", resp)
	}
	got, size := downloadOnce(t, srv, "sub/newdir/u.bin")
	if size != int64(len(payload)) || string(got) != string(payload) {
		t.Fatalf("download 不符：size=%d got=%q", size, got)
	}
	raw, err := os.ReadFile(filepath.Join(root, "sub", "newdir", "u.bin"))
	if err != nil || string(raw) != string(payload) {
		t.Fatalf("落盘内容不符：%v %q", err, raw)
	}
	if _, err := os.Stat(filepath.Join(root, "sub", "newdir", "u.bin"+uploadPartSuffix)); !os.IsNotExist(err) {
		t.Fatalf("应无 .tierpart 残留：%v", err)
	}
}

// 判据②：路径逃逸拒绝（`..`、绝对路径逃逸、符号链接逃逸）
func TestEscapeRejected(t *testing.T) {
	root := newRoot(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("TOPSECRET"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skipf("符号链接不可用：%v", err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "secret-link")); err != nil {
		t.Fatal(err)
	}
	srv := newServer(t, root)

	for _, p := range []string{"../secret.txt", "sub/../../secret.txt", "escape/secret.txt", "secret-link"} {
		resp := call(t, srv, Request{Op: "read", Path: p})
		if resp.Ok {
			t.Fatalf("越界路径 %q 竟然读成功：%+v", p, resp)
		}
		if resp.Text != "" || resp.Base64 != "" {
			t.Fatalf("越界路径 %q 泄漏了内容：%+v", p, resp)
		}
	}
	if resp := call(t, srv, Request{Op: "list", Path: "../"}); resp.Ok {
		t.Fatalf("list 越界竟然成功：%+v", resp)
	}
	c, _ := dial(t, srv)
	if err := WriteLine(c.conn, Request{Op: "download", Path: "escape/secret.txt"}); err != nil {
		t.Fatal(err)
	}
	var resp Response
	readJSONLine(t, c.br, &resp)
	if resp.Ok {
		t.Fatalf("download 越界竟然成功：%+v", resp)
	}
}

// 判据③：取消清理——中断上传不留正式文件、也不动原有文件、不留 .part
func TestWriteCancelCleansUp(t *testing.T) {
	root := newRoot(t)
	original := []byte("original-content")
	if err := os.WriteFile(filepath.Join(root, "target.bin"), original, 0o644); err != nil {
		t.Fatal(err)
	}
	srv := newServer(t, root)
	c, done := dial(t, srv)

	if err := WriteLine(c.conn, Request{Op: "write", Path: "target.bin"}); err != nil {
		t.Fatal(err)
	}
	var ready Response
	readJSONLine(t, c.br, &ready)
	if !ready.Ok {
		t.Fatalf("应进入可写状态：%+v", ready)
	}
	if err := WriteFrame(c.conn, []byte("half-of-new-content")); err != nil {
		t.Fatal(err)
	}
	c.conn.Close() // 取消 = 关流（不发终止帧）
	<-done

	raw, err := os.ReadFile(filepath.Join(root, "target.bin"))
	if err != nil || string(raw) != string(original) {
		t.Fatalf("取消后原文件被破坏：%v %q", err, raw)
	}
	if _, err := os.Stat(filepath.Join(root, "target.bin"+uploadPartSuffix)); !os.IsNotExist(err) {
		t.Fatalf("取消后应清理 .tierpart：%v", err)
	}

	c2, done2 := dial(t, srv)
	if err := WriteLine(c2.conn, Request{Op: "write", Path: "fresh.bin"}); err != nil {
		t.Fatal(err)
	}
	var ready2 Response
	readJSONLine(t, c2.br, &ready2)
	if err := WriteFrame(c2.conn, []byte("partial")); err != nil {
		t.Fatal(err)
	}
	c2.conn.Close()
	<-done2
	if _, err := os.Stat(filepath.Join(root, "fresh.bin")); !os.IsNotExist(err) {
		t.Fatalf("取消后不应存在正式文件：%v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "fresh.bin"+uploadPartSuffix)); !os.IsNotExist(err) {
		t.Fatalf("取消后不应存在临时文件：%v", err)
	}
}

// 判据④：错误码映射与 NAPI 契约对齐
func TestErrorCodes(t *testing.T) {
	root := newRoot(t)
	srv := newServer(t, root)
	cases := []struct {
		name string
		req  Request
		want string
	}{
		{"stat 缺文件", Request{Op: "stat", Path: "nope"}, "not_found"},
		{"read 目录", Request{Op: "read", Path: "sub"}, "is_dir"},
		{"download 目录", Request{Op: "download", Path: "sub"}, "is_dir"},
		{"mkdir 已存在", Request{Op: "mkdir", Path: "a.txt"}, "already_exists"},
		{"mkdir 根", Request{Op: "mkdir", Path: "."}, "invalid_name"},
		{"写根", Request{Op: "write", Path: "."}, "invalid_name"},
		{"写不存在目录", Request{Op: "write", Path: "nodir/x"}, "not_found"},
		{"未知操作", Request{Op: "nope"}, "invalid_arg"},
		{"list 缺目录", Request{Op: "list", Path: "nodir"}, "not_found"},
	}
	for _, tc := range cases {
		resp := call(t, srv, tc.req)
		if resp.Ok || resp.Code != tc.want {
			t.Fatalf("%s：期望 code=%s，实得 %+v", tc.name, tc.want, resp)
		}
		if resp.Msg == "" {
			t.Fatalf("%s：msg 不应为空", tc.name)
		}
	}
}

// 判据⑤：内联读取的上限与截断标记（readText/readImage 的 maxBytes 语义）
func TestReadCaps(t *testing.T) {
	root := newRoot(t)
	big := make([]byte, 4096)
	for i := range big {
		big[i] = 'x'
	}
	if err := os.WriteFile(filepath.Join(root, "big.txt"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	srv := newServer(t, root)

	resp := call(t, srv, Request{Op: "read", Path: "big.txt", MaxBytes: 100})
	if !resp.Ok || len(resp.Text) != 100 || !resp.Truncated || resp.Size != 4096 {
		t.Fatalf("maxBytes 截断语义不符：len=%d truncated=%v size=%d", len(resp.Text), resp.Truncated, resp.Size)
	}
	resp = call(t, srv, Request{Op: "read", Path: "big.txt"})
	if !resp.Ok || len(resp.Text) != 4096 || resp.Truncated {
		t.Fatalf("默认上限应读全：len=%d truncated=%v", len(resp.Text), resp.Truncated)
	}
	resp = call(t, srv, Request{Op: "read", Path: "big.txt", MaxBytes: maxInlineRead * 4})
	if !resp.Ok || len(resp.Text) != 4096 {
		t.Fatalf("超大 maxBytes 应夹到硬上限：%+v", resp)
	}
}

// 边界：请求行不是 JSON / 缺 op → invalid_arg（问候帧仍先到）
func TestBadRequestLine(t *testing.T) {
	root := newRoot(t)
	srv := newServer(t, root)
	c, _ := dial(t, srv)
	if _, err := c.conn.Write([]byte("{not json}\n")); err != nil {
		t.Fatal(err)
	}
	var resp Response
	readJSONLine(t, c.br, &resp)
	if resp.Ok || resp.Code != "invalid_arg" {
		t.Fatalf("非法请求应回 invalid_arg：%+v", resp)
	}
	c2, _ := dial(t, srv)
	if _, err := c2.conn.Write([]byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	readJSONLine(t, c2.br, &resp)
	if resp.Ok || resp.Code != "invalid_arg" {
		t.Fatalf("缺 op 应回 invalid_arg：%+v", resp)
	}
}
