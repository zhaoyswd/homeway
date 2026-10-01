package files

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// pipeDialer：把 Client 的每次拨流接到 Server 上（内存管道，不起真隧道）。
func pipeDialer(srv *Server) StreamDial {
	return func(ctx context.Context) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go srv.ServeConn(c2)
		return c1, nil
	}
}

// 客户端半边：问候/列出/读/上传下载/错误码透传/取消清理。
func TestClientAgainstServer(t *testing.T) {
	root := newRoot(t)
	srv := newServer(t, root)
	cli := &Client{Dial: pipeDialer(srv)}
	ctx := context.Background()

	// 问候（Open 校验过 root/ver）
	s, err := cli.Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if s.Root != srv.RootDir() || s.Ver != Version {
		t.Fatalf("问候字段不符：root=%q ver=%d", s.Root, s.Ver)
	}
	s.Close()

	ents, err := cli.List(ctx, ".")
	if err != nil || len(ents) != 2 {
		t.Fatalf("List: err=%v ents=%v", err, ents)
	}
	if e, err := cli.Stat(ctx, "a.txt"); err != nil || e.Size != 5 {
		t.Fatalf("Stat: err=%v entry=%+v", err, e)
	}
	if err := cli.Mkdir(ctx, "newdir"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	resp, err := cli.Read(ctx, "a.txt", "", 0)
	if err != nil || resp.Text != "hello" {
		t.Fatalf("Read: err=%v resp=%+v", err, resp)
	}

	// 上传 → 下载回读
	payload := bytes.Repeat([]byte("0123456789"), 5000) // 50KB（跨多帧）
	var progress []int64
	n, err := cli.Upload(ctx, "newdir/big.bin", bytes.NewReader(payload), int64(len(payload)), func(v int64) {
		progress = append(progress, v)
	})
	if err != nil || n != int64(len(payload)) {
		t.Fatalf("Upload: err=%v n=%d", err, n)
	}
	if len(progress) == 0 || progress[len(progress)-1] != int64(len(payload)) {
		t.Fatalf("进度回调不符：%v", progress)
	}
	var out bytes.Buffer
	dn, err := cli.Download(ctx, "newdir/big.bin", &out)
	if err != nil || dn != int64(len(payload)) || !bytes.Equal(out.Bytes(), payload) {
		t.Fatalf("Download: err=%v n=%d 内容一致=%v", err, dn, bytes.Equal(out.Bytes(), payload))
	}

	// 错误码透传（NAPI 层直接消费 code）
	if _, err := cli.Stat(ctx, "nope"); err == nil {
		t.Fatal("缺文件应报错")
	} else {
		var fe *Error
		if !errors.As(err, &fe) || fe.Code != "not_found" {
			t.Fatalf("错误码不符：%v", err)
		}
	}

	// 取消上传：本地读端在 chunk 中途失败 ⇒ 关流不发终止帧 ⇒ 目标不变、无 .part
	original := []byte("keep-me")
	if err := os.WriteFile(filepath.Join(root, "keep.txt"), original, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = cli.Upload(ctx, "keep.txt", &failReader{limit: 10}, 0, nil)
	if err == nil {
		t.Fatal("本地读失败应报错")
	}
	raw, rerr := os.ReadFile(filepath.Join(root, "keep.txt"))
	if rerr != nil || string(raw) != string(original) {
		t.Fatalf("取消后原文件被破坏：%v %q", rerr, raw)
	}
	if _, serr := os.Stat(filepath.Join(root, "keep.txt"+uploadPartSuffix)); !os.IsNotExist(serr) {
		waitNotExist(t, filepath.Join(root, "keep.txt"+uploadPartSuffix))
	}
}

// waitNotExist：服务端清理是异步的（客户端关流 → 服务端读 EOF → 清理），
// 给一个短轮询窗口再判定「不留半截」。
func waitNotExist(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("取消后仍残留 %s", path)
}

// failReader：先喂 limit 字节，然后报错（模拟本地读失败/取消）。
type failReader struct {
	limit int
	sent  int
}

func (r *failReader) Read(p []byte) (int, error) {
	if r.sent >= r.limit {
		return 0, errors.New("本地读失败")
	}
	n := copy(p, strings.Repeat("x", r.limit-r.sent))
	r.sent += n
	return n, nil
}

// fakeDownloadServer 起一个只服务一条流的假服务端：问候 → 读请求 → 回响应行
// （声明 size）→ 发 payload → 发终止帧。用来构造真服务端做不到的畸形形态。
func fakeDownloadServer(t *testing.T, declared int64, payload []byte) StreamDial {
	t.Helper()
	return func(ctx context.Context) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go func() {
			defer c2.Close()
			if err := WriteLine(c2, Greeting{Ok: true, Root: "/fake", Ver: Version}); err != nil {
				return
			}
			br := bufio.NewReader(c2)
			if _, err := ReadRequest(br); err != nil {
				return
			}
			if err := WriteLine(c2, Response{Ok: true, Size: declared}); err != nil {
				return
			}
			if len(payload) > 0 {
				if err := WriteFrame(c2, payload); err != nil {
					return
				}
			}
			_ = WriteFrame(c2, nil) // 终止帧（对端自称传完）
		}()
		return c1, nil
	}
}

// TestDownloadShortTransferRejected（FIX-40）：响应行声明 100 字节、实际只给 10 就发
// 终止帧——必须报错（此前静默成功 = 半截文件落盘）。
func TestDownloadShortTransferRejected(t *testing.T) {
	cli := &Client{Dial: fakeDownloadServer(t, 100, bytes.Repeat([]byte("x"), 10))}
	var out bytes.Buffer
	n, err := cli.Download(context.Background(), "f.bin", &out)
	if err == nil {
		t.Fatalf("短传应报错，实际成功（收 %d 字节）", n)
	}
	if !strings.Contains(err.Error(), "下载不完整") || !strings.Contains(err.Error(), "100") ||
		!strings.Contains(err.Error(), "10") {
		t.Fatalf("错误应含声明/实收数字：%v", err)
	}
	var fe *Error
	if !errors.As(err, &fe) || fe.Code != CodeOpFailed {
		t.Fatalf("应归 CodeOpFailed：%v", err)
	}
}

// TestDownloadGrowingFileTolerated（FIX-40 的反面）：实收**多于**声明（下载途中被
// 追加的合法形态）不报错——声明值只是取快照那刻的大小。
func TestDownloadGrowingFileTolerated(t *testing.T) {
	cli := &Client{Dial: fakeDownloadServer(t, 10, bytes.Repeat([]byte("x"), 32))}
	var out bytes.Buffer
	n, err := cli.Download(context.Background(), "grow.log", &out)
	if err != nil {
		t.Fatalf("生长中的文件不应报错：%v", err)
	}
	if n != 32 || out.Len() != 32 {
		t.Fatalf("应完整收到 32 字节，实际 %d/%d", n, out.Len())
	}
}
