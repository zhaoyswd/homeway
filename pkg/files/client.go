// files 协议客户端半边（手机核的任务在 tasks 4.2 用它对接 NAPI）。
//
// 与 Server 同包：线上格式一处定义，两端不会漂移。**不依赖 gvisor/隧道实现**——
// 拨流是注入的函数（生产 = 拨 `隧道IP:<FilesPort>` 的普通 TCP，出口按豁免规则
// 转投后端本机 127.0.0.1:<FilesPort>；早期经 flows.CONNECT，随 flows 退役已直拨）。
//
// 语义对齐 NAPI 契约：每命令一条流（Open → 一条命令 → Close）。
package files

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
)

// StreamDial 起一条内部流（生产 = 拨隧道 IP 的 FilesPort，出口豁免转投本机同端口）。
type StreamDial func(ctx context.Context) (net.Conn, error)

// Client 一次会话里的客户端（无跨命令状态；每个方法自成一条流）。
type Client struct {
	Dial StreamDial
}

// Session 一条已建立（问候帧已读）的流。
type Session struct {
	conn     net.Conn
	br       *bufio.Reader
	Root     string
	Ver      int
	ReadOnly bool // 恒为 false（协议固定读写）；保留字段供未来/诊断
}

// Open 起一条流并读问候帧。
// CodeStreamOpen：**流开场失败**（拨号之后读问候那一段）的稳定错误码。
//
// 为什么要单列一个码（而不是继续用 op_failed）：op_failed 同时表示「出口侧的真实操作失败」与
// 「请求已送达但响应丢了」，二者都**不能**被下游当成「通道不可达」——手机核（tier 仓
// cmd/tailcat/app_files_native.go 的 normalizeOpStreamErr）会把「流开场失败」归一成
// bridge_down 交给 App 的自动重试，前提是它必须**证明请求未送达**。靠文案前缀认阶段是脆的
// （改文案即静默失效），所以这里给一个可以判等的码。
//
// 契约：这个码只在 Open（问候阶段）使用；call 阶段（发请求/读响应）保持 op_failed 不变
// （那时请求可能已经送达，重放有重复副作用风险）。改本码要同步改核侧的归一化与它的单测。
const CodeStreamOpen = "stream_open"

func (c *Client) Open(ctx context.Context) (*Session, error) {
	if c.Dial == nil {
		return nil, errors.New("files: Client.Dial 未配置")
	}
	conn, err := c.Dial(ctx)
	if err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadBytes('\n')
	if err != nil {
		conn.Close()
		return nil, Errw(CodeStreamOpen, err, "读问候帧失败：%v", err)
	}
	var g Greeting
	if err := unmarshalLine(line, &g); err != nil {
		conn.Close()
		return nil, Errw(CodeStreamOpen, err, "问候帧不是 JSON：%v", err)
	}
	if !g.Ok {
		conn.Close()
		return nil, Errf(CodeStreamOpen, "问候帧失败")
	}
	return &Session{conn: conn, br: br, Root: g.Root, Ver: g.Ver, ReadOnly: !g.RW}, nil
}

// Close 关闭本命令的流。
func (s *Session) Close() error { return s.conn.Close() }

// call 发一条命令并读响应；ok=false ⇒ *Error（带稳定 code）。
// 读写两侧的传输错误经 Errw 保留被包错误链（files-cli 1.2：远程面的流终结
// streamend.Error 经 errors.As 可达）；ctx 取消在两次读之间可观察（阻塞中的读由
// CLI 侧看门 Close 打断——传输不设 deadline 与取消可观察两口径分开，design D1）。
func (s *Session) call(ctx context.Context, req Request) (Response, error) {
	if err := ctx.Err(); err != nil {
		return Response{}, Errw("canceled", err, "已取消")
	}
	if err := WriteLine(s.conn, req); err != nil {
		return Response{}, Errw("op_failed", err, "发请求失败：%v", err)
	}
	if err := ctx.Err(); err != nil {
		return Response{}, Errw("canceled", err, "已取消")
	}
	line, err := s.br.ReadBytes('\n')
	if err != nil {
		return Response{}, Errw("op_failed", err, "读响应失败：%v", err)
	}
	var resp Response
	if err := unmarshalLine(line, &resp); err != nil {
		return Response{}, Errw("op_failed", err, "响应不是 JSON：%v", err)
	}
	if !resp.Ok {
		code := resp.Code
		if code == "" {
			code = "op_failed"
		}
		return resp, &Error{Code: code, Msg: resp.Msg}
	}
	return resp, nil
}

// List 列目录。
func (c *Client) List(ctx context.Context, path string) ([]Entry, error) {
	s, err := c.Open(ctx)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	resp, err := s.call(ctx, Request{Op: "list", Path: path})
	if err != nil {
		return nil, err
	}
	return resp.Entries, nil
}

// Stat 单条目信息。
func (c *Client) Stat(ctx context.Context, path string) (Entry, error) {
	s, err := c.Open(ctx)
	if err != nil {
		return Entry{}, err
	}
	defer s.Close()
	resp, err := s.call(ctx, Request{Op: "stat", Path: path})
	if err != nil {
		return Entry{}, err
	}
	if resp.Entry == nil {
		return Entry{}, Errf("op_failed", "响应缺 entry")
	}
	return *resp.Entry, nil
}

// Mkdir 新建目录。
func (c *Client) Mkdir(ctx context.Context, path string) error {
	s, err := c.Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	_, err = s.call(ctx, Request{Op: "mkdir", Path: path})
	return err
}

// Read 内联读取（mode="" 文本、mode="image" 回 base64）。
func (c *Client) Read(ctx context.Context, path, mode string, maxBytes int64) (Response, error) {
	s, err := c.Open(ctx)
	if err != nil {
		return Response{}, err
	}
	defer s.Close()
	return s.call(ctx, Request{Op: "read", Path: path, Mode: mode, MaxBytes: maxBytes})
}

// Download 大文件下载：把载荷帧原样写进 w，返回总字节数。
// 取消 = 关流（调用方 cancel ctx 或 Close），服务端无需清理。
// **签名冻结**（files-cli 1.2，r2 新-6）：App 调用点与集成测试零改——CLI 的 size
// 回调走 DownloadTo。
func (c *Client) Download(ctx context.Context, path string, w io.Writer) (int64, error) {
	return c.DownloadTo(ctx, path, w, nil)
}

// DownloadTo 大文件下载（files-cli 1.2 新增）：响应行的 size 经 onSize 交付一次
// （进度分母——不再多打一次 Stat）；onSize 可为 nil。其余语义与 Download 同。
func (c *Client) DownloadTo(ctx context.Context, path string, w io.Writer, onSize func(int64)) (int64, error) {
	s, err := c.Open(ctx)
	if err != nil {
		return 0, err
	}
	defer s.Close()
	resp, err := s.call(ctx, Request{Op: "download", Path: path})
	if err != nil {
		return 0, err
	}
	if onSize != nil {
		onSize(resp.Size)
	}
	buf := make([]byte, MaxChunk)
	var total int64
	for {
		if cerr := ctx.Err(); cerr != nil {
			return total, Errw("canceled", cerr, "已取消")
		}
		n, err := ReadFrame(s.br, buf)
		if err != nil {
			return total, Errw("op_failed", err, "下载中断：%v", err)
		}
		if n == 0 {
			return total, nil
		}
		if _, err := w.Write(buf[:n]); err != nil {
			return total, Errw("op_failed", err, "写本地失败：%v", err)
		}
		total += int64(n)
	}
}

// Upload 大文件上传：请求 → 服务端 ready → 帧 → 终止帧（提交）。
// **返回前若发生错误/ctx 取消，会关流但不发终止帧 ⇒ 服务端删 .tierpart，目标不变。**
// 读发循环的传输错误经 Errw 保留被包错误链（files-cli 1.2：写方向的流终结经
// daemon 适配层已归一 streamend.Error——errors.As 与读方向同判型）。
func (c *Client) Upload(ctx context.Context, path string, r io.Reader, size int64, onProgress func(int64)) (int64, error) {
	return c.upload(ctx, path, r, size, onProgress, nil)
}

// UploadLimiter 发送端限速缝（files-cli 1.4：CLI 注入令牌桶；nil = 不限）。上传
// 读发循环在每帧发送前 Await——「上行速率不超过标定安全值」的发送端速率义务
// （协议无 ack/credit、守护进程每流缓冲满即收流——无回压信号下的盲节流是发送端
// 唯一可用手段）。Await 吃 ctx（exec-r1 F5）：取消即时打断等待，返回非 nil 由
// 上传循环直接收流（小速率下单帧等待可达秒级，Ctrl-C 不被拖到等待烧尽）。
type UploadLimiter interface {
	Await(ctx context.Context, n int) error
}

func (c *Client) upload(ctx context.Context, path string, r io.Reader, size int64, onProgress func(int64), rate UploadLimiter) (int64, error) {
	s, err := c.Open(ctx)
	if err != nil {
		return 0, err
	}
	defer s.Close()
	if _, err := s.call(ctx, Request{Op: "write", Path: path, Size: size}); err != nil {
		return 0, err
	}
	buf := make([]byte, MaxChunk)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, Errw("canceled", err, "已取消")
		}
		n, rerr := r.Read(buf)
		if n > 0 {
			if rate != nil {
				if aerr := rate.Await(ctx, n); aerr != nil {
					return total, Errw("canceled", aerr, "已取消")
				}
			}
			if err := WriteFrame(s.conn, buf[:n]); err != nil {
				return total, Errw("op_failed", err, "上传中断：%v", err)
			}
			total += int64(n)
			if onProgress != nil {
				onProgress(total)
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			return total, Errw("op_failed", rerr, "读本地失败：%v", rerr)
		}
	}
	if err := WriteFrame(s.conn, nil); err != nil { // 终止帧 = 提交
		return total, Errw("op_failed", err, "提交失败：%v", err)
	}
	line, err := s.br.ReadBytes('\n')
	if err != nil {
		return total, Errw("op_failed", err, "读提交结果失败：%v", err)
	}
	var resp Response
	if err := unmarshalLine(line, &resp); err != nil {
		return total, Errw("op_failed", err, "提交结果不是 JSON：%v", err)
	}
	if !resp.Ok {
		return total, &Error{Code: resp.Code, Msg: resp.Msg}
	}
	return total, nil
}

// UploadRated 带发送端限速的上传（files-cli 1.4：CLI 的 put 注入令牌桶——rate 为
// nil 时与 Upload 等价）。App 调用点继续走 Upload（不限速，行为不变）。
func (c *Client) UploadRated(ctx context.Context, path string, r io.Reader, size int64, onProgress func(int64), rate UploadLimiter) (int64, error) {
	return c.upload(ctx, path, r, size, onProgress, rate)
}
