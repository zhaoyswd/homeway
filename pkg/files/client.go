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
		return nil, Errf("op_failed", "读问候帧失败：%v", err)
	}
	var g Greeting
	if err := unmarshalLine(line, &g); err != nil {
		conn.Close()
		return nil, Errf("op_failed", "问候帧不是 JSON：%v", err)
	}
	if !g.Ok {
		conn.Close()
		return nil, Errf("op_failed", "问候帧失败")
	}
	return &Session{conn: conn, br: br, Root: g.Root, Ver: g.Ver, ReadOnly: !g.RW}, nil
}

// Close 关闭本命令的流。
func (s *Session) Close() error { return s.conn.Close() }

// call 发一条命令并读响应；ok=false ⇒ *Error（带稳定 code）。
func (s *Session) call(req Request) (Response, error) {
	if err := WriteLine(s.conn, req); err != nil {
		return Response{}, Errf("op_failed", "发请求失败：%v", err)
	}
	line, err := s.br.ReadBytes('\n')
	if err != nil {
		return Response{}, Errf("op_failed", "读响应失败：%v", err)
	}
	var resp Response
	if err := unmarshalLine(line, &resp); err != nil {
		return Response{}, Errf("op_failed", "响应不是 JSON：%v", err)
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
	resp, err := s.call(Request{Op: "list", Path: path})
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
	resp, err := s.call(Request{Op: "stat", Path: path})
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
	_, err = s.call(Request{Op: "mkdir", Path: path})
	return err
}

// Read 内联读取（mode="" 文本、mode="image" 回 base64）。
func (c *Client) Read(ctx context.Context, path, mode string, maxBytes int64) (Response, error) {
	s, err := c.Open(ctx)
	if err != nil {
		return Response{}, err
	}
	defer s.Close()
	return s.call(Request{Op: "read", Path: path, Mode: mode, MaxBytes: maxBytes})
}

// Download 大文件下载：把载荷帧原样写进 w，返回总字节数。
// 取消 = 关流（调用方 cancel ctx 或 Close），服务端无需清理。
func (c *Client) Download(ctx context.Context, path string, w io.Writer) (int64, error) {
	s, err := c.Open(ctx)
	if err != nil {
		return 0, err
	}
	defer s.Close()
	if _, err := s.call(Request{Op: "download", Path: path}); err != nil {
		return 0, err
	}
	buf := make([]byte, MaxChunk)
	var total int64
	for {
		n, err := ReadFrame(s.br, buf)
		if err != nil {
			return total, Errf("op_failed", "下载中断：%v", err)
		}
		if n == 0 {
			return total, nil
		}
		if _, err := w.Write(buf[:n]); err != nil {
			return total, Errf("op_failed", "写本地失败：%v", err)
		}
		total += int64(n)
	}
}

// Upload 大文件上传：请求 → 服务端 ready → 帧 → 终止帧（提交）。
// **返回前若发生错误/ctx 取消，会关流但不发终止帧 ⇒ 服务端删 .tierpart，目标不变。**
func (c *Client) Upload(ctx context.Context, path string, r io.Reader, size int64, onProgress func(int64)) (int64, error) {
	s, err := c.Open(ctx)
	if err != nil {
		return 0, err
	}
	defer s.Close()
	if _, err := s.call(Request{Op: "write", Path: path, Size: size}); err != nil {
		return 0, err
	}
	buf := make([]byte, MaxChunk)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, Errf("canceled", "已取消")
		}
		n, rerr := r.Read(buf)
		if n > 0 {
			if err := WriteFrame(s.conn, buf[:n]); err != nil {
				return total, Errf("op_failed", "上传中断：%v", err)
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
			return total, Errf("op_failed", "读本地失败：%v", rerr)
		}
	}
	if err := WriteFrame(s.conn, nil); err != nil { // 终止帧 = 提交
		return total, Errf("op_failed", "提交失败：%v", err)
	}
	line, err := s.br.ReadBytes('\n')
	if err != nil {
		return total, Errf("op_failed", "读提交结果失败：%v", err)
	}
	var resp Response
	if err := unmarshalLine(line, &resp); err != nil {
		return total, Errf("op_failed", "提交结果不是 JSON：%v", err)
	}
	if !resp.Ok {
		return total, &Error{Code: resp.Code, Msg: resp.Msg}
	}
	return total, nil
}
