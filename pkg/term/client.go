//go:build !windows

// 终端服务的客户端半边（tasks 3.5；手机核 NAPI 侧在 4.2 用它）。
//
// 与 service.go 同包：帧协议一处定义。拨流以函数注入（生产 = 拨 `隧道IP:<TermPort>`
// 的普通 TCP，出口按豁免规则转投后端本机 127.0.0.1:<TermPort>），因此不依赖
// gvisor/隧道实现。
package term

import (
	"context"
	"errors"
	"net"
)

// 供外部使用的帧类型（与 frames.go 的内部常量一一对应）。
const (
	OpHello      = opHello
	OpData       = opData
	OpResize     = opResize
	OpEnded      = opEnded
	OpList       = opList
	OpKill       = opKill
	OpError      = opError
	OpState      = opState
	OpAttached   = opAttached
	OpReplayDone = opReplayDone
	OpOK         = opOK
	OpGreeting   = opGreeting
)

// StreamDial 起一条内部流（生产 = 拨隧道 IP 的 TermPort，出口豁免转投本机同端口）。
type StreamDial func(ctx context.Context) (net.Conn, error)

// Client 终端服务客户端（每条腿一条流；会话由后端持有，断腿不杀进程）。
type Client struct{ Dial StreamDial }

// Conn 一条已建立（GREETING 已读）的会话腿。
type Conn struct {
	conn     net.Conn
	Ver      byte
	Features uint32
}

// Open 起一条腿并读 GREETING（不 attach；用于 LIST/KILL 这类一锤子命令）。
func (c *Client) Open(ctx context.Context) (*Conn, error) {
	if c.Dial == nil {
		return nil, errors.New("term: Client.Dial 未配置")
	}
	conn, err := c.Dial(ctx)
	if err != nil {
		return nil, err
	}
	f, err := readTermFrame(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if f.op != opGreeting {
		conn.Close()
		return nil, errors.New("term: 首帧不是 GREETING")
	}
	ver, feats, err := decGreeting(f.payload)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &Conn{conn: conn, Ver: ver, Features: feats}, nil
}

// Attach 起一条腿并 attach/创建会话（create=false 时只 attach 已存在会话）。
func (c *Client) Attach(ctx context.Context, name string, cols, rows uint16, create bool) (*Conn, error) {
	conn, err := c.Open(ctx)
	if err != nil {
		return nil, err
	}
	if err := conn.Send(opHello, encHello(cols, rows, create, name)); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// List 列会话（返回服务端 LIST-REPLY 的原始 JSON）。
func (c *Client) List(ctx context.Context) ([]byte, error) {
	conn, err := c.Open(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.Send(opList, nil); err != nil {
		return nil, err
	}
	f, err := conn.ReadFrame()
	if err != nil {
		return nil, err
	}
	if f.Op != opList {
		return nil, termError(f)
	}
	return f.Payload, nil
}

// Kill 结束会话（幂等；会话不存在时服务端回 ERR）。
func (c *Client) Kill(ctx context.Context, name string) error {
	conn, err := c.Open(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.Send(opKill, encName(name)); err != nil {
		return err
	}
	f, err := conn.ReadFrame()
	if err != nil {
		return err
	}
	if f.Op != opOK {
		return termError(f)
	}
	return nil
}

// Frame 一帧（导出版本，op 见 Op* 常量）。
type Frame struct {
	Op      byte
	Payload []byte
}

// Send 发一帧。
func (c *Conn) Send(op byte, payload []byte) error {
	_, err := c.conn.Write(encodeTermFrame(op, payload))
	return err
}

// SendData 发终端输入（按 ≤16KiB 分片，与 APP 侧契约一致）。
func (c *Conn) SendData(p []byte) error {
	for len(p) > 0 {
		n := len(p)
		if n > termDataChunk {
			n = termDataChunk
		}
		if err := c.Send(opData, p[:n]); err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

// Resize 通知窗口尺寸。
func (c *Conn) Resize(cols, rows uint16) error { return c.Send(opResize, encResize(cols, rows)) }

// ReadFrame 读一帧（调用方可自行处理 DATA/STATE/ATTACHED/ENDED/ERR）。
func (c *Conn) ReadFrame() (Frame, error) {
	f, err := readTermFrame(c.conn)
	if err != nil {
		return Frame{}, err
	}
	return Frame{Op: f.op, Payload: f.payload}, nil
}

// Conn 底层连接（需要自定 deadline 时用）。
func (c *Conn) NetConn() net.Conn { return c.conn }

// Close 关腿（会话继续运行，符合「客户端断开只摘泵」语义）。
func (c *Conn) Close() error { return c.conn.Close() }

// termError 把 ERR 帧转成 error（其它帧类型也算异常）。
func termError(f Frame) error {
	if f.Op == opError {
		if code, msg, err := decErrPayload(f.Payload); err == nil {
			return errors.New("term: " + code + ": " + msg)
		}
	}
	return errors.New("term: 非预期帧类型")
}

// decErrPayload 解析 ERR 载荷：codeLen(1) + code + msgLen(2 LE) + msg（encError 的逆）。
func decErrPayload(p []byte) (code, msg string, err error) {
	if len(p) < 3 {
		return "", "", errTermFrame
	}
	n := int(p[0])
	if len(p) < 1+n+2 {
		return "", "", errTermFrame
	}
	code = string(p[1 : 1+n])
	off := 1 + n
	m := int(p[off]) | int(p[off+1])<<8
	if len(p) < off+2+m {
		return "", "", errTermFrame
	}
	msg = string(p[off+2 : off+2+m])
	return code, msg, nil
}
