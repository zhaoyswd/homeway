package daemon

// term_remote.go — pkg/term RemoteTerm 缝的 daemon 实现（term-remote 1.1，design
// D1/D2）：`--host` 模式的寻址与拨号都经控制面——Resolve = daemon.status 拉主机表 +
// resolveHostTarget（与 host delete/status **同一份寻址实现与文案**，3c 退出口判据
// 「--host 寻址统一」考此）；Dial = control.Dial（control.sock）→
// stream.open{kind:term, host} → streamConn 适配器（ClientStream →
// io.ReadWriteCloser）。term 帧协议端到端原样承载，零 wire 改动。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zhaoyswd/homeway/clientcore/facade"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/zhaoyswd/homeway/internal/control"
	"github.com/zhaoyswd/homeway/pkg/term"
)

// 远端拨号参数。
const (
	// termStreamCloseBudget stream.close 尽力而为的兜底预算（错误忽略）。
	termStreamCloseBudget = 2 * time.Second
)

// TermRemote 构造 pkg/term 的远程接入缝实现（cmd/homeway 接线：
// term.CLI(rest, daemon.TermRemote(version))）。
func TermRemote(version string) term.RemoteTerm {
	return &termRemote{version: version}
}

type termRemote struct{ version string }

// ResolveHostRef 把 --host 的名称/全长 hex/无歧义短前缀解析为 hex id（寻址 = 与
// host delete/status 同一份 resolveHostTarget：同一规则、同一歧义报错文案）。
// 预算口径（exec-r1 L1 校正，原「总预算 10s」措辞不准）：解析与打开**各**用一次
// `--timeout` 预算（CLI 侧两次独立的 context.WithTimeout；默认各 10s，最坏相加 20s）。
func (r *termRemote) ResolveHostRef(ctx context.Context, stateDir, ref string) (string, string, error) {
	dir := stateDir
	if dir == "" {
		dir = DefaultStateDir()
	}
	// 空串错误文案按调用面参数化（r1 P2-7）：resolveHostTarget 的空串分支写死
	// 「homeway host delete」——term 面先拦，不出现 host delete。
	if strings.TrimSpace(ref) == "" {
		return "", "", errors.New("空寻址串不可用——homeway term <子命令> --host 需要 <name|id>（homeway host list 查看在表主机）")
	}
	hosts, closeC, err := fetchHostsForTerm(ctx, dir, r.version)
	if err != nil {
		return "", "", err
	}
	defer closeC()
	return resolveHostTarget(hosts, ref)
}

// DialTerm 打开到目标主机 term 服务的字节流。ctx = 「控制面连接 + stream.open」
// 总预算（CLI --timeout，默认 10s）——目标主机黑洞时先退即放弃该次打开，不静默
// 等满服务端拨号预算（dialTimeout = 30s 上限兜底，r1 P2-9）。
func (r *termRemote) DialTerm(ctx context.Context, stateDir, hexID string) (io.ReadWriteCloser, error) {
	dir := stateDir
	if dir == "" {
		dir = DefaultStateDir()
	}
	c, err := dialControl(ctx, dir, r.version)
	if err != nil {
		return nil, err
	}
	st, err := c.OpenStream(ctx, hexID)
	if err != nil {
		c.Close()
		return nil, streamOpenErr(err)
	}
	return &streamConn{c: c, st: st}, nil
}

// dialControl 连 control.sock 并翻连接层错误（层①文案，term-remote 1.3）。
func dialControl(ctx context.Context, stateDir, version string) (*control.Client, error) {
	sock := filepath.Join(stateDir, control.ControlSockName)
	c, _, err := control.Dial(ctx, sock, control.FrontendInfo{Kind: "cli", Name: "homeway-term", Version: version})
	if err == nil {
		return c, nil
	}
	return nil, controlDialErr(stateDir, sock, err)
}

// controlDialErr 控制面连接层错误 → 可行动文案（层①，design D4：ENOENT 带出
// 「--host 模式下 --state 指守护进程 state」的指代提示——用户按本地面习惯误给
// 出口 state 时可自查；该目录有 term.sock 无 control.sock 时直接点名像是出口 state）。
func controlDialErr(stateDir, sock string, err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		hint := ""
		if _, terr := os.Stat(filepath.Join(stateDir, "term.sock")); terr == nil {
			hint = "；该目录有 term.sock 无 control.sock——像是把 --state 指到了出口 state 目录"
		}
		return fmt.Errorf("homeway daemon 未在运行（%s 不存在%s）\n"+
			"--host 模式下 --state 指守护进程 state 目录（默认 ~/.config/homeway/daemon，control.sock 所在）；先启动：homeway daemon --state %s", sock, hint, stateDir)
	case errors.Is(err, syscall.ECONNREFUSED):
		return fmt.Errorf("连接被拒：%s 像是残留 socket（daemon 进程已退出）；确认 daemon 在跑，或删除该文件后重试", sock)
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return fmt.Errorf("无权连接 %s（control.sock 仅属主可用；命令须与 daemon 同一用户运行）", sock)
	}
	return fmt.Errorf("连不上 daemon 控制面（%s）：%w", sock, err)
}

// streamOpenErr 层②：stream.open 错误码 → 可行动文案（no_host/not_ready/
// stream_refused——后者是「主机离线/隧道未通」的主文案面，design D4）。
func streamOpenErr(err error) error {
	var code control.CodeError
	if errors.As(err, &code) {
		switch string(code) {
		case facade.CodeNoHost:
			return errors.New("主机不在守护进程表中（no_host）；homeway host list 查看在表主机")
		case facade.CodeNotReady:
			return errors.New("守护进程注册表未就绪（not_ready；client 角色启动中/重建窗口），稍后重试")
		case facade.CodeStreamRefused:
			return errors.New("与主机的流打开被拒（stream_refused）——主机离线、隧道未通或主机会话不可用；用 homeway host status <name> 核对会话与链路态")
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("连接/打开超预算（--timeout）：daemon 未应答或目标主机拨号黑洞；可用 --timeout 加大预算后重试")
	}
	return fmt.Errorf("stream.open 失败：%w", err)
}

// fetchHostsForTerm 经控制面拉主机表（term 面的 fetchHosts 对应物——连接层错误
// 走 term 面文案 controlDialErr，host 面的 fetchHosts 文案保持不动）。
func fetchHostsForTerm(ctx context.Context, stateDir, version string) ([]control.HostState, func(), error) {
	c, err := dialControl(ctx, stateDir, version)
	if err != nil {
		return nil, nil, err
	}
	closeC := func() { c.Close() }
	raw, err := c.Request(ctx, facade.OpDaemonStatus, nil)
	if err != nil {
		closeC()
		return nil, nil, fmt.Errorf("daemon.status 失败：%w", err)
	}
	var st control.DaemonStatusResult
	if err := json.Unmarshal(raw, &st); err != nil {
		closeC()
		return nil, nil, fmt.Errorf("daemon.status 载荷解析失败：%w", err)
	}
	return st.Hosts, closeC, nil
}

// ---- streamConn：ClientStream → io.ReadWriteCloser（design D2）----

// streamConn 适配器。不实现 net.Conn 的 deadline 族（半语义不装——满足
// io.ReadWriteCloser 即可，CLI 从不设 deadline，D1 已核）。Read 内部缓冲跨帧重组；
// 流终结（stream.end 已收 / 连接级断开）先记原因、排干余量后以 *term.RemoteEndError
// 终结（errors.Is(err, io.EOF) 成立；Reason ∈ closed|gone|conn 供 CLI 三态文案，D5）。
type streamConn struct {
	c  *control.Client
	st *control.ClientStream

	mu       sync.Mutex
	buf      []byte // 已从 Recv 拉取、未交付
	reason   string // 终结原因（"" = 未终结；closed|gone = end 已收；conn = 连接级断开）
	finished bool   // 余量已排干（此后 Read 恒终结错误）
}

// Read 从流读字节（跨帧重组；终结后排干余量再返回终结错误）。
func (sc *streamConn) Read(p []byte) (int, error) {
	for {
		sc.mu.Lock()
		if len(sc.buf) > 0 {
			n := copy(p, sc.buf)
			sc.buf = sc.buf[n:]
			sc.mu.Unlock()
			return n, nil
		}
		if sc.finished {
			reason := sc.reason
			sc.mu.Unlock()
			// reason 只在锁内读（exec-r1 L5）：锁内先拷局部再解锁返回，守住「锁内
			// 读写」约定——单 reader 调用下无实害，但并发 Read 一旦出现就是数据竞争。
			return 0, &term.RemoteEndError{Reason: reason}
		}
		sc.mu.Unlock()
		select {
		case b := <-sc.st.Recv():
			sc.mu.Lock()
			sc.buf = append(sc.buf, b...)
			sc.mu.Unlock()
		case r := <-sc.st.End():
			// 流级终结（closed|gone）：reader 按帧序投递，end 之前的数据已全在 recv
			// 队列——排干余量（数据先于终结语义）。
			sc.mu.Lock()
			if sc.reason == "" {
				sc.reason = r
			}
			sc.drainLocked()
			sc.mu.Unlock()
		case <-sc.c.Closed():
			// 连接级断开（无 end）：recv 不再进新数据，排干余量后以 conn 终结。
			sc.mu.Lock()
			if sc.reason == "" {
				sc.reason = term.RemoteEndConn
			}
			sc.drainLocked()
			sc.mu.Unlock()
		}
	}
}

// drainLocked 终结后排干 recv 余量（非阻塞）：空了置 finished。调用方持 sc.mu。
func (sc *streamConn) drainLocked() {
	for !sc.finished {
		select {
		case b := <-sc.st.Recv():
			sc.buf = append(sc.buf, b...)
		default:
			sc.finished = true
		}
	}
}

// Write 走 Send（流终结即报错——L4 上行显式化；≤16KiB 分片由 Send 内建）。
// 返回值口径：错误时返回 0（流已死，字节数无意义——调用方按错误收流）。
func (sc *streamConn) Write(p []byte) (int, error) {
	if err := sc.st.Send(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close 收口。**顺序是死锁问题不是风格问题**（design D2 / r1 P0-2）：
// ClientStream.Close 走 Request、其应答由唯一 reader 协程投递；L4 的阻塞投递
// 恰会在下游停读（Ctrl-S 冻结输出）时把 reader 卡在 recv<-——若先 stream.Close
// 等 rsp 则等不到（CLI 从不给 term 连接设 deadline；有 ≤2s 兜底 ctx 时退化为等满
// 该 ctx 才返回，**无界** ctx 才恒挂死），期间 Client.Close 迟迟不执行、<-c.closed
// 逃生口形同失效。故：先 Client.Close()（closed 信号解阻塞 reader）；
// stream.Close 尽力而为（≤2s 有界 ctx、并发发起、错误忽略——连接级断开即触发
// daemon 对在册流全部 teardown（不发 end），出口腿照常回收）。一命令一连接，
// CLI 场景无共享需求。
func (sc *streamConn) Close() error {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ctx, cancel := context.WithTimeout(context.Background(), termStreamCloseBudget)
		defer cancel()
		_ = sc.st.Close(ctx) // 尽力而为：错误忽略
	}()
	sc.c.Close() // 唯一可靠逃生口：closed 解阻塞 reader 的阻塞投递
	select {
	case <-done:
	case <-time.After(termStreamCloseBudget + time.Second):
		// 兜底（理论不可达：ctx 有界）；Close 幂等语义不受影响。
	}
	return nil
}
