//go:build !windows

// term_cli_attach.go — `homeway term attach / new`（接入形态）的 raw 终端客户端
// （term-host-cli 任务 7.2–7.6，design D7）。
//
// 本地终端自己就是仿真器 ⇒ 走 raw 字节模式（D2）：本地 tty 置 raw 双向透传，
// 服务端的回放 + 尺寸哨兵 + 焦点重绘语义原样复用；查询应答（DA1/DSR/OSC 10/11）
// 由本地终端自己答（HELLO 尾随声明 capsRawTerminal ⇒ 服务端 vt 让位，任务 5.1 窄规则）。
//
// 生命周期硬约束（spec「raw 终端接入」）：
//   - 任何退出路径（正常分离 / 会话结束 / 错误 / 信号）都还原本地终端设置（defer + 信号处理，
//     还原失败提示 `reset`）；
//   - 非 TTY（stdin/stdout 任一不是终端）明确拒绝；
//   - TERM_SESSION_ID 指向目标会话时拒绝（输出回环防护）；
//   - 断腿（硬错误/停滞超限）服务端不发 ENDED ⇒ 裸 EOF ⇒ 可行动文案（任务 7.5）。
package term

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

// termiosT 是平台 termios 的别名（ioctl 请求常量按平台见 term_cli_tty_*.go）。
type termiosT = unix.Termios

// attachOpts 是 attach / new（接入形态）的参数。
type attachOpts struct {
	name      string // 目标会话（"" = attach 取最近活跃 / new 自动命名）
	stateDir  string
	create    bool   // new：创建并接入（HELLO bit0）
	reuse     bool   // -A：已存在则复用（不带 only-if-absent）
	takeover  bool   // -d：显式接管（HELLO bit2；其它腿收 ENDED(replaced)）
	autoNamed bool   // new 省略名字：host-<4hex> + already_exists 重试
	detachKey string // --detach-key 原始参数（^x / 单字符 / none）
}

// parseAttachArgs 解析 attach 参数（--flag value 与 --flag=value 两种形态都支持，
// CLI() 入口已用 expandFlagEq 归一）。
func parseAttachArgs(args []string) (attachOpts, error) {
	o := attachOpts{stateDir: DefaultStateDir()}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-d":
			o.takeover = true
		case a == "--state":
			if err := applyCommon(&o.stateDir, args, &i); err != nil {
				return o, err
			}
		case a == "--detach-key":
			v, err := nextArg(args, &i, "--detach-key")
			if err != nil {
				return o, err
			}
			o.detachKey = v
		case strings.HasPrefix(a, "-"):
			return o, fmt.Errorf("不认识的参数 %q（可用：-d、--detach-key <K>、--state <dir>）", a)
		default:
			if o.name != "" {
				return o, fmt.Errorf("只能给一个会话名（已有 %q）", o.name)
			}
			o.name = a
		}
	}
	return o, nil
}

// cliAttachCmd 是 attach / new（接入形态）的入口。返回 nil = 正常退出（分离/会话结束），
// 返回 error = 可行动错误（main 转 stderr + 退出码 1）。
func cliAttachCmd(o attachOpts) error {
	name := o.name
	if name != "" {
		// 嵌套防护（spec「拒绝接入自身会话」）：在会话 A 里 attach A 会输出回环。
		if os.Getenv("TERM_SESSION_ID") == "tailcat-"+name {
			return fmt.Errorf("已在会话 %s 里面（TERM_SESSION_ID 相同）：接入自身会让输出回环；换个会话，或先退出当前会话", name)
		}
		if err := validateName(name); err != nil {
			return err
		}
	}
	// 非 TTY 拒绝（spec「非交互终端拒绝」）。
	in, out := os.Stdin, os.Stdout
	if !cliIsTTY(in) || !cliIsTTY(out) {
		return errors.New("attach 需要交互终端（stdin/stdout 都是 TTY）；在管道/脚本里请用 list / new -d / delete")
	}
	tty, err := cliOpenTTY(in)
	if err != nil {
		return fmt.Errorf("读终端属性失败：%w", err)
	}
	if name == "" && !o.autoNamed {
		// attach 省略名字 = 最近活跃（D7）。
		n, perr := cliPickRecentSession(o.stateDir)
		if perr != nil {
			return perr
		}
		name = n
		if os.Getenv("TERM_SESSION_ID") == "tailcat-"+name {
			return fmt.Errorf("最近活跃的会话就是当前会话（%s）：接入自身会让输出回环；用 homeway term attach <别的会话>", name)
		}
	}

	// 接入：自动命名在这里重试（already_exists ⇒ 换名重来，最多 8 次）。
	if o.autoNamed {
		for i := 0; i < 8; i++ {
			n := genAutoName()
			conn, attached, aerr := cliAttachDial(o, tty, n)
			if aerr != nil {
				if isProtoCode(aerr, "already_exists") {
					continue
				}
				return aerr
			}
			return cliAttachRun(conn, tty, in, out, attached, n, o)
		}
		return errors.New("自动命名连续重名 8 次（运气太差）；请显式给名字：homeway term new <名字>")
	}
	conn, attached, aerr := cliAttachDial(o, tty, name)
	if aerr != nil {
		return aerr
	}
	return cliAttachRun(conn, tty, in, out, attached, name, o)
}

// cliAttachDial：连 term.sock → GREETING → HELLO（capsRawTerminal + 实例标识尾随）→ 首帧。
//
// HELLO 尾随**必须先 caps 后 ID、带 ID 必带 caps**（design D8 编码侧约束，encHelloTail 保证）。
func cliAttachDial(o attachOpts, tty *cliTTY, name string) (net.Conn, []byte, error) {
	conn, err := cliDialTerm(o.stateDir)
	if err != nil {
		return nil, nil, err
	}
	cols, rows := tty.size()
	var flags byte
	if o.create {
		flags |= helloFlagCreate
		if !o.reuse {
			flags |= helloFlagOnlyIfAbsent // `new <名字>`：重名报错、不静默接入
		}
	}
	if o.takeover {
		flags |= helloFlagTakeover // `attach -d` 显式接管（D8）
	}
	hello := encHello(cols, rows, false, name)
	hello[4] = flags
	hello = append(hello, encHelloTail(capsRawTerminal, true, cliClientID())...)
	if _, err := conn.Write(encodeTermFrame(opHello, hello)); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("发 HELLO：%w", err)
	}
	f, err := readTermFrame(conn)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("读 ATTACHED：%w", err)
	}
	if f.op == opError {
		code, msg, _ := decError(f.payload)
		conn.Close()
		return nil, nil, &protoError{code: code, msg: msg}
	}
	if f.op != opAttached {
		conn.Close()
		return nil, nil, fmt.Errorf("首帧应为 ATTACHED，收到 op 0x%02x（服务端与 CLI 不是同代？）", f.op)
	}
	return conn, f.payload, nil
}

// cliAttachRun：raw 模式 + 双向透传 + 分离键 + 尺寸同步 + 收尾（任务 7.2–7.6 的主体）。
func cliAttachRun(conn net.Conn, tty *cliTTY, in, out *os.File, attached []byte, name string, o attachOpts) error {
	prefix, keyEnabled, kerr := detachKeySpec(o.detachKey)
	if kerr != nil {
		_ = conn.Close()
		return kerr
	}

	// raw 模式：任何退出路径都还原（defer 是唯一收尾点；信号/分离只负责解除阻塞）。
	if err := tty.makeRaw(); err != nil {
		_ = conn.Close()
		return fmt.Errorf("切换 raw 模式失败：%w", err)
	}
	// 标题（7.6）：接入时设为「会话 · agent · 状态」，退出恢复原值（查询不到就不动）。
	titleOn := !strings.EqualFold(os.Getenv("HOMEWAY_TERM_TITLE"), "off")
	var oldTitle string
	if titleOn {
		oldTitle = ttyQueryTitle(in, out)
	}
	defer func() {
		if titleOn && oldTitle != "" {
			_, _ = out.Write([]byte("\x1b]2;" + oldTitle + "\x07"))
		}
		if rerr := tty.restore(); rerr != nil {
			fmt.Fprintf(os.Stderr, "\r\nhomeway term: 终端还原失败（%v）；画面混乱时执行 reset 修复\r\n", rerr)
		}
		_ = conn.Close()
	}()

	stop := make(chan struct{})     // 收尾信号（各 goroutine 退出）
	detachCh := make(chan struct{}) // 「干净退出」（分离 / 信号）：决定主循环返回 nil
	var exitNote atomic.Value       // string：干净退出时打的一行
	var stopOnce, detachOnce sync.Once
	finish := func() {
		stopOnce.Do(func() {
			close(stop)
			_ = conn.Close()
		})
	}
	exitCleanly := func(note string) {
		detachOnce.Do(func() {
			exitNote.Store(note)
			close(detachCh)
			finish()
		})
	}

	// 信号（SIGTERM/SIGHUP/SIGINT）：还原 tty 后干净退出（spec「异常退出还原终端」）。
	// raw 模式下 ISIG 已关，Ctrl-C 是普通字节直达会话；这里的信号来自 kill / 终端关闭。
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case <-sigCh:
			exitCleanly("收到信号退出（会话仍在运行）")
		case <-stop:
		}
	}()

	sendResize := func() {
		cols, rows := tty.size()
		_, _ = conn.Write(encodeTermFrame(opResize, encResize(cols, rows)))
	}

	// 尺寸同步（7.3）：SIGWINCH → RESIZE。
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer signal.Stop(winch)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-winch:
				sendResize()
			}
		}
	}()

	setTitle := func(agent, state byte, title string) {
		if !titleOn {
			return
		}
		_, _ = out.Write([]byte("\x1b]2;" + titleLine(name, agent, state, title) + "\x07"))
	}
	if titleOn {
		agent, state := attachedAgentState(attached)
		setTitle(agent, state, "")
	}

	// 输入循环（7.4 的状态机在输入路径上）：stdin → 分离键状态机 → DATA / 动作。
	dm := newDetachMachine(prefix, keyEnabled)
	go func() {
		buf := make([]byte, 8192)
		for {
			n, rerr := in.Read(buf)
			if n > 0 {
				pass, action := dm.feed(buf[:n])
				if len(pass) > 0 {
					if werr := connSendData(conn, pass); werr != nil {
						finish() // 写失败：主循环读端也会失败并给断链文案
						return
					}
				}
				if action == detachRealign {
					sendResize() // 前缀 + r：重新上报本腿尺寸（夺取活动权，D4）
				}
				if action == detachDetach {
					exitCleanly("已分离（会话 " + name + " 继续在出口运行）")
					return
				}
			}
			if rerr != nil {
				finish() // stdin 关了（tty master 被关）：交主循环收尾
				return
			}
		}
	}()

	// 主读循环：DATA → stdout；STATE → 标题；ENDED → 文案后正常退出；裸 EOF → 断链文案。
	for {
		f, rerr := readTermFrame(conn)
		if rerr != nil {
			select {
			case <-detachCh:
				if note, _ := exitNote.Load().(string); note != "" {
					fmt.Fprintln(os.Stderr, "\r\nhomeway term: "+note)
				}
				return nil
			default:
			}
			return fmt.Errorf("与出口的连接被断开（%v）；会话仍在运行，可用 homeway term attach %s 重新接入", rerr, name)
		}
		switch f.op {
		case opData:
			if _, werr := out.Write(f.payload); werr != nil {
				finish()
				return fmt.Errorf("写本地终端：%w", werr)
			}
		case opAttached, opReplayDone:
			// 握手帧：首帧 ATTACHED 已在 dial 阶段处理；重复/回放完成不做事。
		case opState:
			agent, state, title := decStateTitle(f.payload)
			setTitle(agent, state, title)
		case opEnded:
			code, reason := decEndedParts(f.payload)
			finish()
			fmt.Fprintln(os.Stderr, "\r\n"+endedMessage(name, code, reason))
			return nil
		case opError:
			code, msg, _ := decError(f.payload)
			finish()
			return &protoError{code: code, msg: msg}
		default:
			// 防御：raw 腿只该收 DATA/STATE/ENDED/ERROR（surface 区段帧绝不发给 raw 腿，D3）。
			fmt.Fprintf(os.Stderr, "\r\nhomeway term: 忽略未知帧 op 0x%02x（%dB）\r\n", f.op, len(f.payload))
		}
	}
}

// connSendData 把终端输入按 ≤16KiB 分片发 DATA（与 App 侧契约一致）。
func connSendData(conn net.Conn, p []byte) error {
	for len(p) > 0 {
		n := len(p)
		if n > termDataChunk {
			n = termDataChunk
		}
		if _, err := conn.Write(encodeTermFrame(opData, p[:n])); err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

// ---- HELLO / ATTACHED / STATE / ENDED 载荷的客户端侧解析 ----

// attachedAgentState 从 ATTACHED 载荷取 agent/state（cols(2) rows(2) modes(4) agent(1) state(1) name）。
func attachedAgentState(p []byte) (byte, byte) {
	if len(p) >= 10 {
		return p[8], p[9]
	}
	return agentUnknown, stateUnknown
}

// decStateTitle 解 STATE 载荷（agent(1) state(1) titleLen(2 LE) title）。
func decStateTitle(p []byte) (agent, state byte, title string) {
	if len(p) < 4 {
		return agentUnknown, stateUnknown, ""
	}
	n := int(binary.LittleEndian.Uint16(p[2:4]))
	if len(p) >= 4+n {
		title = string(p[4 : 4+n])
	}
	return p[0], p[1], title
}

// decEndedParts 解 ENDED 载荷（code(4 LE) reasonLen(1) reason）。
func decEndedParts(p []byte) (int32, string) {
	if len(p) < 5 {
		return 0, ""
	}
	reason := ""
	if n := int(p[4]); len(p) >= 5+n {
		reason = string(p[5 : 5+n])
	}
	return int32(binary.LittleEndian.Uint32(p[0:4])), reason
}

// endedMessage 按 D8 词表把 ENDED 翻成可行动文案（reason 词表：replaced / self_reconnect）。
func endedMessage(name string, code int32, reason string) string {
	switch {
	case code == termEndReplaced && reason == termReasonSelfReconnect:
		return fmt.Sprintf("homeway term: 本实例的新连接替换了这条腿（self_reconnect）；重新接入：homeway term attach %s", name)
	case code == termEndReplaced && reason == termReasonReplaced:
		return fmt.Sprintf("homeway term: 会话 %s 已被另一客户端接管（replaced）；重新接入：homeway term attach %s", name, name)
	case code == termEndReplaced:
		return fmt.Sprintf("homeway term: 会话 %s 的这条腿被服务端结束（%s）", name, reason)
	case code == termEndKilled:
		return fmt.Sprintf("homeway term: 会话 %s 已被关闭（App 或 homeway term delete）", name)
	case code == termEndServiceStopped:
		return fmt.Sprintf("homeway term: 出口服务正在退出，会话 %s 已结束", name)
	case code >= 0:
		return fmt.Sprintf("homeway term: 会话 %s 已结束（退出码 %d）", name, code)
	default:
		return fmt.Sprintf("homeway term: 会话 %s 已结束（code=%d reason=%s）", name, code, reason)
	}
}

// titleLine 组标题（7.6）：会话 · agent · 状态（· 标题，有才带）。
func titleLine(name string, agent, state byte, title string) string {
	parts := []string{name, agentName(agent), stateName(state)}
	if t := strings.TrimSpace(title); t != "" {
		r := []rune(t)
		if len(r) > 24 {
			t = string(r[:23]) + "…"
		}
		parts = append(parts, t)
	}
	return strings.Join(parts, " · ")
}

// ---- tty ----

type cliTTY struct {
	f     *os.File
	saved *termiosT
}

// cliOpenTTY 读 stdin 的终端属性（失败 = 不是 TTY 或内核错误）。
func cliOpenTTY(f *os.File) (*cliTTY, error) {
	tio, err := termiosGet(int(f.Fd()))
	if err != nil {
		return nil, err
	}
	return &cliTTY{f: f, saved: tio}, nil
}

func cliIsTTY(f *os.File) bool {
	_, err := termiosGet(int(f.Fd()))
	return err == nil
}

// makeRaw 置 raw 模式（cfmakeraw 等价：输入输出全透传、无信号生成、8bit 无奇偶）。
// ⚠ ISIG 关闭 ⇒ Ctrl-C 成为普通字节 0x03 直达会话（多路复用器的正确语义）；
// 进程自身的 SIGINT/SIGTERM/SIGHUP 由 kill 命令等外部来源触发，cliAttachRun 的信号处理兜底。
func (t *cliTTY) makeRaw() error {
	raw := *t.saved
	raw.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP |
		unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	raw.Oflag &^= unix.OPOST
	raw.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	raw.Cflag &^= unix.CSIZE | unix.PARENB
	raw.Cflag |= unix.CS8
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	return termiosSet(int(t.f.Fd()), &raw)
}

func (t *cliTTY) restore() error { return termiosSet(int(t.f.Fd()), t.saved) }

// size 取窗口尺寸（pty.Getsize 返回 rows, cols；失败回默认 80x24）。
func (t *cliTTY) size() (uint16, uint16) {
	rows, cols, err := pty.Getsize(t.f)
	if err != nil || rows <= 0 || cols <= 0 {
		return 80, 24
	}
	return uint16(cols), uint16(rows)
}

// ttyQueryTitle 尽力取当前终端标题（OSC 21 查询，150ms 超时；取不到返回 ""，退出时就不恢复）。
// 必须在 raw 模式下调用（应答是裸字节，规范模式会卡行缓冲）。
func ttyQueryTitle(in, out *os.File) string {
	if _, err := out.Write([]byte("\x1b]21;?\x07")); err != nil {
		return ""
	}
	buf := make([]byte, 512)
	_ = in.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	n, err := in.Read(buf)
	_ = in.SetReadDeadline(time.Time{})
	if err != nil || n == 0 {
		return ""
	}
	// 应答形态（xterm）：\x1b]L<title>\x1b\\（可能前面还带一条 \x1b]l… 的图标名）。
	s := string(buf[:n])
	idx := strings.Index(s, "\x1b]L")
	if idx < 0 {
		return ""
	}
	rest := s[idx+3:]
	end := strings.Index(rest, "\x1b\\")
	if end < 0 {
		return ""
	}
	title := rest[:end]
	if len(title) > 128 { // 荒谬长度当噪声丢弃
		return ""
	}
	return title
}

// ---- 客户端实例标识（design D3：CLI 侧是唯一必需项）----

// cliClientID：主机名 + uid + tty 设备路径的短哈希（同一终端里重跑 ⇒ 同一标识 ⇒
// 重连替换自身旧腿，不会被自己的旧腿锁在腿数上限外）；无 tty（理论上 attach 必须
// TTY，这里只是防御）退化为每进程随机。
func cliClientID() string {
	return clientIDFor(cliTTYName())
}

// cliTTYName 取 stdin 对应的 tty 设备路径（无 tty / 管道返回空）。
//
// linux：/proc/self/fd/0 的 readlink。darwin：/dev/fd/0 的 readlink 对 tty 拿不到
// 目标（fdesc 实测返回空）⇒ 用 Rdev 反查 /dev/ttys*（fstat stdin 与候选设备比 st_rdev）。
func cliTTYName() string {
	if s, err := os.Readlink("/proc/self/fd/0"); err == nil && isTTYDevPath(s) {
		return s
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(os.Stdin.Fd()), &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR {
		return ""
	}
	entries, err := os.ReadDir("/dev")
	if err != nil {
		return ""
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "ttys") {
			continue
		}
		var dev unix.Stat_t
		if unix.Lstat("/dev/"+name, &dev) == nil && dev.Rdev == st.Rdev {
			return "/dev/" + name
		}
	}
	return ""
}

func isTTYDevPath(s string) bool {
	return strings.HasPrefix(s, "/dev/tty") || strings.HasPrefix(s, "/dev/pts/")
}

// clientIDFor 是 cliClientID 的纯函数核（可测）：ttyPath 空 = 每进程随机。
func clientIDFor(ttyPath string) string {
	if ttyPath == "" {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "rnd-00000000"
		}
		return "rnd-" + hex.EncodeToString(b[:])
	}
	hostname, _ := os.Hostname()
	uid := ""
	if u, err := user.Current(); err == nil {
		uid = u.Uid
	}
	sum := sha256.Sum256([]byte(hostname + "\x00" + uid + "\x00" + ttyPath))
	return "host-" + hex.EncodeToString(sum[:4])
}

// genAutoName 自动命名 host-<4hex>（与 App 的 <dev8>-<rand8> 可区分，D7）。
func genAutoName() string {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "host-0000"
	}
	return "host-" + hex.EncodeToString(b[:])
}

// ---- 分离键（任务 7.4）----

// detachKeySpec 解析 --detach-key：'^x' 插入记号（^A–^Z、^@、^[、^\、^]、^^、^_、^?）、
// 单个字面量字符、none/off 关闭；空串 = 默认 Ctrl-b。
func detachKeySpec(s string) (byte, bool, error) {
	switch strings.TrimSpace(strings.ToLower(s)) {
	case "", "^b":
		return 0x02, true, nil
	case "none", "off":
		return 0, false, nil
	}
	if len(s) == 2 && s[0] == '^' {
		return caretByte(s[1]), true, nil
	}
	if len(s) == 1 && s[0] > 0x1f && s[0] != 0x7f {
		return s[0], true, nil
	}
	return 0, false, fmt.Errorf("--detach-key %q 不认识：可用 '^x'（如 ^b、^]）、单字符（如 x）、none（关闭）", s)
}

// caretByte 把 '^' 后一个字符翻成控制字节（^@=0 … ^A–^Z … ^[=ESC ^\ ^] ^^ ^_ ^?=DEL）。
func caretByte(c byte) byte {
	switch {
	case c >= 'a' && c <= 'z':
		return c - 'a' + 1
	case c >= 'A' && c <= 'Z':
		return c - 'A' + 1
	case c == '@':
		return 0
	case c >= '[' && c <= '_':
		return c - '[' + 0x1b
	case c == '?':
		return 0x7f
	}
	return c
}

type detachAction int

const (
	detachNone detachAction = iota
	detachDetach
	detachRealign
)

// detachMachine 分离键状态机：在输入路径上识别前缀，不干扰会话字节流。
//
// 前缀键默认 Ctrl-b（tmux 同款）：d=分离、r=重对齐、前缀前缀=字面量前缀；
// 前缀后跟其它字节 = 前缀与该字节**都透传**（screen 风格，绝不吞用户输入）；
// 动作触发即返回（同一段里动作之后的字节丢弃——腿马上要收尾，属敲键竞态窗口）。
// 状态跨 feed 调用保留（前缀字节与后续字节可以分属两次 read）。
type detachMachine struct {
	prefix    byte
	enabled   bool
	sawPrefix bool
}

func newDetachMachine(prefix byte, enabled bool) *detachMachine {
	return &detachMachine{prefix: prefix, enabled: enabled}
}

func (m *detachMachine) feed(in []byte) ([]byte, detachAction) {
	var pass []byte
	action := detachNone
	for _, b := range in {
		if !m.enabled {
			pass = append(pass, b)
			continue
		}
		if m.sawPrefix {
			m.sawPrefix = false
			switch {
			case b == 'd':
				return pass, detachDetach
			case b == 'r':
				if action == detachNone {
					action = detachRealign // 重对齐：输入不透传；同段后续字节继续处理（会话不收尾）
				}
			case b == m.prefix:
				pass = append(pass, m.prefix) // Ctrl-b Ctrl-b：字面量
			default:
				pass = append(pass, m.prefix, b) // 未绑定的组合：全透传
			}
			continue
		}
		if b == m.prefix {
			m.sawPrefix = true
			continue
		}
		pass = append(pass, b)
	}
	return pass, action
}
