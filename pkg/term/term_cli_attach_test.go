//go:build !windows

// term_cli_attach_test.go — CLI attach 的 PTY 集成测试（term-host-cli 任务 7.2/7.3/7.5）。
//
// 真终端 = creack/pty 的 pty 对；CLI = 子进程跑本测试二进制（-test.run 过滤到
// TestCLIAttachHelperProcess，stdin/stdout/stderr 全接 tty，Setctty 让 SIGWINCH 可达）。
// 判据：字节往返、分离后会话仍在、attach 前后 termios 一致、SIGWINCH→RESIZE、
// Ctrl-b r 重对齐、attach -d 接管（replaced）、同 tty 重连（self_reconnect）、
// 裸 EOF 断链文案、HELLO 尾随形状（先 caps 后 ID）、非 TTY / 嵌套防护。
package term

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
)

// ---- 子进程 helper：在真 pty 上跑 cliAttachCmd，结果写文件 ----

func TestCLIAttachHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	before, _ := termiosGet(0)
	o := attachOpts{
		stateDir:  os.Getenv("CLI_TEST_STATE"),
		name:      os.Getenv("CLI_TEST_NAME"),
		detachKey: os.Getenv("CLI_TEST_DETACH_KEY"),
	}
	switch os.Getenv("CLI_TEST_MODE") {
	case "attach-d":
		o.takeover = true
	case "new":
		o.create = true
	case "new-A":
		o.create, o.reuse = true, true
	}
	err := cliAttachCmd(o)
	after, _ := termiosGet(0)
	same := "diff"
	if before != nil && after != nil && *before == *after {
		same = "same"
	}
	_ = os.WriteFile(os.Getenv("CLI_TEST_RESULT"), []byte(fmt.Sprintf("termios=%s err=[%v]", same, err)), 0o600)
	if err != nil {
		os.Exit(3)
	}
	os.Exit(0)
}

// spawnAttachHelper 在 pty 上起 CLI 子进程（ctty=true 时接管终端 ⇒ SIGWINCH 可达）。
func spawnAttachHelper(t *testing.T, ttyFile *os.File, ctty bool, env map[string]string) (*exec.Cmd, string) {
	t.Helper()
	resFile := filepath.Join(t.TempDir(), "result.txt")
	cmd := exec.Command(os.Args[0], "-test.run=TestCLIAttachHelperProcess", "-test.timeout=120s")
	cmd.Stdin = ttyFile
	cmd.Stdout = ttyFile
	cmd.Stderr = ttyFile
	if ctty {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	}
	cmd.Env = append(os.Environ(),
		"GO_WANT_HELPER_PROCESS=1",
		"CLI_TEST_RESULT="+resFile,
	)
	if _, ok := env["HOMEWAY_TERM_TITLE"]; !ok {
		// 默认关标题：OSC 21 查询窗口可能吃掉紧跟着的测试按键；标题开启路径有专门用例
		//（TestCLIAttachTitleReply / TestCLIAttachTitleNoReply，exec-r3 低5）。
		cmd.Env = append(cmd.Env, "HOMEWAY_TERM_TITLE=off")
	}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	return cmd, resFile
}

func openTestPTY(t *testing.T, cols, rows uint16) (*os.File, *os.File) {
	t.Helper()
	master, ttyFile, err := pty.Open()
	if err != nil {
		t.Fatalf("pty.Open: %v", err)
	}
	t.Cleanup(func() { _ = master.Close(); _ = ttyFile.Close() })
	if err := pty.Setsize(master, &pty.Winsize{Cols: cols, Rows: rows}); err != nil {
		t.Fatalf("setsize: %v", err)
	}
	return master, ttyFile
}

// masterStream 后台累积 pty master 的输出（两个 helper 共 tty 时也照收）。
type masterStream struct {
	mu  sync.Mutex
	acc []byte
}

func readMasterAsync(master *os.File) *masterStream {
	return readMasterAsyncHook(master, nil)
}

// readMasterAsyncHook 同 readMasterAsync，每段输出先过 hook（假终端应答 OSC 21 用）。
func readMasterAsyncHook(master *os.File, hook func(chunk []byte)) *masterStream {
	ms := &masterStream{}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := master.Read(buf)
			if n > 0 {
				if hook != nil {
					hook(buf[:n])
				}
				ms.mu.Lock()
				ms.acc = append(ms.acc, buf[:n]...)
				ms.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	return ms
}

func (ms *masterStream) contains(s string) bool {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	return strings.Contains(string(ms.acc), s)
}

func (ms *masterStream) dump() string {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	if len(ms.acc) > 600 {
		return string(ms.acc[:300]) + " … " + string(ms.acc[len(ms.acc)-300:])
	}
	return string(ms.acc)
}

func waitMaster(t *testing.T, ms *masterStream, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ms.contains(want) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("master 输出等 %q 超时；累计：%s", want, ms.dump())
}

func waitHelper(t *testing.T, cmd *exec.Cmd, timeout time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
		return
	case <-time.After(timeout):
		t.Fatalf("helper 进程（pid=%d）%v 超时未退出", cmd.Process.Pid, timeout)
	}
}

func waitResult(t *testing.T, resFile string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(resFile); err == nil {
			return string(b)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("结果文件 %s 超时未出现", resFile)
	return ""
}

func helperAlive(cmd *exec.Cmd) bool {
	return cmd.Process.Signal(syscall.Signal(0)) == nil
}

func waitSessionSize(t *testing.T, ln net.Listener, name string, cols, rows int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if sess, ok := listSession(listTerm(t, ln), name); ok {
			if int(sess["cols"].(float64)) == cols && int(sess["rows"].(float64)) == rows {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	sess, _ := listSession(listTerm(t, ln), name)
	t.Fatalf("会话 %s 尺寸未到 %dx%d：%v", name, cols, rows, sess)
}

func waitClientsCount(t *testing.T, ln net.Listener, name string, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if sess, ok := listSession(listTerm(t, ln), name); ok {
			clients, _ := sess["clients"].([]any)
			if len(clients) == want {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	sess, _ := listSession(listTerm(t, ln), name)
	t.Fatalf("会话 %s 腿数未到 %d：%v", name, want, sess)
}

// ensureSession 建一个会话后断开（会话由出口持有，CLI 随后 attach）。
func ensureSession(t *testing.T, ln net.Listener, name string) {
	t.Helper()
	c, _, _, _ := attachTerm(t, ln, name, true, 80, 24)
	_ = c.Close()
	time.Sleep(200 * time.Millisecond)
}

// ---- 基本：接入 / 回显 / LIST / 分离后会话仍在 / termios 还原 ----

func TestCLIAttachPTYBasic(t *testing.T) {
	_, ln, dir := startTestTermUDS(t)
	ensureSession(t, ln, "cli-pty1")

	master, ttyFile := openTestPTY(t, 100, 30)
	ms := readMasterAsync(master)
	cmd, res := spawnAttachHelper(t, ttyFile, true, map[string]string{
		"CLI_TEST_STATE": dir, "CLI_TEST_NAME": "cli-pty1", "CLI_TEST_MODE": "attach",
	})
	waitMaster(t, ms, "tick", 10*time.Second) // 接上：会话 ticker 输出经 CLI 到达本地终端

	// 键盘往返：master 写 → CLI DATA → 会话 pty echo → CLI → master。
	if _, err := master.Write([]byte("hi-cli\r")); err != nil {
		t.Fatal(err)
	}
	waitMaster(t, ms, "hi-cli", 5*time.Second)

	// LIST：在场腿 = CLI（kind=host）；接入即活动 ⇒ 会话尺寸切到本终端 100x30。
	sess, ok := listSession(listTerm(t, ln), "cli-pty1")
	if !ok {
		t.Fatal("会话应在列表")
	}
	clients, _ := sess["clients"].([]any)
	if len(clients) != 1 {
		t.Fatalf("应有 1 条腿，实际 %v", clients)
	}
	if cl, _ := clients[0].(map[string]any); cl == nil || cl["kind"] != "host" {
		t.Fatalf("CLI 腿 kind 应为 host：%v", clients[0])
	}
	if sess["cols"].(float64) != 100 || sess["rows"].(float64) != 30 {
		t.Fatalf("会话尺寸应随 CLI 腿切到 100x30：%vx%v", sess["cols"], sess["rows"])
	}

	// 分离（Ctrl-b d）：正常退出 + termios 还原 + 会话仍在。
	if _, err := master.Write([]byte{0x02, 'd'}); err != nil {
		t.Fatal(err)
	}
	waitHelper(t, cmd, 10*time.Second)
	if got := waitResult(t, res, time.Second); !strings.Contains(got, "termios=same") || !strings.Contains(got, "err=[<nil>]") {
		t.Fatalf("分离结果不符（termios/err）：%s", got)
	}
	if _, ok := listSession(listTerm(t, ln), "cli-pty1"); !ok {
		t.Fatal("分离后会话应仍在")
	}
}

// ---- 尺寸：SIGWINCH→RESIZE；他腿抢走后 Ctrl-b r 重对齐 ----

func TestCLIAttachResizeAndRealign(t *testing.T) {
	_, ln, dir := startTestTermUDS(t)
	ensureSession(t, ln, "cli-pty2")

	master, ttyFile := openTestPTY(t, 100, 30)
	ms := readMasterAsync(master)
	cmd, _ := spawnAttachHelper(t, ttyFile, true, map[string]string{
		"CLI_TEST_STATE": dir, "CLI_TEST_NAME": "cli-pty2", "CLI_TEST_MODE": "attach",
	})
	waitMaster(t, ms, "tick", 10*time.Second)

	// 窗口变化 ⇒ SIGWINCH ⇒ CLI RESIZE ⇒ 会话尺寸变化。
	if err := pty.Setsize(master, &pty.Winsize{Cols: 120, Rows: 40}); err != nil {
		t.Fatal(err)
	}
	waitSessionSize(t, ln, "cli-pty2", 120, 40, 5*time.Second)

	// 另一条腿（TCP、90x28）接入即活动 ⇒ 尺寸被抢走。
	c2, _, _, _ := attachTerm(t, ln, "cli-pty2", false, 90, 28)
	defer c2.Close()
	waitSessionSize(t, ln, "cli-pty2", 90, 28, 5*time.Second)

	// Ctrl-b r：重新上报本腿尺寸 ⇒ 切回。
	if _, err := master.Write([]byte{0x02, 'r'}); err != nil {
		t.Fatal(err)
	}
	waitSessionSize(t, ln, "cli-pty2", 120, 40, 5*time.Second)

	if _, err := master.Write([]byte{0x02, 'd'}); err != nil {
		t.Fatal(err)
	}
	waitHelper(t, cmd, 10*time.Second)
}

// ---- 自定义分离键：^b 不再是前缀，^] d 才分离 ----

func TestCLIAttachDetachKeyCustom(t *testing.T) {
	_, ln, dir := startTestTermUDS(t)
	ensureSession(t, ln, "cli-key")

	master, ttyFile := openTestPTY(t, 100, 30)
	ms := readMasterAsync(master)
	cmd, res := spawnAttachHelper(t, ttyFile, true, map[string]string{
		"CLI_TEST_STATE": dir, "CLI_TEST_NAME": "cli-key", "CLI_TEST_MODE": "attach",
		"CLI_TEST_DETACH_KEY": "^]",
	})
	waitMaster(t, ms, "tick", 10*time.Second)

	// Ctrl-b d：在 ^] 前缀下只是普通字节（透传给会话），不该分离。
	if _, err := master.Write([]byte{0x02, 'd'}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(700 * time.Millisecond)
	if !helperAlive(cmd) {
		t.Fatalf("自定义前缀下 Ctrl-b d 不该分离；结果：%s", func() string { b, _ := os.ReadFile(res); return string(b) }())
	}
	// ^] d 才分离。
	if _, err := master.Write([]byte{0x1d, 'd'}); err != nil {
		t.Fatal(err)
	}
	waitHelper(t, cmd, 10*time.Second)
	if got := waitResult(t, res, time.Second); !strings.Contains(got, "err=[<nil>]") {
		t.Fatalf("^] d 应正常分离：%s", got)
	}
}

// ---- 信号：SIGTERM → 还原 termios 后干净退出 ----

func TestCLIAttachSignalRestore(t *testing.T) {
	_, ln, dir := startTestTermUDS(t)
	ensureSession(t, ln, "cli-sig")

	master, ttyFile := openTestPTY(t, 100, 30)
	ms := readMasterAsync(master)
	cmd, res := spawnAttachHelper(t, ttyFile, true, map[string]string{
		"CLI_TEST_STATE": dir, "CLI_TEST_NAME": "cli-sig", "CLI_TEST_MODE": "attach",
	})
	waitMaster(t, ms, "tick", 10*time.Second)

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	waitHelper(t, cmd, 10*time.Second)
	if got := waitResult(t, res, time.Second); !strings.Contains(got, "termios=same") || !strings.Contains(got, "err=[<nil>]") {
		t.Fatalf("SIGTERM 应干净退出且还原 termios：%s", got)
	}
	if _, ok := listSession(listTerm(t, ln), "cli-sig"); !ok {
		t.Fatal("信号退出后会话应仍在")
	}
}

// ---- 断链：代理硬断（无 ENDED）⇒ 裸 EOF ⇒ 可行动文案 ----

func TestCLIAttachBareEOF(t *testing.T) {
	_, ln := startTestTermService(t)
	ensureSession(t, ln, "cli-eof")

	// UDS 代理：<dir>/term.sock ↔ 服务 TCP；硬断两端 = 服务端不发 ENDED 的裸关闭。
	dir, err := os.MkdirTemp("/tmp", "termcli-proxy-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	pln, err := net.Listen("unix", filepath.Join(dir, "term.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pln.Close() })
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, aerr := pln.Accept()
			if aerr != nil {
				return
			}
			up, derr := net.Dial("tcp", ln.Addr().String())
			if derr != nil {
				_ = c.Close()
				continue
			}
			mu.Lock()
			conns = append(conns, c, up)
			mu.Unlock()
			go func() { _, _ = io.Copy(up, c); _ = up.Close(); _ = c.Close() }()
			go func() { _, _ = io.Copy(c, up); _ = c.Close(); _ = up.Close() }()
		}
	}()

	master, ttyFile := openTestPTY(t, 100, 30)
	ms := readMasterAsync(master)
	cmd, res := spawnAttachHelper(t, ttyFile, true, map[string]string{
		"CLI_TEST_STATE": dir, "CLI_TEST_NAME": "cli-eof", "CLI_TEST_MODE": "attach",
	})
	waitMaster(t, ms, "tick", 10*time.Second)

	mu.Lock()
	for _, c := range conns {
		_ = c.Close()
	}
	mu.Unlock()
	waitHelper(t, cmd, 10*time.Second)
	got := waitResult(t, res, time.Second)
	for _, want := range []string{"连接被断开", "会话仍在运行", "homeway term attach cli-eof"} {
		if !strings.Contains(got, want) {
			t.Fatalf("裸 EOF 文案缺 %q：%s", want, got)
		}
	}
}

// ---- 多腿：attach -d 接管（旧腿收 replaced）；同 tty 重连（旧腿收 self_reconnect）----

func TestCLIAttachTakeover(t *testing.T) {
	_, ln, dir := startTestTermUDS(t)
	ensureSession(t, ln, "cli-tko")

	masterA, ttyA := openTestPTY(t, 100, 30)
	msA := readMasterAsync(masterA)
	cmdA, resA := spawnAttachHelper(t, ttyA, true, map[string]string{
		"CLI_TEST_STATE": dir, "CLI_TEST_NAME": "cli-tko", "CLI_TEST_MODE": "attach",
	})
	waitMaster(t, msA, "tick", 10*time.Second)

	masterB, ttyB := openTestPTY(t, 120, 40)
	msB := readMasterAsync(masterB)
	cmdB, resB := spawnAttachHelper(t, ttyB, true, map[string]string{
		"CLI_TEST_STATE": dir, "CLI_TEST_NAME": "cli-tko", "CLI_TEST_MODE": "attach-d",
	})
	waitMaster(t, msB, "tick", 10*time.Second)
	// 旧腿收 ENDED(replaced)：文案打在 A 的终端上。
	waitMaster(t, msA, "接管", 10*time.Second)
	waitMaster(t, msA, "replaced", 2*time.Second)
	waitHelper(t, cmdA, 5*time.Second)
	if got := waitResult(t, resA, time.Second); !strings.Contains(got, "termios=same") || !strings.Contains(got, "err=[<nil>]") {
		t.Fatalf("被接管方应正常退出：%s", got)
	}
	// 只剩接管腿（120x40，活动）。
	waitClientsCount(t, ln, "cli-tko", 1, 5*time.Second)
	waitSessionSize(t, ln, "cli-tko", 120, 40, 5*time.Second)

	if _, err := masterB.Write([]byte{0x02, 'd'}); err != nil {
		t.Fatal(err)
	}
	waitHelper(t, cmdB, 10*time.Second)
	if got := waitResult(t, resB, time.Second); !strings.Contains(got, "err=[<nil>]") {
		t.Fatalf("接管腿分离应正常退出：%s", got)
	}
}

func TestCLIAttachSelfReconnect(t *testing.T) {
	_, ln, dir := startTestTermUDS(t)
	ensureSession(t, ln, "cli-self")

	// 两个 CLI 子进程共享同一 tty ⇒ 同一实例标识（hostname+uid+tty 哈希）。
	// 都不 Setctty：会话 leader 退出会吊销 tty（EIO 连坐另一条腿），此处无需 SIGWINCH。
	master, ttyFile := openTestPTY(t, 100, 30)
	ms := readMasterAsync(master)
	cmdA, resA := spawnAttachHelper(t, ttyFile, false, map[string]string{
		"CLI_TEST_STATE": dir, "CLI_TEST_NAME": "cli-self", "CLI_TEST_MODE": "attach",
	})
	waitMaster(t, ms, "tick", 10*time.Second)
	cmdB, resB := spawnAttachHelper(t, ttyFile, false, map[string]string{
		"CLI_TEST_STATE": dir, "CLI_TEST_NAME": "cli-self", "CLI_TEST_MODE": "attach",
	})
	// 旧腿收 ENDED(self_reconnect)：文案打在共享终端上。
	waitMaster(t, ms, "self_reconnect", 10*time.Second)
	waitHelper(t, cmdA, 5*time.Second)
	if got := waitResult(t, resA, time.Second); !strings.Contains(got, "termios=same") || !strings.Contains(got, "err=[<nil>]") {
		t.Fatalf("被自身重连替换的腿应正常退出：%s", got)
	}
	// 只剩新腿（不累积）。
	waitClientsCount(t, ln, "cli-self", 1, 5*time.Second)

	// 新腿用 SIGTERM 收尾（共享 tty 的输入归属不定，不走键盘分离路径）。
	if err := cmdB.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	waitHelper(t, cmdB, 10*time.Second)
	if got := waitResult(t, resB, time.Second); !strings.Contains(got, "termios=same") || !strings.Contains(got, "err=[<nil>]") {
		t.Fatalf("新腿应正常退出：%s", got)
	}
}

// ---- 双客户端同挂互不顶替（默认 attach 不踢任何腿）----

func TestCLIAttachCoexist(t *testing.T) {
	_, ln, dir := startTestTermUDS(t)
	ensureSession(t, ln, "cli-two")

	masterA, ttyA := openTestPTY(t, 100, 30)
	msA := readMasterAsync(masterA)
	cmdA, resA := spawnAttachHelper(t, ttyA, true, map[string]string{
		"CLI_TEST_STATE": dir, "CLI_TEST_NAME": "cli-two", "CLI_TEST_MODE": "attach",
	})
	waitMaster(t, msA, "tick", 10*time.Second)

	masterB, ttyB := openTestPTY(t, 120, 40)
	msB := readMasterAsync(masterB)
	cmdB, resB := spawnAttachHelper(t, ttyB, true, map[string]string{
		"CLI_TEST_STATE": dir, "CLI_TEST_NAME": "cli-two", "CLI_TEST_MODE": "attach",
	})
	waitMaster(t, msB, "tick", 10*time.Second)

	// A 不被顶掉：没有 ENDED、仍在跑。
	time.Sleep(700 * time.Millisecond)
	if !helperAlive(cmdA) {
		t.Fatalf("后接入的腿不该顶掉先接入的腿；A 结果：%s", func() string { b, _ := os.ReadFile(resA); return string(b) }())
	}
	waitClientsCount(t, ln, "cli-two", 2, 5*time.Second)

	_, _ = masterA.Write([]byte{0x02, 'd'})
	_, _ = masterB.Write([]byte{0x02, 'd'})
	waitHelper(t, cmdA, 10*time.Second)
	waitHelper(t, cmdB, 10*time.Second)
	if got := waitResult(t, resA, time.Second) + "|" + waitResult(t, resB, time.Second); !strings.Contains(got, "err=[<nil>]") {
		t.Fatalf("双腿分离都应正常退出：%s", got)
	}
}

// ---- HELLO 形状（假服务端）：先 caps 后 ID、带 capsRawTerminal、takeover/new 位 ----

func TestCLIAttachHelloShape(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "termcli-shape-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	type helloInfo struct {
		flags       byte
		caps        byte
		capsPresent bool
		ver         byte
		verPresent  bool
		id          string
		cols, rows  uint16
	}
	helloCh := make(chan helloInfo, 8)
	ln, err := net.Listen("unix", filepath.Join(dir, "term.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(15 * time.Second))
				if _, werr := c.Write(encodeTermFrame(opGreeting, encGreeting())); werr != nil {
					return
				}
				f, rerr := readTermFrame(c)
				if rerr != nil || f.op != opHello {
					return
				}
				cols, rows, flags, name, _ := decHello(f.payload)
				caps, present, id, ver, verPresent, _ := decHelloTail(helloTail(f.payload, name))
				helloCh <- helloInfo{flags, caps, present, ver, verPresent, id, cols, rows}
				// 用 no_session 让 CLI 确定性退出（也验证协议错误透出）。
				_, _ = c.Write(encodeTermFrame(opError, encError("no_session", "会话 "+name+" 不存在")))
			}(c)
		}
	}()

	runOne := func(mode string) helloInfo {
		master, ttyFile := openTestPTY(t, 100, 30)
		ms := readMasterAsync(master)
		_ = ms // master 只需承载 helper 的 stdio；这里不判流
		cmd, res := spawnAttachHelper(t, ttyFile, true, map[string]string{
			"CLI_TEST_STATE": dir, "CLI_TEST_NAME": "shape1", "CLI_TEST_MODE": mode,
		})
		waitHelper(t, cmd, 15*time.Second)
		if got := waitResult(t, res, time.Second); !strings.Contains(got, "不存在") || !strings.Contains(got, "homeway term list") {
			t.Fatalf("%s 应以 no_session 映射文案退出：%s", mode, got)
		}
		select {
		case info := <-helloCh:
			return info
		case <-time.After(3 * time.Second):
			t.Fatalf("%s：假服务端没收到 HELLO", mode)
			return helloInfo{}
		}
	}

	plain := runOne("attach")
	if plain.flags != 0 {
		t.Fatalf("普通 attach 的 flags 应为 0，实际 0x%02x", plain.flags)
	}
	if !plain.capsPresent || plain.caps&capsRawTerminal == 0 {
		t.Fatalf("caps 块应声明 capsRawTerminal：present=%v caps=0x%02x", plain.capsPresent, plain.caps)
	}
	// FIX-29 版本声明：假服务端的 GREETING 带 featProtoVerBit（encGreeting）⇒ CLI 应在
	// caps 里声明 capsProtoVer 并带 1 字节本端协议版本。
	if plain.caps&capsProtoVer == 0 || !plain.verPresent || plain.ver != termProtoVer {
		t.Fatalf("出口公布 featProtoVerBit 时 CLI 应声明协议版本：caps=0x%02x ver=%d present=%v",
			plain.caps, plain.ver, plain.verPresent)
	}
	if plain.id == "" || len(plain.id) > termMaxClientIDLen || !strings.Contains(plain.id, "-") {
		t.Fatalf("实例标识形态不对：%q", plain.id)
	}
	if plain.cols != 100 || plain.rows != 30 {
		t.Fatalf("HELLO 应带本终端尺寸 100x30，实际 %dx%d", plain.cols, plain.rows)
	}

	tko := runOne("attach-d")
	if tko.flags&helloFlagTakeover == 0 {
		t.Fatalf("attach -d 应置 takeover 位，实际 0x%02x", tko.flags)
	}
	nw := runOne("new")
	if nw.flags&helloFlagCreate == 0 || nw.flags&helloFlagOnlyIfAbsent == 0 {
		t.Fatalf("new 应置 create|only-if-absent 位，实际 0x%02x", nw.flags)
	}
	nwa := runOne("new-A")
	if nwa.flags&helloFlagCreate == 0 || nwa.flags&helloFlagOnlyIfAbsent != 0 {
		t.Fatalf("new -A 应只置 create 位，实际 0x%02x", nwa.flags)
	}
}

// ---- 非 TTY / 嵌套（进程内，无需子进程）----

func TestCLIAttachRefusals(t *testing.T) {
	// 嵌套：TERM_SESSION_ID 指向目标会话 ⇒ 拒绝（先于 TTY 检查，管道 stdin 也能触发）。
	t.Setenv("TERM_SESSION_ID", "tailcat-cli-nest")
	err := cliAttachCmd(attachOpts{name: "cli-nest", stateDir: "/nonexistent"})
	if err == nil || !strings.Contains(err.Error(), "回环") {
		t.Fatalf("嵌套防护应拒绝：%v", err)
	}
	// 非 TTY：stdin/stdout 换管道 ⇒ 明确拒绝。
	oldIn, oldOut := os.Stdin, os.Stdout
	r, w, perr := os.Pipe()
	if perr != nil {
		t.Fatal(perr)
	}
	os.Stdin, os.Stdout = r, r
	err = cliAttachCmd(attachOpts{name: "x", stateDir: "/nonexistent"})
	os.Stdin, os.Stdout = oldIn, oldOut
	_ = r.Close()
	_ = w.Close()
	if err == nil || !strings.Contains(err.Error(), "交互终端") {
		t.Fatalf("非 TTY 应拒绝：%v", err)
	}
}

// ---- 标题面（exec-r3 高1/低5）：默认开启（不设 HOMEWAY_TERM_TITLE）的真判据 ----

// TestCLIAttachTitleNoReply：不应答 OSC 21 的终端——attach 在 ≤ 查询预算+握手内**自己**进入
// 透传（无需按键解挂），且抢在查询窗口里敲的首键**到达会话**（回显可见）。
// 变异自证：把查询改回无超时阻塞读（吞首键）本用例必红——「tick 到达」与「first-key 回显」
// 两个断言都会被打破（阻塞版要等按键才有 tick，且首键被当应答吃掉、永不回显）。
func TestCLIAttachTitleNoReply(t *testing.T) {
	_, ln, dir := startTestTermUDSShell(t, testTermEchoShell)
	ensureSession(t, ln, "cli-plain")

	master, ttyFile := openTestPTY(t, 100, 30)
	ms := readMasterAsync(master) // 不应答 OSC 21
	start := time.Now()
	cmd, res := spawnAttachHelper(t, ttyFile, true, map[string]string{
		"CLI_TEST_STATE": dir, "CLI_TEST_NAME": "cli-plain", "CLI_TEST_MODE": "attach",
		"HOMEWAY_TERM_TITLE": "", // 显式开启（空 ≠ off）
	})
	// 立即敲首键：落在查询窗口**之内**或之外都必须到达会话（leftover 回投 / 正常输入路径）。
	_, _ = master.Write([]byte("first-key\r"))
	waitMaster(t, ms, "tick", 10*time.Second) // 无按键解挂：不应答终端自己进入透传
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("进入透传太慢（%v；查询预算 150ms + 握手）", d)
	}
	// 首键未被查询吞掉：**会话侧**回显可见（GOT: 前缀只能由会话产生——本地 tty 在 raw 前
	// 也会回显纯文本，纯文本判据在变异下是假绿）。
	waitMaster(t, ms, "GOT:first-key", 5*time.Second)
	_, _ = master.Write([]byte{0x02, 'd'})
	waitHelper(t, cmd, 10*time.Second)
	if got := waitResult(t, res, time.Second); !strings.Contains(got, "err=[<nil>]") {
		t.Fatalf("分离应正常退出：%s", got)
	}
}

// TestCLIAttachTitleReply：应答 OSC 21 的终端——attach 设置标题（OSC 2 含会话名），
// 退出时恢复原值（OSC 2 = 应答里的标题）。
func TestCLIAttachTitleReply(t *testing.T) {
	_, ln, dir := startTestTermUDS(t)
	ensureSession(t, ln, "cli-title")

	master, ttyFile := openTestPTY(t, 100, 30)
	// 假终端：看到 OSC 21 查询就应答（应答落在查询窗口内）。
	hook := func(chunk []byte) {
		if bytes.Contains(chunk, []byte("\x1b]21;?")) {
			_, _ = master.Write([]byte("\x1b]Lmy-old-title\x1b\\"))
		}
	}
	ms := readMasterAsyncHook(master, hook)
	cmd, res := spawnAttachHelper(t, ttyFile, true, map[string]string{
		"CLI_TEST_STATE": dir, "CLI_TEST_NAME": "cli-title", "CLI_TEST_MODE": "attach",
		"HOMEWAY_TERM_TITLE": "",
	})
	// 设置标题：OSC 2 里带会话名（attach 期间唯一会出现会话名的通道）。
	waitMaster(t, ms, "cli-title", 10*time.Second)
	waitMaster(t, ms, "tick", 10*time.Second)

	_, _ = master.Write([]byte{0x02, 'd'})
	waitHelper(t, cmd, 10*time.Second)
	if got := waitResult(t, res, time.Second); !strings.Contains(got, "err=[<nil>]") {
		t.Fatalf("分离应正常退出：%s", got)
	}
	// 退出恢复原值：OSC 2 = 查询应答里的标题。
	waitMaster(t, ms, "my-old-title", 3*time.Second)
}

// ---- N1/N2（exec-r4 非阻塞建议，§9 收尾落地）----

// TestParseTitleReplyStripsRecognizableReplies：N1 的纯函数判据——可识别应答序列
// （图标名 l / 标题 L；ST 与 BEL 两种结束符）必须被剥掉，只有真正的用户字节进 rest。
func TestParseTitleReplyStripsRecognizableReplies(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		title string
		rest  string
		ok    bool
	}{
		{"ST 结尾标题", "\x1b]Lmy-title\x1b\\", "my-title", "", true},
		{"BEL 结尾标题", "\x1b]Lmy-title\x07", "my-title", "", true},
		{"图标名(BEL)+标题(ST)", "\x1b]licon\x07\x1b]Lreal\x1b\\", "real", "", true},
		{"应答前有首键", "a\x1b]Lreal\x07", "real", "a", true},
		{"应答后有首键", "\x1b]Lreal\x07z", "real", "z", true},
		{"纯键入无应答", "abc", "", "abc", false},
		{"收了一半（无结束符）", "\x1b]Lre", "", "", false},
		{"荒谬长度不当标题但剥掉", "\x1b]L" + strings.Repeat("x", 200) + "\x07", "", "", true},
		// CSI 不是 OSC（Index 不命中）——整段原样回投
		{"CSI 应答不命中", "\x1b[?62;22c", "", "\x1b[?62;22c", false},
		// 真 OSC 但不是 l/L（窗口标题/颜色查询应答）：kind 分支不误剥，原样回投（M5）
		{"真 OSC（0;title）不误剥", "\x1b]0;win\x07", "", "\x1b]0;win\x07", false},
		{"真 OSC（11;rgb）不误剥", "\x1b]11;rgb:0000/0000/0000\x07", "", "\x1b]11;rgb:0000/0000/0000\x07", false},
	}
	for _, c := range cases {
		title, rest, ok := parseTitleReply([]byte(c.in))
		if title != c.title || string(rest) != c.rest || ok != c.ok {
			t.Fatalf("%s：got (title=%q rest=%q ok=%v), want (%q %q %v)",
				c.name, title, rest, ok, c.title, c.rest, c.ok)
		}
	}
}

// TestCLIAttachTitleReplyBELForm：应答用 **BEL 结尾 + 先图标名后标题** 的终端（评审假终端
// 形态，N1 的端到端判据）——标题恢复仍生效，且应答字节**不进会话**（master 输出里没有
// ESC ] l/L：误判路径下会话会把它当输入回显回来）。
func TestCLIAttachTitleBELFormNoLeak(t *testing.T) {
	_, ln, dir := startTestTermUDSShell(t, testTermEchoShell)
	ensureSession(t, ln, "cli-bel")

	master, ttyFile := openTestPTY(t, 100, 30)
	hook := func(chunk []byte) {
		if bytes.Contains(chunk, []byte("\x1b]21;?")) {
			// 图标名（BEL）+ 标题（BEL）：只认 ST 的旧解析整条当输入回投。
			_, _ = master.Write([]byte("\x1b]licon\x07\x1b]Lbel-title\x07"))
		}
	}
	ms := readMasterAsyncHook(master, hook)
	cmd, res := spawnAttachHelper(t, ttyFile, true, map[string]string{
		"CLI_TEST_STATE": dir, "CLI_TEST_NAME": "cli-bel", "CLI_TEST_MODE": "attach",
		"HOMEWAY_TERM_TITLE": "",
	})
	waitMaster(t, ms, "tick", 10*time.Second)
	_, _ = master.Write([]byte{0x02, 'd'})
	waitHelper(t, cmd, 10*time.Second)
	if got := waitResult(t, res, time.Second); !strings.Contains(got, "err=[<nil>]") {
		t.Fatalf("分离应正常退出：%s", got)
	}
	// BEL 形态的标题也应被解出并恢复。
	waitMaster(t, ms, "bel-title", 3*time.Second)
	// N1 判据：应答序列不得经会话回显回来（master 输出不应再出现 ESC ] l/L）。
	if ms.contains("\x1b]l") || ms.contains("\x1b]L") {
		t.Fatalf("应答序列泄漏进会话回显（N1 未生效）：%q", ms.dump())
	}
}

// TestCLIAttachTitleNoReplyNoKey：N2——**不写任何键**，不应答 OSC 21 的终端上
// attach 在查询预算（150ms）+ 握手内自己进入透传（tick ≤1s 到达）。现有 NoReply 用例
// spawn 后立即写键，守不住这条（评审临时用例已证可稳定红/绿）。
func TestCLIAttachTitleNoReplyNoKey(t *testing.T) {
	_, ln, dir := startTestTermUDSShell(t, testTermEchoShell)
	ensureSession(t, ln, "cli-nokey")

	master, ttyFile := openTestPTY(t, 100, 30)
	ms := readMasterAsync(master) // 不应答 OSC 21；测试全程不写任何键
	start := time.Now()
	cmd, res := spawnAttachHelper(t, ttyFile, true, map[string]string{
		"CLI_TEST_STATE": dir, "CLI_TEST_NAME": "cli-nokey", "CLI_TEST_MODE": "attach",
		"HOMEWAY_TERM_TITLE": "",
	})
	waitMaster(t, ms, "tick", 3*time.Second)
	if d := time.Since(start); d > time.Second {
		t.Fatalf("无按键也应 ≤1s 进入透传（tick 自达），实际 %v", d)
	}
	// 从 master 侧发分离（这是唯一的「写」——发生在透传建立之后，不破坏用例语义）。
	_, _ = master.Write([]byte{0x02, 'd'})
	waitHelper(t, cmd, 10*time.Second)
	if got := waitResult(t, res, time.Second); !strings.Contains(got, "err=[<nil>]") {
		t.Fatalf("分离应正常退出：%s", got)
	}
}

// TestCLIAttachTitleIconOnlyNoLeak（exec-r5 F6 补射程）：终端**只答图标名**（OSC l，BEL
// 结尾）不答标题（OSC L）——parseTitleReply 识别并剥掉 l 应答但 ok=false，走**超时路径**
// 的余量回投。判据：可识别应答字节不得经「非应答余量」灌进会话（master 输出无 ESC ] l/L）。
// 变异自证：把超时路径改回 `return "", acc`（裸回投）本用例必红——TestCLIAttachTitleBELForm
// 的泄漏断言走不到这条路径（它的应答能解析成功、从 ok 分支返回）。
func TestCLIAttachTitleIconOnlyNoLeak(t *testing.T) {
	_, ln, dir := startTestTermUDSShell(t, testTermEchoShell)
	ensureSession(t, ln, "cli-icon")

	master, ttyFile := openTestPTY(t, 100, 30)
	hook := func(chunk []byte) {
		if bytes.Contains(chunk, []byte("\x1b]21;?")) {
			// 尾部 \n 让回显可见（会话侧 sed 按行缓冲）；它属非应答字节，固定路径也会回投。
			_, _ = master.Write([]byte("\x1b]licon-only\x07\n"))
		}
	}
	ms := readMasterAsyncHook(master, hook)
	cmd, res := spawnAttachHelper(t, ttyFile, true, map[string]string{
		"CLI_TEST_STATE": dir, "CLI_TEST_NAME": "cli-icon", "CLI_TEST_MODE": "attach",
		"HOMEWAY_TERM_TITLE": "",
	})
	waitMaster(t, ms, "tick", 10*time.Second)
	_, _ = master.Write([]byte{0x02, 'd'})
	waitHelper(t, cmd, 10*time.Second)
	if got := waitResult(t, res, time.Second); !strings.Contains(got, "err=[<nil>]") {
		t.Fatalf("分离应正常退出：%s", got)
	}
	if ms.contains("\x1b]l") || ms.contains("\x1b]L") {
		t.Fatalf("图标名应答泄漏进会话回显（超时路径未剥）：%q", ms.dump())
	}
}

// 标题状态词表 = stateV2（term-remote 3.3 单轨化：stateName 已删，标题与表格/STATE
// 帧同值域——blocked 不再折成 waiting）。
func TestTitleLineStateV2(t *testing.T) {
	for st, want := range map[byte]string{
		stateV2Working: "working",
		stateV2Blocked: "blocked",
		stateV2Idle:    "idle",
		stateV2Unknown: "unknown",
	} {
		got := titleLine("dev1", agentCodex, st, "批准")
		if !strings.Contains(got, "dev1 · codex · "+want) {
			t.Fatalf("state=%d 标题状态词应为 %q：%s", st, want, got)
		}
	}
	if got := titleLine("dev1", agentCodex, stateV2Blocked, ""); strings.Contains(got, "waiting") {
		t.Fatalf("标题不得再出现旧词表 waiting：%s", got)
	}
}
