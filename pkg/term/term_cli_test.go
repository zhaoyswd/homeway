//go:build !windows

// term_cli_test.go — 命令面的单测（term-host-cli 任务 7.1/7.4）：
// 参数解析、表格与 JSON 输出、错误文案（连接层两态 + 协议层）、分离键状态机。
package term

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ---- 参数解析 ----

func TestParseNewArgs(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantName string
		wantD    bool
		wantA    bool
		wantAuto bool
		wantErr  string
	}{
		{"裸 new（自动命名）", []string{}, "", false, false, true, ""},
		{"显式名", []string{"build"}, "build", false, false, false, ""},
		{"-d 只创建", []string{"-d", "ci"}, "ci", true, false, false, ""},
		{"-d -A", []string{"-dA", "ci"}, "ci", true, true, false, ""},
		{"非法名就地报错", []string{"bad name!"}, "", false, false, false, "不合法"},
		{"未知参数", []string{"-x"}, "", false, false, false, "不认识的参数"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// -dA 这类合并短 flag 不支持（与既有 explain 解析器口径一致）：拆开测。
			args := expandFlagEq(c.args)
			for i := range args {
				if args[i] == "-dA" {
					args = append(args[:i], append([]string{"-d", "-A"}, args[i+1:]...)...)
				}
			}
			o, err := parseNewArgs2(args)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("期望错误含 %q，实际 %v", c.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("不该报错：%v", err)
			}
			if o.name != c.wantName || o.detached != c.wantD || o.reuse != c.wantA || o.autoNamed != c.wantAuto {
				t.Fatalf("解析结果 = %+v，期望 name=%q d=%v A=%v auto=%v", o, c.wantName, c.wantD, c.wantA, c.wantAuto)
			}
		})
	}
}

// parseNewArgs2 是 parseNewArgs 的直调别名（避免测试里再抄一遍解析体）。
func parseNewArgs2(args []string) (newOpts, error) { return parseNewArgs(args) }

func TestParseAttachArgs(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantName string
		wantTake bool
		wantKey  string
		wantErr  string
	}{
		{"裸 attach", []string{}, "", false, "", ""},
		{"名字", []string{"dev1"}, "dev1", false, "", ""},
		{"-d", []string{"-d", "dev1"}, "dev1", true, "", ""},
		{"--detach-key", []string{"--detach-key", "^]", "dev1"}, "dev1", false, "^]", ""},
		{"--detach-key= 值", []string{"--detach-key=^]"}, "", false, "^]", ""},
		{"缺值", []string{"--detach-key"}, "", false, "", "缺参数"},
		{"两个名字", []string{"a", "b"}, "", false, "", "只能给一个会话名"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o, err := parseAttachArgs(expandFlagEq(c.args))
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("期望错误含 %q，实际 %v", c.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("不该报错：%v", err)
			}
			if o.name != c.wantName || o.takeover != c.wantTake || o.detachKey != c.wantKey {
				t.Fatalf("解析结果 = %+v", o)
			}
		})
	}
}

// ---- 分离键 ----

func TestDetachKeySpec(t *testing.T) {
	type tc struct {
		in       string
		wantByte byte
		wantOn   bool
		wantErr  bool
	}
	for _, c := range []tc{
		{"", 0x02, true, false},
		{"^b", 0x02, true, false},
		{"^B", 0x02, true, false},
		{"^a", 0x01, true, false},
		{"^]", 0x1d, true, false},
		{"^[", 0x1b, true, false},
		{"^?", 0x7f, true, false},
		{"^@", 0x00, true, false},
		{"x", 'x', true, false},
		{"none", 0, false, false},
		{"off", 0, false, false},
		{"^bc", 0, false, true},
		{"abc", 0, false, true},
		{"\x01", 0, false, true}, // 控制字符不能当字面量前缀
	} {
		t.Run("spec="+c.in, func(t *testing.T) {
			b, on, err := detachKeySpec(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("%q 应报错，实际 prefix=0x%02x on=%v", c.in, b, on)
				}
				return
			}
			if err != nil || b != c.wantByte || on != c.wantOn {
				t.Fatalf("detachKeySpec(%q) = (0x%02x,%v,%v)，期望 (0x%02x,%v,nil)",
					c.in, b, on, err, c.wantByte, c.wantOn)
			}
		})
	}
}

func TestDetachMachine(t *testing.T) {
	p := byte(0x02)
	cases := []struct {
		name       string
		feeds      [][]byte
		wantPass   string
		wantAction detachAction
	}{
		{"普通输入直通", [][]byte{[]byte("abc")}, "abc", detachNone},
		{"前缀+d 分离", [][]byte{[]byte{0x02, 'd'}}, "", detachDetach},
		{"前缀+r 重对齐", [][]byte{[]byte{0x02, 'r'}}, "", detachRealign},
		{"前缀前缀=字面量", [][]byte{[]byte{0x02, 0x02, 'x'}}, "\x02x", detachNone},
		{"前缀+未绑定键全透传", [][]byte{[]byte{'a', 0x02, 'z', 'c'}}, "a\x02zc", detachNone},
		{"跨 feed 的前缀", [][]byte{[]byte{0x02}, []byte{'d'}}, "", detachDetach},
		{"前缀后跟前缀再 d", [][]byte{[]byte{0x02, 0x02, 'd'}}, "\x02d", detachNone},
		{"动作后丢弃同段字节", [][]byte{[]byte{'x', 0x02, 'd', 'y'}}, "x", detachDetach},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := newDetachMachine(p, true)
			var pass []byte
			action := detachNone
			for _, f := range c.feeds {
				var got []byte
				got, action = m.feed(f)
				pass = append(pass, got...)
				if action != detachNone {
					break
				}
			}
			if string(pass) != c.wantPass || action != c.wantAction {
				t.Fatalf("pass=%q action=%v，期望 %q/%v", pass, action, c.wantPass, c.wantAction)
			}
		})
	}
	// 关闭状态机：全部字节透传（包括前缀与 d）。
	m := newDetachMachine(p, false)
	pass, action := m.feed([]byte{0x02, 'd'})
	if string(pass) != "\x02d" || action != detachNone {
		t.Fatalf("关闭状态机应全透传：pass=%q action=%v", pass, action)
	}
	// 自定义前缀 ^]（design 示例）：0x02 不再是前缀。
	m2 := newDetachMachine(0x1d, true)
	pass, action = m2.feed([]byte{0x02, 'd', 0x1d, 'd'})
	if string(pass) != "\x02d" || action != detachDetach {
		t.Fatalf("自定义前缀：pass=%q action=%v", pass, action)
	}
	// 病态选键：前缀恰为字面 d/r——「前缀前缀=字面量」前置于动作（exec-r3 低3）：
	// dd/rr 发字面量而不是分离/重对齐。
	m3 := newDetachMachine('d', true)
	pass, action = m3.feed([]byte{'d', 'd', 'x'})
	if string(pass) != "dx" || action != detachNone {
		t.Fatalf("prefix='d'：dd 应为字面量：pass=%q action=%v", pass, action)
	}
	m4 := newDetachMachine('r', true)
	pass, action = m4.feed([]byte{'r', 'r'})
	if string(pass) != "r" || action != detachNone {
		t.Fatalf("prefix='r'：rr 应为字面量：pass=%q action=%v", pass, action)
	}
}

// ---- 错误文案 ----

func TestDialErrText(t *testing.T) {
	sock := "/tmp/fake-state/term.sock"
	err := dialErrText(sock, &fs.PathError{Op: "dial", Path: sock, Err: syscall.ENOENT})
	if err == nil || !strings.Contains(err.Error(), "出口未在运行") || !strings.Contains(err.Error(), "--state") {
		t.Fatalf("ENOENT 文案应合并归因并提 --state：%v", err)
	}
	err = dialErrText(sock, &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)})
	if err == nil || !strings.Contains(err.Error(), "残留 socket") {
		t.Fatalf("ECONNREFUSED 文案应指残留 socket：%v", err)
	}
	err = dialErrText(sock, errors.New("boom"))
	if err == nil || !strings.Contains(err.Error(), "连不上") {
		t.Fatalf("其它错误应带 socket 路径：%v", err)
	}
}

func TestProtoErrorText(t *testing.T) {
	pe := &protoError{code: "no_session", msg: "会话 x 不存在"}
	if !strings.Contains(pe.Error(), "homeway term list") {
		t.Fatalf("no_session 应带 list 提示：%v", pe)
	}
	if !isProtoCode(pe, "no_session") || isProtoCode(pe, "already_exists") {
		t.Fatal("isProtoCode 判定错误")
	}
	if isProtoCode(errors.New("x"), "x") {
		t.Fatal("非 proto 错误不该命中")
	}
}

func TestEndedMessage(t *testing.T) {
	cases := []struct {
		code   int32
		reason string
		want   string
	}{
		{termEndReplaced, termReasonReplaced, "被另一客户端接管"},
		{termEndReplaced, termReasonSelfReconnect, "self_reconnect"},
		{termEndKilled, "", "已被关闭"},
		{termEndServiceStopped, "service_stopped", "出口服务正在退出"},
		{0, "", "已结束（退出码 0）"},
		{7, "", "退出码 7"},
	}
	for _, c := range cases {
		got := endedMessage("s", c.code, c.reason)
		if !strings.Contains(got, c.want) {
			t.Fatalf("endedMessage(%d,%q) = %q，缺 %q", c.code, c.reason, got, c.want)
		}
	}
}

// ---- 实例标识 / 自动命名 ----

func TestClientIDFor(t *testing.T) {
	a, b := clientIDFor("/dev/ttys999"), clientIDFor("/dev/ttys999")
	if a != b || !strings.HasPrefix(a, "host-") {
		t.Fatalf("同一 tty 应得同一 host- 前缀标识：%q vs %q", a, b)
	}
	if c := clientIDFor("/dev/ttys001"); c == a {
		t.Fatalf("不同 tty 的标识不该相同：%q", c)
	}
	r1, r2 := clientIDFor(""), clientIDFor("")
	if r1 == r2 || !strings.HasPrefix(r1, "rnd-") {
		t.Fatalf("无 tty 应退化每进程随机：%q vs %q", r1, r2)
	}
	if len(clientIDFor("/dev/ttys999")) > termMaxClientIDLen {
		t.Fatal("实例标识超上限")
	}
}

func TestGenAutoName(t *testing.T) {
	rx := regexp.MustCompile(`^host-[0-9a-f]{4}$`)
	for i := 0; i < 20; i++ {
		if n := genAutoName(); !rx.MatchString(n) {
			t.Fatalf("自动命名 %q 不合形", n)
		}
	}
}

// ---- 表格与 JSON 输出 ----

func TestCLIListPrint(t *testing.T) {
	entries := []cliSessionInfo{
		{Name: "build", Cols: 120, Rows: 40, StateV2: "working", Agent: "codex", Title: "cargo build", Clients: []cliClientInfo{{Kind: "app"}, {Kind: "host", Active: true}}},
		{Name: "old", Cols: 80, Rows: 24, StateV2: "idle", Agent: "shell"},
	}
	raw := []byte(`{"sessions":[{"name":"build"}]}`)
	var buf bytes.Buffer
	if err := cliListPrint(&buf, entries, raw, false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"NAME", "SIZE", "build", "120x40", "working", "codex", "cargo build", "app,host*", "old", "-"} {
		if !strings.Contains(out, want) {
			t.Fatalf("表格缺 %q：\n%s", want, out)
		}
	}
	// 空列表。
	buf.Reset()
	if err := cliListPrint(&buf, nil, []byte(`{"sessions":[]}`), false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "没有会话") {
		t.Fatalf("空列表文案：%q", buf.String())
	}
	// JSON：与出口 LIST JSON 同构（原样缩进）。
	buf.Reset()
	if err := cliListPrint(&buf, nil, raw, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"name": "build"`) {
		t.Fatalf("--json 应原样缩进出口 JSON：%q", buf.String())
	}
}

// ---- usage 纪律（6.3：不出现旧出口检测/告警文案）----

func TestTermUsageNoLegacyHints(t *testing.T) {
	var buf bytes.Buffer
	termUsage(&buf)
	// 被禁词在仓内 grep 应零命中（任务 6.3 判据），这里拼接构造，避免测试自身成为命中源。
	concat := func(a, b string) string { return a + b }
	for _, banned := range []string{concat("feat", "MultiLeg"), concat("接管", "告警"), concat("重启", "出口")} {
		if strings.Contains(buf.String(), banned) {
			t.Fatalf("usage 不该出现被禁词（%.11s…）", banned)
		}
	}
	for _, want := range []string{"Ctrl-b d", "Ctrl-b r", "--detach-key", "tmux 的前缀相同", "^]"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("usage 缺 %q", want)
		}
	}
}

// ---- 对真实服务的 one-shot 命令（经 UDS 直连）----

// startTestTermUDS 在临时目录起 <state>/term.sock（服务真跑；TCP 监听留给既有 helper 用）。
func startTestTermUDS(t *testing.T) (*termService, net.Listener, string) {
	t.Helper()
	return startTestTermUDSShell(t, testTermShell)
}

// testTermEchoShell：会话侧把收到的每行加 GOT: 前缀回显——「输入真到达会话」的判据源
// （本地 tty 在 raw 之前也会回显，纯文本判据分不清来源；GOT: 只能由会话产生）。
const testTermEchoShell = "while :; do echo tick; sleep 0.2; done & sed s/^/GOT:/"

func startTestTermUDSShell(t *testing.T, shellCmd string) (*termService, net.Listener, string) {
	t.Helper()
	svc, ln := startTestTermServiceShell(t, shellCmd)
	// macOS sun_path 上限 104 字节：t.TempDir() 的 /var/folders 路径太长，换 /tmp 下短目录。
	dir, err := os.MkdirTemp("/tmp", "termcli-uds-")
	if err != nil {
		t.Fatalf("mktemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	uln, err := net.Listen("unix", filepath.Join(dir, "term.sock"))
	if err != nil {
		t.Fatalf("listen uds: %v", err)
	}
	go func() {
		for {
			c, err := uln.Accept()
			if err != nil {
				return
			}
			go svc.ServeConn(c)
		}
	}()
	t.Cleanup(func() { uln.Close(); svc.Close(); ln.Close() })
	return svc, ln, dir
}

func TestCLIListAgainstService(t *testing.T) {
	_, ln, dir := startTestTermUDS(t)
	c, _, _, _ := attachTerm(t, ln, "cli-l1", true, 100, 30)
	defer c.Close()

	entries, raw, err := cliListFetch(&termTarget{stateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "cli-l1" || entries[0].Cols != 100 {
		t.Fatalf("list 结果不符：%+v", entries)
	}
	if !bytes.Contains(raw, []byte(`"clients"`)) {
		t.Fatalf("LIST JSON 缺 clients：%s", raw)
	}
	var buf bytes.Buffer
	if err := cliListPrint(&buf, entries, raw, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "cli-l1") {
		t.Fatalf("表格缺会话名：%s", buf.String())
	}
}

// waitSessionGone 轮询等会话从列表消失：KILL 的 OK 回包**先于**会话 teardown 完成
// （kill 发信号即回包，done 由 pump 收尾路径置位），立即断言存在竞态——批 1 遗留
// flake（三包并行跑时偶发「delete 后会话应消失」红），term-remote 批 2 修为轮询。
func waitSessionGone(t *testing.T, ln net.Listener, name string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := listSession(listTerm(t, ln), name); !ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("会话 %s 应在 5s 内从列表消失（KILL 后 teardown）", name)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestCLIDeleteAgainstService(t *testing.T) {
	_, ln, dir := startTestTermUDS(t)
	c, _, _, _ := attachTerm(t, ln, "cli-del", true, 80, 24)
	defer c.Close()

	if err := cliDelete([]string{"cli-del", "--state", dir}, nil); err != nil {
		t.Fatalf("delete：%v", err)
	}
	waitSessionGone(t, ln, "cli-del")
	err := cliDelete([]string{"cli-del", "--state", dir}, nil)
	if err == nil || !strings.Contains(err.Error(), "homeway term list") {
		t.Fatalf("delete 不存在的会话应报可行动错误：%v", err)
	}
}

func TestCLINewDetachedAgainstService(t *testing.T) {
	_, ln, dir := startTestTermUDS(t)

	if err := cliNew([]string{"-d", "ci1", "--state", dir}, nil); err != nil {
		t.Fatalf("new -d：%v", err)
	}
	sess, ok := listSession(listTerm(t, ln), "ci1")
	if !ok {
		t.Fatal("new -d 后会话应在列表")
	}
	if sess["attached"] != false {
		t.Error("new -d 不接入 ⇒ attached=false")
	}
	if sess["cols"].(float64) != 80 || sess["rows"].(float64) != 24 {
		t.Error("new -d ⇒ 默认尺寸 80x24")
	}
	// 重名（未给 -A）报错。
	err := cliNew([]string{"-d", "ci1", "--state", dir}, nil)
	if !isProtoCode(err, "already_exists") {
		t.Fatalf("new -d 重名应报 already_exists：%v", err)
	}
	// -A -d 复用成功。
	if err := cliNew([]string{"-d", "-A", "ci1", "--state", dir}, nil); err != nil {
		t.Fatalf("new -A -d：%v", err)
	}
	// 自动命名。
	if err := cliNew([]string{"-d", "--state", dir}, nil); err != nil {
		t.Fatalf("new -d 自动命名：%v", err)
	}
	rx := regexp.MustCompile(`^host-[0-9a-f]{4}$`)
	list := listTerm(t, ln)
	found := false
	arr, _ := list["sessions"].([]any)
	for _, it := range arr {
		m, _ := it.(map[string]any)
		if m != nil && rx.MatchString(m["name"].(string)) {
			found = true
		}
	}
	if !found {
		t.Fatalf("自动命名的 host-<4hex> 会话应在列表：%v", list)
	}
}

func TestCLIInvalidNameNoDial(t *testing.T) {
	// 非法名：就地报错（不发起连接——state 目录根本不存在也不会碰到 socket 层错误）。
	err := cliDelete([]string{"bad name!", "--state", "/nonexistent-xyz"}, nil)
	if err == nil || !strings.Contains(err.Error(), "不合法") {
		t.Fatalf("非法名应就地报错：%v", err)
	}
	o, perr := parseNewArgs([]string{"bad name!"})
	if perr == nil || !strings.Contains(perr.Error(), "不合法") {
		t.Fatalf("new 非法名应就地报错：%v（%+v）", perr, o)
	}
}

func TestCLIDialErrAgainstEmptyDir(t *testing.T) {
	dir := t.TempDir() // 没有 term.sock
	err := cliList([]string{"--state", dir}, nil)
	if err == nil || !strings.Contains(err.Error(), "出口未在运行") {
		t.Fatalf("空目录应报 ENOENT 合并文案：%v", err)
	}
}

// TestCLIListDeleteDefaultState：不带 --state 的 list/delete 也必须落到默认 state
// （~/.config/homeway，D1「--state 沿用默认」）——发版后实测裸 `homeway term list` 报
// 「拿不到 state 目录」（cliList/cliDelete 漏了缺省补默认，new/attach/explain 都有），
// 本用例锁回归：HOME 指到带 .config/homeway/term.sock（symlink 到真实 socket）的假家目录。
func TestCLIListDeleteDefaultState(t *testing.T) {
	_, ln, dir := startTestTermUDS(t)
	_, _, _, _ = attachTerm(t, ln, "cli-dflt", true, 100, 30)

	// macOS sun_path 上限 104 字节：t.TempDir() 的 /var/folders 路径太长（连 symlink 都
	// 过不了 connect），与 startTestTermUDS 同款换 /tmp 下短目录。
	home, err := os.MkdirTemp("/tmp", "termcli-home-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	if err := os.MkdirAll(filepath.Join(home, ".config", "homeway"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "term.sock"),
		filepath.Join(home, ".config", "homeway", "term.sock")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	// 裸 list（无 --state）：走默认 state，能列出会话。
	var buf bytes.Buffer
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	listErr := cliList(nil, nil)
	w.Close()
	os.Stdout = old
	_, _ = io.Copy(&buf, r)
	if listErr != nil {
		t.Fatalf("裸 list 应走默认 state：%v", listErr)
	}
	if !strings.Contains(buf.String(), "cli-dflt") {
		t.Fatalf("默认 state 的 list 应列出会话：%s", buf.String())
	}

	// 裸 delete（无 --state）：同样走默认 state（用第二会话验证真删）。注册表摘除与
	// KILL 的 OK 回复存在毫秒级竞态（TestCLIDeleteAgainstService 偶发顺序差），短轮询等它。
	_, _, _, _ = attachTerm(t, ln, "cli-dflt2", true, 100, 30)
	if err := cliDelete([]string{"cli-dflt2"}, nil); err != nil {
		t.Fatalf("裸 delete 应走默认 state：%v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		entries, _, err := cliListFetch(&termTarget{stateDir: dir})
		if err != nil {
			t.Fatal(err)
		}
		gone := true
		for _, e := range entries {
			if e.Name == "cli-dflt2" {
				gone = false
			}
		}
		if gone {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("cli-dflt2 应已被默认 state 的 delete 删除：%+v", entries)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// ---- 3.2 D7-b（term-remote）：非属主无法连接 term.sock 的可自动化最小代理 ----
//
// 与 control.sock 用例（internal/daemon）同机制：权限位参与 connect 判定，chmod 0000
// 后属主同样被拦（EACCES）——「非属主被 0600 拦」的同源最小代理。root 绕过权限位 ⇒
// 跳过；真跨用户面留 live 复核（term-host-cli exec-r5 F3 双端手工实验已证）。

func TestTermSockPermissionBlocksConnect(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 绕过 socket 权限位，chmod 0000 代理用例不成立（真跨用户面留 live 复核）")
	}
	dir, err := os.MkdirTemp("", "termsockperm-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "term.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	// 基线：默认权限下属主可 connect。
	if c, derr := net.DialTimeout("unix", sock, time.Second); derr != nil {
		t.Fatalf("基线：属主应能 connect：%v", derr)
	} else {
		_ = c.Close()
	}

	// chmod 0000 → cliDialTerm 本地面报「无权连接」（EACCES 翻文案 + socket 路径）。
	if err := os.Chmod(sock, 0o0000); err != nil {
		t.Fatal(err)
	}
	_, derr := cliDialTerm(newTermTarget(nil, dir, "", 0))
	if derr == nil {
		t.Fatal("chmod 0000 后本地面拨号应报错")
	}
	if !strings.Contains(derr.Error(), "无权连接") || !strings.Contains(derr.Error(), sock) {
		t.Fatalf("应报 EACCES 翻文案（带 %s）：%v", sock, derr)
	}
}
