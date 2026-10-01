package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestResolveRole(t *testing.T) {
	cases := []struct {
		name string
		args []string
		role string
		rest []string
	}{
		{"裸启动=统一进程", nil, "unified", nil},
		{"全局 flag 首参=统一进程", []string{"--state", "/tmp/x", "--verbose"}, "unified", []string{"--state", "/tmp/x", "--verbose"}},
		{"显式 serve", []string{"serve", "--relay", "rl1x"}, "serve", []string{"--relay", "rl1x"}},
		{"serve 裸调（前台单角色）", []string{"serve"}, "serve", []string{}},
		{"serve 命令组动词", []string{"serve", "start"}, "serve", []string{"start"}},
		{"serve status --json", []string{"serve", "status", "--json"}, "serve", []string{"status", "--json"}},
		{"serve relay set", []string{"serve", "relay", "set", "rl1x"}, "serve", []string{"relay", "set", "rl1x"}},
		{"serve ddns list", []string{"serve", "ddns", "list"}, "serve", []string{"ddns", "list"}},
		{"显式 relay", []string{"relay", "--advertise", "1.2.3.4:41741"}, "relay", []string{"--advertise", "1.2.3.4:41741"}},
		{"relay 裸调（前台单角色）", []string{"relay"}, "relay", []string{}},
		{"relay 命令组动词", []string{"relay", "token"}, "relay", []string{"token"}},
		{"status 跨域名词", []string{"status", "--json"}, "status", []string{"--json"}},
		{"status --watch", []string{"status", "--watch"}, "status", []string{"--watch"}},
		{"export", []string{"export"}, "export", []string{}},
		{"import", []string{"import", "a.tar"}, "import", []string{"a.tar"}},
		{"reset cache", []string{"reset", "cache"}, "reset", []string{"cache"}},
		{"旧名词 exit（迁移提示）", []string{"exit"}, "exit", []string{}},
		{"旧名词 daemon（迁移提示）", []string{"daemon"}, "daemon", []string{}},
		{"旧名词 daemon status（迁移提示）", []string{"daemon", "status"}, "daemon", []string{"status"}},
		{"未知子命令", []string{"foo"}, "foo", []string{}},
		{"host 角色（host-cli 3b）", []string{"host", "add", "--name", "mbp", "hmw1x"}, "host", []string{"add", "--name", "mbp", "hmw1x"}},
		{"host 裸调（usage 面）", []string{"host"}, "host", []string{}},
		{"forward 角色（3e）", []string{"forward", "add", "--host", "ali", "--listen", "8080"}, "forward", []string{"add", "--host", "ali", "--listen", "8080"}},
		{"forward 裸调（usage 面）", []string{"forward"}, "forward", []string{}},
		{"socks 角色（3e）", []string{"socks", "on", "--host", "ali"}, "socks", []string{"on", "--host", "ali"}},
		{"speedtest 角色（3e）", []string{"speedtest", "--host", "ali", "--json"}, "speedtest", []string{"--host", "ali", "--json"}},
		{"speedtest 裸跑（全主机轮流）", []string{"speedtest"}, "speedtest", []string{}},
		{"term 子命令面", []string{"term", "list"}, "term", []string{"list"}},
		{"files 子命令面", []string{"files", "list"}, "files", []string{"list"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			role, rest := resolveRole(c.args)
			if role != c.role {
				t.Fatalf("role = %q, 期望 %q", role, c.role)
			}
			if len(rest) != len(c.rest) {
				t.Fatalf("rest = %#v, 期望 %#v", rest, c.rest)
			}
			for i := range rest {
				if rest[i] != c.rest[i] {
					t.Fatalf("rest = %#v, 期望 %#v", rest, c.rest)
				}
			}
		})
	}
}

// groupVerb 双态分派：动词必须紧跟名词（flag 后跟动词 = 前台形态，D1）。
func TestGroupVerb(t *testing.T) {
	if !groupVerb([]string{"start", "--state", "/x"}, serveGroupVerbs) {
		t.Fatal("serve start 应命中命令组")
	}
	if groupVerb([]string{"--state", "/x", "start"}, serveGroupVerbs) {
		t.Fatal("flag 后的 start 不算命令组动词（前台形态自己报错并提示动词位置）")
	}
	if groupVerb([]string{}, serveGroupVerbs) || groupVerb([]string{"--verbose"}, serveGroupVerbs) {
		t.Fatal("空/纯 flag = 前台单角色")
	}
	if !groupVerb([]string{"start"}, relayGroupVerbs) || groupVerb([]string{"ddns"}, relayGroupVerbs) {
		t.Fatal("relay 组无 ddns 动词")
	}
}

// 旧名词 exit/daemon（含 daemon status）= 迁移提示报错（非零码、不启动任何进程）；
// 统一进程角色 flag = 可行动错误；--version 断言（顶层/角色后，r1 低-5）。
func TestRunRejectsLegacyAndRoleFlagsOnUnified(t *testing.T) {
	if code := run([]string{"exit", "--relay", "rl1x"}); code == 0 {
		t.Fatal("`homeway exit` 应报迁移提示并退出非零")
	}
	if code := run([]string{"daemon"}); code == 0 {
		t.Fatal("`homeway daemon` 应报迁移提示并退出非零")
	}
	if code := run([]string{"daemon", "status"}); code == 0 {
		t.Fatal("`homeway daemon status` 应报迁移提示并退出非零（status 由 `homeway status` 承载）")
	}
	if code := run([]string{"--listen", "41641"}); code == 0 {
		t.Fatal("统一进程形态打角色 flag 应报可行动错误并退出非零")
	}
	if code := run([]string{"--version"}); code != 0 {
		t.Fatal("--version 应零退出")
	}
	if code := run([]string{"serve", "--version"}); code != 0 {
		t.Fatal("homeway serve --version 应零退出（r1 低-5）")
	}
	if code := run([]string{"relay", "--version"}); code != 0 {
		t.Fatal("homeway relay --version 应零退出")
	}
}

// usage 快照面：命令组/聚合 status/工件命令/按需拉起与消歧义句都要在
// （`homeway --help` 的机器可核对替代——关键行逐条断言）。
func TestUsageSnapshot(t *testing.T) {
	var b bytes.Buffer
	usage(&b)
	out := b.String()
	for _, want := range []string{
		"serve start|stop|restart", "serve status [--json]", "serve token",
		"serve relay set <token> [--stdin] | clear", "serve ddns add|delete",
		"relay start|stop|restart|status [--json]|token",
		"homeway status [--json] [--watch]",
		"homeway export", "homeway import <file>", "homeway reset cache",
		"--no-spawn", "已启动 pid=N",
		"同词根不同义", // serve.relay vs [relay] 消歧义句（r1 低-8）
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("usage 缺 %q", want)
		}
	}
}
