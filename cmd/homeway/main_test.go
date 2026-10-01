package main

import (
	"reflect"
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
		{"显式 relay", []string{"relay", "--advertise", "1.2.3.4:41741"}, "relay", []string{"--advertise", "1.2.3.4:41741"}},
		{"旧名词 exit（迁移提示）", []string{"exit"}, "exit", []string{}},
		{"未知子命令", []string{"foo"}, "foo", []string{}},
		{"host 角色（host-cli 3b）", []string{"host", "add", "--name", "mbp", "hmw1x"}, "host", []string{"add", "--name", "mbp", "hmw1x"}},
		{"host 裸调（usage 面）", []string{"host"}, "host", []string{}},
		{"forward 角色（3e）", []string{"forward", "add", "--host", "ali", "--listen", "8080"}, "forward", []string{"add", "--host", "ali", "--listen", "8080"}},
		{"forward 裸调（usage 面）", []string{"forward"}, "forward", []string{}},
		{"socks 角色（3e）", []string{"socks", "on", "--host", "ali"}, "socks", []string{"on", "--host", "ali"}},
		{"speedtest 角色（3e）", []string{"speedtest", "--host", "ali", "--json"}, "speedtest", []string{"--host", "ali", "--json"}},
		{"speedtest 裸跑（全主机轮流）", []string{"speedtest"}, "speedtest", []string{}},
		{"daemon 子命令面", []string{"daemon", "status"}, "daemon", []string{"status"}},
		{"term 子命令面", []string{"term", "list"}, "term", []string{"list"}},
		{"files 子命令面", []string{"files", "list"}, "files", []string{"list"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			role, rest := resolveRole(c.args)
			if role != c.role {
				t.Fatalf("role = %q, 期望 %q", role, c.role)
			}
			if !reflect.DeepEqual(rest, c.rest) {
				t.Fatalf("rest = %#v, 期望 %#v", rest, c.rest)
			}
		})
	}
}

// 旧名词 exit 与角色 flag 打在统一进程形态 = 非零退出（迁移提示/可行动错误）。
func TestRunRejectsLegacyAndRoleFlagsOnUnified(t *testing.T) {
	if code := run([]string{"exit"}); code == 0 {
		t.Fatal("`homeway exit` 应报迁移提示并退出非零")
	}
	if code := run([]string{"--listen", "41641"}); code == 0 {
		t.Fatal("统一进程形态打角色 flag 应报可行动错误并退出非零")
	}
	if code := run([]string{"--version"}); code != 0 {
		t.Fatal("--version 应零退出")
	}
}
