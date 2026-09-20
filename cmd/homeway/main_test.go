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
		{"裸启动=出口", nil, "exit", nil},
		{"显式 exit", []string{"exit", "--relay", "rl1x"}, "exit", []string{"--relay", "rl1x"}},
		{"显式 relay", []string{"relay", "--advertise", "1.2.3.4:41741"}, "relay", []string{"--advertise", "1.2.3.4:41741"}},
		{"省略子命令的 flag", []string{"--relay", "rl1x"}, "exit", []string{"--relay", "rl1x"}},
		{"未知子命令", []string{"foo"}, "foo", []string{}},
		{"exit 裸调", []string{"exit"}, "exit", []string{}},
		{"relay 裸调", []string{"relay"}, "relay", []string{}},
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
