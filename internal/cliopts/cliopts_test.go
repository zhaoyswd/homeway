package cliopts

import (
	"bytes"
	"context"
	"os"
	"testing"
)

// TestDefaultOutIsStderr（FIX-48）：拉起提示的缺省去向必须是 stderr——stdout 是
// 命令输出与 --json 的机器可读面，混进一行「守护进程未运行，已启动 pid=N」会让
// 解析直接碎。
func TestDefaultOutIsStderr(t *testing.T) {
	if got := From(context.Background()).Out; got != os.Stderr {
		t.Fatalf("未挂 Opts 时 Out 应为 os.Stderr，got %v", got)
	}
	if got := From(With(context.Background(), Opts{})).Out; got != os.Stderr {
		t.Fatalf("挂了空 Opts 时 Out 应为 os.Stderr，got %v", got)
	}
	var b bytes.Buffer
	if got := From(With(context.Background(), Opts{Out: &b})).Out; got != &b {
		t.Fatalf("显式 Out 应原样保留，got %v", got)
	}
	if !From(With(context.Background(), Opts{NoSpawn: true})).NoSpawn {
		t.Fatal("NoSpawn 应原样保留")
	}
}
