package daemon

// status_cli_test.go — 4.1 判据：对测试 daemon 端到端跑通（Go 客户端真实路径：
// UDS + 握手 + daemon.status）+ 未运行时可行动错误 + usage 文案。

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zhaoyswd/homeway/internal/control"
)

func TestDaemonStatusCLIEndToEnd(t *testing.T) {
	st, _ := startDaemonForTest(t, nil)
	// 人类可读面：角色/主机/版本都在。
	var buf bytes.Buffer
	if err := statusCLI([]string{"--state", st.Dir}, "cli-test", &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"homeway daemon：运行中", "test-daemon", "client=running", "主机： 无", st.Dir} {
		if !strings.Contains(out, want) {
			t.Fatalf("status 输出缺 %q：\n%s", want, out)
		}
	}

	// --json：机器可读全量快照（服务端载荷原样，可被 daemon.status 载荷结构解回）。
	buf.Reset()
	if err := statusCLI([]string{"--state", st.Dir, "--json"}, "cli-test", &buf); err != nil {
		t.Fatal(err)
	}
	var st2 control.DaemonStatusResult
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &st2); err != nil {
		t.Fatalf("--json 载荷解析：%v（%s）", err, buf.String())
	}
	if st2.ServerVersion != "test-daemon" || st2.Generation == "" || len(st2.Roles) == 0 {
		t.Fatalf("--json 快照形状：%+v", st2)
	}
}

func TestDaemonStatusCLINotRunning(t *testing.T) {
	// 无 daemon 的空 state 目录：可行动错误（含启动命令与 socket 路径——
	// spec「命令归属规则」：守护托管命令在守护进程未运行时）。
	dir := shortTempDirDaemon(t)
	var buf bytes.Buffer
	err := statusCLI([]string{"--state", dir}, "cli-test", &buf)
	if err == nil {
		t.Fatal("未运行时应报错")
	}
	msg := err.Error()
	for _, want := range []string{"homeway daemon 未在运行", "control.sock", "homeway --state"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("可行动错误缺 %q：%s", want, msg)
		}
	}
	if buf.Len() != 0 {
		t.Fatalf("失败路径不应有 stdout 输出：%q", buf.String())
	}
}

func TestDaemonStatusCLIUsage(t *testing.T) {
	var buf bytes.Buffer
	if err := statusCLI([]string{"--help"}, "cli-test", &buf); err != nil {
		t.Fatalf("--help 不应报错：%v", err)
	}
	out := buf.String()
	for _, want := range []string{"homeway daemon status", "-state", "-json", "-timeout"} {
		if !strings.Contains(out, want) {
			t.Fatalf("usage 缺 %q：\n%s", want, out)
		}
	}
	if err := statusCLI([]string{"--nope"}, "cli-test", &buf); err == nil {
		t.Fatal("未知 flag 应报错")
	}
}
