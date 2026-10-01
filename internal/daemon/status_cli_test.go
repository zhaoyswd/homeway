package daemon

// status_cli_test.go — role-management 3.4 判据：聚合 `homeway status` 三态
//（全停直跑底座 / 运行面三 op 并聚 / --json 字段名）+ usage 面。--watch 的需求
// 合成副作用与续播判据在 status_watch_test.go（平移不变，入口 = homeway status --watch）。

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zhaoyswd/homeway/internal/nodeconfig"
)

// aggJSON --json 输出的解回形状（字段名与 spec 清单对拍：process/serve/relay/client）。
type aggJSON struct {
	Process struct {
		Running bool   `json:"running"`
		Pid     int    `json:"pid"`
		Version string `json:"version"`
		StateD  string `json:"stateDir"`
	} `json:"process"`
	Serve struct {
		Enabled bool   `json:"enabled"`
		State   string `json:"state"`
	} `json:"serve"`
	Relay struct {
		Enabled bool   `json:"enabled"`
		State   string `json:"state"`
	} `json:"relay"`
	Client struct {
		Running bool `json:"running"`
		HostCnt int  `json:"hostCount"`
	} `json:"client"`
}

// TestStatusCLIRunningFace 运行面：daemon.status + serve.status + relay.status 并聚。
func TestStatusCLIRunningFace(t *testing.T) {
	st, _ := startDaemonForTest(t, nil)
	var buf bytes.Buffer
	if err := StatusCLI([]string{"--state", st.Dir}, "cli-test", &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"homeway：运行中", "test-daemon", "client=running", "主机： 无", st.Dir} {
		if !strings.Contains(out, want) {
			t.Fatalf("status 输出缺 %q：\n%s", want, out)
		}
	}
	// roles==nil 的测试形态：serve/relay 节按「运行面不可得」降级注明（不炸整份输出）。
	if !strings.Contains(out, "serve：") || !strings.Contains(out, "relay：") {
		t.Fatalf("serve/relay 节缺席：\n%s", out)
	}
}

// TestStatusCLIRunningJSON 运行面 --json：四域字段名 + pid。
func TestStatusCLIRunningJSON(t *testing.T) {
	st, _ := startDaemonForTest(t, nil)
	var buf bytes.Buffer
	if err := StatusCLI([]string{"--state", st.Dir, "--json"}, "cli-test", &buf); err != nil {
		t.Fatal(err)
	}
	var agg aggJSON
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &agg); err != nil {
		t.Fatalf("--json 解析：%v（%s）", err, buf.String())
	}
	if !agg.Process.Running || agg.Process.Pid == 0 || agg.Process.Version != "test-daemon" {
		t.Fatalf("process 域形状：%+v", agg.Process)
	}
	if agg.Serve.State == "" || agg.Relay.State == "" {
		t.Fatalf("serve/relay 域缺席（nil roles 形态给 absent）：%s", buf.String())
	}
	if !agg.Client.Running {
		t.Fatalf("client 域应 running：%s", buf.String())
	}
}

// TestStatusCLIDegradedFace 全停面（spec 场景「全停时读 config 报期望态」）：
// config 期望态 + L2 存在性 + 进程层「未运行」，全程无进程被拉起（纯读）。
func TestStatusCLIDegradedFace(t *testing.T) {
	dir := shortTempDirDaemon(t)
	cfg := nodeconfig.Default()
	cfg.Serve.Enabled = true
	cfg.Relay.Enabled = false
	if err := nodeconfig.Save(nodeconfig.Path(dir), cfg); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := StatusCLI([]string{"--state", dir}, "cli-test", &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"homeway：未运行", "serve：期望启用（未运行）", "relay：期望停用", "不拉起"} {
		if !strings.Contains(out, want) {
			t.Fatalf("全停面缺 %q：\n%s", want, out)
		}
	}
	if !strings.Contains(out, "client：未运行") {
		t.Fatalf("client 节应报未运行：\n%s", out)
	}
	// --json 同面。
	buf.Reset()
	if err := StatusCLI([]string{"--state", dir, "--json"}, "cli-test", &buf); err != nil {
		t.Fatal(err)
	}
	var agg aggJSON
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &agg); err != nil {
		t.Fatal(err)
	}
	if agg.Process.Running || !agg.Serve.Enabled || agg.Serve.State != "期望启用（未运行）" || agg.Relay.Enabled {
		t.Fatalf("全停 --json 形状：%s", buf.String())
	}
	if agg.Client.Running || agg.Client.HostCnt != 0 {
		t.Fatalf("client 未跑面：%s", buf.String())
	}
	// host 表台数（client/hosts.json 存在时点得出）。
	if err := writeHostsFile(dir, `[{"id":"01","name":"mac","added":1}]`); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if err := StatusCLI([]string{"--state", dir, "--json"}, "cli-test", &buf); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &agg); err != nil {
		t.Fatal(err)
	}
	if agg.Client.HostCnt != 1 {
		t.Fatalf("hostCount 应点出 1 台：%s", buf.String())
	}
}

// TestStatusCLIUsage usage 面。
func TestStatusCLIUsage(t *testing.T) {
	var buf bytes.Buffer
	if err := StatusCLI([]string{"--help"}, "cli-test", &buf); err != nil {
		t.Fatalf("--help 不应报错：%v", err)
	}
	out := buf.String()
	for _, want := range []string{"homeway status", "-state", "-json", "-watch", "-timeout"} {
		if !strings.Contains(out, want) {
			t.Fatalf("usage 缺 %q：\n%s", want, out)
		}
	}
	buf.Reset()
	if err := StatusCLI([]string{"--nope"}, "cli-test", &buf); err == nil {
		t.Fatal("未知 flag 应报错")
	}
	buf.Reset()
	err := StatusCLI([]string{"--state", shortTempDirDaemon(t), "--watch"}, "cli-test", &buf)
	if err == nil || !strings.Contains(err.Error(), "未在运行") {
		t.Fatalf("--watch 未跑 = 可行动错误（不拉起）：%v", err)
	}
}

// writeHostsFile 测试夹具：client/hosts.json 写入原始内容（hostCountOnDisk 数据源）。
func writeHostsFile(dir, content string) error {
	if err := os.MkdirAll(filepath.Join(dir, "client"), 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "client", "hosts.json"), []byte(content), 0o600)
}
