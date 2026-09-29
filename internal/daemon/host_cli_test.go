package daemon

// host_cli_test.go — host 命令面端到端判据（host-cli 1.7）：对测试 daemon（真实
// UDS + 帧 + JSON 全链）跑 CLI 全场景——无 daemon 可行动错误/非法 token 不探测/
// 全不可达+--force/仅中继假探测 e2e（relay 档场景证据）/两主机列表含添加时间/
// 删除确认与不存在/非 tty 拒绝 + daemon 分发红绿（B15：NArg 与 --help）。
// token 掩码：全部断言输出不含 token 全文。

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/internal/control"
	"github.com/zhaoyswd/homeway/pkg/probe"
	"github.com/zhaoyswd/homeway/pkg/proto"
)

// injectFakeProbe 假探测注入（生产 = pkg/probe.Reach；四路真探测判据见
// host_add_test.go——此处只驱动 CLI 呈现层的档位映射）。返回还原函数。
func injectFakeProbe(t *testing.T, fn func(ctx context.Context, token string) (*probe.ReachReport, error)) {
	t.Helper()
	orig := reachProbe
	reachProbe = fn
	t.Cleanup(func() { reachProbe = orig })
}

func hostTok(t *testing.T, peer byte, name string) string {
	t.Helper()
	s, err := proto.EncodeToken(proto.Token{PeerID: [32]byte{peer}, Secret: [32]byte{peer, 3}, Endpoints: []proto.Endpoint{{Addr: "127.0.0.1:41000"}}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestHostCLINoDaemonActionableError(t *testing.T) {
	dir := shortTempDirDaemon(t)
	var buf bytes.Buffer
	for _, args := range [][]string{
		{"list", "--state", dir},
		{"status", "--state", dir},
		{"delete", "--yes", "--state", dir, "xx"},
	} {
		buf.Reset()
		if err := hostCLI(args, "cli-test", &buf); err == nil {
			t.Fatalf("%v：无 daemon 应报错", args)
		} else {
			msg := err.Error()
			for _, want := range []string{"homeway daemon 未在运行", "control.sock", "homeway daemon --state"} {
				if !strings.Contains(msg, want) {
					t.Fatalf("%v：可行动错误缺 %q：%s", args, want, msg)
				}
			}
		}
		if buf.Len() != 0 {
			t.Fatalf("失败路径不应有 stdout：%q", buf.String())
		}
	}
	// add 的无 daemon 路径（token 合法才连 daemon）。
	tok := hostTok(t, 21, "")
	var buf2 bytes.Buffer
	err := hostCLI([]string{"add", "--state", dir, tok}, "cli-test", &buf2)
	if err == nil || !strings.Contains(err.Error(), "homeway daemon 未在运行") {
		t.Fatalf("add 无 daemon 应可行动报错：%v", err)
	}
	if strings.Contains(err.Error(), tok) {
		t.Fatal("错误信息不得回显 token 全文（掩码纪律）")
	}
}

func TestHostCLIBadTokenLocalReject(t *testing.T) {
	called := false
	injectFakeProbe(t, func(ctx context.Context, token string) (*probe.ReachReport, error) {
		called = true
		return nil, nil
	})
	var buf bytes.Buffer
	err := hostCLI([]string{"add", "hmw1-not-a-token"}, "cli-test", &buf)
	if err == nil {
		t.Fatal("坏 token 应就地报错")
	}
	if called {
		t.Fatal("坏 token 不得触发探测（本地语法校验前置）")
	}
	if !strings.Contains(err.Error(), "token 非法") || !strings.Contains(err.Error(), "hmw1") {
		t.Fatalf("坏 token 错误面：%v", err)
	}
}

func TestHostCLIUnreachableThenForce(t *testing.T) {
	_, sock := startDaemonForTest(t)
	dir := strings.TrimSuffix(sock, "/control.sock")
	tok := hostTok(t, 22, "")
	injectFakeProbe(t, func(ctx context.Context, token string) (*probe.ReachReport, error) {
		return &probe.ReachReport{Peer: "16000000", Results: nil}, nil // 全不可达
	})

	var buf bytes.Buffer
	err := hostCLI([]string{"add", "--state", dir, "--name", "失联", tok}, "cli-test", &buf)
	if err == nil {
		t.Fatal("全不可达应非零退出（CLI 呈现为错误）")
	}
	msg := err.Error()
	for _, want := range []string{"全不可达", "出口是否在运行", "--force"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("全不可达错误缺 %q：%s", want, msg)
		}
	}
	if strings.Contains(msg, tok) {
		t.Fatal("错误信息不得回显 token 全文")
	}

	// --force：跳过验证直接入表（端点未实测）。
	buf.Reset()
	if err := hostCLI([]string{"add", "--state", dir, "--name", "失联", "--force", tok}, "cli-test", &buf); err != nil {
		t.Fatalf("force 应成功：%v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "已添加主机 失联") || !strings.Contains(out, "端点未实测") {
		t.Fatalf("force 成功输出：%s", out)
	}
	// 清理。
	cleanHost(t, sock)
}

// TestHostCLIRelayTierHint 仅中继可达假探测 e2e（relay 档场景证据，r1 ④-2）：
// 直连无应答 + 中继应答 → 入表 + 中继提示行。
func TestHostCLIRelayTierHint(t *testing.T) {
	_, sock := startDaemonForTest(t)
	dir := strings.TrimSuffix(sock, "/control.sock")
	tok := hostTok(t, 23, "")
	injectFakeProbe(t, func(ctx context.Context, token string) (*probe.ReachReport, error) {
		return &probe.ReachReport{
			Peer: "17000000",
			Results: []probe.ReachResult{
				{EP: "203.0.113.9:41741", RTT: 33 * time.Millisecond, Build: "vtest", Relay: true},
			},
		}, nil
	})
	var buf bytes.Buffer
	if err := hostCLI([]string{"add", "--state", dir, "--name", "中继后端", tok}, "cli-test", &buf); err != nil {
		t.Fatalf("仅中继应添加成功：%v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "仅中继可达") || !strings.Contains(out, "直连不可达，连接将走中继") || !strings.Contains(out, "检查出口公网端口/UPnP") {
		t.Fatalf("relay 档输出缺提示行：%s", out)
	}
	cleanHost(t, sock)
}

// TestHostCLIListStatusJSON 两主机列表含添加时间 + --json 形状（hosts 数组原样、
// 无包裹对象；status <name> = 单元素数组）+ 不存在报错。
func TestHostCLIListStatusJSON(t *testing.T) {
	_, sock := startDaemonForTest(t)
	dir := strings.TrimSuffix(sock, "/control.sock")
	injectFakeProbe(t, func(ctx context.Context, token string) (*probe.ReachReport, error) {
		return &probe.ReachReport{Peer: "18000000", Results: []probe.ReachResult{{EP: "203.0.113.20:41641", RTT: 8 * time.Millisecond}}}, nil
	})
	for _, tc := range []struct {
		peer byte
		name string
	}{{24, "甲"}, {25, "乙"}} {
		if err := hostCLI([]string{"add", "--state", dir, "--name", tc.name, hostTok(t, tc.peer, "")}, "cli-test", &bytes.Buffer{}); err != nil {
			t.Fatalf("add %s：%v", tc.name, err)
		}
	}

	var buf bytes.Buffer
	if err := hostCLI([]string{"list", "--state", dir}, "cli-test", &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"甲", "乙", "添加时间", "20"} { // 名称、表头、添加时间列有值
		if !strings.Contains(out, want) {
			t.Fatalf("list 输出缺 %q：\n%s", want, out)
		}
	}

	// --json = hosts 数组原样（无包裹对象）。
	buf.Reset()
	if err := hostCLI([]string{"list", "--state", dir, "--json"}, "cli-test", &buf); err != nil {
		t.Fatal(err)
	}
	j := bytes.TrimSpace(buf.Bytes())
	if len(j) == 0 || j[0] != '[' || j[len(j)-1] != ']' {
		t.Fatalf("--json 应为裸数组：\n%s", j)
	}
	var hosts []control.HostState
	if err := json.Unmarshal(j, &hosts); err != nil || len(hosts) != 2 {
		t.Fatalf("--json 数组形状：%v（%s）", err, j)
	}
	if hosts[0].AddedAt == 0 {
		t.Fatal("HostState.AddedAt 应上 wire（M1）")
	}

	// status <name> 详面 + --json 单元素数组（位置参数与 flag 次序不敏感）。
	buf.Reset()
	if err := hostCLI([]string{"status", "--state", dir, "甲"}, "cli-test", &buf); err != nil {
		t.Fatal(err)
	}
	out = buf.String()
	for _, want := range []string{"主机 甲", "添加时间", "会话态"} {
		if !strings.Contains(out, want) {
			t.Fatalf("status 详面缺 %q：\n%s", want, out)
		}
	}
	buf.Reset()
	if err := hostCLI([]string{"status", "--state", dir, "--json", "甲"}, "cli-test", &buf); err != nil {
		t.Fatal(err)
	}
	j = bytes.TrimSpace(buf.Bytes())
	var one []control.HostState
	if err := json.Unmarshal(j, &one); err != nil || len(one) != 1 || one[0].Name != "甲" {
		t.Fatalf("status --json 应为单元素数组：%v（%s）", err, j)
	}

	// status 不存在：可行动错误非零。
	if err := hostCLI([]string{"status", "--state", dir, "nosuch"}, "cli-test", &buf); err == nil || !strings.Contains(err.Error(), "不存在") {
		t.Fatalf("status 不存在应报错：%v", err)
	}
	cleanHost(t, sock)
}

func TestHostCLIDeleteScenarios(t *testing.T) {
	_, sock := startDaemonForTest(t)
	dir := strings.TrimSuffix(sock, "/control.sock")
	injectFakeProbe(t, func(ctx context.Context, token string) (*probe.ReachReport, error) {
		return &probe.ReachReport{Peer: "19000000", Results: []probe.ReachResult{{EP: "203.0.113.30:41641", RTT: 5 * time.Millisecond}}}, nil
	})
	if err := hostCLI([]string{"add", "--state", dir, "--name", "待删", hostTok(t, 26, "")}, "cli-test", &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	// ① 非 tty 未给 --yes：拒绝（stdinIsTerminal 注入缝压非 tty——go test 的
	// stdin=/dev/null 是 char device，不能作天然载体）。
	origTTY := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdinIsTerminal = origTTY })
	if err := hostCLI([]string{"delete", "--state", dir, "待删"}, "cli-test", &buf); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("非 tty 应拒绝并提示 --yes：%v", err)
	}
	// 拒绝后主机仍在。
	if err := hostCLI([]string{"status", "--state", dir, "待删"}, "cli-test", &buf); err != nil {
		t.Fatalf("拒绝删除后主机应仍在：%v", err)
	}
	// ② 不存在：可行动错误（幂等 ≠ 静默成功）。
	if err := hostCLI([]string{"delete", "--state", dir, "nosuch", "--yes"}, "cli-test", &buf); err == nil || !strings.Contains(err.Error(), "不存在") {
		t.Fatalf("删除不存在应报错：%v", err)
	}
	// ③ --yes 按名称删除成功。
	buf.Reset()
	if err := hostCLI([]string{"delete", "--state", dir, "待删", "--yes"}, "cli-test", &buf); err != nil {
		t.Fatalf("删除：%v", err)
	}
	if !strings.Contains(buf.String(), "已删除主机 待删") {
		t.Fatalf("删除成功输出：%s", buf.String())
	}
	// 再删同名 = 不存在（非静默）。
	if err := hostCLI([]string{"delete", "--state", dir, "待删", "--yes"}, "cli-test", &buf); err == nil {
		t.Fatal("重复删除应报不存在")
	}
}

// TestDaemonDispatchB15 daemon 分发红绿（B15）：`--state X status` 不再静默起
// 守护进程（NArg 检查）+ `daemon --help` 正常化（ErrHelp→nil）。
func TestDaemonDispatchB15(t *testing.T) {
	dir := shortTempDirDaemon(t)
	// NArg：意外位置参数报错（不取锁、不建 state 布局）。
	err := CLI([]string{"--state", dir, "status"}, "cli-test")
	if err == nil || !strings.Contains(err.Error(), "不接受位置参数") {
		t.Fatalf("--state X status 应报错（此前静默起守护进程）：%v", err)
	}
	if _, serr := os.Stat(filepath.Join(dir, control.ControlSockName)); serr == nil {
		t.Fatal("分发报错路径不得留下守护进程痕迹")
	}
	// --help：exit 0（此前 flag: help requested + exit 1）。
	if err := CLI([]string{"--help"}, "cli-test"); err != nil {
		t.Fatalf("daemon --help 应正常退出：%v", err)
	}
	// host 子命令经 daemon.CLI 分发可用。
	if err := CLI([]string{"host", "list", "--state", dir}, "cli-test"); err == nil {
		t.Fatal("无 daemon 的 host list 应报错")
	}
}

func cleanHost(t *testing.T, sock string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := control.Dial(ctx, sock, control.FrontendInfo{Kind: "cli", Name: "test", Version: "0"})
	if err != nil {
		return
	}
	defer c.Close()
	raw, err := c.Request(ctx, control.OpHostList, nil)
	if err != nil {
		return
	}
	var list control.HostListResult
	if json.Unmarshal(raw, &list) != nil {
		return
	}
	for _, h := range list.Hosts {
		_, _ = c.Request(ctx, control.OpHostRemove, control.HostRemoveArgs{Host: h.ID})
	}
}
