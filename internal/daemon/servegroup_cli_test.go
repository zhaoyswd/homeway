package daemon

// servegroup_cli_test.go — role-management tasks 3.2/3.3 判据：serve/relay 命令组
// 对真统一进程（assembleUnified）全动词跑通——幂等矩阵 / 生命周期语义表 / token
// 双路径 / --stdin / 提示口径 / D8a 推算对拍。spawn 面的判据在 spawn_cli_test.go。

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/internal/nodeconfig"
)

// startUnifiedForGroup 起一个真统一进程（serve 按需、relay 关）并等 serve 实际
// 监听口落盘。返回 (dir, proc)。
func startUnifiedForGroup(t *testing.T, serveEnabled bool) (string, *unifiedProc) {
	t.Helper()
	dir := shortStateDirUnified(t)
	c := safeUnifiedCfg(freeUDPUnified(t))
	c.Serve.Enabled = serveEnabled
	if err := nodeconfig.Save(nodeconfig.Path(dir), c); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	proc, err := assembleUnified(ctx, "group-test", dir, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proc.Close() })
	if serveEnabled {
		waitPortFile(t, filepath.Join(dir, "cache", "listen_port.txt"), c.Serve.Listen, 20*time.Second)
	}
	return dir, proc
}

// TestServeGroupLifecycleMatrix 生命周期语义表：start 幂等 / stop 幂等且不伤其它
// 角色 / restart 角色停时可行动错误 / config 期望态逐段落盘。
func TestServeGroupLifecycleMatrix(t *testing.T) {
	dir, proc := startUnifiedForGroup(t, true)
	var out bytes.Buffer

	// start 幂等：运行中再 start = 无动作。
	out.Reset()
	if err := ServeGroupCLI([]string{"start", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "已在运行（幂等") {
		t.Fatalf("running 时 start 应报幂等：\n%s", out.String())
	}

	// stop：立即应答 + config enabled=false + client/control 不动。
	out.Reset()
	if err := ServeGroupCLI([]string{"stop", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "停止已应答") {
		t.Fatalf("stop 应立即应答：\n%s", out.String())
	}
	// 提示口径（r1 中-10）：stop 是生命周期命令，输出不得含「不热更」提示（与纯配置
	// 写命令的「需 restart 生效」语义相反）。以「不热更」为标记——提示行统一带此前缀。
	if strings.Contains(out.String(), "不热更") {
		t.Fatalf("stop 不得打 restart 提示：\n%s", out.String())
	}
	waitRoleState(t, proc.sup, "serve", roleStateStopped, 20*time.Second)
	waitRoleState(t, proc.sup, "control", roleStateRunning, 5*time.Second)
	waitRoleState(t, proc.sup, "client", roleStateRunning, 5*time.Second)
	cfg, err := nodeconfig.Load(nodeconfig.Path(dir))
	if err != nil || cfg.Serve.Enabled {
		t.Fatalf("stop 后 config 期望态应 false：%v %+v", err, cfg.Serve)
	}

	// stop 幂等：已停再 stop = 已停。
	out.Reset()
	if err := ServeGroupCLI([]string{"stop", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "已停（幂等") {
		t.Fatalf("已停再 stop 应幂等：\n%s", out.String())
	}

	// restart 角色停时 = 可行动错误提示 serve start（r1 中-6）。
	out.Reset()
	err = ServeGroupCLI([]string{"restart", "--state", dir}, "t", &out)
	if err == nil || !strings.Contains(err.Error(), "先 homeway serve start") {
		t.Fatalf("角色停时 restart 应可行动错误：%v", err)
	}

	// status 混合态：进程在跑、角色未装配 → 期望停用（进程在跑）。
	out.Reset()
	if err := ServeGroupCLI([]string{"status", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "期望停用（进程在跑）") {
		t.Fatalf("混合态 status 应报期望停用（进程在跑）：\n%s", out.String())
	}

	// start（stopped → 装配，立即生效）。
	out.Reset()
	if err := ServeGroupCLI([]string{"start", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "已启动") {
		t.Fatalf("stopped 时 start 应装配：\n%s", out.String())
	}
	if strings.Contains(out.String(), "不热更") {
		t.Fatalf("start 不得打 restart 提示：\n%s", out.String())
	}
	waitRoleState(t, proc.sup, "serve", roleStateRunning, 20*time.Second)
	cfg, err = nodeconfig.Load(nodeconfig.Path(dir))
	if err != nil || !cfg.Serve.Enabled {
		t.Fatalf("start 后 config 期望态应 true：%v", err)
	}

	// restart 运行中：等收尾重建、期望态不变、端口稳定（配置口不退让）。
	port := cfg.Serve.Listen
	out.Reset()
	if err := ServeGroupCLI([]string{"restart", "--state", dir, "--timeout", "40s"}, "t", &out); err != nil {
		t.Fatal(err)
	}
	waitRoleState(t, proc.sup, "serve", roleStateRunning, 20*time.Second)
	waitPortFile(t, filepath.Join(dir, "cache", "listen_port.txt"), port, 20*time.Second)
	cfg, err = nodeconfig.Load(nodeconfig.Path(dir))
	if err != nil || !cfg.Serve.Enabled {
		t.Fatalf("restart 不改期望态：%v", err)
	}
}

// TestServeGroupStatusDegradedFaces 未跑降级面：进程未跑时读 config 报期望态。
func TestServeGroupStatusDegradedFaces(t *testing.T) {
	dir := shortStateDirUnified(t)
	c := safeUnifiedCfg(freeUDPUnified(t))
	c.Serve.Enabled = true
	c.Relay.Enabled = false
	if err := nodeconfig.Save(nodeconfig.Path(dir), c); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	before := spawnAttemptedForTest
	if err := ServeGroupCLI([]string{"status", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"期望启用（未运行）", "纯读不拉起"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("serve status 未跑面缺 %q：\n%s", want, out.String())
		}
	}
	if spawnAttemptedForTest != before {
		t.Fatal("纯读命令不得尝试拉起（status 未跑 = 读 config 降级）")
	}
	out.Reset()
	if err := RelayGroupCLI([]string{"status", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "期望停用") {
		t.Fatalf("relay status 未跑面：\n%s", out.String())
	}
	// --json 同面。
	out.Reset()
	if err := ServeGroupCLI([]string{"status", "--state", dir, "--json"}, "t", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"enabled":true`) || !strings.Contains(out.String(), "期望启用") {
		t.Fatalf("serve status --json 未跑面：%s", out.String())
	}
}

// TestServeGroupTokenDualPath spec 场景「token 双路径一致」：在跑段（控制面）与
// 停段（直读台账末行）输出同一 token。探测被关（safeUnifiedCfg）时首轮铸出要等
// 兜底窗（≈15s）——用例预算放宽；等台账出现追加行（末行 = 在用 token）后对拍。
func TestServeGroupTokenDualPath(t *testing.T) {
	dir, proc := startUnifiedForGroup(t, true)
	ledger := filepath.Join(dir, "serve", "tokens.jsonl")
	waitLedgerLines(t, ledger, 2, 25*time.Second) // 预热行 + 首轮追加行
	var out bytes.Buffer
	if err := ServeGroupCLI([]string{"token", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	runningOut := out.String()
	if !strings.Contains(runningOut, "hmw1") {
		t.Fatalf("在跑段应输出 hmw1 token：\n%s", runningOut)
	}
	// exec-r2 N1 接线级判据（真 roleOps → 控制面 wire → CLI 全链）：在跑稳态
	// （token 已铸出 = runtime 路径）必须走运行态真源、带端点行、且不得打
	// 「该 token 无端点」假告警——roleops.go runtime 分支删掉 Eps 回填即红。
	if !strings.Contains(runningOut, "来源：运行态真源") {
		t.Fatalf("在跑段应走运行态真源：\n%s", runningOut)
	}
	if !strings.Contains(runningOut, "端点：") {
		t.Fatalf("在跑段稳态应带端点行（runtime 分支回填 Eps）：\n%s", runningOut)
	}
	if strings.Contains(runningOut, "该 token 无端点") {
		t.Fatalf("在跑段稳态不得打无端点假告警（exec-r2 N1）：\n%s", runningOut)
	}

	// 停角色（进程在跑）→ token 的未跑列 = L2 台账末行（r1 中-6 混合态同款降级）。
	out.Reset()
	if err := ServeGroupCLI([]string{"stop", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	waitRoleState(t, proc.sup, "serve", roleStateStopped, 20*time.Second)
	out.Reset()
	if err := ServeGroupCLI([]string{"token", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	stoppedOut := out.String()
	if !tokenLinesEqual(runningOut, stoppedOut) {
		t.Fatalf("token 双路径不一致：\n在跑段：\n%s\n停段：\n%s", runningOut, stoppedOut)
	}
}

// tokenLinesEqual 比较两次 reveal 输出的 token 行（来源行允许不同——runtime/ledger）。
func tokenLinesEqual(a, b string) bool {
	la, lb := tokenLineOf(a), tokenLineOf(b)
	return la != "" && la == lb
}

func tokenLineOf(out string) string {
	for _, line := range strings.Split(out, "\n") {
		// printTokenReveal 的行首「serve token：/relay token：」用全角冒号。
		if strings.HasPrefix(line, "serve token：") || strings.HasPrefix(line, "relay token：") {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

func waitLedgerLines(t *testing.T, path string, n int, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil {
			cnt := 0
			for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
				if strings.TrimSpace(line) != "" {
					cnt++
				}
			}
			if cnt >= n {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("台账 %s 未在 %v 内出现 %d 行", path, d, n)
}

// TestServeGroupRelaySetAndDDNS relay set（--stdin 双入口）/clear 与 ddns 增删查 +
// 提示口径（纯配置写命令在进程在跑时打「需 restart 生效」）。
func TestServeGroupRelaySetAndDDNS(t *testing.T) {
	dir, _ := startUnifiedForGroup(t, false) // serve 停也行——提示只看进程在跑
	var out bytes.Buffer

	// 位置参数入口 + 形态校验（裸 IP:port 合法——省真 token）。
	tok := "203.0.113.7:41741"
	out.Reset()
	if err := ServeGroupCLI([]string{"relay", "set", tok, "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "已写入 config") || !strings.Contains(out.String(), "需 `homeway serve restart` 生效") {
		t.Fatalf("relay set 应写 config 并打 restart 提示：\n%s", out.String())
	}
	cfg, err := nodeconfig.Load(nodeconfig.Path(dir))
	if err != nil || cfg.Serve.Relay != tok {
		t.Fatalf("config serve.relay 应 = %s：%v %+v", tok, err, cfg.Serve)
	}

	// --stdin 入口（D12：缓解 shell history 落凭证）。
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdin := os.Stdin
	os.Stdin = r
	go func() { fmt.Fprintln(w, "203.0.113.8:41741"); w.Close() }()
	out.Reset()
	stdinErr := ServeGroupCLI([]string{"relay", "set", "--stdin", "--state", dir}, "t", &out)
	os.Stdin = oldStdin
	if stdinErr != nil {
		t.Fatal(stdinErr)
	}
	cfg, err = nodeconfig.Load(nodeconfig.Path(dir))
	if err != nil || cfg.Serve.Relay != "203.0.113.8:41741" {
		t.Fatalf("--stdin 读法应写入新值：%v %+v", err, cfg.Serve)
	}

	// 非法形态可行动报错（CLI 侧校验前置）。
	out.Reset()
	if err := ServeGroupCLI([]string{"relay", "set", "not a token", "--state", dir}, "t", &out); err == nil {
		t.Fatal("非法 token 应就地报错")
	}

	// clear。
	out.Reset()
	if err := ServeGroupCLI([]string{"relay", "clear", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	cfg, err = nodeconfig.Load(nodeconfig.Path(dir))
	if err != nil || cfg.Serve.Relay != "" {
		t.Fatalf("clear 后应为空：%v", err)
	}

	// ddns add / list / delete（多条目）。
	out.Reset()
	if err := ServeGroupCLI([]string{"ddns", "add", "home.example.com", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "需 `homeway serve restart` 生效") {
		t.Fatalf("ddns add 应打 restart 提示：\n%s", out.String())
	}
	if err := ServeGroupCLI([]string{"ddns", "add", "nat.example.com", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := ServeGroupCLI([]string{"ddns", "list", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "home.example.com") || !strings.Contains(out.String(), "nat.example.com") {
		t.Fatalf("ddns list 应含两条：\n%s", out.String())
	}
	// 重复 add 拒绝。
	if err := ServeGroupCLI([]string{"ddns", "add", "home.example.com", "--state", dir}, "t", &out); err == nil {
		t.Fatal("重复 ddns add 应拒绝")
	}
	out.Reset()
	if err := ServeGroupCLI([]string{"ddns", "delete", "home.example.com", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	cfg, err = nodeconfig.Load(nodeconfig.Path(dir))
	if err != nil || len(cfg.Serve.DDNS) != 1 || cfg.Serve.DDNS[0] != "nat.example.com" {
		t.Fatalf("delete 后剩一条：%v %+v", err, cfg.Serve.DDNS)
	}
}

// TestServeGroupRelaySetNotRunning 进程未跑：纯配置写不打 restart 提示（下次启动
// 即生效）。
func TestServeGroupRelaySetNotRunning(t *testing.T) {
	dir := shortStateDirUnified(t)
	if err := nodeconfig.Save(nodeconfig.Path(dir), safeUnifiedCfg(freeUDPUnified(t))); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := ServeGroupCLI([]string{"relay", "set", "203.0.113.7:41741", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "restart 生效") {
		t.Fatalf("未跑时 set 不打 restart 提示：\n%s", out.String())
	}
}

// TestServeGroupStartNotRunningNoSpawn 未跑 + --no-spawn = fail-fast 可行动错误
// （4.1 判据的组命令面）。
func TestServeGroupStartNotRunningNoSpawn(t *testing.T) {
	dir := shortStateDirUnified(t)
	if err := nodeconfig.Save(nodeconfig.Path(dir), safeUnifiedCfg(freeUDPUnified(t))); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := ServeGroupCLI([]string{"start", "--state", dir, "--no-spawn"}, "t", &out)
	if err == nil || !strings.Contains(err.Error(), "--no-spawn") || !strings.Contains(err.Error(), "先手动启动") {
		t.Fatalf("--no-spawn 未跑应可行动错误：%v", err)
	}
	// stop 未跑：直改 config（不拉起、不报错）。
	out.Reset()
	if err := ServeGroupCLI([]string{"stop", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	cfg, err := nodeconfig.Load(nodeconfig.Path(dir))
	if err != nil || cfg.Serve.Enabled {
		t.Fatalf("未跑 stop 应直改 config 为停用：%v", err)
	}
}

// TestRelayGroupLifecycle relay 组对称：start/stop/restart/status/token + D8a
// 固定 advertise 的跑/停对拍（逐字一致，r1 中-7）。
func TestRelayGroupLifecycle(t *testing.T) {
	dir, proc := startUnifiedForGroup(t, false)
	port := freeUDPUnified(t)
	adv := "203.0.113.9:" + strconv.Itoa(int(port))
	if err := nodeconfig.Update(nodeconfig.Path(dir), func(c *nodeconfig.Config) error {
		c.Relay.Enabled = false
		c.Relay.Listen = "127.0.0.1:" + strconv.Itoa(int(port))
		c.Relay.Advertise = adv
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	out.Reset()
	if err := RelayGroupCLI([]string{"start", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	waitRoleState(t, proc.sup, "relay", roleStateRunning, 20*time.Second)

	// status 运行面（监听行在 UDP bind 完成后出现——轮询）。
	okStatus := false
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !okStatus {
		out.Reset()
		if err := RelayGroupCLI([]string{"status", "--state", dir}, "t", &out); err != nil {
			t.Fatal(err)
		}
		okStatus = strings.Contains(out.String(), "运行中") && strings.Contains(out.String(), "监听") && strings.Contains(out.String(), "开放注册")
		if !okStatus {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if !okStatus {
		t.Fatalf("relay status 运行面不全：\n%s", out.String())
	}

	// token 在跑段（runtime；restart 后新轮 onReady 铸出前短暂走 derived——轮询到
	// runtime 源为止，两源同值由 D8a 对拍保证）。
	var runningTok string
	deadlineTok := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadlineTok) {
		out.Reset()
		if err := RelayGroupCLI([]string{"token", "--state", dir}, "t", &out); err != nil {
			t.Fatal(err)
		}
		runningTok = tokenLineOf(out.String())
		if strings.Contains(runningTok, "rl1") && strings.Contains(out.String(), "运行态真源") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(runningTok, "rl1") {
		t.Fatalf("relay token 在跑段应输出 rl1：%s", runningTok)
	}

	// restart 运行中。
	out.Reset()
	if err := RelayGroupCLI([]string{"restart", "--state", dir, "--timeout", "30s"}, "t", &out); err != nil {
		t.Fatal(err)
	}
	waitRoleState(t, proc.sup, "relay", roleStateRunning, 20*time.Second)

	// stop + 未跑推算对拍：固定 advertise 时跑/停两路径**逐字一致**（r1 中-7）。
	out.Reset()
	if err := RelayGroupCLI([]string{"stop", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	waitRoleState(t, proc.sup, "relay", roleStateStopped, 20*time.Second)
	out.Reset()
	if err := RelayGroupCLI([]string{"token", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	derivedTok := tokenLineOf(out.String())
	if runningTok != derivedTok {
		t.Fatalf("固定 advertise 的跑/停 token 对拍不一致：\n在跑：%s\n推算：%s", runningTok, derivedTok)
	}
	if !strings.Contains(out.String(), "离线推算") {
		t.Fatalf("停段应注明离线推算口径：\n%s", out.String())
	}
}

// TestRelayGroupTokenNoKey 未跑且无 relay.key：可行动错误（无从推算）。
func TestRelayGroupTokenNoKey(t *testing.T) {
	dir := shortStateDirUnified(t)
	if err := nodeconfig.Save(nodeconfig.Path(dir), nodeconfig.Default()); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := RelayGroupCLI([]string{"token", "--state", dir}, "t", &out)
	if err == nil || !strings.Contains(err.Error(), "relay.key 不存在") {
		t.Fatalf("无钥推算应可行动错误：%v", err)
	}
}

// TestPrintTokenRevealSourceNotes 来源注记区分（exec-r1 低-5）：ledger（进程未跑/
// 角色未装配）与 ledger-early（角色已装配、本轮 token 未铸出——启动早期窗口）两句
// 注记分开，不再合并成与实情不符的一句；未知来源原样透传。
func TestPrintTokenRevealSourceNotes(t *testing.T) {
	cases := []struct {
		source, want string
	}{
		{"runtime", "运行态真源（控制面）"},
		{"ledger", "台账末行（进程未跑/角色未装配"},
		{"ledger-early", "台账末行（角色已装配、本轮 token 未铸出"},
		{"derived", "离线推算（relay.key + config）"},
		{"自定义来源", "自定义来源"},
	}
	for _, tc := range cases {
		var out bytes.Buffer
		printTokenReveal(&out, "serve", "hmw1FAKE", tc.source, []string{"1.2.3.4:41641"})
		if !strings.Contains(out.String(), "来源："+tc.want) {
			t.Fatalf("source=%s 注记应含 %q：\n%s", tc.source, tc.want, out.String())
		}
	}
}

// TestWarnNoEndpoints 无端点 token 的可行动提示（exec-r1 低-5）：台账末行是
// endpoints=null 预热行时提示「首轮端点尚未铸出 + 稍后重试/看 events.log」；
// 有端点时不打提示。exec-r2 N1：按 Source 门控——runtime 真源的端点与 token
// 同快照，缺端点不得告警（在跑稳态假告警的接线兜底）。
func TestWarnNoEndpoints(t *testing.T) {
	cases := []struct {
		source string
		eps    []string
		want   bool // 是否应打提示行
	}{
		{"ledger", nil, true},                        // 台账预热行（预期场景）
		{"ledger-early", nil, true},                  // 启动早期窗口（预期场景）
		{"ledger", []string{"1.2.3.4:41641"}, false}, // 有端点不打
		{"runtime", nil, false},                      // N1：runtime 不告警
		{"runtime", []string{"1.2.3.4:41641（内网）"}, false},
	}
	for _, tc := range cases {
		var out bytes.Buffer
		warnNoEndpoints(&out, tc.source, tc.eps)
		if tc.want != strings.Contains(out.String(), "该 token 无端点") {
			t.Fatalf("source=%s eps=%v 提示应为 %v：\n%s", tc.source, tc.eps, tc.want, out.String())
		}
		if tc.want && !strings.Contains(out.String(), "events.log") {
			t.Fatalf("无端点提示应含 events.log 落点：\n%s", out.String())
		}
	}
}
