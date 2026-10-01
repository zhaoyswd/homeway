package daemon

// carriers_cli_test.go — forward/socks/speedtest 三命令面的 CLI 级单测（3e
// §3.2–§3.4）：假 control 连接（可编程 Backend 桩 + 真控制面服务器/UDS/帧/JSON
// 全链，CLI 走完整握手）驱动参数/输出/退出码/文案判据；EADDRINUSE 冲突诊断、
// socks 值域与跨主机冲突文案（r1 低-12：断言含占用方主机名 ali 与 --listen 提示）、
// speedtest 轮流顺序/参数边界/busy/link_down 文案/--json 字段清单对拍（r2 附带②）、
// Ctrl-C 终止轮转（先 cancel 当前主机再退出）与显示口径换算（spec ST 既有数值）。

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/facade"
	"github.com/zhaoyswd/homeway/internal/control"
)

// ---------- 可编程承载面桩（嵌入 remoteTestBackend 补基础面） ----------

type carrierStubBackend struct {
	remoteTestBackend

	mu sync.Mutex
	// forward 桩：表 + 注入错误（port -> err，用于 EADDRINUSE 形态）。
	fwdRules map[uint16]control.ForwardAddArgs
	fwdFail  map[uint16]error
	// socks 桩：on 表 + 记忆。
	socksOn  map[string]uint16
	socksMem map[string]uint16
	// speedtest 桩：start 记账（顺序）、ack 注入、status 终态注入、cancel 记账。
	startOrder []string
	startAck   map[string]string // host -> "waiting"|"busy"
	startArgs  map[string]control.SpeedtestStartArgs
	termRes    map[string]*control.SpeedtestResultBrief // host -> 终态（nil = 永远 waiting）
	startedC   chan string                              // start 到达信号（Ctrl-C 用例同步）
	cancelC    chan string                              // cancel 到达信号（exec-r1 B2：同步等待判据）
	cancels    []string
	statusFail bool // status 恒失败形态（N3 用例：连续失败收尾须补发 cancel）
}

func newCarrierStub() *carrierStubBackend {
	return &carrierStubBackend{
		remoteTestBackend: remoteTestBackend{dialErr: map[string]error{}},
		fwdRules:          map[uint16]control.ForwardAddArgs{},
		fwdFail:           map[uint16]error{},
		socksOn:           map[string]uint16{},
		socksMem:          map[string]uint16{},
		startAck:          map[string]string{},
		startArgs:         map[string]control.SpeedtestStartArgs{},
		termRes:           map[string]*control.SpeedtestResultBrief{},
		startedC:          make(chan string, 16),
		cancelC:           make(chan string, 16),
	}
}

func (b *carrierStubBackend) ForwardAdd(a control.ForwardAddArgs) (control.ForwardAddResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err, ok := b.fwdFail[a.Listen]; ok {
		return control.ForwardAddResult{}, err // 守护侧监听失败（如 EADDRINUSE）形态
	}
	if _, taken := b.fwdRules[a.Listen]; taken {
		return control.ForwardAddResult{}, errors.New("监听端口已被占用")
	}
	if _, taken := b.socksOn[a.Host]; taken {
		// 同主机 socks 在同端口（桩简化：socks 占 1080 类）——由 socks 端口检查呈现
	}
	for h, p := range b.socksOn {
		if p == a.Listen {
			return control.ForwardAddResult{}, fmt.Errorf("监听端口已被 %s 的 socks 监听占用", h)
		}
	}
	b.fwdRules[a.Listen] = a
	return control.ForwardAddResult{Rule: control.ForwardRuleBrief{Host: a.Host, Listen: a.Listen,
		TargetIP: a.TargetIP, TargetPort: a.TargetPort, State: "listening"}}, nil
}

func (b *carrierStubBackend) ForwardRemove(a control.ForwardRemoveArgs) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.fwdRules[a.Listen]; !ok {
		return errors.New("forward 规则不存在")
	}
	delete(b.fwdRules, a.Listen)
	return nil
}

func (b *carrierStubBackend) ForwardList(host string) control.ForwardListResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := control.ForwardListResult{Forwards: []control.ForwardRuleBrief{}}
	for _, r := range b.fwdRules {
		if host != "" && r.Host != host {
			continue
		}
		out.Forwards = append(out.Forwards, control.ForwardRuleBrief{Host: r.Host, Listen: r.Listen,
			TargetIP: r.TargetIP, TargetPort: r.TargetPort, State: "listening", Conns: 2})
	}
	return out
}

func (b *carrierStubBackend) SocksOn(host string, listen uint16) (control.SocksOnResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	// exec-r1 B1「桩掩盖」整改：on 缺省的**记忆端口解析语义不在桩里复制**（此前桩自带
	// 解析，CLI 面测试反而掩盖了真实现的缺口）——桩只按「0 = 1080」回显；真语义的
	// 判据在 facade 层（TestSocksOnOffStatus / TestSocksOnDefaultMemoryWins）与 e2e
	//（TestCarriersE2ESocksOnDefaultMemory，真 Carriers 全链）。
	if listen == 0 {
		listen = 1080
	}
	if listen < 1024 {
		return control.SocksOnResult{}, errors.New("监听端口须在 1024–65535")
	}
	for _, r := range b.fwdRules {
		if r.Listen == listen {
			return control.SocksOnResult{}, errors.New("监听端口已被 forward 规则占用")
		}
	}
	for h, p := range b.socksOn {
		if h != host && p == listen {
			return control.SocksOnResult{}, errors.New("监听端口已被其它主机的 socks 监听占用")
		}
	}
	b.socksOn[host] = listen
	b.socksMem[host] = listen
	return control.SocksOnResult{Listen: listen}, nil
}

func (b *carrierStubBackend) SocksOff(host string) (control.SocksOffResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.socksOn, host)
	return control.SocksOffResult{Listen: b.socksMem[host]}, nil
}

func (b *carrierStubBackend) SocksStatus() control.SocksStatusResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := control.SocksStatusResult{Socks: []control.SocksBrief{}}
	for host, mem := range b.socksMem {
		on := false
		if _, ok := b.socksOn[host]; ok {
			on = true
		}
		out.Socks = append(out.Socks, control.SocksBrief{Host: host, On: on, Listen: mem, Conns: 3})
	}
	return out
}

func (b *carrierStubBackend) SpeedtestStart(a control.SpeedtestStartArgs) (control.SpeedtestStartAck, error) {
	b.mu.Lock()
	b.startOrder = append(b.startOrder, a.Host)
	b.startArgs[a.Host] = a
	ack := b.startAck[a.Host]
	b.mu.Unlock()
	b.startedC <- a.Host
	if ack == "" {
		ack = "waiting"
	}
	if ack == "busy" {
		return control.SpeedtestStartAck{Phase: "busy", Reason: "busy"}, nil
	}
	return control.SpeedtestStartAck{Phase: "waiting"}, nil
}

func (b *carrierStubBackend) SpeedtestStatus(host string) (control.SpeedtestStatusResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.statusFail {
		return control.SpeedtestStatusResult{}, errors.New("控制面抖动（桩注入）")
	}
	if res := b.termRes[host]; res != nil {
		return control.SpeedtestStatusResult{Host: host, Phase: "done", Result: res}, nil
	}
	return control.SpeedtestStatusResult{Host: host, Phase: "waiting", Waiting: true, WaitRemainMs: 42000}, nil
}

func (b *carrierStubBackend) SpeedtestCancel(host string) error {
	b.mu.Lock()
	b.cancels = append(b.cancels, host)
	// 取消后注入 cancelled 终态（真实 runner 同款：cancel → 终态可轮询）。
	b.termRes[host] = &control.SpeedtestResultBrief{OK: false, Reason: "cancelled"}
	b.mu.Unlock()
	select {
	case b.cancelC <- host: // exec-r1 B2：cancel 到达的同步信号（用例锁判据用）
	default:
	}
	return nil
}

// startCarrierCLIServer 起一套假 control 服务器（真 UDS + 帧全链），返回 state 目录。
func startCarrierCLIServer(t *testing.T, stub *carrierStubBackend) string {
	t.Helper()
	dir := shortTempDirDaemon(t)
	bus := facade.NewBus(facade.NewGeneration(), facade.BusConfig{})
	srv := control.NewServer(control.ServerConfig{ServerVersion: "stub-1.0", Bus: bus, Backend: stub, Logf: t.Logf})
	_, ln, err := control.ListenControl(dir)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close(); <-done })
	return dir
}

// stubHosts 桩表登记两台主机（ali/mac，带链路态标签）。
func stubHosts(t *testing.T, stub *carrierStubBackend) (ali, mac string) {
	t.Helper()
	ali = strings.Repeat("aa", 32)
	mac = strings.Repeat("bb", 32)
	stub.mu.Lock()
	stub.hosts = []control.HostState{
		{ID: ali, Name: "ali", State: "ready", Link: &control.HostLink{Via: "direct", Ep: "203.0.113.1:41641", RttMs: 12, At: 1}},
		{ID: mac, Name: "mac", State: "ready", Link: &control.HostLink{Via: "relay", Ep: "r:41741", RttMs: 44, At: 1}},
	}
	stub.mu.Unlock()
	return ali, mac
}

// ---------- forward CLI ----------

func TestForwardCLIAddListDelete(t *testing.T) {
	stub := newCarrierStub()
	ali, mac := stubHosts(t, stub)
	dir := startCarrierCLIServer(t, stub)
	var out bytes.Buffer

	// add 正常（名称形态）：建规则成功。
	out.Reset()
	if err := forwardCLI([]string{"add", "--host", "ali", "--listen", "8080", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "已建转发") || !strings.Contains(out.String(), "listening") {
		t.Fatalf("add 输出：%s", out.String())
	}
	// 寻址三形态同构：全长/短前缀对同一后端 → 同一条规则（同端口冲突）。
	for _, ref := range []string{ali, "aa"} {
		out.Reset()
		err := forwardCLI([]string{"add", "--host", ref, "--listen", "8080", "--state", dir}, "t", &out)
		if err == nil || !strings.Contains(err.Error(), "已被") {
			t.Fatalf("add %s 应撞同一条规则（三形态同构）：%v", ref, err)
		}
	}
	out.Reset()
	if err := forwardCLI([]string{"add", "--host", "ali", "--listen", "8080", "--state", dir}, "t", &out); err == nil {
		t.Fatal("同端口重复 add 应报错")
	} else if !strings.Contains(err.Error(), "8080 已被") || !strings.Contains(err.Error(), "ali 的 forward 规则") || !strings.Contains(err.Error(), "--listen 另选") {
		t.Fatalf("冲突文案应含占用方与另选提示：%s", err)
	}

	// 跨主机冲突（mac 抢 8080）：文案指明全局唯一。
	out.Reset()
	if err := forwardCLI([]string{"add", "--host", "mac", "--listen", "8080", "--state", dir}, "t", &out); err == nil || !strings.Contains(err.Error(), "全局唯一") {
		t.Fatalf("跨主机冲突文案应含全局唯一：%v", err)
	}

	// add 任意 IPv4 目标。
	out.Reset()
	if err := forwardCLI([]string{"add", "--host", "ali", "--listen", "5000", "--target", "192.168.3.5:5001", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "192.168.3.5:5001") {
		t.Fatalf("add 输出应含目标：%s", out.String())
	}
	// :P 形态（出口自己指定端口）。
	out.Reset()
	if err := forwardCLI([]string{"add", "--host", "ali", "--listen", "5001", "--target", ":9090", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "出口自己:9090") {
		t.Fatalf(":P 形态输出：%s", out.String())
	}
	// 目标形态非法。
	out.Reset()
	if err := forwardCLI([]string{"add", "--host", "ali", "--listen", "5002", "--target", "nottarget", "--state", dir}, "t", &out); err == nil {
		t.Fatal("非法 target 应报错")
	}

	// EADDRINUSE（守护外进程占用）：桩注入监听失败 + 表里查不到 + 本机真占用。
	occ, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occ.Close()
	port := occ.Addr().(*net.TCPAddr).Port
	stub.mu.Lock()
	stub.fwdFail[uint16(port)] = errors.New("listen tcp 127.0.0.1:xxxx: bind: address already in use")
	stub.mu.Unlock()
	out.Reset()
	err = forwardCLI([]string{"add", "--host", "ali", "--listen", fmt.Sprint(port), "--state", dir}, "t", &out)
	if err == nil || !strings.Contains(err.Error(), "守护进程外的本机进程占用") || !strings.Contains(err.Error(), "规则未入表") {
		t.Fatalf("EADDRINUSE 文案应含占用原因与不入表：%v", err)
	}
	stub.mu.Lock()
	delete(stub.fwdFail, uint16(port))
	stub.mu.Unlock()

	// list 表格 + --json 字段。
	out.Reset()
	if err := forwardCLI([]string{"list", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "8080") || !strings.Contains(out.String(), "listening") {
		t.Fatalf("list 表格：%s", out.String())
	}
	out.Reset()
	if err := forwardCLI([]string{"list", "--host", "mac", "--json", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	var arr []map[string]any
	if err := json.Unmarshal(out.Bytes(), &arr); err != nil {
		t.Fatal(err)
	}
	if len(arr) != 0 { // mac 名下无规则
		t.Fatalf("按 host 过滤应为空：%s", out.String())
	}
	out.Reset()
	if err := forwardCLI([]string{"list", "--json", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out.Bytes(), &arr); err != nil {
		t.Fatal(err)
	}
	if len(arr) < 3 {
		t.Fatalf("应有 ≥3 条规则：%s", out.String())
	}
	for _, key := range []string{"listen", "targetIp", "targetPort", "state", "err", "conns", "host", "name"} {
		if _, ok := arr[0][key]; !ok {
			t.Fatalf("--json 缺字段 %q：%s", key, out.String())
		}
	}

	// delete：正常 / 不存在 / 无主机。
	out.Reset()
	if err := forwardCLI([]string{"delete", "--host", "ali", "--listen", "8080", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "在世连接不强关") {
		t.Fatalf("delete 输出：%s", out.String())
	}
	out.Reset()
	if err := forwardCLI([]string{"delete", "--host", "ali", "--listen", "8080", "--state", dir}, "t", &out); err == nil || !strings.Contains(err.Error(), "规则不存在") {
		t.Fatalf("删不存在的规则应报错：%v", err)
	}
	out.Reset()
	if err := forwardCLI([]string{"delete", "--host", "nosuch", "--listen", "8080", "--state", dir}, "t", &out); err == nil || !strings.Contains(err.Error(), "不存在") {
		t.Fatalf("无主机应报错：%v", err)
	}
	_ = mac
}

// ---------- socks CLI ----------

func TestSocksCLIOnOffStatus(t *testing.T) {
	stub := newCarrierStub()
	_, _ = stubHosts(t, stub)
	dir := startCarrierCLIServer(t, stub)
	var out bytes.Buffer

	// on 缺省 1080。
	out.Reset()
	if err := socksCLI([]string{"on", "--host", "ali", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "127.0.0.1:1080") || !strings.Contains(out.String(), "远程解析") {
		t.Fatalf("on 输出：%s", out.String())
	}

	// 第二主机抢 1080：文案含占用方主机名 ali 与 --listen 提示（r1 低-12）。
	out.Reset()
	err := socksCLI([]string{"on", "--host", "mac", "--state", dir}, "t", &out)
	if err == nil || !strings.Contains(err.Error(), "1080 已被") || !strings.Contains(err.Error(), "ali 的 socks 监听") || !strings.Contains(err.Error(), "--listen 另选") {
		t.Fatalf("第二主机冲突文案（应含 ali 与 --listen）：%v", err)
	}
	// --listen 1081 则成功。
	out.Reset()
	if err := socksCLI([]string{"on", "--host", "mac", "--listen", "1081", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}

	// 值域拒绝（CLI 前置与守护侧两道）。
	out.Reset()
	if err := socksCLI([]string{"on", "--host", "mac", "--listen", "80", "--state", dir}, "t", &out); err == nil || !strings.Contains(err.Error(), "1024–65535") {
		t.Fatalf("CLI 值域拒绝：%v", err)
	}

	// off：记忆保留提示；status：off 但记住的端口（--json 暴露，拍板②）。
	out.Reset()
	if err := socksCLI([]string{"off", "--host", "ali", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "RST") || !strings.Contains(out.String(), "1080 记忆保留") {
		t.Fatalf("off 输出：%s", out.String())
	}
	out.Reset()
	if err := socksCLI([]string{"status", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "off") || !strings.Contains(out.String(), "1080") {
		t.Fatalf("status 表格应含 off+记忆端口：%s", out.String())
	}
	out.Reset()
	if err := socksCLI([]string{"status", "--json", "--state", dir}, "t", &out); err != nil {
		t.Fatal(err)
	}
	var arr []map[string]any
	if err := json.Unmarshal(out.Bytes(), &arr); err != nil {
		t.Fatal(err)
	}
	var aliEntry map[string]any
	for _, m := range arr {
		if m["name"] == "ali" {
			aliEntry = m
		}
	}
	if aliEntry == nil || aliEntry["on"] != false || aliEntry["listen"] != float64(1080) {
		t.Fatalf("--json 应暴露 off 但记住的 1080：%s", out.String())
	}
	if _, ok := aliEntry["via"]; !ok {
		t.Fatalf("--json 应含链路态 via/rttMs：%s", out.String())
	}
}

// ---------- speedtest CLI ----------

func TestSpeedtestCLIRotation(t *testing.T) {
	stub := newCarrierStub()
	ali, mac := stubHosts(t, stub)
	dir := startCarrierCLIServer(t, stub)
	var out, errOut bytes.Buffer

	// 两台终态成功：轮流顺序 ali→mac（daemon.status 次序）、预告、双口径输出。
	stub.termRes[ali] = &control.SpeedtestResultBrief{OK: true,
		DownBps: 8713812, UpBps: 3145728, UsageDown: 8314, UsageUp: 926, WallMs: 23400}
	stub.termRes[mac] = &control.SpeedtestResultBrief{OK: true,
		DownBps: 5242880, UpBps: 780432, UsageDown: 100, UsageUp: 20, WallMs: 23000}

	err := speedtestCLI([]string{"--state", dir}, "t", &out, &errOut)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut.String(), "将依次测 2 台") || !strings.Contains(errOut.String(), "ali、mac") {
		t.Fatalf("预告应含台数与名单：%s", errOut.String())
	}
	if !strings.Contains(out.String(), "↑3MB/s ↓8MB/s") {
		t.Fatalf("显示口径（上行在前）：%s", out.String())
	}
	if !strings.Contains(out.String(), "↑762KB/s ↓5MB/s") {
		t.Fatalf("第二台显示口径（KB 档）：%s", out.String())
	}
	if !strings.Contains(out.String(), "8713812B/s（69.71Mbps，8.31MB/s）") {
		t.Fatalf("精确值行（Mbps=×8/10⁶、MB/s=1024 进位）：%s", out.String())
	}
	stub.mu.Lock()
	order := append([]string(nil), stub.startOrder...)
	stub.mu.Unlock()
	if len(order) != 2 || order[0] != ali || order[1] != mac {
		t.Fatalf("轮流顺序应为 ali→mac：%v", order)
	}

	// --json 字段清单对拍（spec speedtest-cli「字段名冻结」）。
	out.Reset()
	errOut.Reset()
	if err := speedtestCLI([]string{"--json", "--state", dir}, "t", &out, &errOut); err != nil {
		t.Fatal(err)
	}
	var arr []map[string]any
	if err := json.Unmarshal(out.Bytes(), &arr); err != nil {
		t.Fatal(err)
	}
	if len(arr) != 2 {
		t.Fatalf("--json 应两台：%s", out.String())
	}
	for _, key := range []string{"host", "name", "ok", "downBps", "upBps", "usageDown", "usageUp", "wallMs", "via", "rttMs"} {
		if _, ok := arr[0][key]; !ok {
			t.Fatalf("--json 缺字段 %q：%s", key, out.String())
		}
	}
	if arr[0]["downBps"] != 8713812.0 || arr[0]["name"] != "ali" || arr[0]["via"] != "direct" || arr[0]["rttMs"] != float64(12) {
		t.Fatalf("--json 数值/冻结标签：%s", out.String())
	}

	// 混合结果：一台失败（link_down 文案）一台成功 → 退出码 0、失败台如实呈现。
	stub.mu.Lock()
	stub.termRes[mac] = &control.SpeedtestResultBrief{OK: false, Reason: "link_down", Msg: "链路未就绪"}
	stub.mu.Unlock()
	out.Reset()
	errOut.Reset()
	if err := speedtestCLI([]string{"--state", dir}, "t", &out, &errOut); err != nil {
		t.Fatalf("部分成功退出码应为 0：%v", err)
	}
	if !strings.Contains(out.String(), "链路未就绪") || !strings.Contains(out.String(), "link_down") {
		t.Fatalf("失败短因文案：%s", out.String())
	}

	// 全失败：退出码非零；busy 文案。
	stub.mu.Lock()
	stub.termRes[ali] = &control.SpeedtestResultBrief{OK: false, Reason: "busy"}
	stub.mu.Unlock()
	out.Reset()
	errOut.Reset()
	if err := speedtestCLI([]string{"--state", dir}, "t", &out, &errOut); err == nil || !strings.Contains(err.Error(), "全部主机测速失败") {
		t.Fatalf("全失败应非零退出：%v", err)
	}
	if !strings.Contains(out.String(), "并发满员") {
		t.Fatalf("busy 短因文案：%s", out.String())
	}

	// 参数边界（本地前置）：流数/窗口/预热越界即报错。
	for _, bad := range [][]string{
		{"--streams", "7"}, {"--streams", "0"}, {"--down", "16s"}, {"--warmup", "6s"},
	} {
		out.Reset()
		if err := speedtestCLI(append(bad, "--state", dir), "t", &out, &errOut); err == nil {
			t.Fatalf("%v 应越界报错", bad)
		}
	}

	// 空主机表：可行动错误。
	stub2 := newCarrierStub()
	dir2 := startCarrierCLIServer(t, stub2)
	out.Reset()
	if err := speedtestCLI([]string{"--state", dir2}, "t", &out, &errOut); err == nil || !strings.Contains(err.Error(), "主机表为空") {
		t.Fatalf("空表应可行动报错：%v", err)
	}
}

func TestSpeedtestCLICtrlCStopsRotation(t *testing.T) {
	stub := newCarrierStub()
	ali, _ := stubHosts(t, stub)
	dir := startCarrierCLIServer(t, stub)
	var out, errOut bytes.Buffer

	// ali 永远 waiting（无终态）；Ctrl-C 到达后 cancel 使其终态。
	done := make(chan error, 1)
	go func() {
		done <- speedtestCLI([]string{"--state", dir}, "t", &out, &errOut)
	}()
	// 等 CLI 对 ali 发出 start（signal.Notify 已在其前注册——此刻发 SIGINT 安全）。
	select {
	case h := <-stub.startedC:
		if h != ali {
			t.Fatalf("首台应为 ali：%s", h)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("start 未在窗口内到达")
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	// 「cancel 已到达」做成同步等待（exec-r1 B2：此前断言在 CLI 退出后立刻做，start
	// 在途窗口的竞态让用例 flaky 且锁不住判据；同步化后修完代码既确定通过、又能真正
	// 锁死「先 cancel 当前主机」）。
	select {
	case h := <-stub.cancelC:
		if h != ali {
			t.Fatalf("应先 cancel 当前主机 ali，got %s", h)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Ctrl-C 后未在窗口内发出 speedtest.cancel（start 在途窗口缺口的红路）")
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "Ctrl-C") {
			t.Fatalf("Ctrl-C 应非零退出并说明终止轮转：%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Ctrl-C 后 CLI 未在窗口内退出")
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if len(stub.startOrder) != 1 || stub.startOrder[0] != ali {
		t.Fatalf("Ctrl-C 后 mac 不应被测量：%v", stub.startOrder)
	}
	if len(stub.cancels) != 1 || stub.cancels[0] != ali {
		t.Fatalf("应先 cancel 当前主机 ali（恰一次）：%v", stub.cancels)
	}
}

// TestSpeedtestCLIStatusFailCancelsRun status 连续失败收尾补发 cancel（N3/exec-r2）：
// 「已 start 且未到终态 → best-effort cancel」——daemon 侧在跑的轮被清掉，用户立刻
// 重试不再撞 busy（修前该路径直接返回 control_error、无人取消，轮烧满预算）。
func TestSpeedtestCLIStatusFailCancelsRun(t *testing.T) {
	stub := newCarrierStub()
	ali, _ := stubHosts(t, stub)
	dir := startCarrierCLIServer(t, stub)
	stub.mu.Lock()
	stub.statusFail = true // start 可达、status 恒失败（8×250ms 窗后 control_error 收尾）
	stub.mu.Unlock()
	var out, errOut bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- speedtestCLI([]string{"--host", "ali", "--state", dir}, "t", &out, &errOut)
	}()
	select {
	case h := <-stub.cancelC:
		if h != ali {
			t.Fatalf("应 cancel ali，got %s", h)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("status 连续失败收尾未补发 speedtest.cancel（N3 红路）")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("全部失败应非零退出")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("CLI 未在窗口内退出")
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if len(stub.cancels) != 1 || stub.cancels[0] != ali {
		t.Fatalf("应恰一次 cancel ali：%v", stub.cancels)
	}
	if !strings.Contains(out.String(), "control_error") {
		t.Fatalf("应呈现 control_error 短因：%s", out.String())
	}
}

func TestSpeedtestWaitFlagThroughStartPayload(t *testing.T) {
	// --wait 经 start 载荷 waitMs 传给 runner（r1 中-3：start 立即返回 waiting）。
	stub := newCarrierStub()
	ali, _ := stubHosts(t, stub)
	dir := startCarrierCLIServer(t, stub)
	var out, errOut bytes.Buffer
	stub.mu.Lock()
	stub.termRes[ali] = &control.SpeedtestResultBrief{OK: false, Reason: "link_down", Msg: "预算耗尽"}
	stub.mu.Unlock()
	if err := speedtestCLI([]string{"--host", "ali", "--wait", "3s", "--state", dir}, "t", &out, &errOut); err == nil {
		t.Fatal("全失败非零退出")
	}
	stub.mu.Lock()
	a := stub.startArgs[ali]
	stub.mu.Unlock()
	if a.WaitMs != 3000 || a.Host != ali {
		t.Fatalf("start 载荷应含 waitMs=3000：%+v", a)
	}
}

// ---------- 共用面 ----------

func TestCarrierCLIsNoDaemonActionableError(t *testing.T) {
	dir := shortTempDirDaemon(t)
	cases := []struct {
		name string
		fn   func(args []string, version string, w io.Writer) error
		args []string
	}{
		// role-management 4.1：无 daemon = 按需拉起（单测注入缝 = 确定性「拉起失败」
		// 错误）；--no-spawn = 可行动错误（sock 路径 + 启动命令）。
		{"forward list", forwardCLI, []string{"list", "--state", dir}},
		{"socks status", socksCLI, []string{"status", "--state", dir}},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		err := tc.fn(tc.args, "t", &buf)
		if err == nil {
			t.Fatalf("%s：无 daemon 应报错", tc.name)
		}
		if !strings.Contains(err.Error(), "拉起统一进程失败") {
			t.Fatalf("%s：未跑应走按需拉起面（单测桩错误）：%s", tc.name, err)
		}
		var buf2 bytes.Buffer
		noSpawnArgs := append([]string{tc.args[0]}, append([]string{"--no-spawn"}, tc.args[1:]...)...)
		err2 := tc.fn(noSpawnArgs, "t", &buf2)
		if err2 == nil {
			t.Fatalf("%s：--no-spawn 应报错", tc.name)
		}
		for _, want := range []string{"--no-spawn", "control.sock", "先手动启动"} {
			if !strings.Contains(err2.Error(), want) {
				t.Fatalf("%s：--no-spawn 可行动错误缺 %q：%s", tc.name, want, err2)
			}
		}
	}
	var out, errOut bytes.Buffer
	if err := speedtestCLI([]string{"--host", "ali", "--state", dir}, "t", &out, &errOut); err == nil || !strings.Contains(err.Error(), "拉起统一进程失败") {
		t.Fatalf("speedtest 无 daemon 应走拉起面（单测桩）：%v", err)
	}
}

func TestDaemonCLIDispatchCarrierFaces(t *testing.T) {
	// role-management 3.4 起 daemon.CLI 分发面已退役（host/forward/socks/speedtest
	// 由 cmd/homeway 顶层名词直连各 CLI）——命令面的未知子命令/裸调/参数边界行为
	// 在各 CLI 函数上保持不变，这里直连断言。
	var out bytes.Buffer
	if err := forwardCLI([]string{"bogus"}, "t", &out); err == nil || !strings.Contains(err.Error(), "forward 不认识的子命令") {
		t.Fatalf("forward 未知子命令：%v", err)
	}
	if err := socksCLI([]string{}, "t", &out); err == nil || !strings.Contains(err.Error(), "socks 需要子命令") {
		t.Fatalf("socks 裸调可行动报错：%v", err)
	}
	var out2 bytes.Buffer
	if err := speedtestCLI([]string{"--streams", "9"}, "t", &out2, io.Discard); err == nil || !strings.Contains(err.Error(), "越界") {
		t.Fatalf("speedtest 参数边界（本地前置，不连 daemon）：%v", err)
	}
}

func TestHumanRateMobileScale(t *testing.T) {
	// spec speedtest「结果与口径」既有 Scenario 数值（手机口径 = CLI 显示口径）。
	cases := []struct {
		bps  float64
		want string
	}{
		{8713812, "8MB/s"},   // ST Scenario：8713812B/s → 8MB/s
		{3145728, "3MB/s"},   // ↑3MB/s
		{37748736, "36MB/s"}, // ↓36MB/s
		{780432, "762KB/s"},  // 不足 1MB/s 用 KB/s
		{5242880, "5MB/s"},   // ↓5MB/s
		{353280, "345KB/s"},  // ↓345KB/s
		{1048064, "1MB/s"},   // 1023.5KB 四舍五入进位到 1024KB → 归 MB 档
	}
	for _, c := range cases {
		if got := humanRate(c.bps); got != c.want {
			t.Fatalf("humanRate(%v) = %s，期望 %s", c.bps, got, c.want)
		}
	}
}

func TestCarrierOpErrUnknownOpSkew(t *testing.T) {
	// 旧守护（无 3e op）→ unknown_op →「代际过旧，请同批升级」可行动文案。
	err := carrierOpErr("speedtest.start", control.CodeError(facade.CodeUnknownOp))
	if err == nil || !strings.Contains(err.Error(), "unknown_op") || !strings.Contains(err.Error(), "代际过旧") || !strings.Contains(err.Error(), "同批升级") {
		t.Fatalf("unknown_op 文案：%v", err)
	}
}

// 确认 speedtest CLI usage 在裸调时不悬挂（--help 路径）。
func TestSpeedtestCLIHelp(t *testing.T) {
	stub := newCarrierStub()
	dir := startCarrierCLIServer(t, stub)
	var out, errOut bytes.Buffer
	if err := speedtestCLI([]string{"--help", "--state", dir}, "t", &out, &errOut); err != nil {
		t.Fatalf("--help 应正常：%v", err)
	}
	_ = filepath.Join(dir, "x")
}
