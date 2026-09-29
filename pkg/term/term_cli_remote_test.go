//go:build !windows

// term_cli_remote_test.go — `--host` 远程模式的 pkg/term 侧单测（term-remote 1.1–1.4）：
// 假 RemoteTerm 注入（拨号缝参数解析/错误面/五命令 --host 分支）、三态终结文案、
// --file --host 组合拒绝。daemon 控制面侧（真 control 服务器 + streamConn 适配器）
// 的端到端在 internal/daemon/term_remote_test.go。
package term

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRemoteTerm 测试注入的假远程缝：记录 Resolve/Dial 收到的参数；Dial 返回直连
// 到测试 term 服务 UDS 的连接（协议零改动经缝原样承载的最小可测代理——端到端
// 经隧道由 daemon 侧测试覆盖）。
type fakeRemoteTerm struct {
	mu           sync.Mutex
	stateSeen    []string // Resolve/Dial 收到的 stateDir
	resolved     []string // Resolve 收到的 ref
	dialed       []string // Dial 收到的 hexID
	resolveErr   error
	dialErr      error
	ids          map[string]string // ref -> hexID（缺省：ref 自映射）
	sockPath     string            // Dial 实际拨的 UDS（测试 term 服务）
	ctxDeadlines []time.Duration   // Dial ctx 的剩余预算（--timeout 透传断言）
}

func (f *fakeRemoteTerm) ResolveHostRef(ctx context.Context, stateDir, ref string) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stateSeen = append(f.stateSeen, stateDir)
	f.resolved = append(f.resolved, ref)
	if f.resolveErr != nil {
		return "", "", f.resolveErr
	}
	id := ref
	if f.ids != nil {
		if v, ok := f.ids[ref]; ok {
			id = v
		}
	}
	return id, ref, nil
}

func (f *fakeRemoteTerm) DialTerm(ctx context.Context, stateDir, hexID string) (io.ReadWriteCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stateSeen = append(f.stateSeen, stateDir)
	f.dialed = append(f.dialed, hexID)
	if dl, ok := ctx.Deadline(); ok {
		f.ctxDeadlines = append(f.ctxDeadlines, time.Until(dl))
	}
	if f.dialErr != nil {
		return nil, f.dialErr
	}
	var d net.Dialer
	return d.DialContext(ctx, "unix", f.sockPath)
}

func (f *fakeRemoteTerm) calls() (resolved, dialed []string, stateSeen []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.resolved...), append([]string{}, f.dialed...), append([]string{}, f.stateSeen...)
}

// fakeRemoteFor 起一套测试 term 服务并包好假缝（ref -> hex 全 64 位形状）。
func fakeRemoteFor(t *testing.T) (*fakeRemoteTerm, net.Listener, string) {
	t.Helper()
	_, ln, dir := startTestTermUDS(t)
	f := &fakeRemoteTerm{sockPath: filepath.Join(dir, "term.sock")}
	return f, ln, dir
}

// ---- 五命令的 --host 分支（1.1/1.2 判据：参数解析与错误面） ----

func TestCLIListHostViaFakeRemote(t *testing.T) {
	f, ln, _ := fakeRemoteFor(t)
	_, _, _, _ = attachTerm(t, ln, "cli-r1", true, 100, 30)

	// --host + 显式 --state（= daemon state 指代，透传给缝）。
	if err := cliList([]string{"--host", "mac", "--state", "/tmp/daemon-state"}, f); err != nil {
		t.Fatalf("远程 list：%v", err)
	}
	resolved, dialed, stateSeen := f.calls()
	if len(resolved) != 1 || resolved[0] != "mac" {
		t.Fatalf("应解析 ref=mac：%v", resolved)
	}
	if len(dialed) != 1 || !strings.HasPrefix(dialed[0], "mac") {
		t.Fatalf("应经缝拨号：%v", dialed)
	}
	if len(stateSeen) == 0 || stateSeen[0] != "/tmp/daemon-state" {
		t.Fatalf("--host 模式 --state 应透传 daemon state 指代：%v", stateSeen)
	}

	// 不带 --state：stateDir 透传空串（= daemon 侧默认 ~/.config/homeway/daemon）。
	if err := cliList([]string{"--host", "mac"}, f); err != nil {
		t.Fatalf("远程 list（默认 state）：%v", err)
	}
	_, _, stateSeen = f.calls()
	if got := stateSeen[len(stateSeen)-1]; got != "" {
		t.Fatalf("无 --state 时远程模式应透传空串（daemon 侧默认）：%q", got)
	}

	// --host 解析失败原样上抛（寻址错误面 = resolveHostTarget 文案）。
	f.resolveErr = errors.New("主机 \"nope\" 不存在（homeway host list 查看在表主机）")
	err := cliList([]string{"--host", "nope"}, f)
	if err == nil || !strings.Contains(err.Error(), "不存在") {
		t.Fatalf("解析失败应上抛可行动错误：%v", err)
	}
	f.resolveErr = nil
}

func TestCLINewDeleteHostViaFakeRemote(t *testing.T) {
	f, ln, _ := fakeRemoteFor(t)

	if err := cliNew([]string{"-d", "ci-r1", "--host", "mac"}, f); err != nil {
		t.Fatalf("远程 new -d：%v", err)
	}
	if _, ok := listSession(listTerm(t, ln), "ci-r1"); !ok {
		t.Fatal("远程 new -d 后会话应在列表")
	}
	_, dialed, _ := f.calls()
	if len(dialed) != 1 {
		t.Fatalf("new -d 应经缝拨号一次：%v", dialed)
	}

	if err := cliDelete([]string{"ci-r1", "--host", "mac"}, f); err != nil {
		t.Fatalf("远程 delete：%v", err)
	}
	waitSessionGone(t, ln, "ci-r1") // KILL 回包先于 teardown（见 helper 注释）
}

func TestCLIAttachHostArgsParse(t *testing.T) {
	// attach 全跑要 TTY（真机判据 6.1）——这里锁参数解析与 --host 透传形状。
	o, err := parseAttachArgs(expandFlagEq([]string{"dev1", "--host", "mac", "--timeout", "3s"}))
	if err != nil {
		t.Fatal(err)
	}
	if o.hostRef != "mac" || o.timeout != 3*time.Second || o.name != "dev1" {
		t.Fatalf("attach --host/--timeout 解析不符：%+v", o)
	}
	// --host 值缺失/空串就地报错。
	if _, err := parseAttachArgs([]string{"--host"}); err == nil || !strings.Contains(err.Error(), "缺参数") {
		t.Fatalf("--host 缺值应报错：%v", err)
	}
	if _, err := parseAttachArgs([]string{"--host", " "}); err == nil || !strings.Contains(err.Error(), "--host 需要") {
		t.Fatalf("--host 空串应报错：%v", err)
	}
	// --timeout 非法就地报错。
	if _, err := parseAttachArgs([]string{"--timeout", "abc"}); err == nil || !strings.Contains(err.Error(), "不是合法时长") {
		t.Fatalf("--timeout 非法应报错：%v", err)
	}
	// list/new/delete/explain 同款（各抽一态）。
	if _, err := parseNewArgs([]string{"--host", "mac"}); err != nil {
		t.Fatalf("new --host：%v", err)
	}
	if _, err := parseExplainArgs([]string{"s1", "--host", "mac", "--timeout", "1500ms"}); err != nil {
		t.Fatalf("explain --host：%v", err)
	}
	// timeout 缺省补默认 10s / stateDir 留空（newTermTarget 决策）；本地缺省补
	// DefaultStateDir（现状语义）。
	tgt := newTermTarget(&fakeRemoteTerm{}, "", "mac", 0)
	if tgt.timeout != defaultRemoteTimeout || tgt.stateDir != "" {
		t.Fatalf("远程缺省：timeout 应 10s、stateDir 留空（daemon 侧默认）：%+v", tgt)
	}
	lt := newTermTarget(nil, "", "", 0)
	if lt.stateDir != DefaultStateDir() {
		t.Fatalf("本地缺省 stateDir：%q", lt.stateDir)
	}
}

// ---- explain 在线远程化（1.4）----

func TestCLIExplainOnlineHostViaFakeRemote(t *testing.T) {
	f, ln, _ := fakeRemoteFor(t)
	_, _, _, _ = attachTerm(t, ln, "cli-expl", true, 80, 24)

	// 远程在线 explain：EXPLAIN 帧经缝到达**真服务**（标准测试服务恒 HOMEWAY_TERM_DETECT=off，
	// 应答 = 服务端生成的 detect_off 错误帧——足以证明往返经缝原样承载；成功的完整
	// 评估往返 = 6.1 ④ 真机判据）。
	err := cliExplain([]string{"cli-expl", "--host", "mac"}, f)
	if err == nil || !strings.Contains(err.Error(), "detect_off") {
		t.Fatalf("远程 explain 应带回服务端应答（detect_off）：%v", err)
	}
	_, dialed, _ := f.calls()
	if len(dialed) != 1 {
		t.Fatalf("explain 应经缝拨号一次：%v", dialed)
	}
	// 与本地面同构：同一会话直接连 UDS 跑一遍，应答完全一致（零 wire 改动）。
	local, lerr := explainSession(explainOpts{session: "cli-expl", stateDir: filepath.Dir(f.sockPath)}, nil)
	if lerr == nil || lerr.Error() != err.Error() {
		t.Fatalf("远程应答应与本地面同构：远程 %v / 本地 %v（out=%+v）", err, lerr, local)
	}
}

func TestCLIExplainFileHostComboRejected(t *testing.T) {
	// --file 是本地面：与 --host 组合就地报可行动错误（r1 P1-6 的排除面）。
	err := cliExplain([]string{"--file", "/tmp/screen.txt", "--agent", "claude", "--host", "mac"}, nil)
	if err == nil || !strings.Contains(err.Error(), "--file 是本地面") {
		t.Fatalf("--file --host 组合应报可行动错误：%v", err)
	}
	if !strings.Contains(err.Error(), "--host") {
		t.Fatalf("错误应给出远程替代路径：%v", err)
	}
}

// ---- 远程流终结三态文案（1.3，design D5 表）----

func TestRemoteEndMessage(t *testing.T) {
	cases := []struct {
		reason string
		want   string
	}{
		{RemoteEndGone, "仍在目标主机运行"},
		{RemoteEndGone, "重新 attach"},
		{RemoteEndClosed, "也可能是本端长时间停止读取"},
		{RemoteEndClosed, "出口侧慢腿自治收尾"},
		{RemoteEndConn, "与守护进程的连接断开"},
		{RemoteEndConn, "重新执行命令"},
	}
	for _, c := range cases {
		got := remoteEndMessage("s1", c.reason)
		if !strings.Contains(got, c.want) {
			t.Fatalf("remoteEndMessage(%q) 缺 %q：%q", c.reason, c.want, got)
		}
	}
	// RemoteEndError：errors.Is io.EOF + errors.As 取 Reason。
	re := &RemoteEndError{Reason: RemoteEndGone}
	if !errors.Is(re, io.EOF) {
		t.Fatal("RemoteEndError 应 errors.Is io.EOF")
	}
	var as *RemoteEndError
	if !errors.As(error(re), &as) || as.Reason != RemoteEndGone {
		t.Fatal("errors.As 应可取 Reason")
	}
}
