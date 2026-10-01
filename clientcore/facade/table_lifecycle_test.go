package facade

// table_lifecycle_test.go — 表生命周期三登记项红绿用例（自 internal/daemon/
// registry_lifecycle_test.go 随迁，4a 任务 3.1——断言不动；缝随动：stopFunc/
// newSession 改 facade 包级注入缝、Registry→hostTable）：
//
//	B5 先落盘再 Start/换会话：落盘失败注入（新键零副作用、刷新内存保持旧 token
//	   且旧会话在跑；Remove 对称化——落盘失败 = 内存与会话均未动）；
//	B6 事件回调锁内拷 payload、锁外 emit（注入重入回调不死锁）；
//	B7 Stop() -1 三件事：用户面（同键刷新/Remove）拒绝 + events.log 恰一行；
//	   清理收工面（Close）记行后继续。
//
// 落盘失败注入 = state 目录转只读（saveRecordsLocked 的 MkdirAll 对已存在目录
// 恒成功、WriteFile 落 EACCES）；会话构造计数经 newSession 包级接缝。

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/hostsession"
)

// readOnly 让目录只读（落盘必败）。返回还原函数。
func readOnly(t *testing.T, dir string) func() {
	t.Helper()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
}

// countingSessions 覆写 newSession 为计数桩（不真起会话——B5 判据只看「是否构造」）。
func countingSessions(t *testing.T, r *hostTable) *int {
	t.Helper()
	n := 0
	orig := newSession
	newSession = func(cfg hostsession.Config, opts hostsession.Options) (*hostsession.Session, error) {
		n++
		return hostsession.NewSession(cfg, opts)
	}
	t.Cleanup(func() { newSession = orig })
	return &n
}

// TestB5NewKeyPersistFailZeroSideEffect 新键落盘失败 = 零副作用：内存未动、
// 无会话已起（旧实现先 Start 再落盘、失败后只删表不收会话 = 孤儿会话）。
func TestB5NewKeyPersistFailZeroSideEffect(t *testing.T) {
	dir := t.TempDir()
	r := openTestTable(t, dir, tableOptions{strict: true})
	n := countingSessions(t, r)

	restore := readOnly(t, dir)
	tokA, peerA := testToken(t, 11, "127.0.0.1:40011")
	if _, err := r.Add("甲", tokA); err == nil {
		t.Fatal("落盘失败应报错")
	}
	restore()

	if got := len(r.Hosts()); got != 0 {
		t.Fatalf("落盘失败后内存表应未动（表长 %d）", got)
	}
	if r.Session(peerA) != nil {
		t.Fatal("落盘失败不得有会话在册")
	}
	if *n != 0 {
		t.Fatalf("落盘失败不得构造会话（构造了 %d 次）——旧实现此处留孤儿会话", *n)
	}
	if _, err := os.Stat(filepath.Join(dir, hostsFileName)); !os.IsNotExist(err) {
		t.Fatalf("落盘失败不应产生 hosts.json（stat err=%v）", err)
	}
	// 目录恢复后同一 token 可正常入表（零副作用 ⇒ 无残留状态）。
	if _, err := r.Add("甲", tokA); err != nil {
		t.Fatalf("恢复后 Add 应成功：%v", err)
	}
}

// TestB5RefreshPersistFailKeepsOld 同键刷新落盘失败：内存保持旧 token、旧会话
// 照跑（指针不变）、不构造新会话（旧实现 Stop→改内存→Start→save：丢旧会话、
// 内存留新 token、死表风险）。
func TestB5RefreshPersistFailKeepsOld(t *testing.T) {
	dir := t.TempDir()
	r := openTestTable(t, dir, tableOptions{strict: true})
	n := countingSessions(t, r)

	tokA, peerA := testToken(t, 12, "127.0.0.1:40012")
	if _, err := r.Add("甲", tokA); err != nil {
		t.Fatal(err)
	}
	oldSess := r.Session(peerA)
	if oldSess == nil {
		t.Fatal("前置：A 会话应在位")
	}
	built := *n

	restore := readOnly(t, dir)
	tokA2, _ := testToken(t, 12, "127.0.0.1:40052") // 同 peerID 新 token
	if _, err := r.Add("甲", tokA2); err == nil {
		t.Fatal("刷新落盘失败应报错")
	}
	restore()

	recs := r.Hosts()
	if len(recs) != 1 || recs[0].Token != tokA {
		t.Fatalf("内存应保持旧 token（实得 %d 条，token 换新 = B5 红路）", len(recs))
	}
	if got := r.Session(peerA); got != oldSess {
		t.Fatal("落盘失败时旧会话应照跑（会话对象被换 = 旧实现丢会话路径）")
	}
	if *n != built {
		t.Fatalf("落盘失败不应构造新会话（%d → %d）", built, *n)
	}
	// 恢复后重试同 token：刷新成功（先落盘后换会话）。
	if rec, err := r.Add("甲", tokA2); err != nil || rec.Token != tokA2 {
		t.Fatalf("恢复后刷新应成功：%v", err)
	}
	if s := r.Session(peerA); s == nil || s == oldSess {
		t.Fatal("刷新成功后应换新会话对象")
	}
}

// TestB5RemovePersistFailKeepsEntry Remove 对称化：落盘失败 = 内存条目与会话
// 均未动（旧实现先 Stop 再删内存、落盘失败才报错 = 丢内存条目）。
func TestB5RemovePersistFailKeepsEntry(t *testing.T) {
	dir := t.TempDir()
	r := openTestTable(t, dir, tableOptions{strict: true})

	tokA, peerA := testToken(t, 13, "127.0.0.1:40013")
	if _, err := r.Add("甲", tokA); err != nil {
		t.Fatal(err)
	}
	oldSess := r.Session(peerA)

	restore := readOnly(t, dir)
	if err := r.Remove(peerA); err == nil {
		t.Fatal("Remove 落盘失败应报错")
	}
	restore()

	if got := len(r.Hosts()); got != 1 {
		t.Fatalf("落盘失败时内存条目应未动（表长 %d）", got)
	}
	if r.Session(peerA) != oldSess {
		t.Fatal("落盘失败时会话应未动（旧实现先停会话 = 红路）")
	}
	// 恢复后删除成功。
	if err := r.Remove(peerA); err != nil {
		t.Fatalf("恢复后 Remove 应成功：%v", err)
	}
	if len(r.Hosts()) != 0 || r.Session(peerA) != nil {
		t.Fatal("删除后表与会话应清空")
	}
}

// reentrantEvents 重入回调（B6 红路构造：锁内发射时回调重入 Hosts()/Sessions()
// 自死锁——锁外 emit 后可重入）。
type reentrantEvents struct {
	r    *hostTable
	mu   sync.Mutex
	fast []string // 重入成功的主机 id
}

func (e *reentrantEvents) HostAdded(id, name string, addedAt int64) {
	_ = e.r.Hosts() // 重入读表（旧实现：表锁已被 Add 持有 → 死锁）
	e.mu.Lock()
	e.fast = append(e.fast, id)
	e.mu.Unlock()
}

func (e *reentrantEvents) HostRemoved(id, reason string) {
	_ = e.r.Sessions() // 重入读会话集合（Remove 路径同守）
	e.mu.Lock()
	e.fast = append(e.fast, id)
	e.mu.Unlock()
}

func (e *reentrantEvents) HostStateChanged(id, from, to, reason string)        {}
func (e *reentrantEvents) HostLinkChanged(id, via, ep string, rttMs, at int64) {}

// TestB6ReentrantCallbackNoDeadlock 重入回调不死锁（有界等待：锁内发射 = 卡死
// 超时红；锁外 emit = 秒回绿）。
func TestB6ReentrantCallbackNoDeadlock(t *testing.T) {
	dir := t.TempDir()
	ev := &reentrantEvents{}
	r, err := openTable(dir, tableOptions{strict: true, events: ev})
	if err != nil {
		t.Fatal(err)
	}
	ev.r = r
	t.Cleanup(r.Close)

	tokA, peerA := testToken(t, 14, "127.0.0.1:40014")
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := r.Add("甲", tokA); err != nil {
			t.Errorf("Add：%v", err)
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Add 未在 3s 内返回——事件回调持锁发射 + 重入读表 = 死锁（B6 红路）")
	}
	// Remove 路径同守。
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		if err := r.Remove(peerA); err != nil {
			t.Errorf("Remove：%v", err)
		}
	}()
	select {
	case <-done2:
	case <-time.After(3 * time.Second):
		t.Fatal("Remove 未在 3s 内返回——B6 Remove 路径死锁")
	}
	ev.mu.Lock()
	defer ev.mu.Unlock()
	if len(ev.fast) != 2 {
		t.Fatalf("重入回调应两次都执行：%v", ev.fast)
	}
}

// TestB7RefreshRejectOnStopTimeout 刷新遇 Stop -1：拒绝该操作 + events.log 恰一行
// （磁盘或已含新 token、内存保持旧值——重试收敛）。
func TestB7RefreshRejectOnStopTimeout(t *testing.T) {
	dir := t.TempDir()
	var lines []string
	var mu sync.Mutex
	r, err := openTable(dir, tableOptions{
		strict: true,
		eventf: func(format string, args ...any) {
			mu.Lock()
			lines = append(lines, fmt.Sprintf(format, args...))
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)

	tokA, peerA := testToken(t, 15, "127.0.0.1:40015")
	if _, err := r.Add("甲", tokA); err != nil {
		t.Fatal(err)
	}
	oldSess := r.Session(peerA)

	origStop := stopFunc
	stopFunc = func(s *hostsession.Session) int { return -1 } // B7② 注入缝
	t.Cleanup(func() { stopFunc = origStop })

	tokA2, _ := testToken(t, 15, "127.0.0.1:40055")
	if _, err := r.Add("甲", tokA2); !errors.Is(err, errStopTimeout) {
		t.Fatalf("刷新遇 Stop -1 应拒绝（errStopTimeout），实得 %v", err)
	}
	mu.Lock()
	stops := 0
	for _, l := range lines {
		if strings.Contains(l, "停止超时") {
			stops++
		}
	}
	mu.Unlock()
	if stops != 1 {
		t.Fatalf("events.log 应恰一行停止超时记行（实得 %d）：%v", stops, lines)
	}
	// 内存保持旧 token、旧会话对象未动。
	recs := r.Hosts()
	if len(recs) != 1 || recs[0].Token != tokA {
		t.Fatal("拒绝后内存应保持旧 token")
	}
	if r.Session(peerA) != oldSess {
		t.Fatal("拒绝后旧会话对象应未动")
	}
	// 对象未换 ≠ 会话在跑——stopFunc 已返回 -1（真实语义 = Session.Stop 的
	// stopOnce 已触发、等待收尾超时），旧会话已进入垂死/收尾，该主机短暂离线属
	// 预期；本用例注入缝直接短路返回，真实 Stop 语义见 hostsession/service.go
	// 的 stopOnce 注释。落盘失败路径（上一用例）才是「会话完全未动」。
	// 磁盘或已含新 token（B5 先落盘语义——拒绝只回滚内存，磁盘收敛如实注记）：
	// 重试（stopFunc 恢复）后内存与磁盘一致。
	b, err := os.ReadFile(filepath.Join(dir, hostsFileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("注记：拒绝时磁盘 token 状态 = %s", map[bool]string{true: "已含新 token（按磁盘收敛）", false: "仍为旧 token"}[strings.Contains(string(b), tokA2)])
	stopFunc = origStop
	if rec, err := r.Add("甲", tokA2); err != nil || rec.Token != tokA2 {
		t.Fatalf("重试刷新应收敛到新 token：%v", err)
	}
	// 收尾：真收工（重试起的新会话不停会与 TempDir 清理竞争——identity 目录写入）。
	r.Close()
}

// TestB7RemoveRejectOnStopTimeout Remove 遇 Stop -1：拒绝 + events.log 恰一行、
// 条目仍在表。
func TestB7RemoveRejectOnStopTimeout(t *testing.T) {
	dir := t.TempDir()
	var lines []string
	var mu sync.Mutex
	r, err := openTable(dir, tableOptions{
		strict: true,
		eventf: func(format string, args ...any) {
			mu.Lock()
			lines = append(lines, fmt.Sprintf(format, args...))
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)

	tokA, peerA := testToken(t, 16, "127.0.0.1:40016")
	if _, err := r.Add("甲", tokA); err != nil {
		t.Fatal(err)
	}

	origStop := stopFunc
	stopFunc = func(s *hostsession.Session) int { return -1 }
	if err := r.Remove(peerA); !errors.Is(err, errStopTimeout) {
		t.Fatalf("Remove 遇 Stop -1 应拒绝，实得 %v", err)
	}
	mu.Lock()
	stops := 0
	for _, l := range lines {
		if strings.Contains(l, "停止超时") {
			stops++
		}
	}
	mu.Unlock()
	if stops != 1 {
		t.Fatalf("events.log 应恰一行（实得 %d）：%v", stops, lines)
	}
	if len(r.Hosts()) != 1 {
		t.Fatal("拒绝后条目应仍在表")
	}
	stopFunc = origStop
	if err := r.Remove(peerA); err != nil {
		t.Fatalf("重试 Remove 应收敛：%v", err)
	}
}

// TestB7CloseContinuesOnStopTimeout 清理收工面：Close 遇 -1 记行后继续（不绑架
// 注册表收工）。
func TestB7CloseContinuesOnStopTimeout(t *testing.T) {
	dir := t.TempDir()
	var lines []string
	var mu sync.Mutex
	r, err := openTable(dir, tableOptions{
		strict: true,
		eventf: func(format string, args ...any) {
			mu.Lock()
			lines = append(lines, fmt.Sprintf(format, args...))
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	origStop := stopFunc
	stopFunc = func(s *hostsession.Session) int { return -1 }
	defer func() { stopFunc = origStop }()

	var sesss []*hostsession.Session
	for _, pb := range []byte{17, 18} {
		tok, peer := testToken(t, pb, "127.0.0.1:40000")
		if _, err := r.Add(fmt.Sprintf("机%d", pb), tok); err != nil {
			t.Fatal(err)
		}
		if s := r.Session(peer); s != nil {
			sesss = append(sesss, s)
		}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Close() // 不返回错误、不挂等
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close 遇 -1 应记行后继续（挂死 = B7 清理面红路）")
	}
	// 记行数 = 主机数（每台恰一行）。
	mu.Lock()
	stops := 0
	for _, l := range lines {
		if strings.Contains(l, "停止超时") {
			stops++
		}
	}
	mu.Unlock()
	if stops != 2 {
		t.Fatalf("应每台恰一行停止超时记行（实得 %d）：%v", stops, lines)
	}
	if len(r.Hosts()) != 0 {
		t.Fatal("Close 后表应清空")
	}
	// 收尾：恢复真停步并逐台真停——注入 -1 时 Close 记行后继续但**不会真停会话**，
	// 在跑会话的 identity 写入会与 TempDir 清理竞争（CI 实测 unlinkat "directory
	// not empty"——2026-09-29 v0.10.0 tag 首跑）。
	stopFunc = origStop
	for _, s := range sesss {
		_ = s.Stop()
	}
}
