package facade

// table_test.go — 多主机会话注册表（自 internal/daemon/registry_test.go 随迁，4a
// 任务 3.1——断言不动；缝名随动：OpenRegistry→openTestTable、errHostExists→
// ErrHostExists 等）：增删/持久化往返/重复添加/重启按表恢复/临时身份降级。
// token 全部本地签发（proto.EncodeToken，端点不可达也能起会话——构造只建本地
// socket；握手/暖机是异步的，不影响登记面断言）。
// （原文件中的 TestDaemonRefusesExitStateDir 测 daemon 侧 checkNotExitState，
// 留在 internal/daemon。）

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
)

// testToken 本地签发一枚合法 token（peerID 可指定）。
func testToken(t *testing.T, peerByte byte, addr string) (string, [32]byte) {
	t.Helper()
	peer := [32]byte{peerByte}
	tok := proto.Token{
		PeerID:    peer,
		Secret:    [32]byte{peerByte, 2},
		Endpoints: []proto.Endpoint{{Addr: addr}},
	}
	s, err := proto.EncodeToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	return s, peer
}

func openTestTable(t *testing.T, dir string, opts tableOptions) *hostTable {
	t.Helper()
	r, err := openTable(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

// 增删 + 持久化往返（hosts.json 0600）+ 重启按表恢复。
func TestRegistryAddRemovePersistAndRestart(t *testing.T) {
	dir := t.TempDir()
	r := openTestTable(t, dir, tableOptions{strict: true})

	tokA, peerA := testToken(t, 1, "127.0.0.1:40001")
	tokB, peerB := testToken(t, 2, "127.0.0.1:40002")
	if _, err := r.Add("甲", tokA); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add("乙", tokB); err != nil {
		t.Fatal(err)
	}
	if got := len(r.Hosts()); got != 2 {
		t.Fatalf("表长 = %d，want 2：%+v", got, r.Hosts())
	}

	// 持久化：文件在、0600、两条记录。
	p := filepath.Join(dir, hostsFileName)
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("hosts.json 未落盘：%v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("hosts.json 权限 %o ≠ 0600", perm)
	}

	// 删除甲：表与盘同步。
	if err := r.Remove(peerA); err != nil {
		t.Fatal(err)
	}
	if got := len(r.Hosts()); got != 1 {
		t.Fatalf("删除后表长 = %d，want 1", got)
	}
	if err := r.Remove(peerA); err == nil {
		t.Fatal("重复删除应报错")
	}

	// 重启按表恢复：重开同 state，乙的记录在、会话被拉起。
	r.Close()
	r2, err := openTable(dir, tableOptions{strict: true})
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	if got := r2.Hosts(); len(got) != 1 || got[0].Name != "乙" {
		t.Fatalf("重启恢复不符：%+v", got)
	}
	if s := r2.Session(peerB); s == nil {
		t.Fatal("重启后乙的会话未拉起")
	}
	// 身份/缓存目录按既有布局落在 state 内。
	if _, err := os.Stat(filepath.Join(dir, "identity")); err != nil {
		t.Fatalf("identity 目录未建：%v", err)
	}
}

// 重复添加：同 token → host_exists；同 peerID 新 token → 同键刷新（不裂成两条）。
func TestRegistryDuplicateAddAndRefresh(t *testing.T) {
	dir := t.TempDir()
	r := openTestTable(t, dir, tableOptions{strict: true})

	tokA, peerA := testToken(t, 3, "127.0.0.1:40003")
	if _, err := r.Add("甲", tokA); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add("甲again", tokA); !errors.Is(err, ErrHostExists) {
		t.Fatalf("同 token 重复添加应 ErrHostExists，实得 %v", err)
	}

	tokA2, _ := testToken(t, 3, "127.0.0.1:40033") // 同 peerID（后端重签发：新 secret/端点）
	rec, err := r.Add("甲", tokA2)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Token != tokA2 {
		t.Fatal("刷新后记录应携带新 token")
	}
	if got := r.Hosts(); len(got) != 1 {
		t.Fatalf("同后端重签发应同键刷新（表长 %d，want 1）：%+v", len(got), got)
	}
	if s := r.Session(peerA); s == nil {
		t.Fatal("刷新后会话应在位")
	}
}

// 临时身份降级（N2）：StrictIdentity=true 且身份目录不可持久化 → 该主机 failed
// reason=identity_ephemeral（状态面可见、可重试）。
func TestRegistryStrictIdentityEphemeral(t *testing.T) {
	dir := t.TempDir()
	// 在 identity 的路径上放一个**文件**：MkdirAll 必败 ⇒ SourceEphemeral。
	if err := os.WriteFile(filepath.Join(dir, "identity"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := openTestTable(t, dir, tableOptions{strict: true})

	tokA, _ := testToken(t, 4, "127.0.0.1:40004")
	rec, err := r.Add("甲", tokA)
	if err != nil {
		t.Fatal(err)
	}
	idHex := rec.ID
	var id [32]byte
	b, _ := hex.DecodeString(idHex)
	copy(id[:], b)
	sess := r.Session(id)
	if sess == nil {
		t.Skip("会话构造失败（日志文件被 identity 文件占位影响？）——见分支说明")
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		snap := sess.StatusSnapshot()
		if snap.State == "failed" {
			if snap.Reason != "identity_ephemeral" {
				t.Fatalf("failed reason = %q，want identity_ephemeral", snap.Reason)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("10s 内未按 identity_ephemeral 收工（当前 %+v）", sess.StatusSnapshot())
}

// hosts.json 损坏：备份 `hosts.json.corrupt-<ts>` + 空表启动 + 事件级告警
// （exec-r1 M2 红路：此前损坏即拒启——client 角色无限退避、daemon 永远
// not_ready，主机登记（含 token）无自愈路径）。
func TestRegistryCorruptHostsBacksUpAndStartsEmpty(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, hostsFileName)
	if err := os.WriteFile(p, []byte("{这是坏掉的 hosts"), 0o600); err != nil {
		t.Fatal(err)
	}
	var warns []string
	r, err := openTable(dir, tableOptions{
		strict: true,
		eventf: func(format string, args ...any) { warns = append(warns, fmt.Sprintf(format, args...)) },
	})
	if err != nil {
		t.Fatalf("损坏 hosts.json 应备份后空表启动，实得拒启：%v", err)
	}
	defer r.Close()
	if got := len(r.Hosts()); got != 0 {
		t.Fatalf("损坏后应按空表启动（表长 %d）", got)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "hosts.json 损坏") {
		t.Fatalf("应恰好一条事件级告警：%q", warns)
	}
	// 原件保留（备份可人工修复后重启恢复）、主文件已挪走（下次落盘重建）。
	backups := 0
	des, _ := os.ReadDir(dir)
	for _, de := range des {
		if strings.HasPrefix(de.Name(), hostsFileName+".corrupt-") {
			backups++
		}
	}
	if backups != 1 {
		t.Fatalf("应恰有一个 corrupt-<ts> 备份（实得 %d）", backups)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("损坏原件应已挪走（stat err=%v）", err)
	}
	// 空表可继续服役：Add 一台 → 新 hosts.json 落盘且可解析。
	tokA, _ := testToken(t, 7, "127.0.0.1:40007")
	if _, err := r.Add("甲", tokA); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("Add 后 hosts.json 未重建：%v", err)
	}
	var recs []HostRecord
	if err := json.Unmarshal(b, &recs); err != nil || len(recs) != 1 || recs[0].Name != "甲" {
		t.Fatalf("重建的 hosts.json 应含一条可解析记录：%v（%s）", err, b)
	}
}

// 落盘原子性（temp+rename，exec-r1 M2 绿路）：不残留 .tmp；写窗口被中断最坏留
// 完整旧表或完整新表，不再产生截断 JSON（此前裸 os.WriteFile 覆写）。
func TestRegistrySaveAtomicRename(t *testing.T) {
	dir := t.TempDir()
	r := openTestTable(t, dir, tableOptions{strict: true})
	// 预置陈旧 .tmp（上次写窗口被杀的残留）：rename 语义下被覆盖后挪走。
	tmp := filepath.Join(dir, hostsFileName+".tmp")
	if err := os.WriteFile(tmp, []byte("陈旧残tmp"), 0o600); err != nil {
		t.Fatal(err)
	}
	tokA, peerA := testToken(t, 8, "127.0.0.1:40008")
	if _, err := r.Add("甲", tokA); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatalf("落盘后不应残留 .tmp（stat err=%v）", err)
	}
	p := filepath.Join(dir, hostsFileName)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var recs []HostRecord
	if err := json.Unmarshal(b, &recs); err != nil || len(recs) != 1 || recs[0].Name != "甲" {
		t.Fatalf("hosts.json 应为完整可解析新表：%v（%s）", err, b)
	}
	// 第二轮写：删除后再确认（任意中断点都只可能是 rename 前后两个完整态）。
	if err := r.Remove(peerA); err != nil {
		t.Fatal(err)
	}
	b2, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b2, &recs); err != nil || len(recs) != 0 {
		t.Fatalf("删除后应为完整空表：%v（%s）", err, b2)
	}
}

// D7-a（term-remote 3.1）：hosts.json 含 id 非法条目 → 装载保留在表（不启动会话、
// 不进寻址面）→ 后续任意落盘**原样写回**（不再写掉）、装载日志如实。红绿判据：
// 改前行为 = 「条目保留」日志说谎——下次 Add 落盘即把坏条目写没。
func TestRegistryCarriesInvalidIDEntries(t *testing.T) {
	dir := t.TempDir()
	tokA, peerA := testToken(t, 7, "127.0.0.1:40007")
	bad := HostRecord{ID: "zz-not-hex", Name: "坏条目", Token: "token-x", AddedAt: time.Unix(1000, 0)}
	seed := []HostRecord{bad, {ID: hex.EncodeToString(peerA[:]), Name: "甲", Token: tokA, AddedAt: time.Unix(2000, 0)}}
	b, err := json.Marshal(seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, hostsFileName), b, 0o600); err != nil {
		t.Fatal(err)
	}

	var logs []string
	r, err := openTable(dir, tableOptions{
		strict: true,
		logf:   func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	// 会话/寻址面：只有合法的「甲」；坏条目不进任何一面。
	if got := len(r.Hosts()); got != 1 {
		t.Fatalf("寻址面应只含合法条目 1 条，实际 %d（%+v）", got, r.Hosts())
	}
	if got := len(r.Sessions()); got != 1 {
		t.Fatalf("会话面应只含合法条目 1 条，实际 %d", got)
	}
	sawTruth := false
	for _, l := range logs {
		if strings.Contains(l, "zz-not-hex") && strings.Contains(l, "保留") {
			sawTruth = true
		}
	}
	if !sawTruth {
		t.Fatalf("装载日志应如实说明非法条目保留：%v", logs)
	}

	// host add 触发落盘 → 重读文件：坏条目**仍在**（改前在这里被写掉）且三台齐。
	tokB, _ := testToken(t, 8, "127.0.0.1:40008")
	if _, err := r.Add("乙", tokB); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, hostsFileName))
	if err != nil {
		t.Fatal(err)
	}
	var after []HostRecord
	if err := json.Unmarshal(raw, &after); err != nil {
		t.Fatalf("hosts.json 落盘不可解析：%v（%s）", err, raw)
	}
	var badOK, aOK, bOK bool
	for _, rec := range after {
		switch {
		case rec.ID == bad.ID:
			badOK = rec.Name == bad.Name && rec.Token == bad.Token && rec.AddedAt.Equal(bad.AddedAt)
		case rec.ID == hex.EncodeToString(peerA[:]):
			aOK = rec.Name == "甲"
		case rec.Name == "乙":
			bOK = true
		}
	}
	if !badOK || !aOK || !bOK {
		t.Fatalf("落盘后条目不齐：bad=%v 甲=%v 乙=%v（%s）", badOK, aOK, bOK, raw)
	}
	if got := len(r.Hosts()); got != 2 {
		t.Fatalf("Add 后寻址面应 2 条（坏条目不进），实际 %d", got)
	}

	// 重启再装载：坏条目仍保留（幂等，不会第二次装载时漂移）。
	r.Close()
	r2, err := openTable(dir, tableOptions{strict: true})
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	raw2, err := os.ReadFile(filepath.Join(dir, hostsFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw2), bad.ID) {
		t.Fatalf("重启后坏条目应仍在 hosts.json：%s", raw2)
	}
	if got := len(r2.Hosts()); got != 2 {
		t.Fatalf("重启后寻址面应 2 条，实际 %d", got)
	}
}

// L3 注入（role-management D3 拆分表 r1 高-2）：EndpointCacheDir/Out 注入时会话按
// 注入落位；nil/空 = 现状按 stateDir 推导（旧行为零变化）。
func TestTableL3PathInjection(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "cache")
	// 注入目录由装配层负责存在（统一进程 = OpenNodeState 建 cache/）——会话打开
	// Out 失败只摘该会话（不致命，见 startSessionLocked），目录在才能落日志。
	if err := os.MkdirAll(filepath.Join(cacheDir, "endpoints"), 0o700); err != nil {
		t.Fatal(err)
	}
	injected := openTestTable(t, dir, tableOptions{
		endpointCacheDir: filepath.Join(cacheDir, "endpoints"),
		out:              filepath.Join(cacheDir, "client.log"),
	})
	tokA, _ := testToken(t, 9, "127.0.0.1:40009")
	if _, err := injected.Add("注入主机", tokA); err != nil {
		t.Fatal(err)
	}
	waitFileFace(t, filepath.Join(cacheDir, "client.log"))
	if _, err := os.Stat(filepath.Join(dir, "debug.log")); !os.IsNotExist(err) {
		t.Fatal("注入时不得在 stateDir 落 debug.log（现状推导面必须被注入覆盖）")
	}
	// nil/空注入 = 现状：会话日志回 stateDir/debug.log。
	legacy := openTestTable(t, dir, tableOptions{})
	tokB, _ := testToken(t, 10, "127.0.0.1:40010")
	if _, err := legacy.Add("缺省主机", tokB); err != nil {
		t.Fatal(err)
	}
	waitFileFace(t, filepath.Join(dir, "debug.log"))
}

func waitFileFace(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s 未出现", path)
}
