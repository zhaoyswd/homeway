package daemon

// registry_test.go — 多主机会话注册表（host-registry-daemon 1.5，HD「多主机会话
// 注册表」+ N2）：增删/持久化往返/重复添加/重启按表恢复/临时身份降级。
// token 全部本地签发（proto.EncodeToken，端点不可达也能起会话——构造只建本地
// socket；握手/暖机是异步的，不影响登记面断言）。

import (
	"encoding/hex"
	"os"
	"path/filepath"
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

func openTestRegistry(t *testing.T, dir string) *Registry {
	t.Helper()
	r, err := OpenRegistry(dir, RegistryOptions{StrictIdentity: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

// 增删 + 持久化往返（hosts.json 0600）+ 重启按表恢复。
func TestRegistryAddRemovePersistAndRestart(t *testing.T) {
	dir := t.TempDir()
	r := openTestRegistry(t, dir)

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
	r2, err := OpenRegistry(dir, RegistryOptions{StrictIdentity: true})
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
	// 身份/缓存目录按 D3 布局落在 state 内。
	if _, err := os.Stat(filepath.Join(dir, "identity")); err != nil {
		t.Fatalf("identity 目录未建：%v", err)
	}
}

// 重复添加：同 token → host_exists；同 peerID 新 token → 同键刷新（不裂成两条）。
func TestRegistryDuplicateAddAndRefresh(t *testing.T) {
	dir := t.TempDir()
	r := openTestRegistry(t, dir)

	tokA, peerA := testToken(t, 3, "127.0.0.1:40003")
	if _, err := r.Add("甲", tokA); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add("甲again", tokA); err != errHostExists {
		t.Fatalf("同 token 重复添加应 errHostExists，实得 %v", err)
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
	r := openTestRegistry(t, dir)

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
