package server

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
)

// 3.1 判据①：密钥重启不变（两次 OpenState 同目录读同一把钥）。
func TestStateKeyPersistence(t *testing.T) {
	dir := t.TempDir()
	s1, err := OpenState(dir)
	if err != nil {
		t.Fatal(err)
	}
	k1, err := s1.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	// 模拟重启：新实例、同目录
	s2, err := OpenState(dir)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := s2.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if k1 != k2 {
		t.Fatal("身份密钥跨实例变化——token 会全体作废")
	}
	// 权限收紧
	fi, err := os.Stat(dir + "/key.bin")
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key.bin 权限 %v", fi.Mode().Perm())
	}
}

// 3.1 判据②：issue → parse round-trip + secret 台账可回读。
func TestStateIssueTokenRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenState(dir)
	if err != nil {
		t.Fatal(err)
	}
	eps := []proto.Endpoint{
		{Addr: "192.0.2.12:41641"},
		{Addr: "example.net:41641"},
		{Addr: "1.2.3.4:4430", Relay: true},
	}
	tok, err := s.IssueToken(eps)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := proto.EncodeToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := proto.DecodeToken(enc)
	if err != nil {
		t.Fatalf("issue→parse round-trip 失败：%v", err)
	}
	if dec.PeerID != tok.PeerID || dec.Secret != tok.Secret || len(dec.Endpoints) != 3 {
		t.Fatalf("round-trip 字段不匹配：%+v", dec)
	}
	// PeerID 必须是身份公钥（与私钥对应）
	priv, _ := s.PrivateKey()
	pub := priv.PublicKey()
	var want [32]byte
	copy(want[:], pub[:])
	if tok.PeerID != want {
		t.Fatal("token PeerID 与身份公钥不符")
	}

	// 第二个 token secret 不同；台账两条都能回读
	tok2, _ := s.IssueToken(eps)
	if tok2.Secret == tok.Secret {
		t.Fatal("两次签发不应产生相同 secret")
	}
	secrets, err := s.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 2 {
		t.Fatalf("台账条数=%d", len(secrets))
	}
}

// ---- FIX-64：凭证 id / 吊销表 / 台账可读面 ----

// TestStateCredIDStable：凭证 id = secret 的确定派生（不落额外状态；老行无字段
// 也一致）——台账写入落字段与读取现算必须同值。
func TestStateCredIDStable(t *testing.T) {
	var sec [32]byte
	for i := range sec {
		sec[i] = byte(i)
	}
	id := credID(sec)
	if len(id) != 8 {
		t.Fatalf("id 形态（8 hex）：%q", id)
	}
	if id != credID(sec) {
		t.Fatal("同一 secret 的 id 必须稳定")
	}
	// 台账行落字段 = 现算值（Ledger 对老行现算的兜底路径见下）。
	dir := t.TempDir()
	st, err := OpenState(dir)
	if err != nil {
		t.Fatal(err)
	}
	tok, ierr := st.IssueToken(nil)
	if ierr != nil {
		t.Fatal(ierr)
	}
	led, lerr := st.Ledger()
	if lerr != nil {
		t.Fatal(lerr)
	}
	if len(led) != 1 || led[0].ID != credID(tok.Secret) {
		t.Fatalf("台账行的 id 应为 credID(secret)，got %+v", led)
	}
}

// TestStateRevokeFiltersSecrets：吊销后 Secrets() 不再返回该凭证（注册验证集的
// 唯一数据源）；吊销幂等；台账末行重铸给可行动错误（不回死凭证）。
func TestStateRevokeFiltersSecrets(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenState(dir)
	if err != nil {
		t.Fatal(err)
	}
	tok1, _ := st.IssueToken(nil)
	tok2, _ := st.IssueToken(nil)
	if s, _ := st.Secrets(); len(s) != 2 {
		t.Fatalf("吊销前应有 2 枚：%d", len(s))
	}
	already, rerr := st.Revoke(tok1.Secret, "leaked")
	if rerr != nil || already {
		t.Fatalf("首次吊销应成功且非幂等命中：already=%v err=%v", already, rerr)
	}
	if already, _ := st.Revoke(tok1.Secret, "again"); !already {
		t.Fatal("重复吊销应报 already（幂等无动作）")
	}
	secrets, err := st.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 1 || secrets[0] != tok2.Secret {
		t.Fatalf("已吊销凭证必须从验证集滤除，got %d 枚", len(secrets))
	}
	// 台账行仍在（append-only 纪律：吊销不改台账），状态标为已吊销。
	led, _ := st.Ledger()
	if len(led) != 2 || !led[0].Revoked || led[1].Revoked {
		t.Fatalf("台账应保留 2 行且只标第一行已吊销：%+v", led)
	}
	if led[0].Reason != "leaked" {
		t.Fatalf("吊销原因应进台账读面：%+v", led[0])
	}
	// AppendToken 拒写已吊销 secret（防「端点变化轮把死凭证写回末行」）。
	if aerr := st.AppendToken(tok1.Secret, nil); !errors.Is(aerr, ErrSecretRevoked) {
		t.Fatalf("已吊销 secret 的追加应被拒：%v", aerr)
	}
	// LastToken：末行（tok2）仍有效 → 正常返回；吊销末行 → 可行动错误。
	if _, ok, lerr := st.LastToken(); lerr != nil || !ok {
		t.Fatalf("末行有效时应正常 reveal：ok=%v err=%v", ok, lerr)
	}
	if _, rerr := st.Revoke(tok2.Secret, "also"); rerr != nil {
		t.Fatal(rerr)
	}
	if _, _, lerr := st.LastToken(); !errors.Is(lerr, ErrSecretRevoked) {
		t.Fatalf("末行已吊销时必须报 ErrSecretRevoked（MUST NOT 回死凭证），got %v", lerr)
	}
	// 全部吊销后 Secrets 空集 = 启动路径会铸新（serve.go 的分支）。
	if s, _ := st.Secrets(); len(s) != 0 {
		t.Fatalf("全吊销后应为空集，got %d", len(s))
	}
}

// TestRevokedFollowerFollowsFile：跟随读——吊销写盘后秒级（节流窗）生效；文件
// 消失沿用缓存（安全面宁可多拒）；nil 接收者恒 false（无吊销面）。
func TestRevokedFollowerFollowsFile(t *testing.T) {
	var f *revokedFollower
	if f.isRevoked([32]byte{1}) {
		t.Fatal("nil follower 恒 false")
	}
	dir := t.TempDir()
	st, _ := OpenState(dir)
	tok, _ := st.IssueToken(nil)
	fol := newRevokedFollower(st.revocationsPath())
	if fol.isRevoked(tok.Secret) {
		t.Fatal("尚未吊销")
	}
	if _, err := st.Revoke(tok.Secret, "t"); err != nil {
		t.Fatal(err)
	}
	// 节流窗内的判定读缓存（1s）——测试直接把 lastCheck 拨回去，等价于等过 1s。
	fol.mu.Lock()
	fol.lastCheck = time.Time{}
	fol.mu.Unlock()
	if !fol.isRevoked(tok.Secret) {
		t.Fatal("吊销写盘后应生效（节流窗过后）")
	}
	// 文件消失：沿用缓存（已吊销的判定不因文件暂缺而放行）。
	if err := os.Remove(st.revocationsPath()); err != nil {
		t.Fatal(err)
	}
	fol.mu.Lock()
	fol.lastCheck = time.Time{}
	fol.mu.Unlock()
	if !fol.isRevoked(tok.Secret) {
		t.Fatal("吊销表文件消失时应沿用缓存（安全面不放行）")
	}
}
