package wtransport

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
)

func peerIDN(n byte) [32]byte {
	var id [32]byte
	id[0], id[31] = n, 0x5A
	return id
}

// 首次生成 → 落盘（0600）→ 第二次复用同一把身份。
func TestLoadOrCreateIdentityCreatesThenReuses(t *testing.T) {
	dir := t.TempDir()
	id1, src1, err := LoadOrCreateIdentity(dir, peerIDN(1))
	if err != nil || src1 != SourceCreated {
		t.Fatalf("首次：src=%s err=%v", src1, err)
	}
	path := filepath.Join(dir, MasterKeyFile)
	st, serr := os.Stat(path)
	if serr != nil {
		t.Fatalf("主密钥未落盘：%v", serr)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("主密钥权限 = %v，want 0600", st.Mode().Perm())
	}
	if st.Size() != masterKeyLen {
		t.Fatalf("主密钥长度 = %d，want %d", st.Size(), masterKeyLen)
	}
	tagPath := filepath.Join(dir, DevTagFile)
	tst, terr := os.Stat(tagPath)
	if terr != nil {
		t.Fatalf("设备标签未落盘：%v", terr)
	}
	if tst.Mode().Perm() != 0o600 || tst.Size() != 8 {
		t.Fatalf("设备标签属性异常：mode=%v size=%d", tst.Mode().Perm(), tst.Size())
	}

	id2, src2, err := LoadOrCreateIdentity(dir, peerIDN(1))
	if err != nil || src2 != SourceReused {
		t.Fatalf("第二次：src=%s err=%v", src2, err)
	}
	if id1.PublicKey() != id2.PublicKey() || id1.devTag != id2.devTag {
		t.Fatal("同设备同后端应复用同一身份与同一 devTag")
	}
	if id1.ShortPub() == "" || id1.ShortDev() == "" {
		t.Fatal("短指纹不应为空")
	}
}

// 同主密钥：不同后端 → 不同身份（跨出口不可关联）；不同主密钥（换设备）→ 不同身份。
func TestIdentityScopedPerBackendAndPerDevice(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	a1, _, err := LoadOrCreateIdentity(dirA, peerIDN(1))
	if err != nil {
		t.Fatal(err)
	}
	a2, _, err := LoadOrCreateIdentity(dirA, peerIDN(2))
	if err != nil {
		t.Fatal(err)
	}
	b1, _, err := LoadOrCreateIdentity(dirB, peerIDN(1))
	if err != nil {
		t.Fatal(err)
	}
	if a1.PublicKey() == a2.PublicKey() {
		t.Fatal("不同后端不得得到同一把身份（跨出口可关联）")
	}
	if a1.PublicKey() == b1.PublicKey() {
		t.Fatal("不同设备不得得到同一把身份")
	}
	// devTag 也要按设备隔离（换设备不撞表键）
	if a1.devTag == b1.devTag {
		t.Fatal("不同设备不得得到同一 devTag")
	}
}

// 损坏的主密钥：归档 → 重建（SourceRebuilt），身份换钥，但**设备标签保持不变**
// （出口才能走「同 devTag 换公钥」的原子替换，而不是多出一条新设备）。
func TestCorruptMasterArchivedAndRebuilt(t *testing.T) {
	dir := t.TempDir()
	good, _, err := LoadOrCreateIdentity(dir, peerIDN(3))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, MasterKeyFile)
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	rebuilt, src, err := LoadOrCreateIdentity(dir, peerIDN(3))
	if err != nil || src != SourceRebuilt {
		t.Fatalf("重建：src=%s err=%v", src, err)
	}
	if rebuilt.PublicKey() == good.PublicKey() {
		t.Fatal("损坏重建后应是一把新身份")
	}
	if rebuilt.devTag != good.devTag {
		t.Fatal("重建身份不得更换设备标签（否则出口会多一条记录）")
	}
	entries, _ := os.ReadDir(dir)
	archived := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), MasterKeyFile+".bad-") {
			archived = true
		}
	}
	if !archived {
		t.Fatalf("损坏文件应被归档：%v", entries)
	}
	// 重建后的身份要能复用
	again, src2, err := LoadOrCreateIdentity(dir, peerIDN(3))
	if err != nil || src2 != SourceReused || again.PublicKey() != rebuilt.PublicKey() {
		t.Fatalf("重建后复用失败：src=%s err=%v", src2, err)
	}
}

// 「重置本机身份」= 删 master.key：下一把身份是新的，但设备标签不变 ⇒ 出口 rotate 替换同一条记录。
// 这是设置页重置入口的契约（App 只删 master.key，不碰 devtag）。
func TestIdentityResetKeepsDevTag(t *testing.T) {
	dir := t.TempDir()
	before, _, err := LoadOrCreateIdentity(dir, peerIDN(6))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, MasterKeyFile)); err != nil {
		t.Fatal(err)
	}
	after, src, err := LoadOrCreateIdentity(dir, peerIDN(6))
	if err != nil || src != SourceCreated {
		t.Fatalf("重置后应重新生成：src=%s err=%v", src, err)
	}
	if after.PublicKey() == before.PublicKey() {
		t.Fatal("重置后应是新公钥")
	}
	if after.devTag != before.devTag {
		t.Fatal("重置后设备标签必须保持不变（出口按同设备轮换替换）")
	}
}

// 目录不可用：降级为临时身份（SourceEphemeral + 错误），不阻塞建连。
func TestUnwritableDirFallsBackToEphemeral(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(blocker, "identity") // 父路径是文件 ⇒ MkdirAll 必失败
	id, src, err := LoadOrCreateIdentity(dir, peerIDN(4))
	if src != SourceEphemeral {
		t.Fatalf("src=%s，want %s", src, SourceEphemeral)
	}
	if err == nil {
		t.Fatal("降级路径应返回错误供调用方打警告")
	}
	if id == nil || id.PublicKey() == [32]byte{} {
		t.Fatal("降级身份应可用（非零公钥）")
	}
}

// 并发加载（-race）：同目录同后端只应产生一把身份。
func TestConcurrentLoadOrCreateIdentity(t *testing.T) {
	dir := t.TempDir()
	const n = 8
	var wg sync.WaitGroup
	results := make([][32]byte, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			id, _, err := LoadOrCreateIdentity(dir, peerIDN(9))
			if err != nil {
				t.Errorf("并发加载失败：%v", err)
				return
			}
			results[k] = id.PublicKey()
		}(i)
	}
	wg.Wait()
	for i := 1; i < n; i++ {
		if results[i] != results[0] {
			t.Fatalf("并发下产生了不同身份：%x vs %x", results[0], results[i])
		}
	}
}

// 注册报文 v2：devTag 进载荷且可被出口验通（与 proto 的契约对齐）。
func TestIdentityRegCarriesDevTag(t *testing.T) {
	dir := t.TempDir()
	id, _, err := LoadOrCreateIdentity(dir, peerIDN(5))
	if err != nil {
		t.Fatal(err)
	}
	var secret [32]byte
	secret[0] = 0x42
	pkt := id.Reg(secret)
	if len(pkt) != 66 || string(pkt[:2]) != "H2" {
		t.Fatalf("注册报文形状不对：len=%d magic=%q", len(pkt), string(pkt[:2]))
	}
	pub, tag, verr := proto.VerifyReg(secret, pkt, time.Now(), 0)
	if verr != nil {
		t.Fatalf("自验失败：%v", verr)
	}
	if pub != id.PublicKey() || tag != id.devTag {
		t.Fatal("报文里的公钥/devTag 与身份不一致")
	}
}

// 赢家在 O_EXCL 创建之后"被冻结"（超过旧实现的 10×20ms 等待窗口）时，读者必须等锁、
// 拿到赢家写好的那把钥匙，而不是把半成品当"损坏"归档重建（review 复审复现的残留窗口：
// 手机 doze/内存压力下赢家完全可能停在这儿）。
func TestSlowWriterConvergesUnderIdentityLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, MasterKeyFile)

	unlock, ok := lockIdentityDir(dir)
	if !ok {
		t.Skip("本机 flock 不可用——降级路径由 waitForCompleteFile 兜底")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	master := make([]byte, masterKeyLen)
	if _, rerr := rand.Read(master); rerr != nil {
		t.Fatal(rerr)
	}
	var wantMaster [32]byte
	copy(wantMaster[:], master)

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		time.Sleep(600 * time.Millisecond) // 远超旧的 200ms 窗口
		if _, werr := f.Write(master); werr != nil {
			t.Error(werr)
		}
		_ = f.Sync()
		_ = f.Close()
		unlock() // 赢家写完才放锁
	}()

	id, _, err := LoadOrCreateIdentity(dir, peerIDN(9))
	if err != nil {
		t.Fatalf("加载失败：%v", err)
	}
	<-writerDone

	want, derr := deriveKey(wantMaster, peerIDN(9))
	if derr != nil {
		t.Fatal(derr)
	}
	if id.PublicKey() != want.PublicKey() {
		t.Fatalf("读者拿到的不是赢家的钥匙（身份分裂）：%x vs %x", id.PublicKey(), want.PublicKey())
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.Contains(e.Name(), ".bad-") {
			t.Fatalf("把仍在写入的文件当损坏归档了：%s", e.Name())
		}
	}
}
