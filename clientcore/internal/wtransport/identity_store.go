package wtransport

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// 设备身份存储（openspec/changes/device-identity-persist）：
// 一台设备一份主密钥，按后端（token 里的静态公钥 peerID）派生一把**稳定**的 WG 身份。
//
//	master            = 32B 随机（<dir>/master.key，0600；目录 0700；永不外传）
//	identity(backend) = HKDF-SHA256(master, info="tier/dev-id/v1" ‖ peerID(32B), 32B)
//	devTag            = 8B 随机（<dir>/devtag，0600）—— **独立于主密钥持久化**
//
// 为什么 devTag 要独立成文件：设备标签是出口设备表的键，它必须在**身份轮换**（用户「重置本机身份」
// 删掉 master.key、或主密钥损坏重建）时保持不变 —— 出口才能走「同 devTag 换公钥」的原子替换路径
// （一条记录被替换，条目数不变）。若 devTag 也跟着换，重置会变成"多出一台新设备"，
// 与 spec「同设备身份轮换」相悖。
//
// 为什么不能从 token 派生：token 是共享凭证 —— 两台手机同 token ⇒ 同私钥 ⇒ 出口视作同一个 peer，
// WG endpoint 互相抢（现在唯一不会发生的事故，必须继续不发生）。身份必须每设备独立，
// 但对同一后端保持稳定；换 token（secret 轮换/端点变化）不换身份，换后端才换身份
// （不同后端看到不同公钥 ⇒ 跨出口不可关联）。
//
// 健壮性（对应 spec「身份存储的健壮性与降级」）：
//   - 创建用 O_CREATE|O_EXCL 原子落盘；读到损坏/长度非法/全零 ⇒ 归档为 master.key.bad-<ts> 后重建；
//   - 目录不可写 ⇒ 降级为本次会话的临时身份（SourceEphemeral + 返回错误供调用方打警告），
//     绝不因身份存储失败拒绝建连；
//   - 私钥/主密钥只在本文件路径读写，绝不进日志与诊断报告（调用方只应使用 ShortPub/ShortDev）。
type IdentitySource string

const (
	SourceCreated    IdentitySource = "created"     // 首次生成并落盘
	SourceReused     IdentitySource = "reused"      // 复用既有主密钥
	SourceRebuilt    IdentitySource = "rebuilt"     // 既有文件损坏 → 归档后重建
	SourceTagDerived IdentitySource = "tag-derived" // 设备标签文件不可用 → 退化为从主密钥派生（打警告）
	SourceEphemeral  IdentitySource = "ephemeral"   // 目录不可用 → 本次临时身份（降级）
)

const (
	MasterKeyFile = "master.key"
	DevTagFile    = "devtag"
	masterKeyLen  = 32
	devIDLabel    = "tier/dev-id/v1"
	devTagLabel   = "tier/dev-tag/v1"
	// identityLockFile：身份目录的跨进程串行锁（review 复审定稿；见 lockIdentityDir）。
	identityLockFile = "identity.lock"
)

// LoadOrCreateIdentity 取本设备对 peerID（后端静态公钥）的稳定身份。
//
// 返回的 IdentitySource 供日志区分「新建/复用/重建/降级」；err 非空且 src==SourceEphemeral 时
// 表示存储不可用（调用方打警告后照常建连）。
func LoadOrCreateIdentity(dir string, peerID [32]byte) (*Identity, IdentitySource, error) {
	// 跨进程串行化（review 复审）：主密钥与设备标签的"首次创建"必须整段互斥——
	// 否则并发首启（扩展进程的隧道会话 vs App 进程的服务会话）可能各建各的，
	// 出口看到的是两台设备 / 一次身份轮换。详见 lockIdentityDir。
	if unlock, ok := lockIdentityDir(dir); ok {
		defer unlock()
	}
	master, src, err := loadOrCreateMaster(dir)
	if err != nil {
		id, gerr := NewIdentity()
		if gerr != nil {
			return nil, "", fmt.Errorf("identity: 存储不可用（%v）且临时身份生成失败：%w", err, gerr)
		}
		return id, SourceEphemeral, err
	}
	tag, terr := loadOrCreateDevTag(dir)
	if terr != nil {
		// 设备标签文件不可用（目录只读且标签文件缺失等）：退化为从主密钥派生 ——
		// 同一台设备仍然稳定（重连不换标签），但**重置身份会换标签**（出口会多一条记录）。
		tag, err = deriveDevTag(master)
		if err != nil {
			return nil, "", err
		}
		src = SourceTagDerived
	}
	key, err := deriveKey(master, peerID)
	if err != nil {
		return nil, "", err
	}
	return newIdentityFromKey(key, tag), src, nil
}

// loadOrCreateMaster 读主密钥；缺失则创建、损坏则归档重建。
func loadOrCreateMaster(dir string) ([32]byte, IdentitySource, error) {
	var out [32]byte
	if dir == "" {
		return out, "", errors.New("identity: 未配置身份目录")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return out, "", fmt.Errorf("identity: 建目录 %s: %w", dir, err)
	}
	path := filepath.Join(dir, MasterKeyFile)

	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(b) == masterKeyLen && !allZero(b) {
			copy(out[:], b)
			return out, SourceReused, nil
		}
		// 「已存在但长度不足/全零」：先按**写入未完成**处理。持锁的正常路径下读不到
		// 半成品（见 lockIdentityDir）；这里兜的是两类例外：拿不到锁的降级路径，
		// 以及旧版本/崩溃留下的残缺文件——有界重试而不是立刻归档重建。
		if b2, ok := waitForCompleteFile(path, masterKeyLen); ok {
			copy(out[:], b2)
			return out, SourceReused, nil
		}
		arch := fmt.Sprintf("%s.bad-%d", path, time.Now().Unix())
		if rerr := os.Rename(path, arch); rerr != nil {
			return out, "", fmt.Errorf("identity: 归档损坏文件 %s: %w", path, rerr)
		}
		nb, cerr := createRandomFileUnderLock(path, masterKeyLen)
		if cerr != nil {
			return out, "", cerr
		}
		copy(out[:], nb)
		return out, SourceRebuilt, nil
	case !errors.Is(err, os.ErrNotExist):
		return out, "", fmt.Errorf("identity: 读 %s: %w", path, err)
	}

	if b, cerr := createRandomFileUnderLock(path, masterKeyLen); cerr != nil {
		// 输家（EEXIST）：等赢家写完并**用赢家的钥匙**（收敛，review #20——
		// 旧实现把「赢家还在写」当损坏归档重建，两代各拿一把 ⇒ 身份分裂）。
		if b2, ok := waitForCompleteFile(path, masterKeyLen); ok {
			copy(out[:], b2)
			return out, SourceReused, nil
		}
		return out, "", cerr
	} else {
		copy(out[:], b)
	}
	return out, SourceCreated, nil
}

// lockIdentityDir：身份目录上的跨进程排他锁（flock）。
//
// 为什么需要它（review 复审把 #20 的残留窗口从根上关掉）：此前并发首启靠"有界等待
// （10×20ms）+ 复用赢家"的**启发式**收敛——赢家若在 O_EXCL 创建之后被系统冻结/调度
// 延迟超过 200ms（手机 doze、内存压力下完全可能），读者仍会把它的半成品当"损坏"归档
// 重建，两代会话各拿一把钥匙 ⇒ 身份分裂（出口侧表现为同设备身份轮换，会顶掉另一条
// 在线会话的 peer）。锁把整段"读-或-建"变成互斥临界区，这类窗口就不存在了。
//
// flock 随 fd 关闭/进程退出由内核自动释放，崩溃不留死锁。目录不可用或文件系统不支持
// flock 时返回 (nil,false)，调用方照旧走原有的等待/复用兜底（不因为拿不到锁而拒绝服务）。
//
// 平台实现拆分（host-registry-daemon 1.1，r1 A3）：unix 侧 flock 见
// identity_store_unix.go；非 unix 平台降级为无锁（identity_store_other.go）——
// windows 桩门（GOOS=windows CGO_ENABLED=0 go build ./clientcore/internal/...）
// 依赖本文件不引 unix.Flock。

// waitForCompleteFile：等一个「看起来还在写入」的文件变完整（10×20ms 有界）。
// 返回 false = 超时仍是残缺（这才算真损坏，调用方走归档重建）。
func waitForCompleteFile(path string, wantLen int) ([]byte, bool) {
	for i := 0; i < 10; i++ {
		time.Sleep(20 * time.Millisecond)
		if b, err := os.ReadFile(path); err == nil && len(b) == wantLen && !allZero(b) {
			return b, true
		}
	}
	return nil, false
}

// loadOrCreateDevTag 读设备标签；缺失则创建、损坏则归档重建（与主密钥同目录、同权限）。
func loadOrCreateDevTag(dir string) (proto.DevTag, error) {
	var out proto.DevTag
	path := filepath.Join(dir, DevTagFile)
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(b) == len(out) && !allZero(b) {
			copy(out[:], b)
			return out, nil
		}
		arch := fmt.Sprintf("%s.bad-%d", path, time.Now().Unix())
		if rerr := os.Rename(path, arch); rerr != nil {
			return out, fmt.Errorf("identity: 归档损坏设备标签 %s: %w", path, rerr)
		}
		nb, cerr := createRandomFileUnderLock(path, len(out))
		if cerr != nil {
			return out, cerr
		}
		copy(out[:], nb)
		return out, nil
	case !errors.Is(err, os.ErrNotExist):
		return out, fmt.Errorf("identity: 读 %s: %w", path, err)
	}
	nb, cerr := createRandomFileUnderLock(path, len(out))
	if cerr != nil {
		if b2, ok := waitForCompleteFile(path, len(out)); ok {
			copy(out[:], b2)
			return out, nil
		}
		return out, cerr
	}
	copy(out[:], nb)
	return out, nil
}

// createRandomFileUnderLock：O_CREATE|O_EXCL 抢占**最终路径**。
//
// 收敛协议（与 lockIdentityDir 配套）：正常路径上调用方已持目录锁，所以这里的
// O_EXCL 只可能撞上"旧版本/崩溃残留"；万一没拿到锁（降级路径），仍有第二道兜底：
//   - 赢家：OPEN 成功 → 写入 + fsync + close；
//   - 输家：EEXIST → waitForCompleteFile 等赢家写完，**读赢家的内容返回**（不是自己的）；
//   - 崩溃残留（等满仍不完整）：上层归档重建——这才算真损坏。
//
// 不采用 tmp+rename：rename 只保证磁盘上不出现半截文件，两个并发创建者各自 rename 后
// **各内存里仍是自己的钥匙**，身份照样分裂；"赢家权威 + 目录锁"才是收敛的关键。
//
// 跨进程成立（服务会话在 App 进程、隧道在扩展进程，同一沙箱目录）。
func createRandomFileUnderLock(path string, n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("identity: 生成随机材料: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err // EEXIST：调用方走等待-复用路径
	}
	if _, werr := f.Write(buf); werr != nil {
		f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("identity: 写 %s: %w", path, werr)
	}
	if serr := f.Sync(); serr != nil {
		f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("identity: sync %s: %w", path, serr)
	}
	if cerr := f.Close(); cerr != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("identity: close %s: %w", path, cerr)
	}
	return buf, nil
}

// deriveKey：master + 后端公钥 → 该后端的 WG 私钥（确定性、跨进程一致）。
func deriveKey(master [32]byte, peerID [32]byte) (wgtypes.Key, error) {
	raw, err := hkdf.Key(sha256.New, master[:], nil, devIDLabel+string(peerID[:]), 32)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("identity: 派生身份: %w", err)
	}
	k, err := wgtypes.NewKey(raw)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("identity: 构造私钥: %w", err)
	}
	return k, nil
}

// deriveDevTag：master → 设备标签（出口设备表的键；8B）。
func deriveDevTag(master [32]byte) (proto.DevTag, error) {
	var tag proto.DevTag
	raw, err := hkdf.Key(sha256.New, master[:], nil, devTagLabel, len(tag))
	if err != nil {
		return tag, fmt.Errorf("identity: 派生设备标签: %w", err)
	}
	copy(tag[:], raw)
	return tag, nil
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func shortTag(d proto.DevTag) string { return hex.EncodeToString(d[:4]) }

func shortBytes(b []byte) string { return hex.EncodeToString(b) }
