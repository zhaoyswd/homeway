package wtransport

import (
	"crypto/rand"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Identity：设备 WG 身份（wg-native-stack tasks 2.2 的换代，见 openspec/changes/device-identity-persist）。
//
// 生命周期**随设备**：断开重连、换网、重绑、自愈重建、进程重启都复用同一把密钥与同一个
// 设备标签 devTag（由 identity_store.go 从设备主密钥派生并落盘）。
//
// 为什么要持久化：从前「每世代一把临时密钥、不落盘」⇒ 每次重连都在出口设备表多占一条记录；
// 表满后按注册时间淘汰，长连的那台会被后续重连挤掉（2026-09-20 实测：A 长连 + B 重连 8 次 ⇒ A 被踢，
// 黑洞 2–4 分钟）。身份稳定后出口按 devTag 归并，一台设备只占一条记录。
type Identity struct {
	key    wgtypes.Key
	devTag proto.DevTag
}

// NewIdentity 生成临时身份（随机密钥 + 随机设备标签）。
// 只用于测试与「身份目录不可写」的降级路径——生产路径走 LoadOrCreateIdentity。
func NewIdentity() (*Identity, error) {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	var tag proto.DevTag
	if _, err := rand.Read(tag[:]); err != nil {
		return nil, err
	}
	return &Identity{key: k, devTag: tag}, nil
}

// newIdentityFromKey 用既有的持久化材料构造身份（identity store 的加载路径）。
func newIdentityFromKey(k wgtypes.Key, devTag proto.DevTag) *Identity {
	return &Identity{key: k, devTag: devTag}
}

// PublicKey 公钥（reg 报文载荷 / 后端设备登记）。
func (i *Identity) PublicKey() [32]byte {
	pub := i.key.PublicKey()
	var out [32]byte
	copy(out[:], pub[:])
	return out
}

// PrivateKey 供 glue 层配置 device（IpcSet private_key=）。
func (i *Identity) PrivateKey() wgtypes.Key { return i.key }

// Reg 生成带新鲜时间戳的注册报文（v2：公钥 + devTag + ts + HMAC）。
func (i *Identity) Reg(secret [32]byte) []byte {
	return proto.EncodeReg(secret, i.PublicKey(), i.devTag, time.Now())
}

// ShortDev / ShortPub：日志与诊断用的短指纹（4 字节 hex）。
func (i *Identity) ShortDev() string { return shortTag(i.devTag) }

func (i *Identity) ShortPub() string {
	pub := i.PublicKey()
	return shortBytes(pub[:4])
}
