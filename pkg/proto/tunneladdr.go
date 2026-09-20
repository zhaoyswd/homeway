package proto

import (
	"crypto/hmac"
	"crypto/sha256"
	"net/netip"
)

// 隧道地址派生（wg-native-stack tasks 3.7）。
//
// 客户端与服务端**各自独立算出同一个地址**，不需要额外往返、也不改 reg 报文格式：
//
//	tunnelIP = 100.64.<HMAC-SHA256(secret, "hw-tun" ‖ 客户端临时公钥)[:2] 映射>
//
// 为什么必须逐设备唯一：wireguard-go 的 allowedips 是一张全局前缀表，同一个 /32 只能属于
// 一个 peer。App 配置里的隧道地址（默认 10.126.126.2/24）每台设备都一样，直接拿来当
// allowed_ip 会让多设备互相覆盖 ⇒ 后端→客户端方向的包会发给错的设备。
// 派生自「设备身份公钥」（每设备一把稳定密钥，见 internal/wtransport 的 identity store）
// ⇒ 每台设备天然不同，且与后端 allowed_ip 一一对应；身份不变 ⇒ 隧道地址不变。
//
// 地址空间取 100.64.0.1 – 100.64.255.254（避开网段地址 .0.0 与广播 .255.255）。
// 理论冲突概率（cap=32 并发设备）≈ 0.05%；后端检测到冲突会退到池分配并打警告，
// 但客户端仍用派生地址发包 ⇒ 该设备会不通；消解冲突要在手机上「重置本机身份」后重连
// （身份持久化之后重启不再换钥匙，见 pkg/servercore.DeviceTable.assignIPLocked）。
func DeriveTunnelIP(secret [32]byte, pubkey [32]byte) netip.Addr {
	h := hmac.New(sha256.New, secret[:])
	h.Write([]byte("hw-tun"))
	h.Write(pubkey[:])
	sum := h.Sum(nil)
	v := (uint32(sum[0])<<8|uint32(sum[1]))%(65535-1) + 1 // 1..65534
	return netip.AddrFrom4([4]byte{100, 64, byte(v >> 8), byte(v)})
}
