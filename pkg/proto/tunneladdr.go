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
// 派生自「每进程临时公钥」⇒ 每台设备天然不同，且与后端 allowed_ip 一一对应。
//
// 地址空间取 100.64.0.1 – 100.64.255.254（避开网段地址 .0.0 与广播 .255.255）。
// 理论冲突概率（cap=8 并发 peer）≈ 0.04%；后端检测到冲突会退到池分配并打警告，
// 重启其中一台设备即换新临时公钥、重新抽地址（见 internal/server.PeerTable.Register）。
func DeriveTunnelIP(secret [32]byte, pubkey [32]byte) netip.Addr {
	h := hmac.New(sha256.New, secret[:])
	h.Write([]byte("hw-tun"))
	h.Write(pubkey[:])
	sum := h.Sum(nil)
	v := (uint32(sum[0])<<8|uint32(sum[1]))%(65535-1) + 1 // 1..65534
	return netip.AddrFrom4([4]byte{100, 64, byte(v >> 8), byte(v)})
}
