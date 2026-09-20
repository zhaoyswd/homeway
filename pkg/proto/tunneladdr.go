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

// DeriveTunIP：同一设备的应用面（VpnConfig/TUN）地址——l3-exit-intercept 的
// 「第二派生地址」。为什么需要两个：hub 按目的地址分流（隧道 IP → 核心自连的
// B 栈，其余 → TUN），若 TUN 地址 == 隧道 IP，应用回程包会被当成核心自连的回包
// 送进 B 栈、应用永远收不到（端到端测试当场抓到）。两个地址都登记进后端 peer 的
// allowed_ip（ipc.AddPeer），派生确定性相同（secret + pubkey + 不同标签）。
func DeriveTunIP(secret [32]byte, pubkey [32]byte) netip.Addr {
	h := hmac.New(sha256.New, secret[:])
	h.Write([]byte("hw-app"))
	h.Write(pubkey[:])
	sum := h.Sum(nil)
	v := (uint32(sum[2])<<8|uint32(sum[3]))%(65535-1) + 1 // 1..65534
	ip := netip.AddrFrom4([4]byte{100, 64, byte(v >> 8), byte(v)})
	// 同设备两地址相等守卫（review #16）：TunIP == TunnelIP 会让 hub 的分流键失效
	//（应用回程被当核心自连送进 B 栈）。确定性扰动——再散列一次（标签后缀 ".2"），
	// **两端必须同规则**（手机核与出口都走本函数，规则收在 proto 里即保证一致）。
	if ip == DeriveTunnelIP(secret, pubkey) {
		h2 := hmac.New(sha256.New, secret[:])
		h2.Write([]byte("hw-app.2"))
		h2.Write(pubkey[:])
		sum2 := h2.Sum(nil)
		v2 := (uint32(sum2[2])<<8|uint32(sum2[3]))%(65535-1) + 1
		ip = netip.AddrFrom4([4]byte{100, 64, byte(v2 >> 8), byte(v2)})
	}
	return ip
}
