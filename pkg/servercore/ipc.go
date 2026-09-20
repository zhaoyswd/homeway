package servercore

import (
	"encoding/hex"
	"fmt"

	"golang.zx2c4.com/wireguard/device"
)

// ipcConfigurer：DeviceTable 表项 → WG device 的 UAPI（homewayd 与下游嵌入方共用）。
type ipcConfigurer struct{ dev *device.Device }

// NewIPCConfigurer 返回把设备表项落到 device 的 Configurer。
func NewIPCConfigurer(dev *device.Device) Configurer { return &ipcConfigurer{dev: dev} }

// AddPeer：写 peer 的准入材料（公钥 / PSK / allowed_ip）。
//
// ⚠️ 这里**刻意不写** `persistent_keepalive_interval`（WireGuard 的「出口每 N 秒保活」开关）。
// 本栈的保活分工是明确的：
//   - 手机侧每 60s 一条链路巡检探针（`PathProbe` 拨出口 1 号端口）是**唯一**的常态保活来源 ——
//     它同时刷新手机侧 NAT 映射、维持出口对手机直连地址的路径信任、驱动 WG rekey（作为数据发送方）；
//   - 出口侧保持沉默：它的可达性来自路由器 UPnP 静态映射，不需要靠心跳维持；出口发 keepalive
//     只会让手机每 25s 醒一次 radio（电池 + 流量），并对失联设备做无谓的握手重试。
//
// 历史：v0.2.3 之前在 PeerConfig 里有个 `Keepalive: 25` 字段，但它从未落到 UAPI ——
// 是个死字段（读代码的人会误以为出口在保活）。2026-09-20 随设备表换代删除，事实写在这里，
// 避免再被"复活"。如果将来要做"手机冻结期间也保持会话"，正确的位置是**手机侧**开 persistent
// keepalive（NAT 后的一侧），不是这里。
func (d *ipcConfigurer) AddPeer(pc PeerConfig) error {
	return d.dev.IpcSet(fmt.Sprintf(
		"public_key=%s\npreshared_key=%s\nallowed_ip=%s/32\n",
		hex.EncodeToString(pc.Pubkey[:]), hex.EncodeToString(pc.PSK[:]), pc.TunnelIP))
}

func (d *ipcConfigurer) RemovePeer(pub [32]byte) error {
	return d.dev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", hex.EncodeToString(pub[:])))
}
