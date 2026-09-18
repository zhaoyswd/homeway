package servercore

import (
	"encoding/hex"
	"fmt"

	"golang.zx2c4.com/wireguard/device"
)

// ipcConfigurer：PeerTable 表项 → WG device 的 UAPI（homewayd 与下游嵌入方共用）。
type ipcConfigurer struct{ dev *device.Device }

// NewIPCConfigurer 返回把 peer 表项落到 device 的 Configurer。
func NewIPCConfigurer(dev *device.Device) Configurer { return &ipcConfigurer{dev: dev} }

func (d *ipcConfigurer) AddPeer(pc PeerConfig) error {
	return d.dev.IpcSet(fmt.Sprintf(
		"public_key=%s\npreshared_key=%s\nallowed_ip=%s/32\n",
		hex.EncodeToString(pc.Pubkey[:]), hex.EncodeToString(pc.PSK[:]), pc.TunnelIP))
}

func (d *ipcConfigurer) RemovePeer(pub [32]byte) error {
	return d.dev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", hex.EncodeToString(pub[:])))
}
