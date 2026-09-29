//go:build !unix

package wgcore

import (
	"errors"

	"golang.zx2c4.com/wireguard/tun"
)

// NewTunFromFD 的非 unix 桩（参照 pkg/egress/bind_other.go 先例，host-registry-daemon 1.1）：
// 裸 TUN fd 读写只在 unix 形态（生产 = OHOS）存在；本桩为 windows 桩门
// （GOOS=windows CGO_ENABLED=0 go build ./clientcore/internal/...）可编，运行期不可达
// （windows 无 VPN 扩展 fd 可递）。
func NewTunFromFD(fd, mtu int) (tun.Device, error) {
	return nil, errors.New("wgcore: 当前平台不支持 TUN 裸 fd")
}
