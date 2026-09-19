//go:build !darwin && !linux

package egress

import (
	"fmt"
	"net"
)

// bindSocketToIface：其余平台没有等价能力。**刻意报错**而不是静默放行 ——
// 「以为绑上了、其实走默认路由」在 TUN 型代理的机器上就是"隧道在、流量有去无回"，极难查。
func bindSocketToIface(fd int, ifi *net.Interface) error {
	if ifi == nil {
		return nil
	}
	return fmt.Errorf("当前平台不支持把 socket 绑到网卡 %q", ifi.Name)
}
