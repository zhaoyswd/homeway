//go:build !unix

package wtransport

// lockIdentityDir 的非 unix 降级：无目录锁（参照 pkg/egress/bind_other.go 先例，
// host-registry-daemon 1.1 / r1 A3）。生产面（OHOS/Linux/macOS）全走 unix 侧的
// flock；本桩只为 windows 桩门（GOOS=windows CGO_ENABLED=0 go build）可编。
// 无锁时调用方照旧走「有界等待 + 复用赢家」兜底（waitForCompleteFile），收敛性
// 弱于锁但可服务——与本函数 (nil,false) 的既有契约一致。
func lockIdentityDir(dir string) (func(), bool) {
	return nil, false
}
