//go:build unix

package wtransport

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// lockIdentityDir 的 unix 实现（flock）；语义与降级口径见 identity_store.go 的注释。
// 拆分自该文件（host-registry-daemon 1.1，r1 A3）：windows 桩门要求本包不引 unix.Flock。
func lockIdentityDir(dir string) (func(), bool) {
	if dir == "" {
		return nil, false
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, false
	}
	lf, err := os.OpenFile(filepath.Join(dir, identityLockFile), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false
	}
	if err := unix.Flock(int(lf.Fd()), unix.LOCK_EX); err != nil {
		_ = lf.Close()
		return nil, false
	}
	return func() {
		_ = unix.Flock(int(lf.Fd()), unix.LOCK_UN)
		_ = lf.Close()
	}, true
}
