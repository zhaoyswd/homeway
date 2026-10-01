package server

import (
	"os"
	"sync"
	"time"
)

// revokedFollower：吊销表的**跟随读**（FIX-64）。DeviceTable 每次注册验证都问它
// 「这枚 secret 被吊销了吗」——文件级 mtime 节流（1s）+ 缓存，撤销写进
// revoked.jsonl 后秒级生效，**无需重启出口**（泄漏响应是安全面：不能等重启）。
//
// 与 dns.Upstreams 同款判读口径：stat 失败/mtime 未变沿用缓存；解析失败**不**
// 清空（保留上一次已知吊销集合，安全面宁可多拒）；首次加载失败 = 空集（等同
// 「还没有吊销表」——启动期的空文件/无文件都是合法形态）。
type revokedFollower struct {
	path string

	mu        sync.Mutex
	lastCheck time.Time
	mtime     time.Time
	set       map[[32]byte]bool
	loaded    bool
}

// checkInterval：stat 节流窗（跟随粒度秒级——吊销是罕见人工动作，1s 足够“即时”）。
const revokedCheckInterval = time.Second

func newRevokedFollower(path string) *revokedFollower {
	return &revokedFollower{path: path}
}

// isRevoked：该 secret 是否在吊销表内（节流跟随；nil 接收者 = 无吊销面，恒 false）。
func (f *revokedFollower) isRevoked(secret [32]byte) bool {
	if f == nil {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	if !f.loaded || now.Sub(f.lastCheck) >= revokedCheckInterval {
		f.lastCheck = now
		fi, err := os.Stat(f.path)
		switch {
		case err != nil:
			if !f.loaded {
				f.set, f.loaded = map[[32]byte]bool{}, true
			}
			// 已加载过：stat 失败（文件消失）沿用缓存——保守，宁可多拒。
		case !f.loaded || !fi.ModTime().Equal(f.mtime):
			if set, rerr := readRevokedSecrets(f.path); rerr == nil {
				f.set, f.mtime, f.loaded = set, fi.ModTime(), true
			} else if !f.loaded {
				f.set, f.loaded = map[[32]byte]bool{}, true
			}
		}
	}
	return f.set[secret]
}
