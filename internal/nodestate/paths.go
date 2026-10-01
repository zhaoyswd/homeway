package nodestate

// paths.go — 三层 state 布局的**路径 API 单点**（FIX-51）：此前调用方各自
// filepath.Join(stateDir, "serve"/"relay"/"client"/"cache"/"config.toml")，布局挪窝
// （如把 relay 并进 serve）就会漏改一两处、且没有编译期提示。布局树契约见 state.go 包注释。

import "path/filepath"

// 角色子目录名（L2；与角色名一致）。
const (
	RoleServe  = subServe
	RoleRelay  = subRelay
	RoleClient = subClient
)

// ConfigPath L1 意图文件（唯一人写；读写内核在 internal/nodeconfig）。
func ConfigPath(stateDir string) string { return filepath.Join(stateDir, "config.toml") }

// RoleDir L2 角色不变量目录（role ∈ RoleServe/RoleRelay/RoleClient）。
func RoleDir(stateDir, role string) string { return filepath.Join(stateDir, role) }

// CacheDir L3 可弃目录（日志 / 端口记忆 / 端点缓存）。
func CacheDir(stateDir string) string { return filepath.Join(stateDir, subCache) }

// 常用派生物（写死过多次的名字收一处）。
func ServeDir(stateDir string) string  { return RoleDir(stateDir, RoleServe) }
func RelayDir(stateDir string) string  { return RoleDir(stateDir, RoleRelay) }
func ClientDir(stateDir string) string { return RoleDir(stateDir, RoleClient) }

// HostsPath client 角色主机表（daemon 的 status 面读它）。
func HostsPath(stateDir string) string {
	return filepath.Join(ClientDir(stateDir), "hosts.json")
}
