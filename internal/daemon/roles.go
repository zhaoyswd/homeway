package daemon

// roles.go — 角色期望态（host-registry-daemon 2.3，D4）：roles.json 启动读、
// 变更即落盘（本期唯一写入方是初始化默认值；控制面写入路径留给 3f 的 roles.*
// 操作——spec 词表不含它）。损坏按默认 + 告警**不拒启**（HD「角色期望态」）。

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// DesiredState 期望态（本期只有 client 一个角色）。
type DesiredState struct {
	Version int                  `json:"version"`
	Roles   map[string]RoleState `json:"roles"`
}

// RoleState 一个角色的期望开关。
type RoleState struct {
	Enabled bool `json:"enabled"`
}

// defaultRolesJSON 初始化默认：client 角色启用（本期唯一角色；exit/relay 装配归 3f）。
const defaultRolesJSON = `{
  "version": 1,
  "roles": {
    "client": { "enabled": true }
  }
}
`

func defaultDesiredState() DesiredState {
	return DesiredState{
		Version: 1,
		Roles:   map[string]RoleState{"client": {Enabled: true}},
	}
}

// loadDesiredState 读期望态：缺失/损坏 → 默认 + 告警（不拒启）。
func loadDesiredState(dir string, warnf func(format string, args ...any)) DesiredState {
	b, err := os.ReadFile(filepath.Join(dir, rolesFileName))
	if errors.Is(err, os.ErrNotExist) {
		ds := defaultDesiredState()
		warnf("roles: %s 缺失——按默认装配（client 启用）", rolesFileName)
		return ds
	}
	if err != nil {
		warnf("roles: %s 读取失败（%v）——按默认装配", rolesFileName, err)
		return defaultDesiredState()
	}
	var ds DesiredState
	if err := json.Unmarshal(b, &ds); err != nil || ds.Roles == nil {
		warnf("roles: %s 损坏（%v）——按默认装配，不拒启", rolesFileName, err)
		return defaultDesiredState()
	}
	return ds
}

// saveDesiredState 落盘期望态（0600）。
func saveDesiredState(dir string, ds DesiredState) error {
	b, err := json.MarshalIndent(ds, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, rolesFileName), append(b, '\n'), 0o600)
}

// roleEnabled 某角色是否期望启用。**未登记 = 默认 on**（v1 兼容语义，r2 新-2
// 拍板）：既有仅含 client 的 roles.json 升级后 control 等新角色自动在位，仅显式
// `enabled:false` 才关——存量 roles.json 原样不动（不回写用户 state 文件；
// saveDesiredState 仍只服务默认值初始化与未来的控制面写入路径）。
func (ds DesiredState) roleEnabled(name string) bool {
	rs, ok := ds.Roles[name]
	if !ok {
		return true
	}
	return rs.Enabled
}
