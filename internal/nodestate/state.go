// Package nodestate：三层 state 布局与同根自动迁移（role-management tasks 1.2，
// NS「三层状态分离」「迁移映射与部署终态」）。
//
//	<state>/
//	├── config.toml                    L1 意图（唯一人写文件；0600——读写内核在 internal/nodeconfig）
//	├── serve/                         L2 serve 不变量（key.bin / tokens.jsonl）
//	├── relay/                         L2 relay 不变量（relay.key）
//	├── client/                        L2 client 不变量（identity/ hosts.json forwards.json socks.json）
//	├── cache/                         L3 可弃（日志 / listen_port.txt / public_endpoint.txt / endpoints/）
//	├── migration-backup-<ts>/         迁移保命备份（state 顶层——可弃层不承载保命件，r1 低-7）
//	└── control.sock / files.sock / term.sock / speedtest.sock / lock
//	                                   瞬态：重启自动重建；export 不带、reset cache 不碰
//
// OpenNodeState 收紧 0700 + 建 serve/relay/client/cache 子目录 + 同根自动幂等迁移
// （旧布局检测特征与逐项清单见 migration.go）+ config 缺失生成默认（初始
// serve.enabled 按旧形态定，r1 中-9）。迁移摘要行（每文件一行落点）经 Eventf 进
// cache/events.log 并回显终端。
package nodestate

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/zhaoyswd/homeway/internal/logfile"
	"github.com/zhaoyswd/homeway/internal/nodeconfig"
)

// 子目录名（布局树契约）。
const (
	subServe  = "serve"
	subRelay  = "relay"
	subClient = "client"
	subCache  = "cache"
)

// eventsMaxBytes/eventsBackups 摘要日志轮转参数（沿 internal/daemon 口径）。
const (
	eventsMaxBytes = 2 << 20
	eventsBackups  = 3
)

const logTimePrefix = "2006-01-02 15:04:05.000 [homeway] "

// NodeState 打开（或初始化）后的三层 state 布局句柄。
type NodeState struct {
	Dir   string
	evW   *logfile.Writer // cache/events.log（迁移摘要与后续装配层共用）
	migra *migrationResult
}

// OpenNodeState 装配 state：0700 收紧 → 子目录 → 自动迁移（幂等）→ config 缺失生成
// 默认（enabled 按旧形态）→ 摘要日志。迁移摘要只在**有动作**的轮次产生（迁移后再
// 启动零动作、无摘要行——r1 中-8）。
func OpenNodeState(dir string) (*NodeState, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// 既有目录收紧（OpenState/OpenDaemonState 同款：mode 只对新建生效，历史目录
	// 显式 chmod；失败告警不阻断）。
	if err := os.Chmod(dir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "homeway: ⚠️ state 目录 %s 收紧 0700 失败（%v）——建议手工 chmod\n", dir, err)
	}
	for _, sub := range []string{subServe, subRelay, subClient, subCache} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, err
		}
	}
	st := &NodeState{Dir: dir}

	// 自动迁移在日志落地前执行（根下 events/debug.log 也要搬进 cache/），摘要行
	// 先攒着、日志立起来后回放。
	st.migra = migrate(dir)

	if err := st.ensureConfig(); err != nil {
		return nil, err
	}

	// 摘要日志（cache/events.log；打开失败只告警——日志不该挡启动）。
	w, err := logfile.Open(st.CacheDir(), "events.log", eventsMaxBytes, eventsBackups)
	if err != nil {
		fmt.Fprintf(os.Stderr, "homeway: ⚠️ events.log 打开失败（%v）——本轮迁移摘要只回显终端\n", err)
	}
	st.evW = w
	st.replayMigrationSummary()
	return st, nil
}

// Close 收工（关日志句柄）。
func (st *NodeState) Close() {
	if st.evW != nil {
		st.evW.Close()
	}
}

// ServeDir / RelayDir / ClientDir / CacheDir 布局树落点。
func (st *NodeState) ServeDir() string  { return filepath.Join(st.Dir, subServe) }
func (st *NodeState) RelayDir() string  { return filepath.Join(st.Dir, subRelay) }
func (st *NodeState) ClientDir() string { return filepath.Join(st.Dir, subClient) }
func (st *NodeState) CacheDir() string  { return filepath.Join(st.Dir, subCache) }

// Eventf 摘要级日志（cache/events.log + 终端回显——迁移摘要与用户面公告走这条）。
func (st *NodeState) Eventf(format string, args ...any) {
	line := time.Now().Format(logTimePrefix) + fmt.Sprintf(format, args...)
	fmt.Println(line)
	if st.evW != nil {
		_, _ = st.evW.Write([]byte(line + "\n"))
	}
}

// ensureConfig config.toml 缺失时生成默认；初始 serve.enabled 按旧形态定
// （r1 中-9）：旧 exit 布局 ⇒ true（迁移即保持出口在位）；仅旧 daemon 布局 ⇒
// false（纯 daemon 机不得静默开出口）；全新 state（无旧特征）⇒ true（今日零参=
// 出口的连续性只在这条路径上成立）。
func (st *NodeState) ensureConfig() error {
	path := nodeconfig.Path(st.Dir)
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	c := nodeconfig.Default()
	c.Serve.Enabled = !st.migra.daemonOnly
	if err := nodeconfig.Save(path, c); err != nil {
		return fmt.Errorf("nodestate: 生成默认 config 失败：%w", err)
	}
	st.migra.configCreated = true
	st.migra.configEnabled = c.Serve.Enabled
	return nil
}

// replayMigrationSummary 把本轮迁移/config 生成的摘要行回放进 events.log（无动作
// 的轮次零行——幂等判据「迁移后再启动 = 无迁移摘要行」）。
func (st *NodeState) replayMigrationSummary() {
	for _, line := range st.migra.lines {
		st.Eventf("%s", line)
	}
	if st.migra.configCreated {
		st.Eventf("config.toml 缺失——已生成默认（serve.enabled=%v，按旧布局形态判定：%s）",
			st.migra.configEnabled, layoutDesc(st.migra.daemonOnly))
	}
}

func layoutDesc(daemonOnly bool) string {
	if daemonOnly {
		return "仅旧 daemon 布局 ⇒ 不开出口"
	}
	return "旧 exit 布局或全新 state ⇒ 保持出口连续"
}
