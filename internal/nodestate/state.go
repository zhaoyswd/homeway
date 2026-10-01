// Package nodestate：三层 state 布局（role-management tasks 1.2，NS「三层状态分离」）。
//
//	<state>/
//	├── config.toml                    L1 意图（唯一人写文件；0600——读写内核在 internal/nodeconfig）
//	├── serve/                         L2 serve 不变量（key.bin / tokens.jsonl / revoked.jsonl）
//	├── relay/                         L2 relay 不变量（relay.key）
//	├── client/                        L2 client 不变量（identity/ hosts.json forwards.json socks.json）
//	├── cache/                         L3 可弃（日志 / listen_port.txt / public_endpoint.txt / endpoints/）
//	└── control.sock / files.sock / term.sock / speedtest.sock / lock
//	                                   瞬态：重启自动重建；export 不带、reset cache 不碰
//
// OpenNodeState 收紧 0700 + 建 serve/relay/client/cache 子目录 + config 缺失生成默认。
// （旧 exit/daemon 布局的一次性自动迁移已随 B9/FIX-90 删除——现存 state 均为三层布局；
// 历史 migration-backup-<ts>/ 目录保留不动，见 artifact.go 的 export/reset 口径。）
// config 生成的摘要行经 Eventf 进 cache/events.log 并回显终端。
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
	Dir  string
	evW  *logfile.Writer // cache/events.log（公告行与后续装配层共用）
	pend []string        // 日志落地前的公告行（config 生成；OpenNodeState 末尾回放）
}

// OpenNodeState 装配 state：0700 收紧 → 子目录 → config 缺失生成默认 → 摘要日志。
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
		p := filepath.Join(dir, sub)
		if err := os.MkdirAll(p, 0o700); err != nil {
			return nil, err
		}
		// 既有子目录收紧（MkdirAll 的 mode 只对新建生效；runbook 手建的 relay/ 0755
		// 这类漂移在此归一——exec-r1 低-7；失败告警不阻断，与顶层目录同口径）。
		if err := os.Chmod(p, 0o700); err != nil {
			fmt.Fprintf(os.Stderr, "homeway: ⚠️ state 子目录 %s 收紧 0700 失败（%v）——建议手工 chmod\n", p, err)
		}
	}
	st := &NodeState{Dir: dir}

	if err := st.ensureConfig(); err != nil {
		return nil, err
	}

	// 摘要日志（cache/events.log；打开失败只告警——日志不该挡启动）。
	w, err := logfile.Open(st.CacheDir(), "events.log", eventsMaxBytes, eventsBackups)
	if err != nil {
		fmt.Fprintf(os.Stderr, "homeway: ⚠️ events.log 打开失败（%v）——本轮公告只回显终端\n", err)
	}
	st.evW = w
	for _, line := range st.pend {
		st.Eventf("%s", line)
	}
	st.pend = nil
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

// ensureConfig config.toml 缺失时生成默认（已存在则绝不重写——手编意图不被覆盖）。
func (st *NodeState) ensureConfig() error {
	path := nodeconfig.Path(st.Dir)
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	c := nodeconfig.Default()
	if err := nodeconfig.Save(path, c); err != nil {
		return fmt.Errorf("nodestate: 生成默认 config 失败：%w", err)
	}
	st.pend = append(st.pend, fmt.Sprintf("config.toml 缺失——已生成默认（serve.enabled=%v）", c.Serve.Enabled))
	return nil
}
