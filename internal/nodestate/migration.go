package nodestate

// migration.go — 同根自动幂等迁移（NS「迁移映射与部署终态」；tasks 1.2 的逐项清单
// ——r1 中-12 点名）。
//
// 检测特征：
//   - 旧 exit 布局 = 根下 tokens.jsonl / key.bin 存在；
//   - 旧 daemon 布局 = daemon/ 子目录含已知可迁移项（hosts/forwards/socks/identity/
//     endpoints/roles.json 或 daemon 日志）。
//
// 迁移后检测特征升级为「存在未迁移的旧特征文件」（r1 中-8）：收尾规则清掉空
// daemon/ 后，下次启动零特征、零动作、零摘要行；daemon/ 残留未知文件时逐文件告警
// 保留（不重复搬迁）。
//
// 映射表（旧位置 → 新位置）：
//   <state>/{key.bin, tokens.jsonl}                      → serve/
//   <state>/daemon/{hosts.json, forwards.json, socks.json, identity/} → client/
//   <state>/daemon/endpoints/                            → cache/endpoints/
//   <state>/daemon/roles.json                            → 吸收（期望态并入 config，client 恒开）后删除
//   <state>/{events,debug,relay}.log*（含轮转）          → cache/
//   <state>/{listen_port.txt, public_endpoint.txt, exit.log, *-stdout.log} → cache/
//   <state>/daemon/{events,debug}.log*                   → cache/daemon-{events,debug}.log*（防同名碰撞）
//   <state>/daemon/{control.sock, lock}                  → 瞬态不迁移；daemon/lock 无人持有则就地清理
//
// 独立 relay state 的 relay.key 属**跨根**合并（部署 runbook 手工，D11），不在本表。
// 搬迁 = rename（同根同文件系统原子）；搬迁前将动文件复制进
// <state>/migration-backup-<ts>/（state 顶层——r1 低-7，reset cache 不碰）；目标存在
// 则跳过 + 告警（幂等）。

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const daemonSubdir = "daemon"

// daemonKnownFiles 已知 daemon 布局文件（迁移项 + 日志；瞬态除外）。
var daemonKnownFiles = []string{
	"hosts.json", "forwards.json", "socks.json", "identity", "endpoints", "roles.json",
}

// rootLogFiles 根下日志/观测类文件（→ cache/；含轮转后缀 .1/.2…）。
var rootLogPatterns = []string{
	"events.log*", "debug.log*", "relay.log*", "listen_port.txt", "public_endpoint.txt",
	"exit.log", "*-stdout.log",
}

// migrationResult 一轮迁移的结果（摘要行 + 布局形态，供 ensureConfig 与测试用）。
type migrationResult struct {
	lines         []string
	oldExit       bool // 根下 tokens.jsonl/key.bin（旧 exit 布局）
	oldDaemon     bool // daemon/ 含已知可迁移项（旧 daemon 布局）
	daemonOnly    bool // 仅旧 daemon 布局（初始 serve.enabled=false 判据，r1 中-9）
	configCreated bool
	configEnabled bool
}

func (m *migrationResult) line(format string, args ...any) {
	m.lines = append(m.lines, fmt.Sprintf(format, args...))
}

// migrate 检测并执行同根自动迁移。任何单点失败不中断整体（跳过并告警——迁移是
// 启动早期尽力而为的搬迁，失败项留在原地由摘要行暴露，人工处置）。
func migrate(dir string) *migrationResult {
	m := &migrationResult{}
	m.oldExit = oldExitLayout(dir)
	var daemonItems map[string]bool
	m.oldDaemon, daemonItems = oldDaemonLayout(dir)
	m.daemonOnly = m.oldDaemon && !m.oldExit

	backupDir := ""
	backup := func(rel string) {
		if backupDir == "" {
			backupDir = filepath.Join(dir, "migration-backup-"+time.Now().Format("20060102-150405"))
		}
		dst := filepath.Join(backupDir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			m.line("⚠️ 迁移备份失败：%s（%v）", rel, err)
			return
		}
		if err := copyTree(filepath.Join(dir, rel), dst); err != nil {
			m.line("⚠️ 迁移备份失败：%s（%v）", rel, err)
		}
	}
	move := func(rel, dstSub string) {
		src := filepath.Join(dir, rel)
		dst := filepath.Join(dir, dstSub, filepath.Base(rel))
		if _, err := os.Lstat(dst); err == nil {
			m.line("跳过：%s → %s（目标已存在，保留原地）", rel, dstSub+"/"+filepath.Base(rel))
			return
		}
		backup(rel)
		if err := osRename(src, dst); err != nil {
			m.line("⚠️ 迁移失败：%s → %s（%v）", rel, dstSub, err)
			return
		}
		m.line("迁移：%s → %s", rel, dstSub+"/"+filepath.Base(rel))
	}

	// ① 旧 exit 布局：根下身份与台账 → serve/。
	for _, name := range []string{"key.bin", "tokens.jsonl"} {
		if fileExists(filepath.Join(dir, name)) {
			move(name, subServe)
		}
	}

	// ② 根下日志/观测类 → cache/。
	for _, pattern := range rootLogPatterns {
		matches, _ := filepath.Glob(filepath.Join(dir, pattern))
		sort.Strings(matches)
		for _, src := range matches {
			rel, _ := filepath.Rel(dir, src)
			move(rel, subCache)
		}
	}

	// ③ 旧 daemon 布局：逐项清单。
	if daemonItems != nil {
		for _, name := range daemonKnownFiles {
			if !daemonItems[name] {
				continue
			}
			rel := filepath.Join(daemonSubdir, name)
			switch name {
			case "endpoints":
				// daemon/endpoints/ → cache/endpoints/（端点学习缓存是 L3）。
				if fileExists(filepath.Join(dir, subCache, name)) {
					m.line("跳过：%s → cache/%s（目标已存在，保留原地）", rel, name)
					continue
				}
				backup(rel)
				if err := osRename(filepath.Join(dir, rel), filepath.Join(dir, subCache, name)); err != nil {
					m.line("⚠️ 迁移失败：%s → cache/%s（%v）", rel, name, err)
					continue
				}
				m.line("迁移：%s → cache/%s", rel, name)
			case "roles.json":
				// 吸收：期望态并入 config（client 恒开、serve/relay 无历史开关——
				// 初始 enabled 按旧形态定，不走 roles.json）后删除。
				backup(rel)
				if err := os.Remove(filepath.Join(dir, rel)); err != nil {
					m.line("⚠️ 吸收失败：%s（%v）", rel, err)
					continue
				}
				m.line("吸收：%s → 期望态并入 config（client 恒开），文件删除（已备份）", rel)
			default:
				move(rel, subClient)
			}
		}
		// daemon/ 自有日志 → cache/（与根下 events/debug 同名，加 daemon- 前缀防碰撞）。
		for _, pattern := range []string{"events.log*", "debug.log*"} {
			matches, _ := filepath.Glob(filepath.Join(dir, daemonSubdir, pattern))
			sort.Strings(matches)
			for _, src := range matches {
				rel, _ := filepath.Rel(dir, src)
				base := filepath.Base(rel)
				if _, err := os.Lstat(filepath.Join(dir, subCache, "daemon-"+base)); err == nil {
					m.line("跳过：%s → cache/daemon-%s（目标已存在，保留原地）", rel, base)
					continue
				}
				backup(rel)
				if err := osRename(src, filepath.Join(dir, subCache, "daemon-"+base)); err != nil {
					m.line("⚠️ 迁移失败：%s（%v）", rel, err)
					continue
				}
				m.line("迁移：%s → cache/daemon-%s", rel, base)
			}
		}
	}

	// ④ 收尾规则（r1 中-8）：daemon/ 清理与残留告警。
	m.finishDaemon(dir)

	if backupDir != "" {
		m.line("迁移备份：%s（搬迁前原样拷贝；reset cache 不碰它）", backupDir)
	}
	return m
}

// finishDaemon 旧 daemon/ 收尾：瞬态（control.sock/lock）无人持有则清理；目录空则删
// （摘要末行「旧布局目录已清理」）；非空逐文件告警保留（未识别文件不静默丢弃）。
func (m *migrationResult) finishDaemon(dir string) {
	d := filepath.Join(dir, daemonSubdir)
	if !dirExists(d) {
		return
	}
	// 瞬态清理：lock 无人持有（flock 试探成功/文件不存在）才动——有活进程守着的
	// daemon state 不该出现在统一进程启动路径上，但宁可保守。
	if held, err := lockHeld(d); err == nil && !held {
		for _, name := range []string{"control.sock", "lock"} {
			p := filepath.Join(d, name)
			if fileExists(p) {
				if err := os.Remove(p); err != nil {
					m.line("⚠️ 清理失败：daemon/%s（%v）", name, err)
					continue
				}
				m.line("清理：daemon/%s（瞬态，不迁移）", name)
			}
		}
	} else if err == nil && held {
		m.line("⚠️ 旧 daemon/ 的 lock 仍被持有——瞬态文件不动（确认旧进程已停后重启）")
	}
	entries, err := os.ReadDir(d)
	if err != nil {
		m.line("⚠️ 读取 %s 失败（%v）——保留原样", daemonSubdir, err)
		return
	}
	if len(entries) == 0 {
		if err := os.Remove(d); err != nil {
			m.line("⚠️ 删除空 %s 失败（%v）", daemonSubdir, err)
			return
		}
		m.line("旧布局目录已清理")
		return
	}
	// 非空：逐文件告警保留（含未知文件与目标已存在而跳过的已知文件）。
	for _, e := range entries {
		m.line("保留：daemon/%s（未迁移的旧布局文件——请人工确认后删除或搬移）", e.Name())
	}
}

// oldExitLayout 根下 tokens.jsonl / key.bin = 旧 exit 布局特征。
func oldExitLayout(dir string) bool {
	return fileExists(filepath.Join(dir, "tokens.jsonl")) || fileExists(filepath.Join(dir, "key.bin"))
}

// oldDaemonLayout daemon/ 含已知可迁移项 = 旧 daemon 布局特征（瞬态不算——迁移后
// 残留的 control.sock/lock 不触发重复迁移）。
func oldDaemonLayout(dir string) (bool, map[string]bool) {
	d := filepath.Join(dir, daemonSubdir)
	if !dirExists(d) {
		return false, nil
	}
	entries, err := os.ReadDir(d)
	if err != nil {
		return false, nil
	}
	items := map[string]bool{}
	known := false
	for _, e := range entries {
		n := e.Name()
		for _, k := range daemonKnownFiles {
			if n == k {
				items[n] = true
				known = true
			}
		}
		// daemon 日志（events.log/debug.log 及轮转）同算已知项。
		if n == "events.log" || n == "debug.log" || matchDaemonLogRotation(n) {
			known = true
		}
	}
	return known, items
}

func matchDaemonLogRotation(name string) bool {
	for _, base := range []string{"events.log.", "debug.log."} {
		if len(name) > len(base) && name[:len(base)] == base {
			return true
		}
	}
	return false
}

func fileExists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func dirExists(p string) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.IsDir()
}

// copyTree 递归拷贝（保留 mode；符号链接原样拷链接目标字符串）。
func copyTree(src, dst string) error {
	fi, err := os.Lstat(src)
	if err != nil {
		return err
	}
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		target, err := os.Readlink(src)
		if err != nil {
			return err
		}
		return os.Symlink(target, dst)
	case fi.IsDir():
		if err := os.MkdirAll(dst, fi.Mode().Perm()); err != nil {
			return err
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := copyTree(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
				return err
			}
		}
		return nil
	default:
		in, err := os.Open(src)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fi.Mode().Perm())
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	}
}

// osRename 迁移用 rename（测试缝：落位失败注入走 artifact.go 同款）。
var osRename = os.Rename
