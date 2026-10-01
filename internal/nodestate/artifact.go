package nodestate

// artifact.go — 状态工件（role-management tasks 1.3，NS「状态工件」，D7）：
//
//	export [–-state DIR]：不变量四件（config.toml + serve/ + relay/ + client/ 四件）
//	  → 单文件未压缩 tar（0600、固定布局 homeway-export/；不含 cache/ 与任何
//	  socket/lock——瞬态不参与恢复）。
//	import <file>：布局校验（缺件/多件/异物拒）+ 解包路径安全校验（r1 低-4：逐条目
//	  前缀 = homeway-export/ 且无 ../绝对路径/符号链接）→ 临时目录解包 → 落位序
//	  （旧四件改名 .import-old-<ts>/ → rename 入位 → 成功删旧、任一步失败回滚）。
//	  目标 state 的统一进程 MUST 在停（锁试探，在跑 = 可行动错误拒绝）。
//	reset cache：清空 cache/（在跑拒绝——日志文件被进程持有）；L1/L2 与
//	  migration-backup-<ts>/ 都不碰（备份在 state 顶层，r1 低-7）。

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const exportTop = "homeway-export"

// clientPieces client/ 侧点名四件（r1 中-12）；serve/ 与 relay/ 取全目录。
var clientPieces = []string{"identity", "hosts.json", "forwards.json", "socks.json"}

// serveAllowed / relayAllowed import 白名单（多件/异物拒的判据）。
var serveAllowed = map[string]bool{"key.bin": true, "tokens.jsonl": true}

var relayAllowed = map[string]bool{"relay.key": true}

// Export 把 <stateDir> 的不变量四件打包为未压缩 tar（dest 路径，0600）。config.toml
// 缺失 = 三层布局未就位，可行动错误（先跑统一进程完成迁移）。
func Export(stateDir, dest string) error {
	configPath := filepath.Join(stateDir, "config.toml")
	configData, err := os.ReadFile(configPath)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("export: %s 里没有 config.toml——三层布局未就位（先启动统一进程完成迁移）", stateDir)
	}
	if err != nil {
		return err
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	tw := tar.NewWriter(f)

	dirEntry := func(name string) error {
		return tw.WriteHeader(&tar.Header{Name: name + "/", Typeflag: tar.TypeDir, Mode: 0o700})
	}
	fileEntry := func(name string, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(data))}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	// 定序：顶层 → config → relay/ → serve/ → client/（确定性输出，人可 diff）。
	if err := dirEntry(exportTop); err != nil {
		return err
	}
	if err := fileEntry(exportTop+"/config.toml", configData); err != nil {
		return err
	}
	for _, sub := range []struct {
		name     string
		dir      string
		allowed  map[string]bool
		specific []string // 非空 = 只取点名件（client 四件）；空 = 白名单全目录
	}{
		{name: subRelay, dir: filepath.Join(stateDir, subRelay), allowed: relayAllowed},
		{name: subServe, dir: filepath.Join(stateDir, subServe), allowed: serveAllowed},
		{name: subClient, dir: filepath.Join(stateDir, subClient), allowed: nil, specific: clientPieces},
	} {
		if err := dirEntry(exportTop + "/" + sub.name); err != nil {
			return err
		}
		var names []string
		if sub.specific != nil {
			names = sub.specific
		} else {
			entries, err := os.ReadDir(sub.dir)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue // 该角色从未跑过：空目录照样进工件（import 布局校验认空）
				}
				return err
			}
			for _, e := range entries {
				if sub.allowed[e.Name()] {
					names = append(names, e.Name())
				}
			}
			sort.Strings(names)
		}
		for _, n := range names {
			p := filepath.Join(sub.dir, n)
			fi, err := os.Lstat(p)
			if err != nil {
				continue // 点名件缺席（该角色未用过）：跳过
			}
			if fi.IsDir() {
				if err := tarDir(tw, exportTop+"/"+sub.name+"/"+n, p); err != nil {
					return err
				}
				continue
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if err := fileEntry(exportTop+"/"+sub.name+"/"+n, data); err != nil {
				return err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return f.Close()
}

// tarDir 递归打包目录（定序：子项按名排序；保留 0600/0700 权限语义）。
func tarDir(tw *tar.Writer, name, src string) error {
	if err := tw.WriteHeader(&tar.Header{Name: name + "/", Typeflag: tar.TypeDir, Mode: 0o700}); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, n := range names {
		p := filepath.Join(src, n)
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if fi.IsDir() {
			if err := tarDir(tw, name+"/"+n, p); err != nil {
				return err
			}
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{Name: name + "/" + n, Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(data))}); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
	}
	return nil
}

// artifactEntry 内存里的一个工件条目（工件小——key/token/identity 都是 KB 级，整读
// 校验 + 解包两用）。
type artifactEntry struct {
	name string // 工件内路径（homeway-export/…）
	dir  bool
	data []byte
}

// Import 把工件落位到 stateDir（校验 → 解包 → 落位序 → 回滚）。
func Import(stateDir, artifactPath string) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	// 目标进程在停（锁试探；在跑 = 可行动错误拒绝）。
	held, err := lockHeld(stateDir)
	if err != nil {
		return fmt.Errorf("import: 锁试探失败（%s/lock）：%w", stateDir, err)
	}
	if held {
		return fmt.Errorf("import: 目标 state 的统一进程在跑（%s/lock 被持有）——先停进程再导入", stateDir)
	}

	entries, err := readArtifact(artifactPath)
	if err != nil {
		return err
	}
	if err := validateArtifact(entries); err != nil {
		return err
	}

	ts := time.Now().Format("20060102-150405")
	tmpDir := filepath.Join(stateDir, ".import-tmp-"+ts)
	oldDir := filepath.Join(stateDir, ".import-old-"+ts)
	if err := extractArtifact(entries, tmpDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		return err
	}
	if err := placePieces(stateDir, filepath.Join(tmpDir, exportTop), oldDir); err != nil {
		// placePieces 内部已回滚（新件撤掉、旧四件归位）；这里清场临时目录。
		_ = os.RemoveAll(tmpDir)
		if empty, derr := dirEmpty(oldDir); derr != nil || empty {
			_ = os.RemoveAll(oldDir)
			return err
		}
		return fmt.Errorf("%w（旧件已回滚归位；%s 残留可手工检查删除）", err, oldDir)
	}
	_ = os.RemoveAll(tmpDir)
	if err := os.RemoveAll(oldDir); err != nil {
		return fmt.Errorf("import: 落位成功但清理 %s 失败（%v）——可手工删除", oldDir, err)
	}
	return nil
}

func dirEmpty(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	return len(entries) == 0, nil
}

// 工件规模上限（半可信输入的第一道界；配合单文件 64MB 上限）。
const (
	artifactMaxEntries    = 4096      // 条目数上限（目录 + 文件）
	artifactMaxTotalBytes = 256 << 20 // 总字节上限（256MB）
)

// readArtifact 读 tar 并做逐条目安全校验（r1 低-4：前缀 = homeway-export/、无 ../
// 绝对路径/符号链接——工件来自用户、属半可信输入）。
func readArtifact(path string) ([]artifactEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("import: 打开工件失败：%w", err)
	}
	defer f.Close()
	var entries []artifactEntry
	var totalBytes int64
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("import: 工件不是合法 tar：%w", err)
		}
		// 工件来自用户（半可信输入，FIX-55）：**先于解包**界住条目数与总量——
		// 原实现只有单文件 64MB 上限，10 万个小文件或上千个大文件会把条目全读进内存。
		if len(entries) >= artifactMaxEntries {
			return nil, fmt.Errorf("import: 工件条目数超上限（%d）——拒绝", artifactMaxEntries)
		}
		if hdr.Typeflag == tar.TypeReg {
			totalBytes += hdr.Size
			if totalBytes > artifactMaxTotalBytes {
				return nil, fmt.Errorf("import: 工件总字节超上限（%d MB）——拒绝", artifactMaxTotalBytes>>20)
			}
		}
		name := hdr.Name
		switch hdr.Typeflag {
		case tar.TypeSymlink, tar.TypeLink, tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			return nil, fmt.Errorf("import: 违规条目 %q（符号/硬链接及其它特殊类型——只接受普通文件与目录）", name)
		case tar.TypeDir, tar.TypeReg:
		default:
			return nil, fmt.Errorf("import: 违规条目 %q（未知类型 %d）", name, hdr.Typeflag)
		}
		if filepath.IsAbs(name) || strings.HasPrefix(name, "/") {
			return nil, fmt.Errorf("import: 违规条目 %q（绝对路径）", name)
		}
		if !strings.HasPrefix(name, exportTop+"/") && name != exportTop && name != exportTop+"/" {
			return nil, fmt.Errorf("import: 违规条目 %q（前缀必须 = %s/）", name, exportTop)
		}
		for _, part := range strings.Split(strings.Trim(name, "/"), "/") {
			if part == ".." || part == "." || part == "" {
				return nil, fmt.Errorf("import: 违规条目 %q（.. / 空路径段）", name)
			}
		}
		var data []byte
		if hdr.Typeflag == tar.TypeReg {
			if hdr.Size > 64<<20 {
				return nil, fmt.Errorf("import: 违规条目 %q（单文件 %d MB 过大）", name, hdr.Size>>20)
			}
			data = make([]byte, hdr.Size)
			if _, err := io.ReadFull(tr, data); err != nil {
				return nil, fmt.Errorf("import: 条目 %q 读取失败：%w", name, err)
			}
		}
		entries = append(entries, artifactEntry{name: strings.TrimSuffix(name, "/"), dir: hdr.Typeflag == tar.TypeDir, data: data})
	}
	return entries, nil
}

// validateArtifact 布局校验：必件齐（config.toml + serve/ + relay/ + client/）、
// 无多件（白名单外条目拒）、无异物（目录当文件/文件当目录）。
func validateArtifact(entries []artifactEntry) error {
	have := map[string]artifactEntry{}
	for _, e := range entries {
		have[e.name] = e
	}
	if _, ok := have[exportTop]; !ok {
		return fmt.Errorf("import: 缺件 %s/（工件顶层目录）", exportTop)
	}
	if e, ok := have[exportTop+"/config.toml"]; !ok || e.dir {
		return fmt.Errorf("import: 缺件 %s/config.toml", exportTop)
	}
	for _, sub := range []string{subServe, subRelay, subClient} {
		e, ok := have[exportTop+"/"+sub]
		if !ok || !e.dir {
			return fmt.Errorf("import: 缺件 %s/%s/", exportTop, sub)
		}
	}
	for _, e := range entries {
		if e.name == exportTop {
			continue
		}
		rel := strings.TrimPrefix(e.name, exportTop+"/")
		parts := strings.Split(rel, "/")
		switch parts[0] {
		case "config.toml":
			if e.dir || len(parts) != 1 {
				return fmt.Errorf("import: 多件/异物 %q", e.name)
			}
		case subServe:
			if e.dir && len(parts) == 1 {
				continue
			}
			if len(parts) != 2 || e.dir || !serveAllowed[parts[1]] {
				return fmt.Errorf("import: 多件/异物 %q（serve/ 只接受 key.bin / tokens.jsonl）", e.name)
			}
		case subRelay:
			if e.dir && len(parts) == 1 {
				continue
			}
			if len(parts) != 2 || e.dir || !relayAllowed[parts[1]] {
				return fmt.Errorf("import: 多件/异物 %q（relay/ 只接受 relay.key）", e.name)
			}
		case subClient:
			if e.dir && len(parts) == 1 {
				continue
			}
			if len(parts) < 2 {
				return fmt.Errorf("import: 多件/异物 %q", e.name)
			}
			if !clientAllowed(parts[1]) {
				return fmt.Errorf("import: 多件/异物 %q（client/ 只接受 identity/ hosts.json forwards.json socks.json）", e.name)
			}
			if parts[1] != "identity" && (len(parts) != 2 || e.dir) {
				return fmt.Errorf("import: 多件/异物 %q", e.name)
			}
		default:
			return fmt.Errorf("import: 多件/异物 %q（固定布局只含 config.toml 与 serve/ relay/ client/）", e.name)
		}
	}
	return nil
}

func clientAllowed(name string) bool {
	for _, p := range clientPieces {
		if name == p {
			return true
		}
	}
	return false
}

// extractArtifact 解包到临时目录（文件 0600、目录 0700）。
func extractArtifact(entries []artifactEntry, tmpDir string) error {
	for _, e := range entries {
		if e.name == exportTop {
			continue // 顶层目录随子项创建
		}
		dst := filepath.Join(tmpDir, filepath.FromSlash(e.name))
		if e.dir {
			if err := os.MkdirAll(dst, 0o700); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(dst, e.data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// placePieces 落位序（r1 低-4）：旧不变量四件改名进 oldDir → 解包内容 rename 入位
// → 成功后由调用方删旧。rename(2) 不能原子替换非空目录，非原子窗口由「先搬走旧件
// + 失败回滚」收口。工件里缺席的件（如源机从未跑过 relay）维持「工件即全量」语义：
// 旧件随 oldDir 在成功路径一并退场。
func placePieces(stateDir, srcDir, oldDir string) (err error) {
	pieces := []string{"config.toml", subServe, subRelay, subClient}
	var movedOld, placed []string
	defer func() {
		if err == nil {
			return
		}
		// 失败回滚：先撤新入位件，再把旧四件归位（顺序不可反——rename 不能盖非空目录）。
		for _, p := range placed {
			_ = os.RemoveAll(filepath.Join(stateDir, p))
		}
		for _, p := range movedOld {
			_ = osRename(filepath.Join(oldDir, p), filepath.Join(stateDir, p))
		}
	}()
	// ① 旧四件搬走。
	for _, p := range pieces {
		src := filepath.Join(stateDir, p)
		if !fileExists(src) {
			continue
		}
		if err = os.MkdirAll(oldDir, 0o700); err != nil {
			return fmt.Errorf("import: 建旧件暂存目录失败：%w", err)
		}
		if err = osRename(src, filepath.Join(oldDir, p)); err != nil {
			return fmt.Errorf("import: 旧件 %s 搬走失败：%w", p, err)
		}
		movedOld = append(movedOld, p)
	}
	// ② 新四件入位。
	for _, p := range pieces {
		src := filepath.Join(srcDir, p)
		if !fileExists(src) {
			continue
		}
		if err = osRename(src, filepath.Join(stateDir, p)); err != nil {
			return fmt.Errorf("import: 新件 %s 入位失败：%w", p, err)
		}
		placed = append(placed, p)
	}
	return nil
}

// ResetCache 清空 <stateDir>/cache/（在跑拒绝——日志文件被进程持有）；L1/L2 与
// state 顶层的 migration-backup-<ts>/ 不碰。
func ResetCache(stateDir string) error {
	held, err := lockHeld(stateDir)
	if err != nil {
		return fmt.Errorf("reset cache: 锁试探失败（%s/lock）：%w", stateDir, err)
	}
	if held {
		return fmt.Errorf("reset cache: 统一进程在跑（%s/lock 被持有）——先停进程（日志文件被进程持有）", stateDir)
	}
	if err := os.RemoveAll(filepath.Join(stateDir, subCache)); err != nil {
		return err
	}
	return os.MkdirAll(filepath.Join(stateDir, subCache), 0o700)
}
