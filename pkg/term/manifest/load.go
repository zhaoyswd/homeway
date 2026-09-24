// load.go — manifest 加载（任务 4.4）。
//
// 加载顺序（规格「manifest 数据驱动与版本兼容」）：
//
//	① 本地覆盖 `<state>/agent-detection/<id>.toml`（**本地永远优先**）
//	② 内嵌（go:embed manifests/*.toml，随二进制分发）
//
// `min_engine_version` 高于本引擎时**拒载该文件并告警**，回落内嵌版本；本地文件不合法
// （TOML 坏 / 超复杂度上限 / region 名非法 / 正则编不过）同样整份忽略 + 告警，绝不因此退出
// 进程、也不影响其它 manifest。
//
// 重载入口 `Reload()` 给运维与 explain 用（规格要求「重载入口」）；每次 Reload 都重建整张表，
// 所以坏文件只在本次生效期间被跳过，改好再 Reload 即恢复。
package manifest

import (
	"embed"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
)

//go:embed manifests/*.toml
var embedded embed.FS

// OverrideDirName 是覆盖目录名（相对出口 state 目录）。
const OverrideDirName = "agent-detection"

// indexEntry 是 index.toml 的一条（进程名映射 + 文件位置）。
type indexEntry struct {
	ID        string   `toml:"id"`
	Path      string   `toml:"path"`
	Processes []string `toml:"processes"`
}

type indexFile struct {
	SchemaVersion int          `toml:"schema_version"`
	Agents        []indexEntry `toml:"agents"`
}

// Loader 是 manifest 表（可重载）。
type Loader struct {
	overrideDir string

	mu       sync.RWMutex
	byID     map[string]*Compiled
	byProc   map[string]string // 进程名（小写 basename）→ id
	warnings []string
}

// NewLoader 建加载器并立即加载一次。overrideDir 为空 = 只用内嵌版本。
func NewLoader(overrideDir string) *Loader {
	l := &Loader{overrideDir: overrideDir}
	l.Reload()
	return l
}

// Reload 重建整张表（线程安全；失败的文件进 warnings 而不是返回错误）。
func (l *Loader) Reload() {
	byID := map[string]*Compiled{}
	byProc := map[string]string{}
	var warns []string

	idx, err := readIndex()
	if err != nil {
		// 索引坏了是**内嵌产物**的问题（不可能来自用户），如实告警并让表为空。
		warns = append(warns, fmt.Sprintf("index.toml 加载失败：%v", err))
	}

	for _, e := range idx.Agents {
		comp, warn := l.loadOne(e)
		if warn != "" {
			warns = append(warns, warn)
		}
		if comp == nil {
			continue
		}
		byID[e.ID] = comp
		for _, p := range e.Processes {
			byProc[strings.ToLower(strings.TrimSpace(p))] = e.ID
		}
	}

	l.mu.Lock()
	l.byID, l.byProc, l.warnings = byID, byProc, warns
	l.mu.Unlock()
}

// loadOne 按「覆盖 → 内嵌」取一份并编译。返回 (nil, 原因) 表示这份不可用。
func (l *Loader) loadOne(e indexEntry) (*Compiled, string) {
	embeddedData, err := embedded.ReadFile(path.Join("manifests", e.Path))
	if err != nil {
		return nil, fmt.Sprintf("内嵌 manifest %s 缺失：%v", e.Path, err)
	}

	if l.overrideDir != "" {
		ovPath := filepath.Join(l.overrideDir, e.ID+".toml")
		if data, rerr := os.ReadFile(ovPath); rerr == nil {
			m, perr := Parse(data, SourceOverride)
			if perr == nil && m.MinEngineVersion > EngineVersion {
				perr = fmt.Errorf("%w: 声明 min_engine_version=%d，高于本引擎 %d",
					ErrInvalid, m.MinEngineVersion, EngineVersion)
			}
			if perr == nil {
				comp, cerr := Compile(m)
				if cerr == nil {
					return comp, ""
				}
				perr = cerr
			}
			// 覆盖文件坏了：告警 + 回落内嵌（规格「引擎版本过老」「恶意/损坏覆盖文件」两条场景）。
			warn := fmt.Sprintf("覆盖文件 %s 被忽略（%v），回落内嵌版本", ovPath, perr)
			comp, ierr := compileEmbedded(embeddedData, e.Path)
			if ierr != nil {
				return nil, warn + fmt.Sprintf("；内嵌版本也不可用：%v", ierr)
			}
			return comp, warn
		}
	}

	comp, ierr := compileEmbedded(embeddedData, e.Path)
	if ierr != nil {
		return nil, fmt.Sprintf("内嵌 manifest %s 不可用：%v", e.Path, ierr)
	}
	return comp, ""
}

func compileEmbedded(data []byte, name string) (*Compiled, error) {
	m, err := Parse(data, SourceEmbedded)
	if err != nil {
		return nil, err
	}
	if m.MinEngineVersion > EngineVersion {
		return nil, fmt.Errorf("%w: min_engine_version=%d > 引擎 %d", ErrInvalid, m.MinEngineVersion, EngineVersion)
	}
	return Compile(m)
}

func readIndex() (indexFile, error) {
	var idx indexFile
	data, err := embedded.ReadFile("manifests/index.toml")
	if err != nil {
		return idx, err
	}
	if _, err := toml.Decode(string(data), &idx); err != nil {
		return idx, err
	}
	if len(idx.Agents) == 0 {
		return idx, fmt.Errorf("index.toml 里没有 agents")
	}
	return idx, nil
}

// ForID 按 agent id 取（explain / 诊断用）。
func (l *Loader) ForID(id string) (*Compiled, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	c, ok := l.byID[id]
	return c, ok
}

// ForProcess 按**前台进程名**取（出口的主入口）：先按 basename 归一，再查表。
//
// 认不出时返回 (nil,false)——调用方按「未知 CLI」展示，不做任何猜测（规格「识别失败时降级」）。
func (l *Loader) ForProcess(name string) (*Compiled, bool) {
	key := strings.ToLower(strings.TrimSpace(baseName(name)))
	if key == "" {
		return nil, false
	}
	l.mu.RLock()
	id, ok := l.byProc[key]
	l.mu.RUnlock()
	if !ok {
		return nil, false
	}
	return l.ForID(id)
}

// IDs 已加载的 agent id（稳定排序，供列表/诊断）。
func (l *Loader) IDs() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]string, 0, len(l.byID))
	for id := range l.byID {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Warnings 本次加载的告警（调用方打日志；空 = 全部干净）。
func (l *Loader) Warnings() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return append([]string(nil), l.warnings...)
}

// baseName 取路径最后一段（`/usr/local/bin/codex` → `codex`）。
func baseName(p string) string {
	p = strings.TrimSpace(p)
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		p = p[i+1:]
	}
	return p
}
