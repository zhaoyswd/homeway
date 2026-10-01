// Package contracts：契约台账对账器（contract-ledger 4b，design D2）。
//
// 职责：从各词表真源包的源码 AST 提取生产值集（常量声明 + 白名单构造器首参——
// **明文禁止正则全文匹配**，会捞到日志文案与注释），与手写台账 ledger.jsonl 对账：
// 规则① 生产值集 == 台账 active 集（双向：代码多 = 未登记红 / 少 = 台账腐化红）、
// 规则④ 版本空间结构化面 == versions.go。fixtures 引用/摘要（规则②③）与 CLI 面
// 对账在测试文件里表达。纯标准库（go/parser、encoding/json）——windows 与
// CGO=0 构建门天然可编；不 import 任何生产包（解析的是源码文本，不是导出数据）。
package contracts

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// RepoRoot 自 cwd 向上找 go.mod（模块 github.com/zhaoyswd/homeway）所在目录。
// go test 的 cwd = 包目录（contracts/），向上一层即仓根。
func RepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if dir == string(filepath.Separator) || dir == "" {
			return "", fmt.Errorf("contracts: 未找到仓根（go.mod）")
		}
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		dir = filepath.Dir(dir)
	}
}

// constRule 一条「包内常量声明 → 台账族/单元」提取规则（D2 四列表的机器形态）。
// 包粒度 + 常量名前缀匹配（最长前缀胜），不绑文件路径——词表挪文件不红、换名才红
// （换名本就该同批过台账）。Deny 显式排除同前缀的非词表常量（阈值/上限等）。
type constRule struct {
	Dir    string            // 包目录（相对仓根）
	Family string            // 台账族
	Units  map[string]string // 常量名前缀 → unit
	Deny   map[string]bool   // 同前缀但非词表（如 pkg/term 的 agent* 阈值）
}

// ctorRule 一条「白名单构造器首参」提取规则（提常量后的残余兜底——只认指定包内
// 指定函数名的首参字符串字面量）。
type ctorRule struct {
	Dir    string
	Funcs  []string
	Family string
	Unit   string
}

// constRules 提取清单（tasks 2.2 全列；与台账 1.1 逐族对应）。
var constRules = []constRule{
	{
		Dir: "clientcore/facade", Family: "cp",
		Units: map[string]string{
			"Code": "code", "Op": "op", "Domain": "domain", "Kind": "kind",
			"Reach": "reach", "StreamKind": "stream-kind", "StreamEnd": "stream-end",
		},
	},
	{
		Dir: "clientcore/facade", Family: "event-payload",
		Units: map[string]string{"Diag": "diag"},
	},
	{
		Dir: "clientcore/facade", Family: "versions",
		Units: map[string]string{
			"ControlProtoVersion": "control-proto", "TermProtoVersion": "term-proto",
			"SurfacePayloadVersion": "surface-payload", "HelloFlag": "hello-flag",
			"Caps": "caps", "Feat": "feat", "StateV2": "statev2",
		},
	},
	{
		Dir: "internal/control", Family: "cp",
		Units: map[string]string{"Reload": "close-reason", "Goodbye": "close-reason"},
	},
	{
		Dir: "clientcore/hostsession", Family: "event-payload",
		Units: map[string]string{"svcState": "state"},
	},
	{
		Dir: "clientcore/internal/wtransport", Family: "event-payload",
		Units: map[string]string{"via": "via"},
	},
	{
		Dir: "pkg/term", Family: "term-frame",
		Units: map[string]string{
			"agentName": "agent", "agent": "agent-byte",
			"stateV2Name": "stateV2", "stateV2": "stateV2-byte",
			"termEnd": "ended-code", "termReason": "ended-reason",
			"feat": "feat", "helloFlag": "hello-flag", "caps": "caps",
		},
		// agent* 前缀的阈值常量（agent.go 判定阈值）非词表——显式排除，防误入值集。
		Deny: map[string]bool{
			"agentOutWindowSec": true, "agentOutThreshold": true, "agentQuietDegrade": true,
		},
	},
	{
		Dir: "pkg/term", Family: "term-error",
		Units: map[string]string{"termErr": "code"},
	},
	{
		Dir: "pkg/files", Family: "files-proto",
		Units: map[string]string{"Code": "code"},
	},
	{
		// 端口映射失败码（tunStatusJSON.portForwards[].code；app-logic-refactor 批 E）。
		Dir: "pkg/portfwd", Family: "portfwd",
		Units: map[string]string{"ErrCode": "err"},
	},
	{
		Dir: "pkg/speedtest", Family: "speedtest-reason",
		Units: map[string]string{"Reason": "reason"},
	},
	{
		Dir: "pkg/streamend", Family: "streamend",
		Units: map[string]string{"Closed": "reason", "Gone": "reason", "Conn": "reason"},
	},
	{
		Dir: "clientcore/cmd/clientcore", Family: "bridge-files",
		Units: map[string]string{"filesCode": "code"},
	},
	{
		Dir: "clientcore/cmd/clientcore", Family: "bridge-term",
		Units: map[string]string{"termCode": "code"},
	},
}

// ctorRules 白名单构造器首参（提常量后理论上应为空集——残余字面量在这里兜住；
// 出现即说明某处新增了绕过常量的直产码，对账会因值集不齐而红）。
var ctorRules = []ctorRule{
	{Dir: "pkg/files", Funcs: []string{"Errf", "Errw"}, Family: "files-proto", Unit: "code"},
	{Dir: "pkg/term", Funcs: []string{"termErrf"}, Family: "term-error", Unit: "code"},
	{Dir: "clientcore/cmd/clientcore", Funcs: []string{"filesErrf"}, Family: "bridge-files", Unit: "code"},
	{Dir: "clientcore/cmd/clientcore", Funcs: []string{"termErrf"}, Family: "bridge-term", Unit: "code"},
	{Dir: "clientcore/cmd/clientcore", Funcs: []string{"speedFail"}, Family: "speedtest-reason", Unit: "reason"},
}

// payloadRule 一条「JSON 载荷键集」提取规则（FIX-76）：AST 走指定函数体，收
// `map[string]any{...}` 复合字面量的字符串键与 `<map变量>["键"] = …` 下标赋值
// （含多 LHS）。**按 AST 收、不用正则**（正则会把 `{"state":"unknown"}` 这类
// 兜底字符串与日志文案一起捞进来）；同一 (family, unit) 可由多条规则并集贡献
// （如 tun-status 的主组装 + demand 子载荷）。
type payloadRule struct {
	Dir    string
	Func   string
	Family string
	Unit   string
}

// payloadRules 载荷键集的提取清单（载荷 = NAPI 面下发的 JSON；键集是跨仓契约，
// 生产者在本仓、消费者在 tier App 侧 ArkTS 解析器——tier check-vocab-sync 对账）。
var payloadRules = []payloadRule{
	{Dir: "clientcore/cmd/clientcore", Func: "serviceSnapshotJSON", Family: "napi-payload", Unit: "service-status"},
	{Dir: "clientcore/cmd/clientcore", Func: "tunStatusJSON", Family: "napi-payload", Unit: "tun-status"},
	{Dir: "clientcore/cmd/clientcore", Func: "demandSnapshotJSON", Family: "napi-payload", Unit: "tun-status"},
	{Dir: "clientcore/cmd/clientcore", Func: "pfStatusJSON", Family: "napi-payload", Unit: "pf-status"},
}

// Extract 生产值集提取结果：family → unit → value → 常量名（或「ctor:函数名」）。
type Extracted map[string]map[string]map[string]string

// ExtractAll 按规则提取全部词表真源包（解析的是源码文本——cshared 专属文件同样可见，
// 与构建面无关）。
func ExtractAll(root string) (Extracted, error) {
	out := Extracted{}
	seenDir := map[string]*ast.Package{}
	for _, r := range constRules {
		pkg, err := parseDir(root, r.Dir, seenDir)
		if err != nil {
			return nil, err
		}
		for _, f := range pkg.Files {
			for _, decl := range f.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.CONST {
					continue
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, name := range vs.Names {
						unit, ok := matchUnit(r, name.Name)
						if !ok {
							continue
						}
						if i >= len(vs.Values) {
							return nil, fmt.Errorf("contracts: %s：%s 无值（iota 词表需改手写值）", r.Dir, name.Name)
						}
						// 标识符值 fail-closed：词表常量的值须为字面量或源码文本形态
						// （词表聚集体如 termFeatures 不在前缀内，不在此兜底）。
						v, err := evalExpr(vs.Values[i])
						if err != nil {
							return nil, fmt.Errorf("contracts: %s：%s 值不可求值：%w", r.Dir, name.Name, err)
						}
						setExtracted(out, r.Family, unit, v, name.Name)
					}
				}
			}
		}
	}
	for _, r := range payloadRules {
		pkg, err := parseDir(root, r.Dir, seenDir)
		if err != nil {
			return nil, err
		}
		found := false
		for _, f := range pkg.Files {
			ast.Inspect(f, func(n ast.Node) bool {
				fd, ok := n.(*ast.FuncDecl)
				if !ok || fd.Name.Name != r.Func || fd.Body == nil {
					return true
				}
				found = true
				ast.Inspect(fd.Body, func(m ast.Node) bool {
					switch v := m.(type) {
					case *ast.CompositeLit:
						// map[string]any{...}：收字符串键（嵌套字面量由本遍历继续走到）
						if _, isMap := v.Type.(*ast.MapType); isMap {
							for _, el := range v.Elts {
								if kv, ok := el.(*ast.KeyValueExpr); ok {
									if k, ok := stringLit(kv.Key); ok {
										setExtracted(out, r.Family, r.Unit, k, "key:"+r.Func)
									}
								}
							}
						}
					case *ast.AssignStmt:
						// m["键"] = … / a["p"], b["q"] = x, y：收下标 LHS 的字符串键
						for _, lhs := range v.Lhs {
							ix, ok := lhs.(*ast.IndexExpr)
							if !ok {
								continue
							}
							if k, ok := stringLit(ix.Index); ok {
								setExtracted(out, r.Family, r.Unit, k, "key:"+r.Func)
							}
						}
					}
					return true
				})
				return false
			})
		}
		if !found {
			return nil, fmt.Errorf("contracts: %s 找不到载荷组装函数 %s（改名/挪窝须同批更新 payloadRules）", r.Dir, r.Func)
		}
	}
	for _, r := range ctorRules {
		pkg, err := parseDir(root, r.Dir, seenDir)
		if err != nil {
			return nil, err
		}
		for _, f := range pkg.Files {
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				id, ok := call.Fun.(*ast.Ident)
				if !ok {
					return true
				}
				for _, fn := range r.Funcs {
					if id.Name != fn {
						continue
					}
					if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if s, err := strconv.Unquote(lit.Value); err == nil {
							setExtracted(out, r.Family, r.Unit, s, "ctor:"+fn)
						}
					}
				}
				return true
			})
		}
	}
	return out, nil
}

// stringLit 字符串字面量的值（非字符串字面量返回 false）。
func stringLit(e ast.Expr) (string, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(bl.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

func setExtracted(out Extracted, family, unit, value, name string) {
	if out[family] == nil {
		out[family] = map[string]map[string]string{}
	}
	if out[family][unit] == nil {
		out[family][unit] = map[string]string{}
	}
	if _, dup := out[family][unit][value]; dup {
		return // 同值多名（如透传码同名常量）——登记一次即可
	}
	out[family][unit][value] = name
}

func matchUnit(r constRule, name string) (string, bool) {
	if r.Deny[name] {
		return "", false
	}
	best, found := "", false
	for prefix := range r.Units {
		if strings.HasPrefix(name, prefix) && (!found || len(prefix) > len(best)) {
			best, found = prefix, true
		}
	}
	if !found {
		return "", false
	}
	return r.Units[best], true
}

func parseDir(root, dir string, cache map[string]*ast.Package) (*ast.Package, error) {
	if p, ok := cache[dir]; ok {
		return p, nil
	}
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, filepath.Join(root, dir), func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		return nil, fmt.Errorf("contracts: 解析 %s 失败：%w", dir, err)
	}
	if len(pkgs) != 1 {
		return nil, fmt.Errorf("contracts: %s 解析出 %d 个包（期望 1）", dir, len(pkgs))
	}
	for _, p := range pkgs {
		cache[dir] = p
		return p, nil
	}
	return nil, fmt.Errorf("contracts: %s 无包", dir)
}

// evalExpr 求值词表常量的值表达式：字符串字面量原样、整数字面量十进制文本、
// 一元负号、移位/按位或组合、选择子表达式（math.MinInt32）按源码文本渲染；
// 标识符一律 fail-closed 报错（不支持同包常量引用链）。
func evalExpr(e ast.Expr) (string, error) {
	switch v := e.(type) {
	case *ast.BasicLit:
		switch v.Kind {
		case token.STRING:
			return strconv.Unquote(v.Value)
		case token.INT:
			n, err := strconv.ParseInt(v.Value, 0, 64)
			if err != nil {
				return "", err
			}
			return strconv.FormatInt(n, 10), nil
		}
		return "", fmt.Errorf("不支持的字面量 %s", v.Value)
	case *ast.UnaryExpr:
		x, err := evalExpr(v.X)
		if err != nil {
			return "", err
		}
		if v.Op != token.SUB {
			return "", fmt.Errorf("不支持的一元运算 %v", v.Op)
		}
		return "-" + x, nil
	case *ast.BinaryExpr:
		x, err := evalExpr(v.X)
		if err != nil {
			return "", err
		}
		y, err := evalExpr(v.Y)
		if err != nil {
			return "", err
		}
		xi, e1 := strconv.ParseInt(x, 10, 64)
		yi, e2 := strconv.ParseInt(y, 10, 64)
		if e1 != nil || e2 != nil {
			return "", fmt.Errorf("非整数操作数 %q %v %q", x, v.Op, y)
		}
		switch v.Op {
		case token.SHL:
			return strconv.FormatInt(xi<<uint64(yi), 10), nil
		case token.SHR:
			return strconv.FormatInt(xi>>uint64(yi), 10), nil
		case token.OR:
			return strconv.FormatInt(xi|yi, 10), nil
		case token.ADD:
			return strconv.FormatInt(xi+yi, 10), nil
		}
		return "", fmt.Errorf("不支持的二元运算 %v", v.Op)
	case *ast.SelectorExpr:
		if id, ok := v.X.(*ast.Ident); ok {
			return id.Name + "." + v.Sel.Name, nil
		}
		return "", fmt.Errorf("不支持的选择子形态")
	case *ast.Ident:
		return "", fmt.Errorf("未解析的标识符 %s", v.Name)
	}
	return "", fmt.Errorf("不支持的表达式形态 %T", e)
}

// Files returns 解析某目录（相对仓根）的 AST（测试面复用：CLI 面 / NAPI 面审计）。
func Files(root, dir string) ([]*ast.File, *token.FileSet, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, filepath.Join(root, dir), func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ParseComments)
	if err != nil {
		return nil, nil, err
	}
	for _, p := range pkgs {
		files := make([]*ast.File, 0, len(p.Files))
		for _, f := range p.Files {
			files = append(files, f)
		}
		return files, fset, nil
	}
	return nil, nil, fmt.Errorf("contracts: %s 无包", dir)
}

// parseFileComments 解析单个文件（带注释——NAPI //export / CLI 面审计用）。
func parseFileComments(fset *token.FileSet, path string) (*ast.File, error) {
	return parser.ParseFile(fset, path, nil, parser.ParseComments)
}

// unquote 去掉字符串字面量的引号（strconv.Unquote 的薄封装，调用处省 import）。
func unquote(v string) (string, error) {
	return strconv.Unquote(v)
}

// ComputedSets 生产值集的**完整计算面**（规则① 的比较基集）：提取结果 + 族⑥⑦透传
// 并集（bridge-files/bridge-term 的透传不滤值）。测试门与 ledgergen 生成器共用同一
// 计算——两处各算一遍会让生成器与门漂移。
func ComputedSets(root string) (Extracted, error) {
	ex, err := ExtractAll(root)
	if err != nil {
		return nil, err
	}
	computed := Extracted{}
	for fam, units := range ex {
		computed[fam] = map[string]map[string]string{}
		for u, vals := range units {
			m := map[string]string{}
			for v, n := range vals {
				m[v] = n
			}
			computed[fam][u] = m
		}
	}
	mergeInto := func(family, unit string, src map[string]string) {
		if computed[family][unit] == nil {
			computed[family][unit] = map[string]string{}
		}
		for v, n := range src {
			if _, ok := computed[family][unit][v]; !ok {
				computed[family][unit][v] = n
			}
		}
	}
	mergeInto("bridge-files", "code", ex["files-proto"]["code"])
	mergeInto("bridge-term", "code", ex["term-error"]["code"])
	return computed, nil
}

// UnitRef 一个 (family, unit) 对（生成器与门遍历提取清单用）。
type UnitRef struct {
	Family string
	Unit   string
}

// ExtractUnits 有提取源的 (family, unit) 全集（constRules ∪ payloadRules ∪ ctorRules，
// 去重、稳定序）。生成器据此遍历；空集时返回空切片（调用方按「空集假绿」拒绝）。
func ExtractUnits() []UnitRef {
	seen := map[UnitRef]bool{}
	var out []UnitRef
	add := func(family, unit string) {
		k := UnitRef{family, unit}
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	for _, r := range constRules {
		for _, u := range r.Units {
			add(r.Family, u)
		}
	}
	for _, r := range payloadRules {
		add(r.Family, r.Unit)
	}
	for _, r := range ctorRules {
		add(r.Family, r.Unit)
	}
	return out
}
