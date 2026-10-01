// Package nodeconfig：config.toml（L1 意图层，NS「config.toml」）的读改写内核
// （role-management tasks 1.1）。
//
// 键表 = 今日 flag 全集映射（serve/relay 两节 + D2 增补的 dns_port/files_root）；
// 省略键 = 内置默认（serve.enabled=true、relay.enabled=false、relay.listen=":41741"）；
// 覆盖序 = flag 显式设值 > config > 内置默认（flag 一次性覆盖、不写回——Override）。
// `--state` 是引导 flag（config 在 state 里），MUST NOT 进 config；`--verbose` 类终端
// 显示行为留 flag、不进 config。身份密钥类字段 MUST NOT 进键表（key 与 token 台账
// 同居 L2，NS「三层状态分离」）。
//
// 解析/校验 = fail-fast：非法 TOML / 类型不符 / 值域外（端口 1–65535、bind_interface
// 枚举、peer_ttl 时长、ddns 裸域名、relay 取值——口径沿今日 cli.go/ParseRelayArg）/
// 未登记键（typo 保护）→ 报文件+行号/字段+值域的可行动错误，MUST NOT 静默按默认启动。
// 同一口径适用于写路径：Update 读改写遇已损坏 config = 拒绝写入 + 同款错误，
// MUST NOT 以默认值覆盖（r1 中-14）。写入 = tmp+rename 原子替换、0600、定序序列化
// （BurntSushi Encoder 按结构体字段序）+ 头部注释模板（程序改写后用户自加注释丢失
// 是已知代价，D2；模板本身随每次写回保留）。
package nodeconfig

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/zhaoyswd/homeway/pkg/proto"
)

// Path config.toml 在 state 目录里的位置。
func Path(stateDir string) string { return filepath.Join(stateDir, "config.toml") }

// Config config.toml 的内存形态（语义类型；序列化经 fileConfig 逐字段映射）。
type Config struct {
	Serve Serve
	Relay Relay
}

// Serve 出口角色节（[serve]）。
type Serve struct {
	Enabled       bool          // 期望态（serve start/stop 即改此值；重启照此恢复）
	Listen        uint16        // WG 监听端口（被占自动退让）
	BindInterface string        // auto / none / 网卡名 / IP 字面量（原 --bind-interface）
	UPnP          bool          // 向路由器申请 UDP 映射
	STUN          string        // v4 公网映射观测；空 = 关
	STUN6         string        // v6 路径校验；空 = 关
	Relay         string        // 上游中继 token（rl1…）或裸 IP:port（开放模式）；空 = 不用
	MaxPeers      int           // 设备表容量
	PeerTTL       time.Duration // 失联设备回收 TTL；0 = 关
	DNSPort       uint16        // DNS 代答端口；0 = 关闭代答
	FilesRoot     string        // files 根；空 = $HOME
	DDNS          []string      // DDNS 裸域名，可多条（出口只读解析，不自更记录）
}

// Relay 中继角色节（[relay]）。
type Relay struct {
	Enabled   bool   // 期望态
	Listen    string // UDP 监听地址（":41741"）
	Advertise string // token 里公布的中继地址，逗号分隔多条；空 = 运行时探测
}

// Default 内置默认（省略键与缺失文件都按这套；「缺失 = serve.enabled=true」限定
// 全新 state 首启——迁移路径的初始 enabled 按旧布局形态定，见 nodestate 迁移）。
func Default() *Config {
	return &Config{
		Serve: Serve{
			Enabled:       true,
			Listen:        41641,
			BindInterface: "auto",
			UPnP:          true,
			STUN:          "stun.cloudflare.com:3478",
			STUN6:         "stun.cloudflare.com:3478",
			MaxPeers:      32,
			PeerTTL:       7 * 24 * time.Hour,
			DNSPort:       5300,
		},
		Relay: Relay{
			Enabled: false,
			Listen:  ":41741",
		},
	}
}

// ---- TOML 线形态（键表契约；Encode/Decode 都经这层）----

type fileConfig struct {
	Serve fileServe `toml:"serve"`
	Relay fileRelay `toml:"relay"`
}

type fileServe struct {
	Enabled       bool          `toml:"enabled"`
	Listen        int           `toml:"listen"`
	BindInterface string        `toml:"bind_interface"`
	UPnP          bool          `toml:"upnp"`
	STUN          string        `toml:"stun"`
	STUN6         string        `toml:"stun6"`
	Relay         string        `toml:"relay"`
	MaxPeers      int           `toml:"max_peers"`
	PeerTTL       time.Duration `toml:"peer_ttl"`
	DNSPort       int           `toml:"dns_port"`
	FilesRoot     string        `toml:"files_root"`
	DDNS          []fileDDNS    `toml:"ddns"`
}

type fileDDNS struct {
	Domain string `toml:"domain"`
}

type fileRelay struct {
	Enabled   bool   `toml:"enabled"`
	Listen    string `toml:"listen"`
	Advertise string `toml:"advertise"`
}

func defaultFile() *fileConfig {
	d := Default()
	return toFile(d)
}

func toFile(c *Config) *fileConfig {
	f := &fileConfig{
		Serve: fileServe{
			Enabled:       c.Serve.Enabled,
			Listen:        int(c.Serve.Listen),
			BindInterface: c.Serve.BindInterface,
			UPnP:          c.Serve.UPnP,
			STUN:          c.Serve.STUN,
			STUN6:         c.Serve.STUN6,
			Relay:         c.Serve.Relay,
			MaxPeers:      c.Serve.MaxPeers,
			PeerTTL:       c.Serve.PeerTTL,
			DNSPort:       int(c.Serve.DNSPort),
			FilesRoot:     c.Serve.FilesRoot,
		},
		Relay: fileRelay{
			Enabled:   c.Relay.Enabled,
			Listen:    c.Relay.Listen,
			Advertise: c.Relay.Advertise,
		},
	}
	for _, d := range c.Serve.DDNS {
		f.Serve.DDNS = append(f.Serve.DDNS, fileDDNS{Domain: d})
	}
	return f
}

func (f *fileConfig) toConfig() *Config {
	c := &Config{
		Serve: Serve{
			Enabled:       f.Serve.Enabled,
			Listen:        uint16(f.Serve.Listen),
			BindInterface: f.Serve.BindInterface,
			UPnP:          f.Serve.UPnP,
			STUN:          f.Serve.STUN,
			STUN6:         f.Serve.STUN6,
			Relay:         f.Serve.Relay,
			MaxPeers:      f.Serve.MaxPeers,
			PeerTTL:       f.Serve.PeerTTL,
			DNSPort:       uint16(f.Serve.DNSPort),
			FilesRoot:     f.Serve.FilesRoot,
		},
		Relay: Relay{
			Enabled:   f.Relay.Enabled,
			Listen:    f.Relay.Listen,
			Advertise: f.Relay.Advertise,
		},
	}
	for _, d := range f.Serve.DDNS {
		c.Serve.DDNS = append(c.Serve.DDNS, d.Domain)
	}
	return c
}

// Error config 解析/校验失败（fail-fast 可行动错误）。语法/类型错误带行号
// （BurntSushi ParseError）；值域外带字段与合法值域——两类都带文件路径。
type Error struct {
	Path   string
	Line   int    // >0 = 已知行号（语法/类型错误）
	Field  string // 键路径（serve.listen；未登记键报在这里）
	Detail string
}

func (e *Error) Error() string {
	switch {
	case e.Line > 0 && e.Field != "":
		return fmt.Sprintf("%s: 第 %d 行（%s）：%s", e.Path, e.Line, e.Field, e.Detail)
	case e.Line > 0:
		return fmt.Sprintf("%s: 第 %d 行：%s", e.Path, e.Line, e.Detail)
	case e.Field != "":
		return fmt.Sprintf("%s: %s：%s", e.Path, e.Field, e.Detail)
	default:
		return fmt.Sprintf("%s: %s", e.Path, e.Detail)
	}
}

// Load 读 config：文件缺失 = 内置默认（不报错——零参首跑可用）；存在即解析 + 校验，
// 任何非法 = *Error（不静默按默认）。
func Load(path string) (*Config, error) {
	f, err := loadFile(path)
	if err != nil {
		return nil, err
	}
	return f.toConfig(), nil
}

func loadFile(path string) (*fileConfig, error) {
	// 省略键 = 默认：先装默认再 Decode（BurntSushi 只覆盖文件里出现的键）。
	f := defaultFile()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return nil, &Error{Path: path, Detail: fmt.Sprintf("读取失败：%v", err)}
	}
	md, err := toml.Decode(string(b), f)
	if err != nil {
		e := &Error{Path: path, Detail: err.Error()}
		var pe toml.ParseError // 值接收者：Decode 返回的是 ParseError 值
		if errors.As(err, &pe) {
			e.Line, e.Field, e.Detail = pe.Position.Line, pe.LastKey, pe.Message
		}
		return nil, e
	}
	// 未登记键 = typo 保护（L1 是人写意图层，静默忽略会让 typo 变成事实变更）。
	if undec := md.Undecoded(); len(undec) > 0 {
		var keys []string
		for _, k := range undec {
			keys = append(keys, k.String())
		}
		return nil, &Error{Path: path, Field: strings.Join(keys, ", "),
			Detail: "未登记的键（键表见文件头注释；--state 是引导 flag 不进 config）"}
	}
	if err := validateFile(path, f); err != nil {
		return nil, err
	}
	return f, nil
}

// validateFile 值域校验（口径沿今日 cli.go / ParseRelayArg 既有校验）。
func validateFile(path string, f *fileConfig) error {
	bad := func(field, format string, args ...any) error {
		return &Error{Path: path, Field: field, Detail: fmt.Sprintf(format, args...)}
	}
	if f.Serve.Listen < 1 || f.Serve.Listen > 65535 {
		return bad("serve.listen", "%d 非法（合法值域 1–65535）", f.Serve.Listen)
	}
	if f.Serve.DNSPort < 0 || f.Serve.DNSPort > 65535 {
		return bad("serve.dns_port", "%d 非法（合法值域 0–65535；0 = 关闭代答）", f.Serve.DNSPort)
	}
	if err := validateBindInterface(path, f.Serve.BindInterface); err != nil {
		return err
	}
	if f.Serve.PeerTTL < 0 {
		return bad("serve.peer_ttl", "%v 非法（时长串，如 \"168h\"；不小于 0）", f.Serve.PeerTTL)
	}
	for _, d := range f.Serve.DDNS {
		if d.Domain == "" {
			return bad("serve.ddns.domain", "空域名非法")
		}
		if strings.ContainsAny(d.Domain, ":/ ") {
			return bad("serve.ddns.domain", "%q 非法（只要裸域名，不带端口/路径）", d.Domain)
		}
	}
	if err := validateRelayToken(path, "serve.relay", f.Serve.Relay); err != nil {
		return err
	}
	if err := validateUDPAddr(path, "relay.listen", f.Relay.Listen); err != nil {
		return err
	}
	return nil
}

// validateBindInterface：auto/none（含 off/no 与空）枚举、IP 字面量、其余按网卡名
// 放行（运行时 resolve 失败只告警退回 auto——沿今日 resolveBind 口径，不因此拒启）。
func validateBindInterface(path, v string) error {
	t := strings.TrimSpace(v)
	switch strings.ToLower(t) {
	case "", "auto", "none", "off", "no":
		return nil
	}
	if _, err := netip.ParseAddr(t); err == nil {
		return nil
	}
	if strings.ContainsAny(t, ":/ \t") {
		return &Error{Path: path, Field: "serve.bind_interface",
			Detail: fmt.Sprintf("%q 非法（auto / none / 网卡名 / IP 字面量）", v)}
	}
	return nil
}

// ValidateRelayArg relay 取值的 CLI 侧形态校验（role-management 3.2：`serve relay
// set` 写前的就地报错——空 = 不用中继；rl1 前缀 = 必须能解码；其余 = 裸 IP:port
// 开放模式。与 config 校验同一口径）。
func ValidateRelayArg(v string) error {
	return validateRelayToken("cli", "serve.relay", v)
}

// validateRelayToken：空 = 不用中继；rl1 前缀 = 必须能解码；其余 = 裸 IP:port
// 开放模式（ParseRelayArg 同口径——域名不支持，先拿带 IP 的 token）。
func validateRelayToken(path, field, v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	if strings.HasPrefix(v, "rl1") {
		if _, err := proto.DecodeRelayToken(v); err != nil {
			return &Error{Path: path, Field: field, Detail: fmt.Sprintf("中继 token 解析失败：%v", err)}
		}
		return nil
	}
	if _, err := netip.ParseAddrPort(v); err != nil {
		return &Error{Path: path, Field: field,
			Detail: fmt.Sprintf("%q 非法（rl1… token 或裸 IP:port；域名不支持）", v)}
	}
	return nil
}

// validateUDPAddr："[host:]port" 监听地址（host 可空 = 全接口；端口必须 1–65535）。
func validateUDPAddr(path, field, v string) error {
	if v == "" {
		return &Error{Path: path, Field: field, Detail: "空地址非法（如 \":41741\"）"}
	}
	_, port, err := net.SplitHostPort(v)
	if err != nil {
		return &Error{Path: path, Field: field, Detail: fmt.Sprintf("%q 非法（[host:]port 形态，如 \":41741\"：%v）", v, err)}
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return &Error{Path: path, Field: field, Detail: fmt.Sprintf("端口 %q 非法（合法值域 1–65535）", port)}
	}
	return nil
}

// headerComment 头部注释模板：键表速览 + 分层纪律提示（随每次写回保留；用户自加
// 注释在程序改写后丢失是已知代价，D2）。
const headerComment = `# homeway 配置（L1 意图层，唯一人写文件；0600）
# 覆盖序 = flag > 本文件 > 内置默认（flag 一次性覆盖、不写回）；省略键 = 默认。
# 身份密钥不进本文件（key 与 token 台账同居 <state>/serve|relay/，L2）。
# 改动经 restart/重启生效（不热更）；纯配置写命令（relay set/ddns add 等）写完
# 会提示 ` + "`homeway serve restart`" + `。
# 键表（省略即默认）：
#   [serve] enabled / listen(1-65535) / bind_interface(auto|none|网卡|IP) /
#           upnp / stun / stun6 / relay(rl1… 或 IP:port) / max_peers /
#           peer_ttl(时长串，"0s"=关) / dns_port(0=关) / files_root(空=$HOME)
#   [[serve.ddns]] domain = "裸域名"（可多条；出口只读解析，记录由外部 DDNS 维护）
#   [relay] enabled / listen(":41741") / advertise(逗号分隔，空=自动探测)
# 客户端角色无配置节（随进程常开）；host 表在 <state>/client/hosts.json（不进 config）。
`

// Save 原子写 config：校验 → 定序序列化（+头部注释）→ 同目录 tmp → rename 原子替换
// （0600；中断不留半文件——tmp 写失败即清理，目标文件保持写前内容）。
func Save(path string, c *Config) error {
	f := toFile(c)
	if err := validateFile(path, f); err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.WriteString(headerComment)
	enc := toml.NewEncoder(&buf)
	enc.Indent = ""
	if err := enc.Encode(f); err != nil {
		return &Error{Path: path, Detail: fmt.Sprintf("序列化失败：%v", err)}
	}
	return atomicWrite(path, buf.Bytes())
}

// Update 原子读改写（程序写者 set/clear/add/delete/start/stop 的统一落点）：
// 读（坏 config = 拒绝写入 + 同款 fail-fast，MUST NOT 以默认覆盖——r1 中-14）→
// fn 修改 → 校验 → 原子写回。
func Update(path string, fn func(*Config) error) error {
	c, err := Load(path)
	if err != nil {
		return err
	}
	if err := fn(c); err != nil {
		return err
	}
	return Save(path, c)
}

// atomicWrite tmp+rename（同目录保证同文件系统，rename 原子）；失败清理 tmp。
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".config.toml.tmp-*")
	if err != nil {
		return fmt.Errorf("config: 建临时文件失败（%s）：%w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = tmp.Close(); _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("config: 写临时文件失败：%w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("config: 临时文件收紧 0600 失败：%w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("config: 关临时文件失败：%w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("config: 原子替换失败（%s → %s）：%w", tmpName, path, err)
	}
	return nil
}

// Override 覆盖序 helper：flag 显式设值（set=true）优先，否则 config 值生效
// （内置默认已由 Load 折进 cfg 值——「flag > config > 默认」三层由此收拢）。
// Go flag 不自带「是否显式设过」，调用方用 fs.Visit 登记后传入 set。
func Override[T any](set bool, flagVal, cfgVal T) T {
	if set {
		return flagVal
	}
	return cfgVal
}
