package nodeconfig

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zhaoyswd/homeway/pkg/proto"
)

func TestDefaultMatrix(t *testing.T) {
	// 缺失文件 = 内置默认（零参首跑可用）。
	path := filepath.Join(t.TempDir(), "config.toml")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	d := Default()
	if !reflect.DeepEqual(c, d) {
		t.Fatalf("缺失文件应得内置默认：got %+v want %+v", c, d)
	}

	// 省略键 = 默认（只写一个键、空 [relay] 表头，其余保持默认）。
	if err := os.WriteFile(path, []byte("[serve]\nlisten = 5000\n\n[relay]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !c2.Serve.Enabled || c2.Serve.BindInterface != "auto" || !c2.Serve.UPnP ||
		c2.Serve.MaxPeers != 32 || c2.Serve.PeerTTL != 7*24*time.Hour || c2.Serve.DNSPort != 5300 ||
		c2.Relay.Listen != ":41741" || c2.Relay.Enabled {
		t.Fatalf("省略键应保持默认：got %+v", c2)
	}
	if c2.Serve.Listen != 5000 {
		t.Fatalf("显式键应生效：listen=%d want 5000", c2.Serve.Listen)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	rlTok, err := proto.EncodeRelayToken([32]byte{7, 8, 9}, []proto.Endpoint{{Addr: "1.2.3.4:41741"}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	in := &Config{
		Serve: Serve{
			Enabled: true, Listen: 41641, BindInterface: "en0", UPnP: false,
			STUN: "s.example:3478", STUN6: "", Relay: rlTok,
			MaxPeers: 16, PeerTTL: time.Hour, DNSPort: 0, FilesRoot: "/srv/files",
			DDNS: []string{"home.example.com", "home2.example.com"},
		},
		Relay: Relay{Enabled: true, Listen: ":41741", Advertise: "1.2.3.4:41741,::1:41741"},
	}
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out, in) {
		t.Fatalf("序列化往返不一致：\n got %+v\nwant %+v", out, in)
	}
	// [[serve.ddns]] 多条目在文件里逐块落位（头部注释里的提及不算——只数非注释行）。
	b, _ := os.ReadFile(path)
	blocks := 0
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "[[serve.ddns]]") {
			blocks++
		}
	}
	if blocks != 2 {
		t.Fatalf("ddns 多条目应落 2 个 [[serve.ddns]] 块，got %d", blocks)
	}
	// 0600 权限位。
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("config 权限 %v want 0600", fi.Mode().Perm())
	}
}

func TestIllegalValues(t *testing.T) {
	cases := []struct {
		name, body, field string
	}{
		{"listen 超上限", "[serve]\nlisten = 70000\n", "serve.listen"},
		{"listen 为 0", "[serve]\nlisten = 0\n", "serve.listen"},
		{"dns_port 超上限", "[serve]\ndns_port = 65536\n", "serve.dns_port"},
		{"dns_port 允许 0（关闭代答）", "[serve]\ndns_port = 0\n", ""}, // 合法——用 field 空标记
		{"bind_interface 带斜杠", "[serve]\nbind_interface = \"a/b\"\n", "serve.bind_interface"},
		{"bind_interface 带冒号非 IP", "[serve]\nbind_interface = \"host:1\"\n", "serve.bind_interface"},
		{"peer_ttl 负时长", "[serve]\npeer_ttl = \"-1h\"\n", "serve.peer_ttl"},
		{"peer_ttl 非时长串", "[serve]\npeer_ttl = \"abc\"\n", "serve.peer_ttl"},
		{"ddns 带端口", "[[serve.ddns]]\ndomain = \"h:80\"\n", "serve.ddns.domain"},
		{"ddns 带路径", "[[serve.ddns]]\ndomain = \"h/p\"\n", "serve.ddns.domain"},
		{"ddns 空域名", "[[serve.ddns]]\ndomain = \"\"\n", "serve.ddns.domain"},
		{"relay 坏 token", "[serve]\nrelay = \"rl3xxxx\"\n", "serve.relay"},
		{"relay 裸域名不支持", "[serve]\nrelay = \"example.com:1\"\n", "serve.relay"},
		{"relay.listen 空", "[relay]\nlisten = \"\"\n", "relay.listen"},
		{"relay.listen 非地址", "[relay]\nlisten = \"abc\"\n", "relay.listen"},
		{"relay.listen 端口越界", "[relay]\nlisten = \":70000\"\n", "relay.listen"},
		{"未登记键 typo", "[serve]\nlisen = 1\n", "serve.lisen"},
		{"未登记顶层键", "[client]\nenabled = true\n", "client"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if tc.field == "" {
				if err != nil {
					t.Fatalf("应合法却报错：%v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("非法值应 fail-fast 报错")
			}
			var ce *Error
			if !errors.As(err, &ce) {
				t.Fatalf("应报 *Error，got %T：%v", err, err)
			}
			if !strings.Contains(ce.Error(), tc.field) {
				t.Fatalf("错误应含字段 %q：%v", tc.field, ce.Error())
			}
			if !strings.Contains(ce.Error(), path) {
				t.Fatalf("错误应含文件路径：%v", ce.Error())
			}
		})
	}
}

func TestSyntaxErrorCarriesLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[serve]\nlisten = \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("语法错误应 fail-fast")
	}
	var ce *Error
	if !errors.As(err, &ce) {
		t.Fatalf("应报 *Error，got %T", err)
	}
	if ce.Line != 2 || !strings.Contains(ce.Error(), "第 2 行") {
		t.Fatalf("语法错误应带行号： %+v", ce)
	}
}

func TestUpdateBadConfigRefusesOverwrite(t *testing.T) {
	// r1 中-14：坏 config + 程序写路径 = 拒绝写入，文件逐字节不变。
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	bad := []byte("[serve]\nlisten = \n")
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	err := Update(path, func(c *Config) error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatal("坏 config 的写路径应失败")
	}
	if called {
		t.Fatal("读失败就不该进修改回调")
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(bad) {
		t.Fatalf("坏 config 必须逐字节不变：\n got %q\nwant %q", got, bad)
	}
	// 不留 tmp 残留（没走到写路径）。
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".config.toml.tmp") {
			t.Fatalf("不应有 tmp 残留：%s", e.Name())
		}
	}
}

func TestAtomicWriteNoPartial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := Save(path, Default()); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)

	// 写入失败（目录变只读 → tmp 建不出来）：目标保持写前内容、无 tmp 残留。
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	mutated := Default()
	mutated.Serve.Listen = 4242
	err := Save(path, mutated)
	if err == nil {
		t.Fatal("只读目录下 Save 应失败")
	}
	_ = os.Chmod(dir, 0o700)
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatal("写失败后目标文件必须保持写前内容（不留半文件）")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".config.toml.tmp") {
			t.Fatalf("失败路径应清理 tmp：%s", e.Name())
		}
	}

	// 成功路径：写后同样无 tmp 残留。
	if err := Save(path, mutated); err != nil {
		t.Fatal(err)
	}
	entries, _ = os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".config.toml.tmp") {
			t.Fatalf("成功路径不应有 tmp 残留：%s", e.Name())
		}
	}
}

func TestUpdateModifyAndWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := Update(path, func(c *Config) error { return nil }); err != nil {
		t.Fatal(err) // 缺失 = 默认 → 写出默认 config（serve start 隐式建默认的内核）
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("Update 应回写 config")
	}
	if err := Update(path, func(c *Config) error {
		c.Serve.DDNS = append(c.Serve.DDNS, "home.example.com")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Serve.DDNS) != 1 || c.Serve.DDNS[0] != "home.example.com" {
		t.Fatalf("ddns add 未生效：%v", c.Serve.DDNS)
	}
	// fn 报错 = 不写（读改写的「改」失败路径）。
	if err := Update(path, func(c *Config) error { return errors.New("x") }); err == nil {
		t.Fatal("fn 失败应上抛")
	}
	c2, _ := Load(path)
	if len(c2.Serve.DDNS) != 1 {
		t.Fatal("fn 失败不应写回")
	}
}

// TestUpdateCASDoesNotLoseConcurrentWrite（FIX-56）：Update 期间有别的写者改了文件
// ⇒ 必须重读重放而不是盲写覆盖（原实现 load→fn→save 会把并发更新丢掉）。
// 构造：fn 内先「假装并发写者」把文件改掉（新增 relay.advertise），再只设 serve.listen
// ——最终文件应同时含两处变更。
func TestUpdateCASDoesNotLoseConcurrentWrite(t *testing.T) {
	dir := t.TempDir()
	path := Path(dir)
	if err := Save(path, Default()); err != nil {
		t.Fatal(err)
	}
	injected := false
	err := Update(path, func(c *Config) error {
		if !injected {
			injected = true
			// 模拟并发写者：直接在 fn 执行期间改盘。
			if err := Update(path, func(other *Config) error {
				other.Relay.Advertise = "1.2.3.4:41741"
				return nil
			}); err != nil {
				return err
			}
		}
		c.Serve.Listen = 41000
		return nil
	})
	if err != nil {
		t.Fatalf("Update：%v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Serve.Listen != 41000 {
		t.Fatalf("本次更新丢失：listen=%d", got.Serve.Listen)
	}
	if got.Relay.Advertise != "1.2.3.4:41741" {
		t.Fatalf("并发写者的更新被覆盖（FIX-56 的原症状）：advertise=%q", got.Relay.Advertise)
	}
}

// TestUpdateSerialWritesPreserved（对照）：无并发时多次 Update 串行累积，不误触发重试。
func TestUpdateSerialWritesPreserved(t *testing.T) {
	dir := t.TempDir()
	path := Path(dir)
	for i := 0; i < 3; i++ {
		if err := Update(path, func(c *Config) error {
			c.Serve.Listen = uint16(41000 + i)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Serve.Listen != 41002 {
		t.Fatalf("串行更新应累积到 41002，got %d", got.Serve.Listen)
	}
}

// TestPeerTTLZeroOffAbsentDefault（FIX-62）：三处口径统一为「0 = 关」：
// 省略键 = 缺省 7 天（defaultFile 预装）；显式 "0s" = 关；负值 = 非法。
func TestPeerTTLZeroOffAbsentDefault(t *testing.T) {
	dir := t.TempDir()
	path := Path(dir)
	// 省略键 ⇒ 缺省 7 天。
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Serve.PeerTTL != 7*24*time.Hour {
		t.Fatalf("省略键应为缺省 7 天，got %v", c.Serve.PeerTTL)
	}
	// 显式 0 ⇒ 关（不再被 fill 改写成 7 天）。
	if err := os.WriteFile(path, []byte("peer_ttl = \"0s\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = err
	// 该键在 [serve] 段下：
	if err := os.WriteFile(path, []byte("[serve]\npeer_ttl = \"0s\"\nlisten = 41641\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Serve.PeerTTL != 0 {
		t.Fatalf("显式 0s 应为「关」（0），got %v", c.Serve.PeerTTL)
	}
	// 负值非法。
	if err := os.WriteFile(path, []byte("[serve]\npeer_ttl = \"-1h\"\nlisten = 41641\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "peer_ttl") {
		t.Fatalf("负值应被校验拒绝：%v", err)
	}
}
