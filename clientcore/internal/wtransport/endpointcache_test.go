package wtransport

// wg-native-stack tasks 2.5 单测：来源/provenance、verified 语义、TTL、失败剔除、
// 落盘-重读、候选组装顺序。

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testPeerID() [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func TestEndpointCacheObserveVerifyPersist(t *testing.T) {
	dir := t.TempDir()
	c := OpenEndpointCache(dir, testPeerID())
	now := time.Now()
	addr := ap("203.0.113.7:41641")

	if !c.Observe(addr, SourceHint, now) {
		t.Fatal("首次观察应产生变化")
	}
	es := c.Entries(now)
	if len(es) != 1 || es[0].Source != SourceHint || es[0].Verified() {
		t.Fatalf("观察后记录不符：%+v", es)
	}
	// 未验证的 hint 不能冒充已验证
	if !c.MarkVerified(addr, SourceHint, now) {
		t.Fatal("标记验证应产生变化")
	}
	if err := c.Save(now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(c.Path()); err != nil {
		t.Fatalf("缓存文件不存在：%v", err)
	}
	if _, err := os.Stat(c.Path() + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("原子写不应留下 .tmp")
	}

	// 重读：来源与验证状态都在
	c2 := OpenEndpointCache(dir, testPeerID())
	es2 := c2.Entries(now)
	if len(es2) != 1 || !es2[0].Verified() || es2[0].Source != SourceHint {
		t.Fatalf("重读记录不符：%+v", es2)
	}
	if es2[0].Addr != addr {
		t.Fatalf("地址不符：%v", es2[0].Addr)
	}
}

func TestEndpointCacheInvalidAndExpired(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	path := OpenEndpointCache(dir, testPeerID()).Path() // 取路径（此时为空缓存）

	write := func(entries ...LearnedEndpoint) {
		raw, err := json.Marshal(endpointFile{Peer: "p", Entries: entries})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// 无时间戳（learnedAt<=0）必须无效（曾经的条件写反会让这种记录永不过期）
	write(LearnedEndpoint{Endpoint: "198.51.100.10:41641", Source: SourceHint})
	if es := OpenEndpointCache(dir, testPeerID()).Entries(now); len(es) != 0 {
		t.Fatalf("无时间戳文件不应有效：%+v", es)
	}

	// 过期（>7 天）无效
	write(LearnedEndpoint{
		Endpoint:  "198.51.100.11:41641",
		Source:    SourceHint,
		LearnedAt: now.Add(-8 * 24 * time.Hour).UnixMilli(),
	})
	if es := OpenEndpointCache(dir, testPeerID()).Entries(now); len(es) != 0 {
		t.Fatalf("过期文件不应有效：%+v", es)
	}

	// 新鲜记录仍有效（阴性对照，防止上面的判据过宽）
	write(LearnedEndpoint{
		Endpoint:  "198.51.100.12:41641",
		Source:    SourceHint,
		LearnedAt: now.UnixMilli(),
	})
	if es := OpenEndpointCache(dir, testPeerID()).Entries(now); len(es) != 1 {
		t.Fatalf("新鲜记录应有效：%+v", es)
	}
}

func TestEndpointCacheTTL(t *testing.T) {
	dir := t.TempDir()
	c := OpenEndpointCache(dir, testPeerID())
	now := time.Now()
	addr := ap("203.0.113.8:41641")

	c.Observe(addr, SourceInband, now)
	if es := c.Entries(now); len(es) != 1 {
		t.Fatalf("新鲜地址应在候选里：%+v", es)
	}

	// TTL：1 小时有效期下，2 小时前学到的地址无效
	c.setTTL(time.Hour)
	old := ap("203.0.113.9:41641")
	c.Observe(old, SourceHint, now.Add(-2*time.Hour))
	if es := c.Entries(now); len(es) != 1 || es[0].Addr != addr {
		t.Fatalf("超 TTL 的地址不应有效：%+v", es)
	}
}

func TestEndpointCacheMergeOrder(t *testing.T) {
	dir := t.TempDir()
	c := OpenEndpointCache(dir, testPeerID())
	now := time.Now()
	learnedVerified := ap("203.0.113.20:41641")
	learnedFresh := ap("203.0.113.21:41641")
	staticA := Candidate{Addr: ap("192.0.2.1:41641")}
	staticRelay := Candidate{Addr: ap("198.51.100.2:4430"), Relay: true}
	staticDup := Candidate{Addr: learnedVerified} // 与学习记录重复

	c.Observe(learnedVerified, SourceInband, now.Add(-time.Minute))
	c.MarkVerified(learnedVerified, SourceInband, now)
	c.Observe(learnedFresh, SourceHint, now)

	got := c.Merge([]Candidate{staticA, staticRelay, staticDup}, now)
	wantOrder := []netip.AddrPort{learnedVerified, learnedFresh, staticA.Addr, staticRelay.Addr}
	if len(got) != len(wantOrder) {
		t.Fatalf("候选数不符：%+v", got)
	}
	for i, w := range wantOrder {
		if got[i].Addr != w {
			t.Fatalf("候选顺序不符（第 %d 个）：got=%v want=%v（全部 %+v）", i, got[i].Addr, w, got)
		}
	}
	if !got[3].Relay {
		t.Fatal("静态中继候选的 Relay 标记必须保留")
	}
	// 学习到的地址一律按 direct 处理
	for _, cand := range got[:2] {
		if cand.Relay {
			t.Fatalf("学习地址不应被当作中继：%v", cand)
		}
	}
}

func TestEndpointCacheDisabledWithoutDir(t *testing.T) {
	c := OpenEndpointCache("", testPeerID())
	now := time.Now()
	c.ObserveAndSave(ap("203.0.113.30:41641"), SourceHint, now)
	if got := c.Entries(now); len(got) != 1 {
		t.Fatalf("内存态仍应工作：%+v", got)
	}
	if c.Path() != "" {
		t.Fatalf("dir 空时不应有路径：%q", c.Path())
	}
	if err := c.Save(now); err != nil {
		t.Fatalf("dir 空时 Save 应无副作用：%v", err)
	}
	if _, err := os.Stat(filepath.Join("", "x")); err == nil {
		t.Fatal("不应在空目录落下文件")
	}
}

// TestSaveMergesOtherInstance（endpoint-freshness D8）：同一 peerID 的两份缓存实例
// （隧道会话与服务会话）各自学到条目后落盘——后写的一方必须把先写的条目并回来，
// 否则整文件覆盖会抹掉对方的学习成果。
func TestSaveMergesOtherInstance(t *testing.T) {
	dir := t.TempDir()
	a := OpenEndpointCache(dir, [32]byte{1})
	b := OpenEndpointCache(dir, [32]byte{1})
	now := time.Now()

	x := netip.MustParseAddrPort("192.0.2.1:41641")
	y := netip.MustParseAddrPort("192.0.2.2:41641")
	a.ObserveAndSave(x, SourceHint, now)
	b.ObserveAndSave(y, SourceHint, now) // 后写：没有合并的话会把 x 抹掉

	c := OpenEndpointCache(dir, [32]byte{1})
	got := map[netip.AddrPort]bool{}
	for _, e := range c.Entries(now) {
		got[e.Addr] = true
	}
	if !got[x] || !got[y] {
		t.Fatalf("落盘合并失效：x=%v y=%v（entries=%v）", got[x], got[y], got)
	}
}

// TestSourceProbeStrength：probe = 非认证线索、与 hint 同级（不互相升级、可被 inband 升级）。
func TestSourceProbeStrength(t *testing.T) {
	dir := t.TempDir()
	c := OpenEndpointCache(dir, [32]byte{2})
	now := time.Now()

	p := netip.MustParseAddrPort("192.0.2.3:41641")
	c.Observe(p, SourceProbe, now)
	c.Observe(p, SourceHint, now) // 同级：来源不变
	for _, e := range c.Entries(now) {
		if e.Addr == p && e.Source != SourceProbe {
			t.Fatalf("同级来源不该翻转：%s", e.Source)
		}
	}
	c.MarkVerified(p, SourceInband, now) // 认证来源更高：升级
	upgraded := false
	for _, e := range c.Entries(now) {
		if e.Addr == p && e.Source == SourceInband {
			upgraded = true
		}
	}
	if !upgraded {
		t.Fatal("inband 应升级 probe 来源")
	}
}

// 并发保存不竞态（真机 2026-09-22：锁外 tmp+rename 后到者 ENOENT + 失败路径 Remove
// 误删第三者 tmp，连环「落盘失败」）：N 个 goroutine 各自 Observe 后并发 Save，全部
// 应零错误、最终文件完整可读。串行化修复的回归钉子（-race 下同样成立）。
func TestConcurrentSaveNoRace(t *testing.T) {
	dir := t.TempDir()
	c := OpenEndpointCache(dir, [32]byte{7})
	now := time.Now()

	const n = 16
	var wg sync.WaitGroup
	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			addr := netip.MustParseAddrPort(fmt.Sprintf("192.0.2.%d:41641", 10+i))
			c.Observe(addr, SourceHint, now)
			if err := c.Save(now); err != nil {
				errCh <- fmt.Errorf("并发 Save #%d: %w", i, err)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}

	d := OpenEndpointCache(dir, [32]byte{7})
	if got := len(d.Entries(now)); got != n {
		t.Fatalf("并发保存后条目数=%d，期望 %d（落盘有丢失）", got, n)
	}
}

// Merge 的 relay 标记沿用（review 1.4）：学习地址与 static 中继条目同址（出口与中继
// 同机同口的退化形态）时，学习项必须沿用 Relay:true——按地址去重吃掉类型位是
// token relay 腿失效事故的同源形态。
func TestEndpointCacheMergeRelayFlagKept(t *testing.T) {
	dir := t.TempDir()
	c := OpenEndpointCache(dir, testPeerID())
	now := time.Now()
	relayAddr := ap("198.51.100.9:41741")
	c.Observe(relayAddr, SourceHint, now) // 学习来源不区分 relay

	got := c.Merge([]Candidate{{Addr: relayAddr, Relay: true}}, now)
	if len(got) != 1 {
		t.Fatalf("候选数不符：%+v", got)
	}
	if !got[0].Relay {
		t.Fatalf("学习地址命中 static 中继条目时必须沿用 Relay 标记：%+v", got)
	}
}
