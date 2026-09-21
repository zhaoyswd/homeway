package server

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
)

// fakeMapper：内存映射表 + 按预置规则拒绝/接受，记录每次尝试的外部端口。
type fakeMapper struct {
	reject  map[uint16]bool
	table   []upnpMapping // listMappings 返回的既有映射（占位判定用）
	listErr error         // 注入枚举失败（fail-open 用例）
	tried   []uint16
}

func (f *fakeMapper) addPortMapping(_ context.Context, ext uint16, _ netip.Addr, _ uint16) error {
	f.tried = append(f.tried, ext)
	if f.reject[ext] {
		return fmt.Errorf("718 ConflictInMappingEntry")
	}
	return nil
}

func (f *fakeMapper) CleanMappings(context.Context, string, uint16, netip.Addr, uint16) (int, []string, error) {
	return 0, nil, nil
}

func (f *fakeMapper) listMappings(context.Context, int) ([]upnpMapping, error) {
	return f.table, f.listErr
}

// 端口选择顺序：上次成功的端口 → 监听端口 → 监听端口+1。
func TestSelectExternalPortOrder(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.12")
	noop := func(string, ...any) {}

	// ① 有记忆（上次 41643）且它现在空闲 ⇒ 直接沿用，不再去抢 41641。
	m := &fakeMapper{}
	got, err := selectExternalPort(context.Background(), m, 41641, 41643, ip, noop)
	if err != nil || got != 41643 {
		t.Fatalf("应沿用记住的 41643：got=%d err=%v", got, err)
	}
	if len(m.tried) != 1 || m.tried[0] != 41643 {
		t.Fatalf("第一次就应试 41643，实际 %v", m.tried)
	}

	// ② 记忆端口被别人占了 ⇒ 回到监听端口。
	m = &fakeMapper{reject: map[uint16]bool{41643: true}}
	got, err = selectExternalPort(context.Background(), m, 41641, 41643, ip, noop)
	if err != nil || got != 41641 {
		t.Fatalf("记忆端口被占应回落到 41641：got=%d err=%v", got, err)
	}
	if fmt.Sprint(m.tried) != "[41643 41641]" {
		t.Fatalf("尝试顺序 = %v，want [41643 41641]", m.tried)
	}

	// ③ 记忆端口和监听端口都被占 ⇒ 才用 +1。
	m = &fakeMapper{reject: map[uint16]bool{41643: true, 41641: true}}
	got, err = selectExternalPort(context.Background(), m, 41641, 41643, ip, noop)
	if err != nil || got != 41642 {
		t.Fatalf("应回落到 41642：got=%d err=%v", got, err)
	}
	if fmt.Sprint(m.tried) != "[41643 41641 41642]" {
		t.Fatalf("尝试顺序 = %v", m.tried)
	}

	// ④ 没有记忆（首次启动）⇒ 先监听端口；且与记忆相同时不重复试。
	m = &fakeMapper{}
	if got, _ := selectExternalPort(context.Background(), m, 41641, 0, ip, noop); got != 41641 {
		t.Fatalf("首次应先试监听端口，got=%d", got)
	}
	m = &fakeMapper{}
	if got, _ := selectExternalPort(context.Background(), m, 41641, 41641, ip, noop); got != 41641 {
		t.Fatalf("记忆==监听时应直接成功，got=%d", got)
	}
	if len(m.tried) != 1 {
		t.Fatalf("记忆与监听相同时不该重复尝试：%v", m.tried)
	}

	// ⑤ +1…+9 全被路由器拒 ⇒ 报错（错误里带「占用/被拒」统计，便于排障）。
	m = &fakeMapper{reject: map[uint16]bool{}}
	for p := 41641; p <= 41650; p++ {
		m.reject[uint16(p)] = true
	}
	m.reject[41643] = true // prefer
	if _, err := selectExternalPort(context.Background(), m, 41641, 41643, ip, noop); err == nil {
		t.Fatal("全部被拒应报错")
	} else if !strings.Contains(err.Error(), "被路由器拒绝") {
		t.Fatalf("错误信息应区分「路由器拒绝」：%v", err)
	}
}

// 端口用动态挑的空闲口，不用 41641 之类字面量：本机可能真跑着出口（classifyMapping 的
// 活监听检查会看环境），测试必须与环境无关（同 TestFindOurMapping 的约定）。
func freePort(t *testing.T) uint16 {
	c, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	p := uint16(c.LocalAddr().(*net.UDPAddr).Port)
	_ = c.Close()
	return p
}

// 跨主机让位：别人的映射（另一台出口 / 第三方 / 手动）占着候选口 ⇒ 不删不动、让位下一候选。
func TestSelectExternalPortYieldsToForeignMappings(t *testing.T) {
	mine := netip.MustParseAddr("192.0.2.12")
	other := netip.MustParseAddr("192.168.3.99")
	var logs []string
	logf := func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }
	triedHas := func(m *fakeMapper, p uint16) bool {
		for _, x := range m.tried {
			if x == p {
				return true
			}
		}
		return false
	}

	// ① 另一台出口（同前缀、不同内网客户端）占着监听口同号 ⇒ 让位 +1，且不给那个口发 Add。
	base := freePort(t)
	m := &fakeMapper{table: []upnpMapping{{
		Protocol: "UDP", ExternalPort: base, InternalPort: base,
		InternalClient: other.String(), Description: "homeway-exit",
	}}}
	got, err := selectExternalPort(context.Background(), m, base, 0, mine, logf)
	if err != nil || got != base+1 {
		t.Fatalf("应让位到 %d：got=%d err=%v", base+1, got, err)
	}
	if triedHas(m, base) {
		t.Fatalf("被别人占用的 %d 不该收到 AddPortMapping：%v", base, m.tried)
	}
	if !strings.Contains(strings.Join(logs, "\n"), other.String()) {
		t.Fatalf("让位日志应含占用者内网地址 %s：%v", other.String(), logs)
	}

	// ② 第三方/手动映射（不同描述前缀）同样让位、不删。
	logs = nil
	m = &fakeMapper{table: []upnpMapping{{
		Protocol: "UDP", ExternalPort: base, InternalPort: 8080,
		InternalClient: "192.0.2.5", Description: "other-app",
	}}}
	if got, err := selectExternalPort(context.Background(), m, base, 0, mine, logf); err != nil || got != base+1 {
		t.Fatalf("第三方映射应让位：got=%d err=%v", got, err)
	} else if triedHas(m, base) {
		t.Fatalf("第三方占用的 %d 不该收到 AddPortMapping：%v", base, m.tried)
	}

	// ③ 我们自己的映射（同前缀 + 本机地址）⇒ 幂等重建同口，不让位。
	m = &fakeMapper{table: []upnpMapping{{
		Protocol: "UDP", ExternalPort: base, InternalPort: base,
		InternalClient: mine.String(), Description: "homeway-exit",
	}}}
	if got, err := selectExternalPort(context.Background(), m, base, 0, mine, logf); err != nil || got != base {
		t.Fatalf("自己的映射应原口重建：got=%d err=%v", got, err)
	}
	if fmt.Sprint(m.tried) != fmt.Sprint([]uint16{base}) {
		t.Fatalf("应只试 %d，实际 %v", base, m.tried)
	}

	// ④ 同机另一活实例：映射内网端口有人真监听 ⇒ 视为别人，让位（v0.2.2 语义保持）。
	live, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	livePort := uint16(live.LocalAddr().(*net.UDPAddr).Port)
	m = &fakeMapper{table: []upnpMapping{{
		Protocol: "UDP", ExternalPort: base, InternalPort: livePort,
		InternalClient: mine.String(), Description: "homeway-exit",
	}}}
	if got, err := selectExternalPort(context.Background(), m, base, 0, mine, logf); err != nil || got != base+1 {
		t.Fatalf("同机活实例应让位：got=%d err=%v", got, err)
	}
	if triedHas(m, base) {
		t.Fatalf("活实例占用的 %d 不该收到 AddPortMapping：%v", base, m.tried)
	}

	// ⑤ 让位固化：prefer 指向自己的映射 ⇒ 直接沿用，不再回探监听口同号。
	p2 := freePort(t)
	m = &fakeMapper{table: []upnpMapping{
		{Protocol: "UDP", ExternalPort: p2, InternalPort: base, InternalClient: mine.String(), Description: "homeway-exit"},
		{Protocol: "UDP", ExternalPort: base, InternalPort: base, InternalClient: other.String(), Description: "homeway-exit"},
	}}
	if got, err := selectExternalPort(context.Background(), m, base, p2, mine, logf); err != nil || got != p2 {
		t.Fatalf("应固化沿用 %d：got=%d err=%v", p2, got, err)
	}
	if fmt.Sprint(m.tried) != fmt.Sprint([]uint16{p2}) {
		t.Fatalf("固化应只试 %d，实际 %v", p2, m.tried)
	}

	// ⑥ 竞态收敛（覆盖后下轮）：认领失败（prefer=0）、表里同号指向别人 ⇒ 让位；与 ① 同构，
	//    再叠一层「下一轮 prefer=让位口固化」即收敛终态——固化语义已由 ⑤ 钉住。
	logs = nil
	m = &fakeMapper{table: []upnpMapping{{
		Protocol: "UDP", ExternalPort: base, InternalPort: base,
		InternalClient: other.String(), Description: "homeway-exit",
	}}}
	got, _ = selectExternalPort(context.Background(), m, base, 0, mine, logf)
	m2 := &fakeMapper{table: []upnpMapping{
		{Protocol: "UDP", ExternalPort: base, InternalPort: base, InternalClient: other.String(), Description: "homeway-exit"},
		{Protocol: "UDP", ExternalPort: got, InternalPort: base, InternalClient: mine.String(), Description: "homeway-exit"},
	}}
	if got2, err := selectExternalPort(context.Background(), m2, base, got, mine, logf); err != nil || got2 != got {
		t.Fatalf("下一轮应固化在 %d：got=%d err=%v", got, got2, err)
	}

	// ⑦ 枚举失败 fail-open：跳过核验直接申请（即使表里真有别人的映射也看不到）。
	logs = nil
	m = &fakeMapper{
		listErr: fmt.Errorf("SOAP 故障"),
		table: []upnpMapping{{
			Protocol: "UDP", ExternalPort: base, InternalPort: base,
			InternalClient: other.String(), Description: "homeway-exit",
		}},
	}
	if got, err := selectExternalPort(context.Background(), m, base, 0, mine, logf); err != nil || got != base {
		t.Fatalf("枚举失败应回退直接申请 %d：got=%d err=%v", base, got, err)
	}
	if !strings.Contains(strings.Join(logs, "\n"), "跳过所有权核验") {
		t.Fatalf("应留 fail-open 告警日志：%v", logs)
	}
}

// 让尽路径：+1…+9 全被别人占 ⇒ 报错且信息区分「被占用」；不 panic。
func TestSelectExternalPortExhaustedByOccupancy(t *testing.T) {
	mine := netip.MustParseAddr("192.0.2.12")
	other := netip.MustParseAddr("192.168.3.99")
	base := freePort(t)
	var table []upnpMapping
	for i := uint16(0); i <= 9; i++ {
		table = append(table, upnpMapping{
			Protocol: "UDP", ExternalPort: base + i, InternalPort: base + i,
			InternalClient: other.String(), Description: "homeway-exit",
		})
	}
	m := &fakeMapper{table: table}
	_, err := selectExternalPort(context.Background(), m, base, 0, mine, func(string, ...any) {})
	if err == nil {
		t.Fatal("候选让尽应报错")
	}
	if !strings.Contains(err.Error(), "被其它映射占用") {
		t.Fatalf("错误信息应区分「被占用让尽」：%v", err)
	}
	// 多台依次错开（41641/41642/41643 的等价模拟）：占两条让到第三条。
	m = &fakeMapper{table: table[:2]}
	if got, err := selectExternalPort(context.Background(), m, base, 0, mine, func(string, ...any) {}); err != nil || got != base+2 {
		t.Fatalf("两条被占应让到 %d：got=%d err=%v", base+2, got, err)
	}
}
