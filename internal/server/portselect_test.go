package server

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
)

// fakeMapper：记录每次尝试的外部端口，按预置规则拒绝/接受。
type fakeMapper struct {
	reject map[uint16]bool
	tried  []uint16
}

func (f *fakeMapper) addPortMapping(_ context.Context, ext uint16, _ netip.Addr, _ uint16) error {
	f.tried = append(f.tried, ext)
	if f.reject[ext] {
		return fmt.Errorf("718 ConflictInMappingEntry")
	}
	return nil
}

func (f *fakeMapper) CleanMappings(context.Context, string, uint16, netip.Addr) (int, []string, error) {
	return 0, nil, nil
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

	// ⑤ 全被拒 ⇒ 报错（错误里带候选端口，便于排障）。
	m = &fakeMapper{reject: map[uint16]bool{41641: true, 41642: true, 41643: true}}
	if _, err := selectExternalPort(context.Background(), m, 41641, 41643, ip, noop); err == nil {
		t.Fatal("全部被拒应报错")
	}
}
