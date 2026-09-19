package egress

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestIsVirtualIface(t *testing.T) {
	cases := map[string]bool{
		"en0": false, "eth0": false, "eno1": false, "enp3s0": false,
		"utun3": true, "utun0": true, "lo0": true, "bridge100": true,
		"awdl0": true, "llw0": true, "gif0": true, "stf0": true,
		"docker0": true, "veth1234": true, "br-abc": true, "tailscale0": true,
		"TUN0": true, // 大小写不敏感
	}
	for name, want := range cases {
		if got := IsVirtualIface(name); got != want {
			t.Errorf("IsVirtualIface(%q) = %v，want %v", name, got, want)
		}
	}
}

// 候选枚举只做「结构性过滤」，能不能出网由探针决定。
func TestPhysicalCandidatesExcludeVirtual(t *testing.T) {
	cands := PhysicalCandidates()
	for _, c := range cands {
		if IsVirtualIface(c.Name) {
			t.Fatalf("候选里出现了虚拟网卡 %s", c.Name)
		}
		if c.Flags&net.FlagLoopback != 0 || c.Flags&net.FlagUp == 0 {
			t.Fatalf("候选里出现了 down/回环网卡 %s", c.Name)
		}
	}
	t.Logf("候选：%d 张", len(cands))
}

// SelectBest：全不通要报错并给出每张卡的结论；有通的要挑最快的那张。
func TestSelectBestPicksFastest(t *testing.T) {
	cands := []net.Interface{{Name: "en0", Index: 1}, {Name: "en1", Index: 2}}
	probe := func(_ context.Context, ifi *net.Interface, _ []netip.AddrPort, _ time.Duration) (time.Duration, error) {
		switch ifi.Name {
		case "en0":
			return 50 * time.Millisecond, nil
		case "en1":
			return 5 * time.Millisecond, nil
		}
		return 0, nil
	}
	best, err := selectBestWith(context.Background(), cands, nil, nil, time.Second, nil, probe)
	if err != nil {
		t.Fatalf("SelectBest: %v", err)
	}
	if best == nil || best.Name != "en1" {
		t.Fatalf("应挑最快探通的 en1，实际 %v", best)
	}
}

// 默认路由那张卡优先：即使另一张探得更快（典型：docker 网桥探得通但收不到入向包）。
func TestSelectBestPrefersDefaultRouteIface(t *testing.T) {
	cands := []net.Interface{{Name: "eth0", Index: 1}, {Name: "docker0", Index: 2}}
	prefer := &net.Interface{Name: "eth0", Index: 1}
	probe := func(_ context.Context, ifi *net.Interface, _ []netip.AddrPort, _ time.Duration) (time.Duration, error) {
		if ifi.Name == "docker0" {
			return time.Millisecond, nil // 更快
		}
		return 30 * time.Millisecond, nil
	}
	best, err := selectBestWith(context.Background(), cands, prefer, nil, time.Second, nil, probe)
	if err != nil {
		t.Fatal(err)
	}
	if best == nil || best.Name != "eth0" {
		t.Fatalf("默认路由卡探得通时应优先它，实际 %v", best)
	}
}

func TestSelectBestAllFail(t *testing.T) {
	cands := []net.Interface{{Name: "en0", Index: 1}}
	probe := func(_ context.Context, _ *net.Interface, _ []netip.AddrPort, _ time.Duration) (time.Duration, error) {
		return 0, context.DeadlineExceeded
	}
	_, err := selectBestWith(context.Background(), cands, nil, nil, time.Second, nil, probe)
	if err == nil || !strings.Contains(err.Error(), "都探不通") {
		t.Fatalf("全不通应报错并说清：%v", err)
	}
}

// 默认路径探针：拿一个不存在的目标（黑洞地址）应当失败而不是误判成"可用"。
func TestProbeDefaultFailsOnDeadTarget(t *testing.T) {
	dead := []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:1")}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := ProbeDefault(ctx, dead, 400*time.Millisecond); err == nil {
		t.Fatal("死目标不应判成探通")
	}
}
