//go:build !cshared

// （随迁自 cshared package main，host-registry-daemon D8 账本·纯迁 12 之一；
// diff = 构建约束翻面（账本口径：用例迁出 cshared 计数面）+ 包名。）
package hostsession

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/zhaoyswd/homeway/pkg/proto"
)

func noLog(string, ...any) {}

func TestResolveCandidatesIPPassthrough(t *testing.T) {
	eps := []proto.Endpoint{
		{Addr: "192.168.3.12:41641"},
		{Addr: "203.0.113.212:4430", Relay: true},
		{Addr: "192.168.3.12:41641"}, // 重复：去重
	}
	got := resolveCandidates(eps, func(_ context.Context, host string) ([]netip.Addr, error) {
		t.Fatalf("IP 字面量不该触发解析：%s", host)
		return nil, nil
	}, noLog)
	if len(got) != 2 {
		t.Fatalf("候选数 = %d，want 2（去重后）：%+v", len(got), got)
	}
	if got[0].Addr.String() != "192.168.3.12:41641" || got[0].Relay {
		t.Fatalf("候选[0] = %+v", got[0])
	}
	if got[1].Addr.String() != "203.0.113.212:4430" || !got[1].Relay {
		t.Fatalf("候选[1] = %+v（relay 标记必须保留）", got[1])
	}
}

// 域名端点（真机 2026-09-19：某出口用域名 exit.example.com:41641 签发，客户端原先直接判「没有可用端点」）。
func TestResolveCandidatesDomain(t *testing.T) {
	eps := []proto.Endpoint{{Addr: "exit.example.com:41641"}}
	looked := ""
	got := resolveCandidates(eps, func(_ context.Context, host string) ([]netip.Addr, error) {
		looked = host
		return []netip.Addr{netip.MustParseAddr("198.18.6.240"), netip.MustParseAddr("203.0.113.7")}, nil
	}, noLog)
	if looked != "exit.example.com" {
		t.Fatalf("lookup host = %q", looked)
	}
	if len(got) != 2 || got[0].Addr.String() != "198.18.6.240:41641" || got[1].Addr.String() != "203.0.113.7:41641" {
		t.Fatalf("域名候选不符：%+v", got)
	}
}

func TestResolveCandidatesBadAndFailed(t *testing.T) {
	eps := []proto.Endpoint{
		{Addr: "no-port-here"},
		{Addr: "bad.example:0"},
		{Addr: "down.example:41641"},
	}
	got := resolveCandidates(eps, func(_ context.Context, host string) ([]netip.Addr, error) {
		return nil, errors.New("nxdomain")
	}, noLog)
	if len(got) != 0 {
		t.Fatalf("全失败应为空：%+v", got)
	}
}

func TestSplitTokenEndpoints(t *testing.T) {
	eps := []proto.Endpoint{
		{Addr: "192.168.3.12:41641"},
		{Addr: "home.example.com:41641"}, // 域名条目
		{Addr: "203.0.113.212:4430", Relay: true},
	}
	static, domains := splitTokenEndpoints(eps)
	if len(static) != 2 || len(domains) != 1 {
		t.Fatalf("拆分不对：static=%v domains=%v", static, domains)
	}
	if domains[0].Addr != "home.example.com:41641" {
		t.Fatalf("域名条目=%v", domains[0])
	}
	ports := domainEndpointPorts(domains, noLog)
	if len(ports) != 1 || ports[0].Host != "home.example.com" || ports[0].Port != 41641 {
		t.Fatalf("host/port 拆分不对：%v", ports)
	}
	// 端口非法的域名条目：跳过并留痕（不 panic）。
	bad := domainEndpointPorts([]proto.Endpoint{{Addr: "x.example.com:0"}}, noLog)
	if len(bad) != 0 {
		t.Fatalf("零端口应跳过：%v", bad)
	}
}
