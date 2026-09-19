package server

import (
	"net"
	"testing"
)

func TestParseForwardEgress(t *testing.T) {
	cases := []struct {
		in      string
		wantTCP EgressMode
		wantUDP EgressMode
		wantErr bool
	}{
		{"", EgressAuto, EgressAuto, false},
		{"auto", EgressAuto, EgressAuto, false},
		{"bind", EgressBind, EgressBind, false},
		{"default", EgressDefault, EgressDefault, false},
		{"tcp=default,udp=bind", EgressDefault, EgressBind, false},
		{"udp=bind", EgressAuto, EgressBind, false},
		{"tcp=default", EgressDefault, EgressAuto, false},
		{"tcp=default, udp=default", EgressDefault, EgressDefault, false},
		{"tcp=maybe", EgressAuto, EgressAuto, true},
		{"icmp=bind", EgressAuto, EgressAuto, true},
		{"tcp", EgressAuto, EgressAuto, true},
	}
	for _, c := range cases {
		got, err := ParseForwardEgress(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("ParseForwardEgress(%q) err=%v，wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if c.wantErr {
			continue
		}
		if got.TCP != c.wantTCP || got.UDP != c.wantUDP {
			t.Errorf("ParseForwardEgress(%q) = tcp:%s udp:%s，want tcp:%s udp:%s",
				c.in, got.TCP, got.UDP, c.wantTCP, c.wantUDP)
		}
	}
}

// auto 的判据：默认路由是不是隧道型网卡。
func TestResolveEgressPolicy(t *testing.T) {
	physical := &net.Interface{Name: "en0", Index: 6}
	tun := &net.Interface{Name: "utun4", Index: 12}
	auto := ForwardEgress{TCP: EgressAuto, UDP: EgressAuto}
	cases := []struct {
		name    string
		cfg     ForwardEgress
		prefer  *net.Interface
		wantTCP EgressMode
		wantUDP EgressMode
	}{
		{"无代理：两块都钉物理卡", auto, physical, EgressBind, EgressBind},
		{"TUN 代理：TCP 交给它、UDP 钉卡", auto, tun, EgressDefault, EgressBind},
		{"没有默认路由：按物理卡处理", auto, nil, EgressBind, EgressBind},
		{"显式 tcp=default 不被覆盖", ForwardEgress{TCP: EgressDefault, UDP: EgressAuto}, physical, EgressDefault, EgressBind},
		{"显式 udp=default 不被覆盖", ForwardEgress{TCP: EgressAuto, UDP: EgressDefault}, tun, EgressDefault, EgressDefault},
		{"两块都显式", ForwardEgress{TCP: EgressBind, UDP: EgressDefault}, tun, EgressBind, EgressDefault},
	}
	for _, c := range cases {
		tcp, udp := resolveEgressPolicy(c.cfg, c.prefer)
		if tcp != c.wantTCP || udp != c.wantUDP {
			t.Errorf("%s：得到 tcp=%s udp=%s，want tcp=%s udp=%s", c.name, tcp, udp, c.wantTCP, c.wantUDP)
		}
	}
}
