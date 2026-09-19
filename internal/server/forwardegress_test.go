package server

import "testing"

func TestParseForwardEgress(t *testing.T) {
	cases := []struct {
		in      string
		wantTCP EgressMode
		wantUDP EgressMode
		wantErr bool
	}{
		{"", EgressBind, EgressBind, false},
		{"bind", EgressBind, EgressBind, false},
		{"default", EgressDefault, EgressDefault, false},
		{"tcp=default,udp=bind", EgressDefault, EgressBind, false},
		{"udp=bind", EgressBind, EgressBind, false},
		{"tcp=default", EgressDefault, EgressBind, false},
		{"tcp=default, udp=default", EgressDefault, EgressDefault, false},
		{"tcp=maybe", EgressBind, EgressBind, true},
		{"icmp=bind", EgressBind, EgressBind, true},
		{"tcp", EgressBind, EgressBind, true},
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
