package server

import "testing"

// 没探过时不能给假承诺：flags=0（上层按"不可用"处理）。
func TestUDPCapUnknownIsZero(t *testing.T) {
	s := &Server{}
	if got := s.UDPCapFlags(); got != 0 {
		t.Fatalf("未探测时 flags=%#x，want 0", got)
	}
	if s.UDPCapableGeneric() {
		t.Fatal("未探测时不应判成『能承载通用 UDP』")
	}
}

// 两位各管一类：DNS:53 与通用 UDP（STUN:3478）分开上报。
func TestUDPCapFlagsBits(t *testing.T) {
	s := &Server{udpCap: &udpCapState{}}
	s.udpCap.done.Store(true)
	s.udpCap.flags.Store(uint32(UDPCapDNS))
	if s.UDPCapFlags()&UDPCapDNS == 0 || s.UDPCapableGeneric() {
		t.Fatalf("只探通 53 时：flags=%#x，通用应为 false", s.UDPCapFlags())
	}
	s.udpCap.flags.Store(uint32(UDPCapDNS | UDPCapGeneric))
	if !s.UDPCapableGeneric() {
		t.Fatalf("两位都探通时应判通用可用：flags=%#x", s.UDPCapFlags())
	}
}
