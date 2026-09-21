package server

import "testing"

// dns-host-resolver L5：--dns-port 越界（>65535）必须显式报错，不能静默回绕成
// 低位值（回绕到 0 = 关闭代答，是最危险的静默形态）。
func TestCLIDNSPortOutOfRange(t *testing.T) {
	if err := CLI([]string{"--dns-port", "70000"}); err == nil {
		t.Fatal("越界端口应报错")
	}
	if err := CLI([]string{"--dns-port", "65536"}); err == nil {
		t.Fatal("65536 应报错（uint16 回绕到 0）")
	}
}
