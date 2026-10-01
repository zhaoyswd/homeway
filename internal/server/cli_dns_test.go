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

// --listen 值域（FIX-71）：>65535 会被 uint16 静默截断（70000→4464）——必须显式拒绝。
func TestServeListenFlagRange(t *testing.T) {
	for _, bad := range []string{"70000", "0"} {
		if err := CLI([]string{"--listen", bad}); err == nil {
			t.Fatalf("--listen %s 应被拒（越界）", bad)
		}
	}
}

// --public-endpoint 值域（FIX-61）：非法形态在启动前拒绝；合法值照常进配置。
func TestServePublicEndpointFlagValidation(t *testing.T) {
	dir := t.TempDir()
	// 非法：非 ip:port。
	if err := CLI([]string{"--state", dir, "--public-endpoint", "example.com"}); err == nil {
		t.Fatal("非法 --public-endpoint 应报错")
	}
	// 合法值不在本用例覆盖（CLI 会真的起服务并阻塞）；装载与公布面见
	// TestManualPublicEndpointIsPublished（Start 级）。
}
