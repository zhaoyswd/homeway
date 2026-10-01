package portfwd

import (
	"errors"
	"testing"
)

func TestValidateListen(t *testing.T) {
	for _, p := range []uint16{0, 1, 1023} {
		if err := ValidateListen(p); !errors.Is(err, ErrRange) {
			t.Errorf("listen=%d 应 ErrRange，got %v", p, err)
		}
	}
	for _, p := range []uint16{MinPort, 8080, MaxPort} {
		if err := ValidateListen(p); err != nil {
			t.Errorf("listen=%d 应合法：%v", p, err)
		}
	}
}

func TestValidateTarget(t *testing.T) {
	cases := []struct {
		ip   string
		port uint16
		ok   bool
		err  error
	}{
		{"", 0, true, nil},         // 出口自己（同端口）
		{"", 8080, true, nil},      // 出口自己:8080
		{"1.2.3.4", 0, true, nil},  // 同监听端口
		{"1.2.3.4", 22, true, nil}, // 目标端口无 1024 下限（出口去拨、不 bind；spec 只约束监听端口）
		{"1.2.3.4", 8080, true, nil},
		{"example.com", 8080, false, ErrBadTarget}, // 只收 IPv4 字面量
		{"::1", 8080, false, ErrBadTarget},         // 内层 v6 不支持
		{"1.2.3.4", 65535, true, nil},
		{"1.2.3.4", 80, true, nil}, // 同上（转发到出口自己的 :80）
	}
	for _, c := range cases {
		err := ValidateTarget(c.ip, c.port)
		if c.ok && err != nil {
			t.Errorf("target(%q,%d) 应合法：%v", c.ip, c.port, err)
		}
		if !c.ok && (err == nil || !errors.Is(err, c.err)) {
			t.Errorf("target(%q,%d) 应 %v，got %v", c.ip, c.port, c.err, err)
		}
	}
}

func TestDescribeTarget(t *testing.T) {
	cases := []struct {
		ip           string
		port, listen uint16
		want         string
	}{
		{"", 0, 8080, "出口自己（同端口）"},
		{"", 9090, 8080, "出口自己:9090"},
		{"1.2.3.4", 0, 8080, "1.2.3.4:8080"}, // port 0 ⇒ 同监听端口
		{"1.2.3.4", 9090, 8080, "1.2.3.4:9090"},
	}
	for _, c := range cases {
		if got := DescribeTarget(c.ip, c.port, c.listen); got != c.want {
			t.Errorf("DescribeTarget(%q,%d,%d) = %q want %q", c.ip, c.port, c.listen, got, c.want)
		}
	}
}
