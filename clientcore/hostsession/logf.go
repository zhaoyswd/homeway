package hostsession

// logf.go — 核内日志设施（函数类型 + 前缀/丢弃实现；随迁自 cshared logf.go，
// host-registry-daemon D1）。cshared 留守侧经壳（type Logf = hostsession.Logf、
// Discard/WithPrefix/GetLogf 薄壳）引用，引用点零改动。

import (
	"log"
)

// Logf 是核内各处传递的日志函数类型。
type Logf = func(format string, args ...any)

// GetLogf 返回全局 logger（标准库 log.Printf；隧道日志经 cshared 侧 tunStdioBegin
// 重定向到文件——重定向动的是 log 包的全局输出，与本函数天然联动）。
func GetLogf() Logf {
	return log.Printf
}

// Discard 丢弃日志。
func Discard(string, ...any) {}

// WithPrefix 给日志加前缀。
func WithPrefix(logf Logf, prefix string) Logf {
	if logf == nil {
		return func(string, ...any) {}
	}
	return func(format string, args ...any) {
		logf(prefix+format, args...)
	}
}
