//go:build cshared

// logf.go — 核内日志设施（函数类型 + 前缀/丢弃实现）。
package main

import (
	"log"
)

// Logf 是核内各处传递的日志函数类型。
type Logf = func(format string, args ...any)

// getLogf 返回全局 logger（标准库 log.Printf；隧道日志经 tunStdioBegin 重定向到文件）。
func getLogf() Logf {
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
