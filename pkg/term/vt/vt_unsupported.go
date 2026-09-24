//go:build !((darwin || linux) && (amd64 || arm64) && cgo)

// vt_unsupported.go — 不支持的平台/构建变体（design D7：armv7 无 term 纯 Go 变体、
// windows 纯 Go + 桩；CGO_ENABLED=0 同理）。
//
// 这里**不**提供 Terminal 的空实现：与 pkg/term 既有的 service_windows.go 同款约定——
// 依赖 vt 的代码自己按同样的构建约束分文件，本文件只负责让「没有 vt」这件事显式可查
// （Available=false + New 明确报错），避免有人以为终端能力在悄悄工作。
package vt

import "errors"

// ErrUnsupported：本平台/本构建不带 libghostty-vt。
var ErrUnsupported = errors.New("vt: 本平台/本构建不支持服务端 vt（需要 darwin/linux + amd64/arm64 + cgo）")

// Available 报告本构建是否带服务端 vt。
const Available = false
