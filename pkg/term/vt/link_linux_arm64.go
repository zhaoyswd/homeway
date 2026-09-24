//go:build linux && arm64

// libghostty-vt 静态库（tools/build-vt.sh 产；见 third_party/libghostty-vt/README.tier.md）。
//
// 为什么每个目标一个文件：cgo 的 #cgo 指令只在**本文件 import "C"** 时生效——写在无
// import "C" 的文件里会被静默忽略，直到链接才炸（实测）。另外注意 `import "C"` 正上方那段
// 注释就是 **C preamble**（cgo 会剥掉 // 当 C 代码编），所以中文说明必须留在 package 子句之前。
package vt

// #cgo LDFLAGS: -L${SRCDIR}/../../../third_party/libghostty-vt/prebuilt/linux-arm64/lib -lghostty-vt
import "C"
