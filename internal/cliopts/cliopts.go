// Package cliopts：CLI 侧跨层选项的 ctx 载体（role-management tasks 4.1，D4）。
//
// 目前只承载按需拉起的两项：--no-spawn（fail-fast）与提示行输出去向（默认
// os.Stdout）。为什么走 ctx 而不是接口扩参：客户端域命令面（pkg/term / pkg/files）
// 的远程注入缝签名已冻结（Resolve/Dial 只收 stateDir），spawn 决策住在 daemon 侧
// 的统一拨号缝里——ctx 是两端唯一共享的线程（pkg/term 与 daemon 同模块内可共引
// 本包，无 import 环）。
package cliopts

import (
	"context"
	"io"
	"os"
)

// Opts 按需拉起的 CLI 选项。
type Opts struct {
	NoSpawn bool      // true = 未跑时 fail-fast 可行动错误（不拉起；脚本友好）
	Out     io.Writer // 拉起提示行输出去向（nil = os.Stdout）
}

type ctxKey struct{}

// With 把 Opts 挂上 ctx（拨号缝经 From 取回）。
func With(ctx context.Context, o Opts) context.Context {
	return context.WithValue(ctx, ctxKey{}, o)
}

// From 取回 Opts（未挂 = 零值——Out 落 os.Stdout）。
func From(ctx context.Context) Opts {
	if o, ok := ctx.Value(ctxKey{}).(Opts); ok {
		if o.Out == nil {
			o.Out = os.Stdout
		}
		return o
	}
	return Opts{Out: os.Stdout}
}
