// Package term：出口侧终端服务（从 fork 的 cmd/tailcat/term_*.go 机械移植）。
//
// 移植差异（原样保留其余实现与测试）：
//   - 包名 main → term；去掉 tailscale.com/types/logger 依赖（本地 Logf 同签名）。
//   - `newTermService` 改名为导出的 `New`（homewayd 装配用）。
//   - 传输挂接不变：`ServeConn(net.Conn)` 就是「客户端一条腿一条连接」，
//     新栈里由 internal/server 在 127.0.0.1:<TermPort> 上 accept 后喂进来
//     （客户端拨隧道 IP 同端口，出口豁免规则转投 <state>/term.sock——flows 时代曾走 CONNECT，已退役）。
package term

// Logf 日志函数（同 tailscale logger.Logf 签名）；可为 nil。
type Logf func(format string, args ...any)

// TermService 导出别名：装配方（homewayd）持有它，方法集与内部实现一致。
type TermService = termService

// BuildTag 注入构建标记（TERM_PROGRAM_VERSION 用；与 fork 的 forkBuildTag 同义）。
// homewayd 启动时用 ldflags 或 SetBuildTag 设置，默认 "dev"。
var buildTag = "dev"

// SetBuildTag 设置构建标记（空值忽略）。
func SetBuildTag(tag string) {
	if tag != "" {
		buildTag = tag
	}
}

// forkBuildTag 兼容原名（移植代码里就这么调用的）。
func forkBuildTag() string { return buildTag }
