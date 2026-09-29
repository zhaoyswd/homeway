package term

// term_remote.go — `--host` 模式的远程接入缝（term-remote 1.1，design D1）。
// pkg/term 不 import internal/（「pkg/ = 可复用协议层」的既有分层）——远端实现由
// cmd/homeway 注入（internal/daemon.TermRemote，连 daemon 控制面经隧道到达对端
// term 服务），测试注假实现。本文件平台中立（windows 桩也要引用 CLI 签名）。

import (
	"context"
	"io"
)

// RemoteTerm —— `--host` 模式的远程接入缝。
type RemoteTerm interface {
	// ResolveHostRef 把 --host 的名称/全长 hex/无歧义短前缀解析为 hex id（规则与
	// host delete/status 同源）。stateDir = daemon state 目录（control.sock 所在；
	// 空串 = 实现侧默认 ~/.config/homeway/daemon）。
	ResolveHostRef(ctx context.Context, stateDir, ref string) (hexID, name string, err error)
	// DialTerm 打开到目标主机 term 服务的字节流（term 帧协议端到端承载、零改写；
	// 返回的连接已满足「可读 GREETING」的普通流语义）。ctx = 本次拨号（控制面连接 +
	// stream.open）的预算，取 CLI --timeout 的「打开」一份（默认 10s）——解析是另一次
	// 独立预算，最坏相加 20s。
	DialTerm(ctx context.Context, stateDir, hexID string) (io.ReadWriteCloser, error)
}

// 远程流终结原因（attach 的三态归因，design D5；closed/gone 与控制面 stream.end
// 的 reason 词表一致，conn = 连接级断开——不发 end 的那条）。
const (
	RemoteEndClosed = "closed"
	RemoteEndGone   = "gone"
	RemoteEndConn   = "conn"
)

// RemoteEndError 远程流的终结错误（适配器 Read 排干余量后的终结返回）。包装
// io.EOF——errors.Is(err, io.EOF) 成立；errors.As 取 Reason 出三态文案。
type RemoteEndError struct{ Reason string }

func (e *RemoteEndError) Error() string {
	switch e.Reason {
	case RemoteEndClosed:
		return "对端已关闭流（closed）"
	case RemoteEndGone:
		return "与主机的流被收尾（gone）"
	case RemoteEndConn:
		return "与守护进程的连接断开"
	}
	return "流已终结（" + e.Reason + "）"
}

func (e *RemoteEndError) Unwrap() error { return io.EOF }

// remoteEndMessage 远程 attach 的流终结三态文案（design D5 表；与本地面「断链」
// 单一文案区分——这是控制面层的归因，term 层 ENDED 优先先到先解释）。closed 的
// 归因如实带上「也可能是本端慢」（停滞超 60s 出口侧断腿不发 ENDED，r1 P1-5）。
func remoteEndMessage(name string, reason string) string {
	switch reason {
	case RemoteEndGone:
		return "与主机的流被收尾（主机会话不可达或上行过快）；会话 " + name +
			" 仍在目标主机运行，可重新 attach：homeway term attach " + name + " --host <ref>"
	case RemoteEndClosed:
		return "对端已关闭连接（term 服务退出或会话收工；也可能是本端长时间停止读取、" +
			"出口侧慢腿自治收尾了本腿——停滞超 60s 断腿不发 ENDED）"
	case RemoteEndConn:
		return "与守护进程的连接断开；可重新执行命令重连"
	}
	return "与主机的流已终结（" + reason + "）；可重新 attach：homeway term attach " + name + " --host <ref>"
}
