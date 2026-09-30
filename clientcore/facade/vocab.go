package facade

// vocab.go — 控制面契约词汇的真源（自 internal/control/proto.go 迁入，4a 任务 1.1；
// spec daemon-control-plane 冻结的受控枚举：操作名、错误码、订阅域、事件 kind 与
// 载荷字段、reach.tier、stream.end 原因——只增不改，新增走后续 spec delta）。
// 常量值逐字不变（wire 零改动）；internal/control 保传输段（帧封装/握手与请求响应
// wire 体），引用本包词汇不自定义。

import "errors"

// ---------- 错误码表 ----------

// 错误码表（spec「请求/响应与错误码表」，只增不改；连接列 = 是否断连）。
// 常量名为错误码字符串（Code* 前缀）；帧/总线层的 error 哨兵（Err* 前缀）另见
// bus.go（ErrCursorStale/ErrCursorFuture）。
const (
	CodeUnknownOp       = "unknown_op"       // 未知操作名（不断连）
	CodeNoStream        = "no_stream"        // 未知/已关闭的 streamId（不断连）
	CodeBadJSON         = "bad_json"         // 控制类 body 非法 JSON（断连）
	CodeBadRequest      = "bad_request"      // 载荷字段缺失/类型不符/值域外（不断连）
	CodeBadFrame        = "bad_frame"        // 帧长超限/非法 op（断连；超限在读 body 前）
	CodeNotReady        = "not_ready"        // 守护进程未就绪（不断连）
	CodeShuttingDown    = "shutting_down"    // 收工中（不断连）
	CodeHostExists      = "host_exists"      // 重复添加同后端（不断连）
	CodeNoHost          = "no_host"          // 主机不存在（不断连）
	CodeBadToken        = "bad_token"        // token 非法（不断连）
	CodeHostUnreachable = "host_unreachable" // host.add 验证结论为全不可达且未带 force（不入表；不断连；host-cli 3b 只增）
	CodeStreamRefused   = "stream_refused"   // 流打开被拒（含在册流超上限；不断连）
	CodeCursorStale     = "cursor_stale"     // 订阅游标过旧/代际失配（resync 语义；不断连）
)

// ---------- 操作名 ----------

// 操作名（spec 初始集，只增不改）。
const (
	OpDaemonStatus      = "daemon.status"
	OpHostAdd           = "host.add"
	OpHostRemove        = "host.remove"
	OpHostList          = "host.list"
	OpSnapshotGet       = "snapshot.get"
	OpEventsSubscribe   = "events.subscribe"
	OpEventsUnsubscribe = "events.unsubscribe"
	OpStreamOpen        = "stream.open"
	OpStreamClose       = "stream.close"
)

// ---------- reach.tier ----------

// reach.tier 受控枚举（spec「命令归属规则」：direct|relay|skipped，只增不改）。
const (
	ReachTierDirect  = "direct"  // 有直连端点应答
	ReachTierRelay   = "relay"   // 直连全无应答且中继有应答
	ReachTierSkipped = "skipped" // force 跳过探测（端点未实测语义）
)

// ---------- 订阅域 ----------

// 订阅域词表（spec 初始集，只增不改）。
const (
	DomainLink     = "link"
	DomainSession  = "session"
	DomainTransfer = "transfer"
	DomainLog      = "log"
	DomainTerm     = "term"
)

// ---------- 事件 kind 与归属 ----------

// 事件 kind 词表（受控枚举，只增不改）。
const (
	KindLinkChanged         = "link.changed"
	KindSessionAdded        = "session.added"
	KindSessionRemoved      = "session.removed"
	KindSessionStateChanged = "session.state_changed"
	KindSessionLadder       = "session.ladder"
	KindSessionRebuild      = "session.rebuild"
	KindSessionDiag         = "session.diag" // 词表冻结；自 4a §6.3 起发射（spec「诊因事件词表」）
	KindTransferSample      = "transfer.sample"
	KindLogLine             = "log.line"
	KindTermSessionUpdated  = "term.session_updated" // kind 值冻结；载荷字段初始集为空（后续 delta 增补）
	KindTermEnded           = "term.ended"           // 同上
)

// kindDomains kind → 域 的唯一归属表（Publish 校验 + fixtures 对拍真源）。
var kindDomains = map[string]string{
	KindLinkChanged:         DomainLink,
	KindSessionAdded:        DomainSession,
	KindSessionRemoved:      DomainSession,
	KindSessionStateChanged: DomainSession,
	KindSessionLadder:       DomainSession,
	KindSessionRebuild:      DomainSession,
	KindSessionDiag:         DomainSession,
	KindTransferSample:      DomainTransfer,
	KindLogLine:             DomainLog,
	KindTermSessionUpdated:  DomainTerm,
	KindTermEnded:           DomainTerm,
}

// validDomains 订阅域词表。
var validDomains = map[string]bool{
	DomainLink: true, DomainSession: true, DomainTransfer: true, DomainLog: true, DomainTerm: true,
}

// ---------- 事件载荷字段表（spec「事件流」初始集落实现；字段只增不改） ----------

// LinkChangedPayload link.changed 载荷。
type LinkChangedPayload struct {
	Host  string `json:"host"`
	Via   string `json:"via"`
	Ep    string `json:"ep"`
	RttMs int64  `json:"rttMs"`
	At    int64  `json:"at"`
}

// SessionAddedPayload session.added 载荷。
type SessionAddedPayload struct {
	Host    string `json:"host"`
	Name    string `json:"name"`
	AddedAt int64  `json:"addedAt"`
}

// SessionRemovedPayload session.removed 载荷。
type SessionRemovedPayload struct {
	Host   string `json:"host"`
	Reason string `json:"reason"`
}

// SessionStateChangedPayload session.state_changed 载荷（state/reason 值域随
// hostsession 状态机：idle/starting/ready/failed/stopping）。
type SessionStateChangedPayload struct {
	Host   string `json:"host"`
	State  string `json:"state"`
	Reason string `json:"reason"`
}

// SessionLadderPayload session.ladder 载荷（发射点归 facade 期，词表先行）。
type SessionLadderPayload struct {
	Host    string `json:"host"`
	Level   string `json:"level"`
	Outcome string `json:"outcome"`
	Cause   string `json:"cause"`
}

// SessionRebuildPayload session.rebuild 载荷。
type SessionRebuildPayload struct {
	Host   string `json:"host"`
	Reason string `json:"reason"`
}

// SessionDiagPayload session.diag 载荷（词表冻结；自 4a §6.3 起发射；reason 值初始集
// gated/budget/probe_window——只增不改）。
type SessionDiagPayload struct {
	Host   string `json:"host"`
	Reason string `json:"reason"`
}

// 诊因原因值（spec「诊因事件词表」）。
const (
	DiagGated       = "gated"
	DiagBudget      = "budget"
	DiagProbeWindow = "probe_window"
)

// TransferSamplePayload transfer.sample 载荷。
type TransferSamplePayload struct {
	Host    string `json:"host"`
	RxBytes int64  `json:"rxBytes"`
	TxBytes int64  `json:"txBytes"`
}

// LogLinePayload log.line 载荷。
type LogLinePayload struct {
	Level string `json:"level"`
	Msg   string `json:"msg"`
}

// ---------- 流式通道词汇 ----------

// 流 kind 值域（spec「流式通道」：受控枚举只增——term 为初始集，files 自 files-cli
// 期起〔files 命令面的远程取放〕；值域外的 kind 由控制面按既有 bad_request 处理）。
const (
	StreamKindTerm  = "term"
	StreamKindFiles = "files"
)

// stream.end 的 reason 受控枚举（spec：closed = 对端/前端主动关闭；gone = 目标
// 主机不可达或主机会话收工——控制面层的本地原因。term 协议的 ENDED 词表由 term
// 协议自身承载，控制面不重定义）。
const (
	StreamEndClosed = "closed"
	StreamEndGone   = "gone"
)

// ---------- facade 哨兵错误 ----------

// ErrSessionNotCurrent 会话不在（收工/重建窗口）的 facade 哨兵——hostsession 侧
// 同名哨兵的 facade 面（§3.3：绑定层 ErrSessionNotCurrent 映射在此哨兵上，
// errors.Is 可判；语义 = 重建感知拨号在重建窗口/会话收工时的可区分错误）。
var ErrSessionNotCurrent = errors.New("服务会话不在（收工/重建窗口）")
