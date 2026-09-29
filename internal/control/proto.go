package control

// proto.go — 控制面 JSON body 结构与全部词表（spec daemon-control-plane 冻结的
// 受控枚举：订阅域、事件 kind 与载荷字段、操作名、错误码、流 kind 与 stream.end
// 原因——只增不改，新增走后续 spec delta）。
//
// JSON 面纪律（spec「词表冻结」三层）：解码忽略未知字段（encoding/json 默认行为，
// 全部结构体不加 DisallowUnknownField）；编码只要求结构等价（键序不敏感）；二进制
// 帧逐字节冻结由 fixtures 对拍守住（fixtures_test.go）。

import "encoding/json"

// ---------- 握手与生命周期（D5 生命周期） ----------

// FrontendInfo 前端标识（hello 携带；kind 为自由字符串——spec 未冻结前端 kind 词表，
// 服务端只回显进日志，不校验值域）。
type FrontendInfo struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// HelloBody 握手帧 body（前端首发）。
type HelloBody struct {
	ProtoVersion int          `json:"protoVersion"`
	Frontend     FrontendInfo `json:"frontend"`
}

// WelcomeBody 握手应答 body：serverVersion + 代际 generation（每次守护进程启动
// 重新随机）+ serverSeq（应答时刻的总线序号）。
type WelcomeBody struct {
	ServerVersion string `json:"serverVersion"`
	Generation    string `json:"generation"`
	ServerSeq     uint64 `json:"serverSeq"`
}

// ReloadBody reload 信号 body（v1 唯一原因 = proto_mismatch）。
type ReloadBody struct {
	Reason string `json:"reason"`
}

// reload/goodbye/cursor 原因的稳定值（引用错误码表或其子集）。
const (
	ReloadProtoMismatch = "proto_mismatch"
	GoodbyeOverrun      = "overrun"
)

// GoodbyeBody 告别帧 body：reason 引用错误码表的稳定字符串（overrun/bad_frame/
// bad_json/shutting_down…）。
type GoodbyeBody struct {
	Reason string `json:"reason"`
}

// ResyncBody resync 帧 body（v1 词表冻结、服务端无发射场景——订阅原子性由总线锁
// 保证；帧可解码，留给后续版本的服务端主动重同步）。
type ResyncBody struct {
	Reason string `json:"reason"`
}

// ---------- 请求/响应 ----------

// RequestBody 请求帧 body。Op 为操作名（词表见 opHandlers 注册表）；Args 为该操作
// 的载荷（各操作自带结构，见 args.go 区域）。
type RequestBody struct {
	Corr uint64          `json:"corr"`
	Op   string          `json:"op"`
	Args json.RawMessage `json:"args,omitempty"`
}

// ResponseBody 响应帧 body。Ok=false 时 Error 为错误码（稳定字符串，表见下）；
// Ok=true 时 Result 为操作各自的载荷。Ok=false 不代表连接有问题——错误码表里
// 只有 bad_json/bad_frame 断连，其余均不断连。
type ResponseBody struct {
	Corr   uint64          `json:"corr"`
	Ok     bool            `json:"ok"`
	Error  string          `json:"error,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}

// 错误码表（spec「请求/响应与错误码表」，只增不改；连接列 = 是否断连）。
// 常量名为错误码字符串（Code* 前缀）；帧/总线层的 error 哨兵（Err* 前缀）另见
// frame.go / bus.go。
const (
	CodeUnknownOp     = "unknown_op"     // 未知操作名（不断连）
	CodeNoStream      = "no_stream"      // 未知/已关闭的 streamId（不断连）
	CodeBadJSON       = "bad_json"       // 控制类 body 非法 JSON（断连）
	CodeBadRequest    = "bad_request"    // 载荷字段缺失/类型不符/值域外（不断连）
	CodeBadFrame      = "bad_frame"      // 帧长超限/非法 op（断连；超限在读 body 前）
	CodeNotReady      = "not_ready"      // 守护进程未就绪（不断连）
	CodeShuttingDown  = "shutting_down"  // 收工中（不断连）
	CodeHostExists    = "host_exists"    // 重复添加同后端（不断连）
	CodeNoHost        = "no_host"        // 主机不存在（不断连）
	CodeBadToken      = "bad_token"      // token 非法（不断连）
	CodeStreamRefused = "stream_refused" // 流打开被拒（含在册流超上限；不断连）
	CodeCursorStale   = "cursor_stale"   // 订阅游标过旧/代际失配（resync 语义；不断连）
)

// ---------- 操作词表与各操作载荷 ----------

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

// HostAddArgs host.add 载荷（3a 语义 = 仅「解析入表」：token 语法/本地解码校验；
// 连通性验证与三档结论归 host 命令面能力域[3b]，结果以载荷字段只增扩展——spec
// 「命令归属规则」）。
type HostAddArgs struct {
	Name  string `json:"name,omitempty"`
	Token string `json:"token"`
}

// HostAddResult host.add 成功载荷。
type HostAddResult struct {
	ID      string `json:"id"`
	Name    string `json:"name,omitempty"`
	AddedAt int64  `json:"addedAt"`
}

// HostRemoveArgs host.remove 载荷（host = peerID hex）。
type HostRemoveArgs struct {
	Host string `json:"host"`
}

// HostListResult host.list 成功载荷。
type HostListResult struct {
	Hosts []HostBrief `json:"hosts"`
}

// HostBrief 主机静态信息（登记面，无会话动态）。
type HostBrief struct {
	ID      string `json:"id"`
	Name    string `json:"name,omitempty"`
	AddedAt int64  `json:"addedAt"`
}

// SubscribeArgs events.subscribe 载荷。View = 前端订阅视图声明，本期只回显
// （随订阅确认/快照可见），MUST NOT 参与需求判定——信号源归 facade 期（spec
// 「门控信号词表与策略边界」）。Cursor = 上次收到的游标（缺省 = 纯在线订阅，
// 前端标准流程是 snapshot.get 后带 cursor 订阅以补齐快照与订阅之间的缝隙）。
// Generation = 游标所属代际（前端从上次 welcome/snapshot 记下；非空且与当前
// 不符 → cursor_stale——spec「守护进程重启后旧游标失效」场景的服务端检测位；
// 字段只增：旧前端不带此字段时退化为「仅重放窗检查」）。
type SubscribeArgs struct {
	Domains    []string `json:"domains"`
	Cursor     *uint64  `json:"cursor,omitempty"`
	View       string   `json:"view,omitempty"`
	Generation string   `json:"generation,omitempty"`
}

// SubscribeResult 订阅确认载荷（view 回显 + 生效游标 + 代际）。
type SubscribeResult struct {
	Domains    []string `json:"domains"`
	Cursor     uint64   `json:"cursor"`
	View       string   `json:"view,omitempty"`
	Generation string   `json:"generation"`
}

// UnsubscribeArgs events.unsubscribe 载荷（未订阅域 = 幂等成功，无错误码）。
type UnsubscribeArgs struct {
	Domains []string `json:"domains"`
}

// UnsubscribeResult 退订确认载荷（生效域集合）。
type UnsubscribeResult struct {
	Domains []string `json:"domains"`
}

// StreamOpenArgs stream.open 载荷 = 寻址（kind 初始集仅 term；腿参数/caps 不在
// 控制面词表——term 协议语义端到端归前端）。
type StreamOpenArgs struct {
	Kind string `json:"kind"`
	Host string `json:"host"`
}

// StreamOpenResult stream.open 成功载荷。
type StreamOpenResult struct {
	StreamID uint32 `json:"streamId"`
}

// StreamCloseArgs stream.close 载荷。
type StreamCloseArgs struct {
	StreamID uint32 `json:"streamId"`
}

// ---------- 事件流（域与 kind 词表、载荷字段表） ----------

// 订阅域词表（spec 初始集，只增不改）。
const (
	DomainLink     = "link"
	DomainSession  = "session"
	DomainTransfer = "transfer"
	DomainLog      = "log"
	DomainTerm     = "term"
)

// 事件 kind 词表（受控枚举，只增不改）。
const (
	KindLinkChanged         = "link.changed"
	KindSessionAdded        = "session.added"
	KindSessionRemoved      = "session.removed"
	KindSessionStateChanged = "session.state_changed"
	KindSessionLadder       = "session.ladder"
	KindSessionRebuild      = "session.rebuild"
	KindSessionDiag         = "session.diag" // 词表冻结但本期不发射（spec「诊因事件词表」）
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

// EventBody 事件帧 body：seq 自包含（全局单调、随代际唯一化）；payload 为该 kind 的
// 载荷（字段表见 spec，只增不改）。
type EventBody struct {
	Seq     uint64          `json:"seq"`
	Domain  string          `json:"domain"`
	Kind    string          `json:"kind"`
	Payload json.RawMessage `json:"payload,omitempty"`
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

// SessionDiagPayload session.diag 载荷（词表冻结、本期不发射；reason 值初始集
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

// ---------- 流式通道 ----------

// 流 kind 初始集（spec「流式通道」：kind 初始集仅 term）。
const StreamKindTerm = "term"

// stream.end 的 reason 受控枚举（spec：closed = 对端/前端主动关闭；gone = 目标
// 主机不可达或主机会话收工——控制面层的本地原因。term 协议的 ENDED 词表由 term
// 协议自身承载，控制面不重定义）。
const (
	StreamEndClosed = "closed"
	StreamEndGone   = "gone"
)

// StreamEndBody stream.end 帧 body（JSON，非流 DATA 二进制 body）。
type StreamEndBody struct {
	StreamID uint32 `json:"streamId"`
	Reason   string `json:"reason"`
}

// ---------- daemon.status / snapshot.get 载荷 ----------

// DaemonStatusResult daemon.status 成功载荷（版本/代际/角色/主机摘要+链路态）。
type DaemonStatusResult struct {
	ServerVersion string      `json:"serverVersion"`
	Generation    string      `json:"generation"`
	Seq           uint64      `json:"seq"`
	Roles         []RoleBrief `json:"roles"`
	Hosts         []HostState `json:"hosts"`
}

// RoleBrief 角色状态摘要。Reason = 最近一次失败原因（running 态为空；spec
// 「状态面呈现 failed + 原因」——此前只进 events.log、状态面看不到，exec-r1 B10；
// 字段只增，旧前端忽略）。
type RoleBrief struct {
	Name     string `json:"name"`
	State    string `json:"state"`
	Restarts int    `json:"restarts"`
	Reason   string `json:"reason,omitempty"`
}

// HostState snapshot.get / daemon.status 里一台主机的动态面（各会话无锁快照汇成——
// 锁序三路径之②：Registry.mu 拷贝集合 → 会话无锁快照 → 末读总线 seq）。
type HostState struct {
	ID     string    `json:"id"`
	Name   string    `json:"name,omitempty"`
	State  string    `json:"state"`
	Reason string    `json:"reason,omitempty"`
	Link   *HostLink `json:"link,omitempty"`
	Stats  *HostRxTx `json:"stats,omitempty"`
}

// HostLink 链路态（via/ep/rttMs/at）。
type HostLink struct {
	Via   string `json:"via"`
	Ep    string `json:"ep"`
	RttMs int64  `json:"rttMs"`
	At    int64  `json:"at"`
}

// HostRxTx 流量面。
type HostRxTx struct {
	RxBytes int64 `json:"rxBytes"`
	TxBytes int64 `json:"txBytes"`
}

// SnapshotResult snapshot.get 成功载荷（快照带当时序号 seq：前端随后带 cursor=seq
// 订阅续播——「快照 + 从游标续播」取到完整状态）。
type SnapshotResult struct {
	Seq        uint64      `json:"seq"`
	Generation string      `json:"generation"`
	Hosts      []HostState `json:"hosts"`
}
