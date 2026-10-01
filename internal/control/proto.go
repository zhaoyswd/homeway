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
// 见 facade/demand.go 与 spec「门控信号词表」；服务端不校验值域）。
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
	Corr  uint64 `json:"corr"`
	Ok    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// Detail 可行动归因原文（FIX-50，只增字段）：稳定错误码保持窄值域，具体的
	// 「谁占着端口/为什么拒绝」以原文随行——否则 CLI 只能吞成 bad_request 文案，
	// 或自己去猜（forward add 的「现场诊断」正是这个缺口的下游产物）。
	Detail string          `json:"detail,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}

// 错误码表（Code*）与操作名词表（Op*）已迁 clientcore/facade/vocab.go（4a 任务
// 1.1：词汇真源一处定义；本包引用 facade 词汇，不自定义）。

// HostAddArgs host.add 载荷（3b 起含服务端有界连通性验证——验证契约本体见
// host-management；结论以 HostAddResult.reach 字段只增返回）。
type HostAddArgs struct {
	Name  string `json:"name,omitempty"`
	Token string `json:"token"`
	// Force 「仍然添加」逃生口（字段只增）：true = 跳过服务端探测直接入表
	//（端点未实测，首次连接时补全）。token 非法不被 force 绕过（语法校验前置）。
	Force bool `json:"force,omitempty"`
}

// HostAddResult host.add 成功载荷。
type HostAddResult struct {
	ID      string     `json:"id"`
	Name    string     `json:"name,omitempty"`
	AddedAt int64      `json:"addedAt"`
	Reach   *HostReach `json:"reach,omitempty"` // 3b 只增：验证三档结论（nil 不出现——服务端恒填）
}

// （reach.tier 词表 ReachTierDirect/Relay/Skipped 已迁 clientcore/facade/vocab.go。）
// HostReach host.add 成功载荷的验证结论（tier=none 不出现在成功载荷——全不可达
// 用错误码 host_unreachable 表达，不入表不断连）。
type HostReach struct {
	Tier   string        `json:"tier"`
	BestEp string        `json:"bestEp,omitempty"` // 实测最优端点（RTT 最小的对应档活端点；skipped 无
	RttMs  int64         `json:"rttMs,omitempty"`
	Tested []ReachTested `json:"tested"` // 逐端点实测集（恒非 nil；skipped = 空数组）
}

// ReachTested tested[] 单端点结论（只含应答端点）。
type ReachTested struct {
	Ep    string `json:"ep"`
	Relay bool   `json:"relay"`
	RttMs int64  `json:"rttMs"`
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

// SubscribeArgs events.subscribe 载荷。View = 前端订阅视图声明（回显 + 参与需求合成，
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

// ---------- forward / socks / speedtest（3e 只增，design D6） ----------
//
// host 载荷 = peerID hex（CLI 侧 resolveHostTarget 先行解析，同 term/files）。
// 错误码零新增：值域外/冲突 = bad_request、主机不在表 = no_host（用例锁死映射）。

// ForwardAddArgs forward.add 载荷。TargetIP 空 = 出口自己；TargetPort 0 = 同监听端口。
type ForwardAddArgs struct {
	Host       string `json:"host"`
	Listen     uint16 `json:"listen"`
	TargetIP   string `json:"targetIp,omitempty"`
	TargetPort uint16 `json:"targetPort,omitempty"`
}

// ForwardAddResult forward.add 成功载荷（建成的规则面，listening 态）。
type ForwardAddResult struct {
	Rule ForwardRuleBrief `json:"rule"`
}

// ForwardRemoveArgs forward.remove 载荷。
type ForwardRemoveArgs struct {
	Host   string `json:"host"`
	Listen uint16 `json:"listen"`
}

// ForwardRemoveResult forward.remove 成功载荷。
type ForwardRemoveResult struct {
	Removed bool `json:"removed"`
}

// ForwardListArgs forward.list 载荷（host 空 = 全部）。
type ForwardListArgs struct {
	Host string `json:"host,omitempty"`
}

// ForwardRuleBrief forward.list 单条（规则 + 运行态——listening/failed+原因/conns，
// 镜像手机 pfState 口径的桌面版）。
type ForwardRuleBrief struct {
	Host       string `json:"host"`
	Listen     uint16 `json:"listen"`
	TargetIP   string `json:"targetIp,omitempty"`
	TargetPort uint16 `json:"targetPort,omitempty"`
	State      string `json:"state"`
	Err        string `json:"err,omitempty"`
	Conns      int    `json:"conns"`
	Rejected   int    `json:"rejected,omitempty"` // 超并发上限被拒计数（exec-r1 B3-b）
}

// ForwardListResult forward.list 成功载荷。
type ForwardListResult struct {
	Forwards []ForwardRuleBrief `json:"forwards"`
}

// SocksOnArgs socks.on 载荷（listen 0 = 沿用记忆端口，无记忆则 1080）。
type SocksOnArgs struct {
	Host   string `json:"host"`
	Listen uint16 `json:"listen,omitempty"`
}

// SocksOnResult socks.on 成功载荷（实际监听端口）。
type SocksOnResult struct {
	Listen uint16 `json:"listen"`
}

// SocksOffArgs socks.off 载荷。
type SocksOffArgs struct {
	Host string `json:"host"`
}

// SocksOffResult socks.off 成功载荷（Listen = 记忆保留的端口，下次 on 缺省沿用）。
type SocksOffResult struct {
	Listen uint16 `json:"listen"`
}

// SocksBrief socks.status 单条（off 也出现——Listen = 记住的端口，拍板②）。
type SocksBrief struct {
	Host   string `json:"host"`
	On     bool   `json:"on"`
	Listen uint16 `json:"listen"`
	Conns  int    `json:"conns"`
	Err    string `json:"err,omitempty"`
}

// SocksStatusResult socks.status 成功载荷。
type SocksStatusResult struct {
	Socks []SocksBrief `json:"socks"`
}

// SpeedtestStartArgs speedtest.start 载荷（0 = 手机口径默认；waitMs 0 = 不等——
// start 立即返回 waiting 相位、等待由 runner 状态机承载，r1 中-3）。
type SpeedtestStartArgs struct {
	Host     string `json:"host"`
	DownMs   int64  `json:"downMs,omitempty"`
	UpMs     int64  `json:"upMs,omitempty"`
	WarmupMs int64  `json:"warmupMs,omitempty"`
	Streams  int    `json:"streams,omitempty"`
	WaitMs   int64  `json:"waitMs,omitempty"`
}

// SpeedtestStartAck speedtest.start 成功载荷（waiting 或 busy——busy 是载荷里的
// reason，同手机信封形态、不占错误码表）。
type SpeedtestStartAck struct {
	Phase  string `json:"phase"`            // waiting | busy
	Reason string `json:"reason,omitempty"` // busy 时携带
}

// SpeedtestStatusArgs speedtest.status 载荷。
type SpeedtestStatusArgs struct {
	Host string `json:"host"`
}

// SpeedtestResultBrief speedtest 终态结果（镜像引擎 Result 字段名——与手机信封
// downBps/upBps/usageDown/usageUp/wallMs/reason 同名，CLI --json 对拍真源）。
type SpeedtestResultBrief struct {
	OK        bool    `json:"ok"`
	Reason    string  `json:"reason,omitempty"`
	Msg       string  `json:"msg,omitempty"`
	DownBps   float64 `json:"downBps,omitempty"`
	UpBps     float64 `json:"upBps,omitempty"`
	UsageDown int64   `json:"usageDown,omitempty"`
	UsageUp   int64   `json:"usageUp,omitempty"`
	WallMs    int64   `json:"wallMs,omitempty"`
}

// SpeedtestStatusResult speedtest.status 成功载荷：waiting 相位（waitRemainMs）
// 或引擎快照（phase/reason/usage/live/elapsedMs，字段名与手机 Status 信封一致）；
// 轮次到终态时 Result 携带完整结果（nil = 未到终态）。
type SpeedtestStatusResult struct {
	Host         string                `json:"host"`
	Waiting      bool                  `json:"waiting,omitempty"`
	WaitRemainMs int64                 `json:"waitRemainMs,omitempty"`
	Phase        string                `json:"phase"`
	Reason       string                `json:"reason,omitempty"`
	UsageDown    int64                 `json:"usageDown,omitempty"`
	UsageUp      int64                 `json:"usageUp,omitempty"`
	Dir          string                `json:"dir,omitempty"`
	Bytes        int64                 `json:"bytes,omitempty"`
	InstBps      float64               `json:"instBps,omitempty"`
	ElapsedMs    int64                 `json:"elapsedMs,omitempty"`
	Result       *SpeedtestResultBrief `json:"result,omitempty"`
}

// SpeedtestCancelArgs speedtest.cancel 载荷（只作用指定主机，不波及轮转，r1 低-8）。
type SpeedtestCancelArgs struct {
	Host string `json:"host"`
}

// SpeedtestCancelResult speedtest.cancel 成功载荷。
type SpeedtestCancelResult struct {
	Cancelled bool `json:"cancelled"`
}

// ---------- serve / relay 角色管理（3f 只增 10 op，role-management） ----------
//
// 幂等语义在成功载荷呈现（Action ∈ started|already / stopped|already / restarted），
// 不借道错误码；restart 无重建对象（角色停/未装配）= ErrBackendRoleStopped → CLI 侧
// 预检兜住（serve.status 先看状态），wire 理论不可达——错误码零新增。
// token 响应含完整凭证（socket 属主即凭证的既有边界内，CLI 侧 reveal 呈现）；
// status 面一律掩码（reveal 纪律）。

// RoleActionResult serve/relay start/stop/restart 的成功载荷（幂等 = 动作有无）。
type RoleActionResult struct {
	Action string `json:"action"` // started | already | stopped | already | restarted
}

// ServeStatusResult serve.status 成功载荷：期望态 + 运行态 + 领域观测面（peer 表 =
// 连接的 APP 设备；掩码纪律——TokenMask 只给指纹）。
type ServeStatusResult struct {
	Enabled    bool               `json:"enabled"` // 期望态（config serve.enabled）
	State      string             `json:"state"`   // running|stopping|stopped|failed|absent
	Reason     string             `json:"reason,omitempty"`
	ListenPort uint16             `json:"listenPort,omitempty"` // 实际监听口（含退让后真值）
	Published  []string           `json:"published,omitempty"`  // 最近一轮已公布公网端点
	TokenMask  string             `json:"tokenMask,omitempty"`  // 台账末行/在用 token 掩码指纹
	Endpoints  []string           `json:"endpoints,omitempty"`  // 当前 token 端点（类型标注版）
	Peers      []ServePeerBrief   `json:"peers"`
	DDNS       []ServeDDNSBrief   `json:"ddns,omitempty"`
	Intercept  ServeInterceptBits `json:"intercept"`
}

// ServePeerBrief serve peer 表单条（APP 设备维度）。
type ServePeerBrief struct {
	Dev      string `json:"dev"`      // devTag 短指纹
	TunnelIP string `json:"tunnelIp"` // 隧道侧 /32
	LastReg  int64  `json:"lastReg"`  // 最近成功注册（UnixMilli）
	IdleMs   int64  `json:"idleMs"`   // 距最近注册毫秒
}

// ServeDDNSBrief ddns 单域名解析自检状态。
type ServeDDNSBrief struct {
	Domain     string `json:"domain"`
	LagStreak  int    `json:"lagStreak"`
	WarnedLag  bool   `json:"warnedLag,omitempty"`
	WarnedAAAA bool   `json:"warnedAAAA,omitempty"`
}

// ServeInterceptBits 过境拦截计数（真凭据判据的同源计数面）。
type ServeInterceptBits struct {
	DialOK   uint64 `json:"dialOk"`
	DialFail uint64 `json:"dialFail"`
	Reject   uint64 `json:"reject"`
	Flows    uint64 `json:"flows"`
}

// ServeTokenResult serve.token 成功载荷（完整 hmw1 凭证——reveal 命令族）。
// Source = runtime（控制面运行态真源）| ledger（L2 台账末行——角色未装配/未铸出时
// 的降级路径，台账写入纪律下末行 = 最近在用 token）。
type ServeTokenResult struct {
	Token  string   `json:"token"`
	Source string   `json:"source"`
	Eps    []string `json:"endpoints,omitempty"`
}

// RelayStatusResult relay.status 成功载荷。**relay 侧看不到 APP**（在中继注册的是
// 出口、手机流量在 WG 密文里）——Backends 是出口维度，与 serve peer 表不同维。
type RelayStatusResult struct {
	Enabled   bool                `json:"enabled"`
	State     string              `json:"state"` // running|stopping|stopped|failed|absent
	Reason    string              `json:"reason,omitempty"`
	Listen    string              `json:"listen,omitempty"` // 实际监听地址（UDP）
	Advertise string              `json:"advertise,omitempty"`
	TokenMask string              `json:"tokenMask,omitempty"`
	Open      bool                `json:"open"`     // 是否开放注册（无鉴权形态）
	Assocs    int                 `json:"assocs"`   // 活跃客户端分配会话数
	Backends  []RelayBackendBrief `json:"backends"` // 注册的出口列表
}

// RelayBackendBrief 注册出口单条（label 短指纹 + 源地址 + 最近活跃 + 验证态——
// r1 低-14；中继只持 8 字节 label，看不到出口的 host 名/peerID）。
type RelayBackendBrief struct {
	Label       string `json:"label"`
	Addr        string `json:"addr,omitempty"`
	LastActive  int64  `json:"lastActive"` // UnixMilli；0 = 无记录
	Verified    bool   `json:"verified"`
	CtlVerified bool   `json:"ctlVerified"`
	HasCtl      bool   `json:"hasCtl"`
}

// RelayTokenResult relay.token 成功载荷（完整 rl1 凭证；Source 同 serve.token——
// relay 无台账，降级路径 = relay.key + config 离线推算〔D8a〕）。
type RelayTokenResult struct {
	Token  string   `json:"token"`
	Source string   `json:"source"` // runtime | derived
	Eps    []string `json:"endpoints,omitempty"`
}

// ---------- 事件流（域与 kind 词表、载荷字段表） ----------

// （订阅域 Domain*/事件 kind Kind* 词表、kindDomains 归属表与 validDomains 已迁
// clientcore/facade/vocab.go。）
// EventBody 事件帧 body：seq 自包含（全局单调、随代际唯一化）；payload 为该 kind 的
// 载荷（字段表见 spec，只增不改）。
type EventBody struct {
	Seq     uint64          `json:"seq"`
	Domain  string          `json:"domain"`
	Kind    string          `json:"kind"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// （事件载荷结构 *Payload 与诊因原因值 Diag* 已迁 clientcore/facade/vocab.go。）

// ---------- 流式通道 ----------

// （流 kind StreamKindTerm 与 stream.end 原因词表 StreamEndClosed/Gone 已迁
// clientcore/facade/vocab.go。）
// StreamEndBody stream.end 帧 body（JSON，非流 DATA 二进制 body）。
type StreamEndBody struct {
	StreamID uint32 `json:"streamId"`
	Reason   string `json:"reason"`
}

// ---------- daemon.status / snapshot.get 载荷 ----------

// DaemonStatusResult daemon.status 成功载荷（版本/代际/角色/主机摘要+链路态）。
// Demand = 各主机最近一拍的需求判定（4a §6.2：DemandSignal 的观测面，词表只增——
// 旧前端按未知字段忽略）。
type DaemonStatusResult struct {
	ServerVersion string            `json:"serverVersion"`
	Generation    string            `json:"generation"`
	Seq           uint64            `json:"seq"`
	Pid           int               `json:"pid,omitempty"` // 进程 pid（role-management 3f 只增：聚合 status 的进程层）
	Roles         []RoleBrief       `json:"roles"`
	Hosts         []HostState       `json:"hosts"`
	Demand        []HostDemandBrief `json:"demand,omitempty"`
}

// HostDemandBrief daemon.status demand 段单条（host + 最近一拍判定 active/reason/at；
// at = UnixMilli，0 = 从未判定）。
type HostDemandBrief struct {
	Host   string `json:"host"`
	Active bool   `json:"active"`
	Reason string `json:"reason"`
	At     int64  `json:"at"`
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
	ID      string    `json:"id"`
	Name    string    `json:"name,omitempty"`
	State   string    `json:"state"`
	Reason  string    `json:"reason,omitempty"`
	Link    *HostLink `json:"link,omitempty"`
	Stats   *HostRxTx `json:"stats,omitempty"`
	AddedAt int64     `json:"addedAt,omitempty"` // 登记面添加时间（HostRecord.AddedAt 填充；host-cli 3b M1 只增——host status 详面/--json 的「添加时间」数据源）
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
