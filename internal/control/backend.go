package control

// backend.go — 服务器对宿主（internal/daemon）的窄依赖面。control 不 import
// daemon（依赖方向单向：daemon 装配 control）；Backend 由 daemon 侧实现。

import (
	"context"
	"errors"
	"net"
)

// Backend 哨兵错误（server 层映射到错误码表）。
var (
	// ErrBackendHostExists 同 token 重复添加（host_exists）。
	ErrBackendHostExists = errors.New("host 已在表中")
	// ErrBackendBadToken token 本地解析失败（bad_token）。
	ErrBackendBadToken = errors.New("token 非法")
	// ErrBackendNoHost 主机不在表（no_host）。
	ErrBackendNoHost = errors.New("host 不在表中")
	// ErrBackendHostUnreachable host.add 验证结论为全不可达且未带 force
	//（host_unreachable，不入表；host-cli 3b）。
	ErrBackendHostUnreachable = errors.New("host 全不可达（探测无应答且未带 force）")
	// ErrBackendNoSession 主机在表但会话不在（收工/重建窗口/未就绪）——流打开
	// 被拒（stream_refused）。
	ErrBackendNoSession = errors.New("会话不在（收工/重建窗口）")
)

// Backend 控制面服务器的宿主面（daemon 装配时实现；全部方法必须可并发调用）。
// 锁序（design D5 快照路径②）：HostStates 内部先拷贝会话集合再逐会话无锁快照，
// **不得**在持 Registry.mu 时回调 control。
type Backend interface {
	// ServerVersion 服务端版本（welcome/daemon.status）。
	ServerVersion() string
	// RolesStatus 角色状态面（daemon.status）。
	RolesStatus() []RoleBrief
	// HostBriefs 主机登记面（host.list / snapshot.get 的静态部分）。
	HostBriefs() []HostBrief
	// AddHost 解析 + 有界旁路连通性验证 + 入表（host-cli 3b；internal API 非 wire
	// 契约）。force = 跳过服务端探测直接入表（结论 tier=skipped）；全不可达且未带
	// force → ErrBackendHostUnreachable（不入表、不产生任何注册表副作用）。
	AddHost(name, token string, force bool) (HostAddResult, error)
	// RemoveHost 摘除主机。
	RemoveHost(id string) error
	// HostStates 各主机动态面（state/reason/link/stats——各会话无锁快照汇成）。
	HostStates() []HostState
	// DialStream 打开一条到目标主机指定 kind 服务（term=核内约定端口 7724、
	// files=7802——端口映射在 daemon 绑定层，kind 值域真源在 facade vocab）的隧道
	// 连接。控制面对上层协议纯字节透传（spec「流式通道」）。绑定层进程内接口
	//（非 facade 语义、无 wire 面）；全部方法必须可并发调用。
	DialStream(ctx context.Context, kind, host string) (net.Conn, error)
	// NotReady 宿主未就绪（如 client 角色未运行/注册表未挂）——host.*/snapshot
	// 类操作报 not_ready。
	NotReady() bool
	// DemandStatus 各主机最近一拍的需求判定（daemon.status 的 demand 段，4a
	// §6.2——词表只增；宿主无需求面时返回 nil）。
	DemandStatus() []HostDemandBrief

	// ---------- 承载面（3e 只增 9 op 的宿主面；语义全在 facade.Carriers） ----------
	//
	// 错误族：主机不在表（host 载荷值域）= ErrBackendNoHost → no_host；值域外/
	// 冲突/监听失败等 = 其它 error → bad_request（错误码零新增，dispatch 层统一
	// 映射）。busy 是 SpeedtestStart 成功载荷里的 reason，不占错误族。

	// ForwardAdd 建规则并当场起监听（失败不入表）。
	ForwardAdd(args ForwardAddArgs) (ForwardAddResult, error)
	// ForwardRemove 删规则（不强关在世连接）。
	ForwardRemove(args ForwardRemoveArgs) error
	// ForwardList 规则表快照（host 空 = 全部）。
	ForwardList(host string) ForwardListResult
	// SocksOn 开 SOCKS 监听（listen 0 = 沿用记忆/1080），返回实际端口。
	SocksOn(host string, listen uint16) (SocksOnResult, error)
	// SocksOff 关监听（显式 RST 在世连接；端口记忆保留），返回记忆端口。
	SocksOff(host string) (SocksOffResult, error)
	// SocksStatus 各主机承载态快照。
	SocksStatus() SocksStatusResult
	// SpeedtestStart 开跑（立即返回 waiting/busy 相位——busy = 成功载荷 reason；
	// host 不在表 = ErrBackendNoHost）。
	SpeedtestStart(args SpeedtestStartArgs) (SpeedtestStartAck, error)
	// SpeedtestStatus 该主机运行态（无运行面 = Phase 空闲形态；host 不在表 =
	// ErrBackendNoHost）。
	SpeedtestStatus(host string) (SpeedtestStatusResult, error)
	// SpeedtestCancel 取消该主机当前轮（幂等；host 不在表 = ErrBackendNoHost）。
	SpeedtestCancel(host string) error
}
