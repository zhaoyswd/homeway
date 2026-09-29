package hostsession

// options.go — 会话构造的注入面（host-registry-daemon D1/A2）。
//
// Options 字段分工：
//   - BridgeFactory：回环桥构造接缝。实现（bridgeHost）留守 cshared——桥是手机侧能力
//     （App 沙箱内的 UDS 桥）；daemon 传 nil = 无桥直通（桌面直拨隧道端口，桥 socket
//     在桌面根本不出现——「回环桥 socket 路径全会话共享」的并发反例由此消解，D2）。
//   - StrictIdentity：身份降级策略（r1 N2）。daemon = true：SourceEphemeral（身份目录
//     不可持久化）视为该主机会话 failed（reason=identity_ephemeral，可重试）——杜绝
//     「每次重启换临时钥匙在出口多占一条设备记录」；手机 = false 保持现状（打警告
//     继续——手机语义「无论如何先连上」）。
//   - Observer（状态迁移观察者，daemon 事件面消费）：随 1.3 状态机（Session）一道落。

import (
	"context"
	"net"
	"time"
)

// Bridge 服务会话回环桥的最小面（实现留守 cshared 的 bridgeHost 经方法包装满足）。
// 只露状态机要用的四件事：起、停、鉴权 blob（状态面分发）、socket 路径（状态面分发）。
type Bridge interface {
	Start()
	Stop()
	// AuthHex 桥鉴权首包 blob 的 hex（魔数+令牌）：只经本进程内存到消费方，
	// 不落盘、不进日志/诊断报告（cshared bridgeHost.authHex 同语义）。
	AuthHex() string
	// SockJSON 三座桥的 socket 路径串（files/term/speedtest；空串 = 该桥不在）。
	SockJSON() (files, term, speed string)
}

// BridgeFactory 服务会话回环桥的构造接缝：cfg 推桥目录（手机侧从 IdentityDir 推得）、
// dial = 「经当前会话拨出口本机端口」的回调（重建换会话后自动落到新会话上——
// healingDialCurrent 动态取当前会话，cshared 同款）。
type BridgeFactory func(cfg Config, logf Logf, dial func(ctx context.Context, port uint16) (net.Conn, error), dialTimeout time.Duration) Bridge

// Options 会话构造注入面（见文件头注释；零值 = 无桥、非严格身份）。
type Options struct {
	BridgeFactory  BridgeFactory
	StrictIdentity bool
}
