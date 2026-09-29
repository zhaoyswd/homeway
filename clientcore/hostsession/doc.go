// hostsession — 出口会话与服务会话状态机的共享核（host-registry-daemon D1）。
//
// 提取自 clientcore/cmd/clientcore（cshared/package main，基线 796c0fb）：手机面
// （.so 经 cshared 壳引用）与桌面守护进程（internal/daemon 直构）共用同一份会话
// 状态机——提取不编语义、不改节拍（常量原值搬迁，connection-lifecycle 是节拍真源）。
//
// 边界（D1 清单）：
//   - 随迁：Config/Normalize、ExitSession 会话传输面（BuildExitSession）、共享恢复
//     阶梯（RecoverLevel/RecoverDeps/RunRecoverLadder/RecoverGate）、端点解析、
//     Logf 族、服务会话状态机（Session + Default 单例管理器 + StatusSnapshot）；
//   - 留守 cshared：隧道域编排（tunmode）、恢复入口 runRecoverAt/recoverTunnelReady
//     （经壳引用本包阶梯）、回环桥实现（bridgeHost，经 Options.BridgeFactory 注入）、
//     patrolrule、probe_lib 20 导出与 JSON 包装。
//
// 两处登记的非串扰共享点（r1 A2，按评审口径登记不动）：
//  1. wtransport identity_store 的阻塞式 LOCK_EX——多会话**建会话时**短暂串行
//     （每会话一次、毫秒级，无运行期竞争）；
//  2. 本包 recover.go 的三个阶梯预算包级 var——只读共享、仅同包测试改写。
//
// 手机单会话编排约束（「同钥匙两类会话不并发」）属 App/扩展侧编排，不下沉本包：
// Default() 只是单例容器，不承载该约束。
package hostsession
