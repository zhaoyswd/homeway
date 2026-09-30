// Package facade — 客户端会话面的唯一语义真源（Go 进程内面；openspec
// clientcore-facade §4a）。
//
// 控制面 UDS（internal/control，daemon-control-plane spec）与未来任何前端绑定都是
// 本包的绑定：词汇（操作名/错误码/订阅域/事件 kind 与载荷）、事件总线（序号/游标/
// 重放/订阅次序不变量）、版本与能力空间台账只在 facade 一处定义与实现，绑定层
// 引用不自定义。依赖方向单向：facade → hostsession + pkg/{proto,probe}；
// facade MUST NOT import 根 internal/（clientcore 子树纯洁——嵌套子模块后路）。
//
// 分文件：vocab.go（契约词汇）/ versions.go（版本空间台账）/ bus.go（事件总线）/
// daemon.go（进程级 Daemon）/ table.go（角色级主机表与表操作面——Registry 语义
// 迁入）/ host.go（每主机 Host 对象与进程面 DTO）/ demand.go、diag.go（§6 落地）。
package facade
