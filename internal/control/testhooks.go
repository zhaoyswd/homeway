package control

// testhooks.go — 跨包测试支持面（FIX-97 收敛：原先混在 client.go 的生产文件里）。
//
// ⚠️ 本文件的导出**只为测试存在**：生产代码零引用、零行为改动（投递路径不读它）。
// 为什么保留导出而不是 build tag：消费者是 internal/daemon 的跨包用例
// （TestStreamConnCloseEscapeHatch 的「前置成立」断言），Go 没有跨包测试可见性；
// build tag 会造成「默认测试少跑用例（静默漏跑）」或「默认测试恒红」两种坏形态，
// 故取「独立文件 + 显式命名 + 注释定位」的诚实化形态（计划表已登记该偏离）。

import "sync/atomic"

// slowDelivery 满槽投递计数（exec-r1 M1②）：reader 向流 recv 投递 stream.data 时
// 发现队列已满（即将阻塞等消费方读/连接关闭）即 +1。
var slowDelivery atomic.Uint64

// SlowDeliveryCountForTest 返回满槽投递的累计次数（唯一消费者 =
// internal/daemon 的 TestStreamConnCloseEscapeHatch 前置断言）。
func SlowDeliveryCountForTest() uint64 { return slowDelivery.Load() }

// noteSlowDeliveryForTest 满槽投递时计数（client.go 的投递路径调用；探测零副作用）。
func noteSlowDeliveryForTest() { slowDelivery.Add(1) }
