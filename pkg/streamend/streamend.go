// Package streamend：控制面流（stream.open 纯透传）终结错误的**中立公共承载**
// （files-cli 2.1，design D3）。
//
// 为什么中立：终结错误同时被两侧消费——`pkg/term`（attach 三态归因）与
// `pkg/files`（get/put 传输中断归因）——落任何一侧都会让另一侧 import 兄弟协议包。
// 本包只含 Reason 常量与终结错误类型，不依赖 internal/ 与任何协议包。
//
// 迁移口径（design D3 两条同名约束，r2 新-5）：本类型自 `pkg/term` 的
// RemoteEndError 平移，**形状与语义逐字沿用**——Reason 是 string 字段而非具名类型
// （消费方按形参 string 翻文案，具名化即编译红）；Unwrap 恒 io.EOF（errors.Is 可判
// 流终结）。Error() 文案保持含「流已终结」（既有断言按子串匹配，term_remote_test
// 的写路径用例钉住该短语——新-11：文案约束与类型/Unwrap 约束同等级）。
// 三态的**用户面**文案由各消费方（pkg/term.remoteEndMessage / files CLI）自行翻译，
// 本包 Error() 只给机器可判的中性描述。
package streamend

import "io"

// 终结原因三态（closed/gone 与控制面 stream.end 的 reason 词表一致；conn = 连接级
// 断开——不发 end 的那条）。值与 pkg/term 的 RemoteEnd* 常量历史值逐字相同。
const (
	Closed = "closed"
	Gone   = "gone"
	Conn   = "conn"
)

// Error 远程流的终结错误（适配器 Read 排干余量后的终结返回 / Write 路径翻译后的
// 归一类型）。包装 io.EOF——errors.Is(err, io.EOF) 成立；errors.As 取 Reason 出三态。
//
// ⚠ 字段形状冻结：struct{ Reason string } 逐字沿用（不规整成具名 Reason 类型）——
// pkg/term 的 remoteEndMessage(name, re.Reason) 按形参 string 编译，一规整就红。
type Error struct{ Reason string }

func (e *Error) Error() string {
	switch e.Reason {
	case Closed:
		return "流已终结（对端已关闭 closed）"
	case Gone:
		return "流已终结（被收尾 gone）"
	case Conn:
		return "流已终结（连接断开 conn）"
	}
	return "流已终结（" + e.Reason + "）"
}

func (e *Error) Unwrap() error { return io.EOF }
