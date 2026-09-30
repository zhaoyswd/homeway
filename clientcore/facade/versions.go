package facade

// versions.go — 版本与能力空间台账（D2，任务 1.2）：全部版本/能力空间一处登记。
//
// 空间各自独立、不合并不联动——「帧体版本与 cell 编码版本是两个独立空间」教训的
// 成文化：布局变了就升所属空间的版本，升版不联动其它空间。每个空间登记
// 名字 / 当前值 / 归属（真源常量所在包）/ 升版规则：
//
//	| 空间 | 当前值 | 归属真源 | 升版规则 |
//	|---|---|---|---|
//	| 控制面协议版本（握手 protoVersion） | ControlProtoVersion=1 | internal/control ProtoVersion（wire 握手体） | 布局/语义不兼容变更才升；对拍断言落 control 侧测试（control→facade 无环） |
//	| term 帧协议版本（GREETING ver） | TermProtoVersion=1 | pkg/term termProtoVer | 帧布局变更升版本，两端同批 |
//	| surface 载荷版本 | SurfacePayloadVersion=4 | pkg/term surfaceVer | **载荷布局变更 MUST 升版本**（v2 光标块/v3 回滚条/v4 模式位——「先改字段没升版本」的实测错位教训） |
//	| HELLO flags 位 | HelloFlagCreate/OnlyIfAbsent/Takeover | pkg/term helloFlag* | 只增位不复用 |
//	| capability 块 caps 位 | CapsSurface/CapsRawTerminal | pkg/term capsSurface/capsRawTerminal | 长度+位图布局，只增位 |
//	| GREETING features 位 | FeatList/Replay/Modes/Agent/Title/Surface | pkg/term feat* | 客户端不认识的位忽略；只增 |
//	| agent 状态词表 stateV2 | StateV2Unknown/Working/Blocked/Idle | pkg/term stateV2* | 值域只增不改（与 App 侧一一对应） |
//	| 事件 kind / 错误码 / 订阅域词表 | （无单一数值——受控枚举） | facade vocab.go | 只增不改（本身就是一种版本空间：新增走 spec delta，不改既有值） |
//	| 订阅视图 view 文法 | host=<id>[,host=<id>]* | facade demand.go ParseView（4a §6.2 登记） | 条目格式只增不改；未知条目保守忽略（不算需求不报错） |
//
// 对拍机制（r1 中-2）：term 侧真源常量未导出，pkg/term 增只读访问器
// （SurfaceVersion/FrameCaps/HelloFlags/GreetingFeatures/StateV2Values/
// TermProtoVersion——只增不改、零 wire 影响）；对拍测试写 package facade_test
// 外部测试包（import pkg/*、不 import 根 internal/——CD delta 纯洁性口径）。
// 本文件零 import（台账是纯数据）——windows/CGO=0/cshared 面全部可编。
const (
	// ControlProtoVersion 控制面协议版本（握手 protoVersion；真源 =
	// internal/control ProtoVersion，wire 握手体留在传输层）。
	ControlProtoVersion = 1

	// TermProtoVersion term 帧协议版本（GREETING 的 ver 字节；真源 =
	// pkg/term termProtoVer）。
	TermProtoVersion = 1

	// SurfacePayloadVersion surface 载荷版本（进每个大帧的体头；真源 =
	// pkg/term surfaceVer，当前 v4：光标块 v2 → 回滚条 v3 → 模式位+回滚条 v4。
	// 布局变了就必须升版本——两端必须同升，版本门拦「旧二进制新布局」错位）。
	SurfacePayloadVersion = 4

	// HELLO flags 位（真源 = pkg/term helloFlag*；只增不复用）。
	HelloFlagCreate       = 1 << 0 // 创建语义（既有）
	HelloFlagOnlyIfAbsent = 1 << 1 // 名字已存在则报 already_exists（`new` 不带 -A）
	HelloFlagTakeover     = 1 << 2 // 显式接管：踢掉其它腿（`attach -d`；ENDED reason=replaced）

	// capability 块的 caps 位（真源 = pkg/term capsSurface/capsRawTerminal；
	// [capLen:1][flags:capLen] 位图布局，只增位）。
	CapsSurface     = 1 << 0 // surface 腿声明
	CapsRawTerminal = 1 << 1 // raw 终端位（客户端自己是完整终端，服务端 vt 让位）

	// GREETING 的 features 位（真源 = pkg/term feat*；客户端不认识的位忽略，只增）。
	FeatList    = 1 << 0
	FeatReplay  = 1 << 1
	FeatModes   = 1 << 2
	FeatAgent   = 1 << 3
	FeatTitle   = 1 << 4
	FeatSurface = 1 << 5 // surface 能力位（客户端见位才在 HELLO 尾随 capability 块）

	// agent 状态词表 stateV2 的值域（真源 = pkg/term stateV2*；STATE 帧的 state
	// 字节与 LIST JSON 的 stateV2 字段共用，与 App 侧一一对应，值域只增不改）。
	StateV2Unknown byte = 0
	StateV2Working byte = 1
	StateV2Blocked byte = 2
	StateV2Idle    byte = 3
)
