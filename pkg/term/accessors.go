//go:build !windows

// accessors.go — 版本/能力空间真源常量的只读访问器（clientcore-facade 4a 任务
// 1.2，r1 中-2 拍板选导出访问器路线）：frames.go 的 helloFlag*/caps*/feat*、
// term_surface.go 的 surfaceVer、agent.go 的 stateV2* 全部未导出，版本台账
// （clientcore/facade/versions.go）读不到——经本文件暴露只读快照供对拍。
//
// 只增不改：不改变任何真源常量的值与用法、零 wire 影响、不暴露可变状态
// （返回值全部是值拷贝）。消费方 = facade_test 对拍单测（版本台账 ↔ 真源不漂移）。
package term

// HelloFlagBits HELLO flags 位的只读快照（真源 helloFlag*，frames.go）。
type HelloFlagBits struct {
	Create       byte // 创建语义（既有）
	OnlyIfAbsent byte // 名字已存在则报 already_exists（`new` 不带 -A）
	Takeover     byte // 显式接管：踢掉其它腿（`attach -d`）
}

// HelloFlags 返回 HELLO flags 位的只读快照。
func HelloFlags() HelloFlagBits {
	return HelloFlagBits{
		Create:       helloFlagCreate,
		OnlyIfAbsent: helloFlagOnlyIfAbsent,
		Takeover:     helloFlagTakeover,
	}
}

// CapsBits capability 块 caps 位的只读快照（真源 capsSurface/capsRawTerminal）。
type CapsBits struct {
	Surface     byte // surface 腿声明
	RawTerminal byte // raw 终端位（客户端自己是完整终端）
}

// FrameCaps 返回 capability 块 caps 位的只读快照。
func FrameCaps() CapsBits {
	return CapsBits{
		Surface:     capsSurface,
		RawTerminal: capsRawTerminal,
	}
}

// GreetingFeatureBits GREETING features 位的只读快照（真源 feat*，frames.go）。
type GreetingFeatureBits struct {
	List    uint32
	Replay  uint32
	Modes   uint32
	Agent   uint32
	Title   uint32
	Surface uint32 // surface 能力位（featSurface 与 frames.go 的 featSurfaceBit 同值）
}

// GreetingFeatures 返回 GREETING features 位的只读快照。
func GreetingFeatures() GreetingFeatureBits {
	return GreetingFeatureBits{
		List:    featList,
		Replay:  featReplay,
		Modes:   featModes,
		Agent:   featAgent,
		Title:   featTitle,
		Surface: featSurfaceBit,
	}
}

// StateV2Space agent 状态词表 stateV2 值域的只读快照（真源 stateV2*，agent.go；
// STATE 帧的 state 字节与 LIST JSON 的 stateV2 字段共用，与 App 侧一一对应）。
type StateV2Space struct {
	Unknown byte
	Working byte
	Blocked byte
	Idle    byte
}

// StateV2Values 返回 stateV2 值域的只读快照。
func StateV2Values() StateV2Space {
	return StateV2Space{
		Unknown: stateV2Unknown,
		Working: stateV2Working,
		Blocked: stateV2Blocked,
		Idle:    stateV2Idle,
	}
}

// SurfaceVersion 返回 surface 载荷版本（真源 surfaceVer，term_surface.go——
// 进每个大帧的体头；布局变了就必须升版本）。
func SurfaceVersion() byte { return surfaceVer }

// TermProtoVersion 返回 term 帧协议版本（真源 termProtoVer，frames.go——
// GREETING 的 ver 字节）。
func TermProtoVersion() byte { return termProtoVer }
