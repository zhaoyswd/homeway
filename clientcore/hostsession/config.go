package hostsession

// config.go — 会话配置（tunConfig 随迁版，host-registry-daemon D1：cshared 侧留
// `type tunConfig = hostsession.Config` 类型别名 + normalizeTunConfig 薄壳，留守
// 引用点零改动）。字段与 JSON 键逐字不变——它是 App/扩展拼装入参的 wire 形态。
//
// PortForward 随 Config 一并随迁（原 cshared tunPortForward，app_portfwd.go 的
// 端口转发实现留守、经类型别名引用本类型）。

// PortForward 是 Config.PortForwards 的一条（端口映射，见留守的 app_portfwd.go）。
// 字段名与扩展侧拼 JSON 的键一致（listen / targetIp / targetPort）。
type PortForward struct {
	Listen     uint16 `json:"listen"`
	TargetIp   string `json:"targetIp"` // 空 = 出口主机自己
	TargetPort uint16 `json:"targetPort"`
}

type Config struct {
	MTU uint32 `json:"mtu"`
	Out string `json:"out"`
	// 诊断/实验开关（ArkTS 侧不传即取默认值）
	DialMs    int `json:"dialMs"`    // 上游拨号预算（默认 15000）
	StatsSecs int `json:"statsSecs"` // 周期统计间隔（默认 60）
	// EndpointCacheDir 是端点学习缓存的目录（openspec direct-handshake-connect）：
	// 巡检观察到直连端点时按 <serverPubHex>.json 落盘，下次建连排全部候选之前。
	// 空串 = 不读不写（CLI/测试）。文件按 server 公钥命名：删主机时残留无害。
	EndpointCacheDir string `json:"endpointCacheDir"`
	// IdentityDir 是设备身份目录（openspec/changes/device-identity-persist）：
	// <dir>/master.key 存本设备主密钥，按后端派生稳定 WG 身份与设备标签（devTag）。
	// 空串 = 每次进程临时身份（CLI/测试；重连会在出口多占记录）。
	IdentityDir string `json:"identityDir"`

	// DiagFdSecs > 0 时每这么多秒打一行 fd 快照（读 /proc/self/fd + 逐 fd getsockopt）。
	// 默认 0 = 不打（省 CPU 与日志量）；排查 fd 泄漏时由 App 侧常量打开。
	// 无论开关如何，每世代建立后都会打**一行基线**，便于对比。
	DiagFdSecs int `json:"diagFdSecs"`
	// TzOffsetMinutes 设备时区相对 UTC 的偏移（分钟，东八区 = 480）。Go 的 log 包用 time.Local
	// 打时间戳，而 OHOS 上这个进程的 Local 是 UTC —— 不设的话隧道日志比 App 日志差 8 小时，
	// 日志页把两份日志按时间合并时顺序就全乱了（实测）。
	TzOffsetMinutes int `json:"tzOffsetMinutes"`
	// Token：homeway token（唯一入口形态）—— 自带后端公钥、凭证种子与端点列表。
	Token string `json:"token"`

	// PortForwards：端口映射（见留守的 app_portfwd.go）——attached 后在本进程监听
	// 127.0.0.1:<listen>，把连接经隧道转发到 targetIp:targetPort（空 IP = 出口自己）。
	// 空列表 = 无映射，零开销。
	PortForwards []PortForward `json:"portForwards"`
}

// Normalize 填默认值（原 normalizeTunConfig）。必须在暖机之前做：attach 与日志都要用这些值。
// 所有"时长/尺寸"类字段都按 **<=0 就回落默认**处理：负数不仅无意义，还会直接炸掉
// （`time.NewTicker` 参数 <=0 会 panic，而 panic 发生在子 goroutine 里，会把扩展进程带走；
//
//	DialMs 为负则所有拨号立即超时=静默变砖）。App 侧只传固定正值，但这里不该赌调用方。
func Normalize(cfg *Config) {
	if cfg.MTU <= 0 {
		// 与 App 侧 TUN_MTU(1280) 对齐：超过 Tailscale/WireGuard 隧道自身的承载上限会出现
		// 「能连、DNS/TLS 都通、大包被丢」的白屏（AGENTS 坑 23）。任何新调用点忘传 MTU
		// 也不该静默踩回 1360 那个坑。
		cfg.MTU = 1280
	}
	if cfg.DialMs <= 0 {
		cfg.DialMs = 15000
	}
	if cfg.StatsSecs <= 0 {
		cfg.StatsSecs = 60
	}
}
