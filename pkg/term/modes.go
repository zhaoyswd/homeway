//go:build !windows

// term_modes.go — 出口侧的**旁路扫描器**（只读，不消费字节）：从 PTY 输出流里维护
//
//	① 私有模式位掩码（光标键/鼠标上报/焦点/括号粘贴/备用屏）——attach 时下发给客户端，
//	   让「新建的本地 vt」立刻知道当前屏态（term 项目当年在客户端做 capture/回灌，
//	   踩过时机坑；这里改由出口持续维护，客户端零状态）。**surface 路径改读 vt 权威值**
//	   （term_vt.go），本扫描器的模式位只服务 legacy 客户端。
//	② OSC 0/1/2 窗口标题（列表与页面副标题）——**标题的单一来源**（design D1：跨 read 安全、
//	   已实战；surface 快照的标题字段与检测证据共用它，不读 vt 的标题查询）。
//	③ OSC 9 的两副面孔（评审 M9）：`9;4;<state>[;<pct>]` 是 **progress**（检测证据通道），
//	   裸 `9;<text>` 是**通知**（转发到手机通知，任务 2.7 经 NOTIFY 帧下发）。
//	④ OSC 21337 `status=<value>` —— Fig/Amazon Q 集成 CLI 的**状态直报**（检测的第四路证据，
//	   权威级最高；vt 库不解析这一条，见 design D4）。
//
// 关键约束：读缓冲边界不是协议边界 ⇒ 状态机必须能吃**跨 read 切断**的序列。
package term

import "strings"

// 模式位（与 App 侧 terminal 模块的 stream 层一一对应）。
const (
	termModeDECCKM    uint32 = 1 << 0 // ?1h/l   应用光标键
	termModeMouse1000 uint32 = 1 << 1 // ?1000h/l 鼠标：普通跟踪
	termModeMouse1002 uint32 = 1 << 2 // ?1002h/l 鼠标：按键跟踪
	termModeMouse1003 uint32 = 1 << 3 // ?1003h/l 鼠标：任意移动
	termModeMouse1006 uint32 = 1 << 4 // ?1006h/l 鼠标：SGR 格式
	termModeFocus     uint32 = 1 << 5 // ?1004h/l 焦点事件
	termModeBracketed uint32 = 1 << 6 // ?2004h/l 括号粘贴
	termModeAltScreen uint32 = 1 << 7 // ?1049h/l（含 ?47/?1047）备用屏
)

const (
	termScanNone = iota
	termScanEsc
	termScanCSI
	termScanOSC
	termScanOSCEsc
)

const (
	termScanMaxCSI  = 64  // CSI 参数串上限（超长即放弃该序列，防内存放大）
	termScanMaxOSC  = 512 // OSC 载荷上限
	termTitleMax    = 256 // 标题落库上限
	termOSCValueMax = 64  // progress / 直报状态这类短值上限
)

// OSC 9;4 progress 的状态码（xterm 口径）。
const (
	termProgressClear     = 0
	termProgressNormal    = 1
	termProgressError     = 2
	termProgressIndet     = 3
	termProgressWarning   = 4
	termProgressValueNone = -1
)

// termProgress 是最近一条 OSC 9;4 progress 载荷（检测证据通道）。
type termProgress struct {
	state int // termProgress* 之一
	value int // 0..100；未给 = termProgressValueNone
	ok    bool
}

// termScan 是每会话一个的扫描器（由会话锁保护，与 pump 同线程调用）。
type termScan struct {
	st      int
	buf     []byte
	tooLong bool

	modes uint32
	title string

	// 检测证据（term-agent-state 的输入契约）：progress 只认 `9;4;` 前缀；oscStatus 来自
	// OSC 21337；notify 是裸 OSC 9 的通知文本（不进证据，走通知通道）。
	progress  termProgress
	oscStatus string
	notify    string
	// titleStale 表示当前标题**早于**本代前景 agent（切换 agent 时置位）：显示照旧用它，
	// 但检测不得把上一进程的标题算进本进程的判定（term-agent-state 的「agent 切换清证据」）。
	titleStale bool

	// changed 在「本批字节里模式位/标题/证据有变化」时置位（调用方读后自行清零）。
	changed bool
}

func (s *termScan) write(p []byte) {
	for _, b := range p {
		s.byteIn(b)
	}
}

func (s *termScan) push(b byte, max int) {
	if len(s.buf) >= max {
		s.tooLong = true
		return
	}
	s.buf = append(s.buf, b)
}

func (s *termScan) byteIn(b byte) {
	switch s.st {
	case termScanNone:
		if b == 0x1b {
			s.st = termScanEsc
		}
	case termScanEsc:
		switch b {
		case '[':
			s.st, s.buf, s.tooLong = termScanCSI, s.buf[:0], false
		case ']':
			s.st, s.buf, s.tooLong = termScanOSC, s.buf[:0], false
		default:
			// 其它 ESC 序列（单字符或 DCS/OSC 之外的）不关心。
			s.st = termScanNone
		}
	case termScanCSI:
		if b >= 0x40 && b <= 0x7e { // final byte
			if !s.tooLong {
				s.finishCSI(b)
			}
			s.st = termScanNone
			return
		}
		s.push(b, termScanMaxCSI)
	case termScanOSC:
		switch b {
		case 0x07: // BEL
			if !s.tooLong {
				s.finishOSC()
			}
			s.st = termScanNone
		case 0x1b:
			s.st = termScanOSCEsc
		default:
			s.push(b, termScanMaxOSC)
		}
	case termScanOSCEsc:
		// ESC \ = ST；其它则把 ESC 当作序列结束（保守处理）。
		if b == '\\' && !s.tooLong {
			s.finishOSC()
		}
		s.st = termScanNone
	}
}

// finishCSI 处理 `CSI ? Pm h/l`（私有模式设置/复位）；其它 CSI 一律忽略。
func (s *termScan) finishCSI(final byte) {
	if final != 'h' && final != 'l' {
		return
	}
	params := string(s.buf)
	if len(params) == 0 || params[0] != '?' {
		return
	}
	set := final == 'h'
	var changed bool
	for _, part := range splitSemi(params[1:]) {
		n, ok := parseSmallInt(part)
		if !ok {
			continue
		}
		var bit uint32
		switch n {
		case 1:
			bit = termModeDECCKM
		case 47, 1047, 1049:
			bit = termModeAltScreen
		case 1000:
			bit = termModeMouse1000
		case 1002:
			bit = termModeMouse1002
		case 1003:
			bit = termModeMouse1003
		case 1004:
			bit = termModeFocus
		case 1006:
			bit = termModeMouse1006
		case 2004:
			bit = termModeBracketed
		default:
			continue
		}
		before := s.modes
		if set {
			s.modes |= bit
		} else {
			s.modes &^= bit
		}
		changed = changed || before != s.modes
	}
	s.changed = s.changed || changed
}

// finishOSC 按 OSC 命令号分派。**注意 OSC 9 的双语义**（评审 M9）：只有 `9;4;…` 是 progress，
// 裸 `9;…` 是通知——判别按子命令，不能只看命令号。
func (s *termScan) finishOSC() {
	payload := string(s.buf)
	if payload == "" {
		return
	}
	code, rest := payload, ""
	for i := 0; i < len(payload); i++ {
		if payload[i] == ';' {
			code, rest = payload[:i], payload[i+1:]
			break
		}
	}
	switch code {
	case "0", "1", "2":
		s.setTitle(rest)
	case "9":
		s.finishOSC9(rest)
	case "21337":
		s.finishOSC21337(rest)
	}
}

// finishOSC9 处理 OSC 9：`4;<state>[;<pct>]` = progress；其余 = 通知。
func (s *termScan) finishOSC9(rest string) {
	if !strings.HasPrefix(rest, "4;") {
		// 裸 OSC 9：通知文本（转手机通知，任务 2.7 的 NOTIFY 帧）。不进检测证据。
		if text := sanitizeValue(rest, termTitleMax); text != "" && text != s.notify {
			s.notify = text
			s.changed = true
		}
		return
	}
	parts := splitSemi(rest[2:])
	state, ok := parseSmallInt(parts[0])
	if !ok || state < 0 || state > 4 {
		return
	}
	value := termProgressValueNone
	if len(parts) > 1 && parts[1] != "" {
		if v, ok := parseSmallInt(parts[1]); ok && v >= 0 && v <= 100 {
			value = v
		}
	}
	if s.progress.ok && s.progress.state == state && s.progress.value == value {
		return
	}
	s.progress = termProgress{state: state, value: value, ok: true}
	s.changed = true
}

// finishOSC21337 处理 Fig/Amazon Q 的状态直报：载荷形如 `status=<value>`（可带其它键，用 ';' 分隔）。
func (s *termScan) finishOSC21337(rest string) {
	for _, kv := range splitSemi(rest) {
		key, val, found := strings.Cut(kv, "=")
		if !found || key != "status" {
			continue
		}
		val = sanitizeValue(val, termOSCValueMax)
		if val == "" || val == s.oscStatus {
			return
		}
		s.oscStatus = val
		s.changed = true
		return
	}
}

// setTitle 更新标题（OSC 0/1/2 共用；本代新标题自动让 titleStale 失效）。
func (s *termScan) setTitle(raw string) {
	title := sanitizeTitle(raw)
	if title == s.title && !s.titleStale {
		return
	}
	s.title = title
	s.titleStale = false
	s.changed = true
}

// clearOSCEvidence 清空 OSC 证据：前景 agent 变化时调用（term-agent-state 要求旧 agent 的
// progress/直报状态不得参与新 agent 的判定）。
//
// 标题**保留用于显示**，但标为 stale：检测侧读 TitleEvidence() 拿不到它（否则「上一进程残留
// 标题污染下一进程判定」；把标题也抹掉会让会话列表在切换瞬间闪空，是显示层回退）。
func (s *termScan) clearOSCEvidence() {
	had := s.progress.ok || s.oscStatus != "" || !s.titleStale
	s.progress = termProgress{}
	s.oscStatus = ""
	s.titleStale = true
	if had {
		s.changed = true
	}
}

// TitleEvidence 返回可作检测证据的标题：标题早于本代 agent 时返回空串（见 clearOSCEvidence）。
func (s *termScan) TitleEvidence() string {
	if s.titleStale {
		return ""
	}
	return s.title
}

// Progress 返回最近一条 OSC 9;4 progress（ok=false 表示本代还没有过）。
func (s *termScan) Progress() termProgress { return s.progress }

// OSCStatus 返回最近一条 OSC 21337 直报状态（空串 = 无）。
func (s *termScan) OSCStatus() string { return s.oscStatus }

// Notify 返回最近一条裸 OSC 9 通知文本（空串 = 无；供 2.7 的 NOTIFY 帧取用）。
func (s *termScan) Notify() string { return s.notify }

// sanitizeValue 去控制字符并按上限截断（远端可随便发值，别让它撑爆元数据）。
func sanitizeValue(v string, max int) string {
	out := make([]byte, 0, len(v))
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c < 0x20 || c == 0x7f {
			continue
		}
		out = append(out, c)
		if len(out) >= max {
			break
		}
	}
	return string(out)
}

// sanitizeTitle 去掉控制字符并按上限截断（远端可以随便发标题，别让它撑爆元数据）。
func sanitizeTitle(t string) string {
	out := make([]byte, 0, len(t))
	for i := 0; i < len(t); i++ {
		c := t[i]
		if c < 0x20 || c == 0x7f {
			continue
		}
		out = append(out, c)
		if len(out) >= termTitleMax {
			break
		}
	}
	return string(out)
}

func splitSemi(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ';' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// parseSmallInt 只接受 0..9999 的十进制（CSI 参数），其余视为无效。
func parseSmallInt(s string) (int, bool) {
	if s == "" || len(s) > 5 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, true
}
