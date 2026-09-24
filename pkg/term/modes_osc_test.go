//go:build !windows

// term_modes_osc_test.go — OSC 证据腿的单测（任务 1.5）。
//
// 覆盖三件事：① OSC 9 的**双语义判别**（9;4 是 progress、裸 9 是通知）
// ② OSC 21337 状态直报 ③ 跨 read 切断（读缓冲边界不是协议边界）。
package term

import "testing"

func TestTermScanOSCProgress(t *testing.T) {
	cases := []struct {
		name      string
		chunks    []string
		wantState int
		wantValue int
		wantOK    bool
		wantNotif string
		noChange  bool
	}{
		{
			name:      "带百分比的 progress",
			chunks:    []string{"\x1b]9;4;1;50\x07"},
			wantState: termProgressNormal, wantValue: 50, wantOK: true,
		},
		{
			name:      "不带百分比的 progress",
			chunks:    []string{"\x1b]9;4;3\x07"},
			wantState: termProgressIndet, wantValue: termProgressValueNone, wantOK: true,
		},
		{
			name:      "错误态 progress",
			chunks:    []string{"\x1b]9;4;2;100\x1b\\"},
			wantState: termProgressError, wantValue: 100, wantOK: true,
		},
		{
			name:      "清除 progress（state=0）",
			chunks:    []string{"\x1b]9;4;1;80\x07", "\x1b]9;4;0\x07"},
			wantState: termProgressClear, wantValue: termProgressValueNone, wantOK: true,
		},
		{
			name:      "裸 OSC 9 是通知、不进 progress",
			chunks:    []string{"\x1b]9;构建完成\x07"},
			wantOK:    false,
			wantNotif: "构建完成",
		},
		{
			name:      "跨 read 切断的 progress",
			chunks:    []string{"\x1b]9;4;1", ";75\x07"},
			wantState: termProgressNormal, wantValue: 75, wantOK: true,
		},
		{
			name:      "跨 read 切断的通知",
			chunks:    []string{"\x1b]9;构", "建完成\x07"},
			wantOK:    false,
			wantNotif: "构建完成",
		},
		{
			name:     "非法 state 忽略",
			chunks:   []string{"\x1b]9;4;9;50\x07"},
			wantOK:   false,
			noChange: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var s termScan
			for _, chunk := range c.chunks {
				s.write([]byte(chunk))
			}
			if s.progress.ok != c.wantOK {
				t.Fatalf("progress.ok = %v，期望 %v", s.progress.ok, c.wantOK)
			}
			if c.wantOK {
				if s.progress.state != c.wantState || s.progress.value != c.wantValue {
					t.Errorf("progress = {%d,%d}，期望 {%d,%d}",
						s.progress.state, s.progress.value, c.wantState, c.wantValue)
				}
			}
			if s.notify != c.wantNotif {
				t.Errorf("notify = %q，期望 %q", s.notify, c.wantNotif)
			}
			if s.changed == c.noChange {
				t.Errorf("changed = %v，期望 %v", s.changed, !c.noChange)
			}
		})
	}
}

func TestTermScanOSC21337(t *testing.T) {
	cases := []struct {
		name   string
		chunks []string
		want   string
	}{
		{name: "直报 working", chunks: []string{"\x1b]21337;status=working\x07"}, want: "working"},
		{name: "ST 结束", chunks: []string{"\x1b]21337;status=idle\x1b\\"}, want: "idle"},
		{name: "带其它键", chunks: []string{"\x1b]21337;pid=42;status=blocked\x07"}, want: "blocked"},
		{name: "跨 read", chunks: []string{"\x1b]21337;sta", "tus=working\x07"}, want: "working"},
		{name: "没有 status 键则忽略", chunks: []string{"\x1b]21337;pid=42\x07"}, want: ""},
		{name: "空值忽略", chunks: []string{"\x1b]21337;status=\x07"}, want: ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var s termScan
			for _, chunk := range c.chunks {
				s.write([]byte(chunk))
			}
			if s.oscStatus != c.want {
				t.Errorf("oscStatus = %q，期望 %q", s.oscStatus, c.want)
			}
		})
	}
}

// agent 切换要清证据：progress / 直报状态归零，标题**留显示但失去判定资格**。
func TestTermScanClearOSCEvidence(t *testing.T) {
	var s termScan
	s.write([]byte("\x1b]2;codex 运行中\x07\x1b]9;4;1;30\x07\x1b]21337;status=working\x07\x1b]9;提醒\x07"))
	if s.title != "codex 运行中" || !s.progress.ok || s.oscStatus != "working" {
		t.Fatalf("前置状态没建起来：title=%q progress=%+v status=%q", s.title, s.progress, s.oscStatus)
	}
	if got := s.TitleEvidence(); got != "codex 运行中" {
		t.Fatalf("清理前标题应可作证据，实际 %q", got)
	}

	s.clearOSCEvidence()

	if s.progress.ok {
		t.Error("progress 应被清空")
	}
	if s.oscStatus != "" {
		t.Errorf("直报状态应被清空，实际 %q", s.oscStatus)
	}
	if got := s.TitleEvidence(); got != "" {
		t.Errorf("清理后旧标题不该再作证据，实际 %q", got)
	}
	if s.title != "codex 运行中" {
		t.Errorf("标题应保留用于显示，实际 %q", s.title)
	}

	// 新 agent 设了标题 ⇒ 恢复判定资格。
	s.write([]byte("\x1b]2;claude 待批准\x07"))
	if got := s.TitleEvidence(); got != "claude 待批准" {
		t.Errorf("新标题应恢复判定资格，实际 %q", got)
	}
}

// 证据没变化时不置 changed（避免无谓的状态推送；检测侧靠它做短路）。
func TestTermScanNoChangeNoFlag(t *testing.T) {
	var s termScan
	s.write([]byte("\x1b]9;4;1;50\x07"))
	s.changed = false
	s.write([]byte("\x1b]9;4;1;50\x07"))
	if s.changed {
		t.Error("同一 progress 重复到达不该置 changed")
	}
	s.write([]byte("\x1b]9;4;1;51\x07"))
	if !s.changed {
		t.Error("progress 变化应置 changed")
	}
}

// 超长 OSC 载荷不得撑大内存，也不得产出证据。
func TestTermScanOSCOverlong(t *testing.T) {
	var s termScan
	long := append([]byte("\x1b]21337;status="), make([]byte, 4000)...)
	for i := range long[17:] {
		long[17+i] = 'x'
	}
	long = append(long, 0x07)
	s.write(long)
	if len(s.buf) > termScanMaxOSC {
		t.Errorf("缓冲区失控：%d", len(s.buf))
	}
	if s.oscStatus != "" {
		t.Errorf("超长载荷不该产出证据，实际 %q", s.oscStatus)
	}
}
