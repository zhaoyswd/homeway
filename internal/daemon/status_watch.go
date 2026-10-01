package daemon

// status_watch.go — homeway status --watch（4a §7.1，D7 只读消费者；role-management
// 3.4 自 `daemon status --watch` 平移——观测即需求语义不变）：
// 快照 + 订阅续播的 live 渲染——一次 Dial → snapshot.get → events.subscribe
// （link+session 域，view=当前列表视图〔启动时主机集合〕，cursor=快照序号）→
// 终端原地渲染（state/reason/via/rtt 随事件刷新，Ctrl-C 退出）。
//
// **纯绑定（退出口判据）**：只经 internal/control 客户端与 facade 词汇消费控制面
// ——零 facade/control 语义改动（本命令 diff 全在 CLI 层；`git diff --stat
// <batch-base> -- clientcore/facade internal/control` 为空是可执行判据）。
//
// ⚠️ 观测副作用（r1 低-8，usage/README 同款注记）：view 自 facade 期参与需求合成
// ——watch 运行期间被显示主机（启动时列表内的主机）被视为有需求（订阅视图源，
// 门控不压制其巡检证据）；Ctrl-C/断开后该视图的需求贡献随订阅关闭消失。观测
// 行为改变被观测系统，watch 不是纯被动观测。视图声明 = 启动时列表：watch 期间
// 新增/移除的主机照常渲染、不追溯进视图声明（重启 watch 刷新）。
//
// 命名（design D7）：不叫 `homeway status --watch`——3f 已规划 `homeway status`
// 聚合命令（role-management 3.4 已吸收，入口 = homeway status --watch）。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/facade"
	"github.com/zhaoyswd/homeway/internal/control"
)

// watchHost 一台主机的渲染行（快照初值 + 事件增量更新；未知字段零值容忍）。
type watchHost struct {
	id      string
	name    string
	state   string
	reason  string
	via     string
	ep      string
	rttMs   int64
	rxBytes int64
	txBytes int64
}

// statusWatch --watch 模式主体。ctx 取消（生产 = SIGINT/SIGTERM 的
// signal.NotifyContext，测试 = 直接取消）= 正常退出（「Ctrl-C 退出」）；
// 守护进程 goodbye/断开 = 可行动错误。timeout 只限定初始阶段（Dial + 快照 +
// 订阅），渲染期不设预算。
func statusWatch(ctx context.Context, sock, version, stateDir string, timeout time.Duration, w io.Writer) error {
	dctx, dcancel := context.WithTimeout(ctx, timeout)
	defer dcancel()
	c, _, err := control.Dial(dctx, sock, control.FrontendInfo{Kind: "cli", Name: "homeway-watch", Version: version})
	if err != nil {
		// 可行动错误与 statusCLI 同款（守护托管读面：未运行是常态，给启动命令）。
		return fmt.Errorf("homeway 未在运行（sock=%s：%v）\n--watch 需进程在位（纯读不拉起）；先启动：homeway --state %s（零参统一进程）", sock, err, stateDir)
	}
	defer c.Close()
	raw, err := c.Request(dctx, facade.OpSnapshotGet, nil)
	if err != nil {
		return fmt.Errorf("snapshot.get 失败：%w", err)
	}
	var snap control.SnapshotResult
	if err := json.Unmarshal(raw, &snap); err != nil {
		return fmt.Errorf("snapshot.get 载荷解析失败：%w", err)
	}

	// view = 当前列表视图（启动时主机集合；文法 host=<id>[,host=<id>]*——
	// 空表 = 空串，不参与需求合成）。
	hosts := make(map[string]*watchHost, len(snap.Hosts))
	var vb strings.Builder
	for i, h := range snap.Hosts {
		row := &watchHost{id: h.ID, name: h.Name, state: h.State, reason: h.Reason}
		if h.Link != nil {
			row.via, row.ep, row.rttMs = h.Link.Via, h.Link.Ep, h.Link.RttMs
		}
		if h.Stats != nil {
			row.rxBytes, row.txBytes = h.Stats.RxBytes, h.Stats.TxBytes
		}
		hosts[h.ID] = row
		if i > 0 {
			vb.WriteByte(',')
		}
		fmt.Fprintf(&vb, "host=%s", h.ID)
	}
	if _, err := c.Subscribe(dctx, []string{facade.DomainLink, facade.DomainSession}, &snap.Seq, vb.String(), snap.Generation); err != nil {
		if errors.Is(err, control.CodeError(facade.CodeCursorStale)) {
			// 一次性命令的前端重连三层口径最小形态：重跑 = 从全量快照重来。
			return fmt.Errorf("订阅游标失效（cursor_stale：守护进程已重启或事件窗过旧）——重新运行一次 homeway status --watch 即从全量快照开始：%w", err)
		}
		return fmt.Errorf("events.subscribe 失败：%w", err)
	}

	renderWatch(w, snap.Generation, stateDir, hosts)
	for {
		select {
		case <-ctx.Done():
			// Ctrl-C：正常退出。退订由连接关闭承载（conn close → 总线摘订阅者
			// → 该视图的需求贡献消失——CP「门控信号词表」场景）。
			return nil
		case g := <-c.Goodbye():
			return fmt.Errorf("守护进程已断开（goodbye=%s）——检查守护进程（homeway status）后重新运行本命令", g.Reason)
		case <-c.Closed():
			return fmt.Errorf("守护进程连接已断开——守护进程可能已退出（homeway status 确认后重新运行本命令）")
		case ev := <-c.Events():
			applyWatchEvent(hosts, ev)
			renderWatch(w, snap.Generation, stateDir, hosts)
		}
	}
}

// applyWatchEvent 一条事件的增量应用（渲染行按 host 键幂等覆盖——at-least-once
// 语义下重复事件无害；词表只增：未入渲染面的 kind 忽略）。
func applyWatchEvent(hosts map[string]*watchHost, ev control.EventBody) {
	switch ev.Kind {
	case facade.KindSessionAdded:
		var p facade.SessionAddedPayload
		if json.Unmarshal(ev.Payload, &p) != nil || p.Host == "" {
			return
		}
		if _, ok := hosts[p.Host]; !ok {
			hosts[p.Host] = &watchHost{id: p.Host, name: p.Name} // 初始 state 待 state_changed
		}
	case facade.KindSessionRemoved:
		var p facade.SessionRemovedPayload
		if json.Unmarshal(ev.Payload, &p) != nil {
			return
		}
		delete(hosts, p.Host)
	case facade.KindSessionStateChanged:
		var p facade.SessionStateChangedPayload
		if json.Unmarshal(ev.Payload, &p) != nil {
			return
		}
		if row, ok := hosts[p.Host]; ok {
			row.state, row.reason = p.State, p.Reason
		}
	case facade.KindLinkChanged:
		var p facade.LinkChangedPayload
		if json.Unmarshal(ev.Payload, &p) != nil {
			return
		}
		if row, ok := hosts[p.Host]; ok {
			row.via, row.ep, row.rttMs = p.Via, p.Ep, p.RttMs
		}
	}
}

// renderWatch 终端原地渲染（每帧清屏重画——帧率低〔事件驱动〕、无并发写）。
// 中文文案是 CLI 侧映射，MUST NOT 进入契约（与 printStatus 同纪律）。
func renderWatch(w io.Writer, gen, stateDir string, hosts map[string]*watchHost) {
	var b strings.Builder
	b.WriteString("\x1b[H\x1b[2J") // 清屏 + 光标归位（原地刷新）
	fmt.Fprintf(&b, "homeway watch（Ctrl-C 退出）\n  代际： %s\n  state： %s\n", gen, stateDir)
	b.WriteString("  ⚠️ 观测副作用：被显示主机（启动时列表）在 watch 期间视为有需求；退出后贡献消失\n")
	if len(hosts) == 0 {
		b.WriteString("  主机： 无\n")
		_, _ = io.WriteString(w, b.String())
		return
	}
	ids := make([]string, 0, len(hosts))
	for id := range hosts {
		ids = append(ids, id)
	}
	sort.Strings(ids) // 稳定行序（事件乱序到达不抖动渲染）
	fmt.Fprintf(&b, "  主机： %d 台\n", len(hosts))
	for _, id := range ids {
		h := hosts[id]
		name := h.name
		if name == "" {
			name = "-"
		}
		state := h.state
		if state == "" {
			state = "…" // 行由 session.added 建立、state_changed 未至（待刷新）
		}
		line := fmt.Sprintf("    - %s（%s）state=%s", shortHostID(h.id), name, state)
		if h.reason != "" {
			line += " reason=" + h.reason
		}
		if h.via != "" || h.ep != "" {
			line += fmt.Sprintf(" link=%s ep=%s rtt=%dms", h.via, h.ep, h.rttMs)
		}
		if h.rxBytes != 0 || h.txBytes != 0 {
			line += fmt.Sprintf(" rx/tx=%s/%s", humanBytes(h.rxBytes), humanBytes(h.txBytes))
		}
		b.WriteString(line + "\n")
	}
	_, _ = io.WriteString(w, b.String())
}
