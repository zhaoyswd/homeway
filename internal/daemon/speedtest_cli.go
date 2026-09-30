package daemon

// speedtest_cli.go — homeway speedtest（forward-socks-speedtest 3e §3.4，spec
// speedtest-cli）：对指定后端（或全部主机顺序轮流）的隧道测速 CLI 面。守护托管
//（引擎在 daemon 内跑、数据腿直连隧道不经控制面流）；--host 缺省 = 全主机轮流
//（开跑前「将依次测 N 台」预告、顺序执行不并行）；Ctrl-C 终止整个轮转（先 cancel
// 当前主机再退出、退出码非零）；输出双口径（手机显示口径 + 精确值行）；--wait 预算
// 经 start 载荷 waitMs 交 runner 状态机承载（start 立即返回 waiting），CLI 轮询
// status（250ms）渲染过程提示与实时速率（stderr，--quiet 抑制）。

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/zhaoyswd/homeway/clientcore/facade"
	"github.com/zhaoyswd/homeway/internal/control"
	"github.com/zhaoyswd/homeway/pkg/speedtest"
)

// speedtestCLI speedtest 子命令入口（stdout 写 w、过程提示写 errW 便于测试）。
func speedtestCLI(args []string, version string, w, errW io.Writer) error {
	fs := flag.NewFlagSet("homeway speedtest", flag.ContinueOnError)
	fs.SetOutput(w)
	stateDir := fs.String("state", DefaultStateDir(), "守护进程 state 目录（从中找 control.sock）")
	hostRef := fs.String("host", "", "指定主机（缺省 = 主机表内全部主机顺序轮流）")
	jsonOut := fs.Bool("json", false, "机器可读 JSON（逐主机结果对象，stdout 一行）")
	down := fs.Duration("down", 10*time.Second, "下行窗口（≤15s）")
	up := fs.Duration("up", 10*time.Second, "上行窗口（≤15s）")
	warmup := fs.Duration("warmup", 2*time.Second, "预热（≤5s，不计入窗口）")
	streams := fs.Int("streams", 4, "并行流数（1–6）")
	wait := fs.Duration("wait", 60*time.Second, "链路未就绪的有界等待（0 = 不等即报错）")
	quiet := fs.Bool("quiet", false, "抑制过程提示与实时速率（stderr）")
	timeout := fs.Duration("timeout", 10*time.Second, "控制面连接与请求预算（start/status/cancel 各计一次）")
	if err := fs.Parse(flagsFirst(args, carrierFlagBools)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usageSpeedtest(w)
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("speedtest 不接受位置参数（got %q）", fs.Args())
	}
	// 参数边界 = 引擎边界（手机口径；越界就地报错，不连 daemon）。
	p := speedtest.Params{Down: *down, Up: *up, Warmup: *warmup, Streams: *streams}
	if _, err := p.Normalize(); err != nil {
		return fmt.Errorf("参数越界（%v）——窗口 ≤15s、预热 ≤5s、流数 1–6（手机口径同边界）", err)
	}
	if *wait < 0 {
		return fmt.Errorf("--wait %s 为负", *wait)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := dialCarrierCLI(ctx, *stateDir, version, "homeway-speedtest")
	if err != nil {
		return err
	}
	defer c.Close()
	hosts, err := hostsOnConn(ctx, c)
	if err != nil {
		return err
	}

	// 寻址与轮转名单。
	var targets []control.HostState
	if strings.TrimSpace(*hostRef) != "" {
		id, _, rerr := resolveHostTarget(hosts, strings.TrimSpace(*hostRef))
		if rerr != nil {
			return rerr
		}
		for _, h := range hosts {
			if h.ID == id {
				targets = append(targets, h)
			}
		}
	} else {
		targets = hosts
		if len(targets) == 0 {
			return errors.New("主机表为空——先 homeway host add <token> 添加后端，再测速")
		}
		if len(targets) > 1 {
			names := make([]string, 0, len(targets))
			for _, h := range targets {
				names = append(names, displayName(&h))
			}
			fmt.Fprintf(errW, "将依次测 %d 台（顺序执行，互不并行）：%s\n", len(targets), strings.Join(names, "、"))
		} else {
			fmt.Fprintf(errW, "将依次测 %d 台：%s\n", len(targets), displayName(&targets[0]))
		}
	}

	// Ctrl-C：终止整个轮转——先 cancel 当前 host 再退出（signal 转 ctx + 专项通道）。
	sigC := make(chan os.Signal, 1)
	signal.Notify(sigC, syscall.SIGINT)
	defer signal.Stop(sigC)
	go func() {
		select {
		case <-sigC:
			cancel()
		case <-ctx.Done():
		}
	}()

	results := make([]speedHostResult, 0, len(targets))
	interrupted := false
	for _, h := range targets {
		if ctx.Err() != nil { // Ctrl-C 落在两台之间的边界：不再起下一轮（exec-r1 B2）
			interrupted = true
			break
		}
		res, err := runSpeedHost(ctx, c, h, speedtest.Params{Down: *down, Up: *up, Warmup: *warmup, Streams: *streams}, *wait, errW, *quiet, *timeout)
		if err != nil {
			if ctx.Err() != nil { // Ctrl-C：先 cancel 当前 host（runSpeedHost 内已发）再退出
				interrupted = true
				break
			}
			res = speedHostResult{name: displayName(&h), hex: h.ID, ok: false, reason: "interrupted", msg: err.Error()}
		}
		results = append(results, res)
		if !*jsonOut {
			printSpeedResult(w, hosts, res)
		}
	}

	if interrupted {
		return errors.New("已按 Ctrl-C 终止轮转（当前主机已取消；未测的主机不再测量）")
	}
	if *jsonOut {
		out := make([]map[string]any, 0, len(results))
		for _, r := range results {
			out = append(out, r.json())
		}
		b, err := json.Marshal(out)
		if err != nil {
			return err
		}
		fmt.Fprintln(w, string(b))
	}
	// 退出码（拍板①）：全失败非零；至少一台成功 = 0；busy/link_down 等如实呈现短因。
	succ := 0
	for _, r := range results {
		if r.ok {
			succ++
		}
	}
	if succ == 0 {
		return errors.New("全部主机测速失败（短因见上）")
	}
	return nil
}

func usageSpeedtest(w io.Writer) {
	fmt.Fprint(w, `用法：
  homeway speedtest [--host <ref>] [--json] [--down 10s] [--up 10s] [--warmup 2s]
                     [--streams 4] [--wait 60s] [--quiet]
  对指定主机（或全部主机顺序轮流）做隧道上下行测速；输出 = 手机显示口径 + 精确值
  （B/s 与 Mbps）。参数默认与边界 = 手机口径（窗口 ≤15s、预热 ≤5s、流数 1–6）。
  --wait = 链路未就绪的有界等待（0 = 不等即报错；默认 60s 覆盖恢复阶梯最坏时长）。
  Ctrl-C 终止整个轮转（先取消当前主机再退出，退出码非零）。
  --state 恒指 daemon state；--quiet 抑制过程提示与实时速率（stderr）。
`)
}

// speedHostResult 一台主机的结果（--json 的逐主机对象真源——字段名冻结、只增：
// 主机名/两向精确速率/用量/墙钟/via/rtt/结果态）。
type speedHostResult struct {
	name      string
	hex       string
	ok        bool
	reason    string
	msg       string
	downBps   float64
	upBps     float64
	usageDown int64
	usageUp   int64
	wallMs    int64
	via       string
	rttMs     int64
}

func (r *speedHostResult) json() map[string]any {
	m := map[string]any{
		"host": r.hex, "name": r.name, "ok": r.ok,
	}
	if !r.ok {
		m["reason"] = r.reason
		if r.msg != "" {
			m["msg"] = r.msg
		}
	}
	if r.ok {
		m["downBps"] = r.downBps
		m["upBps"] = r.upBps
		m["usageDown"] = r.usageDown
		m["usageUp"] = r.usageUp
		m["wallMs"] = r.wallMs
	}
	if r.via != "" {
		m["via"], m["rttMs"] = r.via, r.rttMs
	}
	return m
}

// runSpeedHost 一台主机的完整轮次：start（waitMs 载荷）→ 250ms 轮询 status 到终态；
// Ctrl-C/超预算 = 先 cancel 再返回错误。via/rtt 开跑时冻结（daemon.status 的链路态）。
func runSpeedHost(ctx context.Context, c *control.Client, h control.HostState, p speedtest.Params, wait time.Duration, errW io.Writer, quiet bool, timeout time.Duration) (speedHostResult, error) {
	name := displayName(&h)
	via, rtt := "", int64(0)
	if h.Link != nil {
		via, rtt = h.Link.Via, h.Link.RttMs
	}
	// Ctrl-C 收尾的单一出口（exec-r1 B2）：start 请求**已发出**后 ctx 取消（含 start
	// 在途窗口——请求帧先写后等，很可能已送达 daemon 并开跑；含轮询期间的任何取消）
	// 统一在收尾 defer 补发 speedtest.cancel（best-effort、独立预算；daemon 侧 Cancel
	// 幂等）。此前只有轮询循环两处显式调用，在途窗口直接返回 = 该轮测速无人取消跑
	// 满预算。
	startSent := false
	defer func() {
		if startSent && ctx.Err() != nil {
			cancelSpeedHost(c, h.ID, timeout)
		}
	}()
	reqCtx, reqCancel := context.WithTimeout(ctx, timeout)
	startSent = true
	raw, err := c.Request(reqCtx, facade.OpSpeedtestStart, control.SpeedtestStartArgs{
		Host:     h.ID,
		DownMs:   p.Down.Milliseconds(),
		UpMs:     p.Up.Milliseconds(),
		WarmupMs: p.Warmup.Milliseconds(),
		Streams:  p.Streams,
		WaitMs:   wait.Milliseconds(),
	})
	reqCancel()
	if err != nil {
		if ctx.Err() != nil {
			return speedHostResult{}, ctx.Err() // 收尾 cancel 由上方 defer 补发
		}
		// no_host/unknown_op 等控制面错误：直接成为该台失败短因（轮转继续）。
		return speedHostResult{name: name, hex: h.ID, ok: false, reason: "control_error", msg: carrierOpErr("speedtest.start", err).Error(), via: via, rttMs: rtt}, nil
	}
	var ack control.SpeedtestStartAck
	if err := json.Unmarshal(raw, &ack); err != nil {
		return speedHostResult{name: name, hex: h.ID, ok: false, reason: "interrupted", msg: "start 载荷解析失败：" + err.Error(), via: via, rttMs: rtt}, nil
	}
	if ack.Phase == "busy" {
		return speedHostResult{name: name, hex: h.ID, ok: false, reason: "busy", msg: "并发满员（同主机已有测速在跑或与手机撞出口上限），稍后再试", via: via, rttMs: rtt}, nil
	}

	if !quiet {
		label := ""
		if via != "" {
			label = fmt.Sprintf("（via=%s rtt=%dms，开跑时冻结）", via, rtt)
		}
		fmt.Fprintf(errW, "▶ %s%s\n", name, label)
	}

	// 轮询预算：wait + 引擎总预算（60s 固定 + 参数）+ 10s 余量（MUST NOT 无限转圈）。
	pollBudget := wait + time.Minute + p.Down + p.Up + p.Warmup + 10*time.Second
	deadline := time.Now().Add(pollBudget)
	lastHint := time.Time{}
	failStreak := 0
	for {
		if ctx.Err() != nil { // Ctrl-C：先 cancel 当前 host 再退出（defer 统一补发）
			return speedHostResult{}, ctx.Err()
		}
		if time.Now().After(deadline) {
			cancelSpeedHost(c, h.ID, timeout)
			return speedHostResult{}, errors.New("status 轮询超预算（MUST NOT 无限转圈）——已取消该主机")
		}
		st, err := fetchSpeedStatus(ctx, c, h.ID, timeout)
		if err != nil {
			if ctx.Err() != nil {
				return speedHostResult{}, ctx.Err() // defer 补发 cancel
			}
			// L5（exec-r1）：status 连续失败如实报错（此前静默烧满整个轮询预算）；
			// 瞬时抖动仍给短窗重试（250ms × 8 = 2s）。
			failStreak++
			if failStreak >= statusFailStreak {
				return speedHostResult{name: name, hex: h.ID, ok: false, reason: "control_error",
					msg: fmt.Sprintf("status 连续 %d 次失败：%v", failStreak, err), via: via, rttMs: rtt}, nil
			}
			time.Sleep(250 * time.Millisecond)
			continue
		}
		failStreak = 0
		if st.Result != nil { // 终态
			return speedHostResult{
				name: name, hex: h.ID, ok: st.Result.OK, reason: st.Result.Reason, msg: st.Result.Msg,
				downBps: st.Result.DownBps, upBps: st.Result.UpBps,
				usageDown: st.Result.UsageDown, usageUp: st.Result.UsageUp, wallMs: st.Result.WallMs,
				via: via, rttMs: rtt,
			}, nil
		}
		// L5（exec-r1）：本台已 start 过——phase=idle 且无终态 = 运行面丢失（daemon
		// 重启等）：快速失败，不烧满轮询预算。
		if !st.Waiting && st.Result == nil && st.Phase == string(speedtest.PhaseIdle) {
			return speedHostResult{name: name, hex: h.ID, ok: false, reason: "interrupted",
				msg: "运行面丢失（守护进程重启？）——本轮测速已不在，请重试", via: via, rttMs: rtt}, nil
		}
		if !quiet && time.Since(lastHint) >= time.Second {
			lastHint = time.Now()
			if st.Waiting {
				fmt.Fprintf(errW, "  等待链路就绪（剩余 %ds）……\n", st.WaitRemainMs/1000)
			} else if st.Dir != "" && st.InstBps > 0 {
				fmt.Fprintf(errW, "  %s %s\n", speedDirText(st.Dir), humanRate(st.InstBps))
			} else {
				fmt.Fprintf(errW, "  %s……\n", speedPhaseText(st.Phase))
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// statusFailStreak status 轮询连续失败上限（超出 = 如实报错；250ms 拍 × 8 = 2s 短窗）。
const statusFailStreak = 8

// fetchSpeedStatus 一次 status 轮询（独立小预算——轮询不占长请求）。
func fetchSpeedStatus(ctx context.Context, c *control.Client, host string, timeout time.Duration) (control.SpeedtestStatusResult, error) {
	reqCtx, reqCancel := context.WithTimeout(ctx, timeout)
	defer reqCancel()
	raw, err := c.Request(reqCtx, facade.OpSpeedtestStatus, control.SpeedtestStatusArgs{Host: host})
	if err != nil {
		return control.SpeedtestStatusResult{}, err
	}
	var st control.SpeedtestStatusResult
	if err := json.Unmarshal(raw, &st); err != nil {
		return control.SpeedtestStatusResult{}, err
	}
	return st, nil
}

// cancelSpeedHost Ctrl-C/超预算收尾：先 cancel 当前 host（只作用该主机、不波及轮转）。
func cancelSpeedHost(c *control.Client, host string, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, _ = c.Request(ctx, facade.OpSpeedtestCancel, control.SpeedtestCancelArgs{Host: host})
}

// printSpeedResult 一台主机的双口径输出（人面；--json 走 speedHostResult.json）。
func printSpeedResult(w io.Writer, hosts []control.HostState, r speedHostResult) {
	if !r.ok {
		fmt.Fprintf(w, "✗ %s：%s（%s）\n", r.name, speedShortReason(r.reason), r.reason)
		return
	}
	fmt.Fprintf(w, "✓ %s：↑%s ↓%s\n", r.name, humanRate(r.upBps), humanRate(r.downBps))
	fmt.Fprintf(w, "  精确值：down=%.0fB/s（%.2fMbps，%.2fMB/s） up=%.0fB/s（%.2fMbps，%.2fMB/s） 用量 ↓%s ↑%s 墙钟 %.1fs\n",
		r.downBps, r.downBps*8/1e6, r.downBps/1048576,
		r.upBps, r.upBps*8/1e6, r.upBps/1048576,
		humanBytes(r.usageDown), humanBytes(r.usageUp), float64(r.wallMs)/1000)
}

// humanRate 手机显示口径（speedtest spec「结果与口径」）：1024 进位、≥1MB/s 用
// MB/s 不足用 KB/s、四舍五入整数（进位到 1024KB 的值归 MB 档）；单位顺序由调用方
// 排（上行在前）。CLI 与 App 同一口径的换算真源——用例值对拍 spec Scenario。
func humanRate(bps float64) string {
	kb := bps / 1024
	rk := math.Round(kb)
	if rk >= 1024 { // 四舍五入进位到 1024KB 的值归 MB 档（spec 口径）
		return fmt.Sprintf("%dMB/s", int64(rk/1024))
	}
	return fmt.Sprintf("%dKB/s", int64(rk))
}

// speedShortReason 失败短因（与手机 SpeedTestRules.ets 的短因族对齐的 CLI 版文案）。
func speedShortReason(reason string) string {
	switch reason {
	case speedtest.ReasonBusy:
		return "并发满员，稍后再试"
	case speedtest.ReasonLinkDown:
		return "链路未就绪（恢复中）"
	case speedtest.ReasonBridgeDown:
		return "主机未连接"
	case speedtest.ReasonBridgeAuth:
		return "凭据过期"
	case speedtest.ReasonNotSupported:
		return "出口没有测速服务（出口需升级）"
	case speedtest.ReasonInterrupted:
		return "通道错误"
	case speedtest.ReasonTimeout:
		return "超时"
	case speedtest.ReasonCancelled:
		return "已取消"
	case "control_error":
		return "控制面错误"
	}
	return "失败"
}

func speedDirText(dir string) string {
	if dir == "up" {
		return "上行中"
	}
	return "下行中"
}

func speedPhaseText(phase string) string {
	switch phase {
	case "waiting":
		return "等待链路就绪"
	case "connecting":
		return "建立连接"
	case "down":
		return "下行中"
	case "up":
		return "上行中"
	}
	return "测速中"
}
