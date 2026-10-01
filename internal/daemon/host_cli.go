package daemon

// host_cli.go — homeway host add/list/status/delete（host-cli 1.7，spec host-cli）：
// 桌面侧管理守护进程多主机注册表的用户入口。命令归属全部 = **守护托管**（经控制
// 面 UDS 操作 daemon 持有的注册表，MUST NOT 直读/直写 hosts.json）；daemon 未运行
// 时报可行动错误（sock 路径 + 启动命令），无降级直读表模式（design D5）。
//
// token 是凭证：输出/错误恒掩码（前缀+尾部若干字符），不回显全文（argv 传入与
// 凭证类命令同威胁模型，文档注记）。--json 形状钉死（design D6/r1 ④-4）：
// list --json 与 status --json 同形 = 控制面快照的 hosts 数组原样（stdout 一行
// JSON、无包裹对象；status <name> = 仅含该主机的单元素数组）。

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/zhaoyswd/homeway/clientcore/facade"
	"io"
	"os"
	"strings"
	"time"

	"github.com/zhaoyswd/homeway/internal/cliopts"
	"github.com/zhaoyswd/homeway/internal/control"
	"github.com/zhaoyswd/homeway/pkg/proto"
)

// HostCLI host 命令面入口（cmd/homeway 顶层名词直连；输出写 w 便于测试）。
func HostCLI(args []string, version string, w io.Writer) error {
	return hostCLI(args, version, w)
}

// hostCLI host 子命令入口（内部实现）。
func hostCLI(args []string, version string, w io.Writer) error {
	if len(args) == 0 {
		usageHost(w)
		return errors.New("host 需要子命令：add / list / status / delete")
	}
	switch args[0] {
	case "add":
		return hostAddCLI(args[1:], version, w)
	case "list":
		return hostListCLI(args[1:], version, w)
	case "status":
		return hostStatusCLI(args[1:], version, w)
	case "delete":
		return hostDeleteCLI(args[1:], version, w)
	}
	usageHost(w)
	return fmt.Errorf("host 不认识的子命令 %q（可用：add / list / status / delete）", args[0])
}

func usageHost(w io.Writer) {
	fmt.Fprint(w, `用法：
  homeway host add [--name N] [--force] <token>   添加主机（服务端有界连通性验证，三档结论）
  homeway host list [--json]                      主机列表（会话态/链路态/流量/添加时间）
  homeway host status [name] [--json]             单台（省略 name = 全部）详面
  homeway host delete <name|id> [--yes]           删除（交互确认；非终端需 --yes）
全部子命令可加 --state DIR（默认与 daemon status 同款）与 --timeout。
`)
}

// hostAddCLI add [--name N] [--force] [--timeout] <token>。
func hostAddCLI(args []string, version string, w io.Writer) error {
	fs := flag.NewFlagSet("homeway host add", flag.ContinueOnError)
	fs.SetOutput(w)
	stateDir := fs.String("state", DefaultStateDir(), "统一 state 根（从中找 control.sock）")
	noSpawn := fs.Bool("no-spawn", false, "守护进程未运行时不按需拉起（直接报可行动错误；脚本友好）")
	name := fs.String("name", "", "主机显示名（可空 = 不命名）")
	force := fs.Bool("force", false, "仍然添加：跳过服务端连通性验证直接入表（端点未实测）")
	timeout := fs.Duration("timeout", 10*time.Second, "连接与请求的总预算（默认 10s > 3.5s 探测 + 余量）")
	if err := fs.Parse(flagsFirst(args, hostFlagBools)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("host add 需要 <token>（token 形如 hmw1…，从出口日志现场获取）")
	}
	token := strings.TrimSpace(fs.Arg(0))
	// ①本地语法校验前置（spec host-cli「token 非法就地报错」：不探测、不连
	// daemon、不入表——失败就地退出）。
	if _, err := proto.DecodeToken(token); err != nil {
		return fmt.Errorf("token 非法（%s）：%v（token 形如 hmw1…，从出口启动日志现场获取后重新粘贴）", maskToken(token), err)
	}
	// exec-r1 第 11 条：--timeout 低于 5s 时告警——服务端探测预算 ≤3.5s，客户端
	// ctx 先退时服务端（每请求独立 goroutine）继续探测并**已入表**，脚本按退出码
	// 判失败会误判（--force 重试得 host_exists）。
	if *timeout < 5*time.Second {
		fmt.Fprintf(w, "  警告：--timeout=%s 低于 5s——超时先退时主机或已入表（核对：homeway host list）\n", *timeout)
	}

	// ②守护托管：结论（三档 + 实测端点）以 host.add 响应载荷只增字段返回；
	// 连接层（含未运行按需拉起）由统一缝给可行动错误。
	ctx, cancel := context.WithTimeout(cliopts.With(context.Background(), cliopts.Opts{NoSpawn: *noSpawn}), *timeout)
	defer cancel()
	c, err := dialControlSpawn(ctx, *stateDir, version, "homeway-host")
	if err != nil {
		return err
	}
	defer c.Close()
	raw, err := c.Request(ctx, facade.OpHostAdd, control.HostAddArgs{Name: *name, Token: token, Force: *force})
	if err != nil {
		var code control.CodeError
		switch {
		case errors.As(err, &code) && string(code) == facade.CodeHostUnreachable:
			return fmt.Errorf("全不可达：token %s 的全部端点（直连与中继）在预算内均无应答，主机未入表\n排查：出口是否在运行 / token 是否为最新（重启出口取新 token）/ 网络与防火墙是否放行 UDP / 受限网络需在出口配置中继后重新粘贴\n仍然添加：homeway host add <token> --force", maskToken(token))
		case errors.As(err, &code) && string(code) == facade.CodeBadToken:
			return fmt.Errorf("token 非法（%s）：服务端解码失败，请从出口启动日志重新获取", maskToken(token))
		case errors.As(err, &code) && string(code) == facade.CodeHostExists:
			return fmt.Errorf("该后端已在表中（同 token 重复添加；换新 token = 同键刷新，无需先删）")
		case errors.As(err, &code) && string(code) == facade.CodeNotReady:
			return fmt.Errorf("守护进程注册表未就绪（client 角色启动中/重建窗口），稍后重试")
		default:
			return fmt.Errorf("host.add 失败：%w", err)
		}
	}
	var res control.HostAddResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return fmt.Errorf("host.add 载荷解析失败：%w", err)
	}
	printHostAdded(w, &res)
	return nil
}

// printHostAdded 三档映射输出（spec host-cli「host add 的呈现」）。
//
// exec-r1 第 1 条：Reach == nil（**版本偏斜**——3a 期常驻 daemon 的 host.add 回
// HostBrief{id,name,addedAt}，无 reach 字段；daemon 独立常驻、升级 CLI 二进制不重启
// 它时该形态可达）走降级分支——不得解引用、不得静默；主机确实已入表（旧 daemon 会
// 先入表），提示重启 daemon 后可复核。未知 tier 值（词表只增，未来新增或漂移）同样
// 非静默（exec-r1 第 4 条）：打印原始值 +「验证结论未知」，添加本身成功不误报失败。
func printHostAdded(w io.Writer, res *control.HostAddResult) {
	name := res.Name
	if name == "" {
		name = "-"
	}
	if res.Reach == nil {
		hint := ""
		if res.Name != "" {
			hint = fmt.Sprintf("（homeway host status %s）", res.Name)
		}
		fmt.Fprintf(w, "已添加主机 %s（%s）——旧版守护进程无验证结论，重启 daemon 后可复核%s\n", name, shortHostID(res.ID), hint)
		return
	}
	switch res.Reach.Tier {
	case facade.ReachTierDirect:
		fmt.Fprintf(w, "已添加主机 %s（%s）——直连可达 ep=%s rtt=%dms\n", name, shortHostID(res.ID), res.Reach.BestEp, res.Reach.RttMs)
	case facade.ReachTierRelay:
		fmt.Fprintf(w, "已添加主机 %s（%s）——仅中继可达 ep=%s rtt=%dms\n", name, shortHostID(res.ID), res.Reach.BestEp, res.Reach.RttMs)
		fmt.Fprintln(w, "  提示：直连不可达，连接将走中继；若非预期请检查出口公网端口/UPnP")
	case facade.ReachTierSkipped:
		fmt.Fprintf(w, "已添加主机 %s（%s）——跳过验证（--force，端点未实测，首次连接时补全）\n", name, shortHostID(res.ID))
	default:
		fmt.Fprintf(w, "已添加主机 %s（%s）——验证结论未知（tier=%q，词表外值；守护进程版本或高于本 CLI）\n", name, shortHostID(res.ID), res.Reach.Tier)
	}
}

// hostListCLI list [--json]。
func hostListCLI(args []string, version string, w io.Writer) error {
	fs := flag.NewFlagSet("homeway host list", flag.ContinueOnError)
	fs.SetOutput(w)
	stateDir := fs.String("state", DefaultStateDir(), "统一 state 根（从中找 control.sock）")
	noSpawn := fs.Bool("no-spawn", false, "守护进程未运行时不按需拉起（直接报可行动错误；脚本友好）")
	jsonOut := fs.Bool("json", false, "机器可读 JSON = 控制面快照的 hosts 数组原样（stdout 一行，无包裹对象）")
	timeout := fs.Duration("timeout", 5*time.Second, "连接与请求的总预算")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("host list 不接受位置参数（got %q）", fs.Args())
	}
	hosts, closeC, err := fetchHosts(*stateDir, *timeout, version, *noSpawn)
	if err != nil {
		return err
	}
	defer closeC()
	if *jsonOut {
		b, err := json.Marshal(hosts)
		if err != nil {
			return err
		}
		fmt.Fprintln(w, string(b))
		return nil
	}
	printHostList(w, hosts)
	return nil
}

// fetchHosts 一次 daemon.status 拿主机动态面（list/status/delete 共用投影真源；
// role-management 4.1 起经按需拉起的统一注入缝——noSpawn 由各命令 flag 集传入）。
func fetchHosts(stateDir string, timeout time.Duration, version string, noSpawn bool) ([]control.HostState, func(), error) {
	ctx, cancel := context.WithTimeout(cliopts.With(context.Background(), cliopts.Opts{NoSpawn: noSpawn}), timeout)
	c, err := dialControlSpawn(ctx, stateDir, version, "homeway-host")
	if err != nil {
		cancel()
		return nil, nil, err
	}
	closeC := func() { c.Close(); cancel() }
	raw, err := c.Request(ctx, facade.OpDaemonStatus, nil)
	if err != nil {
		closeC()
		return nil, nil, fmt.Errorf("daemon.status 失败：%w", err)
	}
	var st control.DaemonStatusResult
	if err := json.Unmarshal(raw, &st); err != nil {
		closeC()
		return nil, nil, fmt.Errorf("daemon.status 载荷解析失败：%w", err)
	}
	return st.Hosts, closeC, nil
}

// printHostList 表格：名称/短 ID/会话态/链路态/流量/添加时间。
func printHostList(w io.Writer, hosts []control.HostState) {
	if len(hosts) == 0 {
		fmt.Fprintln(w, "无主机（homeway host add <token> 添加）")
		return
	}
	fmt.Fprintf(w, "%-12s %-10s %-14s %-22s %-16s %s\n", "名称", "ID", "会话态", "链路", "收/发", "添加时间")
	for _, h := range hosts {
		name := h.Name
		if name == "" {
			name = "-"
		}
		state := h.State
		if h.Reason != "" {
			state += "/" + h.Reason
		}
		link := "-"
		if h.Link != nil {
			link = fmt.Sprintf("%s %s %dms", h.Link.Via, h.Link.Ep, h.Link.RttMs)
		}
		traffic := "-"
		if h.Stats != nil {
			traffic = fmt.Sprintf("%s/%s", humanBytes(h.Stats.RxBytes), humanBytes(h.Stats.TxBytes))
		}
		added := "-"
		if h.AddedAt != 0 {
			added = time.UnixMilli(h.AddedAt).Format("2006-01-02 15:04")
		}
		fmt.Fprintf(w, "%-12s %-10s %-14s %-22s %-16s %s\n", truncRunes(name, 12), shortHostID(h.ID), truncRunes(state, 14), truncRunes(link, 22), traffic, added)
	}
}

func truncRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max-1]) + "…"
}

// hostStatusCLI status [name] [--json]：单台详面（省略 name = 全部）。
func hostStatusCLI(args []string, version string, w io.Writer) error {
	fs := flag.NewFlagSet("homeway host status", flag.ContinueOnError)
	fs.SetOutput(w)
	stateDir := fs.String("state", DefaultStateDir(), "统一 state 根（从中找 control.sock）")
	noSpawn := fs.Bool("no-spawn", false, "守护进程未运行时不按需拉起（直接报可行动错误；脚本友好）")
	jsonOut := fs.Bool("json", false, "机器可读 JSON = hosts 数组原样（status <name> = 单元素数组）")
	timeout := fs.Duration("timeout", 5*time.Second, "连接与请求的总预算")
	if err := fs.Parse(flagsFirst(args, hostFlagBools)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 1 {
		return fmt.Errorf("host status 至多一个位置参数（主机名），got %q", fs.Args())
	}
	hosts, closeC, err := fetchHosts(*stateDir, *timeout, version, *noSpawn)
	if err != nil {
		return err
	}
	defer closeC()
	name := ""
	if fs.NArg() == 1 {
		name = fs.Arg(0)
		if strings.TrimSpace(name) == "" {
			return errors.New("空主机名不可寻址——homeway host status [name] 需要主机名，或省略 name 查看全部（homeway host list 查看在表主机）")
		}
		var matched []control.HostState
		for _, h := range hosts {
			if h.Name == name {
				matched = append(matched, h)
			}
		}
		if len(matched) == 0 {
			return fmt.Errorf("主机 %q 不存在（homeway host list 查看在表主机）", name)
		}
		if len(matched) > 1 {
			// exec-r1 第 6 条：host status 只按名称匹配（不支持 ID 寻址）——提示
			// 必须可行动：改名或先删其一。
			return fmt.Errorf("多台主机同名 %q（%d 台）——请先改名（host delete 其一后重新 host add 命名）再查，或用 host list --json 看全部", name, len(matched))
		}
		hosts = matched
	}
	if *jsonOut {
		b, err := json.Marshal(hosts)
		if err != nil {
			return err
		}
		fmt.Fprintln(w, string(b))
		return nil
	}
	for _, h := range hosts {
		printHostDetail(w, &h)
	}
	return nil
}

// printHostDetail 单台详面：登记信息（名称/完整 ID/添加时间）+ 会话/链路/流量。
func printHostDetail(w io.Writer, h *control.HostState) {
	name := h.Name
	if name == "" {
		name = "-"
	}
	fmt.Fprintf(w, "主机 %s（%s）\n", name, h.ID)
	added := "-"
	if h.AddedAt != 0 {
		added = time.UnixMilli(h.AddedAt).Format("2006-01-02 15:04:05")
	}
	fmt.Fprintf(w, "  添加时间： %s\n", added)
	state := h.State
	if h.Reason != "" {
		state += "（" + h.Reason + "）"
	}
	fmt.Fprintf(w, "  会话态： %s\n", state)
	if h.Link != nil {
		fmt.Fprintf(w, "  链路： via=%s ep=%s rtt=%dms\n", h.Link.Via, h.Link.Ep, h.Link.RttMs)
	} else {
		fmt.Fprint(w, "  链路： 未确立\n")
	}
	if h.Stats != nil {
		fmt.Fprintf(w, "  流量： 收 %s / 发 %s\n", humanBytes(h.Stats.RxBytes), humanBytes(h.Stats.TxBytes))
	}
}

// hostDeleteCLI delete <name|id> [--yes]。
func hostDeleteCLI(args []string, version string, w io.Writer) error {
	fs := flag.NewFlagSet("homeway host delete", flag.ContinueOnError)
	fs.SetOutput(w)
	stateDir := fs.String("state", DefaultStateDir(), "统一 state 根（从中找 control.sock）")
	noSpawn := fs.Bool("no-spawn", false, "守护进程未运行时不按需拉起（直接报可行动错误；脚本友好）")
	yes := fs.Bool("yes", false, "跳过交互确认（非终端 stdin 必须）")
	timeout := fs.Duration("timeout", 5*time.Second, "连接与请求的总预算")
	if err := fs.Parse(flagsFirst(args, hostFlagBools)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("host delete 需要 <name|id>（homeway host list 查看）")
	}
	target := fs.Arg(0)
	hosts, closeC, err := fetchHosts(*stateDir, *timeout, version, *noSpawn)
	if err != nil {
		return err
	}
	defer closeC()
	id, dname, err := resolveHostTarget(hosts, target)
	if err != nil {
		return err
	}

	// 交互确认（默认 N）：非终端且未给 --yes = 拒绝（防脚本误删）。
	if !*yes {
		if !stdinIsTerminal() {
			return fmt.Errorf("标准输入不是终端：删除 %s（%s）需 --yes 确认", dname, shortHostID(id))
		}
		fmt.Fprintf(w, "将删除主机 %s（%s）——停止会话、出表并落盘，不可撤销。[y/N] ", dname, id)
		rd := bufio.NewReader(os.Stdin)
		line, _ := rd.ReadString('\n')
		line = strings.TrimSpace(strings.ToLower(line))
		if line != "y" && line != "yes" {
			fmt.Fprintln(w, "已取消")
			return nil
		}
	}

	ctx, cancel := context.WithTimeout(cliopts.With(context.Background(), cliopts.Opts{NoSpawn: *noSpawn}), *timeout)
	defer cancel()
	c, err := dialControlSpawn(ctx, *stateDir, version, "homeway-host")
	if err != nil {
		return err // 统一缝的可行动错误（未运行拉起/--no-spawn/不可达分型）
	}
	defer c.Close()
	var code control.CodeError
	if _, err := c.Request(ctx, facade.OpHostRemove, control.HostRemoveArgs{Host: id}); err != nil {
		switch {
		case errors.As(err, &code) && string(code) == facade.CodeNoHost:
			return fmt.Errorf("主机 %s 不存在或已被删除（homeway host list 查看）", target)
		default:
			return fmt.Errorf("host.remove 失败：%w", err)
		}
	}
	fmt.Fprintf(w, "已删除主机 %s（%s）\n", dname, shortHostID(id))
	return nil
}

// resolveHostTarget 寻址：名称精确 / peerID hex 全长 / 短前缀无歧义（歧义报错
// 列候选——可行动）。不存在报错（幂等 ≠ 静默成功）。
func resolveHostTarget(hosts []control.HostState, target string) (id, name string, err error) {
	// exec-r1 第 5 条：空 target 显式拒绝——strings.HasPrefix(h.ID, "") 恒真，
	// 单主机时会命中唯一主机（误删风险）、多主机时报歧义；均不可达。
	if strings.TrimSpace(target) == "" {
		return "", "", errors.New("空寻址串不可用——homeway host delete 需要 <name|id>（homeway host list 查看）")
	}
	// ① 名称精确匹配。
	var byName []control.HostState
	for _, h := range hosts {
		if h.Name != "" && h.Name == target {
			byName = append(byName, h)
		}
	}
	if len(byName) == 1 {
		return byName[0].ID, displayName(&byName[0]), nil
	}
	if len(byName) > 1 {
		return "", "", fmt.Errorf("多台主机同名 %q——请用完整 ID 寻址", target)
	}
	// ② ID 全长（64 hex）。
	if len(target) == 64 {
		for _, h := range hosts {
			if h.ID == target {
				return h.ID, displayName(&h), nil
			}
		}
		return "", "", fmt.Errorf("主机 %s 不存在（homeway host list 查看）", target)
	}
	// ③ 短前缀（无歧义才接受）。
	var pref []control.HostState
	for _, h := range hosts {
		if strings.HasPrefix(h.ID, target) {
			pref = append(pref, h)
		}
	}
	if len(pref) == 1 {
		return pref[0].ID, displayName(&pref[0]), nil
	}
	if len(pref) > 1 {
		ids := make([]string, 0, len(pref))
		for _, h := range pref {
			ids = append(ids, shortHostID(h.ID))
		}
		return "", "", fmt.Errorf("前缀 %q 有歧义（候选：%s）——用更长前缀或完整 ID", target, strings.Join(ids, "、"))
	}
	return "", "", fmt.Errorf("主机 %q 不存在（homeway host list 查看在表主机）", target)
}

func displayName(h *control.HostState) string {
	if h.Name == "" {
		return "-"
	}
	return h.Name
}

// maskToken token 掩码（前 4 + … + 尾 4；短串整体遮）。
func maskToken(tok string) string {
	if len(tok) <= 8 {
		return strings.Repeat("·", len(tok))
	}
	return tok[:4] + "…" + tok[len(tok)-4:]
}

// stdinIsTerminal 终端判定注入缝（生产 = os.Stdin 的 char device 判定；同包测试
// 注入——go test 的 stdin=/dev/null 也是 char device，不能作非 tty 路径的天然载体）。
var stdinIsTerminal = func() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// flagsFirst 位置参数挪到 flag 之后（flag 值跟随其 flag）。spec 用法形态是
// `host add [--name N] [--force] <token>` / `delete <name|id> [--yes]`——位置参数
// 可前可后；标准 flag 包遇首个位置参数即停，这里先重排再 Parse。
// boolFlags = 不吃独立值的 flag 名（含单/双划线去缀后的名字）。
func flagsFirst(args []string, boolFlags map[string]bool) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if idx := strings.IndexByte(name, '='); idx >= 0 {
				continue // --state=X 自含值
			}
			if !boolFlags[name] && i+1 < len(args) {
				i++
				flags = append(flags, args[i]) // --state X：值跟随
			}
			continue
		}
		pos = append(pos, a)
	}
	return append(flags, pos...)
}

// cliBoolFlags CLI 全命令面**布尔 flag 全集**（flagsFirst 用；FIX-57 收一份）：
// host/forward/socks/speedtest/artifact 各面共用一张表。此前两张分表且都漏
// `no-spawn`（它定义在各命令的 fs.Bool 里）——`--no-spawn` 被 flagsFirst 当成
// 「吃后一个 token 的值 flag」，会把紧随其后的 flag/位置参数错位吞掉。
// 并集用法安全：flagsFirst 只做重排，真正的 flag 定义仍由各命令的 FlagSet 判定
// （未定义的 flag 照旧报错）。
var cliBoolFlags = map[string]bool{
	"force": true, "json": true, "yes": true, "help": true, "h": true,
	"no-spawn": true, "quiet": true, "verbose": true, "watch": true, "stdin": true,
}

// hostFlagBools host 命令面的布尔 flag 集（= 共享表）。
var hostFlagBools = cliBoolFlags
