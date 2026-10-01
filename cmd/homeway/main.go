// homeway：Homeway 单二进制入口 —— `homeway <谁> <干什么>` 命令体系
// （role-management D1：顶层名词三类——角色 serve/relay、客户端域 host/term/files/
// forward/socks/speedtest、跨域 status）。
//
//	homeway [--state D] [--verbose]  # 零参 = 统一进程前台（按 config 期望态装配全部启用角色）
//	homeway serve [flags]            # 前台只跑出口（一次性覆盖，不改期望态）
//	homeway serve <动词> …           # serve 命令组：start/stop/restart/status/token/relay/ddns
//	homeway relay [flags]            # 前台只跑中继（默认 :41741）
//	homeway relay <动词> …           # relay 命令组：start/stop/restart/status/token
//	homeway status [--json|--watch]  # 聚合状态面（吸收旧 daemon status）
//	homeway export|import|reset …    # 状态工件（不变量四件备份/恢复、清 cache）
//	homeway term/files/host/forward/socks/speedtest …   # 客户端域命令面
//	homeway --version
//
// 统一进程只认全局 flag（--state/--verbose）；角色 flag 打在统一进程形态 = 可行动
// 错误（r1 中-1——角色参数走 config 或 serve/relay 前台形态）。同 state 单实例锁
// （<state>/lock）对统一进程与前台单角色互斥。旧名词 `exit`/`daemon` = 迁移提示
// 报错（非零码，不再按旧语义启动任何进程）。
package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/zhaoyswd/homeway/internal/daemon"
	"github.com/zhaoyswd/homeway/internal/relay"
	"github.com/zhaoyswd/homeway/internal/server"
	"github.com/zhaoyswd/homeway/pkg/files"
	"github.com/zhaoyswd/homeway/pkg/term"
)

// version 由 CI 用 -ldflags "-X main.version=<tag>" 注入（必须是 var：-X 对 const 无效）。
var version = "0.0.0-dev"

// serveGroupVerbs / relayGroupVerbs 命令组动词（名词后首个位置参数命中即走命令组；
// 否则 = 前台单角色形态——动词必须紧跟名词，`homeway serve --state D start` 按
// 前台形态报「不认识的参数」并提示动词位置）。
var serveGroupVerbs = map[string]bool{
	"start": true, "stop": true, "restart": true, "status": true, "token": true, "relay": true, "ddns": true,
}

var relayGroupVerbs = map[string]bool{
	"start": true, "stop": true, "restart": true, "status": true, "token": true,
}

func main() {
	if code := run(os.Args[1:]); code != 0 {
		os.Exit(code)
	}
}

// run 返回进程退出码，便于测试（不直接 os.Exit）。
func run(args []string) int {
	// 顶层元命令：homeway --version / homeway --help
	if meta(args) {
		return 0
	}

	role, rest := resolveRole(args)
	// 角色后的版本号：homeway relay --version / homeway serve --version（r1 低-5）。
	// 注意 **不** 在这里截 --help —— 角色的 --help 由各自的 flag 集打印（参数列表不同）。
	if onlyVersion(rest) {
		return 0
	}
	relay.Version = version // 探测应答的构建标记（add-host-connectivity）

	var err error
	switch role {
	case "unified":
		// 零参 / 首参全局 flag = 统一进程前台（按 config 期望态装配；只认全局 flag）。
		err = daemon.RunUnified(version, rest)
	case "serve":
		if groupVerb(rest, serveGroupVerbs) {
			err = daemon.ServeGroupCLI(rest, version, os.Stdout)
		} else {
			// 前台单角色（exit → serve 更名；词表随 role-management 同升）。
			err = server.CLI(rest)
		}
	case "relay":
		if groupVerb(rest, relayGroupVerbs) {
			err = daemon.RelayGroupCLI(rest, version, os.Stdout)
		} else {
			err = relay.CLI(rest)
		}
	case "status":
		// 聚合状态面（role-management 3.4：吸收旧 daemon status；--watch 平移）。
		err = daemon.StatusCLI(rest, version, os.Stdout)
	case "export":
		err = daemon.ExportCLI(rest, os.Stdout)
	case "import":
		err = daemon.ImportCLI(rest, os.Stdout)
	case "reset":
		err = daemon.ResetCLI(rest, os.Stdout)
	case "exit":
		fmt.Fprintln(os.Stderr, "homeway: `exit` 已更名为 `serve`——前台出口用 `homeway serve`，统一进程（按 config 期望态装配全部角色）直接 `homeway`，启停/查询用 `homeway serve start|stop|status|token`；请更新脚本与文档")
		return 2
	case "daemon":
		fmt.Fprintln(os.Stderr, "homeway: `daemon` 已并入统一进程——直接 `homeway`（零参前台；按 config 期望态装配全部角色）；状态看 `homeway status`（旧 daemon status 已删除）；请更新脚本与文档")
		return 2
	case "term":
		// 远程接入缝注入（term-remote D1）：`term … --host <ref>` 经 daemon 控制面
		// 转发；nil = 仅本地面（此处恒注入）。
		err = term.CLI(rest, daemon.TermRemote(version))
	case "files":
		// 远程接入缝注入（files-cli D1/D3，同款形态）：`files … --host <ref>` 经
		// daemon 控制面 stream.open{kind:files} 转发；nil = 仅本地面（此处恒注入）。
		err = files.CLI(rest, daemon.FilesRemote(version))
	case "host":
		err = daemon.HostCLI(rest, version, os.Stdout)
	case "forward":
		err = daemon.ForwardCLI(rest, version, os.Stdout)
	case "socks":
		err = daemon.SocksCLI(rest, version, os.Stdout)
	case "speedtest":
		err = daemon.SpeedtestCLI(rest, version, os.Stdout, os.Stderr)
	default:
		fmt.Fprintf(os.Stderr, "homeway: 不认识的子命令 %q（可用：serve、relay、status、export、import、reset、term、files、host、forward、socks、speedtest；零参 = 统一进程）\n", role)
		usage(os.Stderr)
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "homeway:", err)
		return 1
	}
	return 0
}

// meta：顶层 --version / --help。命中即处理并返回 true。
func meta(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "--version", "-v", "version":
		fmt.Println("homeway", version)
		return true
	case "--help", "-h", "help":
		usage(os.Stdout)
		return true
	}
	return false
}

// onlyVersion：角色后的 --version（角色的 --help 交给各自 flag 集处理）。
func onlyVersion(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "--version", "-v", "version":
		fmt.Println("homeway", version)
		return true
	}
	return false
}

// groupVerb 名词后首个 token 是否命令组动词（serve/relay 名词双态分派，D1）。
func groupVerb(rest []string, verbs map[string]bool) bool {
	return len(rest) > 0 && verbs[rest[0]]
}

// resolveRole：从首个位置参数解析角色，返回角色与剩余参数。
func resolveRole(args []string) (role string, rest []string) {
	if len(args) == 0 {
		return "unified", nil // 裸 `homeway` = 统一进程前台（按 config 期望态装配）
	}
	switch args[0] {
	case "serve":
		return "serve", args[1:]
	case "relay":
		return "relay", args[1:]
	case "status":
		return "status", args[1:]
	case "export":
		return "export", args[1:]
	case "import":
		return "import", args[1:]
	case "reset":
		return "reset", args[1:]
	case "exit":
		return "exit", args[1:]
	case "daemon":
		return "daemon", args[1:]
	case "term":
		return "term", args[1:]
	case "files":
		return "files", args[1:]
	case "host":
		return "host", args[1:]
	case "forward":
		return "forward", args[1:]
	case "socks":
		return "socks", args[1:]
	case "speedtest":
		return "speedtest", args[1:]
	}
	// `homeway --state D` 这类省略名词的写法：首参是 flag 时按统一进程走
	//（零参形态的等价入口；统一进程拒收角色 flag，r1 中-1）。
	if strings.HasPrefix(args[0], "-") {
		return "unified", args
	}
	return args[0], args[1:] // 未知角色 —— 交给上层报错
}

func usage(w io.Writer) {
	fmt.Fprint(w, `homeway —— Homeway 出口与中继（单二进制，统一进程 + 按需命令）

用法：
  homeway [--state DIR] [--verbose]
                               统一进程前台（零参）：按 <state>/config.toml 期望态装配
                               全部启用角色（serve/relay）+ 恒开的 client/control；
                               同 state 单实例锁（<state>/lock）
  homeway serve [flags]        前台只跑出口（调试形态：不改期望态；flag 一次性覆盖
                               config；--state 即统一 state 根——L2=<state>/serve、
                               L3=<state>/cache）
  homeway serve start|stop|restart [--state DIR] [--no-spawn]
                               角色启停（写 config 期望态；start 未跑时按需拉起统一
                               进程；stop 收尾异步、立即应答；restart 角色停时报错
                               先 start）
  homeway serve status [--json]
                               期望+运行态+观测面（监听/端点/token 掩码/ddns/APP 设备
                               表/过境拦截计数；未跑降级读 config）
  homeway serve token          完整 hmw1 凭证（在跑控制面 / 未跑直读台账末行）
  homeway serve relay set <token> [--stdin] | clear
                               上游中继 token 写/清 config（纯文件操作，需
                               homeway serve restart 生效）。⚠️ 命名消歧义：
                               serve.relay = 本出口**注册到哪个上游中继**；
                               [relay] 节与 homeway relay = 本机**当中继**——
                               同词根不同义
  homeway serve ddns add|delete <domain> | list
                               DDNS 条目（多条目，写 config；需 restart 生效）
  homeway relay [flags]        前台只跑中继（默认 :41741；同上路径注入）
  homeway relay start|stop|restart|status [--json]|token
                               relay 命令组（对称；token 未跑 = relay.key+config
                               离线推算并注明口径）
  homeway status [--json] [--watch]
                               聚合状态面：进程层 + serve + relay + client 四域
                               （未跑时读 config 报期望态，纯读不拉起；--watch =
                               client 域 live 渲染，观测即需求——watch 期间被显示
                               主机视为有需求）
  homeway export [--state DIR] [dest.tar]
                               不变量四件打包（config.toml + serve/ + relay/ +
                               client/；0600 未压缩 tar）
  homeway import <file> [--state DIR]
                               工件导入（布局校验 + 落位序回滚；目标进程必须在停）
  homeway reset cache [--state DIR]
                               清可弃层 cache/（在跑拒绝；L1/L2 与备份不动）
  homeway term <子命令> …      终端命令面（list / new / attach / delete / explain；
                               与 App 同一份会话注册表，经 <state>/term.sock 本地直连）
  homeway files <子命令> …     文件命令面（类 sftp：list / stat / mkdir / read / get /
                               put；无 --host 直连 <state>/files.sock、--host <ref> 经
                               daemon 控制面转发到指定后端主机——--state 双面指代差异
                               见 homeway files --help）
  homeway host add [--name N] [--force] <token>
                               添加主机（服务端有界连通性验证，三档结论；token 恒掩码）
  homeway host list [--json]   主机列表（会话态/链路态/流量/添加时间）
  homeway host status [name] [--json]
                               单台主机详面（省略 name = 全部）
  homeway host delete <name|id> [--yes]
                               删主机（交互确认默认 N；非终端 stdin 需 --yes）
  homeway forward add --host <ref> --listen <P> [--target <ip:P>|:<P>]
                               建端口转发规则并立即起监听（127.0.0.1:P；目标缺省 =
                               该主机出口自己同端口）
  homeway forward list [--host <ref>] [--json]
                               规则表 + 运行态（listening/failed/在世连接数）
  homeway forward delete --host <ref> --listen <P>
                               删规则并关监听（在世连接不强关、自然收口）
  homeway socks on --host <ref> [--listen 1080]
                               该主机开 SOCKS5 监听（仅回环；域名经出口远程解析）
  homeway socks off --host <ref>
                               关监听并显式关在世连接（端口记忆保留）
  homeway socks status [--json]
                               每主机开关态 + 端口 + 在世连接数 + 链路态
  homeway speedtest [--host <ref>] [--json] [--down/--up/--warmup/--streams/--wait]
                               隧道测速（缺省 --host = 全部主机顺序轮流；口径与
                               手机一致；Ctrl-C 终止轮转）
  homeway --version            打印版本

守护托管/控制面转发的命令（host/forward/socks/speedtest、term/files --host、serve|relay start）在统一进程未运行时自动拉起（打印一行「守护进程未运行，已启动 pid=N」；launchd 托管形态先等 KeepAlive 重拉）；全局 --no-spawn = 不拉起、报可行动错误（脚本友好）。纯读命令（status 族）不拉起。

统一进程与前台单角色同 state 互斥（单实例锁）。角色参数：
  homeway serve --help         出口参数（WG 监听、UPnP/STUN、中继注册腿、设备表…）
  homeway relay --help         中继参数（监听地址、对外公布地址、state 目录）
`)
}
