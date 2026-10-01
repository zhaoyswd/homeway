// homeway：Homeway 单二进制入口 —— `homeway <谁> <干什么>` 命令体系
// （role-management D1：顶层名词三类——角色 serve/relay、客户端域 host/term/files/
// forward/socks/speedtest、跨域 status〔随后版本〕）。
//
//	homeway [--state D] [--verbose]  # 零参 = 统一进程前台（按 config 期望态装配全部启用角色）
//	homeway serve [flags]            # 前台只跑出口（一次性覆盖，不改期望态）
//	homeway relay [flags]            # 前台只跑中继（默认 :41741）
//	homeway term <子命令> …          # 终端命令面：list / new / attach / delete / explain
//	homeway files <子命令> …         # 文件命令面（类 sftp）：list / stat / mkdir / read / get / put
//	homeway host <子命令> …          # 主机表管理命令面：add / list / status / delete
//	homeway forward <子命令> …       # 端口转发命令面：add / list / delete（守护托管）
//	homeway socks <子命令> …         # SOCKS5 承载面命令面：on / off / status（守护托管）
//	homeway speedtest […]            # 隧道测速（守护托管；--host 缺省 = 全主机轮流）
//	homeway --version
//
// 统一进程只认全局 flag（--state/--verbose）；角色 flag 打在统一进程形态 = 可行动
// 错误（r1 中-1——角色参数走 config 或 serve/relay 前台形态）。同 state 单实例锁
// （<state>/lock）对统一进程与前台单角色互斥。`homeway exit` 已更名 serve（迁移
// 提示报错）。
package main

import (
	"fmt"
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
	// 角色后的版本号：homeway relay --version。
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
		// 前台单角色（exit → serve 更名；词表随 role-management 同升）。
		err = server.CLI(rest)
	case "relay":
		err = relay.CLI(rest)
	case "exit":
		fmt.Fprintln(os.Stderr, "homeway: `exit` 已更名为 `serve`——前台出口用 `homeway serve`，统一进程（按 config 期望态装配全部角色）直接 `homeway`；请更新脚本与文档")
		return 2
	case "term":
		// 远程接入缝注入（term-remote D1）：`term … --host <ref>` 经 daemon 控制面
		// 转发；nil = 仅本地面（此处恒注入）。
		err = term.CLI(rest, daemon.TermRemote(version))
	case "files":
		// 远程接入缝注入（files-cli D1/D3，同款形态）：`files … --host <ref>` 经
		// daemon 控制面 stream.open{kind:files} 转发；nil = 仅本地面（此处恒注入）。
		err = files.CLI(rest, daemon.FilesRemote(version))
	case "daemon":
		// daemon 本体已并入统一进程；status/host/forward/socks/speedtest 子命令
		// 照旧（随后版本平移为顶层 status / serve·relay 命令组，role-management §3）。
		err = daemon.CLI(rest, version)
	case "host":
		err = daemon.CLI(append([]string{"host"}, rest...), version)
	case "forward":
		err = daemon.CLI(append([]string{"forward"}, rest...), version)
	case "socks":
		err = daemon.CLI(append([]string{"socks"}, rest...), version)
	case "speedtest":
		err = daemon.CLI(append([]string{"speedtest"}, rest...), version)
	default:
		fmt.Fprintf(os.Stderr, "homeway: 不认识的子命令 %q（可用：serve、relay、term、files、host、forward、socks、speedtest；零参 = 统一进程）\n", role)
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
	case "exit":
		return "exit", args[1:]
	case "term":
		return "term", args[1:]
	case "files":
		return "files", args[1:]
	case "daemon":
		return "daemon", args[1:]
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

func usage(w *os.File) {
	fmt.Fprint(w, `homeway —— Homeway 出口与中继（单二进制，统一进程 + 按需命令）

用法：
  homeway [--state DIR] [--verbose]
                               统一进程前台（零参）：按 <state>/config.toml 期望态装配
                               全部启用角色（serve/relay）+ 恒开的 client/control；
                               同 state 单实例锁（<state>/lock）
  homeway serve [flags]        前台只跑出口（不改期望态；flag 一次性覆盖 config；
                               --state 即统一 state 根——L2=<state>/serve、L3=<state>/cache）
  homeway relay [flags]        前台只跑中继（默认 :41741；同上路径注入）
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
  homeway daemon status [--json] [--state DIR]
                               守护域状态（控制面读面；随后版本平移为 homeway status）
  homeway --version            打印版本

统一进程与前台单角色同 state 互斥（单实例锁）；serve/relay 的启停/查询命令组
（start/stop/restart/status/token）随后版本加入（role-management §3）。

角色参数：
  homeway serve --help         出口参数（WG 监听、UPnP/STUN、中继注册腿、设备表…）
  homeway relay --help         中继参数（监听地址、对外公布地址、state 目录）
`)
}
