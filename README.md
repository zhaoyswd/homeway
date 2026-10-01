# homeway

**自建「回家」VPN 的出口节点**：一个二进制，跑在你家里或云上的机器上；配套的 HarmonyOS App
（应用名「Homeway」，手机端仓库私有）把手机的全部 IPv4 流量经 WireGuard 隧道送到这台机器出网 ——
在家外访问家里的网络与服务，公网上看到的 IP 也是这台机器的。

一个二进制、**一个统一进程**承载全部角色：`homeway` 零参前台运行，按
`<state>/config.toml` 的期望态装配启用角色（serve 出口 / relay 中继，client 与
控制面恒开）；命令面 `homeway <谁> <干什么>`。

- **出口**（serve 角色）：WireGuard 端点 + token 签发 + 过境流量拦截（TCP 重拨、
  UDP 长会话），并附带 files（文件管理）、终端（远程 shell）两个本地服务 —— 都只经隧道可达，
  不暴露公网端口。
- **中继**（relay 角色）：给 NAT 后的出口兜底 —— 打洞与流量的公共会合点，
  跑在有公网 IP 的机器上；`homeway relay` 前台单跑（调试形态）或 config 启用。
- **统一进程**（桌面常驻形态）：serve/relay 按期望态 + 多主机客户端注册表（host/term/
  files/forward/socks/speedtest 命令面的宿主）+ 本机控制面（`<state>/control.sock`）。
  归属守护托管的命令在进程未运行时**自动拉起**（打印一行「守护进程未运行，已启动
  pid=N」；`--no-spawn` 关闭）。

能力速览：

| 能力 | 说明 |
|---|---|
| NAT 穿透 | 自动 UPnP 映射 + STUN 探测 + IPv6 双栈外层承载；多数家庭/云环境可直连 |
| 中继兜底 | 直连候选全部失败才走中继，直连恢复后自动升回 |
| DDNS | `homeway serve ddns add home.example.com`：家宽重拨端点漂移后无需重取 token |
| 设备身份 | 多台手机各自稳定身份，重连只刷新、不互踢；token 可多设备共用 |
| files / 终端 | 出口附带的文件管理与远程终端服务，仅经隧道可达 |
| 端口转发 | 在 App 里配「主机端口 → 任意目标」，由出口在本机重拨 |

状态：v0.5.x，已在两台出口（macOS / Debian）与一台公网中继上日常运行。本仓库同时是
线上协议的唯一真源（`pkg/proto`：token / 注册报文 / 中继帧）。

## 使用方法

与 App 内的「使用教程」（设置 → 使用教程）同一套口径，三步跑通。

### 部署出口主机

**1. 下载 homeway**

到 GitHub Releases 下载对应平台的压缩包（Windows 是 zip），解压得到可执行文件 `homeway` ——
它同时承担出口与中继两种角色，按角色运行；中继的配置方式见下一节。

```
https://github.com/zhaoyswd/homeway/releases
```

> macOS：浏览器下载的文件可能带 quarantine 标记导致无法运行，执行一次 `xattr -c ./homeway`
> 清除即可。

**2. 启动出口**

进入解压目录直接执行（Windows 上双击 `homeway.exe`）；首次启动会生成并保存身份密钥，
重启不变、token 里的地址也不会变。

```bash
# 进入所在目录直接执行，默认端口 UDP 41641（serve.enabled 默认 true——零参即出口）
./homeway
```

角色参数写 `<state>/config.toml`（默认 `~/.config/homeway`，缺失自动生成默认；
三层布局：L1 config.toml / L2 凭证〔serve/、relay/、client/〕/ L3 可弃缓存
〔cache/〕）。改角色参数用命令面或手编后重启：

```bash
# 无法直连成功时，配置上游中继（见下一节；--stdin 从 stdin 读，不落 shell history）
homeway serve relay set '中继token'          # 或：homeway serve relay set --stdin
homeway serve restart                        # 纯配置写不热更——重启生效

# 指定主机 DDNS 域名（可多条；家宽重拨端点漂移后无需重取 token）
homeway serve ddns add 'home.example.com'
homeway serve ddns list
homeway serve restart

# 启停与观测（守护托管：未跑则自动拉起统一进程）
homeway serve start | stop | restart | status [--json]
homeway serve token                          # 完整 hmw1 凭证（在跑控制面 / 未跑读台账末行）

# 一次性前台调试形态（不改期望态；flag 一次性覆盖 config）
homeway serve --listen 41641
```

**3. 配置 App**

出口启动成功后会打印一串 `hmw1` 开头的 token，复制这段 token，在 App「主机」页添加主机。
token 是连接主机的凭证，可在多台设备使用，切勿外传。

```
客户端 token（粘进 App 的「添加主机」即可；3 个端点）：
hmw1GiFSJPXiArlX…        ← 复制冒号后面这一整串
```

> homeway 会自动通过 STUN 探测 / 配置 UPnP 映射等方式建立直连，正常情况无需额外配置。

### 部署中继（可选）

当主机在 NAT 后面无法打洞成功时，可以自行部署中继提升打洞成功率或中继流量。

**1. 在有公网 IP 的机器上部署中继**

启动后会打印中继 token（`rl1…`），把它交给出口即可（见下一步）。公网地址会自动探测；
机器只有内网 IP 时用 `--advertise` 显式指定。

```bash
# 前台只跑中继（调试形态；默认端口 TCP/UDP :41741），启动日志打印中继 token（rl1…）
homeway relay
# 指定端口 / 显式指定中继公网 IP（前台一次性覆盖）
homeway relay --listen :41741 --advertise 1.2.3.4:41741
# 常驻形态：config 启用 + 命令组管理（与 serve 同一统一进程，默认端口不冲突）
homeway relay start                          # config 写 relay.enabled=true + 拉起统一进程
homeway relay status [--json]                # 期望+运行态+注册出口列表（中继看不到 APP）
homeway relay token                          # 完整 rl1 凭证（在跑控制面 / 未跑 relay.key+config 离线推算）
homeway relay stop | restart
```

**2. 使用中继**

换出口、换身份都不用动中继；手机端无需额外配置 —— 出口的 token 里已带上中继地址，
直连优先，直连全部失败时才走中继、恢复后自动升回直连。

```bash
# 出口侧配置上游中继（写入 config 的 serve.relay；重启出口生效）
homeway serve relay set '中继token'
homeway serve restart
```

> 云服务器要在安全组/防火墙放行 UDP/TCP 端口。中继同时承担打洞与流量转发职责，直连优先。

### 主机终端（`homeway term`，tmux 式命令面）

人坐在出口主机前时，不用掏手机——主机终端里直接管理与 App **同一份**的终端会话
（同一注册表、同一 agent 状态、可同时接入，互不顶替）：

```bash
homeway term list                 # 列会话（--json 给机器可读格式）
homeway term new [名字] [-d] [-A] # 新建会话；-d = 创建不接入；-A = 重名复用；缺名自动 host-<4hex>
homeway term attach [名字] [-d]   # 接入（缺名 = 最近活跃）；-d = 接管（踢掉其它腿，含手机）
homeway term delete <名字>        # 关闭会话（与 App 的「关闭会话」同一路径）

# 远程：任何机器上经 daemon 控制面接入指定后端主机（term 帧协议经隧道端到端原样复用）
homeway term list --host mac      # --host <name|id>：与 host delete/status 同一寻址规则
homeway term attach --host mac    #（名称精确 / peerID 全长 hex / 无歧义短前缀）
homeway term explain <会话名> --host mac   # 在线 explain 远程往返（--file 离线模式仍是本地面）
```

- **远程模式（`--host`）**：命令经本机统一进程的控制面（`stream.open{kind:term}` 纯透传）
  过隧道到达目标主机的 term 服务——与手机 surface 腿同挂一条会话、互不顶替。
  ⚠️ **`--state` 的指代随 `--host` 切换**：远程模式下指统一 state 根
  （control.sock 所在，默认 `~/.config/homeway`），不再是出口 state；
  `--timeout` 为解析与打开**各**一次的预算（默认各 10s、最坏相加 20s，仅 `--host`
  模式可用——本地面给出即报错；attach 流本身不设 deadline）。
  统一进程未运行 = **自动拉起**（打印启动行后重试；`--no-spawn` = 可行动错误）。
- **接入形态**：本地终端被置为 raw 双向透传，本地终端自己就是仿真器（raw 字节模式）。
  窗口尺寸变化自动同步（SIGWINCH → RESIZE）；会话级尺寸/主题以**最近活动的腿**为准。
- **分离键**：默认 `Ctrl-b` 前缀——`d` 分离（会话继续在出口跑）、`Ctrl-b Ctrl-b` 送字面量、
  `r` 重新对齐（会话尺寸被其它腿改走后，把画面切回本终端尺寸）。
  ⚠️ **`Ctrl-b` 与 tmux 的前缀键相同**：会话里跑 tmux 时两者会抢键，换
  `--detach-key=^]`（或 `--detach-key=none` 关掉分离键）即可；`HOMEWAY_TERM_SHELL`
  配了 tmux 一类命令模式时同样适用。
- **断链文案**：连接被断开（如出口重启）时提示「会话仍在运行，可重新 attach」。
  远程 attach 的流终结按来源归因：`gone` = 主机不可达或上行过快（会话仍在目标主机
  运行，可重新 attach）；`closed` = 对端关闭（也可能是本端长时间停止读取、出口侧
  慢腿自治收尾了本腿）；连接级断开 = 与守护进程的连接断了，重新执行命令即可。
  输入侧流死后逐帧报错早退——粘贴大段文本中途流死，余量不再写进死流。
- **标题**：接入时终端标题设为「会话 · agent · 状态」，退出恢复原值；
  `HOMEWAY_TERM_TITLE=off` 可关。
- **状态词表**：会话状态统一 stateV2 口径（working / blocked / idle / unknown）——
  表格、标题与 `list --json` 同一值域；`--json` 的旧 `state` 字段已退役（不兼容
  更改：消费 `stateV2` 键）。
- **退出码**：分离 / 会话结束（含被接管 `-d`）/ 信号退出 = 0；连接或协议错误、断链 = 1；
  未知 term 子命令 = 1、顶层未知角色 = 2。

**权限边界**：命令面经出口 state 目录下的 `term.sock`（Unix socket）直连，**持有该 socket
的访问权 = 拥有该主机的 shell**。socket 权限位在 linux 与 darwin 都参与 connect 判定
（2026-09-29 双端实测）——出口把 `term.sock`/`files.sock` 显式 chmod **0600**（拦非属主）、
state 目录收紧 **0700** 作第二层防御（同时护住目录里的身份密钥与 token 台账）——不要把
state 目录开放给不可信用户/进程。
（版本边界：`term.sock` 0600 自 v0.9.0 起；`files.sock` 0600 与 `OpenState` 收紧 0700 在
f610f3f 起、**自 v0.10.0 起已生效**——v0.9.0 及更早出口重启后 files.sock 会回到 umask 值，
但 state 目录 700 下实际暴露面为零。）

### 文件命令面（`homeway files`，类 sftp）

与 App **同一份** files 协议（线格式零改动复用），六子命令与协议动词 1:1
（get↔download / put↔write；无 delete/rename——协议没有不发明）：

```bash
homeway files list [path] [--json]   # 列目录（--json = 单行 JSON 数组：name/isDir/size/mtimeMs
                                     #   + mode〔权限位，八进制，诊断用〕）
homeway files stat <path> [--json]   # 单条目信息（--json = 单行 JSON，键同 list）
homeway files mkdir <path>           # 新建目录（已存在报 already_exists）
homeway files read <path> [--max N]  # 文本预览（默认 512KiB=协议文本默认；截断提示走 stderr；
                                     #   --max 超协议内联上限 16MiB 时报错而非静默截断）
homeway files get <远端> [-o 本地] [--force] [--quiet]
                                     # 下载（目标缺省 = basename；已存在默认拒、--force 覆盖；
                                     #   本地原子落盘——写 <目标>.tierpart、成功 rename、
                                     #   中断即删 ⇒ 无半截残留、可直接重试不需 --force）
homeway files put <本地> <远端> [--rate-limit N] [--quiet]
                                     # 上传（远端原子替换；Ctrl-C = 取消，远端清理 .tierpart、
                                     #   目标不变）；--rate-limit <bytes/s> 上行限速，默认保守值
                                     #   2MiB/s，0 = 不限、风险自担——协议无 ack/credit，守护
                                     #   进程每流缓冲（40 帧/640KiB）满即收流，限速是发送端义务
homeway files list --host mac        # --host <ref>：与 host delete/status / term 同一寻址规则
```

- **远程模式（`--host`）**：命令经本机统一进程的控制面（`stream.open{kind:files}` 纯透传）
  过隧道到达目标主机的 files 服务。统一进程未运行 = **自动拉起**（`--no-spawn` =
  可行动错误）；守护进程代际过旧不识 files 流时按 `bad_request` 给出
  「请同批升级」提示（锁步哲学：同批发版同二进制天然同升）。
- ⚠️ **`--state` 的指代随 `--host` 切换**（term 面同款重载语义，非互斥）：无 `--host`
  = 本地面，一次性直连 `<state>/files.sock`（默认**出口 state** `~/.config/homeway`，
  不要求统一进程在位）；`--host <ref>` = 远程面，`--state` 指**统一 state 根**
  （control.sock 所在，默认同 `~/.config/homeway`）。
- **`--timeout`**：解析 / 连接+打开 / 首响应（问候帧）三段各一次的预算（默认各 10s、
  最坏相加 30s；**两面均可用**——term 面本地面不接受）；传输本身不设 deadline，
  超预算/取消的文案按 CLI 自己的阶段归因，不呈现成连接态。
- **流终结与取消归因**（get/put 中途）：`gone` = 流被守护进程收流（主机不可达或上行
  持续过快）；`closed` = 对端已关闭（files 服务收工）；连接级断开 = 与守护进程的连接
  断了，重试即可。get 断流提示已收字节与「可直接重试」；put 断流提示「远端已按取消
  语义清理」；Ctrl-C/SIGTERM = 关流不发终止帧，远端删 `.tierpart`。
- **退出码**：成功 = 0；连接 / 协议 / 超时 / 取消 = 1；未知 files 子命令 = 1、
  顶层未知角色 = 2。

### 统一进程与聚合状态（`homeway status`）

桌面（Mac/Linux）常驻形态：一个统一进程同时承载 serve/relay（按 config 期望态）与
**多台出口主机**的客户端会话（经 `clientcore/facade` 单入口消费——与手机 cshared
包装共用同一份会话状态机与测试，行为零漂移）。`homeway` 零参前台运行；
launchd/systemd/nohup 常驻皆可（macOS 模板见 `tools/launchd/`）。

```bash
homeway status [--json]        # 聚合状态面：进程层 + serve + relay + client 四域
                               # （进程未运行时读 config 报期望态，纯读不拉起；
                               #   --json = 机器可读，供脚本与未来 Mac APP 消费）
homeway status --watch         # client 域 live 渲染：快照 + 订阅续播（state/reason/
                               # via/rtt 随事件刷新，Ctrl-C 退出）。⚠️ 观测副作用：
                               # view 参与需求合成——watch 期间被显示主机（启动时
                               # 列表）视为有需求（门控不压制其巡检证据），退出后
                               # 贡献消失。视图声明 = 启动时列表；进程角色重建
                               # （detach/attach）时补发的 session.added 仅恢复登记面
                               # （host/name），state/link 待后续事件或前端重快照。
                               # --watch 需进程在位（未跑 = 可行动错误，不拉起）；
                               # serve/relay 域暂不进 watch 流（事件总线无该域，
                               # 后续按只增补）。
```

- **期望态与开关**：`serve/relay start|stop|restart` 即改 config 的 enabled 字段并
  装配/停角色（机器重启后照期望态恢复；全停后进程常驻不退出——client/control 是
  统一进程本职）。事实约束：**中继侧看不到 APP**（在中继注册的是出口、手机流量在
  WG 密文里）——APP 维度只从 `serve status` 的 peer 表看。
- **按需拉起**：归属守护托管/控制面转发的命令（host/forward/socks/speedtest、
  term/files `--host`、`serve|relay start`）在统一进程未运行时自动拉起（非静默
  打印一行启动提示；launchd 托管形态先等 KeepAlive 重拉）；`--no-spawn` =
  可行动错误（脚本友好）。纯读命令（status 族）不拉起。
- **控制面**：统一进程在 `<state>/control.sock`（Unix socket，0600；目录 0700）上提供
  本地控制协议——快照/事件流（带游标续播）/term 字节流透传/serve·relay 角色管理。
  **持有该 socket 的访问权 = 拥有这些主机会话的控制权**（与 term.sock 同口径），协议内
  无 token 类凭证。契约真源 = 手机仓 openspec `daemon-control-plane` 能力域的 spec +
  语言无关 fixtures（`internal/control/testdata/fixtures/v1/`，含独立解码对拍脚本
  `decode_check.py`——非 Go 消费者可仅凭 spec + fixtures 实现对拍）。
- **桌面消费形态**：CLI/未来 Mac APP 是控制面的薄前端——`homeway status --json` 与
  `host list --json`（见下）是协议级机器可读消费路径的实证；`status --watch`
  是订阅面（快照 + 游标续播）的第一个真实只读消费者，纯绑定落地（零 facade 语义
  改动——「新只读消费者只加绑定」的实证）。
- **需求门控与诊因**（4a 起）：会话恢复按需求门控——三源保守或合成（出站
  流量增量 / 在场消费连接 / 订阅视图覆盖），无需求期的巡检失败不计恢复证据（手机 App
  路径不受影响）；恢复被门控/限频/探测窗口拦下时发 `session.diag` 诊因事件
  （reason = gated/budget/probe_window——「为什么没在恢复」在事件面可观测）。
- **状态工件**：`homeway export [--state D] [dest.tar]`（不变量四件 = config.toml +
  serve/ + relay/ + client/，0600 未压缩 tar）/ `homeway import <file>`（布局校验 +
  安全解包 + 落位回滚；目标进程必须在停）/ `homeway reset cache`（清可弃层 cache/）。
- **旧布局自动迁移**：统一进程首次在旧 state 上启动时自动幂等搬迁（v0.13.x 及更早的
  exit 布局〔根下 key.bin/tokens.jsonl〕与 daemon 子目录布局）——判据行（`cache/events.log`
  与终端回显）：每文件一行 `迁移：<旧路径> → <新路径>`、`吸收：daemon/roles.json → 期望态
  并入 config（client 恒开）`、`迁移备份：<state>/migration-backup-<ts>/`（state 顶层，
  reset cache 不碰）；目标已存在 = `跳过：…（目标已存在，保留原地）`（幂等）；再次启动
  零迁移行。初始 `serve.enabled` 按旧形态定（旧 exit 布局 ⇒ true、仅 daemon 布局 ⇒ false）。
- **单实例**：state 目录 flock 排他锁（统一进程与前台单角色共用 `<state>/lock`），
  二次启动报「已在运行（pid N）」；进程死亡锁自动释放。

### 主机表管理（`homeway host`，守护托管命令面）

管理统一进程注册表里的多台主机——全部经控制面 UDS 操作（不直读/直写
hosts.json；统一进程未运行时自动拉起，`--no-spawn` = 可行动错误）：

```bash
homeway host add [--name N] [--force] <token>
    # 添加主机。服务端做有界连通性验证（≤3.5s，与手机 App 同一份探测实现），三档结论：
    #   直连可达   → 成功行（实测端点 + RTT）
    #   仅中继可达 → 成功行 + 提示「直连不可达，连接将走中继；检查出口公网端口/UPnP」
    #   全不可达   → 非零退出 + 排查建议 + --force（仍然添加）提示；不入表
    # --force = 跳过验证直接入表（端点未实测，首次连接时补全）。token 在输出与错误
    # 信息中恒为掩码（hmw1…xxxx）；经命令行参数传入（与凭证类命令同威胁模型）。
homeway host list [--json]
    # 主机列表：名称/短 ID/会话态/链路（via/端点/rtt）/收发字节/添加时间。
    # --json = 控制面快照的 hosts 数组原样（stdout 一行 JSON，无包裹对象）。
homeway host status [name] [--json]
    # 单台详面（省略 name = 全部）；--json 同 list 形状，status <name> = 单元素数组。
homeway host delete <name|id> [--yes]
    # 删除：停会话、出表、落盘。按名称/完整 ID/无歧义短前缀寻址；交互确认默认 N，
    # 非终端 stdin 未给 --yes 时拒绝（防脚本误删）；目标不存在报错非零（不静默成功）。
# 全部子命令支持 --state DIR（统一 state 根）与 --timeout / --no-spawn；add 默认 10s，其余 5s。
```

验证实现一份：手机 App（cshared `ClientCoreProbeReach`）与 daemon `host.add` 服务端
同调 `pkg/probe.Reach`（decode → 端点解析（并行，计入同一预算）/去重 → 并发参照点
探测）；探测为纯旁路（独立临时 UDP socket、无身份、不碰任何在跑会话）。
- **launchd 常驻**（macOS）：模板与安装说明见 `tools/launchd/`（零参统一进程单代理，
  RunAtLoad + KeepAlive 崩溃自动重拉；模板经 `launchctl load` 实测）。

### 端口转发（`homeway forward`，守护托管命令面）

桌面侧的端口转发规则——监听器在统一进程内跑（127.0.0.1 仅回环，会话无关长活：
add 即起、delete 即关、进程重启按持久化表重建），入站连接经 facade 拨号缝过隧道
由指定主机出口出网。与手机 App 的端口转发面（App 配置 + `ClientCoreTunSetPortForwards`）
零耦合、互不同步（两套规则表、两套监听宿主；语义与校验口径有意镜像——用户心智一份）：

```bash
homeway forward add --host <ref> --listen <P> [--target <ip:P>|:<P>]
    # 建规则并立即起监听。--host = 名称/完整 ID/无歧义短前缀（与 host delete 同一份
    # 寻址）；目标缺省 = 该主机出口自己的同监听端口，:<P> = 出口自己的指定端口，
    # <ip:P> = 出口可达的任意 IPv4 目标（出口侧过境重拨）。
homeway forward list [--host <ref>] [--json]
    # 规则表 + 运行态（listening / failed+原因 / 在世连接数）。
homeway forward delete --host <ref> --listen <P>
    # 删规则并关监听；已建立的转发连接不强关（自然收口——同手机口径）。
# 全部子命令 --state 恒指统一 state 根（默认 ~/.config/homeway，control.sock
# 所在——本命令面无本地面）；统一进程未运行 = 自动拉起（--no-spawn 关闭）。
```

规则校验：监听端口 1024–65535、目标须为空（出口自己）或 IPv4 字面量、每主机 ≤8 条；
**监听端口在全部 forward 规则与 socks 监听之间全局唯一**（多主机会话并发在世、共享同一
回环命名空间——与手机「每主机唯一」的桌面差异）。add 当场监听失败（如端口被守护进程
外进程占用）= 错误、规则不入表（「failed 软状态」只出现在运行态失败路径——daemon
重启重建时的端口被占，与运行期 accept 连续失败烧尽——监听失效如实呈现）。规则
持久化于 `<state>/client/forwards.json`（0600、原子写、损坏按空表重建）；删除主机时其
全部规则与监听级联消失（不复活）。

### SOCKS5 承载面（`homeway socks`，按主机开关）

桌面浏览器/工具免 VPN 走隧道的承载面——每主机至多一个 SOCKS5 监听（127.0.0.1，多主机
= 多端口，浏览器按端口选出口）；子集契约 = no-auth + CONNECT only + IPv4/域名地址类型：

```bash
homeway socks on --host <ref> [--listen 1080]
    # 开 SOCKS5 监听；--listen 缺省 = 沿用该主机上次端口（无记忆则 1080；1024–65535，
    # 与 forward 同一条值域）。
homeway socks off --host <ref>
    # 关监听并**显式关在世连接**（RST 收口——「off」之后不再有代理流量经隧道跑）；
    # 端口记忆保留，下次 on 缺省沿用。
homeway socks status [--json]
    # 每主机开关态 + 端口（--json 含 off 但记住的端口）+ 在世连接数 + 链路态 via/rtt。
```

**域名目标的解析在出口侧远程完成**（MUST NOT 本地解析）：CONNECT 带主机名时统一进程
经隧道拨该主机出口的 DNS 代答解析腿（TCP 查询 → `Host.DialPort(5300)` →
出口隧道栈内的 listener：隧道 IP:`5300`）发 A 查询，以应答 IPv4 拨隧道——fake-ip/内网 DNS/geo 场景下解析权
跟着指定出口走（`curl --socks5-hostname` 强制域名形态）。解析结果按应答 TTL 缓存
（每 listener 一份 = 按出口主机隔离，有界 256、逐出即弃、否定不缓存；多 A 记录顺序
尝试）。采证判据：出口侧 dns 计数行（TCP 查询）+ intercept 豁免/transit dialok 行。

### 隧道测速（`homeway speedtest`，口径与手机一致）

对指定后端（或全部主机顺序轮流）做隧道上下行测速——**测量口径与手机 App 由共享实现
保证一致**（引擎 `pkg/speedtest` 只有一份，手机核壳与 daemon 侧 runner 都是消费者）：

```bash
homeway speedtest [--host <ref>] [--json] [--down 10s] [--up 10s] [--warmup 2s]
                  [--streams 4] [--wait 60s] [--quiet]
    # --host 缺省 = 主机表内全部主机顺序轮流（开跑前打印「将依次测 N 台」；并行互抢
    #   带宽会使读数失真，故 MUST 顺序）。参数默认与边界 = 手机口径（窗口 ≤15s、
    #   预热 ≤5s、流数 1–6）。输出双口径：显示行（1024 进位、≥1MB/s 用 MB/s、
    #   四舍五入整数、上行在前）+ 精确值行（B/s 与 Mbps/MB/s 带小数、用量、墙钟）。
    # --wait = 链路未就绪的有界等待（0 = 不等即报错；默认 60s 覆盖恢复阶梯最坏时长；
    #   预算经 start 载荷 waitMs 交 daemon 侧 runner 状态机承载，start 立即返回）。
    # --json = 逐主机结果对象（host/name/ok/reason/downBps/upBps/usageDown/usageUp/
    #   wallMs/via/rttMs——via/rtt 为开跑时冻结标签）。
    # Ctrl-C 终止整个轮转：先 speedtest.cancel 当前主机、未测主机不再测量，退出码非零。
```

守护托管：引擎在统一进程内跑（测速数据腿直连隧道，MUST NOT 经控制面流承载——
流通道的有界上行缓冲与全速泵送矛盾）；同主机单飞（在跑时重复 start 报 busy）；记账
差异如实声明——统一进程侧测速拨号照常计入该主机的需求合成（前台显式动作 = 真实需求；
手机侧的豁免口径不适用）。退出码：全部主机失败或 Ctrl-C = 非零，至少一台成功 = 0。

## 运行细节

### 多实例与多角色

双角色同机是**统一进程的常态**（config 同时 `serve.enabled=true` + `relay.enabled=true`，
默认端口 41641 / :41741 已错开）。要再开一套独立身份：换个 `--state` 目录即可（统一
进程与前台单角色共用 `<state>/lock` 单实例锁，同 state 互斥）。

```bash
# 同机双角色：一个统一进程（config 期望态装配）
homeway --state ~/.config/homeway            # serve + relay + client/control

# 第二套独立身份（调试或隔离）
homeway serve --state ~/.config/homeway-b --listen 41642   # 前台单角色
```

身份密钥、token 台账、实际端口、已公布公网端点都在 `--state` 的三层布局里
（serve/relay/client 各一层凭证 + config.toml 意图 + cache/ 可弃层）。

### 日志

终端（stdout）只输出启动时的 token 与端点清单，以及之后 IP/端口变化时的重打；其余全部进文件
（都按大小轮转、总占用有上界；三层布局下日志都在 `<state>/cache/`）：

| 角色 | 文件 | 内容 |
|---|---|---|
| serve | `<state>/cache/events.log`（2MB×3） | 摘要：绑卡/换卡、UPnP、STUN、公网端点公布、服务就绪、运行告警、token 行 |
| serve | `<state>/cache/debug.log`（8MB×2） | 细节：peer 表流水、入站新源、周期观测、会话/流量过程 |
| relay | `<state>/cache/relay.log`（2MB×3） | 全部运行日志：注册腿/会话/回收/分钟统计/告警 |
| 统一进程 | `<state>/cache/daemon-events.log` + `daemon-debug.log` + `spawn.log` | 守护侧摘要（就绪/角色/控制面/主机增删）+ 细节（各主机会话过程）+ 按需拉起子进程的 stdout/stderr |

`./homeway --verbose` 把摘要+细节同时回显终端（现场排障用）。取最新 token：
`homeway serve token`（未跑时直读台账末行，与在跑值一致——台账写入纪律）。

### macOS 安装（Gatekeeper 实情）

darwin 产物带 **ad-hoc 签名**（`codesign -dv` 显示 `Signature=adhoc`、`TeamIdentifier=not set`，
`codesign --verify --strict` 通过）：arm64 由链接器自动加，amd64（`-arch` 交叉链不自动签）由 CI
显式补签；CI 里**没有**开发者身份签名/公证步骤。

- **用 `curl`/`wget` 下载 → 直接能跑**（文件不带隔离标记）。
- **用浏览器下载（Safari/Chrome）→ 文件带 `com.apple.quarantine`，macOS 直接 SIGKILL**
  （`spctl -a -t exec` 判 `rejected`，弹"无法验证开发者"）。要么改用 curl 下载，要么清标记：

  ```bash
  xattr -d com.apple.quarantine ./homeway      # 单个二进制
  xattr -c -r ./homeway                        # 或整个解压目录
  ```

- 想彻底免掉这一步，需要 Apple **Developer ID 签名 + 公证**（CI 要配证书与 notarytool 凭据），
  当前没做 —— 自用/自建场景用上面的 curl 路径即可。

## 布局与开发

```
cmd/homeway         单入口：`homeway <谁> <干什么>` 分发（角色 serve/relay、客户端域、跨域 status）
internal/server     出口角色（WG 端点 + 拦截层 + 本机服务 + 设备表）与前台 CLI
internal/relay      中继角色（注册腿 + per-client 转发 + hint）与前台 CLI
internal/nodeconfig config.toml（L1 意图层）读改写内核
internal/nodestate  三层 state 布局 + 同根自动迁移 + export/import + 单实例锁
internal/daemon     统一进程装配（supervisor + 控制面 + 按需拉起 + 命令组 CLI——经 facade 单入口消费）
clientcore/facade   客户端会话面的唯一语义真源（词汇/版本台账/事件总线/主机表/Host 对象）
internal/control    控制面 wire 绑定（UDS/帧/握手；词汇与总线真源在 clientcore/facade）
pkg/proto           线上契约：token（hmw1 格式）/ reg 报文 / 中继帧 + golden vectors
contracts           契约台账（ledger.jsonl：全族词表/版本空间/fixtures 摘要的机器真源）+ 对账器
                    （`go test ./contracts/...`，CI「契约台账对账门」step）+ 净室解码器（cleanroom）；
                    各协议族词表**先登台账（spec delta 同批）再进代码**，App 面对账在 tier 仓
                    `tools/docs/check-vocab-sync.sh`（读 submodule 钉定的 ledger.jsonl）
```

```bash
go test ./...
```

**门禁**（与 gofmt/vet 并列）：桌面侧（`internal/`、`pkg/`、`cmd/`）对 clientcore
内部件的直 import 必须为零（语义真源收拢在 `clientcore/facade`——openspec
clientcore-facade「收拢判据」；4b 升 CI 门时沿用本命令）：

```bash
[ -z "$(grep -rn '"github.com/zhaoyswd/homeway/clientcore' internal/ pkg/ cmd/ --include='*.go' | grep -v 'clientcore/facade')" ] && echo PASS
```

（`[ -z ]` 口径：`grep -v` 全过滤时退出码 1，直接拿管道退出码当门会假红；排除
模式不带尾引号——facade 子包同被排除。）

race 门（六包——4a 终态五包〔hostsession 自 demand/diag 批起是改动面，exec-r2 后
入列〕+ 3e 起 `pkg/socks`〔每连接起 goroutine〕；后续升 CI 门时沿用本命令）：

```bash
go test -race -count=1 ./clientcore/facade/ ./clientcore/hostsession/ ./internal/control/ ./internal/daemon/ ./pkg/term/ ./pkg/socks/
```

发版 = 推 tag（`v0.x.y`），CI 出 darwin/linux 四目标产物 + sha256（见
`.github/workflows/release.yml`）。

## 版权说明

自有代码：**MIT License**（见 [`LICENSE`](LICENSE)）。

二进制里静态链接了第三方组件（Go runtime 与标准库、golang.org/x/{crypto,net,sys,time}、
wireguard-go、wireguard/wgctrl、gVisor + google/btree、creack/pty、BurntSushi/toml，以及
vendored 的 libghostty-vt 与 herdr 检测规则 manifests）——它们的版权行与许可全文在
[`THIRD-PARTY-NOTICES.txt`](THIRD-PARTY-NOTICES.txt)，Release 归档包与容器镜像里各带一份
（BSD-3 / MIT / Apache-2.0 都要求以二进制形式分发时随附声明，只写组件名不满足）。

该文件由 `tools/gen-third-party-notices.sh` 从各依赖自己的 LICENSE 原文拼装（清单口径 =
发版矩阵逐平台 `go list -deps` 的并集，再加两个 vendored 组件）：**改动依赖后重跑一次**，
CI 的 `--check` 门禁会在它过期时挡下发布。

## 构建与发版

二进制是**单文件**（exit / relay / term 按子命令区分）。构建配方在 `.github/workflows/release.yml`
（openspec term-vt-backend D7），本地复现口径：

**1. 装 zig 0.16.0**（vendor 基线钉死的版本，`tools/build-vt.sh` 只认它）：解压到 `~/zig-0.16.0/`，
或用 `ZIG=<路径>` 指定。首次产库需要联网（zig 自动拉取包依赖）。

**2. 产 vt 静态库**（`prebuilt/` 不入库，克隆后必跑）：

```bash
./tools/build-vt.sh                # 四个目标全产
./tools/build-vt.sh darwin-arm64   # 单目标（本地开发）
```

**3. 编译**（发版矩阵六个目标；带 vt = darwin/linux × amd64/arm64，需 CGO=1）：

| 目标 | 配方 |
|---|---|
| 本机（mac/linux，x86_64/arm64） | `go build -o homeway ./cmd/homeway`（CGO_ENABLED=1） |
| linux 交叉（musl 静态） | `CGO_ENABLED=1 CC="zig cc -target x86_64-linux-musl" GOOS=linux GOARCH=amd64 go build -ldflags "-extldflags -static" …` |
| darwin 交叉 amd64（在 arm Mac 上） | `CGO_ENABLED=1 CC="clang -arch x86_64" GOARCH=amd64 go build …` |
| linux/armv7、windows | `CGO_ENABLED=0` 纯 Go——无 vt 的 legacy 变体（构建标签隔离，见 `pkg/term/term_vt_off.go`） |

⚠️ **不要用 zig cc 交叉 darwin**：zig 的 macOS libc 桩没有 libresolv，Go 的 net 包链接必炸
（2026-09-27 实测）；darwin 产物在 macOS 上编。

发版 = 推 tag（`git tag v0.x.y && git push origin v0.x.y`），CI 自动出六个平台的 Release 归档：
linux 产物 musl 静态（smoke 核验 statically linked）；darwin 产物带 ad-hoc 签名（CI 内
`codesign` 核验），真机冒烟在发版后于主力 Mac 手动 gate（Mac 是主力出口）。
