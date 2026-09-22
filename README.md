# homeway

**自建「回家」VPN 的出口节点**：一个二进制，跑在你家里或云上的机器上；配套的 HarmonyOS App
（应用名「Homeway」，手机端仓库私有）把手机的全部 IPv4 流量经 WireGuard 隧道送到这台机器出网 ——
在家外访问家里的网络与服务，公网上看到的 IP 也是这台机器的。

同一个二进制承载两个角色，按运行方式区分：

- **出口**（`./homeway`，默认角色）：WireGuard 端点 + token 签发 + 过境流量拦截（TCP 重拨、
  UDP 长会话），并附带 files（文件管理）、终端（远程 shell）两个本地服务 —— 都只经隧道可达，
  不暴露公网端口。
- **中继**（`./homeway relay`）：给 NAT 后的出口兜底 —— 打洞与流量的公共会合点，
  跑在有公网 IP 的机器上。

能力速览：

| 能力 | 说明 |
|---|---|
| NAT 穿透 | 自动 UPnP 映射 + STUN 探测 + IPv6 双栈外层承载；多数家庭/云环境可直连 |
| 中继兜底 | 直连候选全部失败才走中继，直连恢复后自动升回 |
| DDNS | `--ddns home.example.com`：家宽重拨端点漂移后无需重取 token |
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
# 进入所在目录直接执行，默认端口 UDP 41641
./homeway
# 无法直连成功时，配置中继（见下一节）
./homeway --relay '中继token'
# 指定主机 DDNS 域名（家宽重拨端点漂移后无需重取 token）
./homeway --ddns 'home.example.com'
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
# 运行中继，获取中继 token，默认端口 TCP/UDP 41641
./homeway relay
# 指定端口
./homeway relay --listen :41741
# 显式指定中继公网 IP
./homeway relay --listen :41741 --advertise 1.2.3.4:41741
```

**2. 使用中继**

换出口、换身份都不用动中继；手机端无需额外配置 —— 出口的 token 里已带上中继地址，
直连优先，直连全部失败时才走中继、恢复后自动升回直连。

```bash
# 启动出口时指定中继服务器
./homeway --relay '中继token'
```

> 云服务器要在安全组/防火墙放行 UDP/TCP 端口。中继同时承担打洞与流量转发职责，直连优先。

## 运行细节

### 多实例

一台机器上可以同时跑多个进程（例如一个出口 + 一个中继）：各进程用 `--state` 区分身份、
用 `--listen` 区分端口（被占用会自动退让并打印实际端口）。同一角色也能起多份（不同 `--state`）。

```bash
# 同机：一个出口 + 一个中继（互不干扰）
./homeway exit  --state ~/.config/homeway-exit  --listen 41641
./homeway relay --state ~/.config/homeway-relay --listen :41741
```

身份密钥、token 台账、实际端口、已公布公网端点都在 `--state` 目录里（默认出口
`~/.config/homeway` / 中继 `~/.config/homeway-relay`）。`--state` 指到哪儿就是哪套身份 ——
想在同一台机器上再开一个独立出口，换个目录即可。

### 日志

终端（stdout）只输出启动时的 token 与端点清单，以及之后 IP/端口变化时的重打；其余全部进文件
（都按大小轮转、总占用有上界）：

| 角色 | 文件 | 内容 |
|---|---|---|
| 出口 | `<state>/events.log`（2MB×3） | 摘要：绑卡/换卡、UPnP、STUN、公网端点公布、服务就绪、运行告警、token 行 |
| 出口 | `<state>/debug.log`（8MB×2） | 细节：peer 表流水、入站新源、周期观测、会话/流量过程 |
| 中继 | `<state>/relay.log`（2MB×3） | 全部运行日志：注册腿/会话/回收/分钟统计/告警 |

`./homeway --verbose` 把摘要+细节同时回显终端（现场排障用）。取最新 token：
`grep 客户端 token <state>/events.log | tail -1`。

### macOS 安装（Gatekeeper 实情）

darwin 产物带的是 **Go 链接器自动加的 ad-hoc 签名**（`codesign -dv` 显示 `Signature=adhoc`、
`TeamIdentifier=not set`，`codesign --verify --strict` 通过）；CI 里**没有**额外签名/公证步骤。

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
cmd/homeway         单入口：按角色（exit / relay）分发
internal/server     出口（WG 端点 + 拦截层 + 本机服务 + 设备表）与它的 CLI
internal/relay      中继（注册腿 + per-client 转发 + hint）与它的 CLI
pkg/proto           线上契约：token（hmw1 格式）/ reg 报文 / 中继帧 + golden vectors
```

```bash
go test ./...
```

发版 = 推 tag（`v0.x.y`），CI 出 darwin/linux 四目标产物 + sha256（见
`.github/workflows/release.yml`）。

## 版权说明

自有代码：**MIT License**（见 [`LICENSE`](LICENSE)）。

二进制里静态链接了第三方组件（Go runtime 与标准库、golang.org/x/{crypto,net,sys,time}、
wireguard-go、wireguard/wgctrl、gVisor + google/btree、creack/pty）——它们的版权行与许可全文在
[`THIRD-PARTY-NOTICES.txt`](THIRD-PARTY-NOTICES.txt)，Release 归档包与容器镜像里各带一份
（BSD-3 / MIT / Apache-2.0 都要求以二进制形式分发时随附声明，只写组件名不满足）。

该文件由 `tools/gen-third-party-notices.sh` 从各依赖自己的 LICENSE 原文拼装（清单口径 =
`go list -deps ./cmd/homeway`）：**改动依赖后重跑一次**，CI 的 `--check` 门禁会在它过期时挡下发布。

> 沿革：`pkg/term`、`internal/server/upnp.go`、`publicendpoint.go`、`pkg/servercore/ifacebind_*.go`
> 标着「从 fork 移植」，来源是我们自己在 tailcat fork 里**新增**的文件（上游 tailcat v0.6.0 里没有
> 这些文件），不是上游 tailcat 代码 ⇒ 不产生 Tailscale 的 BSD-3 归属（逐行比对确认）。
