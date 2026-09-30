# AGENTS.md（homeway）

单二进制 `homeway`（`cmd/homeway`）：零参数/`exit` = 出口（WG 端点 + 拦截层 + files/term/端口转发）、
`relay` = 中继、`daemon` = 桌面守护进程（多主机会话注册表 + 控制面 UDS；`daemon status` 状态面）、
`host add/list/status/delete` = 主机表管理命令面（host-cli 起：守护托管，`host add` 服务端
做有界连通性验证——探测核 `pkg/probe.Reach` 与手机 App 同调一份）、
`term … --host <name|id>` = 远程终端命令面（term-remote 起：经 daemon 控制面
`stream.open{kind:term}` 过隧道接指定后端主机的 term 服务，寻址与 host 面同源；v0.11.0 起
LIST/CLI 状态单轨 stateV2，旧 `state` 键退役）、
`files …` = 文件命令面（files-cli 起，v0.12.0：六子命令 list/stat/mkdir/read/get/put——
本地面直连 `<state>/files.sock`〔默认出口 state〕、`--host <ref>` 远程面经控制面
`stream.open{kind:files}` 纯透传，寻址与 host/term 面同源；`--state` 指代随 `--host` 切换、
`--rate-limit` 上行限速〔默认 2MiB/s 发送端义务〕，详见 README「文件命令面」节）；
`forward add/list/delete` = 端口转发命令面（forward-socks-speedtest 起：守护托管，规则
`<daemon-state>/forwards.json`、监听器住 daemon 进程仅回环、与手机 portfwd 面零耦合——
监听端口跨全部规则与 socks 全局唯一）、`socks on/off/status` = 按主机 SOCKS5 承载面
（同上：域名经指定出口远程解析〔DNS-over-TCP→5300〕、每 listener 一份缓存、off 显式
RST 在世连接且端口记忆保留）、`speedtest` = 隧道测速 CLI（守护托管：引擎
`pkg/speedtest` 与手机壳同一产物，`--host` 缺省 = 全主机顺序轮流、Ctrl-C 先 cancel
当前主机再退出；详见 README 三节）；
`clientcore/` = 手机核
（tier App 经其仓库的 submodule 钉定检出消费，产物 `libclientcore.so`）。本文件只放跨会话
都要知道的硬规则；工程细节看本仓 `README.md` 与 tier 仓（`github.com/zhaoyswd/tier`）的
`AGENTS.md` + `docs/agents/` 分册。

## 必须遵守（硬规则）

- **动核源码（`clientcore/`，或本仓任何会被 App 链进 `libclientcore.so` 的面）默认需要用户点头**：
  先说明「改哪个文件、为什么、影响面」并等明确同意。**例外（2026-09-27 起口径）**：tier 仓
  `docs/agents/roadmap.md` 通用节点 roadmap 范围内的载体 change（含核迁移/改名/发版/双出口部署）
  已由用户**预授权全自动推进**，不再逐项点头；范围外的新方向仍需点头。口径出处：tier 仓
  `AGENTS.md` 硬规则「动核源码…」条与其 roadmap 续接协议。
- **连接/重试/定时探测行为是跨仓契约**：改任何连接档位、节拍、阈值、门控、恢复阶梯（R1–R3）、
  判据行，**必须在同一次提交可核对的范围内同步 tier 仓 `docs/agents/connection-lifecycle.md`**
  （那是单一真源；数字与代码对不上就是文档腐化，下次真机排查会照着错的数字推）。
- **go directive ≤ 1.24（OHOS 绑定，勿升）**：`clientcore/` 编译面钉 OHOS Go 1.24.5
  （`GOTOOLCHAIN=local`），上游 x/* 依赖一旦 directive ≥1.25 就编不过——升版本只能取
  **directive ≤1.24 的最高版**（core-homeway-merge §2.1 实证：x/crypto v0.48 / x/net v0.50 /
  x/sys v0.41 是上限，0.49/0.51/0.42 起 = go 1.25.0）。CI 有 directive 守卫步兜底
  （release.yml 仅 tag / workflow_dispatch 触发，main 直推不拦——日常直推前须本地跑双面测试）。
- **改 `clientcore/` 后**：tier 侧要 `tools/tailcat/build-core.sh` → 重新 `assembleHsp` 才进装机产物
  （tier 仓的活，这里只提醒别以为改完就生效）。NAPI 导出面（`//export ClientCore*`）四处同步的
  机器门在 tier 仓 `tools/docs/check-napi-sync.sh`。

## 两个构建面（测试/构建都要分面跑）

- **无 tag 面**（`go build/vet/test ./...` 排除 `clientcore`，CI 五门）：出口/中继/`pkg/` 全部——
  默认 modcache，官方 toolchain 即可。
- **cshared 面**（`go build/vet/test -tags cshared ./clientcore/...`，CI clientcore job）：手机核。
  cgo 文件靠 `//go:build cshared` 进面，**不带 tag 是 build constraints 排除、不是少跑用例**。
- ⚠️ **OHOS 定制 go（`~/ohos_golang_go`）只做交叉编译，别在 darwin host 上跑重测试**——
  运行时会 GC 崩溃（core-homeway-merge exec-report 环节 2 硬事实）；重测试一律官方 toolchain。
