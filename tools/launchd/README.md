# homeway daemon 的 launchd 用户代理（安装说明）

模板：`me.zhaozhe.homeway-daemon.plist.template`（同目录）。作用 = 开机自启 +
崩溃自动重拉（`RunAtLoad` + `KeepAlive`）——进程级兜底；会话/链路自愈在守护进程
进程内（角色子系统 + 核内恢复阶梯），launchd 只负责「进程死了拉起来」。

## 安装

```bash
# 1. 替换占位（两处：可执行文件路径、state 目录）
sed -e 's|__HOMEWAY_BIN__|/usr/local/bin/homeway|g' \
    -e 's|__STATE_DIR__|/Users/你的用户名/.config/homeway/daemon|g' \
    me.zhaozhe.homeway-daemon.plist.template > ~/Library/LaunchAgents/me.zhaozhe.homeway-daemon.plist

# 2. ⚠️ 先做「禁止同目录」检查（模板头注释同款提醒）：
#    该 state 目录不得与任何在役 `homeway exit --state`/`homeway relay --state`
#    部署相同。daemon 侧已硬拦：state 下存在 tokens.jsonl（出口身份特征）即报错
#    拒启；但 exit/relay 侧不检测（单实例锁只约束 daemon，exit 不取锁）——把
#    exit 指到 daemon 的 state 目录不会被任何一边拦住，只能靠人工避免（两进程
#    会共写 events/debug 日志并各自 rename 轮转互踩、共享 identity 目录）。角色
#    合并归后续能力域（3f）。默认子目录 ~/.config/homeway/daemon 与在役出口
#    ~/.config/homeway 不同目录，可并存。

# 3. 手动跑一次确认 state 初始化正常（可选但建议；目录/权限由守护进程自建）
/usr/local/bin/homeway daemon --state ~/.config/homeway/daemon
# Ctrl-C 收工后再 load

# 4. 加载
launchctl load ~/Library/LaunchAgents/me.zhaozhe.homeway-daemon.plist

# 5. 验证
launchctl list | grep homeway-daemon        # 应有一行（pid 非一、最后一列 0）
homeway daemon status                       # 控制面收发（版本/代际/角色/主机面）
```

## 卸载 / 排障

```bash
launchctl unload ~/Library/LaunchAgents/me.zhaozhe.homeway-daemon.plist
rm ~/Library/LaunchAgents/me.zhaozhe.homeway-daemon.plist
```

- 崩溃重拉验证：`kill -9 <pid>` 后 `launchctl list` 里 pid 应换新（KeepAlive 生效），
  主机表按持久化恢复（`homeway daemon status` 里主机与重启前一致）。
- 启动失败看 `__STATE_DIR__/launchd.log`（进程 stdout/stderr；正常运行期日志在
  `events.log`（摘要）与 `debug.log`（细节），按大小轮转）。
- 残留 `control.sock` 由守护进程自行处理：connect 探测无人监听即替换，被活实例
  占用则报「已在运行」退出（与单实例锁一致）。

## 与既有出口代理并存

| 代理 | label | state | 端口面 |
|---|---|---|---|
| 出口 | `me.zhaozhe.homeway-exit` | `~/.config/homeway` | UDP 41641 等 |
| 守护进程 | `me.zhaozhe.homeway-daemon` | `~/.config/homeway/daemon` | 仅本机 UDS（control.sock，0600） |

不同 label、不同 state 目录、无端口竞争面，可并存。**禁止**把两者的 `--state`
指到同一目录：daemon 侧对含 `tokens.jsonl` 的 state 硬拦拒启，exit/relay 侧不检测
（锁只约束 daemon）——反向指过去只能靠人工避免（见上）。角色合并（exit/relay 装进
daemon 进程、state 归一）归后续能力域（3f），届时本说明随迁移更新。

## 教训（为什么模板必须实测）

现役出口 plist 曾因 `ProgramArguments` 里「exit --relay」子命令形态不工作而换成
根命令形态（`homeway --relay …`）——launchd 的参数传递形态不能想当然。本模板
`daemon --state …` 形态已按上方安装步骤 4/5 实测拉起（拉起/KeepAlive 重拉/期望态
恢复判据见 openspec host-registry-daemon 执行报告 §5.4）。
