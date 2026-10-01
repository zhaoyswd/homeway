# homeway 统一进程的 launchd 用户代理（安装说明）

模板：`me.zhaozhe.homeway-daemon.plist.template`（同目录）。作用 = 开机自启 +
崩溃自动重拉（`RunAtLoad` + `KeepAlive`）——进程级兜底；会话/链路自愈在统一进程
进程内（角色子系统 + 核内恢复阶梯），launchd 只负责「进程死了拉起来」。拉起后按
`config.toml` 期望态恢复全部启用角色（serve/relay），机器重启同款自恢复。

**单代理口径**（role-management 3f）：一个代理管一台机器的统一进程——serve 出口、
relay 中继、client 注册表都在同一进程同一 state 里；不再有「出口代理 + 守护进程
代理」并存（角色已合并，旧隔离检查段随合并删除）。

## 安装

```bash
# 1. 替换占位（两处：可执行文件路径、统一 state 根）
sed -e 's|__HOMEWAY_BIN__|/usr/local/bin/homeway|g' \
    -e 's|__STATE_DIR__|/Users/你的用户名/.config/homeway|g' \
    me.zhaozhe.homeway-daemon.plist.template > ~/Library/LaunchAgents/me.zhaozhe.homeway-daemon.plist

# 2. 手动跑一次确认 state 初始化正常（可选但建议；三层布局/迁移/权限由进程自建）
/usr/local/bin/homeway --state ~/.config/homeway
# Ctrl-C 收工后再 load；角色期望态用命令组定（serve 默认启用）：
#   homeway serve relay set 'rl1…' && homeway serve ddns add home.example.com
#   homeway relay start（这台机当中继时）

# 3. 加载
launchctl load ~/Library/LaunchAgents/me.zhaozhe.homeway-daemon.plist

# 4. 验证
launchctl list | grep homeway-daemon        # 应有一行（pid 非一、最后一列 0）
homeway status                              # 聚合状态面：进程层 + serve/relay + client
pgrep -fl homeway                           # 命令行只有二进制路径——无 token、无角色子命令
```

## 卸载 / 排障

```bash
launchctl unload ~/Library/LaunchAgents/me.zhaozhe.homeway-daemon.plist
rm ~/Library/LaunchAgents/me.zhaozhe.homeway-daemon.plist
```

- 崩溃重拉验证：`kill -9 <pid>` 后 `launchctl list` 里 pid 应换新（KeepAlive 生效），
  主机表与角色期望态按持久化恢复（`homeway status` 与重启前一致）。
- 启动失败看 `__STATE_DIR__/cache/launchd.log`（进程 stdout/stderr）；正常运行期日志
  在 `cache/events.log`（serve 摘要）/`cache/daemon-events.log`（守护侧摘要）/
  `cache/debug.log`（细节），按大小轮转。
- 残留 `control.sock` 由统一进程自行处理：connect 探测无人监听即替换，被活实例
  占用则报「已在运行」退出（与单实例锁一致）。
- CLI 的按需拉起与本代理的交互：CLI 检测到本机 launchd 里有 homeway 代理 plist 时，
  先短轮询等 KeepAlive 重拉（约 4s）、超时才自 exec——不依赖 `launchctl kickstart`。

## 教训（为什么模板必须实测）

launchd 的参数传递形态不能想当然（现役出口 plist 曾因「exit --relay」子命令形态不
工作换过根命令形态）。本模板的零参形态已按上方安装步骤实测拉起（拉起/KeepAlive
重拉/期望态恢复判据见 openspec 对应 change 执行报告）。
