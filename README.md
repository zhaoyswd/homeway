# homeway

Homeway 的后端与中继：基于 WireGuard 的自建出口栈——`homewayd`（后端：WG 端点、
token 签发、流服务）与 `homeway-relay`（中继：多租户注册腿、per-client 分配式转发、
hint 地址观察）。手机端 App 仓库私有，本仓库承载**线上协议的唯一真源**
（`pkg/proto`：token / 注册报文 / 中继帧）。

状态：**早期开发中**（协议冻结阶段，服务实现未完成）。

## 用法（两个程序都零参数可用）

```bash
# 出口（后端）：零参数启动，启动日志里就有给手机用的 token
homewayd
# 需要中继时只多一个参数（中继 token 由 homeway-relay 启动时打印）
homewayd --relay 'rl1…'

# 中继：零参数启动，端口自动挑（冲突就 +1），启动日志里打印中继 token
homeway-relay
# 公网机器指定对外地址（写进 token）
homeway-relay --advertise 1.2.3.4:41741
```

没有生成/查询类子命令：身份密钥、token 台账、实际端口、已公布公网端点都在 `--state` 目录里
（默认 `~/.config/homeway` / `~/.config/homeway-relay`），token 由进程自己打印、看日志即可。
`--state` 指到哪儿就是哪套身份 —— 想在同一台机器上再开一个独立出口，换个目录即可。

## 布局

```
cmd/homewayd        后端（阶段 3 实现）
cmd/homeway-relay   中继，纯 stdlib（阶段 6 实现）
pkg/proto           线上契约：token（hmw1 格式）/ reg 报文 / 中继帧 + golden vectors
pkg/flows           内部流协议两端（阶段 2/3 实现）
```

## 开发

```bash
go test ./...
```

发版 = 推 tag（`v0.x.y`），CI 出 darwin/linux 四目标产物 + sha256（见
`.github/workflows/release.yml`）。

## 许可

待定（开源前必须落定；候选 MIT）。
