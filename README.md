# homeway

Homeway 的后端与中继：基于 WireGuard 的自建出口栈——`homewayd`（后端：WG 端点、
token 签发、流服务）与 `homeway-relay`（中继：多租户注册腿、per-client 分配式转发、
hint 地址观察）。手机端 App 仓库私有，本仓库承载**线上协议的唯一真源**
（`pkg/proto`：token / 注册报文 / 中继帧）。

状态：**早期开发中**（协议冻结阶段，服务实现未完成）。

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
