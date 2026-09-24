# agent 检测规则（携署名移植自 herdr）

本目录是 **herdr**（https://github.com/herdrdev/herdr，Apache-2.0）的 screen manifest 规则集，
按 openspec change `term-vt-backend` 任务 4.5 移植。

## 来源与口径

- 源路径：herdr 仓库 `src/detect/manifests/`，clone 于 2026-09-23（`44f2a44` 时代）。
- 22 份 TOML **逐字节保持上游原样**：文件内注释、issue 引用（如 `issue #2650`）、
  `version` / `min_engine_version` / `updated_at` 一律不改。
- 唯一的本地新增文件是 `index.toml`：`id`/`path` 两列照 herdr 的**远程目录索引**
  （https://herdr.dev/agent-detection/index.toml，2026-09-23 取），`processes` 列是我们加的
  （herdr 把这层「进程名 → agent」映射写在 Rust 代码 `src/detect/mod.rs::lookup_agent` 里；
  出口需要在进程名上直接选 manifest，所以搬成数据）。
- 正则方言差异（`\uXXXX` / `\u{XXXX}` / `\p{Alphabetic}`）由引擎的方言垫片在编译期翻译，
  **不在文件里改**——这样上游更新 manifest 时可以整目录覆盖，不必人工重写。
  垫片与差异清单见 `../dialect.go` 的包注释。

## 许可与署名

Apache-2.0。分发时按 `THIRD-PARTY-NOTICES.txt` 复现署名与许可全文
（与 libghostty-vt 的 MIT 一并列入，见任务 6.2）。上游 `LICENSE` 见 herdr 仓库根目录。

## 移植复核记录（2026-09-23，本机实际 CLI 版本）

复核方式：真 PTY 起 CLI → 输出喂进我们的 vt（`pkg/term/vt`）→ 取**当前视口**纯文本
（`ScreenText()`）→ 跑引擎 explain。夹具与用例见 `../realcli_test.go` 与
`../testdata/*-startup.txt`（真字节，仅把机器路径换成中性路径）。

| CLI（本机版本） | 首屏形态 | 判定 | 结论 |
|---|---|---|---|
| opencode v2.0.11 | 欢迎页 + 「Ask anything…」输入框 | idle（回落） | ✅ 与设计一致：`opencode.toml` 本来就没有 idle 规则（只有 blocked 的 `permission_required` 与两条 working），已知 agent 无命中 ⇒ 回落 idle + 标签 |
| codex 0.155.1 | 首次进入某目录的**信任确认框**（`Do you trust the contents of this directory?` + `› 1. Yes, continue` / `2. No, quit` + `Press enter to continue`） | idle（回落） | ⚠️ **版本漂移**：上游**有** `trust_directory` 规则（p=950, blocked），但它的 region 是 `top_non_empty_lines(20)` 且第一条门是 `\A> You are in [^\r\n]+` —— **要求区域首行就是 `> You are in …`**。codex 0.155.1 在这行之上还画了 ASCII logo 与 `Welcome to Codex…`，首行是 logo ⇒ `\A` 锚点不成立 ⇒ 整条规则不命中 |

**诊断证据**（可直接复现）：把同一个屏幕裁到从 `> You are in` 开始，`trust_directory` 立刻命中
（explain 输出 `判定：blocked，命中规则：trust_directory`）；带 logo 时同一份规则不命中。
⇒ 结论是**规则的锚点假设与 CLI 当前渲染不符**，不是引擎/移植错误。

**处置（按 design 的既定机制，不改移植文件）**：本目录的 TOML 保持上游逐字节原样；
修法走**本地覆盖目录** `<state>/agent-detection/codex.toml`（本地永远优先，改完重启出口即生效，
不必等出口发版）。`realcli_test.go` 的 `TestTrustDialogFixedByOverride` 演示的正是**最小修法**
——把 `\A` 锚点换成 `contains`——并在这个真实屏幕字节上断言判成 blocked。

同类「CLI 改版导致规则失效」的排查入口固定为
`homeway term explain --file <保存的屏幕> --agent <label>`（任务 4.8），
它输出命中规则、优先级、来源/版本与**全部规则的评估轨迹**（哪条在哪个 region 上失手一目了然）。

### 输入口径（顺带定死）

引擎的「屏幕尾部文本」= **当前视口一屏**（`vt.ScreenText()`），不是整条回滚：
契约原文是「当前活动屏方向最近约一屏的纯文本行，滚动位置不影响」。整条回滚既会让
`\A` 这类锚定规则失准，也会让每拍扫描成本随历史长度增长。上面那条 codex 缺口与口径无关
（logo 就在视口里），是纯粹的规则锚点问题。
