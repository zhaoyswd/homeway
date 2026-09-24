# libghostty-vt（vendored）— tier/homeway 的采纳口径

本目录是 **libghostty-vt**（Ghostty 的终端仿真库，C API 形态）的 vendor 副本，供 homeway 出口的
term 服务用作**会话屏态的唯一仿真器**（openspec change `term-vt-backend`，design D1）。

上游与补丁基线**不自行拼装**：直接采纳 herdr（`github.com/herdrdev/herdr`）的 vendor 副本口径，
即 `source_commit 44f2a44df7e8c4a0c6df3f7d872ef3d7ead88e51`（版本串 `1.3.2-HEAD-+44f2a44df`）
**叠加 4 个 herdr 本地补丁**。理由：这四个补丁中有两个直接决定我们的能力面（0002 暴露
modifyOtherKeys 模式查询 = 输入编码依赖；0006 清屏保留光标行），而 spike 验证过的也正是这个
基线——裸 vendor 未打补丁的上游会得到与 spike 不同的行为面。

## 补丁采纳决策

| 补丁 | herdr 侧理由（摘） | 我们是否依赖 | 决策 |
|---|---|---|---|
| `0002-expose-modify-other-keys-mode` | 终端需知道 xterm modifyOtherKeys mode 2 是否激活，才能要求外层终端上报可打印键的释放；formatter API 只能靠格式化整屏+回滚间接恢复该事实 | **是**（D4 输入编码：服务端按 vt 真实模式编码键事件，kitty/modifyOtherKeys 是其中一族） | 采纳 |
| `0004-fix-hosted-wuffs-builds` | 转发 libc 配置给 Wuffs 的 translate-c 依赖（Windows 交叉编）；限制 freestanding 的 calloc/free 桩，避免 hosted Linux 非 SIMD 构建里覆盖 libc 分配器 | **间接**（我们做 linux-musl 交叉编与 `-Dsimd=true`；这是构建正确性补丁，不采纳等于自己踩一遍） | 采纳 |
| `0005-bounded-word-selection` | Ctrl+click 需要能解析跨行折行的 token 而不扫描任意长逻辑行；共享 cell 检查预算，预算耗尽返回无选择而非截断链接 | **否**（我们的客户端不做超链接激活，OSC 8 在本期明确不支持——design Non-Goals） | 采纳（保持与 herdr 基线逐字节一致，成本为零；将来做 OSC 8 激活时它已在） |
| `0006-clear-screen-preserving-cursor-line` | 需要显式清屏/清历史且保留光标所在可见软折行，不写子进程、不打断半截 VT 序列；不动备用屏、清图像放置、标脏 | **待定**（surface 快照全量替换后，清屏语义由快照承担；保留它作为「重排/重绘」路径的备用工具） | 采纳（同上：与基线一致优先） |

补丁原文与验证命令见 herdr 仓库 `vendor/patches/libghostty-vt/` 与
`third_party/libghostty-vt.patches.md`（未复制进本目录，避免与本 README 的摘要重复——需要时按
`44f2a44` 去 herdr 取）。

**移除条件**：上游在 vendored commit 之后提供了等价能力（0002 的标量查询、0005 的有界选择、
0006 的保留光标行清屏、0004 的构建修复）时，按 herdr 那份 `patches.md` 的 remove-when 逐条复核后
可撤；撤补丁 = 换 vendor 基线，属独立改动。

## 本地改动（相对 herdr 的副本）

**源码零改动**——本目录与 herdr 的 `third_party/libghostty-vt/` 逐字节一致，只做了两项**裁剪**
（不改行为，纯粹是别把别人的 CI/打包脚手架拖进来）：

- 删除构建缓存与 VCS/CI 脚手架：`zig-pkg/`、`.zig-cache/`、`.github/`、`.agents/`、`nix/`、
  `flake.*`、`default.nix`、`shell.nix`、`build.zig.zon.{nix,json,txt}`、`CODEOWNERS`、
  `.clang-format` 等编辑器/工具配置。
- 保留 `LICENSE`、`VERSION`、`README.md`、`HACKING.md`、`PACKAGING.md`、`CMakeLists.txt`、
  `Makefile`、`dist/`（上游打包脚手架，不影响 zig 构建）与全部 `src/`、`include/`、`pkg/`。

补丁已应用（不是「补丁文件待打」）：`include/ghostty/vt/terminal.h` 有
`GHOSTTY_TERMINAL_DATA_MODIFY_OTHER_KEYS = 41` 与 `ghostty_terminal_clear_screen`，
`include/ghostty/vt/selection.h` 有 `ghostty_terminal_select_word_bounded`，
`pkg/wuffs/build.zig` 有 hosted libc 配置转发。

## 许可

MIT（`LICENSE`，Copyright (c) 2024 Mitchell Hashimoto, Ghostty contributors）。
随二进制分发时按 `THIRD-PARTY-NOTICES.txt` 的署名要求复现（由
`tools/gen-third-party-notices.sh` 拼装，见该脚本与任务 6.2）。

## 构建

`tools/build-vt.sh`（唯一入口）：钉 zig **0.16.0**，产 per-target 静态库到
`third_party/libghostty-vt/prebuilt/<goos>-<goarch>/lib/libghostty-vt.a`（**不入库**，见 `.gitignore`）。

```bash
./tools/build-vt.sh                      # 四个目标全产
./tools/build-vt.sh darwin-arm64         # 单目标（本地开发用）
```

目标映射与两条硬约束（spike `tools/spikes/03-vt-cgo/` 验证过）：

| goos-goarch | zig `-Dtarget` |
|---|---|
| darwin-arm64 | `aarch64-macos` |
| darwin-amd64 | `x86_64-macos` |
| linux-arm64 | `aarch64-linux-musl` |
| linux-amd64 | `x86_64-linux-musl` |

1. **必须删掉同目录的 dylib**：`-L <dir> -lghostty-vt` 在 `.a` 与 `.dylib` 并存时优先选动态库，
   而我们要求静态链接（解压即跑、无 rpath 依赖）。脚本产完即把 dylib 移出 `lib/`。
2. **darwin 产物用 llvm-ar 口径重打包**：zig 产的归档在 Apple ld 下偶发成员格式问题，
   脚本对 darwin 目标用 `zig ar --format=darwin` 解包-重打（等价 llvm-ar，本机无需 Xcode）。
3. `-Dversion-string` 必须是**语义版本**（上游用 `std.SemanticVersion.parse` 解析；
   传 `tier` 之类会直接 `error.InvalidVersion`），脚本固定 `1.3.2-tier`。

**构建前提**：zig 0.16.0（`ZIG` 环境变量指定，或 `~/zig-0.16.0/zig`，或 PATH 里的 `zig`）
+ 首次构建的**网络访问**（zig 从 `deps.files.ghostty.org` / `codeberg.org` 拉
`translate_c`/`aro`/`uucode`/`libxev`/`vaxis`/`z2d`/`zig_objc` 到 zig 包缓存；
缓存目录不在本目录内，见 zig 的 `--global-cache-dir`）。
