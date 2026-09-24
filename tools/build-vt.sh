#!/usr/bin/env bash
# tools/build-vt.sh — 产 libghostty-vt 静态库（openspec term-vt-backend 任务 1.1）。
#
# 唯一构建入口：从 third_party/libghostty-vt（上游 44f2a44 + herdr 补丁 0002/0004/0005/0006）
# 用 zig 0.16.0 产 per-target 静态归档，落到 third_party/libghostty-vt/prebuilt/<goos>-<goarch>/lib/。
# prebuilt/ 不入库（.gitignore）——构建前提、目标映射与三条硬约束见 third_party/libghostty-vt/README.tier.md。
#
# 用法：
#   ./tools/build-vt.sh                # 四个目标全产
#   ./tools/build-vt.sh darwin-arm64   # 单目标
#   ZIG=/path/to/zig ./tools/build-vt.sh
set -euo pipefail

cd "$(dirname "$0")/.."   # 仓库根

VENDOR=third_party/libghostty-vt
OUT_ROOT="$VENDOR/prebuilt"
# 上游要求 -Dversion-string 是语义版本（std.SemanticVersion.parse；传 "tier" 会 error.InvalidVersion）。
VT_VERSION_STRING=1.3.2-tier

# 目标映射：<goos>-<goarch> → zig -Dtarget。
ALL_TARGETS=(darwin-arm64 darwin-amd64 linux-arm64 linux-amd64)
zig_target() {
  case "$1" in
    darwin-arm64) echo aarch64-macos ;;
    darwin-amd64) echo x86_64-macos ;;
    linux-arm64)  echo aarch64-linux-musl ;;
    linux-amd64)  echo x86_64-linux-musl ;;
    *) return 1 ;;
  esac
}

# zig 定位：$ZIG > ~/zig-0.16.0/zig > PATH。钉 0.16.0（上游 build.zig.zon 的 minimum_zig_version）。
find_zig() {
  if [[ -n "${ZIG:-}" ]]; then echo "$ZIG"; return; fi
  if [[ -x "$HOME/zig-0.16.0/zig" ]]; then echo "$HOME/zig-0.16.0/zig"; return; fi
  command -v zig || true
}

ZIG_BIN="$(find_zig)"
if [[ -z "$ZIG_BIN" || ! -x "$ZIG_BIN" ]]; then
  echo "build-vt: 找不到 zig。装 zig 0.16.0 后用 ZIG=<路径> 指定（见 $VENDOR/README.tier.md）。" >&2
  exit 1
fi
have_ver="$("$ZIG_BIN" version)"
if [[ "$have_ver" != "0.16.0" ]]; then
  echo "build-vt: zig 版本是 $have_ver，本 vendor 基线钉 0.16.0（minimum_zig_version）。" >&2
  exit 1
fi

targets=("$@")
if [[ ${#targets[@]} -eq 0 ]]; then targets=("${ALL_TARGETS[@]}"); fi

for t in "${targets[@]}"; do
  # 注意：变量后面紧跟全角字符时必须写 ${}，否则变量名会被解析成含多字节字符的名字
  # （本机实测 `$t（` → `t<字节>: unbound variable`）。
  zt="$(zig_target "$t")" || { echo "build-vt: 未知目标 ${t}（可用：${ALL_TARGETS[*]}）" >&2; exit 2; }
  out="$OUT_ROOT/$t"
  echo "build-vt: ${t}（zig -Dtarget=${zt}）"
  rm -rf "$out"
  # 缓存放 vendor 内（gitignore），别污染 zig 的全局缓存目录。
  ( cd "$VENDOR" && "$ZIG_BIN" build \
      -Demit-lib-vt -Doptimize=ReleaseFast -Dsimd=true \
      -Dtarget="$zt" -Dversion-string="$VT_VERSION_STRING" \
      -Demit-xcframework=false \
      --cache-dir "$PWD/.zig-cache" \
      -p "$OLDPWD/$out" )
  # 硬约束①：删掉 dylib —— -lghostty-vt 在 .a/.dylib 并存时优先选动态库，我们要静态链接。
  rm -f "$out"/lib/*.dylib "$out"/lib/*.so*
  lib="$(ls "$out"/lib/libghostty-vt.a 2>/dev/null || true)"
  if [[ -z "$lib" ]]; then
    echo "build-vt: ${t} 没产出 lib/libghostty-vt.a（产物目录：${out}）" >&2
    exit 3
  fi
  # 硬约束②：darwin 产物按 llvm-ar 口径重打包（Apple ld 对 zig 归档成员格式偶发挑剔）。
  # zig ar 就是 LLVM Archiver，本机无需 Xcode 的 llvm-ar。
  case "$t" in
    darwin-*)
      # zig ar 解出来的成员是 000 权限（归档里没存模式），不 chmod 会「Permission denied」。
      tmp="$(mktemp -d)"
      ( cd "$tmp" && "$ZIG_BIN" ar x "$OLDPWD/$lib" \
        && chmod -R u+rwX . \
        && rm -f "$OLDPWD/$lib" \
        && "$ZIG_BIN" ar rcs "$OLDPWD/$lib" ./*.o )
      rm -rf "$tmp"
      ;;
  esac
  echo "build-vt: ${t} 完成 → ${lib}（$(wc -c <"$lib" | tr -d ' ') 字节）"
done

echo "build-vt: 全部完成。cgo 绑定层（pkg/term/vt）按 goos-goarch 选这里的库。"
