#!/usr/bin/env bash
# 生成 THIRD-PARTY-NOTICES.txt：把**打进 homeway 二进制**的第三方组件的版权行与许可原文
# 拼装成一份随二进制分发的声明文件（BSD-3 / MIT / Apache-2.0 的二进制分发条款都要求
# 「把版权声明、许可条款与免责声明复现在随分发提供的材料里」——只写组件名不满足）。
#
# 用法：
#   tools/gen-third-party-notices.sh           # 重新生成仓库根的 THIRD-PARTY-NOTICES.txt
#   tools/gen-third-party-notices.sh --check   # 只校验已提交文件是否与当前依赖一致（CI 门禁）
#
# 依赖清单来自发版矩阵（.github/workflows/release.yml 的 6 个 GOOS/GOARCH 组合）逐平台的
# `go list -deps ./cmd/homeway` 取**并集**（评审整改 2026-09-22：只按跑脚本这台机器的 GOOS
# 枚举会漏 Windows 独有的 wintun、多列 Windows 不链接的组件——各平台模块集不同）。
# 许可原文与版权行取自各模块在 GOMODCACHE 里的 LICENSE、**不手抄**（避免法务文本转录错误）；
# 少数上游 LICENSE 里不含版权行（Apache-2.0 的几个），才回落到源码头部的标准署名。
# 新增依赖后：在 meta() 里补一行（漏补会硬失败并打印模块名），然后重跑本脚本。
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/THIRD-PARTY-NOTICES.txt"
SELF="github.com/zhaoyswd/homeway"
ENTRY="./cmd/homeway"

# 发版矩阵（与 release.yml 的 include 保持一致；改矩阵记得同步这里，否则 --check 会漏平台）
RELEASE_TARGETS="darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 linux/arm windows/amd64"

# 模块 → "<节 id>|<展示名>|<许可名>|<版权行兜底：仅当 LICENSE 里没有 Copyright 行时用>"
meta() {
  case "$1" in
    github.com/creack/pty)             echo "pty|creack/pty（出口侧 pty，终端会话用）|MIT|" ;;
    github.com/google/btree)           echo "btree|google/btree（B 树，gVisor 的依赖）|Apache-2.0|Copyright 2014 Google Inc." ;;
    golang.org/x/crypto)               echo "xgo|golang.org/x/crypto|BSD-3-Clause|" ;;
    golang.org/x/net)                  echo "xgo|golang.org/x/net|BSD-3-Clause|" ;;
    golang.org/x/sys)                  echo "xgo|golang.org/x/sys|BSD-3-Clause|" ;;
    golang.org/x/time)                 echo "xgo|golang.org/x/time|BSD-3-Clause|" ;;
    golang.zx2c4.com/wireguard)        echo "wireguard|wireguard-go（WireGuard 数据面）|MIT|Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved." ;;
    golang.zx2c4.com/wireguard/wgctrl) echo "wgctrl|wireguard/wgctrl（UAPI 控制客户端）|MIT|" ;;
    golang.zx2c4.com/wintun)           echo "wintun|wintun（Windows TUN 驱动的 Go 绑定，仅 Windows 构建）|MIT|Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved." ;;
    gvisor.dev/gvisor)                 echo "gvisor|gVisor（netstack：出口过境拦截）|Apache-2.0|Copyright 2018 The gVisor Authors." ;;
    *)                                 echo "" ;;
  esac
}

# Go 模块缓存目录名把大写字母转义成 `!小写`（当前依赖全小写，为将来加依赖兜底）
cache_dir() {
  printf '%s' "$1" | awk '{s="";for(i=1;i<=length($0);i++){c=substr($0,i,1);
    if (c ~ /[A-Z]/) s = s "!" tolower(c); else s = s c} print s}'
}

hash_file() { md5 -q "$1" 2>/dev/null || md5sum "$1" | awk '{print $1}'; }

cd "$ROOT"
GOMODCACHE=$(go env GOMODCACHE)
GOROOT=$(go env GOROOT)
# Go 版本标记读 go.mod 指令而非本机工具链：产物由 CI 按 go.mod 系列构建
#（go-version-file: go.mod），记录工具链 patch 会让本地与 CI 的 --check 永不一致。
GOMOD_GOVER="go$(awk '$1=="go"{print $2; exit}' go.mod)"
[ -n "$GOMOD_GOVER" ] && [ "$GOMOD_GOVER" != "go" ] || { echo "error: go.mod 里没有 go 指令，版本标记取不到" >&2; exit 1; }

# 逐平台枚举取并集：rows_gen 里记 "模块 版本 平台"，最后按模块聚合出平台标签。
LIST="$ROOT/.gen-notices-list.$$"
trap 'rm -f "$LIST"' EXIT
: > "$LIST"
for tgt in $RELEASE_TARGETS; do
  os="${tgt%/*}"; arch="${tgt#*/}"
  GOOS="$os" GOARCH="$arch" go list -deps -f '{{if .Module}}{{.Module.Path}} {{.Module.Version}}{{end}}' "$ENTRY" \
    | sed '/^$/d' | grep -v "^${SELF} " | awk -v p="$os" '{print $1" "$2" "p}' >> "$LIST" || true
done
[ -s "$LIST" ] || { echo "error: go list 没列出任何第三方模块（是不是先要 go mod download？）" >&2; exit 1; }

GEN=$(mktemp -d)
trap 'rm -rf "$GEN" "$LIST"' EXIT
: > "$GEN/seen"; : > "$GEN/sum_ids"; : > "$GEN/rows"

# 收集一个组件：同文本（同 md5）共用一个分节，避免同一份全文重复出现。
# 行里的「全文见 ===== X =====」引用**实际建了分节的那个 id**（评审整改：x/ 与
# GOROOT/LICENSE 字节相同，早先写死自己的 id 会悬空引用不存在的节）。
collect() { # <id> <展示名> <许可名> <版本标记> <LICENSE 文件> <版权行兜底> <平台标签>
  local id="$1" name="$2" lic="$3" ver="$4" file="$5" fallback="$6" plats="$7"
  local cr sum refid
  # 版权行：只看文件开头三行「非空行」里有没有以 Copyright 开头的（Apache 全文里的
  # "Copyright [yyyy] …" 附录在很后面，不会被误取）；没有就回落到 meta() 里登记的署名。
  cr=$(sed -e '/^[[:space:]]*$/d' "$file" | head -3 | grep -m1 '^Copyright' || true)
  [ -n "$cr" ] || cr="$fallback"
  [ -n "$cr" ] || cr="（该 LICENSE 原文未含版权行，见下文全文）"
  sum=$(hash_file "$file")
  refid=$(awk -v s="$sum" '$1==s{print $2; exit}' "$GEN/sum_ids")
  if [ -z "$refid" ]; then
    echo "$sum $id" >> "$GEN/sum_ids"
    refid="$id"
    { echo "===== ${id} ====="; cat "$file"; echo; } >> "$GEN/sections"
  fi
  printf -- '- %s %s — %s — %s — 平台：%s — 全文见 ===== %s =====\n' \
    "$name" "$ver" "$lic" "$cr" "$plats" "$refid" >> "$GEN/rows"
}

# Go runtime：版权行取构建工具链自己的 LICENSE；版本标记用 go.mod 声明系列（见上）；
# 平台 = 全矩阵。
collect "go" "Go runtime（标准库与运行时）" "BSD-3-Clause" "$GOMOD_GOVER" "$GOROOT/LICENSE" "" "全部"

missing=""
# 聚合：模块 → 版本 + 出现过的平台集合；输出按模块路径排序（awk 的 map 遍历
# 顺序不确定，不排序的话 --check 会因行序抖动而误报）。
sort -u "$LIST" | awk '{plat[$1" "$2]=plat[$1" "$2]" "$3} END{for (k in plat) print k plat[k]}' | sort \
  | while read -r path ver plats; do
    m=$(meta "$path")
    if [ -z "$m" ]; then
      echo "  ${path} ${ver}" >> "$GEN/missing"
      continue
    fi
    IFS='|' read -r id name lic fallback <<< "$m"
    dir="$GOMODCACHE/$(cache_dir "$path")@$ver"
    file=$(ls "$dir"/LICENSE* 2>/dev/null | head -1 || true)
    if [ -z "$file" ]; then
      echo "  ${path} ${ver}（模块缓存里没有 LICENSE 文件：${dir}）" >> "$GEN/missing"
      continue
    fi
    collect "$id" "$name" "$lic" "$ver" "$file" "$fallback" "$plats"
  done

if [ -s "$GEN/missing" ]; then
  cat >&2 <<EOF
error: 以下依赖没有登记许可信息，无法生成合规声明：
$(cat "$GEN/missing")
处理：在 tools/gen-third-party-notices.sh 的 meta() 里补一行，然后重跑本脚本。
      （若它本不该进二进制，说明依赖引入方式有问题，先把依赖摘掉。）
EOF
  exit 1
fi

{
  cat <<'EOF'
homeway 第三方组件声明（THIRD-PARTY-NOTICES）
================================================================================
本文件随 homeway 二进制分发：GitHub Release 归档包与容器镜像里各带一份。
homeway 自有代码的许可见 LICENSE（MIT）；本文件只覆盖**静态链接进任一发版平台二进制**的
第三方组件——它们用的是 BSD-3 / MIT / Apache-2.0，都要求以二进制形式分发时把版权声明、
许可条款与免责声明复现在随分发的材料里。

真源就是本文件，内容由 tools/gen-third-party-notices.sh 从各依赖自己的 LICENSE 原文拼装，
**不要手改**（改了会被 CI 的 --check 门禁打回）。分节标记 `===== <id> =====` 与手机端 App
的许可页（tier 仓 entry/src/main/ets/model/ThirdPartyLicenses.ets）同款，便于两仓对照。
许可原文完全相同的组件（如 golang.org/x 系列）共用一个分节。

清单口径 = 发版矩阵逐平台 `go list -deps ./cmd/homeway` 的并集（组件行的「平台」标注它
出现在哪些目标上；只在 go.mod 里、没被任何平台二进制链接的模块不列）。

一、随二进制分发的第三方组件
--------------------------------------------------------------------------------
EOF
  cat "$GEN/rows"
  cat <<'EOF'

二、许可全文
================================================================================
EOF
  cat "$GEN/sections"
} > "$GEN/out.txt"

# 自检：行里的每个「全文见 ===== X =====」必须真有 X 分节（防止生成器回归出悬空引用）。
while IFS= read -r ref; do
  grep -qx "===== ${ref} =====" "$GEN/out.txt" || {
    echo "error: 悬空引用——行里指向的 ===== ${ref} ===== 分节不存在（生成器 bug）" >&2
    exit 1
  }
done < <(sed -n 's/.*全文见 ===== \(.*\) =====$/\1/p' "$GEN/rows" | sort -u)

if [ "${1:-}" = "--check" ]; then
  if ! diff -u "$OUT" "$GEN/out.txt" > "$GEN/diff.txt" 2>&1; then
    echo "error: THIRD-PARTY-NOTICES.txt 与当前依赖不一致（改了依赖没重跑生成脚本）：" >&2
    sed -n '1,40p' "$GEN/diff.txt" >&2
    echo "处理：跑一次 tools/gen-third-party-notices.sh 并提交。" >&2
    exit 1
  fi
  echo "ok: THIRD-PARTY-NOTICES.txt 与当前依赖一致（$(grep -c '^===== ' "$OUT") 个分节）"
  exit 0
fi

cp "$GEN/out.txt" "$OUT"
echo "已生成 ${OUT}（$(grep -c '^- ' "$OUT") 个组件 / $(grep -c '^===== ' "$OUT") 个许可分节）"
