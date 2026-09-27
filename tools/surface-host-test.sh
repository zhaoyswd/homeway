#!/usr/bin/env bash
# tools/surface-host-test.sh — surface 解码头（surface/ 四件套）与 golden fixture 的**宿主编译与运行**。
#
# 由 tier 仓 tools/term/surface-golden-test.sh 随 surface 迁入按新布局改写：include 根 = 本仓根、
# golden 目录 = surface/test/golden、宿主测试 = surface/test/host。render 段**不迁**——
# surface_render_bridge 是 tier terminal HSP 的私有渲染桥，render 判据留 tier 侧脚本。
#
# 用法：
#   tools/surface-host-test.sh
#   出口侧先生成样例：go test ./pkg/term/ -run TestSurfaceGolden -update
#
# 退出码：0 = 两端一致；1 = 不一致（两端实现漂移）；2 = 环境/样例缺失。
set -euo pipefail

cd "$(dirname "$0")/.."   # 仓库根

GOLDEN_DIR=surface/test/golden
OUT_DIR=$(mktemp -d)
trap 'rm -rf "$OUT_DIR"' EXIT

if [[ ! -f "$GOLDEN_DIR/manifest.tsv" ]]; then
  echo "surface-host-test: 还没有共享样例（${GOLDEN_DIR}/manifest.tsv）" >&2
  echo "  先生成：go test ./pkg/term/ -run TestSurfaceGolden -update" >&2
  exit 2
fi

CXX=${CXX:-c++}
# zlib：macOS 自带；Linux 上需要 zlib1g-dev（或指定 ZLIB_PREFIX）。
ZLIB_CFLAGS=${ZLIB_CFLAGS:-}
if [[ -n "${ZLIB_PREFIX:-}" ]]; then
  ZLIB_CFLAGS="-I${ZLIB_PREFIX}/include -L${ZLIB_PREFIX}/lib"
fi

echo "surface-host-test: 编译宿主测试（${CXX}）"
# 跨仓→同仓 golden fixture（任务 2.8）的客户端侧断言：出口 Go 编码器生成样例，这里用 C++ 解码器解一遍。
# shellcheck disable=SC2086
"$CXX" -std=c++17 -O1 -Wall -Wextra -Werror \
  -I . $ZLIB_CFLAGS \
  surface/surface_codec.cpp surface/surface_scroll.cpp surface/surface_selection.cpp \
  surface/test/host/surface_golden_test.cpp \
  -lz -o "$OUT_DIR/surface_golden_test"

# 回滚视图模型（任务 3.3）的宿主判据：预取配方/冻结/锚点漂移都是纯逻辑，宿主能全钉死。
# shellcheck disable=SC2086
"$CXX" -std=c++17 -O1 -Wall -Wextra -Werror \
  -I . \
  surface/surface_codec.cpp surface/surface_scroll.cpp surface/surface_selection.cpp \
  surface/test/host/surface_scroll_test.cpp \
  -lz -o "$OUT_DIR/surface_scroll_test"

# 上行帧（任务 3.4）的字节级判据：布局本身两端各钉一次（下行有 golden fixture，上行靠这份表）。
# shellcheck disable=SC2086
"$CXX" -std=c++17 -O1 -Wall -Wextra -Werror \
  -I . \
  surface/surface_codec.cpp surface/surface_scroll.cpp surface/surface_selection.cpp \
  surface/test/host/surface_input_test.cpp \
  -lz -o "$OUT_DIR/surface_input_test"

# 文本选择（任务 3.7 配套）的宿主判据：选词/跨行拼接/CJK 占位格这些规则最容易悄悄坏。
"$CXX" -std=c++17 -O1 -Wall -Wextra -Werror \
  -I . \
  surface/surface_selection.cpp \
  surface/test/host/surface_selection_test.cpp \
  -o "$OUT_DIR/surface_selection_test"

echo "surface-golden: 运行（样例目录 ${GOLDEN_DIR}）"
"$OUT_DIR/surface_golden_test" "$GOLDEN_DIR"
echo "surface-scroll: 运行（回滚模型判据）"
"$OUT_DIR/surface_scroll_test"
echo "surface-input: 运行（上行帧判据）"
"$OUT_DIR/surface_input_test"
echo "surface-selection: 运行（文本选择判据）"
"$OUT_DIR/surface_selection_test"
