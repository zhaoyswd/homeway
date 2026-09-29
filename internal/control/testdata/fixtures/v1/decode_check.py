#!/usr/bin/env python3
"""decode_check.py — daemon-control-plane fixtures 的独立解码对拍脚本（语言无关自证）。

不依赖任何 Go 代码：仅凭 spec（tier 仓 openspec daemon-control-plane spec）实现的
最小帧解码头，对 fixtures/v1/frames.jsonl 的全部二进制帧向量做解码对拍：
  1. hex → 帧 [op:1][len:4 大端][body]，校验 len == len(body)、op 在码位表内；
  2. 控制类（JSON body）：json.loads 与 fixtures 声明的 expect.json **语义等价**
     （dict 深比较——键序不敏感，与 spec 冻结等级②一致）；
  3. 流 DATA 帧：body = [streamId:4 大端][原始字节]，与 expect.stream 逐字节比对。

用法：python3 decode_check.py [frames.jsonl]（默认同目录）。
退出码 0 = 全部对拍通过；非 0 = 有不一致（禁改 fixtures 字节——那是要冻结的契约）。
"""

import json
import sys
from pathlib import Path

# op 码位表（spec「帧封装」初始集，只增不改）。
OP_NAMES = {
    0x01: "hello",
    0x02: "welcome",
    0x03: "reload",
    0x04: "goodbye",
    0x10: "req",
    0x11: "rsp",
    0x12: "evt",
    0x13: "resync",
    0x20: "stream.data",
    0x21: "stream.end",
}
# 流帧（body 非 JSON：[streamId:4 大端][原始字节]）。
STREAM_BODY_OPS = {0x20}


def decode_frame(hexstr: str):
    raw = bytes.fromhex(hexstr)
    if len(raw) < 5:
        raise ValueError(f"帧短于 5 字节头（{len(raw)}）")
    op = raw[0]
    n = int.from_bytes(raw[1:5], "big")
    body = raw[5:]
    if n != len(body):
        raise ValueError(f"声明长度 {n} ≠ body 实长 {len(body)}")
    if op not in OP_NAMES:
        raise ValueError(f"op 0x{op:02x} 不在码位表")
    return op, body


def check_one(idx: int, fx: dict) -> None:
    name = fx.get("name", f"#{idx}")
    op, body = decode_frame(fx["hex"])
    # op 与声明一致。
    want_op = int(fx["op"], 16)
    if op != want_op:
        raise AssertionError(f"{name}: 帧内 op=0x{op:02x} 与声明 0x{want_op:02x} 不符")
    expect = fx.get("expect", {})
    if op in STREAM_BODY_OPS:
        # 流 DATA：[streamId:4][bytes]。
        if len(body) < 4:
            raise AssertionError(f"{name}: 流 body 短于 streamId 前缀")
        stream_id = int.from_bytes(body[:4], "big")
        payload = body[4:]
        want = expect.get("stream") or expect
        if stream_id != want.get("streamId"):
            raise AssertionError(f"{name}: streamId {stream_id} ≠ {want.get('streamId')}")
        if payload.hex() != (want.get("bytesHex") or ""):
            raise AssertionError(f"{name}: 流字节不一致：{payload.hex()} ≠ {want.get('bytesHex')}")
        print(f"OK   {name}: op={OP_NAMES[op]} streamId={stream_id} bytes={len(payload)}B（逐字节一致）")
        return
    # 控制类：JSON 语义等价（键序不敏感）。
    decoded = json.loads(body.decode("utf-8"))
    want_json = expect.get("json", expect)
    if decoded != want_json:
        raise AssertionError(f"{name}: JSON 语义不等价：\n  解码={json.dumps(decoded, ensure_ascii=False, sort_keys=True)}\n  声明={json.dumps(want_json, ensure_ascii=False, sort_keys=True)}")
    print(f"OK   {name}: op={OP_NAMES[op]} body={len(body)}B（JSON 语义等价）")


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "frames.jsonl"
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    failures = 0
    for i, ln in enumerate(lines):
        try:
            check_one(i, json.loads(ln))
        except Exception as e:  # noqa: BLE001 —— 对拍脚本逐条报告
            failures += 1
            print(f"FAIL {e}")
    print(f"\n{len(lines) - failures}/{len(lines)} 帧向量对拍通过（decode_check.py，protoVersion=v1）")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
