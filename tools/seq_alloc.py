# -*- coding: utf-8 -*-
"""给 roxy 并发窗口分配住宅会话，并记账（支持复用）。

背景
----
会话名到住宅账号的映射是哈希：sha1(name)[:4] % 83。连续递增的会话名（{SEQ}）
映射到随机池位，所以「连续 N 个都落在没用过的池位」在池子用掉一半后几乎不可能
满足。这里改成**名单制**：直接挑出 N 个会话名，写进 tools/_roxy_sessions.json，
roxy 每次新建窗口从名单里弹一个。

复用
----
83 个住宅账号每个 5 MiB，一次注册约 1.8 MB。全新账号用完后就该复用：
按「已用次数」升序挑，优先榨最没被用过的账号，单批内保证池位互不重复
（否则两个并发窗口挤同一个账号会瞬间打干）。默认开启复用，用 --no-reuse 关掉。

用法
----
  python tools/seq_alloc.py --count 10          # 分配 10 个（默认允许复用）
  python tools/seq_alloc.py --count 10 --no-reuse
  python tools/seq_alloc.py --show
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

POOL_PATH = ROOT / "tools" / "cb_res_pool.json"
LEDGER_PATH = ROOT / "tools" / "_roxy_seq_ledger.json"
SESSIONS_PATH = ROOT / "tools" / "_roxy_sessions.json"

RNG = random.Random()


def pool_index(session: str, total: int) -> int:
    """和 tools/socks_bridge_10808.py 的 candidates() 完全一致的映射。"""
    digest = hashlib.sha1(str(session).encode("utf-8", "replace")).digest()
    return int.from_bytes(digest[:4], "big") % max(1, total)


def session_for_index(target: int, total: int, salt: int = 0) -> str:
    """找一个哈希到指定池位的会话名。"""
    for i in range(200000):
        name = "icloud%d" % (100000 + (i * 7919 + salt * 104729 + RNG.randrange(0, 97)))
        if pool_index(name, total) == target:
            return name
    raise RuntimeError("找不到映射到 pool[%d] 的会话名" % target)


def load_json(path: Path, default):
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return default


def save_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def load_ledger() -> dict:
    led = load_json(LEDGER_PATH, {})
    if not isinstance(led, dict):
        led = {}
    led.setdefault("used_counts", {})
    led.setdefault("water", 1)
    led.setdefault("sessions", [])
    return led


def main() -> None:
    global LEDGER_PATH
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--show", action="store_true")
    ap.add_argument("--no-reuse", action="store_true", help="只用完全没用过的住宅账号")
    ap.add_argument(
        "--pool-file",
        default=str(POOL_PATH),
        help="上游池文件。.json 视为账号池；其它按 host:port:user:pass 每行一条解析。"
             "分池模数取该文件的行数，必须与 socks_bridge_10808 的 len(upstreams) 一致 —— "
             "两边模数不同时，池位互不相同的两个会话仍可能映射到同一个出口 IP。",
    )
    args = ap.parse_args()

    pool_path = Path(args.pool_file)
    if not pool_path.exists():
        raise SystemExit("未找到池文件: %s" % pool_path)
    if pool_path.suffix.lower() == ".json":
        pool = json.loads(pool_path.read_text(encoding="utf-8"))
    else:
        pool = []
        for _ln in pool_path.read_text(encoding="utf-8").splitlines():
            _ln = _ln.strip()
            if not _ln or _ln.startswith("#"):
                continue
            _parts = _ln.split(":", 3)
            pool.append({
                "username": _parts[2] if len(_parts) > 2 else _ln,
                "raw": _ln,
            })
    if not pool:
        raise SystemExit("池文件为空: %s" % pool_path)
    total = len(pool)

    # 每个池单独一个账本：池位的含义随模数变化，共用一个账本会把索引算错。
    LEDGER_PATH = LEDGER_PATH.with_name("_roxy_seq_ledger_%s.json" % pool_path.stem)
    led = load_ledger()
    counts = {int(k): int(v) for k, v in (led.get("used_counts") or {}).items()}

    if args.show:
        unused = total - len(counts)
        print("池子大小     : %d" % total)
        print("未用过账号   : %d" % unused)
        print("已用账号     : %d" % len(counts))
        dist: dict[int, int] = {}
        for c in counts.values():
            dist[c] = dist.get(c, 0) + 1
        print("使用次数分布 :", dict(sorted(dist.items())))
        queued = load_json(SESSIONS_PATH, [])
        print("待用名单     : %s" % (queued if isinstance(queued, list) else "[]"))
        return

    # 候选池位按「已用次数升序」排 —— 优先用全新的，其次用只用过一次的
    candidates = sorted(range(total), key=lambda i: (counts.get(i, 0), RNG.random()))
    if args.no_reuse:
        candidates = [i for i in candidates if counts.get(i, 0) == 0]
        if len(candidates) < args.count:
            print("ERROR: 未用过的池位不足：需要 %d 个，只有 %d 个；去掉 --no-reuse 可复用"
                  % (args.count, len(candidates)), file=sys.stderr)
            sys.exit(2)

    if len(candidates) < args.count:
        print("ERROR: 池位总数 %d 少于需要的 %d 个" % (total, args.count), file=sys.stderr)
        sys.exit(2)

    chosen = candidates[:args.count]
    picked = [(session_for_index(idx, total, salt=i), idx) for i, idx in enumerate(chosen)]

    print("会话 / 池位 / 住宅账号 / 已用次数：")
    for name, idx in picked:
        print("  %-14s pool[%-2d] %-16s 已用 %d 次" % (name, idx, pool[idx]["username"], counts.get(idx, 0)))

    if args.dry_run:
        return

    save_json(SESSIONS_PATH, [n for n, _ in picked])
    for _, idx in picked:
        counts[idx] = counts.get(idx, 0) + 1
    led["used_counts"] = {str(k): v for k, v in counts.items()}
    led["sessions"] = (led.get("sessions") or []) + [n for n, _ in picked]
    led["sessions"] = led["sessions"][-600:]
    save_json(LEDGER_PATH, led)
    print("已写名单 %s（%d 个）；未用过账号剩余 %d/%d"
          % (SESSIONS_PATH.name, len(picked), total - len(counts), total))


if __name__ == "__main__":
    main()
