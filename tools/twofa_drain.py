# -*- coding: utf-8 -*-
"""注册批跑完后补设 2FA（注册机自带队列会在 main.py 退出时丢任务）。

为什么需要这个脚本
------------------
core/twofa_service.py 的 executor 写死 max_workers=2，而 main.py 一退出，进程内的
线程池就跟着消失 —— 排在队里还没跑的 2FA 任务**直接丢失**（和套餐查询同一个坑）。
8 并发注册 40 个号，注册期只会跑掉 2 个 2FA，剩下 38 个全被丢掉。

所以每批注册结束、main.py 退出之后，必须再补一遍：把所有「没有 totp_secret 且
不在 queued/running」的账号重新入队，并守到全部落定。

用法
----
  python tools/twofa_drain.py --since 931
  python tools/twofa_drain.py --since 931 --proxy socks5h://127.0.0.1:10808
  python tools/twofa_drain.py --since 931 --dry-run

出口默认 socks5h://127.0.0.1:10808（本地隧道）。2FA 不需要注册地区出口，
走它不花住宅代理流量。
"""
from __future__ import annotations

import argparse
import io
import json
import os
from pathlib import Path
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

import logging
logging.disable(logging.WARNING)

from core import db
from core.twofa_service import enqueue_account_totp_setup, is_running

DEFAULT_PROXY = "socks5h://127.0.0.1:10808"
IN_FLIGHT_MAX = 24          # 队列上限是 50，留余量


def _load_rows(include_archived: bool = False) -> list[dict]:
    """读账号表（显式放开两个默认值）。

    1) `db.list_accounts()` 默认 `archived=False` —— 归档号根本读不到；
    2) 默认 `limit=500` —— 库长过 500 行后会**静默截断**，后面的号被漏掉。
    当前库里非归档 484 行，已经贴着 500 了，必须显式放开。
    """
    return list(db.list_accounts(limit=1000000, archived=None if include_archived else False) or [])


def _promo_amount(row: dict):
    """读这条账号的优惠金额；没有判定结果时返回 None。"""
    raw = row.get("promo_check_json")
    if not raw:
        return None
    try:
        payload = json.loads(raw) if isinstance(raw, str) else raw
        results = payload.get("promo_results") or []
        if not results:
            return None
        return results[0].get("amount")
    except Exception:
        return None


def _promo_methods(row: dict) -> list[str]:
    """读这条账号支持的结账通道（小写）。"""
    raw = row.get("promo_check_json")
    if not raw:
        return []
    try:
        payload = json.loads(raw) if isinstance(raw, str) else raw
        results = payload.get("promo_results") or []
        if not results:
            return []
        r0 = results[0] or {}
        methods = r0.get("methods_all") or r0.get("methods") or []
        return [str(m).strip().lower() for m in methods]
    except Exception:
        return []


def _is_momo_zero(row: dict) -> bool:
    """「0 元 + 支持 MoMo」= 已交付给客户的号，绝对不能动。

    这些号是客户拿 MoMo 通道去付款的，2FA 流程会重认证并换发新的
    access_token —— 一动客户手里的 token 就废了。用户明确要求排除。
    """
    return _promo_amount(row) == 0 and "momo" in _promo_methods(row)


def _load_delivered(path: str) -> tuple[set[int], set[str]]:
    """读「已交付给客户」清单：每行一个 account id 或邮箱（# 开头为注释）。

    为什么要有这份清单：2FA 流程会**重认证并换发新的 access_token**，
    已经交给客户的号一旦被动过，客户手里的 token 就废了。所以这些号
    必须全局排除，不是靠每次手打 --exclude。
    """
    ids: set[int] = set()
    emails: set[str] = set()
    try:
        p = Path(path)
        if not p.exists():
            return ids, emails
        for ln in p.read_text(encoding="utf-8").splitlines():
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            if s.isdigit():
                ids.add(int(s))
            else:
                emails.add(s.lower())
    except Exception as exc:
        print("读取交付清单失败（忽略）：%s" % exc)
    return ids, emails


def _needs_twofa(
    row: dict,
    *,
    skip_zero: bool = False,
    allow_momo_zero: bool = False,
    include_archived: bool = False,
) -> bool:
    if not include_archived and bool(row.get("archived")):
        return False
    if not allow_momo_zero and _is_momo_zero(row):
        return False
    if str(row.get("totp_secret") or "").strip():
        return False
    if not str(row.get("access_token") or "").strip():
        return False
    if skip_zero and _promo_amount(row) == 0:
        return False
    status = str(row.get("totp_setup_status") or "")
    return status not in ("success", "queued", "running")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", type=int, required=True, help="起始 account id（含）")
    ap.add_argument("--until", type=int, default=None, help="结束 account id（含）")
    ap.add_argument("--proxy", default=DEFAULT_PROXY)
    ap.add_argument("--exclude", default="", help="逗号分隔的 account id，跳过这些账号")
    ap.add_argument(
        "--skip-zero", action="store_true",
        help="跳过 amount==0 的账号。默认**不跳过** —— 所有号都要设 2FA。"
             "只有在做对照实验或用户点名要求时才用。",
    )
    ap.add_argument(
        "--skip-file", default=str(Path(__file__).resolve().parent / "delivered_accounts.txt"),
        help="「已交付给客户」的账号清单（每行一个 id 或邮箱），这些号绝对不动。",
    )
    ap.add_argument(
        "--allow-momo-zero", action="store_true",
        help="允许动「0 元 + 支持 MoMo」的账号。默认**不动** —— 这些号已交付给客户，"
             "2FA 会换发新 access_token，把客户手里的 token 作废。",
    )
    ap.add_argument(
        "--include-archived", action="store_true",
        help="连 archived=1 的归档号一起处理。默认跳过（归档号不在 WebUI 正常列表里）。",
    )
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--timeout", type=int, default=3600, help="最长等待秒数")
    ap.add_argument(
        "--force-recover", action="store_true",
        help="把 queued/running 但已无人认领的任务复位成 stopped 再重新入队。"
             "main.py 退出后它的线程池就没了，库里却还留着 queued/running —— "
             "不复位的话 claim_account_totp_setup 会一直拒绝，任务永远补不上。",
    )
    args = ap.parse_args()

    if args.force_recover:
        rows0 = _load_rows(True)
        n = 0
        for r in rows0:
            if int(r.get("id") or 0) < args.since:
                continue
            if args.until is not None and int(r.get("id") or 0) > args.until:
                continue
            st = str(r.get("totp_setup_status") or "")
            if st in ("queued", "running") and not str(r.get("totp_secret") or "").strip():
                db.update_account_totp_secret(int(r["id"]), {
                    "ok": False, "status": "stopped",
                    "error": "上一进程已退出，任务已复位，重新入队",
                })
                n += 1
        print("复位孤儿任务 %d 个" % n)

    excluded = {int(x) for x in str(args.exclude or "").replace("，", ",").split(",") if x.strip().isdigit()}
    rows = _load_rows(args.include_archived)
    targets = [r for r in rows
               if int(r.get("id") or 0) >= args.since
               and (args.until is None or int(r.get("id") or 0) <= args.until)
               and int(r.get("id") or 0) not in excluded]
    if excluded:
        print("按 --exclude 跳过 %d 个：%s" % (len(excluded), sorted(excluded)))
    d_ids, d_emails = _load_delivered(args.skip_file)
    if d_ids or d_emails:
        before = len(targets)
        targets = [r for r in targets
                   if int(r.get("id") or 0) not in d_ids
                   and str(r.get("email") or "").strip().lower() not in d_emails]
        print("交付清单排除 %d 个（清单里 %d 个 id / %d 个邮箱）"
              % (before - len(targets), len(d_ids), len(d_emails)))

    todo = [r for r in targets if _needs_twofa(
        r,
        skip_zero=args.skip_zero,
        allow_momo_zero=args.allow_momo_zero,
        include_archived=args.include_archived,
    )]
    if args.skip_zero:
        nz = sum(1 for r in targets if _promo_amount(r) == 0 and not str(r.get("totp_secret") or "").strip())
        print("（--skip-zero：跳过 %d 个 0 元账号）" % nz)
    if not args.allow_momo_zero:
        mz = sum(1 for r in targets if _is_momo_zero(r) and not str(r.get("totp_secret") or "").strip())
        print("（MoMo-0元 排除 %d 个 —— 已交付客户，动了会作废客户 token）" % mz)
    if not args.include_archived:
        ar = sum(1 for r in targets if bool(r.get("archived")) and not str(r.get("totp_secret") or "").strip())
        print("（archived=1 跳过 %d 个）" % ar)
    print("区间内账号 %d 个，待设 2FA %d 个" % (len(targets), len(todo)))
    if args.dry_run:
        for r in todo:
            print("   ", r.get("id"), r.get("email"))
        return 0
    if not todo:
        print("没有需要补的")
        return 0

    pending = {int(r["id"]): r for r in todo}
    enqueued: set[int] = set()
    deadline = time.time() + args.timeout
    done_ok = done_fail = 0

    while pending and time.time() < deadline:
        # 「在飞」不能只看 is_running：worker 线程是懒启动的，刚入队的任务 is_running
        # 还是 False，会让人以为没在跑而一直往里塞 —— 实测一次塞满 50 个信号量后
        # 剩下的全被拒（2FA 队列已满）。所以直接读库里的 queued/running 状态。
        # 一次循环只读一次库。db.get_account() 内部是 _load_accounts()：整表读取 +
        # 逐行 JSON 解析。待办 120 个 × 每 6 秒调一次 = 每秒解析上百万行，
        # drain 会把自己卡成 CPU 瓶颈（实测 2FA 速度从 ~9/分钟掉到 1.5/分钟）。
        snap = {int(r.get("id") or 0): r for r in _load_rows(True)}
        active = 0
        for _a in pending.values():
            _st = str((snap.get(int(_a["id"])) or {}).get("totp_setup_status") or "")
            if _st in ("queued", "running"):
                active += 1
        for acc_id, row in list(pending.items()):
            if active >= IN_FLIGHT_MAX:
                break
            if acc_id not in snap:
                print("  账号已不存在（WebUI 删除），跳过 %s" % acc_id)
                pending.pop(acc_id, None)
                continue
            r = enqueue_account_totp_setup(
                account_id=acc_id,
                email=str(row.get("email") or ""),
                access_token=str(row.get("access_token") or ""),
                trigger="drain",
                proxy=args.proxy,
            )
            enqueued.add(acc_id)
            if r.get("accepted"):
                active += 1
                print("  入队 %s %s" % (acc_id, row.get("email")))
            elif r.get("busy"):
                active += 1
            elif r.get("queue_full"):
                # 信号量满：**不能丢**，下一轮再试
                print("  队列满，稍后重试（已入队 %d）" % active)
                break
            else:
                print("  入队失败 %s %s -> %s" % (acc_id, row.get("email"), r.get("error")))
                pending.pop(acc_id, None)
                done_fail += 1

        time.sleep(6)
        snap = {int(r.get("id") or 0): r for r in _load_rows(True)}
        for acc_id in list(pending.keys()):
            if acc_id not in snap:
                # 账号在 WebUI 里被删掉了。update_account_totp_secret 找不到行会直接
                # 返回 False，状态永远是空串 —— 旧代码会把它永远挂在 pending 里，
                # 看起来就是「2FA 卡住不动」。直接丢掉。
                print("  账号已不存在（WebUI 删除），跳过 %s" % acc_id)
                pending.pop(acc_id, None)
                continue
            cur = snap.get(acc_id) or {}
            status = str(cur.get("totp_setup_status") or "")
            if str(cur.get("totp_secret") or "").strip():
                print("  完成 %s %s" % (acc_id, cur.get("email")))
                pending.pop(acc_id, None)
                done_ok += 1
            elif status == "failed" and not is_running(acc_id):
                print("  失败 %s %s -> %s" % (acc_id, cur.get("email"), str(cur.get("totp_setup_error") or "")[:90]))
                pending.pop(acc_id, None)
                done_fail += 1

    print()
    print("成功 %d / 失败 %d / 未完成 %d" % (done_ok, done_fail, len(pending)))
    for acc_id in pending:
        cur = db.get_account(acc_id) or {}
        print("   未完成:", acc_id, cur.get("email"), cur.get("totp_setup_status"))
    return 0 if not pending else 1


if __name__ == "__main__":
    raise SystemExit(main())
