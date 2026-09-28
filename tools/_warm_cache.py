# -*- coding: utf-8 -*-
"""预热 Chromium 磁盘缓存（并行版）。

为什么改成并行
--------------
原来是一个 `for slot in SLOTS` 串行跑，每个槽要过 5 条路由、每条路由等资源稳定
（20s 无新增才算稳），单槽 ~200s。9 并发要预热 9 个槽 → 串行就是半小时，纯浪费。
改成线程池并行后，9 个槽总耗时 ≈ 单槽耗时（~3.5 分钟）。

注意：`ROXY_UNLIMITED_EXTRA_ARGS` 是模块级全局量（启动浏览器时读），
并行时必须把「设置全局 + 启动 profile」这段用锁圈起来，否则几个槽会互相串到对方的
`--disk-cache-dir` 上 —— 启动很快，锁不会成为瓶颈；慢的是后面的页面加载，那部分是并行的。
"""
import io
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

import config.roxybrowser as rb
from core.roxybrowser_client import RoxyBrowserClient
from core.roxy_registration import _build_driver

SLOTS = [int(x) for x in (sys.argv[1:] or ["1", "2", "3", "4", "5"])]
CACHE = os.path.join(ROOT, "cache", "roxy-shared")
# 只预热 chatgpt.com/auth/login 是不够的：注册真正跑的是 auth.openai.com 的 SPA
# （create-account / email-verification / password 这些路由的 JS/CSS），它们每号重新下载
# 就是单号流量从 1.1 MB 涨到 2.4 MB 的原因。把注册要走的几个路由都过一遍。
URLS = [
    "https://chatgpt.com/auth/login",
    "https://auth.openai.com/log-in",
    "https://auth.openai.com/create-account",
    "https://auth.openai.com/create-account/password",
    "https://auth.openai.com/email-verification",
]
os.makedirs(CACHE, exist_ok=True)
_LAUNCH_LOCK = threading.Lock()
_PRINT_LOCK = threading.Lock()


def _say(msg: str) -> None:
    with _PRINT_LOCK:
        print(msg, flush=True)


def slot_mb(slot: int) -> float:
    d = os.path.join(CACHE, "w%d" % slot)
    tot = 0
    for r, _, fs in os.walk(d):
        for f in fs:
            try:
                tot += os.path.getsize(os.path.join(r, f))
            except Exception:
                pass
    return tot / 1048576.0


def warm_slot(slot: int) -> tuple:
    d = os.path.join(CACHE, "w%d" % slot)
    before = slot_mb(slot)
    extra = "--disk-cache-dir=%s,--disk-cache-size=536870912" % d
    t0 = time.time()
    op = driver = None
    resources = 0
    err = ""
    try:
        c = RoxyBrowserClient()
        with _LAUNCH_LOCK:
            rb.ROXY_UNLIMITED_EXTRA_ARGS = extra
            op = c.open_profile()
        driver = _build_driver(op)
        driver.set_page_load_timeout(180)
        last = 0
        for url in URLS:
            try:
                driver.get(url)
            except Exception as e:
                _say("     [w%d] get 异常(继续): %s" % (slot, str(e)[:80]))
            stable_at = time.time()
            deadline = time.time() + 90
            while time.time() < deadline:
                try:
                    n = int(driver.execute_script(
                        "return performance.getEntriesByType('resource').length") or 0)
                except Exception:
                    n = last
                if n != last:
                    last, stable_at = n, time.time()
                elif time.time() - stable_at >= 20:
                    break
                time.sleep(3)
        resources = last
        after = slot_mb(slot)
        _say("  [w%-2d] 资源数=%-4d 用时=%4.0fs  缓存 %.1f -> %.1f MB" % (
            slot, resources, time.time() - t0, before, after))
    except Exception as e:
        err = "%s: %s" % (type(e).__name__, str(e)[:150])
        _say("  [w%-2d] 失败 %s" % (slot, err))
    finally:
        try:
            if driver:
                driver.quit()
        except Exception:
            pass
        try:
            if op:
                c.cleanup_profile(op)
        except Exception as e:
            _say("  [w%-2d] 清理: %s" % (slot, str(e)[:70]))
    return slot, resources, time.time() - t0, err


def main() -> int:
    print("代理 =", rb.ROXY_UNLIMITED_PROXY)
    print("槽位 = %s（并行，%d 路）" % (SLOTS, len(SLOTS)))
    print()
    started = time.time()
    results = []
    with ThreadPoolExecutor(max_workers=max(1, len(SLOTS))) as pool:
        futs = [pool.submit(warm_slot, s) for s in SLOTS]
        for fut in as_completed(futs):
            results.append(fut.result())

    print()
    print("预热后各槽:")
    total = 0.0
    for s in sorted(SLOTS):
        m = slot_mb(s)
        total += m
        print("  w%-2d %8.2f MB" % (s, m))
    failed = [r for r in results if r[3]]
    print("合计 %.2f MB | 总耗时 %.0fs（并行）| 失败 %d 个%s" % (
        total, time.time() - started, len(failed),
        ("：" + ", ".join("w%d %s" % (r[0], r[3][:60]) for r in failed)) if failed else ""))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
