# -*- coding: utf-8 -*-
"""批量跑完后的僵尸清理：把残留的 RoxyChrome 进程全部杀掉。

为什么需要
----------
注册窗口的关闭/删除走 Roxy API（/browser/close + /browser/delete）。这两个调用
**失败只 warning 不报错**（API 重启、EPERM、超时都试过会漏），漏掉之后窗口进程还活着，
`--disk-cache-dir` 的独占锁就拿不到 —— 后面每个用同槽的窗口全部重新下载静态资源，
单号流量从 ~2 MB 涨到 ~11 MB（今天实测 1145-1147 就是这么烧的）。

本脚本是**兜底网**：批跑完、确认没有任务在用时，把所有 RoxyChrome 进程杀光。
配合 core/roxybrowser_client.cleanup_profile 里的按 profile 精确清理，双保险。

用法
----
  python tools/reap_roxy_zombies.py            # 检查 + 杀掉残留
  python tools/reap_roxy_zombies.py --force    # 有任务在跑也杀（不推荐，仅排障）
"""
from __future__ import annotations

import argparse
import subprocess
import sys


def _running_tasks() -> list:
    """正在跑、会用到 Roxy 窗口的 python 任务。"""
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'python.exe' } | ForEach-Object { $_.CommandLine }"],
            capture_output=True, text=True, timeout=30,
        ).stdout or ""
    except Exception:
        return []
    hits = []
    for line in out.splitlines():
        low = str(line).lower()
        if "reap_roxy_zombies" in low:
            # 自己（和父进程）的命令行里带着脚本路径，不算任务。
            continue
        if "main.py" in low or "_warm_cache" in low:
            hits.append(line.strip()[:90])
    return hits


def reap_roxy_zombies(quiet: bool = False, force: bool = False) -> int:
    busy = _running_tasks()
    if busy and not force:
        if not quiet:
            print("有任务在用 Roxy 窗口，跳过清理：" + " | ".join(busy))
        return -1
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "$n = (Get-Process RoxyChrome -ErrorAction SilentlyContinue | Measure-Object).Count; "
             + "Get-Process RoxyChrome -ErrorAction SilentlyContinue | Stop-Process -Force; "
             + "Start-Sleep -Milliseconds 800; "
             + "$left = (Get-Process RoxyChrome -ErrorAction SilentlyContinue | Measure-Object).Count; "
             + "$n.ToString() + '/' + $left.ToString()"],
            capture_output=True, text=True, timeout=60,
        ).stdout.strip()
    except Exception as exc:
        if not quiet:
            print("清理异常:", exc)
        return -1
    parts = out.split("/")
    killed = parts[0] if len(parts) > 0 else "?"
    left = parts[1] if len(parts) > 1 else "?"
    if not quiet:
        print("RoxyChrome：杀掉 %s 个，剩余 %s 个" % (killed, left))
    try:
        return int(killed)
    except Exception:
        return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true", help="有任务在跑也杀（仅排障用）")
    args = ap.parse_args()
    rc = reap_roxy_zombies(quiet=False, force=args.force)
    sys.exit(0 if rc >= 0 else 1)