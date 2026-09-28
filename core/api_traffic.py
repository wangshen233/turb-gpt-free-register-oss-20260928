# -*- coding: utf-8 -*-
"""检测流程（Python / curl_cffi）的流量计数 —— 和浏览器那套分开算。

两套口径必须分清楚，别混着报：

| 口径 | 来源 | 包含什么 |
|---|---|---|
| 注册流量 | `core/browser_traffic.py`（Chrome performance log） | **只算注册窗口的页面级请求**，不含 TLS/IP/隧道开销，也看不见 Chrome 后台下载 |
| 检测流量 | 本模块（挂在 curl_cffi 上） | 查套餐 / 优惠检测的全部 HTTP：定价配置、**两次整页 HTML 抓取**（warmup + attestation）、Sentinel、建单、Stripe init |

两个数加起来才是「这个号烧掉的代理流量」的近似值（再叠加 TLS/隧道开销；要精确值用
`tools/_traffic_meter.py` 按字节计量）。

用法
----
    from core import api_traffic
    api_traffic.install()          # 幂等，进程内装一次
    api_traffic.reset()            # 一次检测前
    ...跑检测...
    s = api_traffic.stats()        # {'requests': n, 'download_bytes': x, 'upload_bytes': y, 'by_host': {...}}
"""
from __future__ import annotations

import threading
from typing import Any

_INSTALLED = False
_LOCK = threading.Lock()
_LOCAL = threading.local()


def _bucket() -> dict[str, Any]:
    b = getattr(_LOCAL, "bucket", None)
    if b is None:
        b = {"requests": 0, "download_bytes": 0, "upload_bytes": 0, "by_host": {}}
        _LOCAL.bucket = b
    return b


def _host_of(url: str) -> str:
    try:
        text = str(url or "")
        if "://" in text:
            text = text.split("://", 1)[1]
        return text.split("/", 1)[0] or "-"
    except Exception:
        return "-"


def _upload_size(kwargs: dict) -> int:
    """上传字节的近似值：只算请求体（headers / TLS 开销不算）。"""
    total = 0
    for key in ("data", "json", "content", "files"):
        value = kwargs.get(key)
        if value is None:
            continue
        try:
            if isinstance(value, (bytes, bytearray)):
                total += len(value)
            elif isinstance(value, str):
                total += len(value.encode("utf-8", "replace"))
            elif key == "json":
                import json as _json
                total += len(_json.dumps(value, ensure_ascii=False).encode("utf-8", "replace"))
            elif isinstance(value, dict):
                total += sum(len(str(k)) + len(str(v)) for k, v in value.items())
        except Exception:
            continue
    return total


def install() -> bool:
    """把计数器挂到 curl_cffi.requests.Session.request 上。幂等。"""
    global _INSTALLED
    with _LOCK:
        if _INSTALLED:
            return True
        try:
            from curl_cffi import requests as curl_requests
        except Exception:
            return False
        original = curl_requests.Session.request

        def _counted(self, method, url, *args, **kwargs):
            resp = original(self, method, url, *args, **kwargs)
            try:
                b = _bucket()
                b["requests"] += 1
                try:
                    down = len(resp.content or b"")
                except Exception:
                    down = 0
                up = _upload_size(kwargs)
                b["download_bytes"] += down
                b["upload_bytes"] += up
                host = _host_of(url)
                row = b["by_host"].setdefault(host, {"requests": 0, "download_bytes": 0, "upload_bytes": 0})
                row["requests"] += 1
                row["download_bytes"] += down
                row["upload_bytes"] += up
            except Exception:
                pass
            return resp

        curl_requests.Session.request = _counted
        _INSTALLED = True
        return True


def reset() -> None:
    _LOCAL.bucket = {"requests": 0, "download_bytes": 0, "upload_bytes": 0, "by_host": {}}


def stats() -> dict[str, Any]:
    b = _bucket()
    return {
        "requests": int(b["requests"]),
        "download_bytes": int(b["download_bytes"]),
        "upload_bytes": int(b["upload_bytes"]),
        "total_bytes": int(b["download_bytes"]) + int(b["upload_bytes"]),
        "by_host": {k: dict(v) for k, v in (b.get("by_host") or {}).items()},
    }


def format_line(stats_dict: dict[str, Any] | None = None) -> str:
    """一行摘要：请求数 / 下载 / 上传 / 合计 / host 明细。"""
    s = stats_dict if isinstance(stats_dict, dict) and stats_dict else stats()
    hosts = s.get("by_host") or {}
    detail = "，".join(
        "%s %.1f KiB" % (h, (v.get("download_bytes", 0) + v.get("upload_bytes", 0)) / 1024)
        for h, v in sorted(hosts.items(), key=lambda x: -(x[1].get("download_bytes", 0) + x[1].get("upload_bytes", 0)))
    )
    return "请求 %s 次，下载 %.1f KiB，上传 %.1f KiB，合计 %.1f KiB%s" % (
        s.get("requests", 0),
        s.get("download_bytes", 0) / 1024,
        s.get("upload_bytes", 0) / 1024,
        s.get("total_bytes", 0) / 1024,
        ("（%s）" % detail) if detail else "",
    )
