# -*- coding: utf-8 -*-
"""给协议引擎用的 remail 中继外壳。

── 为什么需要它 ──
协议注册机的入口要求一对 **email----relay_url**（iCloud 中转取件链接），
relay_url 必须是一个能直接 GET、能解析出验证码的 URL。

而 remail 交付的邮箱**没有这种链接** —— 它靠
    GET https://remail.aishop6.com/v1/pickup?email=<email>&token=<service_token>
取码（不需要 API Key）。

这里起一个本地 HTTP 服务，把 remail 的取码包成协议机认得的形态：
    http://127.0.0.1:<PORT>/api/v1/access/<service_token>/mailboxes/<email>/code

协议机的 ICloudRelayProvider 会 GET 这个地址，用 parse_relay_html 扫页面里的
6 位码（有整页扫描兜底），拿不到就 3 秒后再来 —— 正好对上它的轮询节奏。

用法：
    python tools/remail_relay_shim.py --port 19100
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REMAIL_BASE = os.environ.get("REMAIL_API_BASE", "https://remail.aishop6.com").rstrip("/")
TIMEOUT = float(os.environ.get("REMAIL_SHIM_TIMEOUT", "15"))

_cache: dict[str, tuple[float, str]] = {}
_lock = threading.Lock()
CACHE_TTL = 2.0


def _pickup(email: str, token: str) -> dict:
    """问 remail 要一次收件内容。带 2 秒缓存，避免协议机高频轮询把它打爆。"""
    key = email + "|" + token
    now = time.time()
    with _lock:
        hit = _cache.get(key)
        if hit and now - hit[0] < CACHE_TTL:
            return json.loads(hit[1])
    url = "%s/v1/pickup?%s" % (REMAIL_BASE, urllib.parse.urlencode({"email": email, "token": token}))
    req = urllib.request.Request(url, headers={"Accept": "application/json",
                                               "User-Agent": "turb-remail-shim/1.0"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        payload = json.loads(r.read().decode("utf-8", "replace"))
    with _lock:
        _cache[key] = (now, json.dumps(payload, ensure_ascii=False))
    return payload


def _extract_code(payload) -> str:
    """从 pickup 的返回里挖出最新的 6 位验证码。"""
    import re
    items = payload
    if isinstance(payload, dict):
        for k in ("data", "items", "list", "messages", "records", "result"):
            v = payload.get(k)
            if isinstance(v, list):
                items = v
                break
            if isinstance(v, dict):
                items = v.get("items") or v.get("list") or v.get("messages") or []
                break
    if not isinstance(items, list):
        items = [items] if isinstance(items, dict) else []
    best, best_ts = "", -1.0
    for m in items:
        if not isinstance(m, dict):
            continue
        ts = 0.0
        for tk in ("receivedAt", "received_at", "timestamp", "createdAt", "created_at", "time"):
            v = m.get(tk)
            if isinstance(v, (int, float)):
                ts = float(v); break
            if isinstance(v, str):
                try:
                    ts = float(v); break
                except Exception:
                    pass
        blob = json.dumps(m, ensure_ascii=False)
        cands = re.findall(r"(?<!\d)(\d{6})(?!\d)", blob)
        if cands and ts >= best_ts:
            best_ts = ts
            best = cands[0]
    return best


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_a):
        pass

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        parts = [p for p in path.split("/") if p]
        # /api/v1/access/<token>/mailboxes/<email>/code
        code = ""
        err = ""
        if len(parts) >= 6 and parts[0] == "api" and parts[1] == "v1" and parts[2] == "access":
            token = urllib.parse.unquote(parts[3])
            email = urllib.parse.unquote(parts[5])
            try:
                code = _extract_code(_pickup(email, token))
            except Exception as exc:
                err = "%s: %s" % (type(exc).__name__, str(exc)[:120])
        else:
            err = "bad path"
        # ★ 2026-09-24：改成**直接返 JSON**（原来返 HTML）。
        #
        #   原来的 HTML 形态只能走“整页扫描兜底”那条路：
        #   parse_relay_html 的双闸门（码独占一行 + 周围有 openai/chatgpt）
        #   在这个页面上必然失配（页面里没有品牌词）→ 走兜底 →
        #   **ts=None，时间窗失效**，可能拿到旧码。
        #   现在直接返 {"success":true,"code":"123456"}，走 _direct_otp 那条路，
        #   ts 给当前时间，时间窗又回来了 —— 跟 47.108.184.137 那种直给码的
        #   中转完全同一种形态。
        if code:
            payload = {"success": True, "code": code}
        else:
            payload = {"success": False, "code": "no_code",
                       "message": "暂未收到验证码" + ((" " + err) if err else ""),
                       "retryable": True}
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=19100)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    sys.stderr.write("[remail-shim] listening on http://%s:%d  -> %s\n" % (args.host, args.port, REMAIL_BASE))
    sys.stderr.flush()
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
