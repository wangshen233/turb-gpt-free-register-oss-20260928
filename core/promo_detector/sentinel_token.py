# -*- coding: utf-8 -*-
"""OpenAI Sentinel token mint（Node + 真 sdk.js 桥）—— GCash 建单风控证明。

对齐 engines/freepp-backend/ba_paypal/sentinel_mint.py 的成熟实现：
在 Node/V8 沙箱里加载与后端当前部署一致的 sdk.js（`sentinel_assets/sentinel_sdk.js`），
通过注入的 `SentinelSDK.__proto2(flow)` 钩子完成：

    requirementsToken → POST /backend-api/sentinel/req（同一代理/同一 cookie）
    → 服务器返回 {token(c), proofofwork{seed,difficulty}, turnstile{dx}}
    → 真 SDK VM 算出 turnstile proof (t) → 返回 {t, c, seed, diff, powReq}

Node 侧再用同一指纹配置解 PoW 得到 p（gAAAAAB…~S），拼出完整的
`openai-sentinel-token` 头值 JSON：{"p","t","c","id","flow"}。

失败降级：环境变量 `MIN_GCASH_SENTINEL_TOKEN` 直注入（人工从浏览器 DevTools 复制，
~9 分钟有效）；`MIN_GCASH_SENTINEL=0` 显式关闭并返回空。
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

_BRIDGE_VERSION = "20260810913b"
_ASSETS_DIR = Path(__file__).with_name("sentinel_assets")
_BRIDGE_JS = _ASSETS_DIR / "sentinel_bridge.js"


def _redact(value: str, limit: int = 200) -> str:
    text = str(value or "")
    return text[:limit] + ("…" if len(text) > limit else "")


def mint_sentinel_sync(
    *,
    flow: str,
    device_id: str,
    user_agent: str,
    proxy: str = "",
    cores: int = 16,
    page_url: str = "https://chatgpt.com/",
    language: str = "en-US",
    timezone: str = "Asia/Manila",
    platform: str = "Win32",
    platform_label: str = "Windows",
    screen_w: int = 1920,
    screen_h: int = 1080,
    max_touch_points: int = 0,
    cookie_header: str = "",
    timeout_s: float = 120.0,
    emit=None,
) -> dict:
    """生成 OpenAI Sentinel 头值（main dict）。

    返回 {"p":…, "t":…, "c":…, "id":…, "flow":…}（可直接作为
    `openai-sentinel-token` 头值）或空 dict（失败，调用方按无哨兵降级）。
    emit = callable(stage, status, msg) 与 gcash_service 日志风格一致。
    """
    log = emit or (lambda stage, status, msg: None)

    # 降级开关：显式关闭
    if str(os.environ.get("MIN_GCASH_SENTINEL") or "").strip() in {"0", "false", "no"}:
        log("sentinel", "warn", "MIN_GCASH_SENTINEL=0 已关闭哨兵生成，建单按无风控证明直连")
        return {}

    # 降级注入：人工从浏览器 DevTools 复制的完整 token（<9 分钟有效）
    env_token = str(os.environ.get("MIN_GCASH_SENTINEL_TOKEN") or "").strip()
    if env_token:
        try:
            parsed = json.loads(env_token)
            if isinstance(parsed, dict) and parsed.get("p") and parsed.get("c") and parsed.get("id"):
                log("sentinel", "run", "使用 MIN_GCASH_SENTINEL_TOKEN 注入的哨兵令牌（人工抓取）")
                return parsed
        except Exception:
            pass
        log("sentinel", "warn", "MIN_GCASH_SENTINEL_TOKEN 不是合法哨兵 JSON，忽略")

    if not _BRIDGE_JS.is_file():
        log("sentinel", "warn", "哨兵桥文件缺失（sentinel_assets/sentinel_bridge.js），无哨兵直连")
        return {}
    node = os.environ.get("SENTINEL_NODE") or "node"

    payload = json.dumps({
        "ua": user_agent,
        "cores": cores,
        "deviceId": device_id,
        "flow": flow,
        "proxy": proxy,
        "version": _BRIDGE_VERSION,
        "pageUrl": page_url,
        "language": language,
        "timezone": timezone,
        "platform": platform,
        "platformLabel": platform_label,
        "screenW": screen_w,
        "screenH": screen_h,
        "availH": max(0, screen_h - 48),
        "maxTouchPoints": max_touch_points,
        "cookieHeader": cookie_header,
        "sentinelOrigin": "https://chatgpt.com",
    }, separators=(",", ":")).encode("utf-8")

    log("sentinel", "run", "哨兵令牌生成中（Node 真 sdk.js，flow=" + str(flow) + "）…")
    started = time.monotonic()
    try:
        process = subprocess.run(
            [node, str(_BRIDGE_JS)],
            input=payload,
            capture_output=True,
            timeout=timeout_s,
            cwd=str(_ASSETS_DIR),
            check=False,
        )
    except FileNotFoundError:
        log("sentinel", "warn", "哨兵生成需要 Node.js（未找到 node），无哨兵直连")
        return {}
    except subprocess.TimeoutExpired:
        log("sentinel", "warn", "哨兵生成超时（>" + str(int(timeout_s)) + "s），无哨兵直连")
        return {}
    elapsed = round(time.monotonic() - started, 1)

    output = (process.stdout or b"").decode("utf-8", "replace").strip()
    if not output:
        err = (process.stderr or b"").decode("utf-8", "replace")[:300]
        log("sentinel", "warn", "哨兵桥无输出：" + _redact(err, 160) + "，无哨兵直连")
        return {}
    try:
        result = json.loads(output)
    except json.JSONDecodeError:
        log("sentinel", "warn", "哨兵桥输出非 JSON：" + _redact(output, 160) + "，无哨兵直连")
        return {}
    if result.get("error"):
        log("sentinel", "warn", "哨兵桥失败：" + _redact(str(result["error"]), 160) + "，无哨兵直连")
        return {}

    main = str(result.get("main") or "")
    if not main:
        log("sentinel", "warn", "哨兵桥未返回 main token，无哨兵直连")
        return {}
    try:
        token = json.loads(main)
    except json.JSONDecodeError:
        log("sentinel", "warn", "哨兵桥 main token 不是有效 JSON，无哨兵直连")
        return {}

    has_t = bool(result.get("hasT"))
    so_raw = str(result.get("so") or "")
    so_token = None
    if so_raw:
        try:
            so_token = json.loads(so_raw)
        except json.JSONDecodeError:
            so_token = None
    so_err = str(result.get("soErr") or "")
    log(
        "sentinel",
        "ok",
        "哨兵令牌完成（" + str(elapsed) + "s）t=" + ("有" if has_t else "无")
        + " so=" + ("有" if so_token else "无")
        + (("（" + _redact(so_err, 80) + "）") if so_err else "")
        + " flow=" + str(token.get("flow")) + " id=" + _redact(str(token.get("id")), 12),
    )
    if so_token:
        # _so 只是同进程内的中转字段（供 so_token_of() 拆分）；
        # 序列化成请求头前必须剥离，见 sentinel_header_value()。
        token["_so"] = so_token
    return token


def so_token_of(token: dict) -> dict | None:
    """取出内部 so-token；浏览器里它单独走 `openai-sentinel-so-token` 头。"""
    if not isinstance(token, dict):
        return None
    so_token = token.get("_so")
    return so_token if isinstance(so_token, dict) else None


def sentinel_header_value(token: dict) -> str:
    """Sentinel 头值（JSON 紧凑串），供 `openai-sentinel-token` 使用。

    抓包实测该头固定只有 {p,t,c,id,flow} 5 键（4855 / 4873 字节），
    so 必须单独走 `openai-sentinel-so-token`；这里先剥掉 _so 再序列化，
    否则会比浏览器多 1 个键、多 600~710 字节。
    """
    if not isinstance(token, dict) or not token.get("p") or not token.get("c"):
        return ""
    try:
        payload = {k: v for k, v in token.items() if k != "_so"}
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    except Exception:
        return ""



def so_header_value(so_token: dict) -> str:
    """SO 头值（JSON 紧凑串），供 openai-sentinel-so-token 使用。"""
    if not isinstance(so_token, dict) or not so_token.get("so"):
        return ""
    try:
        return json.dumps(so_token, separators=(",", ":"), ensure_ascii=False)
    except Exception:
        return ""
