"""结账检测所需的浏览器风控上下文。"""
from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

from .attestation import fetch_attestation
from .sentinel_token import (
    mint_sentinel_sync,
    sentinel_header_value,
    so_header_value,
    so_token_of,
)

_CLIENT_VERSION = "prod-180ca8b8699a733aef330b7026892aee9bf85fbe"
_CLIENT_BUILD = "9758774"
_DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
)


def _alternate_proxy_scheme(proxy: str) -> str:
    try:
        parsed = urlsplit(str(proxy or ""))
        scheme = (parsed.scheme or "").lower()
        if scheme in ("socks5", "socks5h"):
            target = "http"
        elif scheme in ("http", "https"):
            target = "socks5h"
        else:
            return ""
        return urlunsplit((target, parsed.netloc, parsed.path, parsed.query, parsed.fragment))
    except Exception:
        return ""


def _fingerprint_kwargs(fingerprint: dict) -> dict:
    platform = re.sub(r"\s+", "", str(fingerprint.get("platform") or "Win32"))
    platform_os = str(fingerprint.get("platform_os") or "Windows")
    if "Mac" in platform_os or platform in ("MacIntel", "Mac"):
        platform = "MacIntel"
        platform_label = "macOS"
    elif "win" in platform_os.lower():
        platform = "Win32"
        platform_label = "Windows"
    else:
        platform_label = platform_os
    try:
        width, height = map(int, str(fingerprint.get("screen") or "1920x1080").lower().split("x", 1))
    except Exception:
        width, height = 1920, 1080
    return {
        "platform": platform,
        "platform_label": platform_label,
        "screen_w": width,
        "screen_h": height,
        "max_touch_points": int(fingerprint.get("max_touch_points") or 0),
    }


def _apply_sentinel_headers(headers: dict, token: dict) -> str:
    """把 mint 出来的 token 拆成 openai-sentinel-token / -so-token 两个头。

    浏览器实测：token 头只有 {p,t,c,id,flow} 5 键，so 头只有 {so,c,id,flow} 4 键。
    sentinel_header_value() 已剥离内部 _so，这里负责把 so 单独补成第二个头。
    """
    value = sentinel_header_value(token)
    if not value:
        return ""
    headers["openai-sentinel-token"] = value
    so_token = so_token_of(token)
    so_value = so_header_value(so_token) if so_token else ""
    if so_value:
        headers["openai-sentinel-so-token"] = so_value
    return value


def checkout_risk_headers(
    session_get,
    proxy: str,
    device_id: str,
    session_id: str,
    fingerprint: dict,
    promo_campaign_id: str,
    cookie_header: str,
    timeout: float,
    log,
) -> dict[str, str]:
    """生成检测 checkout 请求所需的 Sentinel 与部署证明请求头。"""
    headers: dict[str, str] = {}
    page_url = (
        "https://chatgpt.com/?promo_campaign=plus-1-month-free"
        if promo_campaign_id
        else "https://chatgpt.com/"
    )
    try:
        token = mint_sentinel_sync(
            flow="chatgpt_checkout",
            device_id=device_id,
            user_agent=str(fingerprint.get("ua") or _DEFAULT_UA),
            proxy=proxy,
            cores=int(fingerprint.get("hardware_concurrency") or 16),
            page_url=page_url,
            language=str(fingerprint.get("oai_language") or "en-US"),
            timezone=str(fingerprint.get("timezone") or "America/Chicago"),
            cookie_header=cookie_header,
            timeout_s=float(max(timeout, 60) or 60),
            emit=log,
            **_fingerprint_kwargs(fingerprint),
        )
        value = _apply_sentinel_headers(headers, token)
        alternate = _alternate_proxy_scheme(proxy) if not value else ""
        if alternate:
            log("sentinel", "run", "当前代理协议未生成风控令牌，使用备用协议重试一次")
            token = mint_sentinel_sync(
                flow="chatgpt_checkout",
                device_id=device_id,
                user_agent=str(fingerprint.get("ua") or _DEFAULT_UA),
                proxy=alternate,
                cores=int(fingerprint.get("hardware_concurrency") or 16),
                page_url=page_url,
                language=str(fingerprint.get("oai_language") or "en-US"),
                timezone=str(fingerprint.get("timezone") or "America/Chicago"),
                cookie_header=cookie_header,
                timeout_s=float(max(timeout, 60) or 60),
                emit=log,
                **_fingerprint_kwargs(fingerprint),
            )
            value = _apply_sentinel_headers(headers, token)
        if value:
            log("sentinel", "ok", "建单风控令牌已写入请求头")
        else:
            log("sentinel", "fail", "未生成建单风控令牌")
    except Exception as exc:
        log("sentinel", "warn", f"哨兵生成异常：{type(exc).__name__}: {str(exc)[:150]}")

    try:
        value = fetch_attestation(
            session_get,
            url=page_url,
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": str(
                    fingerprint.get("accept_language") or "en-US,en;q=0.9"
                ),
                "Origin": "https://chatgpt.com",
                "Referer": "https://chatgpt.com/",
                "User-Agent": str(fingerprint.get("ua") or _DEFAULT_UA),
                "oai-device-id": device_id,
                "oai-session-id": session_id,
                "oai-client-version": _CLIENT_VERSION,
                "oai-client-build-number": _CLIENT_BUILD,
                "Cookie": cookie_header,
                "sec-fetch-dest": "document",
                "sec-fetch-mode": "navigate",
                "sec-fetch-site": "same-origin",
            },
            timeout=timeout,
            emit=log,
        )
        if value:
            headers["oai-web-deployment-attestation"] = value
    except Exception as exc:
        log("attestation", "warn", f"部署证明获取异常：{type(exc).__name__}")
    return headers
