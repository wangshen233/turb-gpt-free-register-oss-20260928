# -*- coding: utf-8 -*-
"""ChatGPT 前端 bootstrap 预热链路。

根据 docs/protocol_fingerprint_har_analysis.md / protocol_har_summary.json
补齐与真实 Web 首屏更接近的 backend-anon / backend-api 初始化请求。该模块只做
可失败的预热：任何单个接口异常都会记录并继续，不打断注册主流程。
"""
from __future__ import annotations

import json
import logging
import re
from typing import Iterable
from urllib.parse import urlparse

from core.session import BrowserSession
from core.sentinel import generate_requirements_token
from config import openai_protocol as _protocol_cfg

logger = logging.getLogger(__name__)

_ANON_BASE = "https://chatgpt.com/backend-anon"
_API_BASE = "https://chatgpt.com/backend-api"


def _json_post(session: BrowserSession, url: str, payload: dict, referer: str, headers: dict | None = None):
    h = headers or session.get_chatgpt_headers(referer=referer, include_content_type=True)
    return session.post(url, headers=h, data=json.dumps(payload, separators=(",", ":")))


def _safe_request(label: str, fn, *, strict: bool = False):
    try:
        resp = fn()
        status = int(getattr(resp, "status_code", 0) or 0)
        if status >= 400:
            raise RuntimeError(f"HTTP {status}: {(getattr(resp, 'text', '') or '')[:180]}")
        return resp
    except Exception as exc:
        if strict:
            raise
        logger.debug("[Bootstrap] %s 跳过/失败：%s: %s", label, type(exc).__name__, str(exc)[:180])
        return None


def _system_hint_paths(modes: Iterable[str], base: str) -> list[str]:
    return [f"{base}/system_hints?mode={mode}" for mode in modes]


def _chat_requirements_prepare(session: BrowserSession, base: str, referer: str, *, strict: bool = False):
    """POST sentinel/chat-requirements/prepare，p 字段与会话画像一致。"""
    sid = getattr(session, "sentinel_sid", session.device_id)
    p = generate_requirements_token(sid, profile=getattr(session, "browser_profile", None))
    return _safe_request(
        f"{base}/sentinel/chat-requirements/prepare",
        lambda: _json_post(
            session,
            f"{base}/sentinel/chat-requirements/prepare",
            {"p": p},
            referer=referer,
        ),
        strict=strict,
    )


def _maybe_chat_requirements_finalize(session: BrowserSession, base: str, referer: str, prepare_resp, *, strict: bool = False):
    """
    HAR 中 finalize 需要 prepare_token/proofofwork/turnstile。不同版本返回结构会变，
    只有在 prepare 响应明确给到可用字段时才提交，避免构造半截 challenge。
    """
    if prepare_resp is None:
        return None
    try:
        data = prepare_resp.json()
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    prepare_token = data.get("prepare_token") or data.get("token") or data.get("c")
    if not prepare_token:
        return None
    payload = {"prepare_token": prepare_token}
    for key in ("proofofwork", "turnstile"):
        value = data.get(key)
        if value:
            payload[key] = value
    return _safe_request(
        f"{base}/sentinel/chat-requirements/finalize",
        lambda: _json_post(session, f"{base}/sentinel/chat-requirements/finalize", payload, referer=referer),
        strict=strict,
    )


# 首屏资源优先级：入口/清单/main 框架优先，其余按文档顺序补齐。
_ASSET_PRIORITY = ("manifest-", "entry.client-", "auth.login-", "root-")
_ASSET_URL_RE = re.compile(r"/cdn/assets/[A-Za-z0-9._\-]+")


def page_asset_urls(html: str, page_url: str, limit: int = 8) -> list[str]:
    """从首屏 HTML 里抽出要补拉的 /cdn/assets 资源（入口脚本优先）。"""
    refs = list(dict.fromkeys(_ASSET_URL_RE.findall(html or "")))
    if not refs:
        return []
    order = {name: i for i, name in enumerate(_ASSET_PRIORITY)}

    def rank(ref: str) -> int:
        for marker, idx in order.items():
            if marker in ref:
                return idx
        return len(order)

    refs.sort(key=rank)  # 稳定排序：同一优先级内保持文档顺序
    parsed = urlparse(page_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    return [base + ref for ref in refs[: max(1, int(limit))]]


def warm_page_assets(
    session: BrowserSession,
    *,
    page_url: str = "https://chatgpt.com/auth/login?next=%2F",
    limit: int = 8,
    strict: bool = False,
) -> dict:
    """像真实浏览器一样把首屏引用的静态资源拉一遍（默认只取前 limit 个）。

    纯协议链路只取文档不取资源，服务端看到的会话是"连 JS 都不下载的浏览器"。
    这里按 modulepreload 顺序补拉入口 JS / 主 CSS，成本可控（约 0.3~1 MB）。
    """
    stats = {"document_bytes": 0, "assets": 0, "asset_bytes": 0, "urls": []}
    try:
        resp = session.get(
            page_url,
            headers=session.get_chatgpt_navigate_headers(referer="https://chatgpt.com/"),
            allow_redirects=True,
        )
        html = getattr(resp, "text", "") or ""
        stats["document_bytes"] = len(html)
    except Exception as exc:
        logger.debug("[Bootstrap] 首屏文档获取失败：%s: %s", type(exc).__name__, str(exc)[:160])
        if strict:
            raise
        return stats

    for url in page_asset_urls(html, page_url, limit):
        is_css = url.endswith(".css")
        headers = session._get_common_headers("chatgpt.com")
        headers.update({
            "accept": "text/css,*/*;q=0.1" if is_css else "*/*",
            "referer": page_url,
            "sec-fetch-dest": "style" if is_css else "script",
            "sec-fetch-mode": "no-cors",
            "sec-fetch-site": "same-origin",
        })
        try:
            asset = session.get(url, headers=headers, allow_redirects=True)
            size = len(getattr(asset, "content", b"") or b"")
            stats["assets"] += 1
            stats["asset_bytes"] += size
            stats["urls"].append(url)
        except Exception as exc:
            logger.debug("[Bootstrap] 首屏资源失败 %s：%s", url, type(exc).__name__)
            if strict:
                raise
    logger.info(
        "[Bootstrap] 首屏资源补拉完成：%s 个，%s KiB（文档 %s KiB）",
        stats["assets"], round(stats["asset_bytes"] / 1024, 1), round(stats["document_bytes"] / 1024, 1),
    )
    return stats


def anonymous_bootstrap(session: BrowserSession, *, strict: bool = False) -> None:
    """注册前匿名态 ChatGPT 首页/模型预热。

    2026-09-13 真机复抓（同一入口 chatgpt.com/auth/login）中，真机这一段只发三个请求：
        GET /backend-anon/accounts/check/v4-2023-04-27?timezone_offset_min=-420
        GET /backend-anon/me
        GET /backend-anon/checkout_pricing_config/configs/{CC}
    且 referer 都是 https://chatgpt.com/auth/login（不是首页）。这里对齐真值；
    下面 models / system_hints / conversation/init 那几条真机没发，保留是为了老链路兼容。
    """
    referer = "https://chatgpt.com/auth/login"
    tz = session.js_timezone_offset_min()
    logger.info("[Bootstrap] 匿名态 ChatGPT 预热开始")
    _safe_request("anon accounts/check", lambda: session.get(
        f"{_ANON_BASE}/accounts/check/v4-2023-04-27?timezone_offset_min={tz}",
        headers=session.get_chatgpt_headers(referer=referer),
    ), strict=strict)
    _safe_request("anon me", lambda: session.get(f"{_ANON_BASE}/me", headers=session.get_chatgpt_headers(referer=referer)), strict=strict)
    _cc = str((getattr(session, "exit_geo", {}) or {}).get("country") or "").strip().upper()
    if _cc:
        _safe_request(f"anon checkout_pricing_config/{_cc}", lambda: session.get(
            f"{_ANON_BASE}/checkout_pricing_config/configs/{_cc}",
            headers=session.get_chatgpt_headers(referer=referer),
        ), strict=strict)

    # 2026-09-13 真机复抓：真机匿名态就上面这三个请求，**没有** models / system_hints /
    # conversation/init / sentinel chat-requirements prepare+finalize。后面这些是早期按
    # 别的抓包补的，属于"不相关的部分"：既增加了机器特征（真机不发），又白吃流量
    # （chat-requirements/prepare 单条解压后 89.6 KiB）。默认关掉，需要时用
    # CHATGPT_ANON_EXTRA_WARMUP=True 打开。
    if bool(getattr(_protocol_cfg, "CHATGPT_ANON_EXTRA_WARMUP", False)):
        prep = _chat_requirements_prepare(session, _ANON_BASE, referer, strict=strict)
        for url in [
            *_system_hint_paths(("custom_agents", "connectors", "basic"), _ANON_BASE),
            f"{_ANON_BASE}/models?iim=false&is_gizmo=false&supports_model_picker_upgrade_presets=true",
        ]:
            _safe_request(url, lambda u=url: session.get(u, headers=session.get_chatgpt_headers(referer=referer)), strict=strict)
        _safe_request("anon conversation/init", lambda: _json_post(session, f"{_ANON_BASE}/conversation/init", {
            "requested_default_model": None,
            "conversation_id": None,
            "timezone_offset_min": tz,
            "conversation_origin": None,
        }, referer=referer), strict=strict)
        _maybe_chat_requirements_finalize(session, _ANON_BASE, referer, prep, strict=strict)
    logger.info("[Bootstrap] 匿名态 ChatGPT 预热完成")


def authenticated_bootstrap(session: BrowserSession, access_token: str | None = None, *, strict: bool = False) -> None:
    """登录态 ChatGPT bootstrap，access_token 存在时补 Authorization。"""
    referer = "https://chatgpt.com/"
    tz = session.js_timezone_offset_min()

    def headers():
        h = session.get_chatgpt_headers(referer=referer)
        if access_token:
            h["authorization"] = access_token if access_token.lower().startswith("bearer ") else f"Bearer {access_token}"
        return h

    logger.info("[Bootstrap] 登录态 ChatGPT 预热开始")
    for path in [
        "/user_granular_consent",
        "/accounts/optimized/check",
        "/me",
        "/settings/is_adult",
        f"/accounts/check/v4-2023-04-27?timezone_offset_min={tz}",
        "/settings/user",
    ]:
        _safe_request(f"auth {path}", lambda p=path: session.get(f"{_API_BASE}{p}", headers=headers()), strict=strict)
    prep = _chat_requirements_prepare(session, _API_BASE, referer, strict=strict)
    for url in [
        *_system_hint_paths(("custom_agents", "plugins", "basic"), _API_BASE),
        f"{_API_BASE}/models?iim=false&is_gizmo=false&supports_model_picker_upgrade_presets=true",
    ]:
        _safe_request(url, lambda u=url: session.get(u, headers=headers()), strict=strict)
    tz_iana = str((getattr(session, "browser_profile", {}) or {}).get("timezone_iana") or "")
    init_payload = {
        "requested_default_model": None,
        "conversation_id": None,
        "timezone_offset_min": tz,
        "conversation_origin": None,
    }
    if tz_iana:
        init_payload["timezone"] = tz_iana
    _safe_request("auth conversation/init", lambda: _json_post(session, f"{_API_BASE}/conversation/init", init_payload, referer=referer, headers=headers()), strict=strict)
    _maybe_chat_requirements_finalize(session, _API_BASE, referer, prep, strict=strict)
    for path in [
        "/conversations?offset=0&limit=28&order=updated&is_archived=false&is_starred=false",
        "/client/strings",
        "/settings/user",
    ]:
        _safe_request(f"auth {path}", lambda p=path: session.get(f"{_API_BASE}{p}", headers=headers()), strict=strict)
    logger.info("[Bootstrap] 登录态 ChatGPT 预热完成")
