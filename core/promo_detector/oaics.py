"""OAICS 结账状态读取与支付方式/金额解析。"""
from __future__ import annotations

import json
import os
import re
import threading
import uuid
from typing import Any, Optional

from config.openai_protocol import OAI_CLIENT_BUILD_NUMBER, OPENAI_BUILD_ID

from .http import chatgpt_session, request

OPENAI_CHECKOUT_URL = "https://chatgpt.com/backend-api/payments/checkout"
# 2026-09-11 收口：原先这里自己一套更旧的硬编码
# （prod-db390ebea64862bf1899c420a4c736e0cf639747 / 7904904），与前端实际发版值
# 不一致。build/version 只允许 config/openai_protocol.py 一处定义，全仓引用同一份。
_CHATGPT_CLIENT_VERSION = OPENAI_BUILD_ID
_CHATGPT_CLIENT_BUILD_NUMBER = OAI_CLIENT_BUILD_NUMBER
_SEC_CH_UA = '"Chromium";v="146", "Google Chrome";v="146", "Not.A/Brand";v="99"'
_SEC_CH_UA_FULL = (
    '"Chromium";v="146.0.7423.118", '
    '"Google Chrome";v="146.0.7423.118", '
    '"Not.A/Brand";v="99.0.0.0"'
)
_CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/146.0.7423.118 Safari/537.36"
)

_LOCALE_PROFILES = {
    "US": ("en-US", "America/Chicago"),
    "BR": ("pt-BR", "America/Sao_Paulo"),
    "GB": ("en-GB", "Europe/London"),
    "DE": ("de-DE", "Europe/Berlin"),
    "FR": ("fr-FR", "Europe/Paris"),
    "JP": ("ja-JP", "Asia/Tokyo"),
    "AU": ("en-AU", "Australia/Sydney"),
    "CA": ("en-CA", "America/Toronto"),
    "TH": ("th-TH", "Asia/Bangkok"),
    "PH": ("en-PH", "Asia/Manila"),
    "VN": ("vi-VN", "Asia/Ho_Chi_Minh"),
    "KR": ("ko-KR", "Asia/Seoul"),
    "IN": ("en-IN", "Asia/Kolkata"),
    "ID": ("id-ID", "Asia/Jakarta"),
    "NL": ("nl-NL", "Europe/Amsterdam"),
    "ES": ("es-ES", "Europe/Madrid"),
    "IT": ("it-IT", "Europe/Rome"),
    "PL": ("pl-PL", "Europe/Warsaw"),
    "SE": ("sv-SE", "Europe/Stockholm"),
    "NO": ("nb-NO", "Europe/Oslo"),
    "DK": ("da-DK", "Europe/Copenhagen"),
    "FI": ("fi-FI", "Europe/Helsinki"),
    "SG": ("en-SG", "Asia/Singapore"),
    "MY": ("ms-MY", "Asia/Kuala_Lumpur"),
    "MX": ("es-MX", "America/Mexico_City"),
    "AR": ("es-AR", "America/Argentina/Buenos_Aires"),
    "CL": ("es-CL", "America/Santiago"),
    "CO": ("es-CO", "America/Bogota"),
    "PE": ("es-PE", "America/Lima"),
    "AE": ("en-AE", "Asia/Dubai"),
    "ZA": ("en-ZA", "Africa/Johannesburg"),
    "IL": ("he-IL", "Asia/Jerusalem"),
    "CH": ("de-CH", "Europe/Zurich"),
}
_SESSION_IDS: dict[str, str] = {}
_SESSION_IDS_LOCK = threading.Lock()
_WRAPPER_KEYS = (
    "checkout_session",
    "checkoutSession",
    "session",
    "checkout",
    "data",
    "result",
    "payload",
    "response",
    "checkout_state",
    "checkoutState",
    "checkout_snapshot",
    "checkoutSnapshot",
)
_AMOUNT_PATHS = (
    ("checkout_amount_minor",),
    ("total_summary", "due"),
    ("totalSummary", "due"),
    ("invoice", "amount_due"),
    ("invoice", "amountDue"),
    ("amount_due",),
    ("amountDue",),
    ("amount_total",),
    ("amountTotal",),
    ("total", "total"),
    ("total", "due"),
    ("total", "taxInclusive"),
    ("total", "taxInclusiveAmount"),
)

# 真正"要付多少钱"的字段，按权威度排序。OAICS 建单响应里 total.taxInclusive 是
# 税额分量（无优惠时为 0），把它和 total.total 并列比较会得出"金额观测不一致"，
# 结果 amount=None、promo=no——把本来该显示的价格也吞掉了。
_PAYABLE_PATHS = (
    ("checkout_amount_minor",),
    ("total_summary", "due"),
    ("totalSummary", "due"),
    ("invoice", "amount_due"),
    ("invoice", "amountDue"),
    ("amount_due",),
    ("amountDue",),
    ("amount_total",),
    ("amountTotal",),
    ("total", "due"),
    ("total", "total"),
)


def profile(country: str) -> dict[str, str]:
    locale, timezone = _LOCALE_PROFILES.get((country or "US").upper(), _LOCALE_PROFILES["US"])
    return {
        "browser_locale": locale,
        "browser_timezone": timezone,
        "browser_language": locale,
    }


def _session_id_for_device(device_id: str) -> str:
    key = str(device_id or "").strip()
    if not key:
        return ""
    with _SESSION_IDS_LOCK:
        if key not in _SESSION_IDS:
            if len(_SESSION_IDS) >= 4096:
                _SESSION_IDS.pop(next(iter(_SESSION_IDS)))
            _SESSION_IDS[key] = str(uuid.uuid4())
        return _SESSION_IDS[key]


def common_headers(
    *,
    country: str,
    device_id: str,
    referer: str,
    route: str = "",
    fingerprint: Optional[dict] = None,
) -> dict[str, str]:
    fp = fingerprint if isinstance(fingerprint, dict) else {}
    locale = profile(country)["browser_language"]
    browser_language = str(fp.get("oai_language") or locale)
    language = browser_language.split("-", 1)[0]
    headers = {
        "Accept": "application/json",
        "Accept-Language": str(
            fp.get("accept_language")
            or f"{browser_language},{language};q=0.9,en;q=0.8"
        ),
        "Origin": "https://chatgpt.com",
        "Referer": referer,
        "User-Agent": str(fp.get("ua") or _CHROME_UA),
        "OAI-Language": browser_language,
        "oai-client-version": _CHATGPT_CLIENT_VERSION,
        "oai-client-build-number": _CHATGPT_CLIENT_BUILD_NUMBER,
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
    }
    sec_ch_ua = str(fp.get("sec_ch_ua") or _SEC_CH_UA).strip()
    if sec_ch_ua:
        headers.update(
            {
                "sec-ch-ua": sec_ch_ua,
                "sec-ch-ua-full-version-list": str(
                    fp.get("sec_ch_ua_full") or _SEC_CH_UA_FULL
                ),
                "sec-ch-ua-mobile": str(fp.get("sec_ch_ua_mobile") or "?0"),
                "sec-ch-ua-platform": str(fp.get("sec_ch_ua_platform") or '"Windows"'),
            }
        )
    if device_id:
        headers["oai-device-id"] = device_id
        headers["oai-session-id"] = (
            str(fp.get("oai_session_id") or "").strip()
            or _session_id_for_device(device_id)
        )
    if route:
        headers["x-openai-target-path"] = route
        headers["x-openai-target-route"] = route
    return headers


def warmup_chatgpt_page(
    session,
    *,
    country: str,
    device_id: str,
    timeout: float = 30,
    fingerprint: Optional[dict] = None,
) -> None:
    """预热同一会话的网页 Cookie；失败不会中断检测。

    ⛔ 2026-09-24 流量优化：原来这里 GET 首页，**一次 ~900 KiB**。
       查优惠整条流程 957 KiB 里这一下就占 903（日志原文：
       「请求 7 次，下载 926.0 KiB（chatgpt.com 903.0 KiB）」）。

       而它的作用只是"预热会话 cookie"（__cf_bm / _cfuvid / cf_clearance），
       而且失败还被吞掉（except: pass）—— 说明它**不是关键路径**。

       /api/auth/csrf 同样会下发那一套 CF cookie（注册流程实测拿到
       __cf_bm / __cfuvid / oai-did / __Host-next-auth.csrf-token），
       体积 4.6 KiB。**省 ~900 KiB/号**，而查优惠必须走动态 IP，这是最值的一刀。

       想退回首页：TURB_WARMUP_LIGHT=0
    """
    # ✅ 2026-09-24 已 A/B 验证，**默认开**。
    #
    #    之前不敢默认开，是因为切成轻量预热后查优惠报 VN:error —— 但当时那条住宅
    #    出口本身就被 CF 拦（11950 打 chatgpt.com 返 403），分不清是谁的锅。
    #    后来换了干净的住宅出口（11092）重做 A/B，同一个号、同一条出口：
    #        首页预热   chatgpt.com 919.4 KiB，promo=yes amount=0
    #        csrf 预热  chatgpt.com 461.4 KiB，promo=yes amount=0
    #    **省 458 KiB/号，结果一字不差。** 出口干净的前提下轻量预热无损。
    #
    #    想退回首页：TURB_WARMUP_LIGHT=0
    _light = str(os.environ.get("TURB_WARMUP_LIGHT", "1")).strip().lower() not in ("0", "false", "no")
    _url = "https://chatgpt.com/api/auth/csrf" if _light else "https://chatgpt.com/"
    try:
        session.get(
            _url,
            headers={
                "Accept": "application/json" if _light else "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "upgrade-insecure-requests": "1",
                **common_headers(
                    country=country,
                    device_id=device_id,
                    referer="https://chatgpt.com/",
                    fingerprint=fingerprint,
                ),
                "sec-fetch-dest": "document",
                "sec-fetch-mode": "navigate",
                "sec-fetch-site": "same-origin",
            },
            timeout=timeout,
        )
    except Exception:
        pass


def fetch_checkout_state(
    proxy: str,
    access_token: str,
    session_token: str,
    session_id: str,
    processor_entity: str,
    *,
    country: str,
    device_id: str,
    fingerprint: Optional[dict] = None,
) -> dict[str, Any]:
    """读取 OAICS 会话状态，不提交支付或确认请求。"""
    if not str(session_id or "").startswith("oaics_"):
        raise ValueError("非 OAICS 结账会话")
    checkout_url = f"https://chatgpt.com/checkout/{processor_entity}/{session_id}"
    route = f"/backend-api/payments/checkout/{processor_entity}/{session_id}"
    session = chatgpt_session(
        proxy,
        access_token,
        session_token,
        device_id=device_id,
        fingerprint=fingerprint,
    )
    try:
        response = request(
            session,
            "GET",
            f"{OPENAI_CHECKOUT_URL}/{processor_entity}/{session_id}",
            headers=common_headers(
                country=country,
                device_id=device_id,
                referer=checkout_url,
                route=route,
                fingerprint=fingerprint,
            ),
            timeout=45,
        )
        if response.status_code == 401:
            raise RuntimeError("读取 OAICS 结账状态失败：HTTP 401")
        if response.status_code != 200:
            raise RuntimeError(
                f"读取 OAICS 结账状态失败：HTTP {response.status_code}: "
                f"{(response.text or '')[:300]}"
            )
        data = response.json() if response.text else {}
        return data if isinstance(data, dict) else {"raw": (response.text or "")[:400]}
    finally:
        session.close()


def _walk_dicts(value: Any):
    if isinstance(value, dict):
        yield value
        for nested in value.values():
            yield from _walk_dicts(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk_dicts(nested)


def payment_method_types(payload: Any) -> list[str]:
    methods: list[str] = []
    seen: set[str] = set()
    for item in _walk_dicts(payload):
        candidates = item.get("payment_method_types")
        if candidates is None:
            candidates = item.get("paymentMethodTypes")
        if not isinstance(candidates, list):
            continue
        for candidate in candidates:
            if isinstance(candidate, dict):
                candidate = candidate.get("type")
            method = str(candidate or "").strip().lower()
            if method and method not in seen:
                seen.add(method)
                methods.append(method)
    return methods


def custom_payment_methods(payload: Any) -> list[dict[str, Any]]:
    methods: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in _walk_dicts(payload):
        candidates = item.get("custom_payment_methods")
        if candidates is None:
            candidates = item.get("customPaymentMethods")
        if not isinstance(candidates, list):
            continue
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            method_id = str(candidate.get("id") or "").strip()
            if method_id.startswith("cpmt_") and method_id not in seen:
                seen.add(method_id)
                methods.append(candidate)
    return methods


def _nested_value(payload: Any, path: tuple[str, ...]) -> Any:
    current = payload
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _minor_amount(value: Any) -> int | None:
    if isinstance(value, dict):
        for key in ("minorUnitsAmount", "minor_units_amount", "amount"):
            if value.get(key) is not None:
                return _minor_amount(value[key])
        return None
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip()
    if not re.fullmatch(r"[+-]?\d+(?:\.0+)?", text):
        return None
    return int(text.split(".", 1)[0])


def _candidate_dicts(payload: Any) -> list[dict]:
    """按 _WRAPPER_KEYS 展开出所有可能承载结账信息的字典（外层在前）。"""
    out: list[dict] = []
    visited: set[int] = set()

    def visit(value: Any) -> None:
        if not isinstance(value, dict) or id(value) in visited:
            return
        visited.add(id(value))
        out.append(value)
        for key in _WRAPPER_KEYS:
            nested = value.get(key)
            if isinstance(nested, dict):
                visit(nested)

    visit(payload)
    return out


def payable_amount(payload: Any) -> tuple[str, int] | None:
    """返回 (字段路径, 实付金额)，取第一个命中的权威字段。"""
    for node in _candidate_dicts(payload):
        for path in _PAYABLE_PATHS:
            amount = _minor_amount(_nested_value(node, path))
            if amount is not None:
                return ".".join(path), amount
    return None


def discount_breakdown(payload: Any) -> tuple[int | None, int | None, int | None]:
    """返回 (subtotal, discount, total)，用于判断是否被全额抵扣。"""
    subtotal = discount = total = None
    for node in _candidate_dicts(payload):
        block = node.get("total") if isinstance(node.get("total"), dict) else None
        if not isinstance(block, dict):
            continue
        if subtotal is None:
            subtotal = _minor_amount(block.get("subtotal"))
        if discount is None:
            discount = _minor_amount(block.get("discount"))
        if total is None:
            total = _minor_amount(block.get("total"))
    return subtotal, discount, total


def amount_observations(payload: Any) -> list[tuple[str, int]]:
    observations: list[tuple[str, int]] = []
    visited: set[int] = set()

    def visit(value: Any, prefix: str = "") -> None:
        if not isinstance(value, dict) or id(value) in visited:
            return
        visited.add(id(value))
        for path in _AMOUNT_PATHS:
            amount = _minor_amount(_nested_value(value, path))
            if amount is not None:
                observations.append((f"{prefix}{'.'.join(path)}", amount))
        for key in _WRAPPER_KEYS:
            nested = value.get(key)
            if isinstance(nested, dict):
                visit(nested, f"{prefix}{key}.")

    visit(payload)
    return list(dict.fromkeys(observations))
