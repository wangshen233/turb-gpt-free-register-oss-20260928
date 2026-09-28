# -*- coding: utf-8 -*-
"""把 djblook 优惠检测接到本项目账号/套餐流程。"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime
from typing import Any

from core import api_traffic
from core.chatgpt_plan import resolve_plan_check_route
from core.promo_detector import oaics
from core.promo_detector.billing import billing_currency
from core.promo_detector.http import chatgpt_session, make_session, request as _req
from core.promo_detector.risk import checkout_risk_headers

logger = logging.getLogger(__name__)
os.environ.setdefault("PYTHON_BIN", sys.executable)

# 账单国 -> 币种的可信来源是 core/promo_detector/billing.py，这里只是把它出现过
# 的币种并进来做参考集合（判断币种合不合法看的是「3 位字母」，不再拿这张表卡）。
CHECKOUT_CURRENCIES = {
    "USD", "AUD", "CAD", "GBP", "EUR", "CLP", "JPY", "INR", "IDR", "PKR",
    "THB", "MYR", "TWD", "VND", "PHP", "NGN", "ZAR",
}
LABELS = {
    "card": "银行卡", "paypal": "PayPal", "link": "Link", "upi": "UPI",
    "pix": "PIX", "momo": "MoMo", "gopay": "GoPay", "grabpay": "GrabPay",
    "gcash": "GCash", "ideal": "iDEAL", "blik": "BLIK", "twint": "TWINT",
    "kakao": "Kakao Pay", "naver_pay": "Naver Pay", "bizum": "Bizum",
    "cashapp": "Cash App", "amazon_pay": "Amazon Pay",
}
# 出口地理探测失败时的兜底国家。必须和实际代理出口一致：用错国家结账会被
# OpenAI 直接拒掉（400 Billing country must match request country），
# 所以当代理池出口是越南时这里就写 VN。
DEFAULT_COUNTRIES = ("VN",)
_GEO_ENDPOINTS = (
    "https://ipinfo.io/json",
    "https://ipapi.co/json",
    "https://ipwho.is/",
)


def detect_proxy_country(proxy: str | None, timeout: float = 6.0) -> str:
    """通过当前优惠检测代理探测出口国家；失败返回空串。"""
    selected = str(proxy or "").strip()
    session = make_session(selected)
    try:
        headers = {"User-Agent": session.headers.get("User-Agent") or "Mozilla/5.0", "Accept": "application/json"}
        for url in _GEO_ENDPOINTS:
            try:
                resp = _req(session, "GET", url, headers=headers, timeout=timeout)
                if int(getattr(resp, "status_code", 0) or 0) != 200:
                    continue
                data = resp.json()
                if not isinstance(data, dict):
                    continue
                raw_cc = str(data.get("country_code") or data.get("countryCode") or "").strip().upper()
                raw_country = str(data.get("country") or "").strip().upper()
                if len(raw_cc) == 2 and raw_cc.isalpha():
                    country = raw_cc
                elif len(raw_country) == 2 and raw_country.isalpha():
                    country = raw_country
                else:
                    country = {"VIET NAM": "VN", "VIETNAM": "VN"}.get(raw_country, "")
                if len(country) == 2 and country.isalpha():
                    logger.info("[Promo] 代理出口国家: %s proxy=%s", country, selected or "direct")
                    return country
            except Exception as exc:
                logger.debug("[Promo] 出口国家探测失败 endpoint=%s: %s: %s", url, type(exc).__name__, exc)
                continue
    finally:
        try:
            session.close()
        except Exception:
            pass
    return ""


def checkout_currency(country: str) -> str:
    """账单币种 = billing_currency(国家)，**不再用白名单兜底成 USD**。

    服务端会校验「账单国 ↔ 币种」一致，不一致直接 400
    `invalid billing details provided`。下面这张 CHECKOUT_CURRENCIES 曾经漏了
    PLN/BRL/SEK/NOK/DKK/CHF/CZK/HUF/RON/TRY/ILS/AED/SAR/KRW/SGD/HKD/NZD/MXN，
    结果是这些国家的币种被兜底成 USD → 建单必失败（2026-09-18 波兰 PL 实测全挂）。
    币种本来就该由账单国唯一决定，所以以 billing 表为准。
    """
    value = str(billing_currency(country) or "").strip().upper()
    return value if len(value) == 3 and value.isalpha() else "USD"


def country_fingerprint(at: str, country: str) -> dict[str, str]:
    cc = (country or "US").upper()
    profile = oaics.profile(cc)
    digest = hashlib.sha256((str(at or "") + "|" + cc).encode("utf-8")).hexdigest()
    versions = ("146", "136", "131", "124")
    version = versions[int(digest[:2], 16) % len(versions)]
    device_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "promo-detect-device|" + digest))
    session_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "promo-detect-session|" + digest))
    locale = str(profile.get("browser_locale") or "en-US")
    language = str(profile.get("browser_language") or locale)
    return {
        "country": cc,
        "device_id": device_id,
        "oai_session_id": session_id,
        "locale": locale,
        "timezone": str(profile.get("browser_timezone") or "America/New_York"),
        "oai_language": language,
        "accept_language": f"{language},{language.split('-')[0]};q=0.9,en;q=0.8",
        "impersonate": "chrome" + version,
        "ua": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36"
        ),
        "sec_ch_ua": f'"Google Chrome";v="{version}", "Not.A/Brand";v="8", "Chromium";v="{version}"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"Windows"',
        "hardware_concurrency": "16",
        "screen": "1920x1080",
        "platform": "Win32",
        "platform_os": "Windows",
    }


def _oaics_method_names(payload: Any) -> list[str]:
    found = list(oaics.payment_method_types(payload))
    known = tuple(LABELS)
    for item in oaics.custom_payment_methods(payload):
        text = json.dumps(item, ensure_ascii=True).lower()
        custom_id = str(item.get("id") or "").lower()
        if custom_id == "cpmt_1togstc6h1nxgoi3wuvey2cj":
            name = "gcash"
        else:
            name = next((method for method in known if method in text), "")
        if not name:
            name = str(item.get("type") or item.get("payment_method_type") or item.get("id") or "").lower()
        if name and name not in found:
            found.append(name)
    return found


# 账号在 accounts/check 里拿到的活动 id 才是它真正能吃到的优惠。写死
# "plus-1-month-free" 只对拿到 1 个月免费额度的账号有效；拿到
# "plus-2-months-50-pct-off" 这类账号会被误判成"没有优惠"。
DEFAULT_CAMPAIGN_ID = "plus-1-month-free"


# 查优惠接口（checkout_pricing_config / payments/checkout）也会被 Cloudflare 挑战：
# 实测同一条桥上有的出口直接 200、有的返回 cf-mitigated=challenge。
# 挑战页不是"这个号没有优惠"的业务结论，换出口重来。
_PROMO_CF_ROTATIONS = 12
_PROMO_CF_ROTATE_SLEEP = 0.6


def _promo_is_cf_challenge(item: dict[str, Any]) -> bool:
    """查优惠结果是不是 Cloudflare 挑战页（而不是业务结论）。"""
    if not isinstance(item, dict) or int(item.get("status") or 0) != 403:
        return False
    text = str(item.get("error") or "").lower()
    return "<html" in text or "cloudflare" in text or "just a moment" in text


def _rotate_promo_proxy(proxy: str, slot: int) -> str:
    """同一座本地桥换个会话用户名＝换一条上游出口。"""
    try:
        from core.session import _with_bridge_session_key

        return _with_bridge_session_key(proxy, "promo-check", int(slot))
    except Exception:
        return proxy


def _checkout_one(
    access_token: str,
    proxy: str,
    country: str,
    timeout: int = 20,
    requested_currency: str = "",
    campaign_id: str = "",
    entry_point: str = "all_plans_pricing_modal",
    checkout_ui_mode: str = "custom",
    include_internal: bool = False,
) -> dict[str, Any]:
    cc = (country or "US").upper()
    campaign = str(campaign_id or "").strip() or DEFAULT_CAMPAIGN_ID
    currency = (requested_currency or checkout_currency(cc)).upper()
    if len(currency) != 3 or not currency.isalpha():
        currency = "USD"
    fp = country_fingerprint(access_token, cc)
    device_id = fp["device_id"]
    session = chatgpt_session(proxy, access_token, "", device_id=device_id, fingerprint=fp)
    try:
        pricing_path = f"/backend-api/checkout_pricing_config/configs/{cc}"
        pricing_headers = {
            **oaics.common_headers(country=cc, device_id=device_id, referer="https://chatgpt.com/", route=pricing_path, fingerprint=fp),
            "Authorization": f"Bearer {access_token}",
        }
        pricing = _req(session, "GET", "https://chatgpt.com" + pricing_path, headers=pricing_headers, timeout=timeout)
        if pricing.status_code >= 400:
            return {
                "ok": False, "country": cc, "currency": currency, "status": pricing.status_code,
                "methods": [], "promo": "error",
                "error": f"定价配置 HTTP {pricing.status_code}: {(pricing.text or '')[:180]}",
            }
        oaics.warmup_chatgpt_page(session, country=cc, device_id=device_id, timeout=timeout, fingerprint=fp)
        cookie_header = f"oai-did={device_id}"
        sentinel = checkout_risk_headers(
            session.get, proxy, device_id, fp["oai_session_id"], fp,
            campaign, cookie_header, timeout,
            lambda stage, status, message: logger.debug("[Promo] %s %s %s", stage, status, message),
        )
        path = "/backend-api/payments/checkout"
        payload = {
            # entry_point 会改变服务端选的结账通道（OAICS 本地支付方式 vs Stripe），
            # 所以它不只是埋点字段，可用于排查/对齐 MoMo 等本地方式。
            "entry_point": entry_point or "all_plans_pricing_modal",
            "plan_name": "chatgptplusplan",
            "billing_details": {"country": cc, "currency": currency},
            "checkout_ui_mode": checkout_ui_mode or "custom",
            "promo_campaign": {"promo_campaign_id": campaign, "is_coupon_from_query_param": False},
        }
        headers = {
            **oaics.common_headers(
                country=cc, device_id=device_id,
                referer=f"https://chatgpt.com/?promo_campaign={campaign}",
                route=path, fingerprint=fp,
            ),
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }
        headers.update(sentinel)
        raw_token = sentinel.get("openai-sentinel-token") if isinstance(sentinel, dict) else None
        if raw_token:
            try:
                parsed = json.loads(raw_token)
                # 兜底：上游若仍带内部 _so 键就剥掉（浏览器 token 头只有 5 键）。
                # so-token 头由 risk.checkout_risk_headers 单独产出，不在这里重算。
                if isinstance(parsed, dict) and parsed.pop("_so", None) is not None:
                    headers["openai-sentinel-token"] = json.dumps(parsed, separators=(",", ":"), ensure_ascii=False)
            except Exception:
                pass
        response = _req(session, "POST", "https://chatgpt.com" + path, json=payload, headers=headers, timeout=timeout)
        try:
            data = response.json()
        except Exception:
            data = {}
        if response.status_code >= 400:
            return {
                "ok": False, "country": cc, "currency": currency, "status": response.status_code,
                "methods": [], "promo": "error",
                "error": f"checkout HTTP {response.status_code}: {str(data)[:220]}",
            }
        cs = data.get("checkout_session_id") or data.get("id")
        pk = data.get("publishable_key")
        if not cs:
            return {"ok": False, "country": cc, "currency": currency, "status": response.status_code, "methods": [], "promo": "error", "error": "checkout 未返回 session id"}
        if str(cs).startswith("oaics_"):
            state = data
            if not _oaics_method_names(state):
                try:
                    entity = str(data.get("processor_entity") or ("openai_llc" if cc == "US" else "openai_ie"))
                    state = oaics.fetch_checkout_state(proxy, access_token, "", str(cs), entity, country=cc, device_id=device_id, fingerprint=fp)
                except Exception:
                    state = data
            methods = _oaics_method_names(state)
            observations = oaics.amount_observations(state)
            payable = oaics.payable_amount(state)
            subtotal, discount, declared_total = oaics.discount_breakdown(state)
            amount = payable[1] if payable else None
            fully_discounted = bool(
                subtotal and discount and discount >= subtotal and (declared_total or 0) == 0
            )
            zero_ok = (amount == 0) or (amount is None and fully_discounted)
            if zero_ok:
                error = ""
            elif amount is None:
                error = f"OAICS 未返回可核验的订单金额；观测={observations[:8]}"
            else:
                error = (
                    f"优惠后金额不是 0: {amount}"
                    f"（subtotal={subtotal} discount={discount} path={payable[0] if payable else '-'}）"
                )
            labels = [LABELS.get(m, m) for m in methods]
            discounted = bool(amount is not None and subtotal and amount < subtotal)
            percent = int(round((1 - amount / subtotal) * 100)) if discounted else 0
            return {
                "ok": zero_ok and bool(methods),
                "country": cc, "currency": currency, "status": response.status_code,
                "session_type": "oaics", "amount": amount, "methods": methods,
                "methods_all": methods,
                "subtotal": subtotal, "discount": discount,
                "discount_percent": percent,
                "promo": "yes" if zero_ok else ("partial" if discounted else "no"),
                "campaign_id": campaign, "error": error,
                "method_labels": labels,
            }
        if not pk:
            return {"ok": False, "country": cc, "currency": currency, "status": response.status_code, "methods": [], "promo": "error", "error": "checkout 未返回 publishable key"}
        body = {
            "browser_locale": fp["locale"], "browser_timezone": fp["timezone"],
            "elements_session_client[client_betas][0]": "custom_checkout_server_updates_1",
            "elements_session_client[client_betas][1]": "custom_checkout_manual_approval_1",
            "elements_session_client[elements_init_source]": "custom_checkout",
            "elements_session_client[referrer_host]": "chatgpt.com",
            "elements_session_client[stripe_js_id]": str(uuid.uuid4()),
            "elements_session_client[locale]": fp["locale"].split("-")[0],
            "elements_options_client[saved_payment_method][enable_save]": "auto",
            "elements_options_client[saved_payment_method][enable_redisplay]": "auto",
            "key": pk,
            "_stripe_version": "2025-03-31.basil; checkout_server_update_beta=v1; checkout_manual_approval_preview=v1",
        }
        stripe = make_session(proxy, impersonate=fp["impersonate"], user_agent=fp["ua"], accept_language=fp["accept_language"])
        try:
            init = _req(
                stripe, "POST", f"https://api.stripe.com/v1/payment_pages/{cs}/init", data=body,
                headers={"Origin": "https://js.stripe.com", "Referer": "https://js.stripe.com/", "User-Agent": fp["ua"], "Accept-Language": fp["accept_language"], "Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
                timeout=timeout,
            )
            try:
                init_data = init.json()
            except Exception:
                init_data = {}
        finally:
            stripe.close()
        invoice = init_data.get("invoice") if isinstance(init_data, dict) else {}
        methods = init_data.get("payment_method_types") if isinstance(init_data, dict) else []
        methods0 = list(dict.fromkeys(str(x).lower() for x in methods)) if isinstance(methods, list) else []
        amount0 = invoice.get("amount_due") if isinstance(invoice, dict) else None
        if init.status_code >= 400:
            return {"ok": False, "country": cc, "currency": currency, "status": init.status_code, "amount": amount0, "methods": [], "promo": "error", "error": str(init_data)[:180]}
        zero_ok = amount0 == 0
        labels = [LABELS.get(m, m) for m in methods0]
        subtotal0 = invoice.get("subtotal") if isinstance(invoice, dict) else None
        discounted = bool(
            amount0 is not None and isinstance(subtotal0, (int, float)) and subtotal0 and amount0 < subtotal0
        )
        percent = int(round((1 - amount0 / subtotal0) * 100)) if discounted else 0
        return {
            "ok": zero_ok and bool(methods0), "country": cc, "currency": currency, "status": init.status_code,
            "session_type": "cs_live", "amount": amount0, "methods": methods0,
            "methods_all": methods0,
            "subtotal": subtotal0, "discount_percent": percent,
            "promo": "yes" if zero_ok else ("partial" if discounted else "no"),
            "campaign_id": campaign,
            "method_labels": labels,
            "error": "" if zero_ok else (
                f"优惠后金额不是 0: {amount0}（{percent}% off，活动 {campaign}）" if discounted
                else f"优惠后金额不是 0: {amount0}"
            ),
            **({"__checkout_response": data, "__stripe_init_response": init_data} if include_internal else {}),
        }
    finally:
        session.close()


def detect_account_promo(
    access_token: str,
    *,
    proxy: str | None = None,
    countries: list[str] | None = None,
    timeout: int = 20,
    campaign_id: str | None = None,
    # ★ 默认 5 次（原来 2 次）。服务端给不给优惠是**不稳定**的 ——
    #   同一个号、同一条出口连查三次实测拿到 error / 0元 / no 三种结果：
    #       try1 promo=error amount=None
    #       try2 promo=yes   amount=0        ← 真出优惠了
    #       try3 promo=no    amount=475000
    #   只试 2 次的话第 3 次那次 0 元根本轮不到，账号就被标成「没优惠」。
    #   每次重试的代价只有结账会话那几十 KiB（不含预热页），
    #   拿几十 KiB 换 20 个百分点的 0 元率，怎么算都值。
    #   环境变量 TURB_PROMO_ATTEMPTS 可覆盖。
    attempts: int = 5,
) -> dict[str, Any]:
    """对账号跑一组国家的 Plus 试用优惠检测。

    campaign_id 传账号在 accounts/check 里拿到的活动 id；不传则退回
    "plus-1-month-free"。账号拿到的是 2 个月 5 折这类活动时，用错 id
    会直接把"有优惠"检测成"没有优惠"。
    """
    token = str(access_token or "").strip()
    checked_at = datetime.now().isoformat(timespec="seconds")
    if not token:
        return {"ok": False, "error": "缺少 access_token", "checked_at": checked_at}
    try:
        route = resolve_plan_check_route(proxy)
        selected_proxy = str(route.get("proxy") or "")
    except Exception as exc:
        return {"ok": False, "error": f"优惠检测网络配置错误: {exc}", "checked_at": checked_at}
    selected: list[str] = []
    for item in (countries or []):
        cc = str(item or "").strip().upper()
        if cc and cc not in selected:
            selected.append(cc)
    if not selected:
        exit_cc = detect_proxy_country(selected_proxy)
        if exit_cc:
            selected = [exit_cc]
        else:
            selected = list(DEFAULT_COUNTRIES)
            logger.info("[Promo] 未能探测代理国家，回退默认 %s", ",".join(selected))
    api_traffic.install()   # 计数器的 reset 由作业编排方（plan_check_service）在做整套查询前调用，
                            # 这里只保证装好；否则会把「查套餐」那段流量从本次统计里抹掉
    results = []
    yes: list[str] = []
    campaign = str(campaign_id or "").strip()
    if campaign:
        logger.info("[Promo] 使用账号活动 id=%s", campaign)
    total_attempts = max(1, int(attempts or 1))
    _env_attempts = str(os.environ.get("TURB_PROMO_ATTEMPTS", "") or "").strip()
    if _env_attempts.isdigit() and int(_env_attempts) > 0:
        total_attempts = int(_env_attempts)
    for cc in selected:
        item: dict[str, Any] = {}
        cf_rotations = 0
        # ★ 业务性重试（没出优惠）也要换出口，用独立计数器 ——
        #   不能蹭 cf_rotations，那个被 _PROMO_CF_ROTATIONS 卡着额度。
        rotations = 0
        attempt = 0
        while attempt < total_attempts:
            attempt += 1
            _slot = cf_rotations + rotations
            attempt_proxy = _rotate_promo_proxy(selected_proxy, _slot) if _slot else selected_proxy
            try:
                item = _checkout_one(token, attempt_proxy, cc, timeout=timeout, campaign_id=campaign)
            except Exception as exc:
                item = {"ok": False, "country": cc, "promo": "error", "methods": [], "error": f"{type(exc).__name__}: {str(exc)[:160]}"}
            # Cloudflare 挑战不是业务结论：换出口重来，且不占 attempts 预算。
            if _promo_is_cf_challenge(item) and cf_rotations < _PROMO_CF_ROTATIONS:
                cf_rotations += 1
                attempt -= 1
                time.sleep(_PROMO_CF_ROTATE_SLEEP)
                logger.info(
                    "[Promo] %s 出口被 Cloudflare 挑战，换上游重试 (%s/%s)",
                    cc, cf_rotations, _PROMO_CF_ROTATIONS,
                )
                continue
            # 服务端是否给优惠是**不稳定**的：同一个账号、同一份请求，
            # 第一次 475000、第二次 0 元都出现过。没拿到优惠就重试，
            # 否则账号列表会把真正有试用的号标成"没有"。
            if item.get("promo") == "yes" or attempt >= total_attempts:
                break
            # ★ 必须**换出口**重试，不能原地重试。
            #   实测：同一个好号，拿 8 条出口查 check_coupon ——
            #       7 条返回 eligible，1 条（全池 100 条里有 10 条这种）返回 not_eligible。
            #   **同一个号、同一份请求，结论完全由出口决定。**
            #   原地重试 = 拿同一条脏出口再问一遍，只会拿到同样的 no。
            rotations += 1
            logger.debug("[Promo] %s 第 %s 次未出优惠，换出口重试", cc, attempt)
            time.sleep(_PROMO_CF_ROTATE_SLEEP)
        if isinstance(item, dict):
            item["attempts"] = attempt
        results.append(item)
        if item.get("promo") == "yes" and item.get("ok"):
            yes.append(cc)
        logger.info("[Promo] %s promo=%s amount=%s methods=%s err=%s", cc, item.get("promo"), item.get("amount"), ",".join(item.get("methods") or []) or "-", (item.get("error") or "")[:80])
    method_names = []
    method_labels = []
    for item in results:
        for name in item.get("methods") or item.get("methods_all") or []:
            if name and name not in method_names:
                method_names.append(name)
                method_labels.append(LABELS.get(name, name))
    parts = []
    # 结账单有两种：oaics_（OpenAI 自己的 OAICS 结账）和 cs_live_（Stripe）。
    # 最终「出链」就是这两种之一，取链方式完全不同，所以判定里必须带上它。
    session_types: list[str] = []
    for x in results:
        cc = x.get("country") or "?"
        stype = str(x.get("session_type") or "").strip()
        if stype and stype not in session_types:
            session_types.append(stype)
        promo_state = x.get("promo") or "error"
        if promo_state == "yes":
            status = "0元"
        elif promo_state == "partial":
            percent = int(x.get("discount_percent") or 0)
            status = f"{percent}%off" if percent else "部分优惠"
        else:
            status = promo_state
        names = x.get("method_labels") or [LABELS.get(m, m) for m in (x.get("methods") or x.get("methods_all") or [])]
        tag = f"[{stype}]" if stype else ""
        if names:
            parts.append(f"{cc}:{status}{tag}({','.join(names)})")
        else:
            parts.append(f"{cc}:{status}{tag}")
    summary = ";".join(parts)
    return {
        "ok": True,
        "checked_at": checked_at,
        "campaign_id": campaign or DEFAULT_CAMPAIGN_ID,
        "promo_ok": bool(yes),
        "promo_countries": yes,
        "promo_methods": method_names,
        "promo_method_labels": method_labels,
        # 结账单类型：oaics = OpenAI 自家结账，cs_live = Stripe。
        # promo_session_types 是这次出现的全部类型（去重、保序）；
        # promo_session_type 只有一个类型时给单值，混用时给逗号串，没拿到给空串。
        "promo_session_types": session_types,
        "promo_session_type": session_types[0] if len(session_types) == 1 else ",".join(session_types),
        "promo_summary": summary,
        "promo_results": results,
        "proxy_used": route.get("proxy_used"),
        "network_route": route.get("network_route"),
        "error": None if results else "未执行任何国家检测",
        # 检测流量（curl_cffi 层实测）：和注册那套浏览器口径分开，两个数加起来才是这个号的开销
        "api_traffic": api_traffic.stats(),
    }
