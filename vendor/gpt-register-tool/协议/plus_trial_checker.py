"""Read-only ChatGPT Plus trial eligibility checker.

The checker follows the two official endpoints used by the referenced project:
the coupon endpoint is the primary source for the one-month trial decision and
the accounts endpoint enriches the result with plan and redemption details.
It never redeems a coupon or changes account state.
"""
from __future__ import annotations

import json
import logging
import time
from collections.abc import Mapping
from typing import Any

from http_client import create_http_session

logger = logging.getLogger("plus_trial_checker")

COUPON_URL = (
    "https://chatgpt.com/backend-api/promo_campaign/check_coupon"
    "?coupon=plus-1-month-free&is_coupon_from_query_param=true"
)
ACCOUNTS_URL = "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27"

_DEACTIVATED_MARKERS = (
    "account_deactivated",
    "accountdeactivated",
    "deactivated",
    "has been deactivated",
    "disabled",
    "suspended",
    "banned",
    "violat",
    "potential abuse",
    "terminated",
)


def _body_text(response: Any) -> str:
    try:
        return str(response.text or "").strip()
    except Exception:  # noqa: BLE001
        return ""


def _looks_deactivated(body: str) -> bool:
    lowered = (body or "").lower()
    return any(marker in lowered for marker in _DEACTIVATED_MARKERS)


def _json_body(response: Any) -> dict[str, Any] | None:
    try:
        value = response.json()
    except Exception:  # noqa: BLE001
        try:
            value = json.loads(_body_text(response))
        except Exception:  # noqa: BLE001
            return None
    return value if isinstance(value, dict) else None


def _profile_headers(
    access_token: str,
    fingerprint: Mapping[str, Any] | None,
    *,
    account_id: str = "",
    device_id: str = "",
) -> dict[str, str]:
    fp = fingerprint or {}
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Origin": "https://chatgpt.com",
        "Referer": "https://chatgpt.com/",
        "User-Agent": str(
            fp.get("user_agent")
            or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
        ),
        "Accept-Language": str(fp.get("lang_full") or "en-US,en;q=0.9"),
        "oai-language": str(fp.get("lang") or fp.get("locale") or "en-US"),
    }
    if account_id:
        headers["ChatGPT-Account-ID"] = account_id
    if device_id:
        headers["Oai-Device-Id"] = device_id

    # Chromium Client Hints are only added when the frozen profile contains
    # them. Firefox and Safari profiles deliberately leave these fields empty.
    if fp.get("sec_ch_ua"):
        headers["sec-ch-ua"] = str(fp["sec_ch_ua"])
        headers["sec-ch-ua-mobile"] = str(fp.get("sec_ch_ua_mobile") or "?0")
        headers["sec-ch-ua-platform"] = str(fp.get("sec_ch_ua_platform") or '"Windows"')
        for key, header in (
            ("sec_ch_ua_full_version_list", "sec-ch-ua-full-version-list"),
            ("sec_ch_ua_arch", "sec-ch-ua-arch"),
            ("sec_ch_ua_bitness", "sec-ch-ua-bitness"),
            ("sec_ch_ua_model", "sec-ch-ua-model"),
            ("sec_ch_ua_platform_version", "sec-ch-ua-platform-version"),
        ):
            if fp.get(key):
                headers[header] = str(fp[key])
    return headers


def _account_snapshot(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    accounts = payload.get("accounts") if isinstance(payload, Mapping) else None
    if not isinstance(accounts, Mapping) or not accounts:
        return {}
    first = next(iter(accounts.values()), {})
    if not isinstance(first, Mapping):
        return {}
    account = first.get("account")
    entitlement = first.get("entitlement")
    campaigns = first.get("eligible_promo_campaigns")
    return {
        "account": account if isinstance(account, Mapping) else {},
        "entitlement": entitlement if isinstance(entitlement, Mapping) else {},
        "eligible_promo_campaigns": campaigns if isinstance(campaigns, Mapping) else {},
    }


def _http_failure(status_code: int, body: str) -> tuple[str, str]:
    if status_code in (401, 403):
        if _looks_deactivated(body):
            return "banned", "封号"
        if status_code == 401:
            return "token_invalid", "凭证失效"
    return "error", f"HTTP {status_code}"


def check_plus_trial(
    access_token: str,
    *,
    proxy: str | None = None,
    fingerprint: Mapping[str, Any] | None = None,
    account_id: str = "",
    device_id: str = "",
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Return a read-only trial and account status for one access token."""
    token = str(access_token or "").strip()
    if not token:
        return {"status": "no_at", "label": "无 access_token"}

    fp = fingerprint or {}
    impersonate = str(fp.get("impersonate") or "chrome")
    timeout = max(3.0, min(float(timeout or 15.0), 60.0))
    session = None
    responses: dict[str, Any] = {}
    failures: dict[str, str] = {}

    try:
        session = create_http_session(
            proxy=(proxy or "").strip() or None,
            impersonate=impersonate,
            user_agent=str(fp.get("user_agent") or "") or None,
        )
        headers = _profile_headers(
            token,
            fp,
            account_id=account_id,
            device_id=device_id,
        )
        for name, url in (("coupon", COUPON_URL), ("accounts", ACCOUNTS_URL)):
            try:
                responses[name] = session.get(url, headers=headers, timeout=timeout)
            except Exception as exc:  # noqa: BLE001
                failures[name] = str(exc)[:240]
    finally:
        if session is not None:
            try:
                session.close()
            except Exception:  # noqa: BLE001
                pass

    coupon_response = responses.get("coupon")
    accounts_response = responses.get("accounts")
    coupon_payload = _json_body(coupon_response) if coupon_response is not None else None
    accounts_payload = _json_body(accounts_response) if accounts_response is not None else None

    coupon_status = int(getattr(coupon_response, "status_code", 0) or 0)
    accounts_status = int(getattr(accounts_response, "status_code", 0) or 0)
    coupon_body = _body_text(coupon_response) if coupon_response is not None else ""
    accounts_body = _body_text(accounts_response) if accounts_response is not None else ""

    # A token error from either official endpoint is conclusive when no other
    # endpoint produced a usable account response.
    if coupon_status in (401, 403) and accounts_status not in (200,):
        status, label = _http_failure(coupon_status, coupon_body)
        return {
            "status": status,
            "label": label,
            "checked_at": time.time(),
            "coupon_http_status": coupon_status,
            "accounts_http_status": accounts_status,
            "error": coupon_body[:240],
        }
    if accounts_status in (401, 403) and coupon_status not in (200,):
        status, label = _http_failure(accounts_status, accounts_body)
        return {
            "status": status,
            "label": label,
            "checked_at": time.time(),
            "coupon_http_status": coupon_status,
            "accounts_http_status": accounts_status,
            "error": accounts_body[:240],
        }

    if coupon_status not in (0, 200) and accounts_status not in (200,):
        status, label = _http_failure(coupon_status, coupon_body)
        return {
            "status": status,
            "label": label,
            "checked_at": time.time(),
            "coupon_http_status": coupon_status,
            "accounts_http_status": accounts_status,
            "error": failures.get("coupon") or coupon_body[:240],
        }
    if coupon_status == 0 and accounts_status != 200:
        return {
            "status": "error",
            "label": "网络失败",
            "checked_at": time.time(),
            "coupon_http_status": coupon_status,
            "accounts_http_status": accounts_status,
            "error": failures.get("coupon") or failures.get("accounts") or "请求失败",
        }

    snapshot = _account_snapshot(accounts_payload)
    account = snapshot.get("account") or {}
    entitlement = snapshot.get("entitlement") or {}
    campaigns = snapshot.get("eligible_promo_campaigns") or {}

    redemption = coupon_payload.get("redemption") if isinstance(coupon_payload, Mapping) else {}
    redemption = redemption if isinstance(redemption, Mapping) else {}
    coupon_state = str(
        (coupon_payload or {}).get("state")
        or (coupon_payload or {}).get("status")
        or ""
    ).strip().lower()
    trial_redeemed = bool(redemption.get("redeemed"))
    trial_eligible = coupon_state == "eligible"

    campaign = campaigns.get("plus") if isinstance(campaigns, Mapping) else None
    if isinstance(campaign, Mapping) and campaign.get("id") == "plus-1-month-free":
        trial_eligible = True

    plan_type = str(account.get("plan_type") or "").strip().lower()
    has_active_subscription = bool(entitlement.get("has_active_subscription"))
    deactivated = bool(account.get("is_deactivated"))

    if deactivated:
        status, label = "banned", "封号"
    elif trial_eligible:
        status, label = "plus_eligible", "可领Plus试用"
    elif trial_redeemed or plan_type == "plus" or has_active_subscription:
        status = "plus_active"
        label = "Plus试用已兑换" if trial_redeemed and plan_type != "plus" and not has_active_subscription else "Plus生效中"
    elif snapshot or coupon_status == 200:
        status, label = "free", "Free"
    else:
        status, label = "error", "响应无法解析"

    result: dict[str, Any] = {
        "status": status,
        "label": label,
        "trial_eligible": trial_eligible,
        "trial_redeemed": trial_redeemed,
        "plan_type": plan_type or "free",
        "has_active_subscription": has_active_subscription,
        "checked_at": time.time(),
        "coupon_http_status": coupon_status,
        "accounts_http_status": accounts_status,
    }
    for source_key, result_key in (
        ("user_redeemed_at", "redeemed_at"),
        ("redeemed_at", "redeemed_at"),
        ("workspace_redeemed_at", "redeemed_at"),
        ("expires_at", "expires_at"),
    ):
        if redemption.get(source_key) and result_key not in result:
            result[result_key] = redemption[source_key]
    if failures:
        result["warnings"] = failures
    return result
