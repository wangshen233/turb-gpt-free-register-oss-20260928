# -*- coding: utf-8 -*-
"""ChatGPT 账号套餐/试用资格查询。"""
from __future__ import annotations

import base64
import ipaddress
import json
import logging
import socket
import time
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import quote, urlparse

from core.session import BrowserSession, is_cf_challenge_response

logger = logging.getLogger(__name__)

ACCOUNTS_CHECK_PATH = "/backend-api/accounts/check/v4-2023-04-27"


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def normalize_token(token: str) -> str:
    token = (token or "").strip().strip('"').strip("'")
    if token.lower().startswith("authorization:"):
        token = token.split(":", 1)[1].strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    return token


def _mask_proxy(proxy: str) -> str:
    """返回可用于日志/API 结果的代理摘要，不泄露用户名和密码。"""
    value = str(proxy or "").strip()
    if not value:
        return ""
    try:
        parsed = urlparse(value if "://" in value else f"//{value}")
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        scheme = f"{parsed.scheme}://" if parsed.scheme else ""
        auth = "***:***@" if parsed.username or parsed.password else ""
        return f"{scheme}{auth}{host}{port}" or "***"
    except Exception:
        return "***"


def _local_proxy_status(proxy: str) -> tuple[bool, bool, str | None]:
    """检查回环代理端口；非本地代理不做预探测，避免额外网络请求。"""
    value = str(proxy or "").strip()
    if not value:
        return False, False, None
    try:
        parsed = urlparse(value if "://" in value else f"//{value}")
        host = parsed.hostname or ""
        is_loopback = host.lower() == "localhost"
        if not is_loopback:
            try:
                is_loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                is_loopback = False
        if not is_loopback:
            return False, True, None
        if not parsed.port:
            return True, False, "本地代理未配置端口"
        try:
            with socket.create_connection((host, parsed.port), timeout=0.5):
                return True, True, None
        except OSError as exc:
            return True, False, f"本地代理 {host}:{parsed.port} 未监听（{type(exc).__name__}）"
    except Exception as exc:
        return False, False, f"代理地址解析失败（{type(exc).__name__}）"


# ── 查套餐出口打分 ──────────────────────────────────────────────────────
# ⛔ 2026-09-24 实测：**0 元率主要由「查套餐用的出口」决定**，不是由注册配置决定。
#    同一批号、同一时间，只换查套餐出口：
#
#        11090   56/56 = 100%
#        11950   30/36 =  83%
#        11097   26/35 =  74%
#        11103    2/19 =  11%     <- 同一个 /24 段里也能差 10 倍
#
#    而 2026-09-24 我把 PLAN_CHECK_PROXY 从固定端口改成"随机从 PROXY_POOL 取"，
#    结果 0 元率从 83% 掉到 67% —— **随机是错的方向**，得按历史战绩挑。
#
#    这里读一份打分台账（_probe/plan_exit_scores.json，由脚本从库里统计生成），
#    优先挑「历史 0 元率高、样本够」的出口。台账不存在就退回随机。
_PLAN_SCORE_FILE = _PROJECT_ROOT / "_probe" / "plan_exit_scores.json" if False else None


def _scored_plan_proxy() -> str:
    """按历史 0 元率挑查套餐出口；台账缺失就返回空串（调用方退回随机）。"""
    import json as _json
    from pathlib import Path as _P
    try:
        root = _P(__file__).resolve().parent.parent
        p = root / "_probe" / "plan_exit_scores.json"
        if not p.exists():
            return ""
        data = _json.loads(p.read_text(encoding="utf-8"))
        cands = [c for c in (data.get("ports") or []) if c.get("proxy") and c.get("n", 0) >= 3]
        # ⛔ 必须过滤掉**已经不在监听**的端口。台账里 11092/11093/11094 的历史战绩
        #    都是 100%，但那几条桥早就关了 —— 不过滤的话挑出来的全是死端口，
        #    然后被 _local_proxy_status 判成"未监听"、退回直连，等于没挑。
        # ⛔ 光看"端口在监听"不够：11091 端口在监听，但它的上游是死的，
        #    打过去全是 curl: (97) cannot complete SOCKS5 connection。
        #    所以再要求**这条代理必须属于当前 PROXY_POOL** —— 池子里的才是
        #    当下真的能用的出口（中继池每轮会重建）。
        try:
            from config import proxy as _pc
            _pool = set(_pc.normalize_proxy_pool(_pc.PROXY_POOL) or [])
        except Exception:
            _pool = set()
        live = []
        for c in cands:
            if _pool and c["proxy"] not in _pool:
                continue
            ok, _avail, _reason = _local_proxy_status(c["proxy"])
            if not ok or _avail:
                live.append(c)
        if not live:
            return ""
        # 先按 0 元率降序，再按样本量降序；取前 3 个里随机一个（避免所有 worker 挤同一个）
        live.sort(key=lambda c: (-(c.get("yes", 0) / max(1, c.get("n", 1))), -c.get("n", 0)))
        import random as _r
        return _r.choice(live[:3])["proxy"]
    except Exception:
        return ""


def resolve_plan_check_route(explicit_proxy: Optional[str] = None) -> dict:
    """解析套餐查询的实际网络路径。

    explicit_proxy 不是 None 时表示 API 调用方明确覆盖配置；空字符串代表直连。
    """
    if explicit_proxy is not None:
        selected = str(explicit_proxy or "").strip()
        return {
            "proxy": selected,
            "proxy_mode": "request",
            "network_route": "proxy" if selected else "direct",
            "proxy_used": _mask_proxy(selected) or None,
            "proxy_fallback_reason": None,
        }

    from config import proxy as proxy_cfg

    mode = str(getattr(proxy_cfg, "PLAN_CHECK_PROXY_MODE", "auto") or "auto").strip().lower()
    if mode not in {"auto", "proxy", "direct"}:
        raise ValueError(f"PLAN_CHECK_PROXY_MODE={mode!r} 无效，可选 auto / proxy / direct")
    if mode == "direct":
        return {
            "proxy": "",
            "proxy_mode": mode,
            "network_route": "direct",
            "proxy_used": None,
            "proxy_fallback_reason": None,
        }

    selected = str(getattr(proxy_cfg, "PLAN_CHECK_PROXY", "") or "").strip()
    if not selected:
        selected = _scored_plan_proxy() or str(proxy_cfg.pick_proxy() or "").strip()
    if not selected:
        if mode == "proxy":
            raise ValueError("套餐查询网络模式为 proxy，但未配置 PLAN_CHECK_PROXY 或 PROXY_POOL")
        return {
            "proxy": "",
            "proxy_mode": mode,
            "network_route": "direct",
            "proxy_used": None,
            "proxy_fallback_reason": "未配置套餐查询代理或代理池",
        }

    is_local, available, reason = _local_proxy_status(selected)
    if mode == "auto" and is_local and not available:
        return {
            "proxy": "",
            "proxy_mode": mode,
            "network_route": "direct_fallback",
            "proxy_used": _mask_proxy(selected),
            "proxy_fallback_reason": reason,
        }
    return {
        "proxy": selected,
        "proxy_mode": mode,
        "network_route": "proxy",
        "proxy_used": _mask_proxy(selected),
        "proxy_fallback_reason": None,
    }


def decode_jwt_payload_unverified(token: str) -> dict:
    """仅本地解析 JWT payload，不校验签名。"""
    token = normalize_token(token)
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except Exception:
        return {}


def token_claims(token: str) -> dict:
    payload = decode_jwt_payload_unverified(token)
    auth = payload.get("https://api.openai.com/auth") or {}
    profile = payload.get("https://api.openai.com/profile") or {}
    exp = payload.get("exp")
    exp_iso = None
    expired = None
    if isinstance(exp, (int, float)):
        exp_iso = datetime.fromtimestamp(exp, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        expired = datetime.now(tz=timezone.utc).timestamp() >= float(exp)
    return {
        "payload": payload,
        "email": profile.get("email"),
        "user_name": profile.get("name"),
        "user_id": auth.get("chatgpt_user_id") or auth.get("user_id"),
        "account_id": auth.get("chatgpt_account_id"),
        "claim_plan_type": auth.get("chatgpt_plan_type"),
        "exp": exp,
        "token_expires_at": exp_iso,
        "token_expired": expired,
    }


def _common_headers(env: BrowserSession, token: str) -> dict[str, str]:
    headers = env._get_common_headers()
    headers.update({
        "accept": "*/*",
        "authorization": f"Bearer {normalize_token(token)}",
        "oai-device-id": env.device_id,
        "oai-language": env.navigator_language(),
        "referer": "https://chatgpt.com/",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "x-openai-target-path": ACCOUNTS_CHECK_PATH,
        "x-openai-target-route": ACCOUNTS_CHECK_PATH,
    })
    return headers


def parse_accounts_check(data: dict, *, token: str = "") -> dict:
    """从 accounts/check 响应提取套餐和 Plus 试用资格。"""
    claims = token_claims(token) if token else {}
    claim_account_id = claims.get("account_id")
    accounts = data.get("accounts") if isinstance(data, dict) else None
    if not isinstance(accounts, dict):
        raise ValueError("响应缺少 accounts 对象")

    item = None
    account_key = None
    if claim_account_id and isinstance(accounts.get(claim_account_id), dict):
        item = accounts.get(claim_account_id)
        account_key = claim_account_id
    elif isinstance(accounts.get("default"), dict):
        item = accounts.get("default")
        account = item.get("account") or {}
        account_key = account.get("account_id") or "default"
    else:
        for k, v in accounts.items():
            if k != "default" and isinstance(v, dict):
                item = v
                account_key = k
                break
    if not isinstance(item, dict):
        raise ValueError("未找到可解析的账号条目")

    account = item.get("account") or {}
    entitlement = item.get("entitlement") or {}
    last_sub = item.get("last_active_subscription") or {}
    eligible_promo_campaigns = item.get("eligible_promo_campaigns") or {}
    plus_campaign = eligible_promo_campaigns.get("plus") if isinstance(eligible_promo_campaigns, dict) else None
    plus_meta = (plus_campaign or {}).get("metadata") or {}
    discount = plus_meta.get("discount") or {}
    duration = plus_meta.get("duration") or {}

    plan_type = account.get("plan_type") or claims.get("claim_plan_type") or ""
    subscription_plan = entitlement.get("subscription_plan") or ""
    has_active_subscription = bool(entitlement.get("has_active_subscription"))
    is_free = str(plan_type).lower() == "free" or str(subscription_plan).lower() == "chatgptfreeplan"
    plus_trial_eligible = bool(is_free and plus_campaign)

    offers = ((item.get("eligible_offers") or {}).get("offers") or [])
    eligible_offer_ids = [o.get("id") for o in offers if isinstance(o, dict) and o.get("id")]

    result = {
        "ok": True,
        "checked_at": now_iso(),
        "account_id": account.get("account_id") or account_key or claim_account_id,
        "account_user_role": account.get("account_user_role"),
        "current_plan_type": plan_type,
        "subscription_plan": subscription_plan,
        "has_active_subscription": has_active_subscription,
        "is_active_subscription_gratis": bool(entitlement.get("is_active_subscription_gratis")),
        "expires_at": entitlement.get("expires_at"),
        "renews_at": entitlement.get("renews_at"),
        "cancels_at": entitlement.get("cancels_at"),
        "billing_period": entitlement.get("billing_period"),
        "billing_currency": entitlement.get("billing_currency"),
        "is_delinquent": bool(entitlement.get("is_delinquent")),
        "discount_type": (entitlement.get("discount") or {}).get("discount_type"),
        "discount_amount": (entitlement.get("discount") or {}).get("amount"),
        "discount_duration_num_periods": (entitlement.get("discount") or {}).get("duration_num_periods"),
        "discount_expires_at": (entitlement.get("discount") or {}).get("discount_expires_at"),
        "discount_cancellation_policy": (entitlement.get("discount") or {}).get("cancellation_policy"),
        "discount_promo_campaign_id": (entitlement.get("discount") or {}).get("promo_campaign_id"),
        "last_purchase_origin_platform": last_sub.get("purchase_origin_platform"),
        "last_will_renew": bool(last_sub.get("will_renew")),
        "plus_trial_eligible": plus_trial_eligible,
        "plus_trial_campaign_id": (plus_campaign or {}).get("id"),
        "plus_trial_title": plus_meta.get("title"),
        "plus_trial_summary": plus_meta.get("summary"),
        "plus_trial_discount_percentage": discount.get("percentage"),
        "plus_trial_duration_num_periods": duration.get("num_periods"),
        "plus_trial_duration_period": duration.get("period"),
        "plus_trial_promotion_type_label": plus_meta.get("promotion_type_label"),
        "eligible_offer_ids": eligible_offer_ids,
        "features_count": len(item.get("features") or []),
        "can_access_with_session": bool(item.get("can_access_with_session")),
        "raw_account_plan_type": account.get("plan_type"),
    }
    result.update({k: v for k, v in claims.items() if k != "payload" and v is not None})
    return result


def _plan_check_settings(
    timeout: float | None,
    max_attempts: int | None,
    retry_delay: float | None,
) -> tuple[float, int, float]:
    from config import proxy as proxy_cfg

    timeout_value = timeout if timeout is not None else getattr(proxy_cfg, "PLAN_CHECK_TIMEOUT", 15.0)
    attempts_value = max_attempts if max_attempts is not None else getattr(proxy_cfg, "PLAN_CHECK_MAX_ATTEMPTS", 2)
    delay_value = retry_delay if retry_delay is not None else getattr(proxy_cfg, "PLAN_CHECK_RETRY_DELAY", 1.5)
    return (
        max(1.0, min(60.0, float(timeout_value or 15.0))),
        max(1, min(4, int(attempts_value or 1))),
        max(0.0, min(30.0, float(delay_value or 0.0))),
    )


def _retryable_plan_error(http_status: int | None) -> bool:
    if http_status is None:
        return True
    # 403 大多是 Cloudflare 挑战页而不是业务拒绝，值得重试。
    return http_status in {403, 408, 409, 425, 429} or http_status >= 500


def _retry_wait_seconds(resp: Any, base_delay: float, attempt: int) -> float:
    try:
        retry_after = (getattr(resp, "headers", {}) or {}).get("retry-after")
        if retry_after is not None:
            return max(0.0, min(30.0, float(retry_after)))
    except (TypeError, ValueError):
        pass
    return max(0.0, min(30.0, base_delay * attempt))


# 套餐查询被 Cloudflare 挑战时最多换几条上游出口。
# /backend-api/accounts/check 是 Cloudflare 重点保护接口：实测同一条桥上有的出口
# 直接 200、有的返回 cf-mitigated=challenge，换出口能避过去但需要多试几次。
# 4 次经常不够（连续 12 次全 403 的窗口也出现过），提到 12 次。
_PLAN_CF_ROTATIONS = 12

# 每次换出口之间稍等，给 Cloudflare 一点时间窗，连续猛打更容易被判为 bot。
_PLAN_CF_ROTATE_SLEEP = 0.6

# ★ 没查到 Plus 试用资格时，最多换几条出口重查。
#   实测（2026-09-24）：同一个 eligible 的号，换 8 条出口查 check_coupon ——
#   7 条返回 eligible、1 条返回 not_eligible。**同一个号、同一份请求，
#   结论完全由出口决定。** 池子 100 条里稳定有 10 条这种脏出口。
#   原来查到 200 就直接 return，等于让一条脏出口给账号判死刑。
_PLAN_ELIG_ROTATIONS = 6


def check_account_plan(
    token: str,
    *,
    proxy: Optional[str] = None,
    timezone_offset_min: str = "-",
    timeout: float | None = None,
    max_attempts: int | None = None,
    retry_delay: float | None = None,
) -> dict:
    token = normalize_token(token)
    if not token:
        return {"ok": False, "checked_at": now_iso(), "error": "token 为空"}
    claims = token_claims(token)
    if claims.get("token_expired") is True:
        return {
            "ok": False,
            "checked_at": now_iso(),
            "http_status": None,
            "error": "AT已过期/失效，请手动查活刷新",
            "needs_live_check": True,
            **{k: v for k, v in claims.items() if k != "payload"},
        }

    try:
        route = resolve_plan_check_route(proxy)
    except Exception as exc:
        return {
            "ok": False,
            "checked_at": now_iso(),
            "http_status": None,
            "error": f"套餐查询网络配置错误: {exc}",
            **{k: v for k, v in claims.items() if k != "payload"},
        }
    route_meta = {k: v for k, v in route.items() if k != "proxy"}
    url = f"https://chatgpt.com{ACCOUNTS_CHECK_PATH}?timezone_offset_min={quote(str(timezone_offset_min))}"
    try:
        timeout_seconds, attempts, base_delay = _plan_check_settings(timeout, max_attempts, retry_delay)
    except Exception as exc:
        return {
            "ok": False,
            "checked_at": now_iso(),
            "http_status": None,
            "error": f"套餐查询重试配置错误: {exc}",
            "retryable": False,
            **route_meta,
            **{k: v for k, v in claims.items() if k != "payload"},
        }

    last_result: dict | None = None
    account_seed = f"account:{(claims.get('email') or claims.get('account_id') or normalize_token(token)[:32]).lower()}"
    attempt = 0
    ip_rotations = 0
    elig_rotations = 0      # 因「查不到试用资格」而换出口的次数，见 _PLAN_ELIG_ROTATIONS
    while attempt < attempts:
        attempt += 1
        env = None
        resp = None
        try:
            # 套餐查询只需要稳定的请求头，不需要额外访问 IP 地理信息接口。
            env = BrowserSession(proxy=route["proxy"], detect_exit_geo=False, fingerprint_seed=account_seed)
            # 住宅池里有一部分出口 IP 已被 Cloudflare 挑战：换个上游重试，
            # 不能把"这个账号没套餐"这种结论建立在 403 挑战页上。
            for _ in range(ip_rotations):
                env.rotate_bridge_upstream()
            resp = env.session.get(
                url,
                headers=_common_headers(env, token),
                allow_redirects=False,
                timeout=timeout_seconds,
            )
            response_text = resp.text or ""
            http_status = int(resp.status_code)
            if http_status == 403 and ip_rotations < _PLAN_CF_ROTATIONS and is_cf_challenge_response(resp):
                ip_rotations += 1
                attempt -= 1  # 换 IP 重试不占业务重试预算
                time.sleep(_PLAN_CF_ROTATE_SLEEP)
                logger.info(
                    "[Plan] 套餐查询出口被 Cloudflare 挑战，换上游重试 (%s/%s)",
                    ip_rotations,
                    _PLAN_CF_ROTATIONS,
                )
                continue
            if not (200 <= http_status < 300):
                is_auth_expired = http_status == 401
                last_result = {
                    "ok": False,
                    "checked_at": now_iso(),
                    "http_status": http_status,
                    "error": "AT已过期/失效，请手动查活刷新" if is_auth_expired else f"HTTP {http_status}",
                    "response_preview": response_text[:500],
                    "retryable": _retryable_plan_error(http_status),
                    "token_expired": True if is_auth_expired else claims.get("token_expired"),
                    "needs_live_check": True if is_auth_expired else False,
                }
            else:
                try:
                    data: Any = resp.json()
                except Exception:
                    data = json.loads(response_text) if response_text.strip().startswith(("{", "[")) else None
                if not isinstance(data, dict):
                    last_result = {
                        "ok": False,
                        "checked_at": now_iso(),
                        "http_status": http_status,
                        "error": "响应不是 JSON 对象",
                        "response_preview": response_text[:500],
                        "retryable": True,
                    }
                else:
                    parsed = parse_accounts_check(data, token=token)
                    parsed["http_status"] = http_status
                    parsed["attempt_count"] = attempt
                    parsed["max_attempts"] = attempts
                    parsed["request_timeout"] = timeout_seconds
                    parsed["retryable"] = False
                    parsed.update(route_meta)
                    # ★ 查不到试用资格 → **换一条出口重查**，别拿一条脏出口的结论定生死。
                    #   原地重试没用：同一份请求同一条出口，结论一模一样。
                    if (
                        not parsed.get("plus_trial_eligible")
                        and elig_rotations < _PLAN_ELIG_ROTATIONS
                        and str(parsed.get("current_plan_type") or "").lower() == "free"
                    ):
                        elig_rotations += 1
                        ip_rotations += 1        # 下一轮开头会 rotate_bridge_upstream
                        last_result = parsed
                        logger.info(
                            "[Plan] %s 这条出口查不到 Plus 试用资格，换出口重查 (%s/%s)",
                            claims.get("email") or "?", elig_rotations, _PLAN_ELIG_ROTATIONS,
                        )
                        time.sleep(_PLAN_CF_ROTATE_SLEEP)
                        continue
                    return parsed
        except Exception as exc:
            logger.debug("套餐查询失败: %s: %s", type(exc).__name__, exc, exc_info=True)
            last_result = {
                "ok": False,
                "checked_at": now_iso(),
                "http_status": int(resp.status_code) if resp is not None and getattr(resp, "status_code", None) else None,
                "error": f"{type(exc).__name__}: {exc}",
                "retryable": True,
            }
        finally:
            if env is not None:
                try:
                    env.session.close()
                except Exception:
                    pass

        last_result = last_result or {"ok": False, "checked_at": now_iso(), "error": "未知错误", "retryable": True}
        last_result.update({
            "attempt_count": attempt,
            "max_attempts": attempts,
            "request_timeout": timeout_seconds,
            **route_meta,
            **{k: v for k, v in claims.items() if k != "payload"},
        })
        if not last_result.get("retryable") or attempt >= attempts:
            return last_result

        # ⛔ 2026-09-24：代理类失败必须**换出口**再试，不能原地重试同一个端口。
        #    实测 PLAN_CHECK_PROXY 钉死在 11950 时，那个端口的粘性会话一挂，
        #    重试两次还是同一个死端口，号查出来全是
        #        ProxyError: curl: (97) cannot complete SOCKS5 connection to chatgpt.com
        #    （WebUI 上整列显示「查询失败」就是这么来的）。
        #    这里在重试前重新解析一次路由 —— 池子模式下会换到另一条出口。
        # 注意判据用 route 的 proxy_mode，不是 proxy is None —— main.py 那条路会把
        # PLAN_CHECK_PROXY 当 explicit_proxy 传进来，用 proxy is None 判就永远轮换不了。
        # proxy_mode == "request" 才是调用方明确指定、不该动的情形。
        _err = str(last_result.get("error") or "")
        if route.get("proxy_mode") != "request" and any(k in _err for k in (
                "ProxyError", "SOCKS", "curl: (97)", "97)", "ConnectionError", "Connection refused")):
            try:
                _new = resolve_plan_check_route(None)
                if _new.get("proxy") and _new.get("proxy") != route.get("proxy"):
                    logger.warning("套餐查询出口不通，换一条重试: %s -> %s",
                                   route.get("proxy_used"), _new.get("proxy_used"))
                    route = _new
                    route_meta = {k: v for k, v in route.items() if k != "proxy"}
            except Exception:
                pass

        wait_seconds = _retry_wait_seconds(resp, base_delay, attempt)
        logger.warning(
            "套餐查询临时失败，第 %s/%s 次，%.1fs 后重试: %s",
            attempt,
            attempts,
            wait_seconds,
            last_result.get("error"),
        )
        if wait_seconds > 0:
            time.sleep(wait_seconds)

    return last_result or {
        "ok": False,
        "checked_at": now_iso(),
        "http_status": None,
        "error": "套餐查询未执行",
        "retryable": False,
        **route_meta,
        **{k: v for k, v in claims.items() if k != "payload"},
    }
