# -*- coding: utf-8 -*-
"""已注册账号查活：优先复用已有 AT 预热后走 reauth OTP，成功刷新 AT 即视为正常。"""
import logging
import json
import threading
import time
from datetime import datetime
from pathlib import Path

from core import db
from core.session import BrowserSession
from core.codex_oauth import _account_registration_password, _account_totp_secret, _account_totp_code
from core.humanize import delay as human_delay
from core.chatgpt_auth import get_csrf_token, get_providers, signin_openai
from core.openai_auth import (
    follow_authorize,
    send_email_otp,
    validate_email_otp,
    EmailOtpInvalidError,
    AccountUnusableError,
    detect_account_unusable_text,
)
from core.account_export import (
    _follow_reauth,
    _trigger_reauth,
    _validate_reauth_otp,
    fetch_session,
    follow_oauth_callback,
)
from core.email_provider import wait_for_otp

logger = logging.getLogger(__name__)
_LOG_DIR = Path(__file__).resolve().parent.parent / "注册日志"
_RUNNING: set[str] = set()
_RUNNING_LOCK = threading.Lock()

# 查活网络预检失败（403/429/代理/超时等）多为出口 IP 被 CF 标记或代理池抖动，
# 视为可换新 IP 重试；账号本身问题（废号/邮箱错误等）不重试。
_RETRYABLE_NETWORK_HINTS = (
    "403", "429", "502", "503", "504",
    "proxy", "socks", "timeout", "timed out",
    "connection", "closed", "reset",
)

_SESSION_FINGERPRINT_KEYS = {
    "device_id",
    "sentinel_sid",
    "oai_session_id",
    "auth_session_logging_id",
    "datadog_trace_id",
    "datadog_parent_id",
    "react_listening_key",
    "react_container_key",
    "react_resources_key",
}


def _is_retryable_network_error(exc: BaseException) -> bool:
    if isinstance(exc, AccountUnusableError):
        return False
    text = str(exc or "").lower()
    return any(h in text for h in _RETRYABLE_NETWORK_HINTS)


def _new_fingerprint_pinned_session(
    email: str,
    proxy: str | None,
    fingerprint_state: dict | None = None,
) -> BrowserSession:
    """创建账号会话；同一查活任务内固定完整浏览器画像，不随出口切换漂移。"""
    state = fingerprint_state if fingerprint_state is not None else {}
    saved_profile = state.get("browser_profile")
    identity = str(email).strip().lower()
    session = BrowserSession(
        proxy=proxy,
        # 首次需要按出口生成地区画像；之后直接复用，不再因重试/直连兜底
        # 把 ja-JP/Asia-Tokyo 突然改成 zh-CN/Asia-Shanghai。
        detect_exit_geo=not bool(saved_profile),
        browser_profile=dict(saved_profile) if isinstance(saved_profile, dict) else None,
        fingerprint_seed=f"account:{identity}",
    )
    if not saved_profile:
        generated_profile = getattr(session, "browser_profile", None)
        if isinstance(generated_profile, dict):
            state["browser_profile"] = dict(generated_profile)
    return session


def _warm_login_fingerprint_context(session: BrowserSession) -> None:
    """按真实 Web 顺序建立首页 Cookie、匿名 bootstrap 和 NextAuth 上下文。"""
    from core.chatgpt_bootstrap import anonymous_bootstrap

    logger.info("[查活] 登录前指纹预热：document → anonymous bootstrap → providers")
    nav = session.get(
        "https://chatgpt.com/",
        headers=session.get_chatgpt_navigate_headers(
            referer="https://chatgpt.com/", user_initiated=False,
        ),
        allow_redirects=True,
    )
    nav.raise_for_status()
    anonymous_bootstrap(session, strict=False)
    # best-effort bootstrap 中某个非关键接口可能 403 并触发本地熔断；在进入
    # NextAuth 正式链路前清理，但首页 document 的错误已经在上面硬失败。
    _clear_optional_bootstrap_circuit(session)
    try:
        get_providers(session)
    except Exception as exc:
        logger.info("[查活] providers 预热未通过，继续 CSRF 正式链路：%s", str(exc)[:180])
    finally:
        _clear_optional_bootstrap_circuit(session)


def _network_preflight_with_retry(
    email: str,
    proxy: str | None,
    max_attempts: int = 4,
    fingerprint_state: dict | None = None,
) -> tuple[BrowserSession, str]:
    """CSRF → Signin 备用预检；失败时重新建立会话。

    `/api/auth/providers` 只是 NextAuth 的发现接口，signin 端点并不依赖它返回的
    内容。实际运行中该接口很容易先被 Cloudflare 拦截，如果把它作为硬门槛，后续
    本来可用的 CSRF/授权链永远不会执行。因此查活备用链不再把 providers 当作
    必经步骤。

    这里必须原样传递 ``proxy``：``None`` 表示按配置选代理，空字符串表示明确
    直连。之前用 ``proxy if proxy else None`` 把直连兜底误变成了再次抽取代理。
    """
    session: BrowserSession | None = None
    last_exc: BaseException | None = None
    state = fingerprint_state if fingerprint_state is not None else {}
    for attempt in range(1, max_attempts + 1):
        if session is not None:
            try:
                session.session.close()
            except Exception:
                pass
        # 保留 None / "" 的语义差异：显式空字符串必须是真直连。
        session = _new_fingerprint_pinned_session(email, proxy, state)
        logger.info(
            "[查活] 会话创建完成：proxy=%s device_id=%s（网络预检第 %s/%s 次）",
            session.proxy or "配置随机/直连", session.device_id, attempt, max_attempts,
        )
        logger.info("[查活] 指纹摘要：%s", session.fingerprint_summary_text())
        try:
            _warm_login_fingerprint_context(session)
            csrf = get_csrf_token(session)
            authorize_url = signin_openai(session, csrf, email)
            return session, authorize_url
        except Exception as exc:
            last_exc = exc
            if attempt >= max_attempts or not _is_retryable_network_error(exc):
                try:
                    session.session.close()
                except Exception:
                    pass
                raise
            logger.warning(
                "[查活] 网络预检失败（%s/%s），重新建立会话重试：%s",
                attempt, max_attempts, str(exc)[:200],
            )
            time.sleep(2)
    raise RuntimeError(f"网络预检多次失败：{last_exc}")


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _safe_fingerprint_for_account(session: BrowserSession) -> dict:
    """账号里只记录运行环境画像，不保存会话/设备标识。"""
    fp = session.fingerprint_summary()
    return {k: v for k, v in fp.items() if k not in _SESSION_FINGERPRINT_KEYS}


def _safe_fingerprint_text_for_account(session: BrowserSession) -> str:
    fp = _safe_fingerprint_for_account(session)
    parts = [
        f"proxy={BrowserSession._short_value(fp.get('proxy') or 'direct', 36)}",
        f"ua={BrowserSession._short_value(fp.get('user_agent'), 72)}",
        f"lang={fp.get('accept_language')}",
        f"tz={fp.get('timezone_iana')}({fp.get('timezone_offset_minutes')})",
        f"screen={fp.get('screen_width')}x{fp.get('screen_height')}@{fp.get('device_pixel_ratio')}",
        f"cpu={fp.get('hardware_concurrency')}",
        f"mem={fp.get('device_memory')}",
        f"geo={fp.get('geo_country') or '?'}:{fp.get('geo_city') or '?'}",
    ]
    return " ".join(parts)


def _extract_continue_url(result: dict | None) -> str:
    if not isinstance(result, dict):
        return ""
    page = result.get("page") or {}
    page = page if isinstance(page, dict) else {}
    return str(
        result.get("continue_url")
        or result.get("external_url")
        or result.get("url")
        or page.get("continue_url")
        or page.get("external_url")
        or page.get("url")
        or ""
    ).strip()


def _extract_factor_id(result: dict | None, continue_url: str) -> str:
    if isinstance(result, dict):
        page = result.get("page") or {}
        page = page if isinstance(page, dict) else {}
        payload = page.get("payload") or {}
        if isinstance(payload, dict):
            factor_id = str(payload.get("factor_id") or "").strip()
            if factor_id:
                return factor_id
        if isinstance(page.get("payload"), dict):
            factor_id = str(page["payload"].get("factor_id") or "").strip()
            if factor_id:
                return factor_id
    if "/mfa-challenge/" in continue_url:
        return continue_url.rstrip("/").rsplit("/", 1)[-1]
    return ""


def _password_verify(session: BrowserSession, password: str) -> dict:
    from core.openai_auth import build_sentinel_header, request_sentinel_token

    sentinel_resp = request_sentinel_token(session, "password_verify")
    sentinel_header, so_header = build_sentinel_header(session, sentinel_resp, "password_verify")
    headers = session.get_auth_headers(referer="https://auth.openai.com/log-in/password")
    headers["openai-sentinel-token"] = sentinel_header
    if so_header:
        headers["openai-sentinel-so-token"] = so_header
    resp = session.post(
        "https://auth.openai.com/api/accounts/password/verify",
        headers=headers,
        data=json.dumps({"password": password}, separators=(",", ":")),
        allow_redirects=False,
    )
    resp.raise_for_status()
    return resp.json()


def _mfa_issue_challenge(session: BrowserSession, factor_id: str) -> dict:
    headers = session.get_auth_headers(referer="https://auth.openai.com/mfa-challenge")
    headers.pop("openai-sentinel-token", None)
    headers.pop("openai-sentinel-so-token", None)
    resp = session.post(
        "https://auth.openai.com/api/accounts/mfa/issue_challenge",
        headers=headers,
        data=json.dumps({"id": factor_id, "type": "totp", "force_fresh_challenge": False}, separators=(",", ":")),
        allow_redirects=False,
    )
    resp.raise_for_status()
    return resp.json()


def _mfa_verify(session: BrowserSession, factor_id: str, code: str) -> dict:
    headers = session.get_auth_headers(referer="https://auth.openai.com/mfa-challenge")
    headers.pop("openai-sentinel-token", None)
    headers.pop("openai-sentinel-so-token", None)
    resp = session.post(
        "https://auth.openai.com/api/accounts/mfa/verify",
        headers=headers,
        data=json.dumps({"id": factor_id, "type": "totp", "code": code}, separators=(",", ":")),
        allow_redirects=False,
    )
    resp.raise_for_status()
    return resp.json()


def _follow_continue_and_fetch(session: BrowserSession, continue_url: str, *, referer: str) -> dict:
    follow_oauth_callback(session, continue_url, referer=referer)
    return fetch_session(session)


def _session_cookies(session: BrowserSession) -> list[dict]:
    """把重登后的 cookie jar 导出来。

    为什么要它：chatgpt.com 的浏览器登录态是 __Secure-next-auth.session-token
    这个 cookie，它只在 OAuth callback 那一刻由服务端下发。access_token 是回调
    完成之后从 /api/auth/session 读出来的**产物**，反推不出 cookie。所以想让浏览器
    「直接就是那个账号」，只能在重登时把 cookie 抓下来再注入浏览器。

    导出字段按 Playwright add_cookies / CDP Network.setCookie 的格式对齐。
    """
    out: list[dict] = []
    try:
        jar = list(session.session.cookies.jar)
    except Exception:
        return out
    for c in jar:
        try:
            name = str(getattr(c, "name", "") or "")
            if not name:
                continue
            raw_exp = getattr(c, "expires", None)
            try:
                expires = int(float(raw_exp)) if raw_exp not in (None, "") else -1
            except Exception:
                expires = -1
            out.append({
                "name": name,
                "value": str(getattr(c, "value", "") or ""),
                "domain": str(getattr(c, "domain", "") or ".chatgpt.com"),
                "path": str(getattr(c, "path", "") or "/"),
                "expires": expires,
                "secure": bool(getattr(c, "secure", True)),
                "httpOnly": bool(getattr(c, "has_nonstandard_attr", lambda *_: False)("HTTPOnly"))
                            or name.startswith("__Secure-"),
                "sameSite": "Lax",
            })
        except Exception:
            continue
    return out


def _stored_access_token(email: str) -> str:
    """读取本地账号已有 AT，用于先预热登录态再走稳定的 reauth 链。"""
    try:
        account = db.get_account_by_email(email)
        return str((account or {}).get("access_token") or "").strip()
    except Exception as exc:
        logger.debug("[查活] 读取已有 accessToken 失败，改走备用登录链：%s: %s", type(exc).__name__, exc)
        return ""


def _clear_optional_bootstrap_circuit(session: BrowserSession) -> None:
    """清理可选登录态预热造成的本地熔断，不影响后续正式认证请求。

    authenticated_bootstrap 是 best-effort 预热，其中个别旧接口返回 403 不等于
    reauth 链不可用；BrowserSession 的通用熔断器若保留该状态，会直接拦截后续
    `/api/auth/csrf`，导致稳定的 2FA 链也无法开始。
    """
    reset = getattr(session, "reset_circuit_breaker", None)
    if callable(reset):
        reset()
        return
    if getattr(session, "blocked_until", 0.0):
        session.blocked_until = 0.0
        session.blocked_reason = ""


def _warm_authenticated_session(session: BrowserSession, access_token: str) -> None:
    """复用 2FA 已验证的登录态预热流程。预热失败不直接判定账号死亡。"""
    if not access_token:
        return
    from core.chatgpt_bootstrap import authenticated_bootstrap

    try:
        logger.info("[查活] 使用已有 accessToken 预热登录态...")
        authenticated_bootstrap(session, access_token, strict=False)
        logger.info("[查活] accessToken 预热完成，继续走 reauth OTP")
    except Exception as exc:
        # strict=False 已经会吞掉大部分单接口错误；这里仅兜住初始化异常。
        logger.warning("[查活] accessToken 预热失败，继续走 reauth OTP：%s: %s", type(exc).__name__, str(exc)[:180])
    finally:
        _clear_optional_bootstrap_circuit(session)


def _exception_response_text(exc: BaseException) -> str:
    response = getattr(exc, "response", None)
    return str(getattr(response, "text", "") or "")


def _exception_status_code(exc: BaseException) -> int | None:
    response = getattr(exc, "response", None)
    try:
        status = int(getattr(response, "status_code", 0) or 0)
    except (TypeError, ValueError):
        return None
    return status or None


def _validate_reauth_with_retry(
    session: BrowserSession,
    email: str,
    otp_after_ts: float,
    max_otp_attempts: int = 3,
    email_source: str | None = None,
) -> str:
    """提交 reauth OTP；验证码错误时重新发送并重新取码。"""
    current_otp: str | None = None
    last_exc: Exception | None = None
    for attempt in range(1, max_otp_attempts + 1):
        try:
            if current_otp is None:
                logger.info("[查活] 等待重认证 OTP：%s（第 %s/%s 次）", email, attempt, max_otp_attempts)
                current_otp = wait_for_otp(
                    email,
                    after_ts=otp_after_ts,
                    email_source=email_source,
                )
            human_delay("otp_input")
            continue_url = _validate_reauth_otp(session, current_otp)
            if not continue_url:
                raise RuntimeError("重认证 OTP 验证响应缺少 continue_url")
            return str(continue_url)
        except AccountUnusableError:
            raise
        except Exception as exc:
            last_exc = exc
            body = _exception_response_text(exc)
            dead_code = detect_account_unusable_text(body) or detect_account_unusable_text(str(exc))
            if dead_code:
                raise AccountUnusableError(
                    f"账号已废弃（{dead_code}），邮箱不可再用",
                    error_code=dead_code,
                ) from exc

            status = _exception_status_code(exc)
            # reauth validate 的 403 可能是 Cloudflare/出口拦截；不要在同一已熔断
            # 会话上反复发送 OTP，交给上层的直连兜底处理。
            # EmailOtpInvalidError（wrong_email_otp_code）必须显式放进来：这个异常对象
            # 上不一定带 status_code，_exception_status_code 会返回 None，于是旧代码
            # 直接 raise —— **一次拿到旧码就把整条重认证判死**。实测换绑时正是如此：
            # 取码接口返回的是上一封 reauth 邮件的旧码 → 401 → 不重试 → 换绑失败。
            # 邮箱 OTP 拿错码是常态（邮件还没到/上一封还在），必须允许重发重取。
            retryable_otp = status in (400, 401, 422) or isinstance(exc, EmailOtpInvalidError)
            if attempt >= max_otp_attempts or not retryable_otp:
                raise
            logger.warning(
                "[查活] 重认证 OTP 无效/过期，重新发送后再取（%s/%s）：%s",
                attempt,
                max_otp_attempts,
                str(exc)[:180],
            )
            send_email_otp(session)
            otp_after_ts = time.time()
            current_otp = None
            time.sleep(1)
    raise last_exc if last_exc else RuntimeError("重认证 OTP 验证失败")


def _complete_mfa_if_challenged(
    session: BrowserSession,
    email: str,
    continue_url: str,
    page_type: str = "",
) -> tuple[str, bool]:
    """落点是 MFA challenge 时，用库里的 totp_secret 完成验证，返回 (新 continue_url, 是否走过 MFA)。

    为什么需要这个助手：**本机的账号全部是无密码注册**（registration_password 一个都没有），
    所以 _login_via_password_or_otp 里那段处理 MFA 的分支永远进不去 —— 它一看没有密码就
    直接走邮箱 OTP。而开了 2FA 的账号，邮箱 OTP 验证通过后会被送到
    /mfa-challenge/<factor_id>，旧代码的 _login_via_email_otp / _login_via_reauth 会把这个
    地址当成普通回调直接 follow 过去，结果拿不到 session，表现为
    「重新登录后未拿到 accessToken」。

    现在把 MFA 处理抽出来，给邮箱 OTP、reauth 两条链路共用；密码链路继续用原分支。
    """
    url = str(continue_url or "")
    is_mfa = "/mfa-challenge/" in url or str(page_type or "") == "mfa_challenge"
    if not is_mfa:
        return url, False
    factor_id = _extract_factor_id(None, url)
    if not factor_id:
        raise RuntimeError(f"进入 MFA challenge 但未拿到 factor_id: {url}")
    secret = _account_totp_secret(email)
    if not secret:
        raise RuntimeError(f"进入 MFA challenge，但账号没有 totp_secret：{email}")
    logger.info("[查活] 进入 MFA challenge，提交 TOTP：%s factor_id=%s", email, factor_id)
    _mfa_issue_challenge(session, factor_id)
    code = _account_totp_code(email)
    if not code:
        raise RuntimeError(f"无法生成 TOTP 验证码：{email}")
    result = _mfa_verify(session, factor_id, code)
    new_url = _extract_continue_url(result) or url
    if not new_url:
        raise RuntimeError(f"MFA 验证成功但没有 continue_url: {result}")
    logger.info("[查活] MFA 验证通过，继续跟随回调：%s", email)
    return new_url, True


def _login_via_reauth(
    session: BrowserSession,
    email: str,
    otp_after_ts: float,
    email_source: str | None = None,
) -> dict:
    """按 2FA 已验证链路重新认证并刷新 ChatGPT session。"""
    auth_url = _trigger_reauth(session, email)
    logger.info("[查活] reauth authorize URL 已获取")
    human_delay("api")
    final_url = _follow_reauth(session, auth_url)
    dead_code = detect_account_unusable_text(final_url)
    if dead_code:
        raise AccountUnusableError(f"账号已废弃（{dead_code}）", error_code=dead_code)
    human_delay("navigate")
    logger.info("[查活] 已跟随 reauth authorize URL，开始等待邮箱 OTP")
    continue_url = _validate_reauth_with_retry(
        session,
        email,
        otp_after_ts,
        email_source=email_source,
    )
    continue_url, used_mfa = _complete_mfa_if_challenged(session, email, continue_url)
    logger.info("[查活] reauth OTP 验证通过%s，开始交换新 token", "（已过 MFA）" if used_mfa else "")
    human_delay("api")
    return _follow_continue_and_fetch(
        session,
        continue_url,
        referer="https://auth.openai.com/mfa-challenge/" if used_mfa else "https://auth.openai.com/email-verification",
    )


def _login_via_email_otp(
    session: BrowserSession,
    email: str,
    otp_after_ts: float,
    email_source: str | None = None,
) -> dict:
    """完成邮箱 OTP 登录，并跟随 OAuth callback 后拉取 ChatGPT session。"""
    validate_result = _validate_with_retry(
        session,
        email,
        otp_after_ts,
        email_source=email_source,
    )
    page = validate_result.get("page") if isinstance(validate_result, dict) else {}
    page = page if isinstance(page, dict) else {}
    page_type = str(page.get("type") or "")
    continue_url = _extract_continue_url(validate_result)
    if not continue_url:
        raise RuntimeError(f"OTP 登录成功但没有 OAuth continue_url: {validate_result}")
    if "about-you" in str(continue_url) or page_type in {"about_you", "about-you"}:
        raise RuntimeError(f"该邮箱登录后进入资料页，疑似不是完整已注册账号: page_type={page_type}, continue_url={continue_url}")
    # 开了 2FA 的账号，邮箱 OTP 之后会被送到 /mfa-challenge，必须先过 TOTP。
    continue_url, used_mfa = _complete_mfa_if_challenged(session, email, continue_url, page_type)
    logger.info("[查活] 邮箱 OTP 验证完成%s，开始跟随 OAuth callback", "（已过 MFA）" if used_mfa else "")
    return _follow_continue_and_fetch(
        session,
        continue_url,
        referer="https://auth.openai.com/mfa-challenge/" if used_mfa else "https://auth.openai.com/email-verification",
    )


def _login_via_password_or_otp(
    session: BrowserSession,
    email: str,
    otp_after_ts: float,
    email_source: str | None = None,
) -> dict:
    """优先密码登录；如进入 MFA challenge 则自动用 TOTP 完成。"""
    password = _account_registration_password(email)
    if not password:
        logger.info("[查活] 未找到注册密码，继续使用邮箱 OTP：%s", email)
        return _login_via_email_otp(
            session,
            email,
            otp_after_ts,
            email_source=email_source,
        )

    logger.info("[查活] 账号存在密码，优先走密码登录：%s", email)
    password_result = _password_verify(session, password)
    continue_url = _extract_continue_url(password_result)
    page = password_result.get("page") if isinstance(password_result, dict) else {}
    page = page if isinstance(page, dict) else {}
    page_type = str(page.get("type") or "")

    if "/mfa-challenge/" in continue_url or page_type == "mfa_challenge":
        factor_id = _extract_factor_id(password_result, continue_url)
        secret = _account_totp_secret(email)
        if not factor_id:
            raise RuntimeError(f"密码登录后进入 MFA 但未拿到 factor_id: {password_result}")
        if not secret:
            raise RuntimeError(f"密码登录后进入 MFA，但账号没有 totp_secret：{email}")
        logger.info("[查活] 已进入 MFA challenge，开始提交 TOTP：%s factor_id=%s", email, factor_id)
        _mfa_issue_challenge(session, factor_id)
        code = _account_totp_code(email)
        if not code:
            raise RuntimeError(f"无法生成 TOTP 验证码：{email}")
        mfa_result = _mfa_verify(session, factor_id, code)
        mfa_continue_url = _extract_continue_url(mfa_result) or continue_url
        if not mfa_continue_url:
            raise RuntimeError(f"MFA 验证成功但没有 continue_url: {mfa_result}")
        return _follow_continue_and_fetch(
            session,
            mfa_continue_url,
            referer=f"https://auth.openai.com/mfa-challenge/{factor_id}",
        )

    if "email-verification" in continue_url or page_type in {"email_verification", "email_otp_send"}:
        logger.info("[查活] 密码登录后仍进入邮箱 OTP，继续完成邮箱验证：%s", email)
        return _login_via_email_otp(
            session,
            email,
            otp_after_ts,
            email_source=email_source,
        )

    if continue_url:
        logger.info("[查活] 密码登录直接给出回调地址，继续完成回调：%s", email)
        return _follow_continue_and_fetch(session, continue_url, referer="https://auth.openai.com/log-in/password")

    raise RuntimeError(f"密码登录成功但没有可用 continue_url: {password_result}")


def log_path(email: str) -> Path:
    safe = str(email or "").replace("/", "_").replace("\\", "_").replace(":", "_")
    return _LOG_DIR / f"live-check-{safe}.log"


def is_checking(email: str) -> bool:
    key = str(email or "").strip().lower()
    with _RUNNING_LOCK:
        return key in _RUNNING


def _validate_with_retry(
    session: BrowserSession,
    email: str,
    otp_after_ts: float,
    max_otp_attempts: int = 3,
    email_source: str | None = None,
) -> dict:
    current_otp = None
    last_exc: Exception | None = None
    for attempt in range(1, max_otp_attempts + 1):
        try:
            if current_otp is None:
                logger.info("[查活] 等待登录 OTP：%s（第 %s/%s 次）", email, attempt, max_otp_attempts)
                # 先直连轮询（抗 ic-mail 网关抖动 + 带 ?after= 过滤旧码），拿不到才回落。
                # 同一个坑在 2FA 那条链上已经修过一次：fetch_latest_otp 碰到一次 ReadTimeout
                # 就把整轮等待判死，而那个网关本来就抖（实测发码最慢 t+145s）。
                from core.email_provider import fetch_code_direct
                current_otp = fetch_code_direct(email, after_ts=otp_after_ts, timeout=180)
                if current_otp:
                    logger.info("[查活] 直连轮询拿到 OTP")
                else:
                    logger.info("[查活] 直连轮询没拿到，回落到 wait_for_otp")
                    current_otp = wait_for_otp(
                        email,
                        after_ts=otp_after_ts,
                        email_source=email_source,
                    )
            from config import openai_protocol as _protocol_cfg
            from core.openai_auth import build_sentinel_header, request_sentinel_token
            sentinel_header = None
            so_header = None
            if getattr(_protocol_cfg, "SEND_SENTINEL_ON_EMAIL_OTP_VALIDATE", False):
                sentinel_resp = request_sentinel_token(session, "email_otp_validate")
                sentinel_header, so_header = build_sentinel_header(session, sentinel_resp, "email_otp_validate")
            result = validate_email_otp(session, current_otp, sentinel_header=sentinel_header, so_header=so_header)
            return result
        except EmailOtpInvalidError as exc:
            last_exc = exc
            if attempt >= max_otp_attempts:
                break
            logger.warning("[查活] OTP 无效/过期，重新发送后再取：%s", str(exc)[:180])
            send_email_otp(session)
            # 以“重新发送请求完成后”为新基准，避免刚刚失败的上一封旧码再次被 after 容忍窗口命中。
            otp_after_ts = time.time()
            current_otp = None
            time.sleep(1)
        except Exception as exc:
            # 提交 OTP 后的网络抖动（连接断开/超时/代理波动）：同一会话重发验证码再验证一次。
            if attempt >= max_otp_attempts or not _is_retryable_network_error(exc):
                raise
            last_exc = exc
            logger.warning("[查活] OTP 验证网络抖动，重新发送后再取（%s/%s）：%s", attempt, max_otp_attempts, str(exc)[:180])
            try:
                send_email_otp(session)
            except Exception:
                raise
            otp_after_ts = time.time()
            current_otp = None
            time.sleep(1)
    raise last_exc if last_exc else RuntimeError("OTP 验证失败")


def check_account_liveness(
    email: str,
    proxy: str | None = None,
    *,
    clear_log: bool = True,
    email_source: str | None = None,
    fingerprint_state: dict | None = None,
    prefer_password: bool = False,
) -> dict:
    """
    重新登录账号并刷新最新 accessToken。

    返回：
      {
        ok: bool,
        status: live/deactivated/failed,
        access_token: str?,
        session: dict?,
        checked_at: ISO,
        error: str?
      }
    """
    email = str(email or "").strip()
    if not email:
        raise ValueError("email 不能为空")

    checked_at = _now()
    key = email.lower()
    path = log_path(email)
    path.parent.mkdir(parents=True, exist_ok=True)
    if clear_log:
        path.write_text("", encoding="utf-8")

    fh: logging.FileHandler | None = None
    session: BrowserSession | None = None
    root_logger = logging.getLogger()
    thread_name = threading.current_thread().name
    with _RUNNING_LOCK:
        _RUNNING.add(key)
    try:
        fh = logging.FileHandler(str(path), encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%H:%M:%S",
        ))
        fh.addFilter(lambda record: record.threadName == thread_name)
        root_logger.addHandler(fh)

        logger.info("[查活] 日志文件：%s", path)
        logger.info("[查活] 开始重新登录：%s", email)
        existing_access_token = _stored_access_token(email)
        has_totp = bool(_account_totp_secret(email))
        # prefer_password=True 时，只要号上有密码就走「密码登录」链，**不发邮箱码**。
        # 用途：cookie_backfill 这类「我只要一条新登录态」的场景 —— 邮箱网关一抖
        # 就会白等一轮（实测 43 个无 2FA 的号里 27 个卡在这）。默认 False，
        # 原有查活/2FA 链路行为完全不变。
        if existing_access_token and not has_totp and not prefer_password:
            # 2FA 设置流程已经验证：先用已有 AT 预热 ChatGPT 登录态，再走
            # reauth → 邮箱 OTP → callback。该链路不依赖容易被 CF 拦截的
            # /api/auth/providers。已开启 TOTP 的账号保留密码 → MFA 路径，
            # 避免把 MFA challenge 误当成邮箱 OTP 页面。
            logger.info("[查活] 流程：登录态预热 → CSRF → Reauth Signin → Authorize → 邮箱 OTP → OAuth callback → Session/AT")
            session = _new_fingerprint_pinned_session(email, proxy, fingerprint_state)
            logger.info(
                "[查活] 会话创建完成：proxy=%s device_id=%s（复用2FA稳定链路）",
                session.proxy or "直连/配置随机",
                session.device_id,
            )
            logger.info("[查活] 指纹摘要：%s", session.fingerprint_summary_text())
            _warm_authenticated_session(session, existing_access_token)
            human_delay("navigate")
            session_info = _login_via_reauth(
                session,
                email,
                time.time(),
                email_source=email_source,
            )
        else:
            # 兼容没有本地 AT 或已开启 TOTP 的记录。providers 不是 signin 的
            # 前置依赖，备用链只执行 CSRF → Signin，避免在 providers 403 时提前终止。
            logger.info("[查活] 流程：CSRF → Signin → Authorize → 密码/邮箱 OTP → MFA(如有) → OAuth callback → Session/AT")
            session, authorize_url = _network_preflight_with_retry(
                email, proxy, fingerprint_state=fingerprint_state,
            )

            otp_after_ts = time.time()
            final_url = follow_authorize(session, authorize_url)
            dead_code = detect_account_unusable_text(final_url)
            if dead_code:
                return {"ok": False, "status": "deactivated", "checked_at": checked_at, "error": dead_code}

            session_info = _login_via_password_or_otp(
                session,
                email,
                otp_after_ts,
                email_source=email_source,
            )
        access_token = str(session_info.get("accessToken") or "")
        if not access_token:
            raise RuntimeError("重新登录后未拿到 accessToken")

        user = session_info.get("user") or {}
        account = session_info.get("account") or {}
        logger.info("[查活] 正常：%s user_id=%s plan=%s", email, user.get("id"), account.get("planType"))
        fp = _safe_fingerprint_for_account(session)
        return {
            "ok": True,
            "status": "live",
            "checked_at": checked_at,
            "access_token": access_token,
            "session": session_info,
            "cookies": _session_cookies(session),
            "proxy_used": session.proxy or None,
            "fingerprint": fp,
            "fingerprint_text": _safe_fingerprint_text_for_account(session),
        }
    except AccountUnusableError as exc:
        code = getattr(exc, "error_code", "") or detect_account_unusable_text(str(exc)) or "account_deactivated"
        logger.warning("[查活] 已废号：%s %s", email, code)
        return {"ok": False, "status": "deactivated", "checked_at": checked_at, "error": code}
    except Exception as exc:
        code = detect_account_unusable_text(_exception_response_text(exc)) or detect_account_unusable_text(str(exc))
        if code:
            logger.warning("[查活] 已废号：%s %s", email, code)
            return {"ok": False, "status": "deactivated", "checked_at": checked_at, "error": code}
        logger.warning("[查活] 失败：%s %s: %s", email, type(exc).__name__, str(exc)[:260])
        return {"ok": False, "status": "failed", "checked_at": checked_at, "error": f"{type(exc).__name__}: {str(exc)[:500]}"}
    finally:
        try:
            logger.info("[查活] 结束：%s", email)
            if session is not None:
                try:
                    session.session.close()
                except Exception:
                    pass
            if fh is not None:
                root_logger.removeHandler(fh)
                fh.close()
        finally:
            with _RUNNING_LOCK:
                _RUNNING.discard(key)
