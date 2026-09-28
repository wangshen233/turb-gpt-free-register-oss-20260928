# -*- coding: utf-8 -*-
"""
注册后处理模块：
    1. 拉取 /api/auth/session，从中抽取 accessToken / user 信息
    2. 设置 2FA（TOTP），返回 secret
    3. 把账号信息（邮箱 + accessToken + TOTP secret）保存到 SQLite

整体复用注册阶段的 BrowserSession（同一 cookie jar / 同一 IP / 同一 UA），
避免再起新会话被风控关联或缺失登录态。
"""
import json
import logging
import random
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlencode

import pyotp

from core.session import BrowserSession
from core.humanize import delay as human_delay

logger = logging.getLogger(__name__)

def _post_register_dwell_seconds() -> float:
    try:
        from config import register as _register_cfg

        raw = str(getattr(_register_cfg, "POST_REGISTER_DWELL_SECONDS_RANGE", "18,45") or "0,0").strip()
    except Exception:
        raw = "0,0"
    try:
        parts = [float(x.strip()) for x in raw.replace(";", ",").replace("|", ",").split(",") if x.strip()]
        if not parts:
            lo = hi = 0.0
        elif len(parts) == 1:
            lo = hi = parts[0]
        else:
            lo, hi = parts[0], parts[1]
    except Exception:
        lo = hi = 0.0
    lo, hi = max(0.0, lo), max(0.0, hi)
    if hi < lo:
        lo, hi = hi, lo
    seconds = random.uniform(lo, hi) if hi > lo else lo
    return max(0.0, min(300.0, seconds))


def post_register_dwell(email: str, *, label: str = "注册后") -> None:
    """注册成功后随机停留一段时间；供不同浏览器驱动复用。"""
    seconds = _post_register_dwell_seconds()
    if seconds <= 0:
        return
    logger.info("[%s] 注册成功后随机停留 %.1fs：%s", label, seconds, email)
    time.sleep(seconds)


def _account_material_line(email: str, row: dict | None = None) -> str:
    """优先输出 Outlook 原始素材；没有素材时退回邮箱地址。"""
    if row:
        base = row.get("original_email_line") or row.get("email") or email
        password = ""
        if isinstance(row.get("extra_json"), str) and row.get("extra_json"):
            try:
                extra = json.loads(str(row.get("extra_json") or ""))
                password = str(extra.get("registration_password") or "").strip()
            except Exception:
                password = ""
        if not password:
            password = str(row.get("password") or "").strip()
        parts = [p for p in str(base or "").split("----") if p != ""]
        if password:
            if not parts:
                base = password
            elif len(parts) == 1:
                if parts[0] != password:
                    parts.insert(1, password)
                base = "----".join(parts)
            elif parts[1] != password:
                looks_like_material = (
                    parts[1].startswith("M.")
                    or parts[1].startswith("m.")
                    or (len(parts[1]) >= 32 and parts[1].count("-") >= 4)
                    or any(ch in parts[1] for ch in ("@", ":", "/", "\\"))
                )
                if looks_like_material:
                    parts.insert(1, password)
                    base = "----".join(parts)
        return base
    return email


def _account_copy_line(
    material_line: str,
    access_token: str,
    gpt_password: str | None = None,
    totp_secret: str | None = None,
) -> str:
    """生成包含 token 的整行归档，方便从批次汇总文件里复制。"""
    parts = [material_line, access_token]
    if gpt_password or totp_secret:
        parts.append(str(gpt_password or ""))
    if totp_secret:
        parts.append(totp_secret)
    return "----".join(parts)


def create_batch_archive_dir(count: int, workers: int = 1) -> None:
    """兼容旧调用方；批次数据现在直接保存到 SQLite，不创建归档目录。"""
    return None


def _append_batch_archive(
    *,
    row_id: int,
    email: str,
    access_token: str,
    totp_secret: str | None,
    email_source: str | None,
    proxy_used: str | None,
    extra: dict,
    batch_dir: Path | None,
) -> None:
    """兼容旧调用方；注册账号已经由 db.insert_account 保存到 SQLite。"""
    from core import db
    # 参数保留是为了兼容注册驱动；不再读取 batch_dir 或写入任何归档文件。
    _ = (db, row_id, email, access_token, totp_secret, email_source, proxy_used, extra, batch_dir)
    return None


def follow_oauth_callback(session: BrowserSession, continue_url: str, referer: str = "https://auth.openai.com/about-you") -> str:
    """
    步骤12.5: 跟随 create_account 返回的 continue_url，完成 OAuth 回调。

    create_account 成功后返回的 continue_url 一般指向
        https://auth.openai.com/authorize/continue?...
    它会再 302 到
        https://chatgpt.com/api/auth/callback/openai?code=...&state=...
    回调请求会让 chatgpt.com 设置 `__Secure-next-auth.session-token` cookie，
    之后 /api/auth/session 才能返回 accessToken。

    Returns:
        重定向链最终落点 URL（一般是 chatgpt.com 站内地址）
    """
    if not continue_url:
        raise ValueError("continue_url 为空，无法完成 OAuth 回调")

    # continue_url 通常是 auth.openai.com/authorize/continue；
    # OTP 后 external_url 分支也可能直接给 chatgpt.com 回调地址。
    # 按目标域名选择导航头，避免 auth step 正确但请求头语义不一致。
    if str(continue_url).startswith("https://chatgpt.com"):
        headers = session.get_chatgpt_navigate_headers(referer=referer)
    else:
        headers = session.get_auth_navigate_headers(referer=referer)

    logger.info(f"[OAuth回调] 跟随 continue_url 完成 OAuth 回调...")
    resp = session.get(continue_url, headers=headers, allow_redirects=True)
    logger.info(f"[OAuth回调] 完成, 最终落点: {resp.url}")
    return resp.url


def fetch_session(session: BrowserSession) -> dict:
    """
    GET https://chatgpt.com/api/auth/session
    注册成功后立刻调用，拿到 accessToken / user / account / expires。

    Returns:
        完整 session JSON，包含字段:
            - accessToken: str (Bearer token, 用于 backend-api 调用)
            - user: {id, name, email, idp, iat, mfa}
            - account: {id, planType, structure, ...}
            - expires: ISO 时间字符串
    """
    url = "https://chatgpt.com/api/auth/session"
    headers = session.get_nextauth_headers(referer="https://chatgpt.com/")

    logger.info("[Session] 拉取 ChatGPT session 信息...")
    resp = session.get(url, headers=headers)
    resp.raise_for_status()
    data = resp.json()

    if not data.get("accessToken"):
        logger.error(f"[Session] 响应中没有 accessToken: {data}")
        raise RuntimeError("未拿到 accessToken，登录态可能未建立")

    user = data.get("user") or {}
    account = data.get("account") or {}
    logger.info(
        f"[Session] 成功，user_id={user.get('id')}, email={user.get('email')}, "
        f"plan={account.get('planType')}, mfa={user.get('mfa')}"
    )
    return data


def _trigger_reauth(session: BrowserSession, email: str) -> str:
    """
    步骤2-3: 发起密码重认证，返回 OpenAI authorize URL。
    重定向链会自动触发邮箱发送一份新的 OTP（用于 2FA 重认证）。
    """
    # 重新拿一次 csrf（旧的可能已过期）
    csrf_url = "https://chatgpt.com/api/auth/csrf"
    csrf_resp = session.get(csrf_url, headers=session.get_nextauth_headers(referer="https://chatgpt.com/"))
    csrf_resp.raise_for_status()
    csrf_token = csrf_resp.json()["csrfToken"]
    logger.info(f"[2FA] 重认证 CSRF: {csrf_token[:20]}...")

    # POST /api/auth/signin/openai 带 reauth 参数
    query = {
        "connection": "password",
        "login_hint": email,
        "reauth": "password",
        "max_age": "0",
        "ext-oai-did": session.device_id,
    }
    signin_url = "https://chatgpt.com/api/auth/signin/openai?" + urlencode(query)

    headers = session.get_nextauth_headers(referer="https://chatgpt.com/")
    headers["content-type"] = "application/x-www-form-urlencoded"
    headers["origin"] = "https://chatgpt.com"

    body = urlencode({
        "callbackUrl": "https://chatgpt.com/?action=enable&factor=totp",
        "csrfToken": csrf_token,
        "json": "true",
    })

    logger.info("[2FA] 发起重认证 signin/openai...")
    resp = session.post(signin_url, headers=headers, data=body)
    resp.raise_for_status()
    auth_url = resp.json().get("url")
    if not auth_url:
        raise RuntimeError(f"未拿到 reauth authorize URL: {resp.text}")
    from core.chatgpt_auth import _ensure_authorize_context
    return _ensure_authorize_context(auth_url, session, email)


def _follow_reauth(session: BrowserSession, auth_url: str) -> str:
    """
    步骤3: 跟随 authorize URL 触发邮箱 OTP 发送。
    auth.openai.com 会重定向到 /email-verification 页面，期间发送 OTP 邮件。
    """
    headers = session.get_auth_navigate_headers(referer="https://chatgpt.com/")
    logger.info("[2FA] 跟随 authorize URL，触发 OTP 发送...")
    resp = session.get(auth_url, headers=headers, allow_redirects=True)
    resp.raise_for_status()
    logger.info(f"[2FA] 落点 URL: {resp.url}")
    return str(getattr(resp, "url", "") or "")


def _trigger_reauth_otp_send(session: BrowserSession) -> None:
    """显式催一封重认证验证码。

    浏览器里是 /email-verification 页面加载后自己打这一枪；纯协议没有页面，
    不显式打就可能在等一封根本没发出来的邮件（实测 1357：显式打之后 t+145s 收到码）。
    两个接口都试：passwordless 优先，被拒（409 invalid_state）就换旧的 email-otp/send。
    """
    for url, tag in (
        ("https://auth.openai.com/api/accounts/passwordless/send-otp", "passwordless/send-otp"),
        ("https://auth.openai.com/api/accounts/email-otp/send", "email-otp/send"),
    ):
        try:
            headers = session.get_auth_headers(referer="https://auth.openai.com/email-verification")
            headers["sec-fetch-site"] = "same-origin"
            headers["sec-fetch-user"] = "?1"
            resp = session.post(url, headers=headers, data="", allow_redirects=False)
            logger.info("[2FA] 显式催码 %s -> HTTP %s", tag, resp.status_code)
            if int(resp.status_code) < 400:
                return
        except Exception as exc:
            logger.info("[2FA] 显式催码 %s 异常: %s", tag, str(exc)[:140])


def _validate_reauth_otp(session: BrowserSession, code: str) -> str:
    """
    步骤4: 提交邮箱 OTP 验证。
    返回 continue_url（带 code 参数的 callback URL，用于跳回 chatgpt.com）。
    2026-09 HAR：email-otp/validate 必须带 sentinel + so-token，
    查活/2FA 重认证不能走裸 OTP。
    """
    from config import openai_protocol as _protocol_cfg
    from core.openai_auth import (
        build_sentinel_header,
        request_sentinel_token,
        validate_email_otp,
    )

    sentinel_header = None
    so_header = None
    if getattr(_protocol_cfg, "SEND_SENTINEL_ON_EMAIL_OTP_VALIDATE", False):
        sentinel_resp = request_sentinel_token(session, "email_otp_validate")
        sentinel_header, so_header = build_sentinel_header(
            session, sentinel_resp, "email_otp_validate",
        )
        logger.info("[2FA] 重认证 OTP 已补齐 email_otp_validate sentinel")
    data = validate_email_otp(
        session,
        code,
        sentinel_header=sentinel_header,
        so_header=so_header,
    )
    continue_url = data.get("continue_url")
    if not continue_url:
        raise RuntimeError(f"OTP 验证响应缺少 continue_url: {data}")
    return continue_url


def _exchange_new_token(session: BrowserSession, continue_url: str) -> str:
    """
    步骤5: 跟随 continue_url 完成回调，再次拉 /api/auth/session 拿到新 accessToken
    （此时 token 内嵌的 pwd_auth_time 是新鲜的，2FA enroll 才会接受）。
    """
    headers = session.get_auth_navigate_headers(referer="https://auth.openai.com/email-verification")
    logger.info("[2FA] 跟随 continue_url，刷新 session-token cookie...")
    session.get(continue_url, headers=headers, allow_redirects=True)

    # 拿新的 accessToken
    new_session = fetch_session(session)
    new_token = new_session["accessToken"]
    logger.info(f"[2FA] 新 accessToken（含新鲜 pwd_auth_time）: {new_token[:40]}...")
    return new_token


def _enroll_totp(session: BrowserSession, access_token: str) -> tuple[str, str]:
    """
    步骤6: 注册 TOTP，返回 (secret, session_id)
    """
    url = "https://chatgpt.com/backend-api/accounts/mfa/enroll"
    headers = session.get_chatgpt_headers(referer="https://chatgpt.com/", include_content_type=True)
    headers["authorization"] = f"Bearer {access_token}"
    headers["oai-device-id"] = session.device_id
    headers["oai-language"] = session.navigator_language()

    body = json.dumps({"factor_type": "totp"}, separators=(",", ":"))

    logger.info("[2FA] 注册 TOTP...")
    resp = session.post(url, headers=headers, data=body)
    if resp.status_code != 200:
        logger.error(f"[2FA] enroll 失败 {resp.status_code}: {resp.text}")
        resp.raise_for_status()
    data = resp.json()
    secret = data.get("secret")
    session_id = data.get("session_id")
    if not secret or not session_id:
        raise RuntimeError(f"enroll 响应字段缺失: {data}")
    logger.info(f"[2FA] TOTP secret 已获取: {secret[:4]}...{secret[-4:]}")
    return secret, session_id


def _activate_totp(
    session: BrowserSession,
    access_token: str,
    secret: str,
    session_id: str,
) -> bool:
    """
    步骤7: 用 secret 生成 6 位 TOTP 码，激活 2FA。
    """
    url = "https://chatgpt.com/backend-api/accounts/mfa/user/activate_enrollment"
    headers = session.get_chatgpt_headers(referer="https://chatgpt.com/", include_content_type=True)
    headers["authorization"] = f"Bearer {access_token}"
    headers["oai-device-id"] = session.device_id
    headers["oai-language"] = session.navigator_language()

    totp_code = pyotp.TOTP(secret).now()
    body = json.dumps({
        "code": totp_code,
        "factor_type": "totp",
        "session_id": session_id,
    }, separators=(",", ":"))

    logger.info(f"[2FA] 激活 enrollment, code={totp_code}")
    resp = session.post(url, headers=headers, data=body)
    if resp.status_code != 200:
        logger.error(f"[2FA] activate 失败 {resp.status_code}: {resp.text}")
        resp.raise_for_status()
    data = resp.json()
    if not data.get("success"):
        raise RuntimeError(f"激活返回 success=false: {data}")
    return True


def setup_2fa(
    session: BrowserSession,
    email: str,
    otp_code: str | None = None,
    access_token: str | None = None,
) -> str:
    """
    完整的 2FA 设置流程。
    会触发再发一份邮箱验证码：
        - USE_EMAIL_SERVICE=True 时自动从 Outlook 账号池拉取
        - 否则需要用户手动输入

    Args:
        session: 已完成注册的会话
        email: 账号邮箱（用作 login_hint）
        otp_code: 邮箱验证码（None 则按上述策略获取）

    Returns:
        TOTP secret（Base32 字符串），可直接用于 pyotp.TOTP() 生成 6 位动态码
    """
    # 用模块属性读，支持 WebUI 热加载
    from config import email as _email_cfg
    from core.chatgpt_bootstrap import authenticated_bootstrap

    logger.info("=" * 60)
    logger.info("开始设置 2FA")
    logger.info("=" * 60)

    if access_token:
        try:
            logger.info("[2FA] 使用现有 accessToken 预热登录态...")
            authenticated_bootstrap(session, access_token, strict=False)
            human_delay("navigate")
            logger.info("[2FA] accessToken 预热完成")
        except Exception as exc:
            logger.warning("[2FA] accessToken 预热失败，继续按重认证流程执行：%s: %s", type(exc).__name__, str(exc)[:180])

    # 阶段一：重认证
    logger.info("[2FA] 阶段1：发起重认证")
    reauth_otp_after_ts = time.time()
    auth_url = _trigger_reauth(session, email)
    logger.info("[2FA] 重认证 authorize URL 已获取")
    human_delay("api")
    _follow_reauth(session, auth_url)
    logger.info("[2FA] 已跟随重认证 authorize URL")
    human_delay("navigate")
    # 显式催一封码再开始等 —— 不催的话有些号服务端根本不发（实测 1357）
    _trigger_reauth_otp_send(session)

    if otp_code is None:
        if _email_cfg.USE_EMAIL_SERVICE:
            from core.email_provider import fetch_code_direct, wait_for_otp
            # 先直连轮询（抗 ic-mail 网关抖动 + 带 ?after= 过滤旧码），拿不到才回落
            # 超时给足 240s：实测 ic-mail 这个网关发码最慢能到 t+145s，而且中途会
            # ReadTimeout 几次（150s 的窗口会刚好卡在门外，表现为 GenericApiMailError）
            logger.info("[2FA] 直连轮询取码（带 after 过滤，最多 240s）...")
            otp_code = fetch_code_direct(email, after_ts=reauth_otp_after_ts, timeout=240)
            if otp_code:
                logger.info("[2FA] 直连轮询拿到重认证 OTP")
            else:
                logger.info("[2FA] 直连轮询没拿到，回落到 wait_for_otp")
                otp_code = wait_for_otp(email, after_ts=reauth_otp_after_ts)
                logger.info("[2FA] 已收到邮箱重认证 OTP")
        else:
            logger.info("")
            logger.info("[2FA] 请检查邮箱，输入新收到的 6 位验证码")
            otp_code = input(">>> 2FA 验证码: ").strip()
            logger.info("[2FA] 已手动输入邮箱重认证 OTP")

    human_delay("otp_input")
    logger.info("[2FA] 正在提交邮箱重认证 OTP...")
    try:
        continue_url = _validate_reauth_otp(session, otp_code)
    except Exception as first_exc:
        # 部分取码接口会短暂返回缓存中的上一封邮件。若服务端拒绝验证码，
        # 重新轮询一次并提交最新候选，避免第一次旧码直接终止整个 2FA 流程。
        status_code = getattr(getattr(first_exc, "response", None), "status_code", None)
        if status_code != 401 or not bool(getattr(_email_cfg, "USE_EMAIL_SERVICE", False)):
            raise
        logger.warning("[2FA] 首次 OTP 被拒绝，重新获取最新验证码后再试一次")
        from core.email_provider import wait_for_otp
        retry_settle = max(8, int(getattr(_email_cfg, "OTP_SETTLE_SECONDS", 5) or 5))
        fresh_otp = wait_for_otp(
            email,
            after_ts=reauth_otp_after_ts,
            settle_seconds=retry_settle,
        )
        if fresh_otp == otp_code:
            logger.warning("[2FA] 重试仍获取到相同 OTP=%s，继续提交以保留原始错误信息", fresh_otp)
        else:
            logger.info("[2FA] 已获取新的 OTP=%s，替换首次候选", fresh_otp)
        otp_code = fresh_otp
        continue_url = _validate_reauth_otp(session, otp_code)
    logger.info("[2FA] 邮箱重认证 OTP 验证通过，continue_url=%s", continue_url)

    # 账号**已经开着 2FA** 时，邮箱 OTP 过后落点是 /mfa-challenge/<factor_id>，
    # 后面换 token / enroll 必然失败，最后只会抛一个含糊的
    # "未拿到 accessToken，登录态可能未建立"，让人误判成网络问题。
    # 这里显式识别并给出可诊断的错误（这种号只能人工在网页端移除 2FA 后重设）。
    if "/mfa-challenge" in str(continue_url or ""):
        raise RuntimeError(
            "该账号已启用 2FA，重认证落点进入 MFA challenge（"
            + str(continue_url) + "）；本地没有 totp_secret，无法继续设置。"
            "需登录网页端「设置 → 安全 → 移除两步验证」后再重设。"
        )
    human_delay("api")
    logger.info("[2FA] 正在交换新 token...")
    new_token = _exchange_new_token(session, continue_url)
    # 重认证后服务端会下发一个带新鲜 pwd_auth_time 的 token。挂在 session 上让
    # 调用方（twofa_service）写回数据库 —— 否则库里永远留着注册时那个旧 token，
    # 一旦服务端在后续清理时吊销旧会话，账号就会表现为"有记录但 token 已失效"。
    try:
        session.refreshed_access_token = new_token
    except Exception:
        pass
    logger.info("[2FA] 已拿到新 token")
    human_delay("api")

    # 阶段二：enroll + activate
    logger.info("[2FA] 阶段2：开始 enroll TOTP")
    secret, session_id = _enroll_totp(session, new_token)
    logger.info("[2FA] enroll 成功，session_id=%s", session_id)
    human_delay("form")
    logger.info("[2FA] 正在激活 TOTP enrollment")
    _activate_totp(session, new_token, secret, session_id)
    logger.info("[2FA] TOTP 激活完成")

    logger.info("=" * 60)
    logger.info(f"✅ 2FA 设置完成! Secret: {secret[:4]}...{secret[-4:]}")
    logger.info("=" * 60)
    return secret


def save_account_data(
    email: str,
    access_token: str,
    totp_secret: str | None = None,
    extra: dict | None = None,
    output_path: Path | None = None,  # 兼容老接口，已废弃
    email_source: str | None = None,
    proxy_used: str | None = None,
    batch_dir: Path | None = None,
    auto_plan_check: bool | None = None,
) -> int:
    """
    将账号信息保存到 SQLite；output_path 仅为兼容旧调用方保留。
    返回新插入/更新的 row id。
    """
    from core.db import insert_account
    extra = dict(extra or {})
    # Remail 的 service token 只存在进程内上下文中。注册成功后把订单上下文
    # 一并保存到账号 extra_json，服务重启时查活即可恢复，不再依赖“同一进程
    # 中先领取邮箱”。普通账号列表不会返回 extra_json。
    if str(email_source or "").strip().lower() == "remail":
        try:
            from core.remail_client import get_account_context_metadata

            remail_metadata = get_account_context_metadata(email)
            if remail_metadata:
                existing_service = extra.get("email_service")
                merged_service = dict(existing_service) if isinstance(existing_service, dict) else {}
                merged_service.update(remail_metadata)
                extra["email_service"] = merged_service
        except Exception as exc:
            # 订单上下文保存失败不应让已经完成的注册失败；后续查活仍会
            # 尝试用 API Key 按邮箱搜索 Remail 订单恢复凭证。
            logger.warning(
                "[Save] 保存 Remail 订单上下文失败，后续将尝试按邮箱恢复：%s: %s",
                type(exc).__name__,
                str(exc)[:180],
            )
    user = extra.get("user") or {}
    account = extra.get("account") or {}
    # 从 extra.codex 抽出顶层 codex 状态/错误，方便 WebUI 直接读账号字段
    codex = extra.get("codex") or {}
    codex_status = codex.get("status")  # success / failed / skipped
    codex_error = None
    if codex_status == "failed":
        codex_error = codex.get("message")

    row_id = insert_account(
        email=email,
        access_token=access_token,
        totp_secret=totp_secret,
        user_id=user.get("id"),
        user_name=user.get("name"),
        plan_type=account.get("planType"),
        expires_at=extra.get("expires"),
        proxy_used=proxy_used,
        email_source=email_source,
        extra=extra,
        codex_status=codex_status,
        codex_error=codex_error,
    )
    batch_folder = _append_batch_archive(
        row_id=row_id,
        email=email,
        access_token=access_token,
        totp_secret=totp_secret,
        email_source=email_source,
        proxy_used=proxy_used,
        extra=extra,
        batch_dir=batch_dir,
    )
    logger.info("[Save] 账号及凭证已保存到 SQLite, id=%s, email=%s", row_id, email)

    auto_twofa = False
    twofa_proxy = ""
    try:
        from config import twofa as _twofa_cfg

        auto_twofa = bool(getattr(_twofa_cfg, "ENABLE_2FA", False))
        # TWOFA_PROXY 优先：默认 socks5h://127.0.0.1:10808，不让 2FA 走计费住宅代理。
        twofa_proxy = str(getattr(_twofa_cfg, "TWOFA_PROXY", "") or "").strip()
    except Exception:
        auto_twofa = False
    if auto_twofa and not str(totp_secret or "").strip():
        try:
            from core.twofa_service import enqueue_account_totp_setup

            queued = enqueue_account_totp_setup(
                account_id=row_id,
                email=email,
                access_token=access_token,
                trigger="registration_auto",
                proxy=twofa_proxy or proxy_used,
            )
            if queued.get("accepted"):
                logger.info(f"[2FA] 注册后自动开启 2FA 已入队: id={row_id}, email={email}")
            elif queued.get("busy"):
                logger.info(f"[2FA] 账号已有 2FA 任务，注册流程不重复入队: id={row_id}, email={email}")
            else:
                logger.warning(f"[2FA] 注册后自动开启 2FA 入队失败（不影响注册结果）: {email}, {queued.get('error')}")
        except Exception as exc:
            logger.warning(
                f"[2FA] 注册后自动开启 2FA 入队异常（不影响注册结果）: "
                f"{email}, {type(exc).__name__}: {str(exc)[:180]}"
            )

    if auto_plan_check is None:
        try:
            from config import register as _register_cfg

            auto_plan_check = bool(getattr(_register_cfg, "AUTO_PLAN_CHECK_AFTER_REGISTER", False))
        except Exception:
            auto_plan_check = False
    if not auto_plan_check:
        logger.info(f"[Plan] 注册后自动套餐查询已跳过: id={row_id}, email={email}")
        return row_id
    # 协议注册原先不走 dwell。新号刚落地立刻打 accounts/check + checkout
    # 会被风控直接打废；先按 POST_REGISTER_DWELL_SECONDS_RANGE 停一会儿。
    post_register_dwell(email, label="注册后查套餐前")
    # session 中的 account.planType 不能说明 Plus 试用资格。账号落库后只负责
    # 入队，由专用线程池异步查询并回写，避免占用注册工作线程。
    try:
        from core.plan_check_service import enqueue_account_plan_check

        queued = enqueue_account_plan_check(
            account_id=row_id,
            email=email,
            access_token=access_token,
            trigger="registration_auto",
        )
        if queued.get("accepted"):
            logger.info(f"[Plan] 注册后自动查询已入队: id={row_id}, email={email}")
        elif queued.get("busy"):
            logger.info(f"[Plan] 账号已有套餐查询，注册流程不重复入队: id={row_id}, email={email}")
        else:
            logger.warning(f"[Plan] 注册后自动查询入队失败（不影响注册结果）: {email}, {queued.get('error')}")
    except Exception as exc:
        logger.warning(
            f"[Plan] 注册后自动查询入队异常（不影响注册结果）: "
            f"{email}, {type(exc).__name__}: {str(exc)[:180]}"
        )
    return row_id
