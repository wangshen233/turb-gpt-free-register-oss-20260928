# -*- coding: utf-8 -*-
"""
ChatGPT Auth 模块
处理 chatgpt.com 域名下的认证请求（步骤1-3）
"""
import json
import logging
from urllib.parse import urlencode, urlparse, parse_qs

from core.session import BrowserSession
from config import (
    OPENAI_CLIENT_ID, OPENAI_SCOPE, OPENAI_AUDIENCE, OPENAI_REDIRECT_URI
)

logger = logging.getLogger(__name__)

# 2026-09-09 HAR：authorize URL 带 ccaps=login_methods chatgpt_login_finalizer_v1，
# 以及 auth_return_target_category=chatgpt_home。纯协议保持同形态。
_CC_CAPS = "login_methods chatgpt_login_finalizer_v1"
_AUTH_RETURN_TARGET_CATEGORY = "chatgpt_home"

# 2026-09-12 HAR（hrr-export 注册抓包）：
#   POST /api/auth/signin/openai?prompt=login&screen_hint=signup&auth_session_logging_id=…
#       &ext-oai-did=…&login_hint=<email>
# 前端已经把 screen_hint 从 "login_or_signup" 改成 "signup"，入口页也从
# /auth/login 换成 /auth/login_with?callback_path=%2F&screen_hint=signup&…
# 用旧的 login_or_signup 时服务端会落进遗留的密码注册路径
# （/api/accounts/user/register 或 /create-account/password），
# core/openai_auth.py 会直接判定「落入旧密码注册路径」并停掉，白烧一个邮箱。
# 注册链路统一改用 signup。
_SCREEN_HINT = "signup"


def _ensure_authorize_context(authorize_url: str, session: BrowserSession, email: str) -> str:
    """
    对 NextAuth 返回的 authorize URL 做最后兜底：确保当前前端默认
    signup 链路（2026-09-12 起）的上下文参数没有在重定向生成阶段丢失。
    """
    try:
        parsed = urlparse(authorize_url)
        if not parsed.netloc.endswith("auth.openai.com"):
            return authorize_url
        params = parse_qs(parsed.query, keep_blank_values=True)
        required = {
            "ext-oai-did": session.device_id,
            "auth_session_logging_id": session.auth_session_logging_id,
            "screen_hint": _SCREEN_HINT,
            "login_hint": email,
            "ccaps": _CC_CAPS,
            "auth_return_target_category": _AUTH_RETURN_TARGET_CATEGORY,
        }
        changed = False
        for key, value in required.items():
            if not params.get(key):
                params[key] = [value]
                changed = True
        if not changed:
            return authorize_url
        return parsed._replace(query=urlencode(params, doseq=True)).geturl()
    except Exception:
        return authorize_url


def mark_authentication_started(session: BrowserSession) -> bool:
    """步骤0: POST https://chatgpt.com/unauth-mweb/auth/handoff

    2026-09-12 注册抓包新增的一步。真机在 GET /api/auth/csrf **之前**先打这一枪，
    携带贯穿整条注册链路的 auth_session_logging_id：

        {"authSessionLoggingId": "<uuid>", "authenticationStarted": true}   ->  204

    服务端用它标记"这次认证已经开始"。纯协议原先完全没有这一步。
    这是提示性请求，失败不阻断注册（返回 False 只记日志）。
    """
    url = "https://chatgpt.com/unauth-mweb/auth/handoff"
    headers = session.get_chatgpt_mweb_headers(referer="https://chatgpt.com/")
    body = json.dumps({
        "authSessionLoggingId": session.auth_session_logging_id,
        "authenticationStarted": True,
    }, separators=(",", ":"))

    logger.info("[步骤0] 标记认证开始 unauth-mweb/auth/handoff ...")
    try:
        resp = session.post(url, headers=headers, data=body)
    except Exception as exc:
        logger.warning("[步骤0] handoff 异常（不阻断注册）: %s: %s", type(exc).__name__, exc)
        return False

    ok = int(resp.status_code) in (200, 204)
    if ok:
        logger.info("[步骤0] handoff 成功: HTTP %s", resp.status_code)
    else:
        logger.warning("[步骤0] handoff 非预期状态 HTTP %s: %s", resp.status_code, (resp.text or "")[:150])
    return ok


def get_providers(session: BrowserSession) -> dict:
    """
    步骤1: 获取 OAuth Providers 列表。
    GET https://chatgpt.com/api/auth/providers

    验证与 chatgpt.com 的连接是否正常，并获取可用的 OAuth 提供商。

    Returns:
        providers 字典，例如:
        {
            "openai": {
                "id": "openai",
                "name": "openai",
                "type": "oauth",
                "signinUrl": "https://chatgpt.com/api/auth/signin/openai",
                "callbackUrl": "https://chatgpt.com/api/auth/callback/openai"
            },
            ...
        }
    """
    url = "https://chatgpt.com/api/auth/providers"
    headers = session.get_nextauth_headers(referer="https://chatgpt.com/")

    logger.info("[步骤1] 获取 OAuth Providers...")
    resp = session.get(url, headers=headers)
    resp.raise_for_status()

    data = resp.json()
    logger.info(f"[步骤1] 成功获取 {len(data)} 个 providers: {list(data.keys())}")
    return data


def get_csrf_token(session: BrowserSession) -> str:
    """
    步骤2: 获取 CSRF Token。
    GET https://chatgpt.com/api/auth/csrf

    CSRF token 将在后续 signin 请求中使用。

    Returns:
        csrfToken 字符串
    """
    url = "https://chatgpt.com/api/auth/csrf"
    headers = session.get_nextauth_headers(referer="https://chatgpt.com/")

    logger.info("[步骤2] 获取 CSRF Token...")
    resp = session.get(url, headers=headers)
    resp.raise_for_status()

    data = resp.json()
    csrf_token = data.get("csrfToken", "")
    logger.info(f"[步骤2] 获取 CSRF Token 成功: {csrf_token[:20]}...")
    return csrf_token


def signin_openai(session: BrowserSession, csrf_token: str, email: str) -> str:
    """
    步骤3: 发起 OAuth Signin 请求。
    POST https://chatgpt.com/api/auth/signin/openai

    构造 OAuth 授权参数，获取 authorize URL。

    Args:
        session: 浏览器会话
        csrf_token: 从步骤2获取的 CSRF token
        email: 注册邮箱

    Returns:
        authorize_url: auth.openai.com 的授权 URL
    """
    # 构造 URL 查询参数
    query_params = {
        "prompt": "login",
        "ext-oai-did": session.device_id,
        "auth_session_logging_id": session.auth_session_logging_id,
        "screen_hint": _SCREEN_HINT,
        "login_hint": email,
    }
    url = "https://chatgpt.com/api/auth/signin/openai?" + urlencode(query_params)

    # 构造请求头
    headers = session.get_nextauth_headers(referer="https://chatgpt.com/")
    headers["content-type"] = "application/x-www-form-urlencoded"
    headers["origin"] = "https://chatgpt.com"

    # 构造请求体
    # 2026-09-11 抓包：body 为 callbackUrl=%2F（即相对路径 "/"）；09-08 抓包还是
    # 绝对 URL "https://chatgpt.com/"。已核对下游没有地方依赖它的绝对形态：
    #   * 本函数的返回值只取响应 JSON 的 "url"（authorize_url），callbackUrl 不被读回；
    #   * callbackUrl 只被 NextAuth 存进 signin cookie，OAuth 完成时用它做跳转，
    #     相对路径按 chatgpt.com 解析，落点仍是 https://chatgpt.com/；
    #   * 真正的 OAuth 回调走服务端 continue_url（core/account_export.follow_oauth_callback），
    #     与该字段无关。
    # urlencode({"callbackUrl": "/"}) 正好产出与抓包一致的 "callbackUrl=%2F"。
    # 实测两种形态都出现过，是会漂的字段：
    #   2026-09-11 抓包         : callbackUrl=%2F
    #   2026-09-12 注册抓包     : callbackUrl=https%3A%2F%2Fchatgpt.com%2F
    #   2026-09-13 真浏览器复抓 : callbackUrl=%2F   ← 同一入口 chatgpt.com/auth/login，现在按这个走
    # 要切回绝对形态，把下面这行的值换成 "https://chatgpt.com/" 即可。
    body = urlencode({
        "callbackUrl": "/",
        "csrfToken": csrf_token,
        "json": "true",
    })

    logger.info(f"[步骤3] 发起 OAuth Signin 请求, 邮箱: {email}")
    resp = session.post(url, headers=headers, data=body)
    resp.raise_for_status()

    data = resp.json()
    authorize_url = data.get("url", "")

    if not authorize_url:
        raise ValueError(f"[步骤3] 未获取到 authorize URL, 响应: {data}")

    authorize_url = _ensure_authorize_context(authorize_url, session, email)
    logger.info("[步骤3] 获取 authorize URL 成功，已确认 signup/oai-did 上下文")
    logger.debug(f"[步骤3] URL: {authorize_url[:160]}...")
    return authorize_url
