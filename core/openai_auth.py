# -*- coding: utf-8 -*-
"""
OpenAI Auth 模块
处理 auth.openai.com 域名下的注册请求（步骤4-5、7-8、10、12）
以及 sentinel.openai.com 的 sentinel token 请求（步骤6、9、11）
"""
import json
import logging
import time

from core.session import BrowserSession, is_cf_challenge_response
from core.sentinel import (
    generate_requirements_token,
    build_sentinel_request_body,
)
from core.sentinel_runner import generate_sentinel_token

logger = logging.getLogger(__name__)


class EmailOtpInvalidError(RuntimeError):
    """邮箱验证码无效/过期，可重新发送后重试。"""


class AccountUnusableError(Exception):
    """
    邮箱对应的 OpenAI 账号已废（删除/停用/封禁），再试也是同样结果。

    与普通网络/风控错误区分：这类错误意味着这个邮箱素材本身不可用，
    上层应把邮箱标成 failed 直接剔除，而不是放回 available 反复重试。

    携带 error_code 便于日志与排查（如 account_deactivated）。
    """

    def __init__(self, message: str, error_code: str = ""):
        super().__init__(message)
        self.error_code = error_code


# 远端返回这些 error code 时，判定邮箱素材已废，不再重试。
_ACCOUNT_DEAD_CODES = frozenset({
    "account_deactivated",   # 账号已删除/停用
    "account_deleted",
    "account_banned",
})

_ACCOUNT_DEAD_TEXT_MARKERS = (
    "account_deactivated",
    "account_deleted",
    "account_banned",
    "account deactivated",
    "account deleted",
    "account banned",
    "account has been deactivated",
    "account has been deleted",
    "account was deactivated",
    "account was deleted",
    "your account has been deactivated",
    "your account has been deleted",
    "your account was deactivated",
    "your account was deleted",
    "账号已停用",
    "账号已禁用",
    "账号已删除",
    "账户已停用",
    "账户已禁用",
    "账户已删除",
)


def detect_account_unusable_text(text: str) -> str:
    """从浏览器页面/异常文本里识别账号已废，返回规范 error_code；未命中返回空串。"""
    low = str(text or "").lower()
    for code in _ACCOUNT_DEAD_CODES:
        if code in low:
            return code
    if any(marker in low for marker in _ACCOUNT_DEAD_TEXT_MARKERS):
        if "delete" in low or "删除" in low:
            return "account_deleted"
        if "ban" in low or "封" in low:
            return "account_banned"
        return "account_deactivated"
    return ""


def detect_account_unusable_response_body(body: str) -> str:
    """
    按纯协议模式同源逻辑，从接口响应 JSON 的 error.code 识别账号已废。

    这不是页面文字识别；用于浏览器/指纹浏览器拦截
    /api/accounts/email-otp/validate 响应后，读取响应体里的结构化错误码。
    """
    try:
        payload = json.loads(body or "")
    except Exception:
        return ""
    err = payload.get("error") if isinstance(payload, dict) else None
    code = ""
    if isinstance(err, dict):
        code = str(err.get("code") or "")
    elif isinstance(payload, dict):
        code = str(payload.get("code") or payload.get("error_code") or "")
    return code if code in _ACCOUNT_DEAD_CODES else ""


def _extract_error_code(resp) -> str:
    """从响应体 JSON 里抽 error.code（拿不到返回空串）。"""
    try:
        payload = resp.json()
    except Exception:
        return ""
    err = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(err, dict):
        return str(err.get("code") or "")
    return ""


# 步骤4 网络层临时性错误（代理抽风 / TLS 握手失败 / 重置等）的重试参数
_FOLLOW_AUTH_MAX_ATTEMPTS = 3
_FOLLOW_AUTH_BACKOFF_BASE = 2.0  # 第 N 次重试前等 2^(N-1) 秒


def _is_transient_network_error(exc: Exception) -> bool:
    """识别可重试的临时性网络错误（TLS / 连接超时 / 连接重置 / 代理拒绝）。"""
    name = type(exc).__name__
    msg = str(exc).lower()
    transient_classes = ("SSLError", "ConnectionError", "Timeout", "CurlError", "ProxyError")
    if any(t.lower() in name.lower() for t in transient_classes):
        return True
    transient_keywords = (
        "wrong_version_number",      # 代理给了非 TLS 响应
        "tls connect",
        "ssl",
        "connection reset",
        "connection refused",
        "timed out",
        "proxy",
        "curl: (35)",
        "curl: (52)",                # empty reply from server
        "curl: (56)",                # network recv failure
    )
    return any(k in msg for k in transient_keywords)


# 预检/authorize 被 Cloudflare 挑战时的换 IP 次数（仅本地桥支持）。
_AUTH_IP_ROTATIONS = 5


def is_cloudflare_challenge(resp) -> bool:
    """判断响应是不是 Cloudflare 人机挑战（而不是普通 4xx）。"""
    return is_cf_challenge_response(resp)


def ensure_auth_ip_not_challenged(session: BrowserSession) -> None:
    """注册前确认当前出口 IP 没被 auth.openai.com 挑战；被挑战就换上游重试。

    住宅池里总有一部分 IP 已被 Cloudflare 拉黑：同一个会话里 chatgpt.com 首页
    200、follow_authorize 却直接 403 challenge，账号就白烧一个邮箱。
    """
    # 真浏览器从不 GET auth.openai.com/log-in（09-11 抓包 219 条 ABSENT；09-13 真机复抓也没有）。
    # 这个端点只在流程内被 authorize 重定向自然触达，脱离流程单独打是纯机器特征。
    # 改打真实前端入口；auth.openai.com 侧的 CF 挑战由 follow_authorize 的换 IP 逻辑兜。
    url = "https://chatgpt.com/auth/login?next=%2F"
    last_exc: Exception | None = None
    for attempt in range(1, _AUTH_IP_ROTATIONS + 1):
        try:
            resp = session.get(
                url,
                headers=session.get_chatgpt_navigate_headers(referer="https://chatgpt.com/"),
                allow_redirects=True,
            )
            if not is_cloudflare_challenge(resp) and int(getattr(resp, "status_code", 0) or 0) < 400:
                if attempt > 1:
                    logger.info("[预检] 第 %s 个上游出口可用，继续注册", attempt)
                return
            detail = (
                f"status={getattr(resp, 'status_code', '?')}"
                f", cf-mitigated={str((getattr(resp, 'headers', {}) or {}).get('cf-mitigated') or '')}"
            )
            last_exc = RuntimeError(f"auth 出口被 Cloudflare 挑战: {detail}")
        except Exception as exc:
            last_exc = exc
        rotated = session.rotate_bridge_upstream()
        if not rotated:
            if last_exc:
                raise last_exc
            return
        logger.warning(
            "[预检] 当前出口被 Cloudflare 挑战（%s:%s），已换到上游 slot=%s 重试",
            type(last_exc).__name__ if last_exc else "challenge",
            str(last_exc)[:90],
            getattr(session, "_bridge_slot", "?"),
        )
    if last_exc:
        raise last_exc


def network_preflight(session: BrowserSession) -> None:
    """
    注册前网络预检：只建立边缘节点/cookie/基础连通性，不携带邮箱、不触发 OTP。

    这样真正会“烧邮箱”的 authorize 重定向发生前，已经确认当前代理、TLS
    impersonate、ChatGPT/Auth/Sentinel 三段链路都可达。
    """
    # 2026-09-11 抓包（captures/har-20260911）事实：
    #   * 219 条请求里 https://auth.openai.com/log-in 与 https://chatgpt.com/login 一次都没出现；
    #   * 真实前端入口是 https://chatgpt.com/auth/login?next=%2F；
    #   * 真实首个 auth 页面 /email-verification 依赖 authorize 导航带下来的 state cookie，
    #     脱离流程单独 GET 必然 4xx，因此**不放进预检**。
    #
    # 2026-09-13：原先在网络预检之前还额外调用一次 ensure_auth_ip_not_challenged()，
    # 而它打的正是下面 checks[0] 的同一个 URL —— 登录页是整页 HTML（实测 1072 KiB），
    # 每个号白白多下 1 MB。现在 CF 挑战检测 + 换上游重试并进下面的 checks 循环，
    # 功能不减，少一个 1 MB 请求。
    checks = [
        # 整页 GET 登录页（真实下行 179.9 KiB）。默认关掉省流量；开回来只需把
        # PROTOCOL_PREFLIGHT_PAGE_ENABLED 置 True。真机出口被 CF 挑战时，
        # follow_authorize 里还有换上游重试兜底。
        *([("chatgpt-auth-login", lambda: session.get(
            "https://chatgpt.com/auth/login?next=%2F",
            headers=session.get_chatgpt_navigate_headers(referer="https://chatgpt.com/"),
            allow_redirects=True,
        ))] if __import__("config", fromlist=["openai_protocol"]).PROTOCOL_PREFLIGHT_PAGE_ENABLED else []),
        ("chatgpt-csrf", lambda: session.get(
            "https://chatgpt.com/api/auth/csrf",
            allow_redirects=True,
        )),
        ("sentinel-frame", lambda: session.get(
            "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=" + __import__("config", fromlist=["SENTINEL_SV"]).SENTINEL_SV,
            headers=session.get_auth_navigate_headers(referer="https://chatgpt.com/auth/login", target_origin="https://sentinel.openai.com"),
            allow_redirects=True,
        )),
        # 2026-09-13 真机复抓：真机在 auth.openai.com 页面上会取这份 sdk.js（referer=auth.openai.com/）。
        # 协议原先只取 frame.html，不取 sdk.js。补上，保持同形。
        ("sentinel-sdk", lambda: session.get(
            "https://sentinel.openai.com/backend-api/sentinel/sdk.js",
            headers=session.get_auth_navigate_headers(referer="https://auth.openai.com/", target_origin="https://sentinel.openai.com"),
            allow_redirects=True,
        )),
    ]
    for label, fn in checks:
        last_exc = None
        for attempt in range(1, _FOLLOW_AUTH_MAX_ATTEMPTS + 1):
            try:
                logger.info(f"[预检] {label} ({attempt}/{_FOLLOW_AUTH_MAX_ATTEMPTS})")
                resp = fn()
                # 出口被 Cloudflare 挑战时先换上游（住宅池里总有一部分 IP 已被拉黑），
                # 不与普通 4xx 混在一起。
                if is_cloudflare_challenge(resp):
                    if session.rotate_bridge_upstream():
                        logger.warning(
                            "[预检] %s 出口被 Cloudflare 挑战，已换到上游 slot=%s 重试",
                            label, getattr(session, "_bridge_slot", "?"),
                        )
                        continue
                    raise RuntimeError(f"{label} 出口被 Cloudflare 挑战且无法换 IP")
                if getattr(resp, "status_code", 0) >= 400:
                    # 错误文案带上 CF 挑战标记，便于区分"被 Cloudflare 拦"和普通 4xx。
                    cf_mitigated = ""
                    try:
                        cf_mitigated = str(getattr(resp, "headers", {}).get("cf-mitigated") or "")
                    except Exception:
                        cf_mitigated = ""
                    raise RuntimeError(
                        f"{label} status={resp.status_code}"
                        + (f", cf-mitigated={cf_mitigated}" if cf_mitigated else "")
                        + f", body={(getattr(resp, 'text', '') or '')[:180]}"
                    )
                break
            except Exception as exc:
                last_exc = exc
                if not _is_transient_network_error(exc) or attempt >= _FOLLOW_AUTH_MAX_ATTEMPTS:
                    raise
                backoff = _FOLLOW_AUTH_BACKOFF_BASE ** (attempt - 1)
                logger.warning(f"[预检] {label} 临时失败：{type(exc).__name__}: {str(exc)[:120]}，{backoff:.1f}s 后重试")
                time.sleep(backoff)
        else:
            raise last_exc if last_exc else RuntimeError(f"[预检] {label} 未完成")


def follow_authorize(session: BrowserSession, authorize_url: str) -> str:
    """
    步骤4: 跟随 authorize URL 重定向。
    GET auth.openai.com/api/accounts/authorize?...

    这个请求会产生一系列重定向，建立 auth.openai.com 的 session cookies。
    遇到临时性网络错误（代理抽风 / TLS 握手失败 等）会自动重试。

    Args:
        session: 浏览器会话
        authorize_url: 从步骤3获取的 authorize URL
    """
    headers = session.get_auth_navigate_headers(referer="https://chatgpt.com/")

    last_exc: Exception | None = None
    for attempt in range(1, _FOLLOW_AUTH_MAX_ATTEMPTS + 1):
        try:
            logger.info(f"[步骤4] 跟随 authorize URL 重定向 (尝试 {attempt}/{_FOLLOW_AUTH_MAX_ATTEMPTS})...")
            resp = session.get(authorize_url, headers=headers, allow_redirects=True)
            if is_cloudflare_challenge(resp):
                # 出口 IP 被 Cloudflare 挑战：换一条上游再试，别把邮箱烧在 403 上。
                if session.rotate_bridge_upstream() and attempt < _FOLLOW_AUTH_MAX_ATTEMPTS:
                    logger.warning(
                        "[步骤4] 当前出口被 Cloudflare 挑战（status=%s），已换到上游 slot=%s 重试",
                        getattr(resp, "status_code", "?"),
                        getattr(session, "_bridge_slot", "?"),
                    )
                    continue
                raise RuntimeError(
                    f"[步骤4] 出口被 Cloudflare 挑战且无法换 IP: status={getattr(resp, 'status_code', '?')}"
                )
            resp.raise_for_status()
            final_url = str(getattr(resp, "url", "") or "")
            if "/api/accounts/user/register" in final_url or "/create-account/password" in final_url:
                raise RuntimeError(f"[步骤4] 落入旧密码注册路径，已拒绝继续烧邮箱: {final_url}")
            logger.info(f"[步骤4] 重定向完成, 最终URL: {final_url}")
            return final_url
        except Exception as exc:
            last_exc = exc
            if not _is_transient_network_error(exc):
                # 非临时性错误（比如 4xx 业务错误）直接抛出，不重试
                raise
            if attempt >= _FOLLOW_AUTH_MAX_ATTEMPTS:
                break
            backoff = _FOLLOW_AUTH_BACKOFF_BASE ** (attempt - 1)
            logger.warning(
                f"[步骤4] 临时性网络错误 ({type(exc).__name__}: {str(exc)[:120]})，"
                f"{backoff:.1f}s 后重试..."
            )
            time.sleep(backoff)

    # 三次都失败：抛出最后一次异常
    raise last_exc if last_exc else RuntimeError("步骤4 重试耗尽但无异常记录")


def request_sentinel_token(session: BrowserSession, flow: str) -> dict:
    """
    步骤6/9/11: 请求 Sentinel Token。
    POST https://sentinel.openai.com/backend-api/sentinel/req

    Args:
        session: 浏览器会话
        flow: 流程类型
            - "username_password_create": 步骤6
            - "email_otp_validate": 步骤9/10（邮箱 OTP）
            - "authorize_continue": 兼容旧 Codex 登录继续步
            - "oauth_create_account": 步骤11

    Returns:
        sentinel 响应 JSON，包含 token、turnstile、proofofwork 等
    """
    url = "https://sentinel.openai.com/backend-api/sentinel/req"

    # 生成 p 字段（浏览器指纹）
    # 引擎切换：protocol（默认，走主人改好的协议机）/ native（turb 原来的合成 PoW）。
    from core.sentinel_protocol import request_p as _proto_request_p, use_protocol
    if use_protocol():
        p = _proto_request_p(session, flow)
    else:
        p = generate_requirements_token(getattr(session, "sentinel_sid", session.device_id), profile=getattr(session, "browser_profile", None))

    # 构建请求体
    body = build_sentinel_request_body(p, session.device_id, flow)

    headers = session.get_sentinel_headers()

    logger.info(f"[Sentinel] 请求 sentinel token, flow={flow}")
    resp = session.post(url, headers=headers, data=body)
    resp.raise_for_status()

    data = resp.json()
    if isinstance(data, dict):
        # DX 用 sentinel/req 时提交的 p 做 XOR key；必须原样交给 runner。
        # 协议引擎第二趟（solve）也要它 —— 就是「发给 /sentinel/req 的那个 p」。
        data["_requirements_p"] = p
    logger.info(f"[Sentinel] 获取 sentinel token 成功, persona={data.get('persona')}")

    if data.get("proofofwork", {}).get("required"):
        seed = data["proofofwork"]["seed"]
        difficulty = data["proofofwork"]["difficulty"]
        logger.info(f"[Sentinel] 需要 PoW: seed={seed}, difficulty={difficulty}")

    # 增强诊断：哪些反爬机制被要求
    requires = []
    if data.get("turnstile", {}).get("required"):
        requires.append("turnstile")
    if data.get("so", {}).get("required"):
        requires.append("so")
    if data.get("proofofwork", {}).get("required"):
        requires.append("pow")
    logger.info(f"[Sentinel] 服务端要求项: {requires or '无'}")
    try:
        ts = data.get("turnstile") if isinstance(data.get("turnstile"), dict) else {}
        so = data.get("so") if isinstance(data.get("so"), dict) else {}
        pow_req = bool((data.get("proofofwork") or {}).get("required"))
        logger.info(
            "[Sentinel] dx 长度 turnstile=%s collector=%s snapshot=%s pow=%s difficulty=%s (HAR 31464/18968/21424, pow=yes)",
            len(str(ts.get("dx") or "")),
            len(str(so.get("collector_dx") or "")),
            len(str(so.get("snapshot_dx") or "")),
            pow_req,
            str((data.get("proofofwork") or {}).get("difficulty") or "-"),
        )
    except Exception:
        pass

    return data


def build_sentinel_header(session: BrowserSession, sentinel_resp: dict, flow: str) -> tuple:
    """
    根据 sentinel 响应构建 openai-sentinel-token 和 openai-sentinel-so-token 请求头值。

    实现策略：把 challenge 喂给 sentinel-runner.js（Node + sdk.js 在 vm 沙箱中执行），
    让真实 SDK 自己产出包含 turnstile / so / pow 的最终 token，避免硬塞 dx 被风控拒绝。

    Args:
        session: 浏览器会话（提供 device_id 与 user_agent，必须与后续 HTTP 请求保持一致）
        sentinel_resp: sentinel/req 的响应 JSON
        flow: 流程类型，必须与请求 challenge 时传入的 flow 完全一致

    Returns:
        (sentinel_header, so_header) 元组
        sentinel_header: openai-sentinel-token 请求头的值（runner 直接产出的 JSON 字符串）
        so_header: openai-sentinel-so-token 请求头的值（若 SDK 输出含 so 字段则填充，否则为 None）
    """
    from config import USER_AGENT

    # ── 引擎切换：protocol（默认）─────────────────────────────────────────────
    # 协议机自己两趟出 token（跑真 sdk.js），和 turb 的 sentinel-runner.js 是
    # **互斥**的两条路。这里直接返回，绝不混用 —— 混着用会得到两套指纹拼起来的
    # token，比任何一条单独走都更像机器人。
    from core.sentinel_protocol import solve as _proto_solve, use_protocol
    if use_protocol():
        req_p = str(sentinel_resp.get("_requirements_p") or "")
        token, so_token = _proto_solve(session, flow, sentinel_resp, req_p)
        logger.info(
            "[Sentinel] 协议引擎出 token: len=%d so=%s",
            len(token), (str(len(so_token)) if so_token else "无（服务端没要或没算出来）"),
        )
        return token, so_token

    header_value = generate_sentinel_token(
        challenge=sentinel_resp,
        flow=flow,
        device_id=session.device_id,
        user_agent=(getattr(session, "browser_profile", {}) or {}).get("user_agent") or USER_AGENT,
        browser_profile=getattr(session, "browser_profile", None),
        sentinel_sid=getattr(session, "sentinel_sid", None),
        react_listening_key=getattr(session, "react_listening_key", None),
        react_container_key=getattr(session, "react_container_key", None),
        react_resources_key=getattr(session, "react_resources_key", None),
        cookie=session.auth_cookie_header() if hasattr(session, "auth_cookie_header") else f"oai-did={session.device_id}",
        proxy=getattr(session, "proxy", None) or None,
    )

    # 解析 runner 输出：runner 会把 so 塞进同一份 JSON，但浏览器实测
    # openai-sentinel-token 固定只有 {p,t,c,id,flow} 5 键，so 必须单独走
    # openai-sentinel-so-token。这里先 pop 掉 so 再重新序列化，否则 token 头
    # 会比浏览器多 1 个键、多 600~710 字节（典型机器人特征）。
    so_header = None
    try:
        parsed = json.loads(header_value)
        # HAR token.p = gAAAAAB + PoW 结果；runner 经常把 requirements p（gAAAAAC）原样吐出。
        if isinstance(parsed, dict) and (sentinel_resp.get("proofofwork") or {}).get("required"):
            from core.sentinel import get_enforcement_token
            pow_p = get_enforcement_token(
                sentinel_resp,
                str((sentinel_resp.get("proofofwork") or {}).get("seed") or ""),
                str((sentinel_resp.get("proofofwork") or {}).get("difficulty") or ""),
                session.device_id,
                profile=getattr(session, "browser_profile", None),
            )
            if str(pow_p).startswith("gAAAAAB"):
                old_prefix = str(parsed.get("p") or "")[:8]
                parsed["p"] = pow_p
                header_value = json.dumps(parsed, separators=(",", ":"))
                logger.info("[Sentinel] token.p 已换成 enforcement %s → %s", old_prefix, pow_p[:8])
        so_value = parsed.pop("so", None) if isinstance(parsed, dict) else None
        if isinstance(parsed, dict) and so_value is not None:
            header_value = json.dumps(parsed, separators=(",", ":"))
            logger.info("[Sentinel] token 头已剥离 so，仅保留键 %s", sorted(parsed.keys()))
        outer_len = len(so_value) if isinstance(so_value, str) else 0
        if isinstance(so_value, str):
            text = so_value.strip()
            if text.startswith("{") and text.endswith("}"):
                try:
                    nested = json.loads(text)
                    inner = nested.get("so") if isinstance(nested, dict) else None
                    if isinstance(inner, str) and len(inner) >= 400:
                        so_value = inner
                    elif isinstance(inner, str):
                        logger.warning(
                            "[Sentinel] 内层 so 过短（inner=%s outer=%s），丢弃假 so",
                            len(inner), outer_len,
                        )
                        so_value = None
                except (ValueError, TypeError):
                    pass
        elif isinstance(so_value, dict):
            inner = so_value.get("so")
            if isinstance(inner, str) and len(inner) >= 400:
                so_value = inner
            else:
                logger.warning("[Sentinel] dict so 内层过短，丢弃假 so")
                so_value = None
        if isinstance(so_value, str) and len(so_value) < 400 and sentinel_resp.get("so", {}).get("required"):
            logger.warning("[Sentinel] so 字段过短（%s），按未产出处理", len(so_value))
            so_value = None
        if so_value:
            so_header = json.dumps(
                {
                    "so": so_value,
                    "c": parsed.get("c", sentinel_resp.get("token", "")),
                    "id": session.device_id,
                    "flow": flow,
                },
                separators=(',', ':'),
            )
            logger.info("[Sentinel] 检测到 SO 字段，已构建 so-token 头 len=%s", len(so_value) if isinstance(so_value, str) else type(so_value).__name__)
        elif sentinel_resp.get("so", {}).get("required"):
            logger.warning("[Sentinel] 服务端要求 so，但 runner 未产出完整 so 字段")
    except (ValueError, TypeError) as exc:
        logger.warning(f"[Sentinel] runner 输出解析失败: {exc}")

    return header_value, so_header


# ============================================================
# 密码分支专用函数（已停用，保留作备用）
# 当前 OpenAI 主流程：follow_authorize 自动跳到 /email-verification 并发 OTP，
# 不再走密码注册路径。如未来需要恢复密码注册（点击"使用密码继续"按钮的分支），
# 可参考下方实现解封即可。
# ============================================================

# def get_create_account_page(session: BrowserSession) -> None:
#     """
#     [备用] 步骤5: 访问创建账号-密码页面（密码分支）。
#     GET https://auth.openai.com/create-account/password
#     """
#     url = "https://auth.openai.com/create-account/password"
#     headers = session.get_auth_navigate_headers(referer="https://auth.openai.com/email-verification")
#     headers["sec-fetch-site"] = "same-origin"
#
#     logger.info("[步骤5] 访问创建账号-密码页（切换密码分支）...")
#     resp = session.get(url, headers=headers, allow_redirects=True)
#     resp.raise_for_status()
#     logger.info(f"[步骤5] 创建账号-密码页访问成功, 落点: {resp.url}")


# def register_user(session: BrowserSession, email: str, password: str, sentinel_header: str) -> dict:
#     """
#     [备用] 步骤7: 提交注册请求（邮箱+密码）。
#     POST https://auth.openai.com/api/accounts/user/register
#
#     Returns:
#         注册响应 JSON，例如:
#         {
#             "continue_url": "https://auth.openai.com/api/accounts/email-otp/send",
#             "method": "GET",
#             "page": {"type": "email_otp_send", "backstack_behavior": "default"}
#         }
#     """
#     url = "https://auth.openai.com/api/accounts/user/register"
#
#     headers = session.get_auth_headers(referer="https://auth.openai.com/create-account/password")
#     headers["openai-sentinel-token"] = sentinel_header
#
#     body = json.dumps({
#         "password": password,
#         "username": email,
#     })
#
#     logger.info(f"[步骤7] 提交注册请求, 邮箱: {email}")
#     resp = session.post(url, headers=headers, data=body)
#
#     if resp.status_code != 200:
#         logger.error(f"[步骤7] 请求失败, 状态码: {resp.status_code}")
#         logger.error(f"[步骤7] 响应内容: {resp.text}")
#         resp.raise_for_status()
#
#     data = resp.json()
#     logger.info(f"[步骤7] 注册请求成功: {data.get('page', {}).get('type')}")
#     return data


# def send_email_otp(session: BrowserSession) -> None:
#     """
#     [备用] 步骤8: 触发发送邮箱验证码。
#     GET https://auth.openai.com/api/accounts/email-otp/send
#     """
#     url = "https://auth.openai.com/api/accounts/email-otp/send"
#
#     headers = session.get_auth_navigate_headers(referer="https://auth.openai.com/create-account/password")
#     headers["sec-fetch-site"] = "same-origin"
#     headers["sec-fetch-user"] = "?1"
#
#     logger.info("[步骤8] 触发发送邮箱验证码...")
#     resp = session.get(url, headers=headers, allow_redirects=True)
#     logger.info(f"[步骤8] 验证码发送请求完成, 状态码: {resp.status_code}")


def navigate_about_you(session: BrowserSession, about_url: str | None = None) -> str:
    """进入 about-you 页面状态；服务端未返回 continue_url 时使用默认页面 URL 兜底。"""
    url = str(about_url or "https://auth.openai.com/about-you")
    if url.startswith("/"):
        url = "https://auth.openai.com" + url
    headers = session.get_auth_navigate_headers(referer="https://auth.openai.com/email-verification")
    headers["sec-fetch-site"] = "same-origin"
    logger.info("[步骤10.5] 导航到 about-you 页面，建立资料页状态")
    resp = session.get(url, headers=headers, allow_redirects=True)
    if resp.status_code >= 400:
        raise RuntimeError(f"about-you 导航失败 status={resp.status_code}: {(resp.text or '')[:240]}")
    final_url = str(getattr(resp, "url", "") or url)
    if "/api/accounts/user/register" in final_url or "/create-account/password" in final_url:
        raise RuntimeError(f"about-you 导航落入旧密码注册路径: {final_url}")
    logger.info(f"[步骤10.5] about-you 导航完成，落点: {final_url}")
    return final_url


def send_email_otp(session: BrowserSession, referer: str = "https://auth.openai.com/email-verification") -> None:
    """重新发送邮箱验证码。用于验证码错误/过期后重新取码。"""
    url = "https://auth.openai.com/api/accounts/email-otp/send"
    headers = session.get_auth_navigate_headers(referer=referer)
    headers["sec-fetch-site"] = "same-origin"
    headers["sec-fetch-user"] = "?1"
    logger.info("[OTP] 请求重新发送邮箱验证码...")
    resp = session.get(url, headers=headers, allow_redirects=True)
    if resp.status_code >= 400:
        logger.warning("[OTP] 重新发送验证码失败 status=%s: %s", resp.status_code, (resp.text or '')[:300])
        resp.raise_for_status()
    logger.info("[OTP] 重新发送验证码请求完成，status=%s", resp.status_code)


def validate_email_otp(session: BrowserSession, code: str, sentinel_header: str | None = None, so_header: str | None = None) -> dict:
    """
    步骤10: 提交邮箱验证码验证。
    POST https://auth.openai.com/api/accounts/email-otp/validate

    Args:
        session: 浏览器会话
        code: 6位数字验证码
        sentinel_header: openai-sentinel-token 头的值（email_otp_validate flow）

    Returns:
        验证响应 JSON，例如:
        {
            "continue_url": "https://auth.openai.com/about-you",
            "method": "GET",
            "page": {"type": "about_you", "backstack_behavior": "default"}
        }
    """
    url = "https://auth.openai.com/api/accounts/email-otp/validate"

    headers = session.get_auth_headers(referer="https://auth.openai.com/email-verification")
    if sentinel_header:
        headers["openai-sentinel-token"] = sentinel_header
    if so_header:
        headers["openai-sentinel-so-token"] = so_header
        logger.info("[步骤10] 已添加 openai-sentinel-so-token 头")

    # 真浏览器发的是 JSON.stringify 的结果，键值之间没有空格；Python 的 json.dumps 默认
    # 会加 ", " / ": "，每个 body 多出几个字节。这是稳定可测的字节级差异，必须压掉。
    body = json.dumps({"code": code}, separators=(",", ":"))

    logger.info(f"[步骤10] 提交邮箱验证码: {code}")
    resp = session.post(url, headers=headers, data=body)

    if resp.status_code != 200:
        logger.error(f"[步骤10] 请求失败, 状态码: {resp.status_code}")
        logger.error(f"[步骤10] 响应内容: {resp.text}")
        # 先看是不是"账号已废"——这类邮箱再试也没用，单独抛出让上层标 failed
        err_code = _extract_error_code(resp)
        if err_code in _ACCOUNT_DEAD_CODES:
            raise AccountUnusableError(
                f"账号已废弃（{err_code}），邮箱不可再用", error_code=err_code,
            )
        low = (resp.text or '').lower()
        if resp.status_code in (400, 401, 422) and any(k in low for k in (
            'invalid', 'incorrect', 'expired', 'code', 'otp', 'verification',
            '验证码', '認証コード', '確認コード', 'コード'
        )):
            raise EmailOtpInvalidError(f"邮箱验证码无效或已过期: status={resp.status_code}, body={(resp.text or '')[:240]}")
        resp.raise_for_status()

    data = resp.json()
    page_type = data.get('page', {}).get('type')
    logger.info(f"[步骤10] 验证码验证成功: {page_type}")
    logger.info(f"[步骤10] 验证响应摘要: {json.dumps(data, ensure_ascii=False)[:1000]}")
    return data


def create_account(session: BrowserSession, name: str, birthday: str, sentinel_header: str, so_header: str = None) -> dict:
    """
    步骤12: 提交用户信息，完成注册。
    POST https://auth.openai.com/api/accounts/create_account

    Args:
        session: 浏览器会话
        name: 用户显示名称
        birthday: 生日，格式 "YYYY-MM-DD"
        sentinel_header: openai-sentinel-token 头的值
        so_header: openai-sentinel-so-token 头的值

    Returns:
        创建账号响应 JSON
    """
    url = "https://auth.openai.com/api/accounts/create_account"

    headers = session.get_auth_headers(referer="https://auth.openai.com/about-you")
    headers["openai-sentinel-token"] = sentinel_header
    if so_header:
        headers["openai-sentinel-so-token"] = so_header
        logger.info(f"[步骤12] 已添加 openai-sentinel-so-token 头")

    body = json.dumps({
        "name": name,
        "birthdate": birthday,
    }, separators=(",", ":"))

    logger.info(f"[步骤12] 提交用户信息, 名称: {name}, 生日: {birthday}")
    resp = session.post(url, headers=headers, data=body)

    if resp.status_code != 200:
        logger.error(f"[步骤12] 请求失败, 状态码: {resp.status_code}")
        logger.error(f"[步骤12] 响应内容: {resp.text}")
        resp.raise_for_status()

    data = resp.json()
    logger.info("[步骤12] 创建接口返回成功，等待 OAuth 回调建立登录态")
    return data
